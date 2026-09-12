//! Required-literal extraction over a parsed regex Hir.
//!
//! The core guarantee this module provides: every byte string returned by
//! `required_literals` is a substring of *every* string the pattern can
//! match. This is the soundness property the fragment cache depends on --
//! get it wrong and rawgrep silently skips blocks that contain real matches.
//!
//! Deliberately conservative in a few places (documented at each site)
//! rather than clever, because a missed optimization costs throughput and
//! a wrong optimization costs correctness. Those are not the same severity
//! of bug.

use regex_syntax::hir::{Hir, HirKind};

/// Extract byte strings that must appear verbatim, at least once, in any
/// text the given Hir can match.
///
/// Not attempting a fully general multi-string longest-common-substring
/// search across every possible way branches could align (the fold in
/// `alternation_literals` below is a sound but greedy approximation of
/// that), and unrolling a `{min,max}` repetition of a *non-literal* unit
/// into multiple independent copies (each copy still contributes its own
/// required parts once, since copies of a variable unit are not
/// guaranteed adjacent -- see the doc comment on the Repetition arm).
pub fn required_literals(hir: &Hir) -> Vec<Vec<u8>> {
    match hir.kind() {
        HirKind::Empty => Vec::new(),
        HirKind::Literal(lit) => vec![lit.0.to_vec()],

        // A multi-element class matches one of several bytes/chars, so no
        // specific byte is guaranteed. (Single-element classes are already
        // folded into HirKind::Literal by regex-syntax before we see them,
        // so there is no singleton case to special-case here.)
        HirKind::Class(_) => Vec::new(),

        // Zero-width assertions (^, $, \b, ...) contribute no matched bytes.
        HirKind::Look(_) => Vec::new(),

        HirKind::Repetition(rep) => {
            if rep.min == 0 {
                Vec::new()
            } else if let Some(unit) = literal_bytes(&rep.sub) {
                //
                // The repeated unit is a pure literal with zero
                // variability, so unlike the general case below, the
                // first `min` copies are guaranteed to sit back-to-back
                // regardless of how many times (up to max) the repeat
                // actually fires: '(?:ab){3,5}' always contains 'ababab'
                // as a leading substring, whether it repeated 3, 4, or 5
                // times.
                //
                // This does NOT generalize when the unit has any
                // internal variability (a class, an alternation) --
                // see `repetition_of_nonliteral_does_not_merge_across_copies`
                // in the tests for why 'aa' would be an unsound claim for '(?:a[xy]){2,3}'.
                //
                vec![repeat_bytes(&unit, rep.min)]
            } else {
                required_literals(&rep.sub)
            }
        }

        HirKind::Capture(cap) => required_literals(&cap.sub),
        HirKind::Concat(subs) => concat_literals(subs),
        HirKind::Alternation(subs) => alternation_literals(subs),
    }
}

/// Bounds how large a literal we'll materialize by repeating a unit
/// `min` times, so a pathological pattern like "a{100000000}" can't force
/// an unbounded allocation here. Repeating fewer than `min` times is
/// still a fully sound (if less specific) claim: the real match always
/// contains at least `min` copies, and any prefix of that guaranteed run
/// is equally guaranteed. Always produces at least one copy when `min >= 1`
/// and the unit is nonempty, matching the pre-optimization behavior as a floor.
pub const MAX_REPEATED_LITERAL_BYTES: usize = 4096;

fn repeat_bytes(unit: &[u8], min: u32) -> Vec<u8> {
    if unit.is_empty() {
        return Vec::new();
    }

    let max_copies = (MAX_REPEATED_LITERAL_BYTES / unit.len()).max(1) as u32;
    let copies = min.min(max_copies);

    let mut out = Vec::with_capacity(unit.len() * copies as usize);
    for _ in 0..copies {
        out.extend_from_slice(unit);
    }

    out
}

/// Unwraps a Hir that reduces to exactly one known literal byte string,
/// with no other possibility -- through capturing-group wrappers
/// (a non-capturing group produces no Hir node at all, so only Capture needs
/// unwrapping) and through a Concat all of whose own children are, in
/// turn, fully literal (so `((a)(b))c` collapses all the way to 'abc').
///
/// Anything structurally uncertain anywhere in the tree returns None, so
/// callers never overclaim.
#[inline]
pub(crate) fn literal_bytes(hir: &Hir) -> Option<Vec<u8>> {
    match hir.kind() {
        HirKind::Literal(lit) => Some(lit.0.to_vec()),

        HirKind::Capture(cap) => literal_bytes(&cap.sub),

        HirKind::Concat(subs) => {
            let mut buf = Vec::new();
            for sub in subs {
                buf.extend_from_slice(&literal_bytes(sub)?);
            }
            Some(buf)
        }

        _ => None,
    }
}

/// True only when `hir` is (optionally wrapped in capturing groups) a
/// top-level alternation all of whose branches collapse to an exact
/// literal via `literal_bytes`. This is a stronger claim than anything
/// `required_literals` makes: not "these substrings are required
/// somewhere," but "the whole pattern *is* exactly one of these
/// strings." Any branch that isn't a pure literal invalidates the whole
/// pattern for this fast path -- we bail entirely rather than dropping
/// that branch, since dropping a branch would make the resulting
/// matcher under-match.
#[inline]
pub(crate) fn as_exact_alternation(hir: &Hir) -> Option<Vec<Vec<u8>>> {
    match hir.kind() {
        HirKind::Capture(cap) => as_exact_alternation(&cap.sub),
        HirKind::Alternation(subs) => subs.iter().map(literal_bytes).collect(),
        _ => None,
    }
}

/// Concatenation: merge adjacent literal children (through capture-group
/// wrappers) into contiguous byte runs, since they are guaranteed adjacent
/// in any match; anything else breaks the run and contributes its own
/// required parts independently.
fn concat_literals(subs: &[Hir]) -> Vec<Vec<u8>> {
    let mut parts = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    for sub in subs {
        if let Some(bytes) = literal_bytes(sub) {
            run.extend_from_slice(&bytes);
        } else {
            if !run.is_empty() {
                parts.push(std::mem::take(&mut run));
            }
            parts.extend(required_literals(sub));
        }
    }

    if !run.is_empty() {
        parts.push(run);
    }

    parts
}

/// Alternation: in general no single required literal survives a branch
/// choice, but any byte run that shows up in *every* branch's own
/// required literals is still guaranteed no matter which branch actually
/// matched. This subsumes the shared-prefix and shared-suffix cases
/// (`prefix(foo|bar)suffix`) as special cases of 'common substring', and
/// also catches shared content in the *middle* of otherwise-unrelated
/// branches (`foo[a-z]123bar|baz[a-z]123qux` both requiring "123") that
/// prefix/suffix-only matching cannot see.
///
/// Implementation is a greedy pairwise fold, not an exhaustive multi-way
/// common-substring search: seed the candidate set from the first
/// branch's own required parts, then repeatedly intersect against each
/// remaining branch by finding maximal common substrings between every
/// current candidate and every part of that branch. Each surviving
/// candidate is, by construction, an exact substring of some required
/// part of every branch processed so far, so this is sound at every
/// step; it is not guaranteed to find every common substring an
/// exhaustive search would (a different fold order can occasionally
/// surface a different, non-overlapping set), which is the same
/// "correct but not maximal" tradeoff as everything else here. An
/// alternation with an empty branch (`foo|`) correctly collapses to
/// nothing, since intersecting against that branch's empty part list
/// empties the candidate set immediately.
fn alternation_literals(subs: &[Hir]) -> Vec<Vec<u8>> {
    const MIN_ALTERNATION_SUBSTRING:  usize = 2;
    const MAX_ALTERNATION_CANDIDATES: usize = 32;

    let mut branches = subs.iter().map(required_literals);
    let mut candidates = match branches.next() {
        Some(parts) => parts,
        None => return Vec::new(),
    };

    for parts in branches {
        if candidates.is_empty() {
            break;
        }

        let mut next = Vec::new();
        for c in &candidates {
            for p in &parts {
                next.extend(common_substrings(c, p, MIN_ALTERNATION_SUBSTRING));
            }
        }

        next.sort();
        next.dedup();

        //
        // A wide alternation with many required parts per branch
        // could otherwise make the candidate set grow every fold
        // step.
        //
        // Keeping the longest candidates is a reasonable bias --
        // they are the more useful fragments anyway.
        //
        if next.len() > MAX_ALTERNATION_CANDIDATES {
            next.sort_by_key(|c| std::cmp::Reverse(c.len()));
            next.truncate(MAX_ALTERNATION_CANDIDATES);
        }

        candidates = next;
    }

    candidates
}

// @Note:
//
// Capped at `MAX_LEN` per input since this is O(len(a) * len(b)) time and space.
//
// Regex literal parts are small in reality, but nothing
// here should let a pathological pattern turn this quadratic.
fn common_substrings(a: &[u8], b: &[u8], min_len: usize) -> Vec<Vec<u8>> {
    const MAX_LEN: usize = 256;
    if a.is_empty() || b.is_empty() || a.len() > MAX_LEN || b.len() > MAX_LEN {
        return Vec::new();
    }

    let n = a.len();
    let m = b.len();

    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    let mut results = Vec::new();

    for i in 1..=n {
        for j in 1..=m {
            if a[i - 1] != b[j - 1] {
                continue;
            }

            dp[i][j] = dp[i - 1][j - 1] + 1;

            let at_end = i == n || j == m;
            let can_extend = !at_end && a[i] == b[j];
            if !can_extend && dp[i][j] >= min_len {
                results.push(a[i - dp[i][j]..i].to_owned());  // @Speed @Memory
            }
        }
    }

    results
}

#[inline]
pub fn extract_regex_literals(pattern: &str) -> Option<(Vec<u32>, usize)> {
    use crate::fragments::{MIN_FRAGMENT_LEN, extract_pattern_fragments_with_len, select_fragment_len};
    use nohash_hasher::IntSet;

    let hir = regex_syntax::Parser::new().parse(pattern).ok()?;
    let mut parts = required_literals(&hir);

    //
    // All parts' lengths must be >= MIN_FRAGMENT_LEN
    //
    parts.retain(|p| p.len() >= MIN_FRAGMENT_LEN);
    if parts.is_empty() {
        return None;
    }

    let fragment_len = select_fragment_len(parts.iter().map(|p| p.as_slice()))?;

    let mut all_fragments = IntSet::default();
    for part in &parts {
        let frags = extract_pattern_fragments_with_len(part, fragment_len);
        all_fragments.extend(frags);
    }

    Some((all_fragments.into_iter().collect(), fragment_len))
}
