use crate::tracy;
use crate::util::unlikely;

use std::{path::MAIN_SEPARATOR, sync::Arc};

use memchr::{memchr, memrchr};
use smallvec::SmallVec;

/// A chain of gitignore matchers from root to current directory
#[derive(Clone)]
#[repr(transparent)]
pub struct GitignoreChain {
    inner: Option<Arc<GitignoreChainInner>>,
}

struct GitignoreChainInner {
    /// (depth, path_prefix_len, gitignore). `path_prefix_len` is the byte
    /// length of the path to the directory that *contains* this .gitignore
    /// -- what we strip off `path` before handing it to this file's
    /// anchored-pattern matcher, since anchored patterns are relative to
    /// the gitignore's own directory, not the walk root.
    stack: SmallVec<[(u16, u32, Arc<Gitignore>); 8]>,

    /// Pre-computed: any gitignore in chain has negations?
    has_any_negations: bool,
}

impl Default for GitignoreChain {
    #[inline]
    fn default() -> Self {
        Self { inner: None }
    }
}

impl GitignoreChain {
    #[inline]
    pub fn from_root(gi: Gitignore) -> Self {
        let has_negations = gi.has_negations;
        let mut stack = SmallVec::new();
        stack.push((0, 0, Arc::new(gi)));
        Self {
            inner: Some(Arc::new(GitignoreChainInner {
                stack,
                has_any_negations: has_negations,
            })),
        }
    }

    /// Add a gitignore at the given depth
    /// Only clones the stack if there are other references (Cow)
    #[inline]
    pub fn with_gitignore(self, depth: u16, path_prefix_len: u32, gi: Gitignore) -> Self {
        let _span = tracy::span!("GitignoreChain::with_gitignore");

        let has_negations = gi.has_negations;
        let new_gi = Arc::new(gi);

        let Some(inner) = self.inner else {
            let mut stack = SmallVec::new();
            stack.push((depth, path_prefix_len, new_gi));
            return Self {
                inner: Some(Arc::new(GitignoreChainInner {
                    stack,
                    has_any_negations: has_negations,
                })),
            }
        };

        match Arc::try_unwrap(inner) {
            Ok(mut owned) => {
                // We have exclusive ownership - mutate in place
                owned.stack.retain(|(d, ..)| *d < depth);
                owned.stack.push((depth, path_prefix_len, new_gi));

                owned.has_any_negations = has_negations
                    || owned.stack[..owned.stack.len() - 1].iter().any(|(.., gi)| gi.has_negations);

                Self {
                    inner: Some(Arc::new(owned)),
                }
            }

            Err(shared) => {
                // Other references exist - must clone
                let mut new_stack: SmallVec<[_; 8]> = shared
                    .stack
                    .iter()
                    .filter(|(d, ..)| *d < depth)
                    .cloned()
                    .collect();

                let mut has_any_negations = has_negations;
                for (.., gi) in &new_stack {
                    has_any_negations |= gi.has_negations;
                }

                new_stack.push((depth, path_prefix_len, new_gi));

                Self {
                    inner: Some(Arc::new(GitignoreChainInner {
                        stack: new_stack,
                        has_any_negations,
                    })),
                }
            }
        }
    }

    #[inline]
    pub fn is_ignored(&self, path: &[u8], is_dir: bool) -> bool {
        let inner = match &self.inner {
            Some(inner) => inner,
            None => return false,
        };

        if inner.stack.is_empty() {
            return false;
        }

        let filename_start = memrchr(MAIN_SEPARATOR as _, path).map_or(0, |i| i + 1);
        let filename = unsafe { path.get_unchecked(filename_start..) };
        let filename_hash = fnv1a(filename);

        if inner.stack.len() == 1 {
            let (_, prefix_len, gi) = unsafe { inner.stack.get_unchecked(0) };
            let rel = relative_path(path, *prefix_len);
            return gi.is_ignored_with_filename_hashed(rel, filename, is_dir, filename_hash)
        }

        if !inner.has_any_negations {
            // -------- NO NEGATIONS - early exit on first match
            for (_, prefix_len, gi) in inner.stack.iter() {
                let rel = relative_path(path, *prefix_len);
                if gi.is_ignored_with_filename_hashed(rel, filename, is_dir, filename_hash) {
                    return true;
                }
            }

            return false
        }

        // ---------- HAS NEGATIONS - must check all, last match wins
        let mut result = false;
        for (_, prefix_len, gi) in inner.stack.iter() {
            let rel = relative_path(path, *prefix_len);
            match gi.check_ignored_with_filename(rel, filename, is_dir, filename_hash) {
                MatchResult::Ignored => result = true,
                MatchResult::Negated => result = false,
                MatchResult::NoMatch => {}
            }
        }

        result
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            None => true,
            Some(inner) => inner.stack.is_empty(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MatchResult {
    NoMatch,
    Ignored,
    Negated,
}

#[inline(always)]
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Open-addressed linear-probed table mapping a literal pattern's bytes to
/// its index in `literal_meta`. Built once per gitignore file at parse time,
/// never mutated after.
struct LiteralLookup {
    slots: Box<[(u64, u16)]>, // (hash, literal_meta index), index == u16::MAX means empty
    mask:  u64,
}

impl LiteralLookup {
    fn build(literal_data: &[u8], metas: &[LiteralMeta], indices: &[u16]) -> Self {
        let cap  = (indices.len().max(1) * 2).next_power_of_two();
        let mask = (cap - 1) as u64;
        let mut slots = vec![(0u64, u16::MAX); cap].into_boxed_slice();

        for &idx in indices {
            let meta    = metas[idx as usize];
            let pattern = &literal_data[meta.offset as usize..meta.offset as usize + meta.len as usize];
            let h       = fnv1a(pattern);

            let mut slot = (h & mask) as usize;
            while slots[slot].1 != u16::MAX {
                slot = (slot + 1) & mask as usize;
            }

            slots[slot] = (h, idx);
        }

        Self { slots, mask }
    }

    #[inline]
    fn contains_hashed(
        &self,
        literal_data: &[u8],
        metas: &[LiteralMeta],
        filename: &[u8],
        is_dir: bool,
        h: u64,
    ) -> bool {
        let mut slot = (h & self.mask) as usize;

        loop {
            let (slot_hash, idx) = self.slots[slot];
            if idx == u16::MAX {
                return false;
            }

            if slot_hash == h {
                let meta = metas[idx as usize];
                if !(meta.dir_only() && !is_dir) {
                    let len     = meta.len as usize;
                    let pattern = &literal_data[meta.offset as usize..meta.offset as usize + len];
                    if pattern == filename {
                        return true;
                    }
                }
            }

            slot = (slot + 1) & self.mask as usize;
        }
    }
}

#[allow(dead_code, reason = "@Incomplete")]
pub struct Gitignore {
    /// Pre-computed: does this gitignore have any negations?
    pub(crate) has_negations: bool,

    /// Literal patterns
    literal_data: Box<[u8]>,
    literal_meta: Box<[LiteralMeta]>,

    /// Pattern execution order for correct semantics
    order: Box<[OrderEntry]>,

    /// Wildcard patterns
    wildcards: Box<[WildcardPattern]>,

    /// Fast path, used only when has_negations is false. In that case
    /// "any match ignores" and "last match ignores" are the same rule,
    /// so declaration order can be discarded and we can go straight to
    /// whatever's cheapest instead of walking `order`.
    unanchored_lookup:        LiteralLookup,
    anchored_literal_indices: Box<[u16]>,
}

/// Packed literal pattern metadata
#[repr(C)]
#[derive(Clone, Copy)]
struct LiteralMeta {
    offset: u16,
    len: u8,
    flags: u8, // bit 0: negated, bit 1: anchored, bit 2: dir_only
}

impl LiteralMeta {
    #[inline(always)]
    fn negated(self) -> bool { self.flags & 1 != 0 }

    #[inline(always)]
    fn anchored(self) -> bool { self.flags & 2 != 0 }

    #[inline(always)]
    fn dir_only(self) -> bool { self.flags & 4 != 0 }
}

struct WildcardPattern {
    bytes: Box<[u8]>,

    /// bit 0: negated, bit 1: anchored, bit 2: dir_only
    flags: u8,

    /// For patterns like "*.rs", store the suffix for fast matching
    suffix: Option<Box<[u8]>>,

    /// For patterns like "test*", store the prefix
    prefix: Option<Box<[u8]>>,

    /// For patterns like "A/**/B", the literal "A" to check against the full
    /// anchored path before matching "B" against just the filename.
    ///
    /// "**" already accounts for zero or more intervening directories, so once
    /// this prefix check passes, the rest is an ordinary filename match.
    mid_anchor: Option<Box<[u8]>>,

    /// Set when the pattern is anchored and ends in a bare "/**"
    /// (or is exactly "**", i.e. "/**" with an empty head).
    ///
    /// Holds the literal directory prefix before the "/**" (empty for bare "/**").
    ///
    /// Per gitignore(5): "A trailing /** matches everything inside" -- this
    /// must cross directory separators, unlike an ordinary anchored "*",
    /// so it needs its own match path rather than going through the
    /// generic glob_match backtracker.
    trailing_double_star: Option<Box<[u8]>>,

    /// Set when the pattern began with a leading "**/" whose remainder
    /// still has internal directory structure
    /// (e.g. "**/target/**", "**/a/**/b") and so couldn't be collapsed
    /// into a bare unanchored filename check.
    ///
    /// "**/" matches zero or more leading directories, so at match time
    /// the remainder's anchored match (trailing_double_star
    /// mid_anchor / literal-or-glob tail) is retried at every
    /// path-component boundary in "text", not just at the root.
    leading_double_star: bool,
}

// @Refactor use bitflags instead in WildcardPattern?
impl WildcardPattern {
    #[inline(always)]
    fn negated(&self) -> bool { self.flags & 1 != 0 }

    #[inline(always)]
    fn anchored(&self) -> bool { self.flags & 2 != 0 }

    #[inline(always)]
    fn dir_only(&self) -> bool { self.flags & 4 != 0 }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct OrderEntry {
    /// 0 = literal, 1 = wildcard
    ty: u8,
    index: u16,
}

impl Gitignore {
    pub fn from_bytes(content: &[u8]) -> Self {
        // @SmallVecCandidate @Constant
        let mut literal_data = Vec::with_capacity(256);
        let mut literal_meta = Vec::with_capacity(32);

        let mut wildcards = Vec::new();
        let mut order = Vec::new();

        let mut has_negations = false;

        for line in content.split(|&b| b == b'\n') {
            if line.is_empty() || line[0] == b'#' {
                continue;
            }

            let line = trim_bytes(line);
            if line.is_empty() {
                continue;
            }

            let (mut pattern_bytes, negated) = if line[0] == b'!' {
                (&line[1..], true)
            } else {
                (line, false)
            };
            if pattern_bytes.is_empty() {
                continue;
            }
            if negated {
                has_negations = true;
            }

            // Unescape a leading "\#" or "\!" -- gitignore(5): "Put a backslash in
            // front of the first hash/bang for patterns that begin with a literal
            // hash/bang." Without this, the backslash itself stays part of the
            // stored pattern and never matches the real (unescaped) filename.
            if pattern_bytes.len() >= 2
                && pattern_bytes[0] == b'\\'
                && matches!(pattern_bytes[1], b'#' | b'!')
            {
                pattern_bytes = &pattern_bytes[1..];
            }

            // Strip a trailing '/' -- and any further redundant trailing
            // slashes, e.g. "foo//" -- *before* determining anchoring.
            // Per gitignore(5), the trailing slash is removed "for the
            // purpose of" the anchoring check, so it must never be
            // mistaken for a separator "at the beginning or middle" of
            // the pattern. Doing this the other way around (checking
            // anchoring first) had two bugs: a lone trailing slash on an
            // otherwise slash-free pattern like "foo/" spuriously
            // anchored it, and a doubled trailing slash like "**//" could
            // strip the pattern down to nothing and silently drop the
            // rule entirely.
            let dir_only = pattern_bytes.last() == Some(&(MAIN_SEPARATOR as _));
            if dir_only {
                while pattern_bytes.last() == Some(&(MAIN_SEPARATOR as _)) {
                    pattern_bytes = &pattern_bytes[..pattern_bytes.len() - 1];
                }
            }

            if pattern_bytes.is_empty() {
                continue;
            }

            let mut leading_double_star = false;
            let (pattern_bytes, anchored) = if pattern_bytes[0] == MAIN_SEPARATOR as _ {
                (&pattern_bytes[1..], true)

            } else if pattern_bytes.len() > 3 && pattern_bytes.starts_with(b"**/") {
                let rest = &pattern_bytes[3..];
                if memchr(MAIN_SEPARATOR as _, rest).is_none() {
                    //
                    // "**/foo" IS just unanchored "foo"
                    //
                    (rest, false)
                } else {
                    // Structure remains ("target/**", "a/**/b", ...) -- keep it
                    // anchored so mid_anchor/trailing_double_star still fire on the
                    // remainder below, but flag that the anchor floats to any depth.
                    leading_double_star = true;
                    (rest, true)
                }

            } else {
                (pattern_bytes, memchr(MAIN_SEPARATOR as _, pattern_bytes).is_some())
            };

            if pattern_bytes.is_empty() {
                continue;
            }

            //
            // Detect a mid-pattern "/**/" (e.g. "lisp/**/*loaddefs.el").
            // Per gitignore semantics "**" between two slashes matches zero or more
            // full directory components, so "A/**/B" must also match "A/B" directly.
            //
            let mid_anchor: Option<Box<[u8]>> = if anchored {
                memchr::memmem::find(pattern_bytes, b"/**/").and_then(|pos| {
                    let tail = &pattern_bytes[pos + 4..];
                    (!tail.is_empty() && memchr(MAIN_SEPARATOR as _, tail).is_none())
                        .then(|| pattern_bytes[..pos].into())
                })
            } else {
                None
            };

            let trailing_double_star: Option<Box<[u8]>> = if anchored && mid_anchor.is_none() {
                if pattern_bytes == b"**" {
                    Some(Box::from(&b""[..]))
                } else if pattern_bytes.len() > 3
                    && pattern_bytes.ends_with(b"/**")
                    && memchr::memchr3(b'*', b'?', b'[', &pattern_bytes[..pattern_bytes.len() - 3]).is_none()
                {
                    Some(pattern_bytes[..pattern_bytes.len() - 3].into())
                } else {
                    None
                }
            } else {
                None
            };

            let pattern_bytes: &[u8] = match &mid_anchor {
                Some(head) => &pattern_bytes[head.len() + 4..],
                None => pattern_bytes,
            };

            let has_wildcards = memchr::memchr3(b'*', b'?', b'[', pattern_bytes).is_some();

            let flags = (negated as u8) | ((anchored as u8) << 1) | ((dir_only as u8) << 2);

            if !has_wildcards && mid_anchor.is_none() {
                // --------- LITERAL PATTERN
                let offset = literal_data.len();
                let len = pattern_bytes.len();

                if len <= 255 && offset <= 0xFFFF {
                    literal_data.extend_from_slice(pattern_bytes);

                    literal_meta.push(LiteralMeta {
                        offset: offset as u16,
                        len: len as u8,
                        flags,
                    });

                    order.push(OrderEntry {
                        ty: 0,
                        index: (literal_meta.len() - 1) as u16,
                    });

                } else {
                    // Too long, treat as wildcard
                    wildcards.push(WildcardPattern {
                        bytes: pattern_bytes.to_vec().into_boxed_slice(),
                        flags,
                        mid_anchor: None,
                        suffix: None,
                        prefix: None,
                        trailing_double_star: None,
                        leading_double_star: false
                    });
                    order.push(OrderEntry {
                        ty: 1,
                        index: (wildcards.len() - 1) as u16,
                    });
                }

            } else {
                // --------- WILDCARD, or a mid_anchor "A/**/B" pattern where B happens
                // to be a plain literal -- either way it needs match_wildcard, so both
                // route through here.
                let (suffix, prefix) = if trailing_double_star.is_some() {
                    (None, None)
                } else if has_wildcards {
                    analyze_wildcard(pattern_bytes)
                } else {
                    (None, None) // literal tail, glob_match's no-wildcard fast path (pattern == text) covers it
                };

                wildcards.push(WildcardPattern {
                    bytes: pattern_bytes.into(),
                    flags,
                    suffix,
                    prefix,
                    mid_anchor,
                    trailing_double_star,
                    leading_double_star
                });
                order.push(OrderEntry {
                    ty: 1,
                    index: (wildcards.len() - 1) as u16,
                });
            }
        }

        let unanchored_indices: Vec<u16> = literal_meta.iter().enumerate()
            .filter(|(_, m)| !m.anchored())
            .map(|(i, _)| i as u16)
            .collect();

        let anchored_literal_indices = literal_meta.iter().enumerate()
            .filter(|(_, m)| m.anchored())
            .map(|(i, _)| i as u16)
            .collect();

        let unanchored_lookup = LiteralLookup::build(&literal_data, &literal_meta, &unanchored_indices);

        Self {
            has_negations,
            anchored_literal_indices,
            unanchored_lookup,
            literal_data: literal_data.into_boxed_slice(),
            literal_meta: literal_meta.into_boxed_slice(),
            wildcards: wildcards.into_boxed_slice(),
            order: order.into_boxed_slice(),
        }
    }

    /// Check if ignored, returns bool (for non-negation fast path)
    #[inline(always)]
    pub fn is_ignored_with_filename(&self, path: &[u8], filename: &[u8], is_dir: bool) -> bool {
        let filename_hash = fnv1a(filename);
        self.is_ignored_with_filename_hashed(path, filename, is_dir, filename_hash)
    }

    /// Check if ignored, returns bool (for non-negation fast path)
    #[inline(always)]
    pub fn is_ignored_with_filename_hashed(&self, path: &[u8], filename: &[u8], is_dir: bool, filename_hash: u64) -> bool {
        if self.order.is_empty() {
            return false;
        }

        if !self.has_negations {
            if self.unanchored_lookup.contains_hashed(&self.literal_data, &self.literal_meta, filename, is_dir, filename_hash) {
                return true;
            }

            for &idx in self.anchored_literal_indices.iter() {
                let meta = unsafe { *self.literal_meta.get_unchecked(idx as usize) };
                if meta.dir_only() && !is_dir { continue; }

                let len = meta.len as usize;
                let pattern = unsafe {
                    self.literal_data.get_unchecked(meta.offset as usize..meta.offset as usize + len)
                };

                if match_anchored_literal(pattern, path) {
                    return true;
                }
            }

            for pattern in self.wildcards.iter() {
                if pattern.dir_only() && !is_dir { continue; }

                let text = if pattern.anchored() { path } else { filename };
                if match_wildcard(pattern, text) {
                    return true;
                }
            }

            return false;
        }

        let mut result = false;

        for entry in self.order.iter() {
            if entry.ty == 0 {
                // ------ LITERAL
                let meta = unsafe { *self.literal_meta.get_unchecked(entry.index as usize) };

                if meta.dir_only() && !is_dir {
                    continue;
                }

                let len = meta.len as usize;
                let pattern = unsafe {
                    self.literal_data.get_unchecked(meta.offset as usize..meta.offset as usize + len)
                };

                let matched = if meta.anchored() {
                    match_anchored_literal(pattern, path)
                } else {
                    // @QuickCheck
                    filename.len() == len && filename == pattern
                };

                if matched {
                    result = !meta.negated();
                }
            } else {
                // -------- WILDCARD
                let pattern = unsafe { self.wildcards.get_unchecked(entry.index as usize) };

                if pattern.dir_only() && !is_dir {
                    continue;
                }

                let text = if pattern.anchored() { path } else { filename };
                let matched = match_wildcard(pattern, text);

                if matched {
                    result = !pattern.negated();
                }
            }
        }

        result
    }

    /// Check if ignored, returns MatchResult (for negation handling)
    #[inline]
    fn check_ignored_with_filename(&self, path: &[u8], filename: &[u8], is_dir: bool, filename_hash: u64) -> MatchResult {
        if self.order.is_empty() {
            return MatchResult::NoMatch;
        }

        if !self.has_negations {
            // @Cutnpaste from is_ignored_with_filename_hashed

            if self.unanchored_lookup.contains_hashed(&self.literal_data, &self.literal_meta, filename, is_dir, filename_hash) {
                return MatchResult::Ignored;
            }

            for &idx in self.anchored_literal_indices.iter() {
                let meta = unsafe { *self.literal_meta.get_unchecked(idx as usize) };
                if meta.dir_only() && !is_dir { continue; }

                let len = meta.len as usize;
                let pattern = unsafe {
                    debug_assert!(meta.offset as usize + len <= self.literal_data.len());
                    self.literal_data.get_unchecked(meta.offset as usize..meta.offset as usize + len)
                };

                if match_anchored_literal(pattern, path) {
                    return MatchResult::Ignored;
                }
            }

            for pattern in self.wildcards.iter() {
                if pattern.dir_only() && !is_dir { continue; }

                let text = if pattern.anchored() { path } else { filename };
                if match_wildcard(pattern, text) {
                    return MatchResult::Ignored;
                }
            }

            return MatchResult::NoMatch;
        }

        let mut result = MatchResult::NoMatch;

        for entry in self.order.iter() {
            if entry.ty == 0 {
                // ------ LITERAL
                let meta = unsafe { *self.literal_meta.get_unchecked(entry.index as usize) };

                if meta.dir_only() && !is_dir {
                    continue;
                }

                let len = meta.len as usize;
                let pattern = unsafe {
                    self.literal_data.get_unchecked(meta.offset as usize..meta.offset as usize + len)
                };

                let matched = if meta.anchored() {
                    match_anchored_literal(pattern, path)
                } else {
                    filename.len() == len && filename == pattern
                };

                if matched {
                    result = if meta.negated() {
                        MatchResult::Negated
                    } else {
                        MatchResult::Ignored
                    };
                }
            } else {
                // ------- WILDCARD
                let pattern = unsafe {
                    self.wildcards.get_unchecked(entry.index as usize)
                };

                if pattern.dir_only() && !is_dir {
                    continue;
                }

                let text = if pattern.anchored() { path } else { filename };

                if match_wildcard(pattern, text) {
                    result = if pattern.negated() {
                        MatchResult::Negated
                    } else {
                        MatchResult::Ignored
                    };
                }
            }
        }

        result
    }
}

/// Analyze wildcard pattern for fast-path matching
/// Returns (suffix, prefix) for patterns like "*.rs" or "test*"
#[allow(clippy::type_complexity)]
fn analyze_wildcard(pattern: &[u8]) -> (Option<Box<[u8]>>, Option<Box<[u8]>>) {
    if pattern.is_empty() {
        return (None, None);
    }

    //
    // Pattern "*.ext"
    //
    if pattern[0] == b'*' {
        let rest = &pattern[1..];
        if !rest.is_empty() && memchr::memchr3(b'*', b'?', b'[', rest).is_none() {
            return (Some(rest.into()), None);
        }
    }

    //
    // Pattern "prefix*"
    //
    if let Some(star_pos) = memchr(b'*', pattern) {
        if star_pos == pattern.len() - 1 {
            let head = &pattern[..star_pos];
            if !head.is_empty() && memchr::memchr3(b'*', b'?', b'[', head).is_none() {
                return (None, Some(head.into()));
            }
        }
    }

    (None, None)
}

/// Anchored literal pattern match: exact path equality only.
/// Matching a directory name does NOT implicitly cover paths nested under it -- that's
/// a property of the tree walk (skip recursing into an ignored dir), not of
/// a single-path check. See `match_anchored_dir_prefix` for the mid_anchor case.
#[inline(always)]
fn match_anchored_literal(pattern: &[u8], path: &[u8]) -> bool {
    pattern == path
}

/// Whether `prefix` is `path` itself, or a leading directory component of
/// `path` (followed by a separator).
///
/// Used only for the literal head of a mid_anchor "a/**/b" pattern --
/// "**" already accounts for zero or more intervening directories,
/// so this just confirms `prefix` is an ancestor.
#[inline(always)]
fn match_anchored_dir_prefix(prefix: &[u8], path: &[u8]) -> bool {
    let len = prefix.len();
    if len >= path.len() {
        return false;
    }

    let head = unsafe { path.get_unchecked(..len) };
    head == prefix && unsafe { *path.get_unchecked(len) } == MAIN_SEPARATOR as _
}

#[inline(always)]
fn match_wildcard(pattern: &WildcardPattern, text: &[u8]) -> bool {
    if pattern.leading_double_star {
        let mut start = 0usize;
        loop {
            if match_wildcard_anchored_at(pattern, &text[start..]) {
                return true;
            }
            match memchr(MAIN_SEPARATOR as u8, &text[start..]) {
                Some(off) => start += off + 1,
                None => return false,
            }
        }
    }

    match_wildcard_anchored_at(pattern, text)
}

#[inline(always)]
fn match_wildcard_anchored_at(pattern: &WildcardPattern, text: &[u8]) -> bool {
    if let Some(prefix) = &pattern.trailing_double_star {
        return if prefix.is_empty() {
            //
            // Bare "/**": matches everything inside the anchor point
            //

            !text.is_empty()
        } else {
            let pattern_len = prefix.len();

            //
            // Must be strictly *inside* the prefix directory, not equal to it
            //

            text.len() > pattern_len
                && unsafe { text.get_unchecked(..pattern_len) } == prefix.as_ref()
                && unsafe { *text.get_unchecked(pattern_len) }  == MAIN_SEPARATOR as u8
        };
    }

    //
    // mid_anchor patterns are always anchored, so `text` here is always the full path.
    //
    // Confirm the literal head, then match the tail against just the filename,
    // "**" has already accounted for zero-or-more directories in between.
    //
    if let Some(mid) = &pattern.mid_anchor {
        if !match_anchored_dir_prefix(mid, text) {
            return false;
        }

        let filename_start = memrchr(MAIN_SEPARATOR as u8, text).map_or(0, |i| i + 1);
        let filename = unsafe { text.get_unchecked(filename_start..) };
        return match_wildcard_tail(pattern, filename, false);
    }

    match_wildcard_tail(pattern, text, pattern.anchored())
}

#[inline(always)]
fn match_wildcard_tail(pattern: &WildcardPattern, text: &[u8], anchored: bool) -> bool {
    // Fast path: suffix match (*.rs), optionally combined with a prefix (dir/*.rs)
    if let Some(ref suffix) = pattern.suffix {
        debug_assert!(!suffix.is_empty(), "analyze_wildcard never produces an empty suffix");

        let suffix_len = suffix.len();
        if text.len() < suffix_len {
            return false;
        }

        // SAFETY: text.len() >= slen, checked above.
        let split = text.len() - suffix_len;
        let tail = unsafe { text.get_unchecked(split..) };
        if tail != suffix.as_ref() {
            return false;
        }

        let head = unsafe { text.get_unchecked(..split) };

        let middle = if let Some(ref prefix) = pattern.prefix {
            let pattern_len = prefix.len();
            if head.len() < pattern_len {
                return false;
            }

            // SAFETY: head.len() >= plen, checked above.
            if unsafe { head.get_unchecked(..pattern_len) } != prefix.as_ref() {
                return false;
            }

            unsafe { head.get_unchecked(pattern_len..) }
        } else {
            head
        };

        return !anchored || memchr(b'/', middle).is_none();
    }

    // Fast path: prefix match (test*)
    if let Some(ref prefix) = pattern.prefix {
        debug_assert!(!prefix.is_empty(), "analyze_wildcard never produces an empty prefix");

        let pattern_len = prefix.len();
        if text.len() < pattern_len {
            return false;
        }

        if unsafe { text.get_unchecked(..pattern_len) } != prefix.as_ref() {
            return false;
        }

        let middle = unsafe { text.get_unchecked(pattern_len..) };
        return !anchored || memchr::memchr(b'/', middle).is_none();
    }

    // Fallback
    glob_match(&pattern.bytes, text, anchored)
}

#[inline]
fn glob_match(pattern: &[u8], text: &[u8], anchored: bool) -> bool {
    let pattern_len = pattern.len();
    let text_len = text.len();

    if pattern_len == 0 {
        return text_len == 0;
    }

    // Fast path: no wildcards
    if memchr::memchr3(b'*', b'?', b'[', pattern).is_none() {
        return pattern == text;
    }

    let mut pattern_idx = 0;
    let mut text_idx = 0;
    let mut star_idx = usize::MAX;
    let mut star_run_end = usize::MAX;
    let mut match_idx = 0;

    //
    // Whether the star run at star_idx..star_run_end is a "**" standing as
    // its own path component (bounded by '/' or pattern start/end on both
    // sides).
    //
    // Such a run may swallow '/' characters; an ordinary '*' (or a
    // "**" embedded mid-token, which gitignore considers invalid) may not,
    // when `anchored`.
    //
    // Per gitignore(5): a bare/leading/trailing "**"
    // component crosses directory separators; a single "*" never does.
    //
    let mut star_can_cross = false;

    while text_idx < text_len {
        if pattern_idx < pattern_len {
            let p_char = unsafe { *pattern.get_unchecked(pattern_idx) };

            match p_char {
                b'*' => {
                    let run_start = pattern_idx;
                    let mut run_end = pattern_idx + 1;
                    while run_end < pattern_len && unsafe { *pattern.get_unchecked(run_end) } == b'*' {
                        run_end += 1;
                    }

                    let left_ok = run_start == 0
                        || unsafe { *pattern.get_unchecked(run_start - 1) } == MAIN_SEPARATOR as u8;

                    let right_ok = run_end == pattern_len
                        || unsafe { *pattern.get_unchecked(run_end) } == MAIN_SEPARATOR as u8;

                    star_can_cross = (run_end - run_start) == 2 && left_ok && right_ok;

                    //
                    // A "**/" component may match zero directories, in which case it
                    // (and its trailing separator) contributes nothing at all -- e.g.
                    // "**/foo" must match bare "foo".
                    //
                    // The backtracking below only ever tries "one or more directories"
                    // (by requiring an actual separator to occur later in `text`),
                    // so handle zero-and-more explicitly via recursion
                    // whenever a "**" is immediately followed by a separator.
                    //
                    if star_can_cross && right_ok && run_end < pattern_len {
                        let rest = &pattern[run_end + 1..];

                        //
                        // Zero directories -- "**/" vanishes entirely
                        //
                        if glob_match(rest, &text[text_idx..], anchored) {
                            return true;
                        }

                        //
                        // One or more directories --
                        //
                        // try consuming through each subsequent separator in turn.
                        //
                        let mut search_from = text_idx;
                        loop {
                            match memchr(MAIN_SEPARATOR as u8, &text[search_from..text_len]) {
                                Some(off) => {
                                    let sep_pos = search_from + off;
                                    if glob_match(rest, &text[sep_pos + 1..], anchored) {
                                        return true;
                                    }

                                    search_from = sep_pos + 1;
                                }

                                None => return false,
                            }
                        }
                    }

                    star_idx = run_start;
                    star_run_end = run_end;
                    match_idx = text_idx;
                    pattern_idx = run_end;
                    continue;
                }

                b'?' => {
                    // '?' must not match a separator either, when anchored
                    if anchored && unsafe { *text.get_unchecked(text_idx) } == MAIN_SEPARATOR as u8 {
                        // Fallthrough to backtrack logic below...
                    } else {
                        pattern_idx += 1;
                        text_idx += 1;
                        continue;
                    }
                }

                b'[' => {
                    let ch = unsafe { *text.get_unchecked(text_idx) };
                    let sep_blocked = anchored && ch == MAIN_SEPARATOR as u8;

                    match match_char_class(pattern, pattern_idx, ch) {
                        Some((new_p, true)) if !sep_blocked => {
                            pattern_idx = new_p;
                            text_idx += 1;
                            continue;
                        }

                        Some(_) => {
                            //
                            // Well-formed class, this char just isn't in it (or hit the
                            // anchored-separator guard) -- fall through to backtrack.
                            //
                        }

                        None if ch == b'[' && !sep_blocked => {
                            //
                            // No closing ']' anywhere in the pattern -- malformed bracket
                            // expression, treat '[' as an ordinary literal char instead
                            // of aborting the whole match.
                            //
                            pattern_idx += 1;
                            text_idx += 1;
                            continue;
                        }

                        _ => {}
                    }
                }

                c if c == unsafe { *text.get_unchecked(text_idx) } => {
                    pattern_idx += 1;
                    text_idx += 1;
                    continue;
                }

                _ => {}
            }
        }

        if star_idx == usize::MAX {
            return false;
        }

        let next_pat_idx = star_run_end;
        let crossable = star_can_cross;

        let next_lit = if next_pat_idx < pattern_len {
            let b = unsafe { *pattern.get_unchecked(next_pat_idx) };
            (b != b'*' && b != b'?' && b != b'[').then_some(b)
        } else {
            None
        };

        match next_lit {
            Some(lit) => {
                let search_start = match_idx + 1;
                debug_assert!(search_start <= text_len);
                let haystack = unsafe { text.get_unchecked(search_start..text_len) };

                //
                // An anchored '*' can't swallow a '/', so normally we must not
                // search past one. EXCEPT when the literal we're looking for
                // IS '/' itself (e.g. pattern "a/*b/c"), then finding that
                // separator IS the goal.
                //
                let bound = if anchored && !crossable && lit != MAIN_SEPARATOR as u8 {
                    memchr(MAIN_SEPARATOR as u8, haystack).unwrap_or(haystack.len())
                } else {
                    haystack.len()
                };

                let scoped = unsafe { haystack.get_unchecked(..bound) };
                match memchr(lit, scoped) {
                    Some(off) => {
                        match_idx   = search_start + off;
                        text_idx    = match_idx;
                        pattern_idx = next_pat_idx;
                    }

                    None => return false,
                }
            }

            None => {
                //
                // Trailing star, or followed by another wildcard token
                //

                if anchored && !crossable && unsafe { *text.get_unchecked(text_idx) } == MAIN_SEPARATOR as u8 {
                    return false;
                }
                pattern_idx = next_pat_idx;
                match_idx += 1;
                text_idx = match_idx;
            }
        }
    }

    //
    // Skip trailing stars
    //
    while pattern_idx < pattern_len && unsafe { *pattern.get_unchecked(pattern_idx) } == b'*' {
        pattern_idx += 1;
    }

    pattern_idx == pattern_len
}

/// Returns `None` if there's no closing `]` anywhere (malformed, caller
/// should treat `[` as an ordinary literal character, per POSIX fnmatch
/// convention).
///
/// Returns `Some((next_pattern_idx, matched))` for a well-formed class,
/// whether or not `ch` actually matched it.
fn match_char_class(pattern: &[u8], start: usize, ch: u8) -> Option<(usize, bool)> {
    let pattern_len = pattern.len();
    if start + 2 >= pattern_len || unsafe { *pattern.get_unchecked(start) } != b'[' {
        return None;
    }

    let negated =
        unsafe { *pattern.get_unchecked(start + 1) } == b'!'
     || unsafe { *pattern.get_unchecked(start + 1) } == b'^';

    let mut i = if negated { start + 2 } else { start + 1 };

    // Find closing ]
    let mut end = i;
    while end < pattern_len && unsafe { *pattern.get_unchecked(end) } != b']' {
        end += 1;
    }
    if end >= pattern_len {
        return None;
    }

    let mut matched = false;
    while i < end {
        if i + 2 < end && unsafe { *pattern.get_unchecked(i + 1) } == b'-' {
            let lo = unsafe { *pattern.get_unchecked(i) };
            let hi = unsafe { *pattern.get_unchecked(i + 2) };

            if ch >= lo && ch <= hi {
                matched = true;
                break;
            }

            i += 3;
        } else {
            if ch == unsafe { *pattern.get_unchecked(i) } {
                matched = true;
                break;
            }

            i += 1;
        }
    }

    Some((end + 1, matched != negated))
}

#[inline(always)]
fn trim_bytes(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    if end == 0 {
        return bytes;
    }

    if unlikely(bytes[end - 1] == b'\r') {
        end -= 1;
    }

    while end > 0 && bytes[end - 1] == b' ' {
        let backslash_run = bytes[..end - 1]
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count();

        if unlikely(backslash_run % 2 == 1) {
            break;
        }

        end -= 1;
    }

    unsafe { bytes.get_unchecked(..end) }
}

#[inline]
pub fn build_gitignore_from_bytes(content: &[u8]) -> Gitignore {
    Gitignore::from_bytes(content)
}

/// Build gitignore from a file path
/// Returns None if file doesn't exist or can't be read
#[inline]
pub fn build_gitignore_from_file(gitignore_path: &str) -> Option<Gitignore> {
    use std::fs;
    use std::path::Path;

    let path = Path::new(gitignore_path);

    // Read file contents
    let content = fs::read(path).ok()?;

    Some(Gitignore::from_bytes(&content))
}

/// Path relative to the directory that owns a given stack entry's gitignore.
#[inline(always)]
fn relative_path(path: &[u8], prefix_len: u32) -> &[u8] {
    let prefix_len = prefix_len as usize;
    if prefix_len == 0 {
        // Root gitignore: nothing to strip, and there's no leading
        // separator to skip since the first path segment is pushed with
        // needs_slash = false.
        path
    } else if path.len() <= prefix_len {
        &[]
    } else {
        // Skip the owning directory's path *and* the separator that was
        // inserted when descending into its first child.
        unsafe { path.get_unchecked(prefix_len + 1..) }
    }
}
