//! Property test for the one thing that actually matters here: every
//! literal `required_literals` reports for a pattern must be a substring
//! of *every* string that pattern can match.

use rawgrep::extractor::*;
use regex_syntax::Parser;

fn parts_of(pattern: &str) -> Vec<Vec<u8>> {
    let hir = Parser::new().parse(pattern).unwrap();
    let mut parts = required_literals(&hir);
    parts.sort();
    parts
}

fn s(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // xorshift64* needs a nonzero seed.
        Rng(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn range(&mut self, lo: u32, hi_inclusive: u32) -> u32 {
        debug_assert!(hi_inclusive >= lo);
        let span = (hi_inclusive - lo) as u64 + 1;
        lo + (self.next_u64() % span) as u32
    }
}

#[derive(Debug, Clone)]
enum Node {
    Lit(&'static str),
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat(Box<Node>, u32, u32),
    Class(&'static [char]),
}

const LITERAL_POOL: &[&str] = &["a", "ab", "b", "bc", "c", "ca", "x", "y", "foo", "bar"];
const CLASS_POOL: &[char] = &['a', 'b', 'c', 'd', 'e'];

fn gen_node(rng: &mut Rng, depth: u32) -> Node {
    if depth == 0 {
        return gen_leaf(rng);
    }
    match rng.range(0, 4) {
        0 | 1 => gen_leaf(rng),
        2 => {
            let n = rng.range(1, 3);
            Node::Concat((0..n).map(|_| gen_node(rng, depth - 1)).collect())
        }
        3 => {
            let n = rng.range(2, 3);
            Node::Alt((0..n).map(|_| gen_node(rng, depth - 1)).collect())
        }
        _ => {
            let min = rng.range(0, 3);
            let max = min + rng.range(0, 2);
            Node::Repeat(Box::new(gen_node(rng, depth - 1)), min, max)
        }
    }
}

fn gen_leaf(rng: &mut Rng) -> Node {
    if rng.range(0, 3) == 0 {
        let n = rng.range(1, 3) as usize;
        Node::Class(&CLASS_POOL[..n])
    } else {
        let idx = rng.range(0, LITERAL_POOL.len() as u32 - 1) as usize;
        Node::Lit(LITERAL_POOL[idx])
    }
}

fn pattern_of(n: &Node) -> String {
    match n {
        Node::Lit(s) => (*s).to_string(),
        Node::Concat(v) => v.iter().map(pattern_of).collect(),
        Node::Alt(v) => format!(
            "(?:{})",
            v.iter().map(pattern_of).collect::<Vec<_>>().join("|")
        ),
        Node::Repeat(inner, lo, hi) => format!("(?:{}){{{},{}}}", pattern_of(inner), lo, hi),
        Node::Class(cs) => format!("[{}]", cs.iter().collect::<String>()),
    }
}

fn sample_match(n: &Node, rng: &mut Rng) -> String {
    match n {
        Node::Lit(s) => (*s).to_string(),
        Node::Concat(v) => v.iter().map(|c| sample_match(c, rng)).collect(),
        Node::Alt(v) => {
            let i = rng.range(0, v.len() as u32 - 1) as usize;
            sample_match(&v[i], rng)
        }
        Node::Repeat(inner, lo, hi) => {
            let k = if hi > lo { rng.range(*lo, *hi) } else { *lo };
            (0..k).map(|_| sample_match(inner, rng)).collect()
        }
        Node::Class(cs) => {
            let i = rng.range(0, cs.len() as u32 - 1) as usize;
            cs[i].to_string()
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

const SAMPLES_PER_PATTERN: u32 = 50;
const CASES: u32 = 100_000;

#[test]
fn every_extracted_literal_is_present_in_every_sampled_match() {
    for case in 0..CASES {
        let mut build_rng = Rng::new(0x9E3779B97F4A7C15u64.wrapping_add(case as u64));
        let root = gen_node(&mut build_rng, 4);
        let pattern = pattern_of(&root);

        let hir = match Parser::new().parse(&pattern) {
            Ok(h) => h,
            Err(_) => continue, // generator can produce a degenerate pattern; not what we're testing
        };
        let parts = required_literals(&hir);
        if parts.is_empty() {
            continue;
        }

        for sample_idx in 0..SAMPLES_PER_PATTERN {
            let mut sample_rng = Rng::new(
                0xC2B2AE3D27D4EB4Fu64
                    .wrapping_add(case as u64 * 1_000_003)
                    .wrapping_add(sample_idx as u64),
            );
            let sample = sample_match(&root, &mut sample_rng);
            let sample_bytes = sample.as_bytes();

            for part in &parts {
                assert!(
                    contains(sample_bytes, part),
                    "UNSOUND: pattern {:?} (case {}) claimed required literal {:?} \
                     but sampled match {:?} does not contain it",
                    pattern,
                    case,
                    String::from_utf8_lossy(part),
                    sample
                );
            }
        }
    }
}

#[test]
fn coverage_sanity_check() {
    let mut parsed_ok = 0u32;
    let mut nonempty_parts = 0u32;
    let mut multi_part = 0u32;
    let mut max_parts_seen = 0usize;
    let mut multi_copy_repeat_merges = 0u32;
    let mut alternation_candidates_found = 0u32;
    for case in 0..CASES {
        let mut build_rng = Rng::new(0x9E3779B97F4A7C15u64.wrapping_add(case as u64));
        let root = gen_node(&mut build_rng, 4);
        let pattern = pattern_of(&root);
        let hir = match Parser::new().parse(&pattern) {
            Ok(h) => h,
            Err(_) => continue,
        };
        parsed_ok += 1;
        let parts = required_literals(&hir);
        if !parts.is_empty() {
            nonempty_parts += 1;
        }
        if parts.len() > 1 {
            multi_part += 1;
        }
        max_parts_seen = max_parts_seen.max(parts.len());

        // A part longer than any single pool literal (max 3 bytes) is
        // evidence the min-copies repetition merge actually fired.
        if parts.iter().any(|p| p.len() > 3) {
            multi_copy_repeat_merges += 1;
        }
        if pattern.contains('|') && !parts.is_empty() {
            alternation_candidates_found += 1;
        }
    }
    eprintln!(
        "parsed_ok={parsed_ok}/{CASES} nonempty_parts={nonempty_parts} multi_part={multi_part} \
         max_parts_seen={max_parts_seen} multi_copy_repeat_merges={multi_copy_repeat_merges} \
         alternation_cases_with_findings={alternation_candidates_found}"
    );
    assert!(parsed_ok > CASES / 2, "generator producing too many invalid patterns");
    assert!(nonempty_parts > CASES / 4, "extractor rarely finding anything, test may be vacuous");
    assert!(multi_part > 0, "never exercised the multi-part / alternation-prefix path");
    assert!(
        multi_copy_repeat_merges > 0,
        "never observed a repetition min-copies merge longer than a single pool literal"
    );
}

#[test]
fn plain_literal() {
    assert_eq!(parts_of("abcdef"), vec![s(b"abcdef")]);
}

#[test]
fn optional_char_does_not_poison_the_surrounding_literal() {
    // This is the original bug: "abc?def" used to be treated as requiring
    // the literal "abc", but "c" is optional, so "abdef" is a real match
    // that contains neither "abc" nor "abcdef".
    let parts = parts_of("abc?def");
    assert_eq!(parts, vec![s(b"ab"), s(b"def")]);
    assert!(!parts.contains(&s(b"abc")));
}

#[test]
fn optional_group_does_not_poison_the_surrounding_literal() {
    let parts = parts_of("(bc)?d");
    assert_eq!(parts, vec![s(b"d")]);
}

#[test]
fn bounded_repetition_with_nonzero_min_is_required() {
    // min=2 means two copies of "a" are guaranteed back-to-back,
    // regardless of whether the match actually repeated 2 or 3 times.
    let parts = parts_of("a{2,3}b");
    assert_eq!(parts, vec![s(b"aa"), s(b"b")]);
}

#[test]
fn bounded_repetition_with_zero_min_is_not_required() {
    let parts = parts_of("a{0,3}b");
    assert_eq!(parts, vec![s(b"b")]);
}

#[test]
fn escaped_metachar_merges_into_surrounding_literal() {
    // regex-syntax resolves the escape to its literal byte before we ever
    // see the Hir, so this recovers the full literal in one piece, which
    // the byte-scanning version could not do at all.
    assert_eq!(parts_of(r"foo\.bar"), vec![s(b"foo.bar")]);
}

#[test]
fn anchors_do_not_block_extraction_of_interior_literal() {
    assert_eq!(parts_of("^foo$"), vec![s(b"foo")]);
}

#[test]
fn word_boundary_does_not_block_extraction() {
    assert_eq!(parts_of(r"\bfoo\b"), vec![s(b"foo")]);
}

#[test]
fn non_capturing_group_is_transparent() {
    assert_eq!(parts_of("(?:abc)def"), vec![s(b"abcdef")]);
}

#[test]
fn capturing_group_merges_into_surrounding_literal() {
    assert_eq!(parts_of("(?P<name>foo)bar"), vec![s(b"foobar")]);
}

#[test]
fn nested_capturing_groups_merge() {
    assert_eq!(parts_of("((a)(b))c"), vec![s(b"abc")]);
}

#[test]
fn nongreedy_repetition_min_is_still_required() {
    // Laziness affects search order, not whether the minimum count of
    // repeats is required to exist somewhere in the match.
    assert_eq!(parts_of("a{2,4}?b"), vec![s(b"aa"), s(b"b")]);
}

#[test]
fn alternation_alone_yields_nothing() {
    assert_eq!(parts_of("(?:foo|bar)"), Vec::<Vec<u8>>::new());
}

#[test]
fn alternation_shares_common_prefix() {
    let parts = parts_of("(?:abcfoo|abcbar)");
    assert_eq!(parts, vec![s(b"abc")]);
}

#[test]
fn alternation_shares_common_suffix() {
    let parts = parts_of("(?:fooxyz|barxyz)");
    assert_eq!(parts, vec![s(b"xyz")]);
}

#[test]
fn alternation_shares_both_prefix_and_suffix() {
    let mut parts = parts_of("(?:abcfooxyz|abcbarxyz)");
    parts.sort();
    let mut expected = vec![s(b"abc"), s(b"xyz")];
    expected.sort();
    assert_eq!(parts, expected);
}

#[test]
fn alternation_with_empty_branch_yields_nothing() {
    // "foo|" can match the empty string, so nothing at all is guaranteed.
    assert_eq!(parts_of("(?:foo|)"), Vec::<Vec<u8>>::new());
}

#[test]
fn alternation_wrapping_shared_prefix_and_suffix_literal() {
    // prefix(bar|baz)suffix, the motivating example from the original ask.
    let mut parts = parts_of("foo(?:bar|baz)qux");
    parts.sort();
    let mut expected = vec![s(b"foo"), s(b"ba"), s(b"qux")];
    expected.sort();
    assert_eq!(parts, expected);
}

#[test]
fn multi_element_char_class_yields_nothing() {
    assert_eq!(parts_of("[abc]"), Vec::<Vec<u8>>::new());
}

#[test]
fn singleton_char_class_is_a_literal() {
    // regex-syntax folds this into a Literal before we see it.
    assert_eq!(parts_of("[a]"), vec![s(b"a")]);
}

#[test]
fn case_insensitive_flag_yields_nothing() {
    // Neither "abc" nor "ABC" nor any other case variant is uniquely
    // required, so correctly nothing is extracted.
    assert_eq!(parts_of("(?i)abc"), Vec::<Vec<u8>>::new());
}

#[test]
fn top_level_optional_yields_nothing() {
    assert_eq!(parts_of("a?"), Vec::<Vec<u8>>::new());
}

#[test]
fn dot_breaks_the_literal_run() {
    let parts = parts_of("ab.cd");
    assert_eq!(parts, vec![s(b"ab"), s(b"cd")]);
}

#[test]
fn lookaround_is_a_parse_error_not_our_problem() {
    // Confirms the assumption the whole design leans on: patterns using
    // lookaround never reach required_literals in the first place, because
    // they never successfully parse as a regex-syntax Hir. The wrapper
    // function's .ok()? on the parse falls back to None (no prefilter,
    // scan everything), which is always sound.
    assert!(Parser::new().parse(r"(?=foo)bar").is_err());
    assert!(Parser::new().parse(r"foo(?<!bar)").is_err());
}

#[test]
fn backreference_is_also_a_parse_error() {
    assert!(Parser::new().parse(r"(foo)\1").is_err());
}

#[test]
fn repetition_of_multibyte_literal_concatenates_min_copies() {
    let parts = parts_of("(?:ab){3,5}");
    assert_eq!(parts, vec![s(b"ababab")]);
}

#[test]
fn repetition_of_nonliteral_does_not_merge_across_copies() {
    // "ayay" is a real match for this pattern and does not contain "aa"
    // anywhere -- the two "a"s are not adjacent, because a variable "x"
    // or "y" from the class sits between each copy's own "a". Merging
    // the per-copy required part ("a") into "aa" here would be unsound.
    let parts = parts_of("(?:a[xy]){2,3}");
    assert_eq!(parts, vec![s(b"a")]);
    assert!(!parts.contains(&s(b"aa")));
}

#[test]
fn repetition_min_copy_literal_is_capped_not_unbounded() {
    let hir = Parser::new().parse("a{100000}").unwrap();
    let parts = required_literals(&hir);
    assert_eq!(parts.len(), 1);
    assert!(
        parts[0].len() <= MAX_REPEATED_LITERAL_BYTES,
        "repeated-literal materialization should be capped, got {} bytes",
        parts[0].len()
    );
    assert!(parts[0].iter().all(|&b| b == b'a'));
}

#[test]
fn alternation_finds_shared_substring_in_the_interior_not_just_the_ends() {
    // Neither branch shares a prefix or a suffix with the other, but
    // both are guaranteed to contain "123" in the middle.
    let parts = parts_of("(?:foo[a-z]123bar|baz[a-z]123qux)");
    assert!(
        parts.contains(&s(b"123")),
        "expected \"123\" among interior-shared candidates, got {:?}",
        parts
            .iter()
            .map(|p| String::from_utf8_lossy(p))
            .collect::<Vec<_>>()
    );
}

#[test]
fn alternation_below_min_substring_length_is_dropped() {
    // "xay" vs "zay" share the length-2 suffix "ay"; a lone single-byte
    // match should not additionally appear as its own candidate.
    let parts = parts_of("(?:xay|zay)");
    assert!(parts.contains(&s(b"ay")));
    assert!(!parts.contains(&s(b"a")));
    assert!(!parts.contains(&s(b"y")));
}
