use std::io;

use regex::bytes::Regex;
use memchr::memmem::Finder;
use aho_corasick::AhoCorasick;

use crate::{cli::Cli, tracy};

const REGEX_METACHARS: &str = ".*+?[]{}()|\\^$";

#[inline]
fn extract_literal(pattern: &str) -> Option<Box<[u8]>> {
    let trimmed = pattern.trim_start_matches('^').trim_end_matches('$');

    if trimmed.chars().any(|c| REGEX_METACHARS.contains(c)) {
        return None;
    }

    Some(trimmed.as_bytes().into())
}

#[inline]
fn extract_alternation_literals(pattern: &str) -> Option<Box<[Box<[u8]>]>> {
    if !pattern.contains('|') {
        return None;
    }

    let parts = pattern.split('|').collect::<Vec<_>>();
    let mut literals = Vec::new();

    for part in parts {
        let Some(literal) = extract_literal(part) else {
            continue;
        };

        literals.push(literal);
    }

    Some(literals.into())
}

// NOTE:
//   `Literal::iter` is 320 bytes,
//   the second-largest variant contains at least 120 bytes,
//   so the entire enum is 352 bytes.
//
//   clippy advises us to Box `iter`, but I don't think that
//   the overhead of having 1 more indirection (AND allocating on the heap) really worth it.
#[allow(clippy::large_enum_variant)]
pub enum MatchIterator<'a> {
    Literal {
        iter: memchr::memmem::FindIter<'a, 'a>,
        needle_len: usize,
    },
    MultiLiteral(aho_corasick::FindIter<'a, 'a>),
    Regex(regex::bytes::Matches<'a, 'a>),
}

impl<'a> Iterator for MatchIterator<'a> {
    type Item = (usize, usize);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            MatchIterator::Literal { iter, needle_len } => {
                iter.next().map(|pos| (pos, pos + *needle_len))
            }
            MatchIterator::MultiLiteral(iter) => {
                iter.next().map(|m| (m.start(), m.end()))
            }
            MatchIterator::Regex(iter) => {
                iter.next().map(|m| (m.start(), m.end()))
            }
        }
    }
}

// NOTE: Read the `NOTE` above
#[allow(clippy::large_enum_variant)]
pub enum Matcher {
    Literal(Finder<'static>),
    MultiLiteral {
        ac: AhoCorasick,
        patterns: Box<[Box<[u8]>]>,  // Keep original patterns for fragment extraction
    },
    Regex {
        re: Regex,
        pattern: Box<str>,  // Keep original pattern for literal extraction
    },
}

impl Matcher {
    pub fn new(cli: &Cli) -> io::Result<Self> {
        let _span = tracy::span!("Matcher::new");

        let pattern = &cli.pattern;

        if cli.force_literal {
            return Ok(Matcher::Literal(Finder::new(pattern.as_bytes()).into_owned()));
        }

        // Try literal extraction first
        if let Some(literal) = extract_literal(pattern) {
            return Ok(Matcher::Literal(Finder::new(&literal).into_owned()));
        }

        // Try alternation extraction: "foo|bar|baz"
        if let Some(literals) = extract_alternation_literals(pattern) {
            let ac = AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::LeftmostFirst)
                .build(&literals)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid alternation pattern '{pattern}': {e}")
                    )
                })?;

            return Ok(Matcher::MultiLiteral {
                ac,
                patterns: literals,
            });
        }

        // Fallback to regex
        let re = Regex::new(pattern).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid regex '{pattern}': {e}")
            )
        })?;

        Ok(Matcher::Regex { re, pattern: pattern.clone().into_boxed_str() })
    }

    #[inline(always)]
    pub fn find_matches<'a>(&'a self, haystack: &'a [u8]) -> MatchIterator<'a> {
        match self {
            Matcher::Literal(finder) => {
                MatchIterator::Literal {
                    iter: finder.find_iter(haystack),
                    needle_len: finder.needle().len(),
                }
            }
            Matcher::MultiLiteral { ac, .. } => {
                MatchIterator::MultiLiteral(ac.find_iter(haystack))
            }
            Matcher::Regex { re, .. } => {
                MatchIterator::Regex(re.find_iter(haystack))
            }
        }
    }

    /// Extract fragment hashes for this matcher, along with the single fragment length
    /// (3 or 4) used to compute all of them.
    ///
    /// Returns `None` if the fragment cache should be skipped entirely for this pattern e.g.
    /// because some literal (or, for alternations/regex, the shortest literal) is under
    /// `MIN_FRAGMENT_LEN`. Callers must not fall back to a smaller fragment in that case;
    /// see `select_fragment_len`'s docs for why.
    pub fn extract_fragment_hashes(&self) -> Option<(Vec<u32>, usize)> {
        use nohash_hasher::IntSet;

        match self {
            Matcher::Literal(finder) => {
                let needle = finder.needle();
                let fragment_len = crate::fragments::select_fragment_len(std::iter::once(needle))?;
                let hashes = crate::fragments::extract_pattern_fragments_with_len(needle, fragment_len);
                Some((hashes, fragment_len))
            }

            Matcher::MultiLiteral { patterns, .. } => {
                //
                // One fragment length shared across every alternation branch, must be chosen
                // from the shortest branch, not per-branch (see select_fragment_len docs).
                //
                let fragment_len = crate::fragments::select_fragment_len(
                    patterns.iter().map(|p| p.as_ref())
                )?;

                let mut all_fragments = IntSet::default();
                for pattern in patterns.iter() {
                    let frags = crate::fragments::extract_pattern_fragments_with_len(pattern, fragment_len);
                    all_fragments.extend(frags);
                }
                Some((all_fragments.into_iter().collect(), fragment_len))
            }

            Matcher::Regex { pattern, .. } => {
                extract_regex_literals(pattern)
            }
        }
    }
}

/// Extract literal substrings from a regex pattern for the fragment cache, all hashed with
/// one shared fragment length (the shortest literal part). Returns `None` if there are no
/// usable literal parts, or the shortest one is under `MIN_FRAGMENT_LEN`.
fn extract_regex_literals(pattern: &str) -> Option<(Vec<u32>, usize)> {
    use nohash_hasher::IntSet;

    // Split on common regex operators to find literal parts
    let parts: Vec<&[u8]> = pattern
        .split(|c| ".*+?{[(".contains(c))
        .filter(|s| !s.is_empty())
        // Skip parts that still contain other regex metacharacters -- not a clean literal.
        .filter(|part| !part.chars().any(|c| "\\^$|)]}>".contains(c)))
        .map(str::as_bytes)
        .collect();

    if parts.is_empty() {
        return None;
    }

    let fragment_len = crate::fragments::select_fragment_len(parts.iter().copied())?;

    let mut all_fragments = IntSet::default();
    for part in &parts {
        let frags = crate::fragments::extract_pattern_fragments_with_len(part, fragment_len);
        all_fragments.extend(frags);
    }

    Some((all_fragments.into_iter().collect(), fragment_len))
}
