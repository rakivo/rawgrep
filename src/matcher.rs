use std::io;

use regex::bytes::Regex;
use memchr::memmem::Finder;
use aho_corasick::AhoCorasick;

use crate::tracy;

#[inline]
fn extract_literal(pattern: &str) -> Option<Vec<u8>> {
    let trimmed = pattern.trim_start_matches('^').trim_end_matches('$');

    // Check for regex metacharacters
    if trimmed.chars().any(|c| ".*+?[]{}()|\\^$".contains(c)) {
        return None;
    }

    Some(trimmed.as_bytes().to_vec())
}

#[inline]
fn extract_alternation_literals(pattern: &str) -> Option<Vec<Vec<u8>>> {
    if !pattern.contains('|') {
        return None;
    }

    let parts = pattern.split('|').collect::<Vec<_>>();
    let mut literals = Vec::new();

    for part in parts {
        let trimmed = part.trim_start_matches('^').trim_end_matches('$');
        if trimmed.chars().any(|c| ".*+?[]{}()\\^$".contains(c)) {
            return None; // Contains regex metacharacters
        }
        literals.push(trimmed.as_bytes().to_vec());
    }

    Some(literals)
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
        let _span = tracy::span!("MatchIterator::next");
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
    Literal(Finder<'static>),  // Single literal: "error"
    MultiLiteral(AhoCorasick), // Multiple: "error|warning|fatal"
    Regex(Regex),              // Complex patterns
}

impl Matcher {
    pub fn new(pattern: &str) -> io::Result<Self> {
        let _span = tracy::span!("Matcher::new");

        // Try literal extraction first
        if let Some(literal) = extract_literal(pattern) {
            return Ok(Matcher::Literal(Finder::new(&literal).into_owned()));
        }

        // Try alternation extraction: "foo|bar|baz"
        if let Some(literals) = extract_alternation_literals(pattern) {
            return AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::LeftmostFirst)
                .build(&literals)
                .map(Matcher::MultiLiteral)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid alternation pattern '{pattern}': {e}")
                    )
                });
        }

        // Fallback to regex
        Regex::new(pattern)
            .map(Matcher::Regex)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid regex '{pattern}': {e}")
                )
            })
    }

    #[inline(always)]
    pub fn is_match(&self, haystack: &[u8]) -> bool {
        match self {
            Matcher::Literal(finder) => finder.find(haystack).is_some(),
            Matcher::MultiLiteral(ac) => ac.is_match(haystack),
            Matcher::Regex(re) => re.is_match(haystack),
        }
    }

    #[inline(always)]
    pub fn find_at(&self, haystack: &[u8], start: usize) -> Option<(usize, usize)> {
        // Bounds check to prevent panics in slicing
        if start >= haystack.len() {
            return None;
        }

        match self {
            Matcher::Literal(finder) => {
                // memchr returns index relative to the slice provided
                finder.find(&haystack[start..]).map(|i| {
                    let real_start = start + i;
                    (real_start, real_start + finder.needle().len())
                })
            }
            Matcher::MultiLiteral(ac) => {
                // Aho-Corasick returns index relative to the slice provided
                ac.find(&haystack[start..]).map(|m| {
                    (start + m.start(), start + m.end())
                })
            }
            Matcher::Regex(re) => {
                // Regex::find_at takes the WHOLE buffer and a start index.
                // It returns ABSOLUTE indices, so we do NOT add `start` here.
                re.find_at(haystack, start).map(|m| (m.start(), m.end()))
            }
        }
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
            Matcher::MultiLiteral(ac) => {
                MatchIterator::MultiLiteral(ac.find_iter(haystack))
            }
            Matcher::Regex(re) => {
                MatchIterator::Regex(re.find_iter(haystack))
            }
        }
    }
}
