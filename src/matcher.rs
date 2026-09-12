#![allow(unsafe_op_in_unsafe_fn)]

use crate::{cli::Cli, tracy};
use crate::extractor::{extract_regex_literals, literal_bytes, as_exact_alternation};

use std::io;

use memchr::memmem::Finder;
use aho_corasick::AhoCorasick;
use regex_automata::meta::{Regex as MetaRegex, Cache as MetaCache};

#[cfg(feature = "hyperscan")]
use hyperscan::prelude::*;

struct RegexMatchIter<'a> {
    re: &'a MetaRegex,
    cache: &'a mut MetaCache,
    haystack: &'a [u8],
    at: usize,
}

impl<'a> Iterator for RegexMatchIter<'a> {
    type Item = (usize, usize);

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.at > self.haystack.len() {
            return None;
        }

        let input = regex_automata::Input::new(self.haystack).span(self.at..self.haystack.len());
        let m = self.re.search_with(self.cache, &input)?;

        let start = m.start();
        let end = m.end();
        self.at = if start == end { end + 1 } else { end };

        Some((start, end))
    }
}

// NOTE:
//   `Literal::iter` is 320 bytes,
//   the second-largest variant contains at least 120 bytes,
//   so the entire enum is 352 bytes.
//
//   clippy advises us to Box `iter`, but I don't think that
//   the overhead of having 1 more indirection (AND allocating on the heap) really worth it.
#[allow(clippy::large_enum_variant)]
enum MatchIterator<'a> {
    Literal {
        needle_len: usize,
        iter: memchr::memmem::FindIter<'a, 'a>,
    },
    MultiLiteral(aho_corasick::FindIter<'a, 'a>),
    Regex(RegexMatchIter<'a>),
}

impl<'a> Iterator for MatchIterator<'a> {
    type Item = (usize, usize);

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            MatchIterator::Literal { iter, needle_len } => {
                iter.next().map(|pos| (pos, pos + *needle_len))
            }

            MatchIterator::MultiLiteral(iter) => {
                iter.next().map(|m| (m.start(), m.end()))
            }

            MatchIterator::Regex(re) => re.next()
        }
    }
}

#[cfg(feature = "hyperscan")]
#[allow(dead_code)]
pub struct SendSyncScratch(Scratch);

#[cfg(feature = "hyperscan")]
unsafe impl Sync for SendSyncScratch {}

#[cfg(feature = "hyperscan")]
unsafe impl Send for SendSyncScratch {}

pub enum MatcherCache {
    /// `Literal` and `MultiLiteral` are stateless and need no scan state.
    Empty,

    Regex(MetaCache),

    #[cfg(feature = "hyperscan")]
    Hyperscan(Scratch),
}

impl MatcherCache {
    /// # Safety
    /// This cache must have been created by [`Matcher::create_cache`] for a
    /// `Matcher::Regex`.
    #[inline(always)]
    unsafe fn regex_unchecked(&mut self) -> &mut MetaCache {
        match self {
            MatcherCache::Regex(cache) => cache,

            _ => {
                debug_assert!(false, "MatcherCache::regex_unchecked called on a non-Regex cache");
                std::hint::unreachable_unchecked()
            }
        }
    }

    /// # Safety
    /// This cache must have been created by [`Matcher::create_cache`] for a
    /// `Matcher::Hyperscan`.
    #[cfg(feature = "hyperscan")]
    #[inline(always)]
    unsafe fn hyperscan_unchecked(&self) -> &Scratch {
        match self {
            MatcherCache::Hyperscan(scratch) => scratch,
            _ => {
                debug_assert!(false, "MatcherCache::hyperscan_unchecked called on a non-Hyperscan cache");
                std::hint::unreachable_unchecked()
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
        case_insensitive: bool,
    },

    // Preferred over `Regex` when the `hyperscan` feature is enabled and Hyperscan is
    // able to compile the pattern; see `Matcher::try_hyperscan`.
    #[cfg(feature = "hyperscan")]
    Hyperscan {
        db: BlockDatabase,
        scratch: SendSyncScratch,
        pattern: Box<str>,           // Keep original pattern for literal extraction
        case_insensitive: bool,
    },

    Regex {
        re: MetaRegex,
        case_insensitive: bool,
        pattern: Box<str>,           // Keep original pattern for literal extraction
    },
}

impl Matcher {
    pub fn new(cli: &Cli) -> io::Result<Self> {
        let _span = tracy::span!("Matcher::new");

        let pattern = &cli.pattern;

        if cli.force_literal {
            return Ok(Matcher::Literal(Finder::new(pattern.as_bytes()).into_owned()));
        }

        if let Ok(hir) = regex_syntax::Parser::new().parse(pattern) {
            if let Some(literal) = literal_bytes(&hir) {
                if let Some(m) = Self::literal_matcher(&literal, cli.ignore_case)? {
                    return Ok(m);
                }
            } else if let Some(literals) = as_exact_alternation(&hir) {
                if let Some(m) = Self::multi_literal_matcher(&literals, cli.ignore_case)? {
                    return Ok(m);
                }
            }

            //
            // Not a pure literal/alternation, or ignore_case + non-ASCII with
            // no safe fold... Fallthrough...
            //
        }

        //
        // Fallback to regex: prefer Hyperscan when it's available and can compile this
        // pattern; otherwise fall back to the regex-automata engine below.
        //

        #[cfg(feature = "hyperscan")]
        if let Some(matcher) = Self::try_hyperscan(pattern, cli.ignore_case) {
            return Ok(matcher);
        }

        const LIMIT: usize = 16 * 1024 * 1024; // @Configuration

        use regex_automata::*;

        let re = MetaRegex::builder()
            .configure(
                meta::Config::new()
                    .dfa_size_limit(Some(LIMIT))
                    .nfa_size_limit(Some(LIMIT))
            )
            .syntax(util::syntax::Config::new().case_insensitive(cli.ignore_case))
            .build(pattern)
            .map_err(|e| io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid regex '{pattern}': {e}"),
            ))?;

        Ok(Matcher::Regex { re, pattern: pattern.clone().into_boxed_str(), case_insensitive: cli.ignore_case })
    }

    /// Try to compile `pattern` with Hyperscan. Returns `None` if Hyperscan rejects the
    /// pattern (unsupported syntax, pattern too large, etc.) or if scratch allocation
    /// fails, in which case the caller should fall back to the regex-automata engine.
    #[cfg(feature = "hyperscan")]
    fn try_hyperscan(pattern: &str, ignore_case: bool) -> Option<Self> {
        let _span = tracy::span!("Matcher::try_hyperscan");

        //
        // 'SOM_LEFTMOST' is required to get match *start* offsets, without it Hyperscan
        // only reports where a match ends.
        //
        // We deliberately don't set 'CompileFlags::UTF8':
        // haystacks here are arbitrary bytes that may not be valid UTF-8, and Hyperscan's
        // UTF-8 mode is documented as undefined behavior on invalid input.
        //

        let db: BlockDatabase = Pattern::with_flags(pattern, hyperscan::CompileFlags::SOM_LEFTMOST)
            .ok()?
            .build()
            .ok()?;

        let scratch = db.alloc_scratch().ok()?;

        Some(Matcher::Hyperscan {
            db,
            case_insensitive: ignore_case,
            scratch: SendSyncScratch(scratch),
            pattern: pattern.into(),
        })
    }

    /// Builds the single-literal fast path.
    ///
    /// Returns `Ok(None)` when `ignore_case` is set but the literal isn't pure ASCII --
    /// `ascii_case_insensitive` only folds a-z/A-Z, so anything outside
    /// that range can't be handled correctly here and must fall back to
    /// the regex engine's full Unicode case folding.
    fn literal_matcher(literal: &[u8], ignore_case: bool) -> io::Result<Option<Self>> {
        if !ignore_case {
            return Ok(Some(Matcher::Literal(Finder::new(literal).into_owned())));
        }

        if !literal.is_ascii() {
            return Ok(None);
        }

        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(aho_corasick::MatchKind::LeftmostFirst)
            .build([literal])
            .expect("single nonempty pattern always builds");

        Ok(Some(Matcher::MultiLiteral {
            ac,
            case_insensitive: ignore_case,
            patterns: [literal.into()].into(),
        }))
    }

    /// Builds the exact-alternation fast path. Same ASCII caveat as
    /// `literal_matcher`, but applied to the whole set: `ascii_case_insensitive`
    /// is one builder-level setting for the whole automaton, so a single
    /// non-ASCII branch means the *entire* set must fall back, not just
    /// that branch -- there's no way to fold some patterns and not others
    /// in one Aho-Corasick instance.
    fn multi_literal_matcher(literals: &[Vec<u8>], ignore_case: bool) -> io::Result<Option<Self>> {
        if ignore_case && literals.iter().any(|l| !l.is_ascii()) {
            return Ok(None);
        }

        let ac = AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostFirst)
            .ascii_case_insensitive(ignore_case)
            .build(literals)
            .map_err(|e| io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid alternation pattern '{:?}': {e}", literals),
            ))?;

        Ok(Some(Matcher::MultiLiteral {
            ac,
            case_insensitive: ignore_case,
            patterns: literals.iter().cloned().map(Vec::into_boxed_slice).collect(),
        }))
    }

    #[inline(always)]
    #[allow(clippy::redundant_locals, clippy::while_let_on_iterator)]
    pub fn push_all_matches(
        &self,
        haystack: &[u8],
        cache: Option<&mut MatcherCache>,
        ranges_scratch: &mut Vec<(u32, u32)>
    ) {
        //
        // @Speed: Scan straight into ranges_scratch
        //
        #[cfg(feature = "hyperscan")]
        if let Matcher::Hyperscan { db, .. } = self {
            let scratch = unsafe { cache.unwrap_unchecked().hyperscan_unchecked() };

            let mut last_end: u64 = 0;
            _ = db.scan(haystack, scratch, |_id, from, to: u64, _flags| {
                if from >= last_end {
                    ranges_scratch.push((from as u32, to as u32));

                    last_end = to.max(from + 1);
                }

                Matching::Continue
            });

            return;
        }

        match self {
            Matcher::Literal(finder) => {
                let needle_len = finder.needle().len();
                let mut iter = MatchIterator::Literal {
                    iter: finder.find_iter(haystack),
                    needle_len,
                };

                while let Some((s, e)) = iter.next() {
                    ranges_scratch.push((s as u32, e as u32));
                }
            }

            Matcher::MultiLiteral { ac, .. } => {
                for (s, e) in MatchIterator::MultiLiteral(ac.find_iter(haystack)) {
                    ranges_scratch.push((s as u32, e as u32));
                }
            }

            Matcher::Regex { re, .. } => {
                let re = MatchIterator::Regex(RegexMatchIter {
                    re,
                    cache: unsafe { cache.unwrap_unchecked().regex_unchecked() },
                    haystack,
                    at: 0,
                });

                for (s, e) in re {
                    ranges_scratch.push((s as u32, e as u32));
                }
            }

            #[cfg(feature = "hyperscan")]
            Matcher::Hyperscan { .. } => unsafe { std::hint::unreachable_unchecked() }
        }
    }

    /// Allocate the per-thread scan state this matcher's backend needs, if any.
    ///
    /// Call this once per thread and reuse the result across every `find_matches` /
    /// `push_all_matches` call that thread makes on *this* `Matcher` — see
    /// [`MatcherCache`] for the rules around sharing.
    #[inline]
    pub fn create_cache(&self) -> io::Result<MatcherCache> {
        match self {
            Matcher::Literal(_) | Matcher::MultiLiteral { .. } => Ok(MatcherCache::Empty),

            Matcher::Regex { re, .. } => Ok(MatcherCache::Regex(re.create_cache())),

            #[cfg(feature = "hyperscan")]
            Matcher::Hyperscan { db, .. } => db
                .alloc_scratch()
                .map(MatcherCache::Hyperscan)
                .map_err(|e| io::Error::new(
                    io::ErrorKind::Other,
                    format!("failed to allocate hyperscan scratch: {e}"),
                )),
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
            //
            // @Incomplete: No case-insensitive regex-literal/multi-literal extraction for now...
            //
            #[cfg(feature = "hyperscan")]
            Matcher::Hyperscan    { case_insensitive: true, .. } |
            Matcher::Regex        { case_insensitive: true, .. } |
            Matcher::MultiLiteral { case_insensitive: true, .. } => None,

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

            Matcher::Regex { pattern, .. } => extract_regex_literals(pattern),

            #[cfg(feature = "hyperscan")]
            Matcher::Hyperscan { pattern, .. } => extract_regex_literals(pattern)
        }
    }
}
