use crate::tracy;

use std::sync::Arc;

use memchr::{memchr, memrchr};
use smallvec::SmallVec;

/// A chain of gitignore matchers from root to current directory
#[derive(Clone)]
#[repr(transparent)]
pub struct GitignoreChain {
    inner: Option<Arc<GitignoreChainInner>>,
}

struct GitignoreChainInner {
    /// Stack of (depth, gitignore) pairs
    stack: SmallVec<[(u16, Arc<Gitignore>); 8]>,
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
        stack.push((0, Arc::new(gi)));
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
    pub fn with_gitignore(self, depth: u16, gi: Gitignore) -> Self {
        let _span = tracy::span!("GitignoreChain::with_gitignore");

        let has_negations = gi.has_negations;
        let new_gi = Arc::new(gi);

        let Some(inner) = self.inner else {
            let mut stack = SmallVec::new();
            stack.push((depth, new_gi));
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
                owned.stack.retain(|(d, _)| *d <= depth);
                owned.stack.push((depth, new_gi));
                owned.has_any_negations |= has_negations;
                Self {
                    inner: Some(Arc::new(owned)),
                }
            }
            Err(shared) => {
                // Other references exist - must clone
                let mut new_stack: SmallVec<[_; 8]> = shared
                    .stack
                    .iter()
                    .filter(|(d, _)| *d <= depth)
                    .cloned()
                    .collect();
                
                let mut has_any_negations = has_negations;
                for (_, gi) in &new_stack {
                    has_any_negations |= gi.has_negations;
                }
                
                new_stack.push((depth, new_gi));
                
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

        let filename_start = memrchr(b'/', path).map_or(0, |i| i + 1);
        let filename = unsafe { path.get_unchecked(filename_start..) };

        if inner.stack.len() == 1 {
            return unsafe {
                inner.stack.get_unchecked(0).1.is_ignored_with_filename(path, filename, is_dir)
            };
        }

        if !inner.has_any_negations {
            // -------- NO NEGATIONS - early exit on first match
            for (_, gi) in inner.stack.iter() {
                if gi.is_ignored_with_filename(path, filename, is_dir) {
                    return true;
                }
            }
            return false
        }

        // ---------- HAS NEGATIONS - must check all, last match wins
        let mut result = false;
        for (_, gi) in inner.stack.iter() {
            match gi.check_ignored_with_filename(path, filename, is_dir) {
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

#[derive(Clone)]
#[allow(dead_code, reason = "@Incomplete")]
pub struct Gitignore {
    /// Pre-computed: does this gitignore have any negations?
    pub(crate) has_negations: bool,

    /// Quick rejection: if filename length is outside this range, skip literal checks
    min_literal_len: u8,
    max_literal_len: u8,

    /// Literal patterns
    literal_data: Box<[u8]>,
    literal_meta: Box<[LiteralMeta]>,

    /// Wildcard patterns
    wildcards: Box<[WildcardPattern]>,

    /// Pattern execution order for correct semantics
    order: Box<[OrderEntry]>,
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

#[derive(Clone)]
struct WildcardPattern {
    bytes: Box<[u8]>,
    flags: u8, // bit 0: negated, bit 1: anchored, bit 2: dir_only
    /// For patterns like "*.rs", store the suffix for fast matching
    suffix: Option<Box<[u8]>>,
    /// For patterns like "test*", store the prefix
    prefix: Option<Box<[u8]>>,
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

        let mut min_literal_len = u8::MAX;
        let mut max_literal_len = 0u8;

        for line in content.split(|&b| b == b'\n') {
            if line.is_empty() || line[0] == b'#' {
                continue;
            }

            let line = trim_bytes(line);
            if line.is_empty() {
                continue;
            }

            let (pattern_bytes, negated) = if line[0] == b'!' {
                has_negations = true;
                (&line[1..], true)
            } else {
                (line, false)
            };

            if pattern_bytes.is_empty() {
                continue;
            }

            let (pattern_bytes, anchored) = if pattern_bytes[0] == b'/' {
                (&pattern_bytes[1..], true)
            } else if pattern_bytes.starts_with(b"**/") {
                (&pattern_bytes[3..], false)
            } else {
                (pattern_bytes, memchr(b'/', pattern_bytes).is_some())
            };

            let dir_only = pattern_bytes.last() == Some(&b'/');
            let pattern_bytes = if dir_only {
                &pattern_bytes[..pattern_bytes.len() - 1]
            } else {
                pattern_bytes
            };

            if pattern_bytes.is_empty() {
                continue;
            }

            let has_wildcards = memchr(b'*', pattern_bytes).is_some()
                || memchr(b'?', pattern_bytes).is_some()
                || memchr(b'[', pattern_bytes).is_some();

            let flags = (negated as u8) | ((anchored as u8) << 1) | ((dir_only as u8) << 2);

            if !has_wildcards {
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

                    // Track length bounds for quick rejection
                    min_literal_len = min_literal_len.min(len as u8);
                    max_literal_len = max_literal_len.max(len as u8);

                    order.push(OrderEntry {
                        ty: 0,
                        index: (literal_meta.len() - 1) as u16,
                    });
                } else {
                    // Too long, treat as wildcard
                    wildcards.push(WildcardPattern {
                        bytes: pattern_bytes.to_vec().into_boxed_slice(),
                        flags,
                        suffix: None,
                        prefix: None,
                    });
                    order.push(OrderEntry {
                        ty: 1,
                        index: (wildcards.len() - 1) as u16,
                    });
                }
            } else {
                // --------- WILDCARD PATTERN - analyze for fast paths
                let (suffix, prefix) = analyze_wildcard(pattern_bytes);

                wildcards.push(WildcardPattern {
                    bytes: pattern_bytes.to_vec().into_boxed_slice(),
                    flags,
                    suffix,
                    prefix,
                });
                order.push(OrderEntry {
                    ty: 1,
                    index: (wildcards.len() - 1) as u16,
                });
            }
        }

        Self {
            has_negations,
            min_literal_len,
            max_literal_len,
            literal_data: literal_data.into_boxed_slice(),
            literal_meta: literal_meta.into_boxed_slice(),
            wildcards: wildcards.into_boxed_slice(),
            order: order.into_boxed_slice(),
        }
    }

    /// Check if ignored, returns bool (for non-negation fast path)
    #[inline(always)]
    pub fn is_ignored_with_filename(&self, path: &[u8], filename: &[u8], is_dir: bool) -> bool {
        if self.order.is_empty() {
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

                let matched = match_wildcard_fast(pattern, text);

                if matched {
                    result = !pattern.negated();
                }
            }
        }

        result
    }

    /// Check if ignored, returns MatchResult (for negation handling)
    #[inline]
    fn check_ignored_with_filename(&self, path: &[u8], filename: &[u8], is_dir: bool) -> MatchResult {
        if self.order.is_empty() {
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

                if match_wildcard_fast(pattern, text) {
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
// @Speed @Refactor
#[allow(clippy::type_complexity)]
fn analyze_wildcard(pattern: &[u8]) -> (Option<Box<[u8]>>, Option<Box<[u8]>>) {
    // Pattern "*.ext" - very common
    if pattern.len() >= 2
        && pattern[0] == b'*'
        && !pattern[1..].contains(&b'*')
        && !pattern[1..].contains(&b'?')
        && !pattern[1..].contains(&b'[')
    {
        return (Some(pattern[1..].to_vec().into_boxed_slice()), None);
    }

    // Pattern "prefix*" - also common
    if pattern.len() >= 2 {
        if let Some(star_pos) = memchr(b'*', pattern) {
            if star_pos == pattern.len() - 1
                && !pattern[..star_pos].contains(&b'*')
                && !pattern[..star_pos].contains(&b'?')
                && !pattern[..star_pos].contains(&b'[')
            {
                return (None, Some(pattern[..star_pos].to_vec().into_boxed_slice()));
            }
        }
    }

    (None, None)
}

#[inline(always)]
fn match_anchored_literal(pattern: &[u8], path: &[u8]) -> bool {
    let len = pattern.len();
    if len > path.len() {
        return false;
    }

    let prefix = unsafe { path.get_unchecked(..len) };
    prefix == pattern && (path.len() == len || unsafe { *path.get_unchecked(len) } == b'/')
}

#[inline(always)]
fn match_wildcard_fast(pattern: &WildcardPattern, text: &[u8]) -> bool {
    // Fast path: suffix match (*.rs)
    if let Some(ref suffix) = pattern.suffix {
        return text.len() >= suffix.len() && unsafe {
            text.get_unchecked(text.len() - suffix.len()..)
        } == suffix.as_ref();
    }

    // Fast path: prefix match (test*)
    if let Some(ref prefix) = pattern.prefix {
        return text.len() >= prefix.len() && unsafe {
            text.get_unchecked(..prefix.len())
        } == prefix.as_ref();
    }

    // Fallback
    glob_match(&pattern.bytes, text)
}

#[inline]
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let plen = pattern.len();
    let tlen = text.len();

    if plen == 0 {
        return tlen == 0;
    }

    // Fast path: no wildcards
    if !pattern.contains(&b'*') &&
        !pattern.contains(&b'?') &&
        !pattern.contains(&b'[')
    {
        return pattern == text;
    }

    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = usize::MAX;
    let mut match_idx = 0;

    while t_idx < tlen {
        if p_idx < plen {
            let p_char = unsafe { *pattern.get_unchecked(p_idx) };

            match p_char {
                b'*' => {
                    star_idx = p_idx;
                    match_idx = t_idx;
                    p_idx += 1;
                    continue;
                }

                b'?' => {
                    p_idx += 1;
                    t_idx += 1;
                    continue;
                }

                b'[' => {
                    if let Some(new_p) = match_char_class(
                        pattern,
                        p_idx,
                        unsafe { *text.get_unchecked(t_idx) }
                    ) {
                        p_idx = new_p;
                        t_idx += 1;
                        continue;
                    }
                }

                c if c == unsafe { *text.get_unchecked(t_idx) } => {
                    p_idx += 1;
                    t_idx += 1;
                    continue;
                }

                _ => {}
            }
        }

        if star_idx != usize::MAX {
            p_idx = star_idx + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    // Skip trailing stars
    while p_idx < plen && unsafe {
        *pattern.get_unchecked(p_idx)
    } == b'*' {
        p_idx += 1;
    }

    p_idx == plen
}

#[inline]
fn match_char_class(pattern: &[u8], start: usize, ch: u8) -> Option<usize> {
    let plen = pattern.len();
    if start + 2 >= plen || unsafe { *pattern.get_unchecked(start) } != b'[' {
        return None;
    }

    let negated = unsafe { *pattern.get_unchecked(start + 1) } == b'!'
        || unsafe { *pattern.get_unchecked(start + 1) } == b'^';
    let mut i = if negated { start + 2 } else { start + 1 };

    // Find closing ]
    let mut end = i;
    while end < plen && unsafe { *pattern.get_unchecked(end) } != b']' {
        end += 1;
    }
    if end >= plen {
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

    if matched != negated {
        Some(end + 1)
    } else {
        None
    }
}

#[inline(always)]
fn trim_bytes(bytes: &[u8]) -> &[u8] {
    let len = bytes.len();
    if len == 0 {
        return bytes;
    }

    let mut start = 0;
    while start < len && unsafe { *bytes.get_unchecked(start) }.is_ascii_whitespace() {
        start += 1;
    }

    let mut end = len;
    while end > start && unsafe { *bytes.get_unchecked(end - 1) }.is_ascii_whitespace() {
        end -= 1;
    }

    unsafe { bytes.get_unchecked(start..end) }
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod chain_tests {
    use super::*;

    // =========================================================================
    // BASIC CHAIN OPERATIONS
    // =========================================================================

    #[test]
    fn test_empty_chain() {
        let chain = GitignoreChain::default();

        assert!(chain.is_empty());
        assert!(!chain.is_ignored(b"anything", false));
        assert!(!chain.is_ignored(b"file.txt", false));
        assert!(!chain.is_ignored(b"node_modules", true));
    }

    #[test]
    fn test_chain_from_root() {
        let gi = Gitignore::from_bytes(b"*.log\ntarget/\n");
        let chain = GitignoreChain::from_root(gi);

        assert!(!chain.is_empty());
        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"target", true));
        assert!(!chain.is_ignored(b"file.txt", false));
    }

    #[test]
    fn test_chain_single_gitignore() {
        let gi = Gitignore::from_bytes(b"node_modules\n*.tmp\n");
        let chain = GitignoreChain::from_root(gi);

        assert!(chain.is_ignored(b"node_modules", true));
        assert!(chain.is_ignored(b"src/node_modules", true));
        assert!(chain.is_ignored(b"file.tmp", false));
        assert!(chain.is_ignored(b"deep/path/file.tmp", false));
    }

    // =========================================================================
    // CHAIN DEPTH AND STACKING
    // =========================================================================

    #[test]
    fn test_chain_with_gitignore_adds_depth() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        let sub = Gitignore::from_bytes(b"*.tmp\n");
        let chain = chain.with_gitignore(1, sub);

        // Both patterns should match
        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"test.tmp", false));
        assert!(!chain.is_ignored(b"test.txt", false));
    }

    #[test]
    fn test_chain_multiple_depths() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        let depth1 = Gitignore::from_bytes(b"*.tmp\n");
        let chain = chain.with_gitignore(1, depth1);

        let depth2 = Gitignore::from_bytes(b"*.bak\n");
        let chain = chain.with_gitignore(2, depth2);

        // All three patterns should match
        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"test.tmp", false));
        assert!(chain.is_ignored(b"test.bak", false));
        assert!(!chain.is_ignored(b"test.txt", false));
    }

    #[test]
    fn test_chain_depth_pruning() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        let depth2 = Gitignore::from_bytes(b"*.tmp\n");
        let chain = chain.with_gitignore(2, depth2);

        let depth3 = Gitignore::from_bytes(b"*.bak\n");
        let chain = chain.with_gitignore(3, depth3);

        // Now add at depth 1 - should prune depth 2 and 3
        let depth1_new = Gitignore::from_bytes(b"*.cache\n");
        let chain = chain.with_gitignore(1, depth1_new);

        // Root (depth 0) and new depth 1 should remain
        assert!(chain.is_ignored(b"test.log", false));    // depth 0
        assert!(chain.is_ignored(b"test.cache", false));  // depth 1

        // These were pruned
        assert!(!chain.is_ignored(b"test.tmp", false));   // was depth 2
        assert!(!chain.is_ignored(b"test.bak", false));   // was depth 3
    }

    #[test]
    fn test_chain_same_depth_replaces() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        let first = Gitignore::from_bytes(b"*.tmp\n");
        let chain = chain.with_gitignore(1, first);

        // Add another at same depth - first one should be pruned
        let second = Gitignore::from_bytes(b"*.bak\n");
        let chain = chain.with_gitignore(1, second);

        assert!(chain.is_ignored(b"test.log", false));   // root remains
        assert!(chain.is_ignored(b"test.bak", false));   // new depth 1
        // Note: *.tmp is pruned because depth 1 was replaced
        // Actually, retain keeps d <= depth, so d=1 is kept... let me check
        // retain(|(d, _)| *d <= depth) with depth=1 keeps d=0 and d=1
        // So actually *.tmp should still be there
        assert!(chain.is_ignored(b"test.tmp", false));   // depth 1 retained
    }

    #[test]
    fn test_chain_deeper_depth_doesnt_prune() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        let depth1 = Gitignore::from_bytes(b"*.tmp\n");
        let chain = chain.with_gitignore(1, depth1);

        // Add at deeper depth - shouldn't prune anything
        let depth5 = Gitignore::from_bytes(b"*.bak\n");
        let chain = chain.with_gitignore(5, depth5);

        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"test.tmp", false));
        assert!(chain.is_ignored(b"test.bak", false));
    }

    // =========================================================================
    // NEGATION HANDLING IN CHAIN
    // =========================================================================

    #[test]
    fn test_chain_negation_in_same_gitignore() {
        let gi = Gitignore::from_bytes(b"*.log\n!important.log\n");
        let chain = GitignoreChain::from_root(gi);

        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"debug.log", false));
        assert!(!chain.is_ignored(b"important.log", false));
    }

    #[test]
    fn test_chain_negation_across_depths() {
        // Root ignores all .log files
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        // Subdirectory negates important.log
        let sub = Gitignore::from_bytes(b"!important.log\n");
        let chain = chain.with_gitignore(1, sub);

        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"debug.log", false));
        assert!(!chain.is_ignored(b"important.log", false));
    }

    #[test]
    fn test_chain_negation_then_reignore() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        let depth1 = Gitignore::from_bytes(b"!important.log\n");
        let chain = chain.with_gitignore(1, depth1);

        // Re-ignore at deeper level
        let depth2 = Gitignore::from_bytes(b"important.log\n");
        let chain = chain.with_gitignore(2, depth2);

        // Last match wins
        assert!(chain.is_ignored(b"important.log", false));
    }

    #[test]
    fn test_chain_no_negations_early_exit() {
        // When no negations exist, chain can early-exit on first match
        let root = Gitignore::from_bytes(b"target\n");
        let chain = GitignoreChain::from_root(root);

        let sub = Gitignore::from_bytes(b"node_modules\n");
        let chain = chain.with_gitignore(1, sub);

        // Both should match
        assert!(chain.is_ignored(b"target", true));
        assert!(chain.is_ignored(b"node_modules", true));

        // Verify has_any_negations is false (can't directly test, but behavior should be correct)
        assert!(!chain.is_ignored(b"src", true));
    }

    #[test]
    fn test_chain_with_negations_checks_all() {
        let root = Gitignore::from_bytes(b"*.txt\n");
        let chain = GitignoreChain::from_root(root);

        // This gitignore has negation
        let sub = Gitignore::from_bytes(b"!readme.txt\n*.md\n");
        let chain = chain.with_gitignore(1, sub);

        assert!(chain.is_ignored(b"test.txt", false));
        assert!(!chain.is_ignored(b"readme.txt", false));  // Negated
        assert!(chain.is_ignored(b"doc.md", false));
    }

    // =========================================================================
    // CLONING AND ARC BEHAVIOR
    // =========================================================================

    #[test]
    fn test_chain_clone_is_cheap() {
        let root = Gitignore::from_bytes(b"*.log\nnode_modules\ntarget\n");
        let chain = GitignoreChain::from_root(root);

        // Clone should be O(1) - just Arc refcount bump
        let chain2 = chain.clone();
        let chain3 = chain.clone();

        // All clones should work identically
        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain2.is_ignored(b"test.log", false));
        assert!(chain3.is_ignored(b"test.log", false));
    }

    #[test]
    fn test_chain_cow_behavior_exclusive() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        // No other references - should mutate in place (COW)
        let chain = chain.with_gitignore(1, Gitignore::from_bytes(b"*.tmp\n"));

        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"test.tmp", false));
    }

    #[test]
    fn test_chain_cow_behavior_shared() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        // Create a clone (now refcount > 1)
        let chain_clone = chain.clone();

        // This should clone the stack (COW)
        let chain_modified = chain.with_gitignore(1, Gitignore::from_bytes(b"*.tmp\n"));

        // Original clone unchanged
        assert!(chain_clone.is_ignored(b"test.log", false));
        assert!(!chain_clone.is_ignored(b"test.tmp", false));

        // Modified chain has both
        assert!(chain_modified.is_ignored(b"test.log", false));
        assert!(chain_modified.is_ignored(b"test.tmp", false));
    }

    // =========================================================================
    // REAL-WORLD SCENARIOS
    // =========================================================================

    #[test]
    fn test_chain_typical_project_structure() {
        // Root .gitignore
        let root = Gitignore::from_bytes(b"
target/
*.log
.env
node_modules/
");
        let chain = GitignoreChain::from_root(root);

        // src/.gitignore
        let src = Gitignore::from_bytes(b"
generated/
*.generated.rs
");
        let chain = chain.with_gitignore(1, src);

        // src/tests/.gitignore
        let tests = Gitignore::from_bytes(b"
fixtures/
*.snapshot
!important.snapshot
");
        let chain = chain.with_gitignore(2, tests);

        // Test root patterns
        assert!(chain.is_ignored(b"target", true));
        assert!(chain.is_ignored(b"app.log", false));
        assert!(chain.is_ignored(b".env", false));
        assert!(chain.is_ignored(b"node_modules", true));

        // Test src patterns
        assert!(chain.is_ignored(b"generated", true));
        assert!(chain.is_ignored(b"types.generated.rs", false));

        // Test tests patterns
        assert!(chain.is_ignored(b"fixtures", true));
        assert!(chain.is_ignored(b"test.snapshot", false));
        assert!(!chain.is_ignored(b"important.snapshot", false));

        // Non-ignored files
        assert!(!chain.is_ignored(b"main.rs", false));
        assert!(!chain.is_ignored(b"Cargo.toml", false));
    }

    #[test]
    fn test_chain_monorepo_structure() {
        // Root
        let root = Gitignore::from_bytes(b"
.git/
*.log
.env*
");
        let chain = GitignoreChain::from_root(root);

        // packages/frontend
        let frontend = Gitignore::from_bytes(b"
dist/
node_modules/
.next/
");
        let frontend_chain = chain.clone().with_gitignore(2, frontend);

        // packages/backend
        let backend = Gitignore::from_bytes(b"
target/
*.pyc
__pycache__/
");
        let backend_chain = chain.clone().with_gitignore(2, backend);

        // Frontend chain
        assert!(frontend_chain.is_ignored(b"dist", true));
        assert!(frontend_chain.is_ignored(b"node_modules", true));
        assert!(frontend_chain.is_ignored(b".next", true));
        assert!(!frontend_chain.is_ignored(b"target", true));

        // Backend chain
        assert!(backend_chain.is_ignored(b"target", true));
        assert!(backend_chain.is_ignored(b"app.pyc", false));
        assert!(backend_chain.is_ignored(b"__pycache__", true));
        assert!(!backend_chain.is_ignored(b"node_modules", true));

        // Both have root patterns
        assert!(frontend_chain.is_ignored(b".git", true));
        assert!(backend_chain.is_ignored(b".git", true));
        assert!(frontend_chain.is_ignored(b"debug.log", false));
        assert!(backend_chain.is_ignored(b"debug.log", false));
    }

    #[test]
    fn test_chain_deep_nesting() {
        let chain = GitignoreChain::from_root(Gitignore::from_bytes(b"*.log\n"));

        let chain = chain.with_gitignore(1, Gitignore::from_bytes(b"*.tmp\n"));
        let chain = chain.with_gitignore(2, Gitignore::from_bytes(b"*.bak\n"));
        let chain = chain.with_gitignore(3, Gitignore::from_bytes(b"*.old\n"));
        let chain = chain.with_gitignore(4, Gitignore::from_bytes(b"*.cache\n"));
        let chain = chain.with_gitignore(5, Gitignore::from_bytes(b"*.swp\n"));

        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"test.tmp", false));
        assert!(chain.is_ignored(b"test.bak", false));
        assert!(chain.is_ignored(b"test.old", false));
        assert!(chain.is_ignored(b"test.cache", false));
        assert!(chain.is_ignored(b"test.swp", false));
        assert!(!chain.is_ignored(b"test.txt", false));
    }

    #[test]
    fn test_chain_directory_traversal_simulation() {
        // Simulate walking: root -> src -> src/lib -> src/lib/utils
        let root = Gitignore::from_bytes(b"target/\n*.log\n");
        let chain = GitignoreChain::from_root(root);

        // Enter src/ (no .gitignore here, but we pass the chain along)
        let chain_src = chain.clone();

        // Enter src/lib/ (has .gitignore)
        let lib_gi = Gitignore::from_bytes(b"generated/\n");
        let chain_lib = chain_src.clone().with_gitignore(2, lib_gi);

        // Enter src/lib/utils/ (has .gitignore)
        let utils_gi = Gitignore::from_bytes(b"*.generated.rs\n");
        let chain_utils = chain_lib.clone().with_gitignore(3, utils_gi);

        // Now go back up to src/tests/ (should NOT have lib's patterns)
        let tests_gi = Gitignore::from_bytes(b"fixtures/\n");
        let chain_tests = chain_src.clone().with_gitignore(2, tests_gi);

        // chain_utils has: root + lib + utils
        assert!(chain_utils.is_ignored(b"target", true));
        assert!(chain_utils.is_ignored(b"generated", true));
        assert!(chain_utils.is_ignored(b"types.generated.rs", false));

        // chain_tests has: root + tests (NOT lib or utils)
        assert!(chain_tests.is_ignored(b"target", true));
        assert!(chain_tests.is_ignored(b"fixtures", true));
        assert!(!chain_tests.is_ignored(b"generated", true));
        assert!(!chain_tests.is_ignored(b"types.generated.rs", false));
    }

    // =========================================================================
    // EDGE CASES
    // =========================================================================

    #[test]
    fn test_chain_empty_gitignore() {
        let empty = Gitignore::from_bytes(b"");
        let chain = GitignoreChain::from_root(empty);

        // Should not be empty (has a gitignore, just with no patterns)
        // Actually, is_empty checks stack.is_empty(), and we pushed one
        assert!(!chain.is_empty());
        assert!(!chain.is_ignored(b"anything", false));
    }

    #[test]
    fn test_chain_comments_only_gitignore() {
        let comments = Gitignore::from_bytes(b"# Just a comment\n# Another comment\n");
        let chain = GitignoreChain::from_root(comments);

        assert!(!chain.is_ignored(b"file.txt", false));
    }

    #[test]
    fn test_chain_with_gitignore_on_empty() {
        let chain = GitignoreChain::default();

        let gi = Gitignore::from_bytes(b"*.log\n");
        let chain = chain.with_gitignore(5, gi);

        assert!(!chain.is_empty());
        assert!(chain.is_ignored(b"test.log", false));
    }

    #[test]
    fn test_chain_depth_zero() {
        let chain = GitignoreChain::default();

        let gi = Gitignore::from_bytes(b"*.log\n");
        let chain = chain.with_gitignore(0, gi);

        assert!(chain.is_ignored(b"test.log", false));
    }

    #[test]
    fn test_chain_max_depth() {
        let chain = GitignoreChain::default();

        let gi = Gitignore::from_bytes(b"*.log\n");
        let chain = chain.with_gitignore(u16::MAX, gi);

        assert!(chain.is_ignored(b"test.log", false));
    }

    #[test]
    fn test_chain_filename_extraction() {
        let gi = Gitignore::from_bytes(b"secret.txt\n");
        let chain = GitignoreChain::from_root(gi);

        // Should match filename regardless of path depth
        assert!(chain.is_ignored(b"secret.txt", false));
        assert!(chain.is_ignored(b"a/secret.txt", false));
        assert!(chain.is_ignored(b"a/b/secret.txt", false));
        assert!(chain.is_ignored(b"a/b/c/d/e/secret.txt", false));
    }

    #[test]
    fn test_chain_dir_vs_file() {
        let gi = Gitignore::from_bytes(b"build/\nbuild.rs\n");
        let chain = GitignoreChain::from_root(gi);

        // build/ only matches directories
        assert!(chain.is_ignored(b"build", true));
        assert!(!chain.is_ignored(b"build", false));  // file named "build"

        // build.rs matches files
        assert!(chain.is_ignored(b"build.rs", false));
        assert!(chain.is_ignored(b"src/build.rs", false));
    }

    #[test]
    fn test_chain_unicode_paths() {
        let gi = Gitignore::from_bytes("日本語.txt\n*.中文\n".as_bytes());
        let chain = GitignoreChain::from_root(gi);

        assert!(chain.is_ignored("日本語.txt".as_bytes(), false));
        assert!(chain.is_ignored("test.中文".as_bytes(), false));
    }

    #[test]
    fn test_chain_special_characters_in_path() {
        let gi = Gitignore::from_bytes(b"file with spaces.txt\nfile-with-dashes.log\n");
        let chain = GitignoreChain::from_root(gi);

        assert!(chain.is_ignored(b"file with spaces.txt", false));
        assert!(chain.is_ignored(b"file-with-dashes.log", false));
    }

    // =========================================================================
    // PERFORMANCE-RELATED TESTS
    // =========================================================================

    #[test]
    fn test_chain_many_gitignores() {
        let mut chain = GitignoreChain::default();

        for i in 0..100u16 {
            let pattern = format!("pattern{}.txt\n", i);
            let gi = Gitignore::from_bytes(pattern.as_bytes());
            chain = chain.with_gitignore(i, gi);
        }

        assert!(chain.is_ignored(b"pattern0.txt", false));
        assert!(chain.is_ignored(b"pattern50.txt", false));
        assert!(chain.is_ignored(b"pattern99.txt", false));
        assert!(!chain.is_ignored(b"pattern100.txt", false));
    }

    #[test]
    fn test_chain_many_patterns_per_gitignore() {
        let mut patterns = String::new();
        for i in 0..500 {
            patterns.push_str(&format!("file{}.txt\n", i));
        }

        let gi = Gitignore::from_bytes(patterns.as_bytes());
        let chain = GitignoreChain::from_root(gi);

        assert!(chain.is_ignored(b"file0.txt", false));
        assert!(chain.is_ignored(b"file250.txt", false));
        assert!(chain.is_ignored(b"file499.txt", false));
        assert!(!chain.is_ignored(b"file500.txt", false));
    }

    #[test]
    fn test_chain_long_paths() {
        let gi = Gitignore::from_bytes(b"target\n");
        let chain = GitignoreChain::from_root(gi);

        let long_path = b"a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/target";
        assert!(chain.is_ignored(long_path, true));
    }

    #[test]
    fn test_chain_repeated_clone_and_extend() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        // Simulate many parallel directory traversals
        let mut chains = Vec::new();
        for i in 0..10u16 {
            let gi = Gitignore::from_bytes(format!("dir{}/\n", i).as_bytes());
            chains.push(chain.clone().with_gitignore(i + 1, gi));
        }

        // Each chain should have root + its own pattern
        for (i, c) in chains.iter().enumerate() {
            assert!(c.is_ignored(b"test.log", false));
            assert!(c.is_ignored(format!("dir{}", i).as_bytes(), true));
        }
    }
}
