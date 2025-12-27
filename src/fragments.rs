//! # Fragment-Based Cache System
//!
//! This module implements the core fragment extraction logic for rawgrep's nowgrep-inspired
//! caching system. Fragments are small byte sequences used to quickly determine if a file
//! can be skipped without reading it.
//!
//! ## What Are Fragments?
//!
//! A **fragment** is a 4-byte sliding window extracted from text. For example:
//!
//! ```text
//! Pattern: "ERROR:"
//!
//! Windows: "ERRO"   [E, R, R, O] -> hash -> 0x12345678
//!           "RROR"  [R, R, O, R] -> hash -> 0x23456789
//!            "ROR:" [R, O, R, :] -> hash -> 0x34567890
//!
//! Result: 3 fragment hashes
//! ```
//!
//! Even different patterns benefit from previous searches if they share fragments.
//!
//! ### Space Complexity
//!
//! - **Per pattern:** 4 bytes * num_fragments (typically 8-40 bytes)
//! - **Per file:**    num_fragments / 8 bytes for bitset (typically 1-100 bytes)
//! - **Total cache:** ~42 bytes per file + fragment overhead
//!   - 100 MB cache -> ~2.3M files tracked
//!
//! ## References
//!
//! Inspired by nowgrep's fragment-based filtering:
//! - <https://github.com/asbott/nowgrep>
//! - Similar to Bloom filters but with explicit tracking

use nohash_hasher::IntSet;

/// Hash a 4-byte fragment to u32.
#[inline(always)]
pub const fn hash_fragment(frag: [u8; 4]) -> u32 {
    u32::from_le_bytes(frag).wrapping_mul(0x9e3779b9)
}

/// Hash a u32 fragment
#[inline(always)]
pub const fn hash_fragment_u32(frag: u32) -> u32 {
    frag.wrapping_mul(0x9e3779b9)
}

/// Determine stride for file fragment extraction based on file size.
///
/// Balances extraction speed vs accuracy using adaptive sampling:
/// - Small files  (<=64KB):   Scan all bytes (stride=1) for completeness
/// - Medium files (64KB-1MB): Sample every 8th byte for efficiency
/// - Large files  (>1MB):     Sample every 64th byte to avoid bottleneck
///
/// # Rationale
/// Fragment extraction happens off the critical path (after search completes).
/// Sampling is sufficient because if a 4-byte fragment exists in a file,
/// we'll likely find it even with sparse sampling.
///
/// @Heuristic @Tune
#[inline(always)]
pub const fn stride_heuristic(buf_len: usize) -> usize {
    match buf_len {
        0..=65536       => 1,  // 100% coverage for small files
        65537..=1048576 => 8,  // 12.5% coverage for medium files
        _               => 64, // 1.56% coverage for large files
    }
}

/// Extract fragment hashes from a search pattern.
#[inline]
pub fn extract_pattern_fragments(pattern: &[u8]) -> Vec<u32> {
    if pattern.len() < 4 {
        return Vec::new();
    }

    // for N bytes, we get N-3 overlapping 4-byte windows
    let mut fragments = Vec::with_capacity(pattern.len().saturating_sub(4 - 1));
    let mut seen = IntSet::default();

    for window in pattern.windows(4) {
        let mut frag = [0u8; 4];
        frag.copy_from_slice(window);
        let hash = hash_fragment(frag);

        if seen.insert(hash) {
            fragments.push(hash);
        }
    }

    fragments
}

#[inline]
fn extract_file_fragments_no_simd(buf: &[u8], max_fragments: usize) -> Vec<u32> {
    if buf.len() < 4 {
        return Vec::new();
    }

    let stride = stride_heuristic(buf.len());

    let mut seen = IntSet::default();
    let mut fragments = Vec::with_capacity(max_fragments.min(buf.len() / stride));

    let mut i = 0;
    while i + 4 <= buf.len() && fragments.len() < max_fragments {
        let mut frag = [0u8; 4];
        frag.copy_from_slice(&buf[i..i + 4]);
        let hash = hash_fragment(frag);

        if seen.insert(hash) {
            fragments.push(hash);
        }

        i += stride;
    }

    fragments
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn extract_file_fragments_simd(
    buf: &[u8],
    stride: usize,
    max_fragments: usize,
) -> Vec<u32> {
    use std::arch::x86_64::*;

    if buf.len() < 32 {
        return extract_file_fragments_no_simd(buf, max_fragments);
    }

    let mut seen = IntSet::default();
    let mut fragments = Vec::with_capacity(max_fragments);

    let mut offset = 0;
    while offset + 32 <= buf.len() && fragments.len() < max_fragments {
        let data = unsafe { _mm256_loadu_si256(buf.as_ptr().add(offset) as *const __m256i) };

        // Extract 8 overlapping 4-byte fragments at once
        // We can use shuffle/permute to get different 4-byte windows

        // For positions 0, 4, 8, 12, 16, 20, 24, 28 (non-overlapping)
        // Extract as 32-bit integers directly
        let lane0 = _mm256_extract_epi32::<0>(data) as u32;
        let lane1 = _mm256_extract_epi32::<1>(data) as u32;
        let lane2 = _mm256_extract_epi32::<2>(data) as u32;
        let lane3 = _mm256_extract_epi32::<3>(data) as u32;
        let lane4 = _mm256_extract_epi32::<4>(data) as u32;
        let lane5 = _mm256_extract_epi32::<5>(data) as u32;
        let lane6 = _mm256_extract_epi32::<6>(data) as u32;
        let lane7 = _mm256_extract_epi32::<7>(data) as u32;

        for &frag in &[lane0, lane1, lane2, lane3, lane4, lane5, lane6, lane7] {
            if fragments.len() >= max_fragments {
                break;
            }
            let hash = hash_fragment_u32(frag);
            if seen.insert(hash) {
                fragments.push(hash);
            }
        }

        offset += stride.max(32);
    }

    while offset + 4 <= buf.len() && fragments.len() < max_fragments {
        let frag = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
        let hash = hash_fragment_u32(frag);
        if seen.insert(hash) {
            fragments.push(hash);
        }
        offset += stride;
    }

    fragments
}

/// Extract fragments with SIMD if available, fall back to scalar
#[inline]
pub fn extract_file_fragments(buf: &[u8], max_fragments: usize) -> Vec<u32> {
    if buf.len() < 4 {
        return Vec::new();
    }

    let stride = stride_heuristic(buf.len());

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") && buf.len() >= 32 && stride >= 32 {
            unsafe { extract_file_fragments_simd(buf, stride, max_fragments) }
        } else {
            extract_file_fragments_no_simd(buf, max_fragments)
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        extract_file_fragments_no_simd(buf, max_fragments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_fragment() {
        let frag = b"test";
        let hash = hash_fragment(*frag);
        assert_ne!(hash, 0);
    }

    #[test]
    fn test_extract_pattern_fragments() {
        let pattern = b"hello";
        let frags = extract_pattern_fragments(pattern);

        // "hello" should produce: "hell", "ello"
        assert_eq!(frags.len(), 2);
    }

    #[test]
    fn test_extract_pattern_fragments_dedup() {
        let pattern = b"aaaa";
        let frags = extract_pattern_fragments(pattern);

        // all windows are identical, should deduplicate to 1
        assert_eq!(frags.len(), 1);
    }

    #[test]
    fn test_extract_file_fragments_small() {
        let buf = b"test data here";
        let frags = extract_file_fragments_no_simd(buf, 1000);

        // should extract all 4-byte windows (stride=1 for small files)
        assert!(frags.is_empty());
        assert!(frags.len() <= buf.len() - 3);
    }

    #[test]
    fn test_extract_file_fragments_max_limit() {
        let buf = vec![0u8; 100000];
        let frags = extract_file_fragments_no_simd(&buf, 100);

        // should respect max_fragments limit
        assert!(frags.len() <= 100);
    }

    #[test]
    fn test_extract_too_short() {
        let pattern = b"hi";
        let frags = extract_pattern_fragments(pattern);
        assert_eq!(frags.len(), 0);
    }
}
