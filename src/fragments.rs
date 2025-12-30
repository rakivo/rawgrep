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
use smallvec::{smallvec, SmallVec};

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

/// Returns a SmallVec where `result[i]` is true if `fragment_hashes[i]` was found in the buffer.
#[inline]
pub fn check_fragment_presence(buf: &[u8], fragment_hashes: &[u32]) -> SmallVec<[bool; 32]> {
    let num_frags = fragment_hashes.len();

    if num_frags == 0 {
        return SmallVec::new();
    }

    if buf.len() < 4 {
        return smallvec![false; num_frags];
    }

    #[cfg(target_arch = "x86_64")] {
        if is_x86_feature_detected!("avx2") && buf.len() >= 32 {
            return unsafe { check_fragment_presence_avx2(buf, fragment_hashes) };
        }
    }

    #[cfg(target_arch = "aarch64")] {
        if std::arch::is_aarch64_feature_detected!("neon") && buf.len() >= 16 {
            return unsafe { check_fragment_presence_neon(buf, fragment_hashes) };
        }
    }

    check_fragment_presence_scalar(buf, fragment_hashes)
}

/// Scalar fallback for fragment presence checking
#[inline]
fn check_fragment_presence_scalar(buf: &[u8], fragment_hashes: &[u32]) -> SmallVec<[bool; 32]> {
    let num_frags = fragment_hashes.len();
    let stride = stride_heuristic(buf.len());

    // Build a set of pattern fragment hashes for O(1) lookup
    let pattern_frag_set = fragment_hashes.iter().copied().collect::<IntSet<_>>();

    let mut found: SmallVec<[bool; 32]> = smallvec![false; num_frags];
    let mut found_count = 0;

    let mut i = 0;
    while i + 4 <= buf.len() {
        let hash = hash_fragment([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);

        if pattern_frag_set.contains(&hash) {
            for (idx, &frag_hash) in fragment_hashes.iter().enumerate() {
                if frag_hash == hash && !found[idx] {
                    found[idx] = true;
                    found_count += 1;

                    if found_count == num_frags {
                        return found;
                    }

                    break;
                }
            }
        }

        i += stride;
    }

    found
}

/// AVX2-optimized fragment presence checking (x86_64).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn check_fragment_presence_avx2(buf: &[u8], fragment_hashes: &[u32]) -> SmallVec<[bool; 32]> {
    use std::arch::x86_64::*;

    let num_frags = fragment_hashes.len();
    let stride = stride_heuristic(buf.len()).max(8); // at least 8 for AVX2
    let mut found = smallvec![false; num_frags];
    let mut found_mask: u32 = 0;
    let all_found_mask: u32 = (1u32 << num_frags) - 1;

    //
    // Hash multiplier constant: 0x9e3779b9 (golden ratio)
    //
    let hash_mult = _mm256_set1_epi32(0x9e3779b9_u32 as i32);

    let buf_len = buf.len();
    let mut offset = 0;

    //
    // Process 8 overlapping windows at a time
    //
    while offset + (12 - 1) <= buf_len {
        let data_ptr = buf.as_ptr().add(offset);
        let w0 = (data_ptr.add(0) as *const u32).read_unaligned();
        let w1 = (data_ptr.add(1) as *const u32).read_unaligned();
        let w2 = (data_ptr.add(2) as *const u32).read_unaligned();
        let w3 = (data_ptr.add(3) as *const u32).read_unaligned();
        let w4 = (data_ptr.add(4) as *const u32).read_unaligned();
        let w5 = (data_ptr.add(5) as *const u32).read_unaligned();
        let w6 = (data_ptr.add(6) as *const u32).read_unaligned();
        let w7 = (data_ptr.add(7) as *const u32).read_unaligned();

        let windows = _mm256_set_epi32(
            w7 as i32, w6 as i32, w5 as i32, w4 as i32,
            w3 as i32, w2 as i32, w1 as i32, w0 as i32
        );

        let hashes = _mm256_mullo_epi32(windows, hash_mult);

        //
        // Compare against each pattern hash
        //
        for (frag_idx, &frag_hash) in fragment_hashes.iter().enumerate() {
            if found_mask & (1 << frag_idx) != 0 {
                continue;
            }

            let pattern_hash = _mm256_set1_epi32(frag_hash as i32);
            let cmp = _mm256_cmpeq_epi32(hashes, pattern_hash);
            let mask = _mm256_movemask_epi8(cmp);

            if mask != 0 {
                found[frag_idx] = true;
                found_mask |= 1 << frag_idx;

                if found_mask == all_found_mask {
                    return found;
                }
            }
        }

        offset += stride;
    }

    found
}

/// NEON-optimized fragment presence checking (ARM64).
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn check_fragment_presence_neon(buf: &[u8], fragment_hashes: &[u32]) -> SmallVec<[bool; 32]> {
    use std::arch::aarch64::*;

    let num_frags = fragment_hashes.len();
    let stride = stride_heuristic(buf.len()).max(4); // At least 4 for NEON
    let mut found: SmallVec<[bool; 32]> = smallvec![false; num_frags];
    let mut found_mask: u32 = 0;
    let all_found_mask: u32 = (1u32 << num_frags) - 1;

    //
    // Hash multiplier constant: 0x9e3779b9 (golden ratio)
    //
    let hash_mult = vdupq_n_u32(0x9e3779b9);

    let buf_len = buf.len();
    let mut offset = 0;

    //
    // Process 4 overlapping windows at a time
    //
    while offset + 7 <= buf_len {
        let data_ptr = buf.as_ptr().add(offset);

        //
        // Load 4 overlapping 4-byte windows
        //
        let w0 = (data_ptr.add(0) as *const u32).read_unaligned();
        let w1 = (data_ptr.add(1) as *const u32).read_unaligned();
        let w2 = (data_ptr.add(2) as *const u32).read_unaligned();
        let w3 = (data_ptr.add(3) as *const u32).read_unaligned();

        //
        // Pack into NEON register
        let windows = vld1q_u32([w0, w1, w2, w3].as_ptr());

        //
        // Compute hashes: hash = window * 0x9e3779b9
        //
        let hashes = vmulq_u32(windows, hash_mult);

        //
        // Compare against each pattern hash
        //
        for (frag_idx, &frag_hash) in fragment_hashes.iter().enumerate() {
            if found_mask & (1 << frag_idx) != 0 {
                continue;
            }

            let pattern_hash = vdupq_n_u32(frag_hash);
            let cmp = vceqq_u32(hashes, pattern_hash);

            //
            // Check if any lane matched (vmaxvq_u32 returns max of all lanes)
            //
            if vmaxvq_u32(cmp) != 0 {
                found[frag_idx] = true;
                found_mask |= 1 << frag_idx;

                if found_mask == all_found_mask {
                    return found;
                }
            }
        }

        offset += stride;
    }

    found
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
    fn test_check_fragment_presence_found() {
        let buf = b"hello world test";
        let pattern_frags = extract_pattern_fragments(b"hello");
        let found = check_fragment_presence(buf, &pattern_frags);

        // "hello" fragments should be found in "hello world test"
        assert!(found.iter().all(|&x| x));
    }

    #[test]
    fn test_check_fragment_presence_not_found() {
        let buf = b"hello world test";
        let pattern_frags = extract_pattern_fragments(b"xyzzy");
        let found = check_fragment_presence(buf, &pattern_frags);

        // "xyzzy" fragments should NOT be found
        assert!(found.iter().all(|&x| !x));
    }

    #[test]
    fn test_extract_too_short() {
        let pattern = b"hi";
        let frags = extract_pattern_fragments(pattern);
        assert_eq!(frags.len(), 0);
    }
}
