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
pub fn extract_pattern_fragments(pattern: &[u8]) -> Vec<u32> {  // @Memory @Speed: This function is called pretty much ONCE in the whole program, so it's probably fine to allocate here.
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
pub fn check_fragment_presence(buf: &[u8], fragment_hashes: &[u32], fragment_presence_scratch: &mut Vec<u64>) {
    let num_frags = fragment_hashes.len();

    if num_frags == 0 {
        return;
    }

    if buf.len() < 4 {
        return;
    }

    #[cfg(target_arch = "x86_64")] {
        if is_x86_feature_detected!("avx2") && buf.len() >= 32 {
            return unsafe { check_fragment_presence_avx2(buf, fragment_hashes, fragment_presence_scratch) };
        }
    }

    #[cfg(target_arch = "aarch64")] {
        if std::arch::is_aarch64_feature_detected!("neon") && buf.len() >= 16 {
            return unsafe { check_fragment_presence_neon(buf, fragment_hashes, fragment_presence_scratch) };
        }
    }

    check_fragment_presence_scalar(buf, fragment_hashes, fragment_presence_scratch)
}

/// Scalar fallback for fragment presence checking
#[inline]
fn check_fragment_presence_scalar(buf: &[u8], fragment_hashes: &[u32], fragment_presence_scratch: &mut Vec<u64>) {
    let num_frags = fragment_hashes.len();
    let stride = stride_heuristic(buf.len());

    // Build a set of pattern fragment hashes for O(1) lookup
    let pattern_frag_set = fragment_hashes.iter().copied().collect::<IntSet<_>>();

    let mut found_count = 0;

    let mut i = 0;
    while i + 4 <= buf.len() {
        let hash = hash_fragment([buf[i], buf[i+1], buf[i+2], buf[i+3]]);

        if pattern_frag_set.contains(&hash) {
            for (idx, &frag_hash) in fragment_hashes.iter().enumerate() {
                if frag_hash == hash {
                    let (word, bit) = (idx / 64, 1u64 << (idx % 64));
                    if fragment_presence_scratch[word] & bit == 0 {
                        fragment_presence_scratch[word] |= bit;
                        found_count += 1;
                        if found_count == num_frags { return; }
                    }

                    break;
                }
            }
        }

        i += stride;
    }
}

macro_rules! impl_fragment_presence_scanner {
    (
        fn_name: $fn_name:ident,
        cfg: $cfg_arch:literal,
        feature: $feature:literal,
        min_stride: $min_stride:expr,
        hashes_ty: $hashes_ty:ty,
        window_load: |$data_ptr:ident| $load_block:block,
        splat: |$scalar:ident| $splat_block:block,
        any_match: |$ha:ident, $hb:ident| $match_block:block,
    ) => {
        #[cfg(target_arch = $cfg_arch)]
        #[target_feature(enable = $feature)]
        #[allow(unsafe_op_in_unsafe_fn)]
        unsafe fn $fn_name(buf: &[u8], fragment_hashes: &[u32], fragment_presence_scratch: &mut Vec<u64>) {
            let num_frags = fragment_hashes.len();
            let stride = stride_heuristic(buf.len()).max($min_stride);
            let buf_len = buf.len();

            if crate::util::likely(num_frags <= 64) {
                //
                // Fast path: register-only bitmask
                //

                let mut found_mask: u64 = 0;
                let all_found_mask: u64 = if num_frags == 64 { u64::MAX } else { (1u64 << num_frags) - 1 };

                let mut offset = 0;
                while offset + (12 - 1) <= buf_len {
                    let $data_ptr = buf.as_ptr().add(offset);
                    let hashes: $hashes_ty = $load_block;

                    for (frag_idx, &frag_hash) in fragment_hashes.iter().enumerate() {
                        let bit = 1u64 << frag_idx;
                        if found_mask & bit != 0 {
                            continue;
                        }

                        let $scalar = frag_hash;
                        let pattern: $hashes_ty = $splat_block;
                        let $ha = hashes;
                        let $hb = pattern;
                        if $match_block {
                            found_mask |= bit;
                        }
                    }

                    if found_mask == all_found_mask {
                        break;
                    }

                    offset += stride;
                }

                fragment_presence_scratch[0] = found_mask;
            } else {
                //
                // Fallback: >64 fragments, can't fit a register mask
                //

                let mut remaining = num_frags;

                let mut offset = 0;
                while offset + (12 - 1) <= buf_len {
                    let $data_ptr = buf.as_ptr().add(offset);
                    let hashes: $hashes_ty = $load_block;

                    for (frag_idx, &frag_hash) in fragment_hashes.iter().enumerate() {
                        debug_assert!(frag_idx < fragment_presence_scratch.len());

                        if *fragment_presence_scratch.get_unchecked(frag_idx / 64) & (1u64 << (frag_idx % 64)) != 0 {
                            continue;
                        }

                        let $scalar = frag_hash;
                        let pattern: $hashes_ty = $splat_block;
                        let $ha = hashes;
                        let $hb = pattern;
                        if $match_block {
                            *fragment_presence_scratch.get_unchecked_mut(frag_idx / 64) |= 1u64 << (frag_idx % 64);
                            remaining -= 1;
                        }
                    }

                    if remaining == 0 {
                        break;
                    }

                    offset += stride;
                }
            }
        }
    };
}

impl_fragment_presence_scanner! {
    fn_name: check_fragment_presence_avx2,
    cfg: "x86_64",
    feature: "avx2",
    min_stride: 8,
    hashes_ty: std::arch::x86_64::__m256i,

    window_load: |data_ptr| {
        use std::arch::x86_64::*;
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
            w3 as i32, w2 as i32, w1 as i32, w0 as i32,
        );

        // Hash multiplier constant: 0x9e3779b9 (golden ratio).
        // Let's pray LLVM's LICM hoists this broadcast out the loop.
        _mm256_mullo_epi32(windows, _mm256_set1_epi32(0x9e3779b9_u32 as i32))
    },

    splat: |scalar| {
        std::arch::x86_64::_mm256_set1_epi32(scalar as i32)
    },

    any_match: |a, b| {
        use std::arch::x86_64::*;
        _mm256_movemask_epi8(_mm256_cmpeq_epi32(a, b)) != 0
    },
}

impl_fragment_presence_scanner! {
    fn_name: check_fragment_presence_neon,
    cfg: "aarch64",
    feature: "neon",
    min_stride: 4,
    hashes_ty: std::arch::aarch64::uint32x4_t,

    window_load: |data_ptr| {
        use std::arch::aarch64::*;
        let w0 = (data_ptr.add(0) as *const u32).read_unaligned();
        let w1 = (data_ptr.add(1) as *const u32).read_unaligned();
        let w2 = (data_ptr.add(2) as *const u32).read_unaligned();
        let w3 = (data_ptr.add(3) as *const u32).read_unaligned();
        let windows = vld1q_u32([w0, w1, w2, w3].as_ptr());
        vmulq_u32(windows, vdupq_n_u32(0x9e3779b9))
    },

    splat: |scalar| {
        std::arch::aarch64::vdupq_n_u32(scalar)
    },

    any_match: |a, b| {
        use std::arch::aarch64::*;
        vmaxvq_u32(vceqq_u32(a, b)) != 0
    },
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
        let words_per_file = (pattern_frags.len() + 63) / 64;
        let mut found = vec![0u64; words_per_file];
        check_fragment_presence(buf, &pattern_frags, &mut found);

        // "hello" fragments should be found in "hello world test"
        let full_mask = if pattern_frags.len() % 64 == 0 { u64::MAX } else { (1u64 << (pattern_frags.len() % 64)) - 1 };
        assert_eq!(found[0] & full_mask, full_mask);
    }

    #[test]
    fn test_check_fragment_presence_not_found() {
        let buf = b"hello world test";
        let pattern_frags = extract_pattern_fragments(b"xyzzy");
        let words_per_file = (pattern_frags.len() + 63) / 64;
        let mut found = vec![0u64; words_per_file];
        check_fragment_presence(buf, &pattern_frags, &mut found);

        // "xyzzy" fragments should NOT be found
        assert!(found.iter().all(|&w| w == 0));
    }

    #[test]
    fn test_extract_too_short() {
        let pattern = b"hi";
        let frags = extract_pattern_fragments(pattern);
        assert_eq!(frags.len(), 0);
    }
}
