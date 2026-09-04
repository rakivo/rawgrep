//! # Fragment-Based Cache System
//!
//! This module implements the core fragment extraction logic for rawgrep's nowgrep-inspired
//! caching system. Fragments are small byte sequences used to quickly determine if a file
//! can be skipped without reading it.
//!
//! ## What Are Fragments?
//!
//! A **fragment** is a small (3- or 4-byte) sliding window extracted from text. For example,
//! with a 4-byte window:
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
//! ## Fragment size
//!
//! The fragment is 4 bytes whenever the pattern (or, for alternations/regex literals, the
//! *shortest* literal involved) is at least 4 bytes long. Shorter patterns fall back to a
//! 3-byte fragment so they can still use the cache at all -- previously any pattern under
//! 4 bytes (e.g. `"foo"`, or a single multi-byte UTF-8 character like an em dash, which is
//! 3 bytes in UTF-8) produced zero fragments and got no benefit from this cache whatsoever.
//!
//! We do not go below 3 bytes. A back-of-envelope collision estimate (assuming uniform
//! random bytes, which is generous -- real source text has much lower effective entropy)
//! puts the odds of a *specific* fragment appearing in a file purely by chance at roughly
//! `positions_checked / 256^fragment_len`. Each byte removed from the fragment costs a factor
//! of 256x here. At 2 bytes, a 64KB file already has a >50% chance of a spurious "found"
//! signal, and by ~1MB it's essentially guaranteed -- i.e. the presence check almost never
//! says "definitely not here" so it stops being a useful filter at all. 3 bytes is still
//! meaningfully discriminating for typical source-file sizes, so that's the floor.
//!
//! See [`MIN_FRAGMENT_LEN`] and [`select_fragment_len`].
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

#[derive(Clone, Copy)]
pub enum FragmentLen { Three, Four }

impl FragmentLen {
    #[inline(always)]
    pub const fn from_fragment_len(fragment_len: usize) -> Self {
        match fragment_len {
            3 => FragmentLen::Three,
            4 => FragmentLen::Four,
            _ => unsafe { std::hint::unreachable_unchecked() }
        }
    }

    #[inline(always)]
    pub const fn as_usize(self) -> usize {
        match self {
            FragmentLen::Three => 3,
            FragmentLen::Four  => 4,
        }
    }
}

/// Shortest pattern length for which the fragment cache is worth using at all. Below this,
/// the false-positive rate of the presence check is too high (see module docs) to provide
/// any real filtering power, so callers should skip the fragment cache entirely rather than
/// use a degenerate 1- or 2-byte window.
pub const MIN_FRAGMENT_LEN: usize = 3;

/// Hash a 4-byte fragment to u32. For fragments shorter than 4 bytes, the caller is expected
/// to zero-pad the unused trailing bytes (see [`extract_pattern_fragments_with_fragment`]) so
/// this always operates on a consistent 4-byte value.
#[inline(always)]
pub const fn hash_fragment(frag: [u8; 4]) -> u32 {
    u32::from_le_bytes(frag).wrapping_mul(0x9e3779b9)
}

#[inline(always)]
pub const fn hash_fragment_u32(frag: u32) -> u32 {
    frag.wrapping_mul(0x9e3779b9)
}

/// Byte mask that zeroes out everything past `fragment_len` bytes in a little-endian u32, so a
/// masked 4-byte load from a buffer can stand in for a genuine `fragment_len`-byte fragment.
/// `fragment_len` must be in `1..=4`; anything else is treated as a full 4-byte fragment.
#[inline(always)]
pub const fn fragment_mask_u32(fragment_len: usize) -> u32 {
    match fragment_len {
        1 => 0x0000_00FF,
        2 => 0x0000_FFFF,
        3 => 0x00FF_FFFF,
        _ => 0xFFFF_FFFF,
    }
}

/// Pick a single fragment length usable across every literal in `patterns`, or `None`
/// if the fragment cache should be skipped entirely for this query.
///
/// This has to be the *minimum* over every literal, not the maximum or an average: if pattern
/// A is 3 bytes and pattern B is 8 bytes, and we picked a 4-byte fragment, then A -- being
/// shorter than the fragment -- would contribute zero fragments. The presence check would then
/// only ever be vouching for B, and "no fragments found" could incorrectly skip a file that
/// actually contains a match via A. So every literal must be at least `fragment_len` bytes, and
/// the only way to guarantee that is to key off the shortest one. If even the shortest
/// literal is under [`MIN_FRAGMENT_LEN`], the whole query bails out of the fragment cache
/// (returns `None`) rather than silently degrading to a fragment size we know is unreliable.
pub fn select_fragment_len<'a>(patterns: impl IntoIterator<Item = &'a [u8]>) -> Option<usize> {
    let shortest = patterns.into_iter().map(<[u8]>::len).min()?;

    if shortest < MIN_FRAGMENT_LEN {
        None
    } else {
        Some(shortest.min(4))
    }
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

/// Extract fragment hashes from a search pattern using the default 4-byte fragment.
///
/// Kept for callers that don't care about short patterns; prefer
/// [`extract_pattern_fragments_with_fragment`] together with [`select_fragment_len`] for new code,
/// since this always returns empty for patterns under 4 bytes.
#[inline]
pub fn extract_pattern_fragments(pattern: &[u8]) -> Vec<u32> {
    let fragment_len = pattern.len().clamp(3, 4);
    extract_pattern_fragments_with_len(pattern, fragment_len)
}

/// Extract fragment hashes from a search pattern using a `fragment_len`-byte sliding fragment
/// (`fragment_len` should be in `MIN_FRAGMENT_LEN..=4`, typically from [`select_fragment_len`]).
///
/// Fragments shorter than 4 bytes are zero-padded on the right before hashing, so they hash
/// identically to how [`check_fragment_presence`] hashes a masked 4-byte buffer load with the
/// same `fragment_len`.
#[inline]
pub fn extract_pattern_fragments_with_len(pattern: &[u8], fragment_len: usize) -> Vec<u32> {  // @Memory @Speed: This function is called pretty much ONCE in the whole program, so it's probably fine to allocate here.
    debug_assert!((1..=4).contains(&fragment_len));

    if pattern.len() < fragment_len {
        return Vec::new();
    }

    // for N bytes, we get N-(fragment_len-1) overlapping fragment_len-byte fragments
    let mut fragments = Vec::with_capacity(pattern.len().saturating_sub(fragment_len - 1));
    let mut seen = IntSet::default();

    for fragment in pattern.windows(fragment_len) {
        let mut frag = [0u8; 4];
        frag[..fragment_len].copy_from_slice(fragment);
        let hash = hash_fragment(frag);

        if seen.insert(hash) {
            fragments.push(hash);
        }
    }

    fragments
}

/// `fragment_len` must match whatever fragment length `fragment_hashes` was extracted with (see
/// [`extract_pattern_fragments_with_fragment`]) -- it controls how many trailing bytes of each
/// masked 4-byte buffer load are ignored.
#[inline]
pub fn check_fragment_presence(
    buf: &[u8],
    fragment_hashes: &[u32],
    fragment_presence_scratch: &mut [u64],
    fragment_len: usize,
) {
    let num_frags = fragment_hashes.len();

    if num_frags == 0 {
        return;
    }

    if buf.len() < 4 {
        return;
    }

    let mask = fragment_mask_u32(fragment_len);

    #[cfg(target_arch = "x86_64")] {
        if is_x86_feature_detected!("avx2") && buf.len() >= 32 {
            return unsafe { check_fragment_presence_avx2(buf, fragment_hashes, fragment_presence_scratch, mask) };
        }
    }

    #[cfg(target_arch = "aarch64")] {
        if std::arch::is_aarch64_feature_detected!("neon") && buf.len() >= 16 {
            return unsafe { check_fragment_presence_neon(buf, fragment_hashes, fragment_presence_scratch, mask) };
        }
    }

    check_fragment_presence_scalar(buf, fragment_hashes, fragment_presence_scratch, mask)
}

/// Scalar fallback for fragment presence checking
#[inline]
fn check_fragment_presence_scalar(buf: &[u8], fragment_hashes: &[u32], fragment_presence_scratch: &mut [u64], mask: u32) {
    let num_frags = fragment_hashes.len();
    let stride = stride_heuristic(buf.len());

    // Build a set of pattern fragment hashes for O(1) lookup
    let pattern_frag_set = fragment_hashes.iter().copied().collect::<IntSet<_>>();

    let mut found_count = 0;

    let mut i = 0;
    while i + 4 <= buf.len() {
        let raw = u32::from_le_bytes([buf[i], buf[i+1], buf[i+2], buf[i+3]]) & mask;
        let hash = hash_fragment_u32(raw);

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
        fragment_load: |$data_ptr:ident, $mask_val:ident| $load_block:block,
        splat: |$scalar:ident| $splat_block:block,
        any_match: |$ha:ident, $hb:ident| $match_block:block,
    ) => {
        #[cfg(target_arch = $cfg_arch)]
        #[target_feature(enable = $feature)]
        #[allow(unsafe_op_in_unsafe_fn)]
        unsafe fn $fn_name(buf: &[u8], fragment_hashes: &[u32], fragment_presence_scratch: &mut [u64], mask: u32) {
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
                    let $mask_val = mask;
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
                    let $mask_val = mask;
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

    fragment_load: |data_ptr, mask_val| {
        use std::arch::x86_64::*;
        let w0 = (data_ptr.add(0) as *const u32).read_unaligned();
        let w1 = (data_ptr.add(1) as *const u32).read_unaligned();
        let w2 = (data_ptr.add(2) as *const u32).read_unaligned();
        let w3 = (data_ptr.add(3) as *const u32).read_unaligned();
        let w4 = (data_ptr.add(4) as *const u32).read_unaligned();
        let w5 = (data_ptr.add(5) as *const u32).read_unaligned();
        let w6 = (data_ptr.add(6) as *const u32).read_unaligned();
        let w7 = (data_ptr.add(7) as *const u32).read_unaligned();
        let fragments = _mm256_set_epi32(
            w7 as i32, w6 as i32, w5 as i32, w4 as i32,
            w3 as i32, w2 as i32, w1 as i32, w0 as i32,
        );

        // Zero out the trailing bytes beyond the fragment (no-op when fragment_len == 4)
        // *before* multiplying, so this matches hash_fragment_u32(raw & mask) exactly.
        let masked = _mm256_and_si256(fragments, _mm256_set1_epi32(mask_val as i32));

        // Hash multiplier constant: 0x9e3779b9 (golden ratio).
        // Let's pray LLVM's LICM hoists the mask/multiplier broadcasts out the loop.
        _mm256_mullo_epi32(masked, _mm256_set1_epi32(0x9e3779b9_u32 as i32))
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

    fragment_load: |data_ptr, mask_val| {
        use std::arch::aarch64::*;
        let w0 = (data_ptr.add(0) as *const u32).read_unaligned();
        let w1 = (data_ptr.add(1) as *const u32).read_unaligned();
        let w2 = (data_ptr.add(2) as *const u32).read_unaligned();
        let w3 = (data_ptr.add(3) as *const u32).read_unaligned();
        let fragments = vld1q_u32([w0, w1, w2, w3].as_ptr());
        let masked = vandq_u32(fragments, vdupq_n_u32(mask_val));
        vmulq_u32(masked, vdupq_n_u32(0x9e3779b9))
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
    fn short_pattern_gets_fragments_with_3_byte_fragment() {
        // "foo" is 3 bytes -- with the old fixed 4-byte fragment this produced zero fragments.
        let fragment_len = select_fragment_len(std::iter::once("foo".as_bytes())).unwrap();
        assert_eq!(fragment_len, 3);

        let frags = extract_pattern_fragments_with_len("foo".as_bytes(), fragment_len);
        assert_eq!(frags.len(), 1, "a 3-byte pattern with a 3-byte fragment is exactly one fragment");
    }

    #[test]
    fn em_dash_gets_fragments() {
        // U+2014 EM DASH is 3 bytes in UTF-8: [0xE2, 0x80, 0x94]
        let em_dash = "—".as_bytes();
        assert_eq!(em_dash.len(), 3);

        let fragment_len = select_fragment_len(std::iter::once(em_dash)).unwrap();
        let frags = extract_pattern_fragments_with_len(em_dash, fragment_len);
        assert_eq!(frags.len(), 1);
    }

    #[test]
    fn too_short_pattern_disables_fragment_cache() {
        // 2 bytes is below MIN_FRAGMENT_LEN -- the whole point is that the cache is not worth
        // using at all here, not that it should use an even smaller fragment.
        assert_eq!(select_fragment_len(std::iter::once("fo".as_bytes())), None);
        assert_eq!(select_fragment_len(std::iter::once("f".as_bytes())), None);
    }

    #[test]
    fn mixed_length_alternation_uses_shortest() {
        // "fo|hello" -- "fo" is only 2 bytes, so the fragment cache must bail out entirely for
        // the whole alternation, not just quietly drop "fo" from consideration.
        let patterns: [&[u8]; 2] = ["fo".as_bytes(), "hello".as_bytes()];
        assert_eq!(select_fragment_len(patterns), None);

        // "foo|hello" -- shortest is 3 bytes, so fragment_len should be 3 for both.
        let patterns: [&[u8]; 2] = ["foo".as_bytes(), "hello".as_bytes()];
        assert_eq!(select_fragment_len(patterns), Some(3));
    }

    #[test]
    fn masked_buffer_hash_matches_padded_pattern_hash() {
        // The whole trick relies on: hash(pattern zero-padded to 4 bytes) ==
        // hash(masked 4-byte buffer load), for any 4th byte in the buffer.
        let fragment_len = 3;
        let mask = fragment_mask_u32(fragment_len);

        let pattern_frag = {
            let mut frag = [0u8; 4];
            frag[..3].copy_from_slice(b"foo");
            hash_fragment(frag)
        };

        for tail_byte in 0..=255u8 {
            let buf_word = u32::from_le_bytes([b'f', b'o', b'o', tail_byte]);
            let buf_hash = hash_fragment_u32(buf_word & mask);
            assert_eq!(buf_hash, pattern_frag, "tail byte {tail_byte} should be masked out");
        }
    }
}
