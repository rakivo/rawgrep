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

use crate::index_::{Index_, IndexMut_};
use crate::util::{prefetch_read, read_u32_unaligned_le};

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

pub const FRAGMENT_HASH_MULTIPLIER: u32 = 0x9e3779b9;

/// Hash a 4-byte fragment to u32. For fragments shorter than 4 bytes, the caller is expected
/// to zero-pad the unused trailing bytes (see [`extract_pattern_fragments_with_fragment`]) so
/// this always operates on a consistent 4-byte value.
#[inline(always)]
pub const fn hash_fragment(frag: [u8; 4]) -> u32 {
    // SAFETY: 0x9e3779b9 is odd, so multiplication by it is a
    // bijection on Z/2^32Z (odd constants are units mod 2^32). This means
    // hash_fragment can NEVER produce a collision for distinct 4-byte inputs.
    //
    // FragmentCache relies on this: it treats hash equality as fragment
    // identity (see find_fragment_index / add_fragment) with no fallback
    // verification. If this constant is ever changed, it MUST remain odd,
    // or FragmentCache's collision-free assumption breaks silently.
    u32::from_le_bytes(frag).wrapping_mul(FRAGMENT_HASH_MULTIPLIER)
}

#[inline(always)]
pub const fn hash_fragment_u32(frag: u32) -> u32 {
    frag.wrapping_mul(FRAGMENT_HASH_MULTIPLIER)
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

#[inline(always)]
pub fn ascii_lowercase_u32_le(w: u32) -> u32 {
    let bytes = w.to_le_bytes().map(|b| b.to_ascii_lowercase());
    u32::from_le_bytes(bytes)
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
    fragment_index: &IntSet<u32>,
    fragment_len: usize,
    case_insensitive: bool,
) {
    let num_frags = fragment_hashes.len();

    if num_frags == 0 || buf.len() < fragment_len {
        return;
    }

    if buf.len() < 4 {
        let mut tmp = [0u8; 4];
        tmp[..buf.len()].copy_from_slice(buf);
        return check_fragment_presence_scalar(
            &tmp,
            fragment_hashes,
            fragment_presence_scratch,
            fragment_index,
            fragment_mask_u32(fragment_len),
            case_insensitive
        );
    }

    let mask = fragment_mask_u32(fragment_len);

    #[cfg(target_arch = "x86_64")] {
        if num_frags <= 64 && buf.len() >= 64 && is_x86_feature_detected!("avx2") {
            return unsafe {
                if case_insensitive {
                    teddy::check_fragment_presence::<true >(buf, fragment_hashes, fragment_presence_scratch, mask)
                } else {
                    teddy::check_fragment_presence::<false>(buf, fragment_hashes, fragment_presence_scratch, mask)
                }
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if num_frags <= 64 && buf.len() >= 32 && std::arch::is_aarch64_feature_detected!("neon") {
            return unsafe {
                if case_insensitive {
                    teddy::check_fragment_presence::<true >(buf, fragment_hashes, fragment_presence_scratch, mask)
                } else {
                    teddy::check_fragment_presence::<false>(buf, fragment_hashes, fragment_presence_scratch, mask)
                }
            }
        }
    }

    check_fragment_presence_scalar(
        buf,
        fragment_hashes,
        fragment_presence_scratch,
        fragment_index,
        mask,
        case_insensitive,
    )
}

#[inline(always)]
fn fragment_present(hash: u32, fragment_hashes: &[u32], fragment_index: &IntSet<u32>) -> bool {
    if fragment_hashes.len() <= 8 {  // @Tune
        fragment_hashes.contains(&hash)
    } else {
        fragment_index .contains(&hash)
    }
}

/// Scalar fallback for fragment presence checking
#[inline]
pub fn check_fragment_presence_scalar(
    buf: &[u8],
    fragment_hashes: &[u32],
    fragment_presence_scratch: &mut [u64],
    fragment_index: &IntSet<u32>,
    mask: u32,
    case_insensitive: bool,
) {
    let num_frags = fragment_hashes.len();

    let words = num_frags.div_ceil(64);
    let mut found_count: usize = fragment_presence_scratch.get_(..words)
        .iter()
        .map(|w| w.count_ones() as usize).sum();

    if found_count >= num_frags { return; }

    let prefetch_dist = stride_heuristic(buf.len()); // perf hint only now

    let win = ((32 - mask.leading_zeros()) / 8) as usize;   // 3 or 4

    let mut i = 0;
    while i + win <= buf.len() {
        let ahead = i + prefetch_dist;
        if ahead + 4 <= buf.len() {
            prefetch_read(unsafe { buf.as_ptr().add(ahead) });
        }

        let mut raw = if i + 4 <= buf.len() {
            read_u32_unaligned_le(buf, i)
        } else {
            let mut t = [0u8; 4];
            t[..buf.len() - i].copy_from_slice(&buf[i..]);
            u32::from_le_bytes(t)
        };
        if case_insensitive {
            raw = ascii_lowercase_u32_le(raw);
        }
        raw &= mask;

        let hash = hash_fragment_u32(raw);

        if fragment_present(hash, fragment_hashes, fragment_index) {
            for (index, &frag_hash) in fragment_hashes.iter().enumerate() {
                if frag_hash != hash { continue; }

                let (word, bit) = (index / 64, 1u64 << (index % 64));
                if fragment_presence_scratch[word] & bit == 0 {
                    fragment_presence_scratch[word] |= bit;
                    found_count += 1;
                }

                // No break: another fragment at a different index can share this hash
            }

            if found_count == num_frags { return; }
        }

        i += 1;
    }
}

pub const FRAGMENT_HASH_MUL:     u32 = 0x9e37_79b9;
pub const FRAGMENT_HASH_MUL_INV: u32 = 0x144c_bc89;

const _: () = assert!(FRAGMENT_HASH_MUL.wrapping_mul(FRAGMENT_HASH_MUL_INV) == 1);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[allow(unsafe_op_in_unsafe_fn, clippy::needless_range_loop)]
pub mod teddy {
    use super::{tail_hash_at, tail_hash_padded, FRAGMENT_HASH_MUL_INV, Index_, IndexMut_};

    use isa::{and, any_set, lane_mask, load, load_table, lookup, splat, store, zero, Reg, LANES, LANE_SHIFT};

    //
    // Everything ISA-specific lives in 'isa', the kernel below is shared.
    // What it needs from an ISA: a register with one window start per byte lane
    // ('LANES' of them), a 16-entry byte table lookup (pshufb / tbl), and a handful
    // of and / load / store / test helpers.
    //
    // 'lane_mask' reports lane i at bit 'i << LANE_SHIFT', which is 1 bit per lane on AVX2
    // (movemask) and 4 bits per lane on NEON (no movemask, so it narrows to nibbles instead).
    //

    #[cfg(target_arch = "x86_64")]
    mod isa {
        use std::arch::x86_64::*;

        pub type Reg = __m256i;

        pub const LANES: usize     = 32;
        pub const LANE_SHIFT: u32  = 0;

        #[inline]
        #[target_feature(enable = "avx2")]
        pub unsafe fn zero() -> Reg {
            _mm256_setzero_si256()
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        pub unsafe fn splat(b: u8) -> Reg {
            _mm256_set1_epi8(b as i8)
        }

        /// The same 16-entry table in both 128-bit halves, since '_mm256_shuffle_epi8' looks up per lane.
        #[inline]
        #[target_feature(enable = "avx2")]
        pub unsafe fn load_table(t: &[u8; 16]) -> Reg {
            _mm256_broadcastsi128_si256(_mm_loadu_si128(t.as_ptr() as *const __m128i))
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        pub unsafe fn load(p: *const u8) -> Reg {
            _mm256_loadu_si256(p as *const __m256i)
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        pub unsafe fn store(p: *mut u8, v: Reg) {
            _mm256_storeu_si256(p as *mut __m256i, v)
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        pub unsafe fn and(a: Reg, b: Reg) -> Reg {
            _mm256_and_si256(a, b)
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        pub unsafe fn any_set(v: Reg) -> bool {
            _mm256_testz_si256(v, v) == 0
        }

        /// Bit 'i' set <=> byte lane 'i' of 'v' is nonzero
        #[inline]
        #[target_feature(enable = "avx2")]
        pub unsafe fn lane_mask(v: Reg) -> u64 {
            !(_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, _mm256_setzero_si256())) as u32) as u64
        }

        /// For each of the 32 bytes of 'v': which buckets have a fragment whose byte here is this one
        #[inline]
        #[target_feature(enable = "avx2")]
        pub unsafe fn lookup(lo: Reg, hi: Reg, v: Reg, nibble_mask: Reg) -> Reg {
            _mm256_and_si256(
                _mm256_shuffle_epi8(lo, _mm256_and_si256(v, nibble_mask)),
                _mm256_shuffle_epi8(hi, _mm256_and_si256(_mm256_srli_epi16::<4>(v), nibble_mask)),
            )
        }
    }

    #[cfg(target_arch = "aarch64")]
    mod isa {
        use std::arch::aarch64::*;

        pub type Reg = uint8x16_t;

        pub const LANES: usize     = 16;
        pub const LANE_SHIFT: u32  = 2;

        #[inline]
        #[target_feature(enable = "neon")]
        pub unsafe fn zero() -> Reg {
            vdupq_n_u8(0)
        }

        #[inline]
        #[target_feature(enable = "neon")]
        pub unsafe fn splat(b: u8) -> Reg {
            vdupq_n_u8(b)
        }

        /// 'tbl' takes the whole 16-entry table from one register
        #[inline]
        #[target_feature(enable = "neon")]
        pub unsafe fn load_table(t: &[u8; 16]) -> Reg {
            vld1q_u8(t.as_ptr())
        }

        #[inline]
        #[target_feature(enable = "neon")]
        pub unsafe fn load(p: *const u8) -> Reg {
            vld1q_u8(p)
        }

        #[inline]
        #[target_feature(enable = "neon")]
        pub unsafe fn store(p: *mut u8, v: Reg) {
            vst1q_u8(p, v)
        }

        #[inline]
        #[target_feature(enable = "neon")]
        pub unsafe fn and(a: Reg, b: Reg) -> Reg {
            vandq_u8(a, b)
        }

        #[inline]
        #[target_feature(enable = "neon")]
        pub unsafe fn any_set(v: Reg) -> bool {
            vmaxvq_u8(v) != 0
        }

        /// Bit '4 * i' set <=> byte lane 'i' of 'v' is nonzero.
        ///
        /// No movemask on NEON: 'vtstq' turns each nonzero byte into 0xFF, then narrowing-shifting
        /// the u16 view right by 4 packs two byte lanes into each result byte, one nibble each,
        /// and that fits in a single u64.
        #[inline]
        #[target_feature(enable = "neon")]
        pub unsafe fn lane_mask(v: Reg) -> u64 {
            let nonzero = vtstq_u8(v, v);
            let nibbles = vshrn_n_u16::<4>(vreinterpretq_u16_u8(nonzero));
            vget_lane_u64::<0>(vreinterpret_u64_u8(nibbles)) & 0x1111_1111_1111_1111
        }

        /// For each of the 16 bytes of 'v': which buckets have a fragment whose byte here is this one.
        ///
        /// 'tbl' returns 0 for an index >= 16, so the low nibble has to be masked.
        /// The high nibble doesnt: shifting u8 lanes right by 4 can't leave anything above bit 3.
        #[inline]
        #[target_feature(enable = "neon")]
        pub unsafe fn lookup(lo: Reg, hi: Reg, v: Reg, nibble_mask: Reg) -> Reg {
            vandq_u8(
                vqtbl1q_u8(lo, vandq_u8(v, nibble_mask)),
                vqtbl1q_u8(hi, vshrq_n_u8::<4>(v)),
            )
        }
    }

    /// Nibble lookup tables, one lo/hi pair per fingerprint byte.
    /// Bit b of an entry = 'some unfound fragment in bucket b has this nibble at this position'.
    /// Fragment k lives in bucket k & 7.
    struct Tables {
        lo: [[u8; 16]; 4],
        hi: [[u8; 16]; 4],
    }

    impl Tables {
        #[inline]
        fn add<const CI: bool>(&mut self, frag: [u8; 4], k: usize, positions: usize) {
            let bit = 1u8 << (k & 7);

            for p in 0..positions {
                let c = frag[p];

                self.lo[p][(c & 15) as usize] |= bit;
                self.hi[p][(c >> 4) as usize] |= bit;

                if CI {
                    //
                    // Case-insensitive: accept both cases of a letter right in the tables, so the
                    // data never has to be folded for the filter.
                    //
                    let other = if c.is_ascii_lowercase() { c - 32 }
                           else if c.is_ascii_uppercase() { c + 32 }
                           else { c };

                    self.lo[p][(other & 15) as usize] |= bit;
                    self.hi[p][(other >> 4) as usize] |= bit;
                }
            }
        }

        #[inline]
        fn clear_bucket(&mut self, bucket: usize, positions: usize) {
            let keep = !(1u8 << bucket);

            for p in 0..positions {
                for v in self.lo[p].iter_mut() { *v &= keep; }
                for v in self.hi[p].iter_mut() { *v &= keep; }
            }
        }
    }

    struct Regs {
        lo: [Reg; 4],
        hi: [Reg; 4],
    }

    #[inline]
    #[cfg_attr(target_arch = "x86_64",  target_feature(enable = "avx2"))]
    #[cfg_attr(target_arch = "aarch64", target_feature(enable = "neon"))]
    unsafe fn load_regs(t: &Tables, positions: usize) -> Regs {
        let mut r = Regs { lo: [zero(); 4], hi: [zero(); 4] };

        for p in 0..positions {
            r.lo[p] = load_table(&t.lo[p]);
            r.hi[p] = load_table(&t.hi[p]);
        }

        r
    }

    /// Same as 'check_fragment_presence', but for any number of fragments.
    /// Fragment k is bit k % 64 of 'presence[k / 64]', so each group of 64 is just its own single-word call.
    ///
    /// # Safety
    /// AVX2 (x86_64) / NEON (aarch64) must be available; presence.len() >= ceil(fragment_hashes.len() / 64).
    #[cfg_attr(target_arch = "x86_64",  target_feature(enable = "avx2"))]
    #[cfg_attr(target_arch = "aarch64", target_feature(enable = "neon"))]
    #[allow(unsafe_op_in_unsafe_fn)]
    pub unsafe fn check_fragment_presence_any_count<const CI: bool>(
        buf: &[u8],
        fragment_hashes: &[u32],
        presence: &mut [u64],
        mask: u32,
    ) {
        for (chunk, hashes) in fragment_hashes.chunks(64).enumerate() {
            check_fragment_presence::<CI>(buf, hashes, &mut presence[chunk..chunk + 1], mask);
        }
    }

    /// Exact presence of up to 64 fragments in 'buf', ORed into 'presence[0]'.
    ///
    /// # Safety
    /// AVX2 (x86_64) / NEON (aarch64) must be available; 1 <= fragment_hashes.len() <= 64; presence.len() >= 1.
    #[cfg_attr(target_arch = "x86_64",  target_feature(enable = "avx2"))]
    #[cfg_attr(target_arch = "aarch64", target_feature(enable = "neon"))]
    pub unsafe fn check_fragment_presence<const CI: bool>(
        buf: &[u8],
        fragment_hashes: &[u32],
        presence: &mut [u64],
        mask: u32,
    ) {
        let num_frags = fragment_hashes.len();
        debug_assert!((1..=64).contains(&num_frags));

        let all: u64 = if num_frags == 64 { u64::MAX } else { (1u64 << num_frags) - 1 };

        //
        // OR into the existing row: an earlier piece of a streamed file may have set bits already
        //
        let mut found = presence[0] & all;
        if found == all { return; }

        let win: usize       = ((32 - mask.leading_zeros()) / 8) as usize;  // 3 or 4 max
        let positions: usize = if win == 4 { 4 } else { 3 };                // Fingerprint bytes

        //
        // Recover each fragment's window bytes from its hash, and bucket the fragments.
        //
        let mut frag_bytes  = [[0u8; 4]; 64];
        let mut bucket_list = [[0u8; 8];  8];
        let mut bucket_len  = [0usize;    8];

        for (k, &h) in fragment_hashes.iter().enumerate() {
            frag_bytes[k] = h.wrapping_mul(FRAGMENT_HASH_MUL_INV).to_le_bytes();

            let b = k & 7;
            *bucket_list.get_mut_(b).get_mut_(*bucket_len.get_(b)) = k as u8;
            *bucket_len .get_mut_(b) += 1;
        }

        let mut tables: Tables = unsafe { core::mem::zeroed() };
        for k in 0..num_frags {
            if (found >> k) & 1 == 0 { tables.add::<CI>(frag_bytes[k], k, positions); }
        }

        let mut regs = load_regs(&tables, positions);

        let nibble_mask = splat(0x0f);

        let len  = buf.len();
        let base = buf.as_ptr();

        //
        // One block = LANES window starts (32 on AVX2, 16 on NEON).
        // It loads the buffer at +0..+positions-1 for the fingerprint (ending at off + LANES - 1 + positions) and verifies
        // candidates with a 4-byte read at up to off + LANES - 1, so it needs off + LANES + positions <= len.
        //
        let need = LANES + positions;
        let mut off = 0usize;

        while off + need <= len {
            let x = load(base.add(off));
            let y = load(base.add(off + 1));
            let z = load(base.add(off + 2));

            let mut candidates = and(
                and(
                    lookup(regs.lo[0], regs.hi[0], x, nibble_mask),
                    lookup(regs.lo[1], regs.hi[1], y, nibble_mask),
                ),
                lookup(regs.lo[2], regs.hi[2], z, nibble_mask),
            );

            if positions == 4 {
                let w = load(base.add(off + 3));
                candidates = and(candidates, lookup(regs.lo[3], regs.hi[3], w, nibble_mask));
            }

            if any_set(candidates) {
                let mut nonzero = lane_mask(candidates);

                let mut bucket_bits = [0u8; LANES];
                store(bucket_bits.as_mut_ptr(), candidates);

                let mut newly = 0u64;

                while nonzero != 0 {
                    let i = (nonzero.trailing_zeros() >> LANE_SHIFT) as usize;
                    nonzero &= nonzero - 1;

                    //
                    // Same hash the scalar path computes: folded (if CI), masked, multiplied
                    //
                    let h = tail_hash_at::<CI>(buf, off + i, mask);

                    let mut bits = *bucket_bits.get_(i) as u32;
                    while bits != 0 {
                        let b = bits.trailing_zeros() as usize;
                        bits &= bits - 1;

                        let n = *bucket_len.get_(b);
                        for j in 0..n {
                            let k = *bucket_list.get_(b).get_(j) as usize;
                            if *fragment_hashes.get_(k) == h { newly |= 1u64 << k; }
                        }
                    }
                }

                newly &= !found;
                if newly != 0 {
                    found |= newly;
                    if found == all { break; }

                    //
                    // Only the buckets that lost a fragment need their entries redone
                    //
                    let mut dirty = 0u32;
                    let mut m = newly;
                    while m != 0 {
                        dirty |= 1u32 << (m.trailing_zeros() & 7);
                        m &= m - 1;
                    }

                    while dirty != 0 {
                        let b = dirty.trailing_zeros() as usize;
                        dirty &= dirty - 1;

                        tables.clear_bucket(b, positions);

                        let n = bucket_len[b];
                        for j in 0..n {
                            let k = *bucket_list.get_(b).get_(j) as usize;
                            if (found >> k) & 1 == 0 { tables.add::<CI>(*frag_bytes.get_(k), k, positions); }
                        }
                    }

                    regs = load_regs(&tables, positions);
                }
            }

            off += LANES;
        }

        //
        // Tail: every window start the blocks above didn't reach (fewer than 'need' bytes),
        // down to 'win' bytes remaining .. a 3-byte fragment's last window only needs 3.
        //
        if found != all {
            while off + win <= len {
                let h = tail_hash_padded::<CI>(buf, off, mask);

                for (k, &fh) in fragment_hashes.iter().enumerate() {
                    if fh == h { found |= 1u64 << k; }
                }

                if found == all { break; }
                off += 1;
            }
        }

        presence[0] = found;
    }
}

#[inline(always)]
fn tail_hash_padded<const CI: bool>(buf: &[u8], offset: usize, mask: u32) -> u32 {
    if crate::util::likely(offset + 4 <= buf.len()) {
        return tail_hash_at::<CI>(buf, offset, mask);
    }

    let mut tmp = [0u8; 4];
    let n = buf.len() - offset;
    tmp[..n].copy_from_slice(&buf[offset..]);
    tail_hash_at::<CI>(&tmp, 0, mask)
}

// Hashes one window scalar-style, folding case first when this instantiation is the CI variant.
#[inline(always)]
fn tail_hash_at<const CASE_INSENSITIVE: bool>(buf: &[u8], offset: usize, mask: u32) -> u32 {
    let mut raw = u32::from_le_bytes([
        buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3],
    ]);

    if CASE_INSENSITIVE {
        raw = ascii_lowercase_u32_le(raw);
    }

    raw &= mask;
    hash_fragment_u32(raw)
}
