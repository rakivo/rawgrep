//
// Exact, persistent memory of the files the binary probe rejected.
//
// A file is identified by FileIdentifier, the same key that the fragment cache uses,
// so an unchanged file that the probe rejected once is skipped on later runs without reading it.
//
// Only consulted when binary files are NOT being searched: the verdict is 'the probe rejects this',
// which means nothing when the probe is OFF.
//
// The file also carries the binary_worker_table, so a new run starts with the extension statistics of
// the last one instead of learning them again.
//

#![allow(unsafe_op_in_unsafe_fn)]

use crate::index_::Index_;
use crate::parser::FileIdentifier;
use crate::util::{read_u32_unaligned_le, read_u64_unaligned_le};

use std::{fs, io, path::Path};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};

const MAGIC:      u32 = 0x5247_4256;  // 'RGBV'

const VERSION:    u32 = 1;

// Upper bound on what is kept. Beyond it entries no file matched this run are dropped
// (files that changed or were deleted leave dead fingerprints behind).
const MAX_KEPT:   usize =  1 * 1024 * 1024;
const MAX_LOADED: usize = 64 * 1024 * 1024;

#[cfg_attr(
    any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "powerpc64"),
    repr(align(128))
)]
#[cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "powerpc64")),
    repr(align(64))
)]
struct CachePad<T>(T);

impl<T> std::ops::Deref for CachePad<T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T { &self.0 }
}

// What the binary probe looks at. For a file we expect to be rejected, this is all we want to
// fetch upfront, both as a prefetch hint and as the first read.
pub const PROBE_BYTES: usize = 2 * 1024;

pub const SLOT_COUNT: usize = 512;

// Per-slot: high 16 bits = files rejected by the probe, low 16 = files accepted.
// Collisions between extensions only blur a heuristic, therefore nothing depends on this being exact.
static WORKER_TABLE: [CachePad<AtomicU32>; SLOT_COUNT] = [const { CachePad(AtomicU32::new(0)) }; SLOT_COUNT];

use binary_worker_table::*;

pub mod binary_worker_table {
    use super::*;

    //
    // Once a slot has SETTLED_AT observations it stops counting every file and only takes a sample:
    // 1 in 2^SAMPLE_SHIFT, picked by inode number so the choice is uncorrelated with the extension.
    //
    // That keeps hot lines (c, h, ...) from bouncing between every worker, still lets a slot that
    // settled on the wrong answer correct itself, and also applies to mixed slots, which never
    // settled under the old '16 of one kind and none of the other' rule and so kept writing forever.
    //
    pub const SETTLED_AT:   u32 = 16;
    pub const SAMPLE_SHIFT: u32 = 4;
    pub const CAP:          u32 = 0x7FFF;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Verdict { Unknown, Text, Binary }

    #[inline]
    fn slot(file_ext_or_name: &[u8]) -> &'static AtomicU32 {
        // fnv1a over at most 8 lowercase bytes
        let mut h = 0x811c_9dc5u32;
        for &b in file_ext_or_name.iter().take(8) {
            h = (h ^ b.to_ascii_lowercase() as u32).wrapping_mul(0x0100_0193);
        }

        &WORKER_TABLE[(h as usize) & (SLOT_COUNT - 1)]
    }

    /// What this file's extension says: rejected by the probe often enough to be probably binary,
    /// accepted often enough to be probably text, or not enough to tell
    /// (this includes extensionless files, which all share one slot and are usually a mix...?).
    #[inline]
    pub fn verdict(file_ext_or_name: &[u8]) -> Verdict {
        let v = slot(file_ext_or_name).load(Relaxed);
        let (binary, text) = (v >> 16, v & 0xFFFF);

        if      binary >= 4 && binary >= 8 * text   { Verdict::Binary }
        else if text   >= 4 && text   >= 8 * binary { Verdict::Text }
        else                                        { Verdict::Unknown }
    }

    /// Should this file be treated as likely-binary for prefetch and first-read sizing?
    ///
    /// The extension decides when it has a clear opinion. When it doesn't, fall back to what the
    /// files already probed in this directory looked like: build outputs and object stores are
    /// binary files with unique names, but they cluster by directory.
    ///
    /// A clear 'text' verdict is never overridden, so a stray .c file in a directory full of objects
    /// is still being fully read.
    #[inline]
    pub fn likely_binary(file_ext_or_name: &[u8], dir: &DirTally) -> bool {
        match verdict(file_ext_or_name) {
            Verdict::Binary  => true,
            Verdict::Text    => false,
            Verdict::Unknown => dir.likely_binary(),
        }
    }

    /// Record one probe outcome (binary = the probe rejected the file).
    #[inline]
    pub fn record(file_ext_or_name: &[u8], file_id: u64, binary: bool) {
        let s = slot(file_ext_or_name);
        let v = s.load(Relaxed);
        let (bin, text) = (v >> 16, v & 0xFFFF);

        if bin + text >= SETTLED_AT
        && (file_id.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - SAMPLE_SHIFT)) != 0
        {
            return;
        }

        //
        // A counter at its cap would carry into the other half, so age both instead of
        // refusing to count.
        //
        if (binary && bin >= CAP) || (!binary && text >= CAP) {
            s.store(((bin >> 1) << 16) | (text >> 1), Relaxed);
        }

        // The checks above use a stale load, so racing threads can overshoot a little
        s.fetch_add(if binary { 1 << 16 } else { 1 }, Relaxed);
    }

    /// Probe outcomes for the directory this worker is walking right now.
    /// One per worker. Reset when the worker starts a new directory.
    ///
    /// Lookahead runs ahead of the probe, so this only has something to say once a few files of the
    /// directory have been processed.
    #[derive(Default)]
    pub struct DirTally {
        binary: u32,
        text:   u32,
    }

    impl DirTally {
        #[inline]
        pub const fn reset(&mut self) {
            self.binary = 0;
            self.text   = 0;
        }

        #[inline]
        pub const fn record(&mut self, binary: bool) {
            let c = if binary { &mut self.binary } else { &mut self.text };
            *c = c.saturating_add(1);
        }

        #[inline]
        pub const fn likely_binary(&self) -> bool {
            let (b, t) = (self.binary as u64, self.text as u64);
            b >= 4 && b >= 8 * t
        }
    }
}

#[inline]
pub fn fingerprint(id: FileIdentifier) -> u64 {
    #[inline]
    const fn mix(mut z: u64) -> u64 {
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    let mut h = mix(VERSION as u64 ^ 0x5247_4256_0000_0000);

    for x in [id.key.device_id, id.key.inode, id.meta.mtime_sec as u64, id.meta.size] {
        h = mix(h.wrapping_add(x).wrapping_add(0x9E37_79B9_7F4A_7C15));
    }

    h
}

#[derive(Debug)]
pub struct BinaryVerdicts {
    known: Vec<u64>,       // Sorted and unique
    index: Vec<u32>,       // Bucket -> first position in 'known'
    shift: u32,            // 64 - log2(buckets)
    used:  Vec<AtomicU64>, // Bit per 'known' entry -- matched a file this run
}

impl BinaryVerdicts {
    pub fn empty() -> Self {
        Self::from_sorted(Vec::new())
    }

    fn from_sorted(known: Vec<u64>) -> Self {
        //
        // ~4 entries per bucket capped at 2^24 buckets
        //

        let mut bits = 1u32;
        while (1usize << bits) * 4 < known.len() && bits < 24 { bits += 1; }

        let buckets = 1usize << bits;
        let shift   = 64 - bits;

        // index[b] = first position whose top bits are >= b; index[buckets] = known.len()
        let mut index = vec![0u32; buckets + 1];
        let mut p     = 0usize;

        for (b, slot) in index.iter_mut().enumerate() {
            while p < known.len() && ((known.get_(p) >> shift) as usize) < b { p += 1 }
            *slot = p as u32;
        }

        Self {
            used: (0..known.len().div_ceil(64)).map(|_| AtomicU64::new(0)).collect(),
            known,
            index,
            shift,
        }
    }

    /// Any problem (missing, wrong magic or version, truncated, unsorted) gives an empty set.
    #[inline]
    pub fn load(path: &Path) -> Self {
        crate::util::mmap_populate(path)
            .and_then(|mmap| Self::parse(&mmap))
            .unwrap_or_else(Self::empty)
    }

    fn parse(buf: &[u8]) -> Option<Self> {
        let u32_at = |o: usize| buf.get(o..o.checked_add(4)?).map(|b| read_u32_unaligned_le(b, 0));
        let u64_at = |o: usize| buf.get(o..o.checked_add(8)?).map(|b| read_u64_unaligned_le(b, 0));

        if u32_at(0)? != MAGIC || u32_at(4)? != VERSION { return None; }
        if u32_at(8)? as usize != SLOT_COUNT            { return None; }

        let mut off = 12;

        let mut table = [0u32; SLOT_COUNT];
        for (i, t) in table.iter_mut().enumerate() {
            *t = u32_at(off + i * 4)?;
        }
        off += SLOT_COUNT * 4;

        let count = u64_at(off)? as usize;
        off += 8;

        if count > MAX_LOADED { return None; }

        let end   = off.checked_add(count.checked_mul(8)?)?;
        let known = buf
            .get(off..end)?
            .chunks_exact(8)
            .map(|c| read_u64_unaligned_le(c, 0))
            .collect::<Vec<_>>();

        // Must be sorted and unique
        if !known.windows(2).all(|w| w[0] < w[1]) { return None; }

        //
        // Load the saved table, counts are scaled down to a small total
        // with the ratio kept, so a stale verdict is quick to lose against what this run sees.
        //
        {
            let saved = &table;

            for (s, &v) in WORKER_TABLE.iter().zip(saved) {
                let (bin, text) = (v >> 16, v & 0xFFFF);
                let scale = ((bin + text) / (2 * SETTLED_AT)).max(1);

                s.store(((bin / scale) << 16) | (text / scale), Relaxed);
            }
        }

        Some(Self::from_sorted(known))
    }

    /// Position of 'fingerprint' in 'known' if present.
    #[inline(always)]
    fn find(&self, fingerprint: u64) -> Option<usize> {
        if self.known.is_empty() { return None; }

        let b  = (fingerprint >> self.shift) as usize;
        let lo = *self.index.get_(b)         as usize;
        let hi = *self.index.get_(b + 1)     as usize;

        for i in lo..hi {
            let k = *self.known.get_(i);

            if k == fingerprint { return Some(i); }
            if k >  fingerprint { return None;    }  // Bucket entries are sorted
        }

        None
    }

    /// Did the probe reject this exact file on an earlier run?
    /// Marks the entry as used this run.
    #[inline]
    pub fn is_binary(&self, fingerprint: u64) -> bool {
        match self.find(fingerprint) {
            Some(i) => {
                //
                // Set the bit only if it isn't already
                //
                let word = &self.used[i >> 6];
                let bit  = 1u64 << (i & 63);
                if word.load(Relaxed) & bit == 0 { word.fetch_or(bit, Relaxed); }

                true
            }

            None => false,
        }
    }

    /// Like is_binary, without marking it used.
    #[inline(always)]
    pub fn contains(&self, fingerprint: u64) -> bool { self.find(fingerprint).is_some() }

    /// Nothing loaded: callers can skip computing a fingerprint at all.
    #[inline(always)]
    pub fn is_empty(&self) -> bool { self.known.is_empty() }

    #[inline(always)]
    pub fn len(&self) -> usize { self.known.len() }

    /// Write 'known + fresh' back. 'fresh' is every fingerprint the probe rejected this run,
    /// concatenated from the workers.
    ///
    /// Nothing new means nothing to write, and entries we already have don't count as something.
    #[inline]
    pub fn save(&self, path: &Path, mut fresh: Vec<u64>) -> io::Result<()> {
        if fresh.is_empty() { return Ok(()); }

        fresh.sort_unstable();
        fresh.dedup();

        fresh.retain(|&fingerprint| !self.contains(fingerprint));
        if fresh.is_empty() { return Ok(()); }

        let merged = self.merge(&fresh, MAX_KEPT);
        let table: [u32; SLOT_COUNT] = {
            use std::mem::MaybeUninit;

            let mut out: [MaybeUninit<_>; SLOT_COUNT] = unsafe { MaybeUninit::uninit().assume_init() };

            for (o, s) in out.iter_mut().zip(WORKER_TABLE.iter()) {
                o.write(s.load(Relaxed));
            }

            const _: () = assert!(WORKER_TABLE.len() == SLOT_COUNT);
            unsafe { std::mem::transmute::<[std::mem::MaybeUninit<u32>; SLOT_COUNT], [u32; SLOT_COUNT]>(out) }
        };

        let magic_bytes      = MAGIC.to_le_bytes();
        let version_bytes    = VERSION.to_le_bytes();
        let table_len_bytes  = (table.len() as u32).to_le_bytes();
        let merged_len_bytes = (merged.len() as u64).to_le_bytes();

        let mut out: Vec<u8> = Vec::new();
        crate::batch_extend_pod!(out, [
            &magic_bytes[..], &version_bytes[..], &table_len_bytes[..], &table[..],
            &merged_len_bytes[..], &merged[..],
        ]);

        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        fs::write (&tmp, &out)?;
        #[cfg(unix)] { _ = crate::cache::fix_ownership(&tmp); }
        fs::rename(&tmp, path)
    }

    /// 'fresh' must be sorted and unique. Result is sorted and unique.
    ///
    /// A known entry is dropped only when the set is over 'cap' AND no file matched it this run
    /// (its file changed or is gone).
    ///
    /// An entry that also appears in 'fresh' is always kept.
    fn merge(&self, fresh: &[u64], cap: usize) -> Vec<u64> {
        let keep_unused = self.known.len() + fresh.len() <= cap;
        let keep_known  = |i: usize| {
            keep_unused || (self.used.get_(i >> 6).load(Relaxed) >> (i & 63)) & 1 != 0
        };

        let mut merged = Vec::with_capacity(self.known.len() + fresh.len());

        let (mut i, mut j) = (0usize, 0usize);
        loop {
            match (self.known.get(i), fresh.get(j)) {
                (Some(&k), Some(&f)) if k == f => { merged.push(k); j += 1;             i += 1 }
                (Some(&k), Some(&f)) if k <  f => { if keep_known(i) { merged.push(k) } i += 1 }
                (Some(&k), None)               => { if keep_known(i) { merged.push(k) } i += 1 }
                (_,        Some(&f))           => { merged.push(f); j += 1 }
                (None,     None)               => break,
            }
        }

        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn xorshift(s: &mut u64) -> u64 { *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17; s.wrapping_mul(0x9E37_79B9_7F4A_7C15) }

    fn make(mut v: Vec<u64>) -> BinaryVerdicts {
        v.sort_unstable();
        v.dedup();
        BinaryVerdicts::from_sorted(v)
    }

    #[test]
    fn lookup_matches_a_hashset() {
        let mut rng = 0x1234_5678_9ABC_DEF1u64;

        for round in 0..300 {
            let n = (xorshift(&mut rng) % 3000) as usize;

            let mut v: Vec<u64> = (0..n).map(|_| xorshift(&mut rng)).collect();

            // Awkward shapes: extremes, and many keys sharing their top bits (one crowded bucket)
            v.extend([0, 1, u64::MAX, u64::MAX - 1, 1 << 63]);
            if round % 3 == 0 {
                let base = xorshift(&mut rng) & !0xFFFF_FFFF;
                v.extend((0..200).map(|_| base | (xorshift(&mut rng) & 0xFFFF_FFFF)));
            }

            let bv  = make(v.clone());
            let set: HashSet<u64> = v.iter().copied().collect();

            for &k in &v { assert!(bv.is_binary(k), "missed a key that is present"); }

            for _ in 0..2000 {
                let q = if xorshift(&mut rng) % 4 == 0 { v[(xorshift(&mut rng) as usize) % v.len()] ^ 1 } else { xorshift(&mut rng) };
                assert_eq!(bv.is_binary(q), set.contains(&q), "q={q:#x}");
            }
        }

        assert!(!BinaryVerdicts::empty().is_binary(12345));
    }

    #[test]
    fn merge_is_sorted_unique_and_gc_only_drops_unused_over_the_cap() {
        let bv = make(vec![10, 20, 30, 40, 50]);

        // Mark 20 and 40 as matched this run
        assert!(bv.is_binary(20));
        assert!(bv.is_binary(40));

        // Under the cap: everything is kept, duplicates collapse
        assert_eq!(bv.merge(&[5, 30, 60], 100), vec![5, 10, 20, 30, 40, 50, 60]);

        // Over the cap: known entries nobody matched (10, 30, 50) go, unless they are in `fresh` too
        assert_eq!(bv.merge(&[5, 30, 60], 3), vec![5, 20, 30, 40, 60]);
    }

    #[test]
    fn save_is_a_no_op_when_nothing_is_new() {
        let path = std::env::temp_dir().join(format!("rgbv-noop-{}", std::process::id()));

        make(vec![1, 2, 3]).save(&path, vec![1, 2, 3, 4]).unwrap();
        let loaded = BinaryVerdicts::load(&path);
        assert_eq!(loaded.len(), 4);

        // Overwrite with a marker: a save that has only known entries must not touch the file
        fs::write(&path, b"marker").unwrap();
        loaded.save(&path, vec![4, 3, 2, 1, 1]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"marker");

        // ...but one genuinely new entry does rewrite it
        loaded.save(&path, vec![4, 5]).unwrap();
        assert_ne!(fs::read(&path).unwrap(), b"marker");
        assert_eq!(BinaryVerdicts::load(&path).len(), 5);

        _ = fs::remove_file(&path);
    }

    #[test]
    fn save_then_load_round_trips() {
        let path = std::env::temp_dir().join(format!("rgbv-test-{}", std::process::id()));

        let bv = make(vec![3, 9, 27]);
        bv.save(&path, vec![81, 9, 1]).unwrap();

        let loaded = BinaryVerdicts::load(&path);
        assert_eq!(loaded.len(), 5);
        for k in [1, 3, 9, 27, 81] { assert!(loaded.is_binary(k)); }
        assert!(!loaded.is_binary(4));

        // Garbage and truncation are an empty set, never a failure
        fs::write(&path, b"nope").unwrap();
        assert_eq!(BinaryVerdicts::load(&path).len(), 0);
        assert_eq!(BinaryVerdicts::load(&path.with_extension("missing")).len(), 0);

        _ = fs::remove_file(&path);
    }
}
