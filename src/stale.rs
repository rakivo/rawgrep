//
// Stale block-device page cache tracking.
//
// rawgrep reads the block device, whose page cache is separate from the per-file one.
//
// Writeback of an edited file goes around the device cache, so a data block cached there
// before the edit stays stale until dropped. sync/syncfs() doesn't help (it only flushes dirty pages),
// and dropping the whole device cache every run makes everything cold, which would make everything
// really slow, which would make me really sad.
//
// Only files that changed can be stale, and a changed file has a fresh ctime. The device cache
// is empty at boot, so only files with ctime >= boot time are candidates. Candidates get their
// clean device pages dropped just before they're read.
//
// To keep them warm afterwards, a memo of (inode, ctime) pairs is persisted per boot, it's only
// written for files that were quiet before this run's sync() (ctime < run_start - KERNEL_THRESHOLD),
// because for those, whatever we read after dropping is what's final on disk.
//
// A memo entry only certifies bytes that were actually re-read after the drop, so it's only
// written when the drop covered the whole file (max_size >= file_size) -- otherwise a later run
// reading further into the file would wrongly trust an unverified tail.
//

use crate::debug;
use crate::util::likely;
use crate::parser::UniversalFileId;
use crate::index_::{Index_, IndexMut_};
use crate::util::{RawAppend, read_u64_unaligned_le, mmap_populate};

use std::io::Write;
use std::path::PathBuf;
use std::fs::OpenOptions;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};

// Kernel timestamps are coarse and taken separately from ours
const KERNEL_THRESHOLD_SECS: i64 = 2;

// The wall clock can be stepped after boot (RTC, NTP), so look this much further back than boot.
const BOOT_MARGIN_SECS: i64 = 300;

const MAGIC:          &[u8; 8]   = b"RGSTALE1";
const BOOT_ID_LEN:     usize     = 36;
const HEADER_LEN:      usize     = 8 + BOOT_ID_LEN;
const RECORD_LEN:      usize     = 8; // (inode: u32, ctime: u32) in LE

// ctime >= this: The file may have changed since boot. MIN (before init) = everything, i.e. safe but slow.
static CANDIDATE_FROM: AtomicI64 = AtomicI64::new(i64::MIN);

// ctime <  this: The file was quiescent before our sync()
static SETTLED_BEFORE: AtomicI64 = AtomicI64::new(i64::MIN);

static RUN_START:      AtomicI64 = AtomicI64::new(0);
static PAGE_SIZE:      AtomicU64 = AtomicU64::new(4096);
static DROPPED_FILES:  AtomicU64 = AtomicU64::new(0);

// Path of the stale-file memo, for the holder to keep warm. 'None' before 'init()' has run, or
// if the memo doesn't hold anything yet worth protecting from swap (nothing was memoized as of
// the last save, e.g. this is the first run since boot).
#[inline]
pub fn holder_path() -> Option<PathBuf> {
    MEMO.get().filter(|m| !m.known.is_empty()).map(|m| m.path.clone())
}

// Might this file's data blocks be stale in the device page cache?
#[inline(always)]
pub fn needs_invalidation(inode: UniversalFileId, ctime_sec: i64) -> bool {
    debug_assert_eq!(inode >> 32, 0, "inode doesn't fit in u32 since stale module assumes ext4 (@Incomplete)");

    if likely(ctime_sec < CANDIDATE_FROM.load(Relaxed)) { return false; }

    match MEMO.get() {
        Some(m) => m.known.get(inode as u32) != Some(ctime_sec as u32),
        None    => true,
    }
}

/// The file's pages were just dropped!
#[cold]
#[inline(never)]
pub fn note_invalidated(inode: u64, ctime_sec: i64, complete: bool) {
    DROPPED_FILES.fetch_add(1, Relaxed);

    if likely(!complete || ctime_sec >= SETTLED_BEFORE.load(Relaxed)) { return }

    if let Some(m) = MEMO.get() {
        if let Ok(mut added) = m.added.lock() {
            added.push((inode as u32, ctime_sec as u32));
        }
    }
}

// Flat open-addressing table for the (inode -> ctime) memo, built once at load and read-only
// for the rest of the run. Inode 0 is never allocated on ext4 (this module is only ever
// used from the ext4 path for now (@Incomplete)), so it doubles as the 'empty slot' sentinel for free.
//
// Each slot packs (ctime << 32 | inode) into one u64.
struct InodeTable {
    slots: Vec<u64>,
    mask:  usize,     // slots.len() - 1, for probe wraparound (len is a power of two)
    shift: u32,       // 32 - log2(slots.len()), so the hash uses the high (well-mixed) bits
    len:   usize,
}

impl InodeTable {
    #[inline(always)]
    fn with_capacity(min_entries: usize) -> Self {
        // Keep the load factor under ~50% so probe chains stay short
        let cap = min_entries.saturating_mul(2).next_power_of_two().max(16);

        InodeTable {
            slots: vec![0u64; cap],
            mask:  cap - 1,
            shift: 32 - cap.trailing_zeros(),
            len:   0,
        }
    }

    #[inline(always)]
    const fn is_empty(&self) -> bool { self.len == 0 }

    #[inline(always)]
    const fn pack(ino: u32, ctime: u32) -> u64 { ((ctime as u64) << 32) | ino as u64 }

    #[inline(always)]
    const fn unpack(v: u64) -> (u32, u32) { (v as u32, (v >> 32) as u32) }  // (ino, ctime)

    #[inline(always)]
    const fn hash(&self, ino: u32) -> usize {
        // Fibonacci hashing: one multiply, then take the high bits (better mixed than the low
        // bits for a multiplicative hash). Spreads ext4 inode numbers, allocated in runs per
        // block group, so raw low bits cluster across the table.
        ((ino.wrapping_mul(0x9E37_79B9)) >> self.shift) as usize
    }

    // Insert, keeping the larger ctime on a duplicate key
    fn insert_max(&mut self, inode_num: u32, ctime: u32) {
        debug_assert_ne!(inode_num, 0, "inode 0 is never valid on ext4; reserved as the empty-slot sentinel");

        let mut i = self.hash(inode_num);
        loop {
            let slot = *self.slots.get_(i);
            if slot == 0 {
                *self.slots.get_mut_(i) = Self::pack(inode_num, ctime);
                self.len += 1;
                return;
            }

            let (slot_ino, slot_ctime) = Self::unpack(slot);
            if slot_ino == inode_num {
                if ctime > slot_ctime {
                    *self.slots.get_mut_(i) = Self::pack(inode_num, ctime);
                }
                return;
            }

            i = (i + 1) & self.mask;
        }
    }

    #[inline]
    fn get(&self, ino: u32) -> Option<u32> {
        if ino == 0 { return None; }  // Poisoned...

        let mut i = self.hash(ino);
        loop {
            let slot = *self.slots.get_(i);
            if slot == 0 { return None; }

            let (slot_ino, slot_ctime) = Self::unpack(slot);
            if slot_ino == ino { return Some(slot_ctime); }

            i = (i + 1) & self.mask;
        }
    }
}

struct Memo {
    known:  InodeTable,
    added:  Mutex<Vec<(u32, u32)>>,
    path:   PathBuf,
    header: [u8; HEADER_LEN],
}

static MEMO: OnceLock<Memo> = OnceLock::new();

// @Cleanup: run_temperature::cachestat already kinda asks for the page size we could reuse...?
#[inline(always)]
pub fn page_size() -> u64 { PAGE_SIZE.load(Relaxed) }

// Call right before the startup sync(), a file modified after this point may not have been
// written back by that sync, so it must not be memoized as settled.
pub fn mark_run_start() {
    RUN_START.store(now_secs(), Relaxed);
}

pub fn init(device_path: &str) {
    let now       = now_secs();
    let run_start = match RUN_START.load(Relaxed) { 0 => now, t => t };

    SETTLED_BEFORE.store(run_start - KERNEL_THRESHOLD_SECS, Relaxed);

    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page > 0 { PAGE_SIZE.store(page as u64, Relaxed); }

    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } == 0 {
        CANDIDATE_FROM.store(now - ts.tv_sec - BOOT_MARGIN_SECS, Relaxed);
    }

    //
    // The memo needs to know which boot it belongs to. Without that (or without a cache dir) we
    // simply run without one: correct, and slower for files changed since boot.
    //
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
    let boot_id = boot_id.trim();
    if boot_id.is_empty() { return; }

    let key: String = device_path.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    let Ok(path) = crate::cache::get_cache_path(None, &format!("stale_{key}.bin")) else { return };

    let mut header = [0u8; HEADER_LEN];
    header.get_mut_(..8).copy_from_slice(MAGIC);
    let n = boot_id.len().min(BOOT_ID_LEN);
    header.get_mut_(8..8 + n).copy_from_slice(boot_id.as_bytes().get_(..n));

    let known = if let Some(mmap) = mmap_populate(&path) {
        let valid =
                mmap.len() >= HEADER_LEN
            &&  mmap.get_(..HEADER_LEN) == header
            && (mmap.len() - HEADER_LEN) % RECORD_LEN == 0;

        if likely(valid) {
            let record_count = (mmap.len() - HEADER_LEN) / RECORD_LEN;

            let mut table = InodeTable::with_capacity(record_count);
            for r in mmap.get_(HEADER_LEN..).chunks_exact(RECORD_LEN) {
                let word               = read_u64_unaligned_le(r, 0);
                let (inode_num, ctime) = InodeTable::unpack(word);

                if inode_num != 0 {
                    table.insert_max(inode_num, ctime);
                }
            }

            table
        } else {
            InodeTable::with_capacity(0) // Torn / Foreign-boot file: discard, run without a memo
        }
    } else {
        InodeTable::with_capacity(0)     // No file yet, or couldn't map it
    };

    let memo = Memo { known, path, header, added: Default::default() };

    if MEMO.set(memo).is_ok() {
        unsafe { libc::atexit(save_at_exit); }
    }
}

extern "C" fn save_at_exit() { save(); }

pub fn save() {
    let Some(m) = MEMO.get() else { return };

    let added = match m.added.lock() {
        Ok(mut a) => std::mem::take(&mut *a),
        Err(_)    => return,
    };

    debug!(
        "stale: dropped device pages of {} files, {} new memo entries",
        DROPPED_FILES.load(Relaxed),
        added.len()
    );

    if added.is_empty() { return; }


    //
    // The file is a compacted snapshot, not an append log. Every save() rewrites it from
    // scratch as the union of known and added (max ctime wins per inode), so re-settling
    // the same file across many runs this boot never grows the file past one record per
    // distinct memoized inode.
    //
    let mut merged = InodeTable::with_capacity(m.known.len + added.len());

    for &slot in &m.known.slots {
        if slot != 0 {
            let (ino, ctime) = InodeTable::unpack(slot);
            merged.insert_max(ino, ctime);
        }
    }

    for (ino, ctime) in added {
        merged.insert_max(ino, ctime);
    }

    let total_len = HEADER_LEN + merged.len * RECORD_LEN;
    let mut buf = Vec::with_capacity(total_len);

    let mut cursor = RawAppend::new(&mut buf);
    unsafe {
        cursor.extend(&m.header);

        for &slot in &merged.slots {
            if slot != 0 {
                cursor.extend(&slot.to_le_bytes());
            }
        }
    }
    cursor.finish();

    let tmp_path = PathBuf::from(format!("{}.tmp.{}", m.path.display(), std::process::id()));

    let wrote = OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(&tmp_path)
        .and_then(|mut f| f.write_all(&buf));

    match wrote {
        Ok(())  => { _ = std::fs::rename(&tmp_path, &m.path); }
        Err(_)  => { _ = std::fs::remove_file(&tmp_path); }  // Don't leave droppings on failure
    }
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
