#![allow(clippy::needless_range_loop)]

use crate::writeln_blue;
use crate::unwrap_::Unwrap_;
use crate::index_::{Index_, IndexMut_};
use crate::util::{likely, unlikely, prefetch_read};
use crate::parser::{FileIdentifier, FileKey, FileMeta};

use std::io;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU32;
use std::time::{Instant, Duration};
#[cfg(not(feature = "no-cache-stats"))]
use std::sync::atomic::Ordering;

const FILE_LOOKUP_EMPTY: u32 = u32::MAX;

/// File slot flag:       An existing row that must be zeroed before its bits are written.
const RESET: u32 = 1 << 31;

/// File slot marker:     A new file that did not fit under `max_files`.
const DROPPED: u32 = u32::MAX;

/// Fragment slot marker: The fragment could not be given a cache slot.
const NO_SLOT: u32 = u32::MAX;

#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: u32,
    pub misses: u32,
    pub invalidations: u32,
    pub dropped_at_capacity: u32,
}

#[derive(Debug, Default)]
#[cfg(not(feature = "no-cache-stats"))]
pub struct AtomicCacheStats {
    pub hits: AtomicU32,
    pub misses: AtomicU32,
    pub invalidations: AtomicU32,
    pub dropped_at_capacity: AtomicU32,
}

#[cfg(not(feature = "no-cache-stats"))]
impl AtomicCacheStats {
    pub fn to_cache_stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            invalidations: self.invalidations.load(Ordering::Relaxed),
            dropped_at_capacity: self.dropped_at_capacity.load(Ordering::Relaxed),
        }
    }
}

impl Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total_lookups = self.hits + self.misses;

        writeln_blue!(f, "Cache Summary:")?;

        macro_rules! cache_row {
            ($label:expr, $count:expr) => {
                let pct = if total_lookups == 0 { 0.0 } else { ($count as f64 / total_lookups as f64) * 100.0 };
                writeln!(f, "  {:<25} {:>8} ({:>5.1}%)", $label, $count, pct)?;
            };
        }

        cache_row!("Total lookups", total_lookups);
        cache_row!("Hits", self.hits);
        cache_row!("Misses", self.misses);

        if self.invalidations > 0 {
            writeln!(f, "  {:<25} {:>8}", "Invalidations", self.invalidations)?;
        }

        if self.dropped_at_capacity > 0 {
            writeln!(f, "  Files dropped at capacity {:>8} -- These files will never be cached until max_files is increased", self.dropped_at_capacity)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_fragments: usize,
    pub max_files: usize,
    pub cache_dir: Option<Box<Path>>,
    pub ignore_cache: bool,
}

impl CacheConfig {
    /// Calculate from memory budget in MB
    pub fn from_memory_mb(memory_mb: usize) -> Self {
        // Memory breakdown:
        // - fragment_hashes: max_fragments * 4 bytes
        // - fragment_data:   max_fragments * 4 bytes
        // - file_keys:       max_files * 16 bytes
        // - file_metas:      max_files * 16 bytes
        // - file_bitsets:    max_files * max_fragments / 8 bytes
        // - file_lookup:     (max_files * 2) * 4 bytes (load factor 0.5)
        //
        // Total = ~ max_fragments * 8 + max_files * (32 + max_fragments/8 + 8)
        // Simplified: max_files * max_fragments / 8 dominates

        let bytes = memory_mb * 1024 * 1024;

        // For literal patterns: ~2-10 fragments, so pattern fragments dominate
        // Assume 10 pattern fragments max (conservative)
        let assumed_fragments = 10usize; // @Constant @Tune

        // Memory per file:
        // - file_key: 16 bytes
        // - file_meta: 16 bytes
        // - file_bitset: assumed_fragments bits = ~2 bytes
        // - file_lookup: 8 bytes (2x for hash table)
        // Total: ~42 bytes per file
        let bytes_per_file = 16 + 16 + assumed_fragments.div_ceil(8) + 8;

        let max_files = (bytes / bytes_per_file).clamp(10_000, 10_000_000); // @Constant @Tune
        let max_fragments = assumed_fragments.max(1024);

        Self {
            max_fragments,
            max_files,
            cache_dir: None,
            ignore_cache: false,
        }
    }
}

const CACHE_MAGIC: u64 = 0x5247_4352_4157_0001; // "RAWGRC" + version 1

/// A pointer+length pair that can safely produce slices.
struct FatPtr<T> {
    ptr: *const T,
    len: usize
}

impl<T: Copy> FatPtr<T> {
    #[inline(always)]
    #[allow(clippy::borrowed_box)]
    const fn from_box(boxed: &Box<[T]>) -> Self {
        Self { ptr: boxed.as_ptr(), len: boxed.len() }
    }

    /// Create from raw pointer and length (for mmap data)
    ///
    /// # SAFETY
    /// - `ptr` must be valid for reads of `len * size_of::<T>()` bytes
    /// - `ptr` must be properly aligned for T
    /// - The memory must remain valid for the lifetime of this FatPtr
    #[inline(always)]
    const unsafe fn from_raw(ptr: *const T, len: usize) -> Self {
        Self { ptr, len }
    }

    #[inline(always)]
    fn get(&self, index: usize) -> T {
        let Self { ptr, len } = *self;
        debug_assert!(index < len, "FatPtr: index {index} out of bounds (len {len})");
        unsafe { *ptr.add(index) }
    }

    #[inline(always)]
    #[allow(unused)]
    fn slice(&self, start: usize, end: usize) -> &[T] {
        let Self { ptr, len } = *self;

        debug_assert!(start < len && end < len, "FatPtr: slice out of bounds (len {len})");

        if len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(ptr, len) } }
    }

    #[inline(always)]
    fn make_slice(&self, new_len: usize) -> &[T] {
        let Self { ptr, len } = *self;

        debug_assert!(new_len <= len, "FatPtr: slice out of bounds (new len {new_len}) (len {len})");

        if new_len == 0 { &[] } else { unsafe { core::slice::from_raw_parts(ptr, new_len) } }
    }

    #[allow(unused)]
    #[inline(always)]
    fn len(&self) -> usize {
        self.len
    }
}

// SAFETY: FatPtr is just a pointer+len, safe to send/sync if T is
unsafe impl<T: Send> Send for FatPtr<T> {}
unsafe impl<T: Sync> Sync for FatPtr<T> {}

/// Header for the zero-copy cache format
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CacheHeader {
    magic: u64,
    num_fragments: u32,
    num_files: u32,
    ring_pos: u32,
    _padding: u32,

    // Data follows header in this order:
    // - fragment_hashes: [u32; num_fragments]
    // - file_keys:       [FileKey; num_files]  (aligned to 16)
    // - file_metas:      [FileMeta; num_files] (aligned to 16)
    // - file_bitsets:    [u64; num_files * bits_per_file_u64]
}

pub trait CacheStorage {
    fn load(&self) -> io::Result<Option<Vec<u8>>>;
    fn save(&self, data: &[u8]) -> io::Result<()>;
    fn save_segments(&self, segments: &[&[u8]], total_size: usize) -> io::Result<()>;

    /// Load cache bytes, preferring a zero-copy mmap when the backend
    /// supports one. Default falls back to `load()` for backends that
    /// can't (e.g. in-memory test storage).
    fn load_mapped(&self) -> io::Result<Option<CacheBytes>> {
        Ok(self.load()?.map(Into::into).map(CacheBytes::Owned))
    }
}

/// Owned bytes backing a loaded cache, either a live mmap or a plain
/// heap buffer (used by storage backends that can't mmap, e.g. tests).
pub enum CacheBytes {
    Mapped(memmap2::Mmap),
    Owned(Box<[u8]>),
}

impl std::ops::Deref for CacheBytes {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        match self {
            CacheBytes::Mapped(m) => &m[..],
            CacheBytes::Owned(v)  => &v[..],
        }
    }
}

#[inline]
#[cfg(not(unix))]
pub fn fix_ownership(_path: &Path) -> io::Result<()> { Ok(()) }

/// Ownership of the cache directory/file may fuck up and error out
/// when we try to write/read from it.
///
/// So this function is for preventing that.
#[inline]
#[cfg(unix)]
pub fn fix_ownership(path: &Path) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let (sudo_uid, sudo_gid) = match (
        std::env::var("SUDO_UID").ok().and_then(|s| s.parse::<u32>().ok()),
        std::env::var("SUDO_GID").ok().and_then(|s| s.parse::<u32>().ok()),
    ) {
        (Some(uid), Some(gid)) => (uid, gid),
        _ => return Ok(()),  // Not running with sudo, nothing to fix
    };

    let path_cstr = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let ret = unsafe { libc::chown(path_cstr.as_ptr(), sudo_uid, sudo_gid) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

#[derive(Clone)]
pub struct DiskStorage {
    path: PathBuf,
}

impl DiskStorage {
    #[inline]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl CacheStorage for DiskStorage {
    #[inline]
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        if !self.path.exists() {
            return Ok(None);
        }
        Ok(Some(std::fs::read(&self.path)?))
    }

    #[inline]
    fn save(&self, data: &[u8]) -> io::Result<()> {
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, data)?;

        fix_ownership(&tmp)?;
        std::fs::rename(&tmp, &self.path)?;
        fix_ownership(&self.path)?;

        Ok(())
    }

    #[inline]
    fn save_segments(&self, segments: &[&[u8]], total_size: usize) -> io::Result<()> {
        use std::io::{IoSlice, Write};

        let tmp = self.path.with_extension("tmp");
        let mut file = std::fs::File::create(&tmp)?;

        file.set_len(total_size as _)?;

        let mut owned_slices = segments.iter().map(|s| IoSlice::new(s)).collect::<Vec<_>>();
        let mut slices: &mut [IoSlice] = &mut owned_slices;

        while !slices.is_empty() {
            let written = file.write_vectored(slices)?;
            if written == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write whole buffer"));
            }

            IoSlice::advance_slices(&mut slices, written);
        }

        file.sync_all()?;
        drop(file);

        fix_ownership(&tmp)?;
        std::fs::rename(&tmp, &self.path)?;

        Ok(())
    }

    #[inline]
    #[allow(unused_mut)]
    fn load_mapped(&self) -> io::Result<Option<CacheBytes>> {
        let mut file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        let len = file.metadata()?.len();

        // mmap2 refuses to map a zero-length file, treat that as no-cache.
        if len == 0 {
            return Ok(None);
        }

        #[cfg(windows)]
        {
            //
            // Apparently, a live mmap keeps the file's section object referenced at the
            // kernel level regardless of share-mode flags, which blocks the
            // tmp+rename swap in save_segments. Read into an owned buffer
            // instead so the handle is fully released once this returns.
            //
            use std::io::Read;
            let mut buf = Vec::with_capacity(len as usize);
            file.read_to_end(&mut buf)?;
            return Ok(Some(CacheBytes::Owned(buf.into())));
        }

        #[cfg(not(windows))]
        {
            // SAFETY: the file is only ever replaced via tmp+rename, never truncated
            // or modified in place, so this mapping stays valid while we hold it.
            let mmap = unsafe {
                let mut opts = memmap2::MmapOptions::new();
                opts.populate();
                opts.map(&file)?
            };

            Ok(Some(CacheBytes::Mapped(mmap)))
        }
    }
}

#[derive(Default)]
pub struct MemoryStorage {
    data: std::sync::Mutex<Option<Vec<u8>>>,
}

impl CacheStorage for MemoryStorage {
    #[inline]
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.data.lock().unwrap_().clone())
    }

    #[inline]
    fn save(&self, data: &[u8]) -> io::Result<()> {
        *self.data.lock().unwrap_() = Some(data.to_vec());
        Ok(())
    }

    #[inline]
    fn save_segments(&self, segments: &[&[u8]], total_size: usize) -> io::Result<()> {
        let mut data = Vec::with_capacity(total_size);

        debug_assert!(segments.iter().map(|s| s.len()).sum::<usize>() == total_size);

        for segment in segments {
            data.extend_from_slice(segment);
        }

        *self.data.lock().unwrap_() = Some(data);
        Ok(())
    }
}

/// Allocate a lookup table with 'size' slots, all initialized to
/// FILE_LOOKUP_EMPTY. 'size' must be a power of two. Writing the 0xFF byte
/// pattern directly is a single memset instead of a per-element store loop.
#[inline(always)]
fn new_empty_lookup(size: usize) -> Box<[u32]> {
    let mut lookup = Box::new_uninit_slice(size);
    unsafe {
        std::ptr::write_bytes(lookup.as_mut_ptr(), 0xFF, size);
        lookup.assume_init()
    }
}

/// Insert 'num_files' entries into 'lookup' via open addressing, hashing
/// each file's key through 'key_at(file_id)'. Shared by the full-table
/// rebuild in 'ensure_capacity''s rehash and by 'load_from_disk's
/// from-scratch build, both used to carry their own copy of this loop.
///
/// Prefetches the next file's target slot one iteration ahead so its cache
/// line is already in flight while we're still probing for the current file.
fn rebuild_lookup(lookup: &mut [u32], num_files: usize, key_at: impl Fn(usize) -> FileKey) {
    let mask = lookup.len() - 1;
    let mut next_index = (num_files > 0).then(|| (key_at(0).hash() as usize) & mask);

    for file_id in 0..num_files {
        let index = next_index.unwrap_();

        if let Some(next_id) = (file_id + 1 < num_files).then_some(file_id + 1) {
            let nh = (key_at(next_id).hash() as usize) & mask;
            prefetch_read(unsafe { lookup.as_ptr().add(nh) });
            next_index = Some(nh);
        }

        let mut probe = index;
        for _ in 0..16 {
            let existing = *lookup.get_(probe);
            if existing == FILE_LOOKUP_EMPTY {
                *lookup.get_mut_(probe) = file_id as u32;
                break;
            }

            probe = (probe + 1) & mask;
        }
    }
}

/// Core Fragment cache
#[repr(C, align(64))]
pub struct FragmentCache<S: CacheStorage = DiskStorage> {
    pub num_fragments: u32,
    num_files:         u32,
    ring_pos:          u32,
    max_fragments:     u32,
    max_files:         u32,
    file_capacity:     usize, // Current allocation capacity for file arrays

    // -------- File data indexed by file_id , immutable during search
    //

    // Read-only slice pointers (point into mmap or owned boxes)
    // Using FatPtr for bounds-checked access in debug builds
    //
    fragment_hashes: FatPtr<u32>,      // hash of 4-byte fragment
    file_keys:       FatPtr<FileKey>,  // file identifiers
    file_metas:      FatPtr<FileMeta>, // for cache invalidation
    file_bitsets:    FatPtr<u64>,      // flattened bitsets: file_id * num_fragments_in_u64 + bit_index

    // @Cleanup
    owned_fragment_hashes: Option<Box<[u32]>>,

    owned_file_keys:       Option<Box<[FileKey]>>,
    owned_file_metas:      Option<Box<[FileMeta]>>,
    owned_file_bitsets:    Option<Box<[u64]>>,

    // Set only by apply_batch, which always rebuilds keys+metas+bits together in
    // lockstep -- so unlike the trio above, they belong in one allocation. u128
    // as the element type is just a cheap way to get a 16-byte-aligned buffer
    // (matches FileKey/FileMeta's repr(align(16))) without hand-rolling
    // std::alloc::Layout. When this is Some, the trio above is None -- see
    // apply_batch's commit step and save_to_disk's dirty check.
    owned_arena: Option<Box<[u128]>>,

    //
    // ---------------------------------------------------------------

    file_lookup: Box<[u32]>,  // Open-addressed hash table

    #[cfg(not(feature = "no-cache-stats"))]
    pub stats: AtomicCacheStats,

    storage: S,

    backing: Option<CacheBytes>,

    // Held for the process's entire lifetime when we're the one
    // accumulating a fresh cache. Drop (including on process exit by crash)
    // closes the fd, which releases the flock and is exactly the signal other
    // waiting instances need.
    build_lock: Option<std::fs::File>,

    // Set only when this cache holds data actually loaded from a
    // pre-existing file on disk (never on the create_empty/leader path).
    //
    // This is what tells the caller 'there's something here
    // worth having the holder pin', as opposed to an empty cache
    // that's about to be built and rewritten this run.
    pub loaded_from_disk: bool,
}

enum WaitOutcome { Released, TimedOut }

#[cfg(unix)]
fn wait_for_leader(fd: std::os::fd::RawFd, max_wait: Duration) -> WaitOutcome {
    let deadline = Instant::now() + max_wait;
    loop {
        // flock has no timed variant, so poll LOCK_NB with backoff.
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            unsafe { libc::flock(fd, libc::LOCK_UN) }; // we only needed the signal, not ownership
            return WaitOutcome::Released;
        }
        if Instant::now() >= deadline {
            return WaitOutcome::TimedOut;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

impl FragmentCache<DiskStorage> {
    #[cfg(unix)]
    pub fn new(config: &CacheConfig) -> io::Result<Self> {
        use std::os::fd::AsRawFd;

        let t0 = Instant::now();
        let path = get_cache_path(config.cache_dir.as_deref(), "fragment-cache.bin")?;
        let storage = DiskStorage::new(path.clone());

        if !config.ignore_cache {
            if let Ok(cache) = Self::load_from_disk(storage.clone(), config, t0) {
                return Ok(cache);
            }
        }

        // No usable cache yet. Try to become the sole builder for this run.
        let lock_path = path.with_extension("lock");
        let lock_file = std::fs::OpenOptions::new()
            .truncate(false)
            .create(true)
            .write(true)
            .open(&lock_path)?;
        let fd = lock_file.as_raw_fd();

        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            // Leader: builds from scratch this run. Nothing to pin yet, the
            // next invocation loads the published file and pins that.
            let mut cache = Self::create_empty(config, storage)?;
            cache.build_lock = Some(lock_file);
            return Ok(cache);
        }

        match wait_for_leader(fd, Duration::from_secs(2)) {
            WaitOutcome::Released => {
                if !config.ignore_cache {
                    if let Ok(cache) = Self::load_from_disk(storage.clone(), config, t0) {
                        return Ok(cache);
                    }
                }
                Self::create_empty(config, storage)
            }
            WaitOutcome::TimedOut => Self::create_empty(config, storage),
        }
    }

    /// Create new or load existing cache
    #[inline]
    #[cfg(not(unix))]
    pub fn new(config: &CacheConfig) -> io::Result<Self> {
        let t0 = Instant::now();

        let path = get_cache_path(config.cache_dir.as_deref(), "fragment-cache.bin")?;
        let storage = DiskStorage::new(path);

        if !config.ignore_cache {
            if let Ok(cache) = Self::load_from_disk(storage.clone(), config, t0) {
                return Ok(cache);
            }
        }

        Self::create_empty(config, storage)
    }
}

impl FragmentCache<MemoryStorage> {
    #[inline]
    pub fn new_in_memory(max_fragments: usize, max_files: usize) -> Self {
        let config = CacheConfig {
            max_fragments,
            max_files,
            cache_dir: None,
            ignore_cache: false,
        };
        Self::create_empty(&config, MemoryStorage::default()).unwrap_()
    }

    pub fn with_test_data(
        fragment_hashes: Vec<u32>,
        file_keys: Vec<FileKey>,
        file_metas: Vec<FileMeta>,
        fragment_presence: Vec<Vec<bool>>,
    ) -> Self {
        let max_fragments = fragment_hashes.len().max(64);
        let max_files = file_keys.len().max(64);

        let mut cache = Self::new_in_memory(max_fragments, max_files);

        for &h in &fragment_hashes {
            cache.add_fragment(h);
        }

        let num_fragments = cache.num_fragments as usize;
        let bits_per_file_u64 = num_fragments.div_ceil(64);
        let num_files = file_keys.len();

        {
            let owned_keys  = cache.owned_file_keys.as_mut().unwrap_();
            let owned_metas = cache.owned_file_metas.as_mut().unwrap_();
            let owned_bits  = cache.owned_file_bitsets.as_mut().unwrap_();

            for file_id in 0..num_files {
                owned_keys[file_id]  = file_keys[file_id];
                owned_metas[file_id] = file_metas[file_id];

                let offset = file_id * bits_per_file_u64;
                for i in 0..bits_per_file_u64 {
                    owned_bits[offset + i] = !0u64;
                }

                for (frag_index, &present) in fragment_presence[file_id].iter().enumerate() {
                    if present {
                        let u64_index = offset + frag_index / 64;
                        let bit_index = frag_index % 64;
                        if u64_index < owned_bits.len() {
                            owned_bits[u64_index] &= !(1u64 << bit_index);
                        }
                    }
                }
            }
        }

        cache.fragment_hashes = FatPtr::from_box(cache.owned_fragment_hashes.as_ref().unwrap_());
        cache.file_keys       = FatPtr::from_box(cache.owned_file_keys.as_ref().unwrap_());
        cache.file_metas      = FatPtr::from_box(cache.owned_file_metas.as_ref().unwrap_());
        cache.file_bitsets    = FatPtr::from_box(cache.owned_file_bitsets.as_ref().unwrap_());

        cache.num_files = num_files as u32;

        for (file_id, &key) in file_keys.iter().enumerate() {
            cache.insert_into_lookup(key, file_id as u32);
        }

        cache
    }
}

impl<S: CacheStorage> FragmentCache<S> {
    fn create_empty(config: &CacheConfig, storage: S) -> io::Result<Self> {
        let max_fragments = config.max_fragments as u32;
        let max_files     = config.max_files as u32;

        // Start with reasonable capacity to avoid many reallocations
        // 64K files = ~2MB for keys+metas, acceptable tradeoff for speed
        const INITIAL_CAPACITY: usize = 64 * 1024;

        let owned_fragment_hashes     = Box::<[u32]>::new_uninit_slice(config.max_fragments);
        let owned_file_keys           = Box::<[FileKey]>::new_uninit_slice(INITIAL_CAPACITY);
        let owned_file_metas          = Box::<[FileMeta]>::new_uninit_slice(INITIAL_CAPACITY);

        let owned_fragment_hashes     = unsafe { owned_fragment_hashes.assume_init() };
        let owned_file_keys           = unsafe { owned_file_keys.assume_init() };
        let owned_file_metas          = unsafe { owned_file_metas.assume_init() };

        // Stride=1 covers first 64 fragments, ensure_fragment_capacity
        // handles growth beyond that
        let owned_file_bitsets        = vec![!0u64; INITIAL_CAPACITY].into_boxed_slice();

        // Small lookup table initially
        let lookup_size = (INITIAL_CAPACITY * 2).next_power_of_two();
        let mut file_lookup = Box::<[u32]>::new_uninit_slice(lookup_size);
        unsafe {
            std::ptr::write_bytes(file_lookup.as_mut_ptr(), 0xFF, lookup_size);
        }
        let file_lookup = unsafe { file_lookup.assume_init() };

        // Create FatPtrs from the owned boxes
        let fragment_hashes = FatPtr::from_box(&owned_fragment_hashes);
        let file_keys       = FatPtr::from_box(&owned_file_keys);
        let file_metas      = FatPtr::from_box(&owned_file_metas);
        let file_bitsets    = FatPtr::from_box(&owned_file_bitsets);

        Ok(Self {
            num_fragments: 0,
            backing: None,
            num_files: 0,
            ring_pos: 0,
            max_fragments,
            max_files,
            build_lock: None,
            file_capacity: INITIAL_CAPACITY,
            fragment_hashes,
            loaded_from_disk: false,
            owned_arena: None,
            file_keys,
            file_metas,
            file_bitsets,
            owned_fragment_hashes: Some(owned_fragment_hashes),
            owned_file_keys: Some(owned_file_keys),
            owned_file_metas: Some(owned_file_metas),
            owned_file_bitsets: Some(owned_file_bitsets),
            file_lookup,
            storage,
            #[cfg(not(feature = "no-cache-stats"))]
            stats: AtomicCacheStats::default(),
        })
    }

    /// Migrate bitsets when num_fragments crosses a 64-boundary.
    /// Must be called BEFORE incrementing num_fragments.
    /// new_num_fragments is the count AFTER the increment.
    fn ensure_fragment_capacity(&mut self, old_num_fragments: usize, new_num_fragments: usize) {
        let old_stride = old_num_fragments.div_ceil(64).max(1);
        let new_stride = new_num_fragments.div_ceil(64).max(1);

        if new_stride <= old_stride {
            return;
        }

        let num_files     = self.num_files as usize;
        let file_capacity = self.file_capacity;

        let old_bits = self.owned_file_bitsets.take().unwrap_();

        // Unknown -- only bits we've actually verified get set to 1.
        let mut new_bits = vec![0u64; file_capacity * new_stride].into_boxed_slice();

        if !old_bits.is_empty() {
            //
            // Only copy if there's actually data to copy. One copy_from_slice
            // per file row compiles to a memcpy instead of the old per-word
            // branch+store, which matters once old_stride is more than a
            // word or two (@Speedup, same result).
            //
            for file_id in 0..num_files {
                let old_offset = file_id * old_stride;
                let new_offset = file_id * new_stride;
                let copy_len   = old_stride.min(old_bits.len().saturating_sub(old_offset));

                if copy_len > 0 {
                    new_bits[new_offset..new_offset + copy_len]
                        .copy_from_slice(&old_bits[old_offset..old_offset + copy_len]);
                }
            }
        }

        self.owned_file_bitsets = Some(new_bits);
        self.file_bitsets = FatPtr::from_box(self.owned_file_bitsets.as_ref().unwrap_());
    }

    fn load_from_disk(storage: S, config: &CacheConfig, t0: Instant) -> io::Result<Self> {
        let Some(bytes) = storage.load_mapped()? else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no cache data"));
        };

        if bytes.len() < size_of::<CacheHeader>() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "cache file too small"));
        }

        let header = unsafe { &*(bytes.as_ptr() as *const CacheHeader) };

        if header.magic != CACHE_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid cache magic"));
        }

        let num_fragments = (header.num_fragments as usize).min(config.max_fragments);
        let num_files = (header.num_files as usize).min(config.max_files);

        // ---------- Calculate offsets (data follows header with proper alignment)
        let header_size         = size_of::<CacheHeader>();
        let fragments_offset    = header_size;
        let fragments_size      = num_fragments * 4; // @Constant

        // ---------- Align file_keys to 16 bytes
        let file_keys_offset    = (fragments_offset + fragments_size + 15) & !15;
        let file_keys_size      = num_files * size_of::<FileKey>();

        // ---------- file_metas follows file_key
        let file_metas_offset   = file_keys_offset + file_keys_size;
        let file_metas_size     = num_files * size_of::<FileMeta>();

        // ---------- file_bitsets follows (align to 8 bytes for u64)
        let file_bitsets_offset = (file_metas_offset + file_metas_size + 7) & !7;
        let bits_per_file_u64   = num_fragments.div_ceil(64);
        let file_bitsets_len    = num_files * bits_per_file_u64;

        let expected_size       = file_bitsets_offset + file_bitsets_len * size_of::<u64>();
        if bytes.len() < expected_size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "cache data truncated"));
        }

        // SAFETY: offsets were computed from the same alignment rules `save_to_disk` used to write this file.
        let fragment_hashes = unsafe {
            FatPtr::from_raw(bytes.as_ptr().add(fragments_offset) as *const u32, num_fragments)
        };
        let file_keys       = unsafe {
            FatPtr::from_raw(bytes.as_ptr().add(file_keys_offset) as *const FileKey, num_files)
        };
        let file_metas      = unsafe {
            FatPtr::from_raw(bytes.as_ptr().add(file_metas_offset) as *const FileMeta, num_files)
        };
        let file_bitsets    = unsafe {
            FatPtr::from_raw(bytes.as_ptr().add(file_bitsets_offset) as *const u64, file_bitsets_len)
        };

        // ---- Build lookup table
        let lookup_size = ((num_files * 2).max(1024)).next_power_of_two();
        let mut file_lookup = new_empty_lookup(lookup_size);
        rebuild_lookup(&mut file_lookup, num_files, |id| file_keys.get(id));

        let file_capacity = num_files;

        eprintln!(
            "Cache allocations:\n  fragment_hashes: {}KB\n  file_keys: {}KB\n  file_metas: {}KB\n  file_bitsets: {}KB\n  file_lookup: {}KB\n  raw_bytes: {}KB\n  file_capacity: {}\n  bits_per_file_u64: {}",
            (config.max_fragments * 4) / 1024,
            (file_capacity * size_of::<FileKey>()) / 1024,
            (file_capacity * size_of::<FileMeta>()) / 1024,
            (file_capacity * bits_per_file_u64 * 8) / 1024,
            (lookup_size * 4) / 1024,
            bytes.len() / 1024,
            file_capacity,
            bits_per_file_u64,
        );

        eprintln!(
            "Cache loaded: {} files, {} fragments, {:.2}MB in {}ms",
            num_files, num_fragments,
            bytes.len() as f64 / (1024.0 * 1024.0),
            t0.elapsed().as_millis() as f64
        );

        Ok(Self {
            num_fragments: num_fragments as u32,
            num_files: num_files as u32,
            ring_pos: header.ring_pos,
            backing: Some(bytes),
            max_fragments: config.max_fragments as u32,
            max_files: config.max_files as u32,
            build_lock: None,
            owned_arena: None,
            loaded_from_disk: true,
            file_capacity,
            fragment_hashes,
            file_keys,
            file_metas,
            file_bitsets,
            owned_fragment_hashes: None,
            owned_file_keys:       None,
            owned_file_metas:      None,
            owned_file_bitsets:    None,
            file_lookup,
            storage,
            #[cfg(not(feature = "no-cache-stats"))]
            stats: AtomicCacheStats::default(),
        })
    }

    #[inline]
    pub fn save_to_disk(&self) -> io::Result<()> {
        if self.owned_file_keys.is_none() && self.owned_arena.is_none() {
            // Never dirtied this run, on-disk cache is already current.
            return Ok(());
        }

        let start = Instant::now();

        let num_fragments     = self.num_fragments as usize;
        let num_files         = self.num_files as usize;

        let header_size       = size_of::<CacheHeader>();
        let fragments_size    = num_fragments * 4;

        // ------- Calculate padding for alignment
        let pad1_size         = ((header_size + fragments_size + (16 - 1)) & !(16 - 1)) - (header_size + fragments_size);
        let file_keys_size    = num_files * size_of::<FileKey>();
        let file_metas_size   = num_files * size_of::<FileMeta>();

        let after_metas       = header_size + fragments_size + pad1_size + file_keys_size + file_metas_size;
        let pad2_size         = ((after_metas + (8 - 1)) & !(8 - 1)) - after_metas;

        let bits_per_file_u64 = num_fragments.div_ceil(64);
        let file_bitsets_size = num_files * bits_per_file_u64 * size_of::<u64>();

        // ------- Header
        let total_size = header_size + fragments_size + pad1_size
            + file_keys_size + file_metas_size + pad2_size
            + file_bitsets_size;

        let header = CacheHeader {
            magic: CACHE_MAGIC,
            num_fragments: num_fragments as u32,
            num_files: num_files as u32,
            ring_pos: self.ring_pos,
            _padding: 0,
        };

        let pad1 = [0u8; 16];
        let pad2 = [0u8; 8];

        let segments: [&[u8]; 7] = [
            unsafe { std::slice::from_raw_parts(&header as *const CacheHeader as *const u8, header_size) },
            unsafe { std::slice::from_raw_parts(self.fragment_hashes.ptr as *const u8, fragments_size) },
            &pad1[..pad1_size],
            unsafe { std::slice::from_raw_parts(self.file_keys.ptr as *const u8, file_keys_size) },
            unsafe { std::slice::from_raw_parts(self.file_metas.ptr as *const u8, file_metas_size) },
            &pad2[..pad2_size],
            unsafe { std::slice::from_raw_parts(self.file_bitsets.ptr as *const u8, file_bitsets_size) },
        ];

        eprintln!(
            "Cache prepared to write in {:.2}ms",
            start.elapsed().as_millis() as f64
        );

        debug_assert_eq!(total_size, segments.iter().map(|s| s.len()).sum::<usize>());

        let start = Instant::now();

        self.storage.save_segments(&segments, total_size)?;

        eprintln!(
            "Cache saved: {} files, {} fragments, {:.2}MB in {:.2}ms",
            num_files, num_fragments,
            total_size as f64 / (1024.0 * 1024.0),
            start.elapsed().as_millis() as f64
        );

        Ok(())
    }

    /// Check if file can be skipped
    #[inline(always)]
    pub fn can_skip_file(
        &self,
        FileIdentifier { key: file_key, meta: file_meta }: FileIdentifier,
        fragment_indexes: &[u32],
    ) -> bool {
        let Some(file_id) = self.lookup_file_id(file_key) else {
            // ----- Fast path
            #[cfg(not(feature = "no-cache-stats"))] {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
            }

            return false;
        };

        // -------- Check if any required fragment is marked absent
        let num_fragments     = self.num_fragments as usize;
        let bits_per_file_u64 = num_fragments.div_ceil(64).max(1);
        let offset            = (file_id as usize) * bits_per_file_u64;  // Start of this file's bitset

        //
        // Computable from file_id alone -- no dependency on the metadata check
        // below. Fire it now so it has the width of stored_meta.matches() to
        // land before the fragment loop actually needs it.
        //
        if let Some(&frag_index) = fragment_indexes.first() {
            prefetch_read(unsafe { self.file_bitsets.ptr.add(offset + (frag_index as usize >> 6)) });
        }

        // ------- Validate metadata
        let stored_meta = self.file_metas.get(file_id as usize);
        if unlikely(stored_meta != file_meta) {
            #[cfg(not(feature = "no-cache-stats"))] {
                self.stats.invalidations.fetch_add(1, Ordering::Relaxed);
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
            }

            return false;
        }

        for &frag_index in fragment_indexes {
            let frag_index = frag_index as usize;

            let  u64_index = offset + (frag_index >> 6); // Which u64 contains the bit
            let  bit_index = frag_index & 63;            // Which bit contains the info

            let bitset_val = self.file_bitsets.get(u64_index);

            let is_absent  = (bitset_val & (1u64 << bit_index)) != 0;
            if likely(is_absent) {
                #[cfg(not(feature = "no-cache-stats"))] {
                    self.stats.hits.fetch_add(1, Ordering::Relaxed);
                }

                return true;
            }
        }

        #[cfg(not(feature = "no-cache-stats"))] {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
        }

        false
    }

    #[inline(always)]
    fn find_fragment_index(&self, frag_hash: u32, num_fragments: usize) -> Option<usize> {
        // small arrays (2-10 fragments) so linear is fastest
        (0..num_fragments).find(|&i| self.fragment_hashes.get(i) == frag_hash)
    }

    /// Resolve each hash in `required_fragment_hashes` to its current
    /// ring-buffer index, pushing results onto `out`.
    ///
    /// A hash that isn't currently tracked (evicted, or never added) is simply
    /// omitted -- same as the continue in can_skip_file's fragment loop.
    #[inline]
    pub fn resolve_fragment_indexes(&self, required_fragment_hashes: &[u32], out: &mut Vec<u32>) {
        let num_fragments = self.num_fragments as usize;
        for &hash in required_fragment_hashes {
            if let Some(index) = self.find_fragment_index(hash, num_fragments) {
                out.push(index as u32);
            }
        }
    }

    #[inline(always)]
    pub fn prefetch_lookup(&self, file_key: FileKey) {
        let hash = file_key.hash();
        let mask = self.file_lookup.len() - 1;
        let index = (hash as usize) & mask;
        prefetch_read(unsafe { self.file_lookup.as_ptr().add(index) });
    }

    #[inline(always)]
    fn lookup_file_id(&self, file_key: FileKey) -> Option<u32> {
        let hash = file_key.hash();
        let mask = self.file_lookup.len() - 1;
        let mut index = (hash as usize) & mask;

        for _ in 0..16 {
            let file_id = *self.file_lookup.get_(index);
            if file_id == FILE_LOOKUP_EMPTY {
                return None;
            }

            let stored_key = self.file_keys.get(file_id as usize);
            if stored_key == file_key {
                return Some(file_id);
            }

            index = (index + 1) & mask;
        }

        None
    }

    /// Add fragment to ring buffer (returns index)
    fn add_fragment(&mut self, frag_hash: u32) -> u32 {
        let num_fragments = self.num_fragments as usize;

        if let Some(index) = self.find_fragment_index(frag_hash, num_fragments) {
            return index as u32;
        }

        if num_fragments < self.max_fragments as usize {
            // ------- Ring buffer is not full
            let index = num_fragments;
            let new_num_fragments = num_fragments + 1;

            *self.owned_fragment_hashes.as_mut()
                .unwrap_()
                .get_mut_(index) = frag_hash;

            //
            // Migrate bitset stride if we crossed a 64-boundary
            //

            // Pass num_fragments (old) and new_num_fragments explicitly
            // so ensure_fragment_capacity doesn't read the already-incremented atomic
            self.ensure_fragment_capacity(num_fragments, new_num_fragments);
            self.num_fragments = new_num_fragments as u32;

            //
            //
            // Clear this fragment bit for ALL existing files
            // New fragments are "unknown" for existing files and we MUST check them
            //
            //

            let num_files         = self.num_files as usize;
            let bits_per_file_u64 = new_num_fragments.div_ceil(64).max(1);
            self.clear_fragment_bit_for_all_files(index, bits_per_file_u64, num_files);

            index as u32
        } else {
            // ------- Ring buffer is full
            // evict oldest (FIFO)

            let ring_pos = self.ring_pos as usize;
            let index = ring_pos;

            *self.owned_fragment_hashes.as_mut()
                .unwrap_()
                .get_mut_(index) = frag_hash;

            let next_pos = (ring_pos + 1) % (self.max_fragments as usize);
            self.ring_pos = next_pos as u32;

            //
            // Clear this fragment position for all files (unknown state)
            //

            // Ring buffer full means num_fragments == max_fragments,
            // so stride is already at its maximum and will never grow again
            let num_files         = self.num_files as usize;
            let bits_per_file_u64 = num_fragments.div_ceil(64).max(1);
            self.clear_fragment_bit_for_all_files(index, bits_per_file_u64, num_files);

            index as u32
        }
    }

    /// Clear fragment `index`'s bit for every existing file, marking that
    /// fragment "unknown/must-check" for files that predate it. Shared by
    /// both branches of `add_fragment()` above -- growing the ring and
    /// evicting into it both need every prior file re-checked against
    /// whatever fragment now lives at `index`.
    fn clear_fragment_bit_for_all_files(&mut self, index: usize, bits_per_file_u64: usize, num_files: usize) {
        let u64_offset = index / 64;
        let bit_index  = index % 64;
        let mask       = !(1u64 << bit_index);

        let owned_file_bitsets = self.owned_file_bitsets.as_mut().unwrap_();

        if bits_per_file_u64 == 1 {
            debug_assert_eq!(u64_offset, 0, "bits_per_file_u64 == 1 implies index < 64");

            //
            // Each file's word sits at exactly file_id -- one bounds check up
            // front, and a flat contiguous slice that LLVM can auto-vectorize
            // with unmasked loads/stores.
            //
            let n = num_files.min(owned_file_bitsets.len());
            for word in &mut owned_file_bitsets[..n] {
                *word &= mask;
            }

            return;
        }

        //
        // General strided path (bits_per_file_u64 > 1)...
        //

        let owned_file_bitsets_len = owned_file_bitsets.len();
        for file_id in 0..num_files {
            let bitset_index = file_id * bits_per_file_u64 + u64_offset;
            if bitset_index < owned_file_bitsets_len {
                *owned_file_bitsets.get_mut_(bitset_index) &= mask;
            }
        }
    }

    /// Insert file into lookup table
    #[inline]
    fn insert_into_lookup(&mut self, file_key: FileKey, file_id: u32) {
        let hash      = file_key.hash();
        let mask      = self.file_lookup.len() - 1;
        let mut index = (hash as usize) & mask;

        // @Note: This might silently fail, which means this file will always
        // miss the cache, maybe we should return like a boolean or something.
        for _ in 0..16 {
            let existing = *self.file_lookup.get_(index);

            if existing == FILE_LOOKUP_EMPTY {
                *self.file_lookup.get_mut_(index) = file_id;

                return;  // Successfully inserted
            }

            index = (index + 1) & mask;
        }
    }

    #[inline]
    #[cfg(not(feature = "no-cache-stats"))]
    pub fn get_stats(&self) -> (u32, u32, u32) {
        (
            self.stats.hits.load(Ordering::Relaxed),
            self.stats.misses.load(Ordering::Relaxed),
            self.stats.invalidations.load(Ordering::Relaxed),
        )
    }

    /// Calculate memory usage in bytes
    #[inline]
    pub fn memory_usage(&self) -> usize {
        let num_fragments     = self.num_fragments as usize;
        let num_files         = self.num_files as usize;

        let fragments_size    = num_fragments * size_of::<u32>();
        let file_keys_size    = num_files * size_of::<FileKey>();
        let file_metas_size   = num_files * size_of::<FileMeta>();

        let bits_per_file     = num_fragments.div_ceil(64) * 64;
        let file_bitsets_size = num_files * (bits_per_file / 8);

        let lookup_size       = self.file_lookup.len() * size_of::<AtomicU32>();

        fragments_size + file_keys_size + file_metas_size + file_bitsets_size + lookup_size
    }
}

#[inline]
pub fn get_cache_path(cache_dir: Option<&Path>, cache_name: &str) -> io::Result<PathBuf> {
    let dir = if let Some(d) = cache_dir {
        d.to_path_buf()
    } else {
        let home = if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            //
            // ~/.cache/rawgrep/
            // When running with sudo, use the actual user's home directory
            //
            PathBuf::from("/home").join(sudo_user)
        } else {
            #[cfg(unix)]
            let home_str = std::env::var("HOME");

            #[cfg(not(unix))]
            let home_str = std::env::var("USERPROFILE");

            let home_str = home_str.map_err(|_| io::Error::new(io::ErrorKind::NotFound, "HOME not set"))?;

            PathBuf::from(home_str)
        };

        home.join(".cache").join("rawgrep")
    };

    std::fs::create_dir_all(&dir)?;
    fix_ownership(&dir)?;

    Ok(dir.join(cache_name))
}

#[repr(transparent)]
#[derive(Copy, Clone)]
struct ExistingIndex(std::num::NonZeroU32);
impl ExistingIndex {
    #[inline(always)]
    pub fn new(index: u32) -> Self {
        Self(unsafe { std::num::NonZeroU32::new_unchecked(index.checked_add(1).unwrap()) })
    }
    #[inline(always)]
    pub fn get(&self) -> u32 {
        self.0.get() - 1
    }
}

/// Resolution of a single fragment hash against the current table.
/// Computed once per batch since fragment_hashes is shared by every file.
struct FragPlan {
    hash: u32,

    // Some if already in the table. None means apply_batch must add it.
    existing_index: Option<ExistingIndex>,
}

/// Resolution of a single file against the current table.
struct FilePlan {
    file_index:   u32,                   // Index into the caller's file_keys/file_metas
    existing_id:  Option<ExistingIndex>, // None means apply_batch must insert it
    meta_changed: bool,
}

pub struct BatchPlan {
    frags: Vec<FragPlan>,
    files: Vec<FilePlan>,

    // True if applying this plan would touch any stored byte.
    changed: bool,
}

impl<S: CacheStorage> FragmentCache<S> {
    /// Read-only resolution pass. Never touches owned_* buffers.
    /// Shared by merge_updates() and merge_updates_if_changed() so the lookups only
    /// happen once no matter which caller ends up applying the result.
    #[inline(never)]
    fn plan_batch(
        &self,
        file_ids:          &[FileIdentifier],
        fragment_hashes:   &[u32],
        fragment_presence: &[u64],
    ) -> BatchPlan {
        let num_fragments     = self.num_fragments as usize;
        let bits_per_file_u64 = num_fragments.div_ceil(64).max(1);
        let words_per_file    = fragment_hashes.len().div_ceil(64);

        //
        // Resolve fragments once, shared across every file below.
        //
        let mut frags = Vec::with_capacity(fragment_hashes.len().min(100));
        let mut has_new_fragment = false;
        for &hash in fragment_hashes.iter() {
            let existing_index = self.find_fragment_index(hash, num_fragments).map(|index| index as u32);
            if existing_index.is_none() {
                has_new_fragment = true;
            }

            let existing_index = existing_index.map(ExistingIndex::new);
            frags.push(FragPlan { hash, existing_index });
        }

        let n = file_ids.len();

        let mut files = Vec::with_capacity(n);

        //
        // A new fragment always dirties the batch: add_fragment() clears
        // that bit for every existing file, which is a state change even
        // if every file's own presence data matches what's on disk already.
        //
        let mut changed = has_new_fragment;

        let fast_word = bits_per_file_u64 == 1 && words_per_file == 1 && !has_new_fragment;
        let selector_mask: u64 = if fast_word {
            frags.iter().fold(0u64, |m, f| m | (1u64 << f.existing_index.unwrap_().get()))
        } else {
            0
        };

        for file_index in 0..n {
            if let Some(&next_id) = file_ids.get(file_index + 1) {
                self.prefetch_lookup(next_id.key);
            }

            let file_id = *file_ids.get_(file_index);

            let existing_id = self.lookup_file_id(file_id.key);
            let meta_changed = match existing_id {
                None => true,  // Brand-new file is always a change
                Some(id) => {
                    let stored_meta = self.file_metas.get(id as usize);
                    stored_meta != file_id.meta
                }
            };

            if existing_id.is_none() || meta_changed {
                changed = true;
            }

            //
            // Only worth comparing individual bits if the batch isn't
            // already known dirty, and this file exists with matching
            // meta (a new/invalidated file is a full rewrite regardless of what the bits say).
            //
            if !changed && let Some(id) = existing_id {
                let offset = (id as usize) * bits_per_file_u64;

                if fast_word {
                    //
                    // Fast branch-free path when bits_per_file_u64 == 1 ...
                    //

                    let presence_word = *fragment_presence.get_(file_index);

                    let mut deposited = 0u64;
                    for (frag_i, f) in frags.iter().enumerate() {
                        let bit = (presence_word >> frag_i) & 1;
                        deposited |= bit << f.existing_index.unwrap_().get();
                    }

                    let expected = !deposited & selector_mask;
                    let actual   = self.file_bitsets.get(offset) & selector_mask;

                    if actual != expected {
                        changed = true;
                    }

                } else {
                    let presence = fragment_presence.get_(
                        file_index * words_per_file
                        ..
                        (file_index + 1) * words_per_file
                    );

                    let mut cached_u64_index = usize::MAX;
                    let mut cached_word = 0u64;

                    for (frag_i, frag_plan) in frags.iter().enumerate() {
                        //
                        // has_new_fragment is false here, so this is always Some.
                        //
                        let frag_index     = frag_plan.existing_index.unwrap_().get() as usize;

                        let presence       = *presence.get_(frag_i / 64);
                        let is_present     = (presence & (1 << (frag_i % 64))) != 0;

                        let expect_bit_set = !is_present;

                        let u64_index      = offset + (frag_index >> 6);
                        let bit_index      = frag_index & 63;

                        if u64_index != cached_u64_index {
                            cached_word = self.file_bitsets.get(u64_index);
                            cached_u64_index = u64_index;
                        }

                        if (cached_word & (1u64 << bit_index) != 0) != expect_bit_set {
                            changed = true;
                            break;
                        }
                    }
                }
            }

            let existing_id = existing_id.map(ExistingIndex::new);
            files.push(FilePlan { file_index: file_index as u32, existing_id, meta_changed });
        }

        BatchPlan { frags, files, changed }
    }

    /// Decide, for every fragment in the batch, which cache column it uses.
    ///
    /// Existing fragments keep their slots, new fragments are appended while there is room.
    /// Once the ring is full they evict FIFO, but never a slot this batch depends on
    /// A fragment that finds no free slot is dropped; its bits are simply never recorded.
    ///
    /// Outputs: scratch.slot_of, scratch.clear (columns to zero in pre-existing rows) and
    /// scratch.hashes[..num_fragments].
    fn resolve_fragments(&self, plan: &BatchPlan, scratch: &mut ScratchViews<'_>) -> io::Result<FragmentLayout> {
        let max               = self.max_fragments as usize;
        let old_num_fragments = self.num_fragments as usize;

        if old_num_fragments > max || self.fragment_hashes.len() < old_num_fragments {
            return Err(bad("fragment table inconsistent"));
        }

        debug_assert_eq!(scratch.hashes .len(), max);
        debug_assert_eq!(scratch.slot_of.len(), plan.frags.len());

        let hashes  = &mut *scratch.hashes;   // Working table, zeroed
        let pinned  = &mut *scratch.pinned;   // Slots this batch depends on
        let clear   = &mut *scratch.clear;    // Columns to zero in pre-existing rows
        let slot_of = &mut *scratch.slot_of;

        hashes[..old_num_fragments].copy_from_slice(self.fragment_hashes.make_slice(old_num_fragments));

        let mut num_fragments = old_num_fragments;
        let mut ring_pos      = if (self.ring_pos as usize) < max { self.ring_pos as usize } else { 0 };
        let mut dropped       = 0u32;

        //
        // Everything already resolved by plan_batch is pinned first, so eviction can't hit it.
        // (Scratch is zeroed, not NO_SLOT-filled, so every entry is written explicitly here.)
        //

        for (out, f) in slot_of.iter_mut().zip(&plan.frags) {
            match f.existing_index {
                Some(i) if (i.get() as usize) < old_num_fragments => {
                    let i = i.get();
                    bit_set(pinned, i as usize);
                    *out = i;
                }

                Some(_) => return Err(bad("plan existing_index out of range")),
                None    => *out = NO_SLOT,
            }
        }

        //
        // Place the new ones.
        //

        for (file_index, frag) in plan.frags.iter().enumerate() {
            if frag.existing_index.is_some() { continue; }

            //
            // plan_batch should already have resolved this ... keep the old add_fragment() guarantee.
            //
            if let Some(s) = hashes.get_(..num_fragments).iter().position(|&h| h == frag.hash) {
                bit_set(pinned, s);
                *slot_of.get_mut_(file_index) = s as u32;

                continue;
            }

            let slot = if num_fragments < max {
                num_fragments += 1;
                num_fragments - 1
            } else {
                let mut found = None;
                for _ in 0..max {
                    let s = ring_pos;
                    ring_pos = if ring_pos + 1 == max { 0 } else { ring_pos + 1 };

                    if !bit_get(pinned, s) { found = Some(s); break; }
                }

                match found {
                    Some(s) => s,
                    None    => { dropped += 1; continue; }  // Every slot is pinned by this batch; stays NO_SLOT
                }
            };

            *slot_of.get_mut_(file_index) = slot as u32;
            *hashes .get_mut_(slot)       = frag.hash;
            bit_set(pinned,   slot);
            bit_set(clear,    slot);
        }

        Ok(FragmentLayout { num_fragments, ring_pos, dropped })
    }

    /// Applies a plan produced by plan_batch(). Caller checks plan.changed first.
    /// On Err the cache is unchanged.
    ///
    /// COW: `self.file_keys/metas/bitsets/fragment_hashes` may currently point into an mmap'd
    /// disk backing, so this never mutates in place. Everything below is built fresh
    /// into a new arena and the FatPtrs are swapped onto it atomically at the end.
    ///
    /// Allocations: one scratch (temporaries, freed on return) + one arena (kept).
    pub fn apply_batch(
        &mut self,
        plan: &BatchPlan,
        file_ids:          &[FileIdentifier],
        fragment_presence: &[u64],
    ) -> io::Result<()> {
        let mut laps = Laps::new();

        //
        //
        // Validate and size
        //
        //

        let old_num_files       = self.num_files as usize;
        let max_files           = self.max_files as usize;
        let max_fragments       = self.max_fragments as usize;
        let old_num_fragments   = self.num_fragments as usize;
        let old_words_per_file  = old_num_fragments.div_ceil(64).max(1);
        let plan_words_per_file = plan.frags.len().div_ceil(64).max(1);

        if max_files >= RESET as usize || old_num_files > max_files {
            return Err(bad("max_files out of range"));
        }
        if self.file_keys.len() < old_num_files || self.file_metas.len() < old_num_files {
            return Err(bad("cache arrays shorter than num_files"));
        }

        //
        // One zeroed allocation for every temporary: file/fragment slots,
        // the pinned/clear bitsets and the table.
        //
        let mut scratch       = BatchScratch::new(plan.files.len(), plan.frags.len(), max_fragments)?;
        populate_capacity(&mut scratch.buf);
        let mut scratch       = scratch.views();

        let mut next          = old_num_files;
        let mut dropped_files = 0u32;
        for (out, file_plan) in scratch.slots.iter_mut().zip(&plan.files) {
            let file_index = file_plan.file_index as usize;

            if file_index >= file_ids.len()
            || (!plan.frags.is_empty() && (file_index + 1) * plan_words_per_file > fragment_presence.len())
            {
                return Err(bad("plan references a file outside the input slices"));
            }

            *out = match file_plan.existing_id {
                Some(id) if (id.get() as usize) < old_num_files => id.get() | if file_plan.meta_changed { RESET } else { 0 },
                Some(_) => return Err(bad("plan existing_id out of range")),

                //
                // self.file_capacity is capped at max_files, so once `next` hits it every
                // remaining new file in this batch drops.
                //
                None if next < max_files => { next += 1; (next - 1) as u32 }
                None => { dropped_files += 1; DROPPED }
            };
        }
        let final_files = next;

        //
        // Guards against a single merge_updates() batch containing the same
        // file_key twice. If that happens, the second occurrence's
        // needs_full_reset pass would zero and clobber bits the first
        // occurrence just wrote for fragments outside the current batch silently.
        //
        // Callers are expected to de-duplicate by file_key before calling merge_updates,
        // which they don't right now... Not sure if this might actually happen.
        //
        #[cfg(debug_assertions)]
        {
            let mut seen = vec![0u64; final_files.div_ceil(64).max(1)];
            for &s in scratch.slots.iter().filter(|&&s| s != DROPPED) {
                let id = (s & !RESET) as usize;
                assert!(
                    !bit_get(&seen, id),
                    "apply_batch: file_id {id} appears more than once in a single batch, \
                     caller must de-duplicate by file_key"
                );
                bit_set(&mut seen, id);
            }
        }

        let fragment_layout    = self.resolve_fragments(plan, &mut scratch)?;
        let new_num_fragments  = fragment_layout.num_fragments;
        let new_words_per_file = new_num_fragments.div_ceil(64).max(1);
        let total_u64s = final_files.checked_mul(new_words_per_file).ok_or_else(|| bad("bitset size overflow"))?;

        let slots:      &[u32] = &*scratch.slots;
        let slot_of:    &[u32] = &*scratch.slot_of;
        let clear:      &[u64] = scratch.clear .get_(..new_words_per_file);
        let new_hashes: &[u32] = scratch.hashes.get_(..new_num_fragments);
        laps.lap("plan");

        //
        //
        // Allocate
        //
        //

        let old_keys     = self.file_keys   .make_slice(old_num_files);
        let old_metas    = self.file_metas  .make_slice(old_num_files);
        let old_bits     = self.file_bitsets.make_slice(self.file_bitsets.len().min(old_num_files * old_words_per_file));

        //
        // keys and metas are both FileKey/FileMeta (repr align(16), size 16), so both
        // regions are exact multiples of 16 bytes -- metas and bits both land on a
        // 16-byte boundary already. Bits is a multiple of 8 bytes, so the hashes region
        // that follows it is 8-byte aligned (needs 4).
        //

        const _: ()      = assert!(align_of::<FileKey >() == 16);
        const _: ()      = assert!(align_of::<FileMeta>() == 16);

        let   keys_bytes = final_files  .checked_mul(size_of::<FileKey>()) .ok_or_else(|| bad("size overflow"))?;
        let  metas_bytes = final_files  .checked_mul(size_of::<FileMeta>()).ok_or_else(|| bad("size overflow"))?;
        let   bits_bytes = total_u64s   .checked_mul(size_of::<u64>())     .ok_or_else(|| bad("size overflow"))?;
        let hashes_bytes = max_fragments.checked_mul(size_of::<u32>())     .ok_or_else(|| bad("size overflow"))?;

        debug_assert_eq!(keys_bytes  % 16, 0);
        debug_assert_eq!(metas_bytes % 16, 0);

        let arena_bytes = keys_bytes.checked_add(metas_bytes)
            .and_then(|s| s.checked_add(bits_bytes))
            .and_then(|s| s.checked_add(hashes_bytes))
            .ok_or_else(|| bad("size overflow"))?;

        //
        // Zeroed calloc allocation from kernel's zero pages.
        //
        let mut arena = vec![0u128; arena_bytes.div_ceil(16)];
        populate(&mut arena);

        //
        // SAFETY: base is 16-byte aligned (u128). The four regions (keys | metas | bits | hashes)
        // are laid out back-to-back at the offsets computed above, each sized exactly to the
        // FatPtr length it's given, no aliasing.
        //
        // 'arena' is not touched again until into_boxed_slice() at the very end,
        // so these pointers stay valid for the rest of the function.
        //

        let base                    = arena.as_mut_ptr() as *mut u8; assert_eq!(base as usize % 16, 0);
        let   keys_ptr              = base as *mut FileKey;
        let  metas_ptr              = unsafe { base.add(keys_bytes) } as *mut FileMeta;
        let   bits_ptr              = unsafe { base.add(keys_bytes + metas_bytes) } as *mut u64;
        let hashes_ptr              = unsafe { base.add(keys_bytes + metas_bytes + bits_bytes) } as *mut u32;

        let keys:   &mut [FileKey]  = unsafe { std::slice::from_raw_parts_mut(keys_ptr,   final_files)   };
        let metas:  &mut [FileMeta] = unsafe { std::slice::from_raw_parts_mut(metas_ptr,  final_files)   };
        let bits:   &mut [u64]      = unsafe { std::slice::from_raw_parts_mut(bits_ptr,   total_u64s)    };
        let hashes: &mut [u32]      = unsafe { std::slice::from_raw_parts_mut(hashes_ptr, max_fragments) };

        keys  .get_mut_(..old_num_files)    .copy_from_slice(old_keys);
        metas .get_mut_(..old_num_files)    .copy_from_slice(old_metas);
        hashes.get_mut_(..new_num_fragments).copy_from_slice(new_hashes);  // Tail stays zero
        laps.lap("alloc");

        //
        //
        // Rows migration
        //
        //

        //
        // Fused old->new bitset copy. 'dst' is freshly zeroed, so stride growth needs no
        // explicit padding.
        //
        // Columns in 'clear' are zeroed on the way through, which replaces every per-fragment
        // 'clear this bit for all existing files' strided loop with one sequential pass
        // (or a plain memcpy when nothing needs clearing).
        //

        let rows_available = old_bits.len() / old_words_per_file;

        debug_assert!(old_words_per_file <= new_words_per_file                  && clear.len()    ==                 new_words_per_file);
        debug_assert!(bits.len()         >= rows_available * new_words_per_file && old_bits.len() >= rows_available * old_words_per_file);

        let no_clear = clear.iter().all(|&c| c == 0);
        if old_words_per_file == new_words_per_file {
            let n = rows_available * old_words_per_file;

            if no_clear {
                bits.get_mut_(..n).copy_from_slice(old_bits.get_(..n));

            } else if old_words_per_file == 1 {
                let keep = !clear[0];
                for (dst, src) in bits.get_mut_(..rows_available).iter_mut().zip(old_bits.get_(..rows_available)) { *dst = *src & keep }

            } else {
                let src_chunks = old_bits.get_(..n).chunks_exact    (old_words_per_file);
                let dst_chunks = bits.get_mut_(..n).chunks_exact_mut(old_words_per_file);
                for (dst, src) in dst_chunks.zip(src_chunks) {
                    for ((dst, src), clear) in dst.iter_mut().zip(src).zip(clear) { *dst = *src & !*clear }
                }
            }

        } else {
            for r in 0..rows_available {
                let src = old_bits.get_(r * old_words_per_file..).get_    (..old_words_per_file);
                let dst = bits.get_mut_(r * new_words_per_file..).get_mut_(..old_words_per_file);
                for ((dst, src), clear) in dst.iter_mut().zip(src).zip(clear) { *dst = *src & !*clear }
            }
        }

        laps.lap("migrate");

        //
        //
        // Apply the batch
        //
        //

        const AHEAD: usize = 16;

        for (i, file_plan) in plan.files.iter().enumerate() {
            if let Some(&ahead) = slots.get(i + AHEAD) {
                let ahead_id = ahead & !RESET;
                if ahead != DROPPED && (ahead_id as usize) < old_num_files {
                    prefetch_read(bits.as_ptr().wrapping_add(ahead_id as usize * new_words_per_file));
                }
            }

            let slot = *slots.get_(i);
            if slot == DROPPED { continue; }

            let id         = (slot & !RESET)      as usize;
            let file_index = file_plan.file_index as usize;

            //
            // final_files-sized regions are already fully allocated,
            // so every id -- new or existing -- is just a direct write.
            //
            let file_id = *file_ids.get_(file_index);
            *keys .get_mut_(id) = file_id.key;
            *metas.get_mut_(id) = file_id.meta;

            let row = bits.get_mut_(id * new_words_per_file..).get_mut_(..new_words_per_file);
            if slot & RESET != 0 { row.fill(0); }

            let presence = fragment_presence.get_(file_index * plan_words_per_file..).get_(..plan_words_per_file);
            for (file_index, &slot) in slot_of.iter().enumerate() {
                if slot == NO_SLOT { continue; }

                let present = bit_get(presence, file_index);

                let dst     = slot as usize;
                let w       = row.get_mut_(dst >> 6);

                if present {
                    // ----- Fragment PRESENT (bit=0)
                    *w     &= !(1u64 << (dst & 63));
                } else {
                    // ----- Fragment ABSENT  (bit=1)
                    *w     |=   1u64 << (dst & 63);
                }
            }
        }

        laps.lap("apply");

        //
        //
        // Commit
        //
        //

        let arena                  = crate::util::vec_into_boxed_slice_noshrink(arena);

        self.fragment_hashes       = unsafe { FatPtr::from_raw(hashes_ptr as *const u32, max_fragments) };
        self.file_keys             = unsafe { FatPtr::from_raw(keys_ptr as *const FileKey, final_files) };
        self.file_metas            = unsafe { FatPtr::from_raw(metas_ptr as *const FileMeta, final_files) };
        self.file_bitsets          = unsafe { FatPtr::from_raw(bits_ptr as *const u64, total_u64s) };

        self.owned_fragment_hashes = None;  // Ownership moved into owned_arena
        self.owned_file_keys       = None;
        self.owned_file_metas      = None;
        self.owned_file_bitsets    = None;
        self.owned_arena           = Some(arena);

        self.num_fragments         = new_num_fragments as u32;
        self.ring_pos              = fragment_layout.ring_pos as u32;
        self.num_files             = final_files as u32;
        self.file_capacity         = final_files;
        self.backing               = None;
        self.file_lookup           = Box::default();

        laps.lap("commit");

        if dropped_files > 0 {
            #[cfg(not(feature = "no-cache-stats"))]
            self.stats.dropped_at_capacity.fetch_add(dropped_files, Ordering::Relaxed);

            eprintln!(
                "FragmentCache dropped {} file(s), max_files ({}) reached; \
                 these files will never be cached until max_files is increased",
                dropped_files, self.max_files
            );
        }

        if fragment_layout.dropped > 0 {
            eprintln!(
                "FragmentCache dropped {} fragment(s): every ring slot is used by this batch \
                 (batch has more distinct fragments than max_fragments = {})",
                fragment_layout.dropped, self.max_fragments
            );
        }

        laps.report(plan.files.len(), plan.frags.len());

        Ok(())
    }

    /// apply_batch leaves `file_lookup` empty (the table is not persisted, and a one-shot
    /// writer never queries it). Anything that needs it afterwards calls this first.
    /// Load factor is <= 0.5, so unbounded probing terminates. Make the reader probe
    /// unbounded too, otherwise entries past probe 16 can't be found (see chat).
    pub fn rebuild_lookup_from_keys(&mut self) {
        let n    = self.num_files as usize;
        let size = (2 * n.max(1)).next_power_of_two();
        let mask = size - 1;

        let mut table = vec![FILE_LOOKUP_EMPTY; size].into_boxed_slice();
        for (id, key) in self.file_keys.make_slice(n).iter().enumerate() {
            let mut i = (key.hash() as usize) & mask;
            while table[i] != FILE_LOOKUP_EMPTY { i = (i + 1) & mask; }
            table[i] = id as u32;
        }

        self.file_lookup = table;
    }

    /// Same as merge_updates(), but skips ensure_owned() and every mutation
    /// entirely if the batch would not change anything already on disk.
    /// Returns whether it actually wrote anything, so the caller knows
    /// whether save_to_disk() is worth calling.
    pub fn merge_updates_if_changed(
        &mut self,
        file_ids:          &[FileIdentifier],
        fragment_hashes:   &[u32],
        fragment_presence: &[u64],
    ) -> io::Result<bool> {
        if file_ids.is_empty() {
            return Ok(false);
        }

        let plan = self.plan_batch(file_ids, fragment_hashes, fragment_presence);
        if !plan.changed {
            return Ok(false);
        }

        self.apply_batch(&plan, file_ids, fragment_presence)?;

        Ok(true)
    }
}

#[allow(dead_code, reason = "tests")]
impl<S: CacheStorage> FragmentCache<S> {
    /// Check if file can be skipped
    #[inline]
    pub fn can_skip_file_for_tests(
        &self,
        key:   FileKey,
        meta:  FileMeta,
        fragment_hashes: &[u32],
    ) -> bool {
        let mut fragment_indexes = Vec::new();
        self.resolve_fragment_indexes(fragment_hashes, &mut fragment_indexes);

        self.can_skip_file(FileIdentifier { key, meta }, &fragment_indexes)
    }

    /// Unconditional merge, same behavior as before. Used by tests and any
    /// caller that already knows it wants to write.
    pub fn merge_updates(
        &mut self,
        file_keys:         &[FileKey],
        file_metas:        &[FileMeta],
        fragment_hashes:   &[u32],
        fragment_presence: &[u64],
    ) -> io::Result<()> {
        if file_keys.is_empty() {
            return Ok(());
        }

        let file_ids = file_keys.iter()
            .zip(file_metas.iter())
            .map(|(&key, &meta)| FileIdentifier { key, meta })
            .collect::<Vec<_>>();

        let plan = self.plan_batch(&file_ids, fragment_hashes, fragment_presence);
        self.apply_batch(&plan, &file_ids, fragment_presence)
    }

    /// Adapter for `merge_updates` that accepts presence as a flat `Vec<bool>`
    /// (`fragment_presence[file_index * fragment_count + frag_index]`) instead of packed bits.
    pub fn merge_updates_for_tests(
        &mut self,
        file_keys:         Vec<FileKey>,
        file_metas:        Vec<FileMeta>,
        fragment_hashes:  &[u32],
        fragment_presence: Vec<bool>,
    ) -> io::Result<()> {
        let fragment_count = fragment_hashes.len();
        let words_per_file = fragment_count.div_ceil(64);
        debug_assert_eq!(
            fragment_presence.len(),
            file_keys.len() * fragment_count,
            "fragment_presence len must be file_keys.len() * fragment_hashes.len()"
        );

        let mut packed = Vec::with_capacity(file_keys.len() * words_per_file);
        for file_index in 0..file_keys.len() {
            let row = &fragment_presence[file_index * fragment_count..(file_index + 1) * fragment_count];

            let mut words = vec![0u64; words_per_file];
            for (frag_index, &present) in row.iter().enumerate() {
                if present {
                    words[frag_index / 64] |= 1u64 << (frag_index % 64);
                }
            }

            packed.extend_from_slice(&words);
        }

        self.merge_updates(&file_keys, &file_metas, fragment_hashes, &packed)?;

        self.rebuild_lookup_from_keys();

        Ok(())
    }
}

#[inline(always)] fn bad(msg: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, msg.to_owned()) }
#[inline(always)] fn bit_get(w: &    [u64], i: usize) -> bool {  w.get_    (i >> 6) >> (i & 63) & 1 != 0 }
#[inline(always)] fn bit_set(w: &mut [u64], i: usize)         { *w.get_mut_(i >> 6) |= 1u64 << (i & 63); }

// ---------------------------------------------------------------------------
// Phase timers. Everything is recorded and printed ONCE at the end, so the
// stderr writes are not inside any measured interval. Also records minor page
// faults per phase.
// ---------------------------------------------------------------------------
fn minflt() -> i64 {
    let mut r: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut r) };
    r.ru_minflt as i64
}

struct Laps {
    start: Instant,
    last:  Instant,
    flt:   i64,
    rows:  [(&'static str, f64, i64); 8],
    n:     usize,
}

impl Laps {
    fn new() -> Self {
        let now = Instant::now();
        Laps { start: now, last: now, flt: minflt(), rows: [("", 0.0, 0); 8], n: 0 }
    }

    fn lap(&mut self, name: &'static str) {
        let now = Instant::now();
        let flt = minflt();
        if self.n < self.rows.len() {
            self.rows[self.n] = (name, (now - self.last).as_secs_f64() * 1e3, flt - self.flt);
            self.n += 1;
        }
        self.last = now;
        self.flt  = flt;
    }

    fn report(&self, files: usize, frags: usize) {
        let mut s = String::new();
        for &(name, ms, flt) in &self.rows[..self.n] {
            s += &format!(" {name} {ms:.2}ms/{flt}pf");
        }
        eprintln!(
            "Cache updated: {files} files, {frags} frags in {:.2}ms |{s}",
            (self.last - self.start).as_secs_f64() * 1e3,
        );
    }
}

/// What resolve_fragments() decided. The bulk data (slot_of / clear / hashes) stays in the
/// caller's scratch.
struct FragmentLayout {
    num_fragments: usize,
    ring_pos:      usize,
    dropped:       u32,
}

// ---------------------------------------------------------------------------
// Bulk page pre-fault. `vec![0u64; n]` / `Vec::with_capacity(n)` for a big n comes
// back as an unbacked mapping: nothing physical exists until each 4K page is
// first touched -- which is exactly what step 3 above was doing, one page at a
// time, interleaved with everything else. MADV_POPULATE_WRITE asks the kernel
// to back the whole range in one call instead, so that cost happens once, up
// front, rather than trickling in as N minor faults during the write loop.
//
// Pure latency hint: correctness never depends on it. Kernels older than 5.14
// (or any non-Linux target) just take the faults the old way, lazily.
// ---------------------------------------------------------------------------

//
// madvise() wants a page-aligned start address and fails with EINVAL otherwise. A large
// allocation from the system allocator is NOT page aligned: glibc's mmap'd chunks hand out
// `page_start + 16` (the chunk header sits in front), so passing the raw pointer made every
// call here fail and populate nothing.
//
// So shrink the range inward to whole pages: round the start up, the end down. The partial
// pages at either end may hold someone else's bytes, and they just fault in lazily as before.
//
#[cfg(target_os = "linux")]
fn populate_range(ptr: *mut u8, len: usize) {
    if len == 0 { return; }

    let page  = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let start = (ptr as usize).next_multiple_of(page);
    let end   = (ptr as usize + len) & !(page - 1);

    if end <= start { return; }

    unsafe { libc::madvise(start as *mut libc::c_void, end - start, libc::MADV_POPULATE_WRITE); }
}

#[cfg(target_os = "linux")]
fn populate<T>(slice: &mut [T]) {
    populate_range(slice.as_mut_ptr() as *mut u8, std::mem::size_of_val(slice));
}

#[cfg(target_os = "linux")]
fn populate_capacity<T>(v: &mut Vec<T>) {
    populate_range(v.as_mut_ptr() as *mut u8, v.capacity() * std::mem::size_of::<T>());
}

#[cfg(not(target_os = "linux"))]
fn populate<T>(_slice: &mut [T]) {}
#[cfg(not(target_os = "linux"))]
fn populate_capacity<T>(_v: &mut Vec<T>) {}

/// Every per-batch temporary, carved out of one zeroed allocation.
///
///   u64 region:  [ clear | pinned ]             max_words each
///   u32 region:  [ slots | slot_of | hashes ]   plan.files, plan.frags, max_fragments
///
/// Nothing here outlives apply_batch(): the fragment hashes are copied into the final
/// arena at commit time.
struct BatchScratch {
    buf:           Vec<u64>,
    files:         usize,
    frags:         usize,
    max_fragments: usize,
    words:         usize,
}

struct ScratchViews<'a> {
    slots:   &'a mut [u32],
    slot_of: &'a mut [u32],
    hashes:  &'a mut [u32],
    clear:   &'a mut [u64],
    pinned:  &'a mut [u64],
}

impl BatchScratch {
    fn new(files: usize, frags: usize, max_fragments: usize) -> io::Result<Self> {
        let words = max_fragments.div_ceil(64).max(1);

        let n32   = files.checked_add(frags)
            .and_then(|n| n.checked_add(max_fragments))
            .ok_or_else(|| bad("scratch size overflow"))?;

        let n64   = words.checked_mul(2)
            .and_then(|n| n.checked_add(n32.div_ceil(2)))
            .ok_or_else(|| bad("scratch size overflow"))?;

        Ok(Self { buf: vec![0u64; n64], files, frags, max_fragments, words })
    }

    fn views(&mut self) -> ScratchViews<'_> {
        let (u64s, rest)    = self.buf.split_at_mut(self.words * 2);
        let (clear, pinned) = u64s.split_at_mut(self.words);

        //
        // SAFETY: u32 has weaker alignment than u64 and every bit pattern is a valid u32,
        // and `rest` is a whole number of u64s, so prefix and suffix are both empty and
        // `mid` covers all of `rest` (2 * rest.len() u32s, >= files + frags + max_fragments).
        //
        let (pre, mid, post) = unsafe { rest.align_to_mut::<u32>() };
        assert!(pre.is_empty() && post.is_empty());

        let (slots,   mid) = mid.split_at_mut(self.files);
        let (slot_of, mid) = mid.split_at_mut(self.frags);
        let hashes         = &mut mid[..self.max_fragments];

        ScratchViews { slots, slot_of, hashes, clear, pinned }
    }
}
