#![allow(clippy::needless_range_loop)]

use crate::debug;
use crate::writeln_blue;
use crate::util::{likely, unlikely, prefetch_read};

use std::time::Instant;
use std::io::{self};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

const FILE_LOOKUP_EMPTY: u32 = u32::MAX;

/// Uniquely identifies a file across reboots
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileKey {
    pub device_id: u64,
    pub inode: u64,
}

impl FileKey {
    #[inline(always)]
    pub const fn new(device_id: u64, inode: u64) -> Self {
        Self { device_id, inode }
    }

    #[inline(always)]
    pub const fn hash(&self) -> u32 {
        ((self.device_id ^ self.inode).wrapping_mul(0x9e3779b9)) as u32
    }
}

/// Metadata for cache invalidation
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    pub mtime_sec: i64,
    pub size: u64,
}

impl FileMeta {
    #[inline(always)]
    pub const fn new(mtime_sec: i64, size: u64) -> Self {
        Self { mtime_sec, size }
    }

    #[inline(always)]
    pub const fn matches(&self, other: FileMeta) -> bool {
        self.mtime_sec == other.mtime_sec && self.size == other.size
    }
}

#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: u32,
    pub misses: u32,
    pub invalidations: u32,
    pub dropped_at_capacity: u32,
}

#[derive(Debug, Default)]
pub struct AtomicCacheStats {
    pub hits: AtomicU32,
    pub misses: AtomicU32,
    pub invalidations: AtomicU32,
    pub dropped_at_capacity: AtomicU32,
}

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
    #[allow(unused)]
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

impl CacheBytes {
    #[cfg(unix)]
    #[inline]
    fn advise(&self, advice: memmap2::Advice) {
        if let CacheBytes::Mapped(mmap) = self { _ = mmap.advise(advice) }
    }
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

        Self::fix_ownership(&tmp)?;
        std::fs::rename(&tmp, &self.path)?;
        Self::fix_ownership(&self.path)?;

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

        Self::fix_ownership(&tmp)?;
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
            fn ensure_memlock_capacity(min_bytes: u64) {
                let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl) } != 0 {
                    return;  // Can't even query; leave as-is...
                }

                // RLIM_INFINITY means no hard cap -- safe to just request what we need
                let target = if rl.rlim_max == libc::RLIM_INFINITY {
                    min_bytes
                } else {
                    min_bytes.min(rl.rlim_max)
                };

                if rl.rlim_cur >= target {
                    return;  // Already sufficient
                }

                let new_rl = libc::rlimit { rlim_cur: target, rlim_max: rl.rlim_max };
                let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &new_rl) };
                if ret != 0 {
                    debug!(
                        "[cache] setrlimit(RLIMIT_MEMLOCK) failed ({}), mlock may still fail",
                        io::Error::last_os_error()
                    );
                }
            }

            fn try_mlock_cache(bytes: &[u8]) -> bool {
                let ret = unsafe { libc::mlock(bytes.as_ptr() as *const libc::c_void, bytes.len()) };
                if ret != 0 {
                    let err = io::Error::last_os_error();
                    eprintln!("[cache] mlock failed ({err}), falling back to populate+advise");
                    false
                } else {
                    true
                }
            }

            ensure_memlock_capacity(256 * 1024 * 1024); // @Constant @Tune

            let t0 = Instant::now();

            // SAFETY: the file is only ever replaced via tmp+rename,
            // never truncated/modified in place, so this mapping stays valid for
            // as long as we hold it. External processes touching the cache path
            // directly would violate this, but that's outside our control anyway.
            let mmap = unsafe {
                memmap2::MmapOptions::new().populate().map(&file)?
            };

            eprintln!("mmap populated cache pages in {}ms", t0.elapsed().as_millis() as f64);

            let t0 = Instant::now();
            if try_mlock_cache(&mmap[..]) {
                eprintln!("mlock-cached cache pages in {}ms", t0.elapsed().as_millis() as f64);
            }

            Ok(Some(CacheBytes::Mapped(mmap)))
        }
    }
}

impl DiskStorage {
    #[inline]
    #[cfg(unix)]
    fn fix_ownership(path: &Path) -> io::Result<()> {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        let (sudo_uid, sudo_gid) = match (
            std::env::var("SUDO_UID").ok().and_then(|s| s.parse::<u32>().ok()),
            std::env::var("SUDO_GID").ok().and_then(|s| s.parse::<u32>().ok()),
        ) {
            (Some(uid), Some(gid)) => (uid, gid),
            _ => return Ok(()),
        };

        let path_cstr = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let ret = unsafe { libc::chown(path_cstr.as_ptr(), sudo_uid, sudo_gid) };
        if ret != 0 { return Err(io::Error::last_os_error()); }

        Ok(())
    }

    #[inline]
    #[cfg(not(unix))]
    fn fix_ownership(_path: &Path) -> io::Result<()> { Ok(()) }
}

#[derive(Default)]
pub struct MemoryStorage {
    data: parking_lot::Mutex<Option<Vec<u8>>>,
}

impl CacheStorage for MemoryStorage {
    #[inline]
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.data.lock().clone())

    }

    #[inline]
    fn save(&self, data: &[u8]) -> io::Result<()> {
        *self.data.lock() = Some(data.to_vec());
        Ok(())
    }

    #[inline]
    fn save_segments(&self, segments: &[&[u8]], total_size: usize) -> io::Result<()> {
        let mut data = Vec::with_capacity(total_size);

        debug_assert!(segments.iter().map(|s| s.len()).sum::<usize>() == total_size);

        for segment in segments {
            data.extend_from_slice(segment);
        }

        *self.data.lock() = Some(data);
        Ok(())
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

    //
    // ---------------------------------------------------------------

    file_lookup: Box<[u32]>,  // Open-addressed hash table

    pub stats: AtomicCacheStats,

    storage: S,

    backing: Option<CacheBytes>,
}

impl FragmentCache<DiskStorage> {
    /// Create new or load existing cache
    #[inline]
    pub fn new(config: &CacheConfig) -> io::Result<Self> {
        let path = Self::get_cache_path(config.cache_dir.as_deref())?;
        let storage = DiskStorage::new(path);

        if !config.ignore_cache {
            if let Ok(cache) = Self::load_from_disk(storage.clone(), config) {
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
        Self::create_empty(&config, MemoryStorage::default()).unwrap()
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
            let owned_keys  = cache.owned_file_keys.as_mut().unwrap();
            let owned_metas = cache.owned_file_metas.as_mut().unwrap();
            let owned_bits  = cache.owned_file_bitsets.as_mut().unwrap();

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

        cache.fragment_hashes = FatPtr::from_box(cache.owned_fragment_hashes.as_ref().unwrap());
        cache.file_keys       = FatPtr::from_box(cache.owned_file_keys.as_ref().unwrap());
        cache.file_metas      = FatPtr::from_box(cache.owned_file_metas.as_ref().unwrap());
        cache.file_bitsets    = FatPtr::from_box(cache.owned_file_bitsets.as_ref().unwrap());

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
        let max_files = config.max_files as u32;

        // Start with reasonable capacity to avoid many reallocations
        // 64K files = ~2MB for keys+metas, acceptable tradeoff for speed
        const INITIAL_CAPACITY: usize = 64 * 1024;

        let owned_fragment_hashes = Box::<[u32]>::new_uninit_slice(config.max_fragments);
        let owned_file_keys = Box::<[FileKey]>::new_uninit_slice(INITIAL_CAPACITY);
        let owned_file_metas = Box::<[FileMeta]>::new_uninit_slice(INITIAL_CAPACITY);

        let owned_fragment_hashes = unsafe { owned_fragment_hashes.assume_init() };
        let owned_file_keys = unsafe { owned_file_keys.assume_init() };
        let owned_file_metas = unsafe { owned_file_metas.assume_init() };

        // Stride=1 covers first 64 fragments, ensure_fragment_capacity
        // handles growth beyond that
        let owned_file_bitsets = vec![!0u64; INITIAL_CAPACITY].into_boxed_slice();

        // Small lookup table initially
        let lookup_size = (INITIAL_CAPACITY * 2).next_power_of_two();
        let mut file_lookup = Box::<[u32]>::new_uninit_slice(lookup_size);
        unsafe {
            std::ptr::write_bytes(file_lookup.as_mut_ptr(), 0xFF, lookup_size);
        }
        let file_lookup = unsafe { file_lookup.assume_init() };

        // Create FatPtrs from the owned boxes
        let fragment_hashes = FatPtr::from_box(&owned_fragment_hashes);
        let file_keys = FatPtr::from_box(&owned_file_keys);
        let file_metas = FatPtr::from_box(&owned_file_metas);
        let file_bitsets = FatPtr::from_box(&owned_file_bitsets);

        Ok(Self {
            num_fragments: 0,
            backing: None,
            num_files: 0,
            ring_pos: 0,
            max_fragments,
            max_files,
            file_capacity: INITIAL_CAPACITY,
            fragment_hashes,
            file_keys,
            file_metas,
            file_bitsets,
            owned_fragment_hashes: Some(owned_fragment_hashes),
            owned_file_keys: Some(owned_file_keys),
            owned_file_metas: Some(owned_file_metas),
            owned_file_bitsets: Some(owned_file_bitsets),
            file_lookup,
            stats: AtomicCacheStats::default(),
            storage
        })
    }

    /// COW: copy mmap data to owned buffers when we need to write
    fn ensure_owned(&mut self) {
        if self.owned_fragment_hashes.is_some() {
            // already owned
            return;
        }

        let start = Instant::now();

        let num_fragments = self.num_fragments as usize;
        let num_files = self.num_files as usize;

        // Allocate with growth headroom
        let new_capacity = (num_files + 64*1024).min(self.max_files as usize);

        let alloc_start = Instant::now();
        let mut new_fragment_hashes = Box::<[u32]>::new_uninit_slice(self.max_fragments as usize);
        let mut new_file_keys = Box::<[FileKey]>::new_uninit_slice(new_capacity);
        let mut new_file_metas = Box::<[FileMeta]>::new_uninit_slice(new_capacity);

        let bits_per_file_u64 = num_fragments.div_ceil(64).max(1);
        let total_u64s = new_capacity * bits_per_file_u64;
        let used_u64s = num_files * bits_per_file_u64;

        eprintln!(
            "ensure_owned called: num_files={}, new_capacity={}, bits_per_file_u64={}, total_bitset_KB={}",
            num_files,
            (num_files * 4).max(64 * 1024).min(self.max_files as usize),
            num_fragments.div_ceil(64).max(1),
            ((num_files * 4).max(64 * 1024).min(self.max_files as usize) * num_fragments.div_ceil(64).max(1) * 8) / 1024,
        );

        // allocate uninit and only copy what we need
        let mut new_file_bitsets = Box::<[u64]>::new_uninit_slice(total_u64s);
        let alloc_time = alloc_start.elapsed();

        //
        // Copy existing data from the mmap
        //
        let copy_start = Instant::now();
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.fragment_hashes.ptr,
                new_fragment_hashes.as_mut_ptr() as *mut u32,
                num_fragments,
            );
            std::ptr::copy_nonoverlapping(
                self.file_keys.ptr,
                new_file_keys.as_mut_ptr() as *mut FileKey,
                num_files,
            );
            std::ptr::copy_nonoverlapping(
                self.file_metas.ptr,
                new_file_metas.as_mut_ptr() as *mut FileMeta,
                num_files,
            );

            //
            // Copy used bitsets from mmap!!
            //
            std::ptr::copy_nonoverlapping(
                self.file_bitsets.ptr,
                new_file_bitsets.as_mut_ptr() as *mut u64,
                self.file_bitsets.len().min(used_u64s),
            );

            //
            // We leave the rest uninitialized - `merge_updates` will
            // initialize each new file's bitset when its added
            //
        }
        let copy_time = copy_start.elapsed();

        let new_fragment_hashes = unsafe { new_fragment_hashes.assume_init() };
        let new_file_keys = unsafe { new_file_keys.assume_init() };
        let new_file_metas = unsafe { new_file_metas.assume_init() };
        let new_file_bitsets = unsafe { new_file_bitsets.assume_init() };

        // ----------- Update pointers to point to owned data
        self.fragment_hashes = FatPtr::from_box(&new_fragment_hashes);
        self.file_keys = FatPtr::from_box(&new_file_keys);
        self.file_metas = FatPtr::from_box(&new_file_metas);
        self.file_bitsets = FatPtr::from_box(&new_file_bitsets);

        // ----------- Store owned data
        self.owned_fragment_hashes = Some(new_fragment_hashes);
        self.owned_file_keys = Some(new_file_keys);
        self.owned_file_metas = Some(new_file_metas);
        self.owned_file_bitsets = Some(new_file_bitsets);

        // ----------- Update capacity
        self.file_capacity = new_capacity;

        let total_time = start.elapsed();
        eprintln!(
            "Cache copy-on-write: {} files (capacity {}), {} fragments in {:.2}ms (alloc: {:.2}ms, copy: {:.2}ms)",
            num_files,
            new_capacity,
            num_fragments,
            total_time.as_millis() as f64,
            alloc_time.as_millis() as f64,
            copy_time.as_millis()  as f64,
        );
    }

    /// Grow capacity to fit at least `needed` files
    /// Must be called after ensure_owned()
    fn ensure_capacity(&mut self, needed: usize) {
        if needed <= self.file_capacity {
            return;
        }

        // @Constant
        let new_capacity = (needed + 64 * 1024).min(self.max_files as usize);
        if new_capacity <= self.file_capacity {
            return; // at max capacity already
        }

        let num_files = self.num_files as usize;
        let num_fragments = self.num_fragments as usize;
        let bits_per_file_u64 = num_fragments.div_ceil(64).max(1);

        //
        // Grow file_keys
        //
        let old_file_keys = self.owned_file_keys.take().unwrap();
        let mut new_file_keys = Box::<[FileKey]>::new_uninit_slice(new_capacity);
        unsafe {
            std::ptr::copy_nonoverlapping(
                old_file_keys.as_ptr(),
                new_file_keys.as_mut_ptr() as *mut FileKey,
                num_files,
            );
        }
        let new_file_keys = unsafe { new_file_keys.assume_init() };

        //
        // Grow file_metas
        //
        // @Refactor @Cutnpaste from above
        let old_file_metas = self.owned_file_metas.take().unwrap();
        let mut new_file_metas = Box::<[FileMeta]>::new_uninit_slice(new_capacity);
        unsafe {
            std::ptr::copy_nonoverlapping(
                old_file_metas.as_ptr(),
                new_file_metas.as_mut_ptr() as *mut FileMeta,
                num_files,
            );
        }
        let new_file_metas = unsafe { new_file_metas.assume_init() };

        //
        // Grow file_bitsets
        //
        // @Refactor @Cutnpaste from above
        let old_file_bitsets = self.owned_file_bitsets.take().unwrap();
        let old_u64s = num_files * bits_per_file_u64;
        let new_total_u64s = new_capacity * bits_per_file_u64;
        let mut new_file_bitsets = Box::<[u64]>::new_uninit_slice(new_total_u64s);
        unsafe {
            std::ptr::copy_nonoverlapping(
                old_file_bitsets.as_ptr(),
                new_file_bitsets.as_mut_ptr() as *mut u64,
                old_u64s.min(old_file_bitsets.len()),
            );
        }
        let new_file_bitsets = unsafe { new_file_bitsets.assume_init() };

        //
        // Grow lookup table if needed (maintain load factor < 0.5)
        //
        let needed_lookup_size = (new_capacity * 2).next_power_of_two();
        if needed_lookup_size > self.file_lookup.len() {
            let mut new_lookup = Box::<[u32]>::new_uninit_slice(needed_lookup_size);
            unsafe {
                std::ptr::write_bytes(new_lookup.as_mut_ptr(), 0xFF, needed_lookup_size);
            }
            let mut new_lookup = unsafe { new_lookup.assume_init() };

            //
            // Rehash all existing entries
            //
            let mask = needed_lookup_size - 1;
            let mut next_index = (num_files > 0)
                .then(|| (unsafe { new_file_keys.get_unchecked(0) }.hash() as usize) & mask);

            for file_id in 0..num_files {
                let index = unsafe { next_index.unwrap_unchecked() };

                if let Some(next_id) = (file_id + 1 < num_files).then_some(file_id + 1) {
                    let nh = (unsafe { new_file_keys.get_unchecked(next_id) }.hash() as usize) & mask;
                    prefetch_read(unsafe { new_lookup.as_ptr().add(nh) });
                    next_index = Some(nh);
                }

                let mut probe = index;
                for _ in 0..16 {
                    let existing = *unsafe { new_lookup.get_unchecked(probe) };
                    if existing == FILE_LOOKUP_EMPTY {
                        unsafe { *new_lookup.get_unchecked_mut(probe) = file_id as u32 };
                        break;
                    }

                    probe = (probe + 1) & mask;
                }
            }

            self.file_lookup = new_lookup;
        }

        //
        // Update FatPtrs
        //
        self.file_keys = FatPtr::from_box(&new_file_keys);
        self.file_metas = FatPtr::from_box(&new_file_metas);
        self.file_bitsets = FatPtr::from_box(&new_file_bitsets);

        //
        // Store new owned data
        //
        self.owned_file_keys = Some(new_file_keys);
        self.owned_file_metas = Some(new_file_metas);
        self.owned_file_bitsets = Some(new_file_bitsets);

        eprintln!("Cache capacity grew: {} -> {} files", self.file_capacity, new_capacity);
        self.file_capacity = new_capacity;
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

        let old_bits = self.owned_file_bitsets.take().unwrap();

        // Unknown -- only bits we've actually verified get set to 1.
        let mut new_bits = vec![0u64; file_capacity * new_stride].into_boxed_slice();

        if !old_bits.is_empty() {
            //
            // Only copy if there's actually data to copy
            //
            for file_id in 0..num_files {
                let old_offset = file_id * old_stride;
                let new_offset = file_id * new_stride;
                for i in 0..old_stride {
                    if old_offset + i < old_bits.len() {
                        new_bits[new_offset + i] = old_bits[old_offset + i];
                    }
                }
            }
        }

        self.owned_file_bitsets = Some(new_bits);
        self.file_bitsets = FatPtr::from_box(self.owned_file_bitsets.as_ref().unwrap());
    }

    fn load_from_disk(storage: S, config: &CacheConfig) -> io::Result<Self> {
        let start = Instant::now();

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
        let header_size = size_of::<CacheHeader>();
        let fragments_offset = header_size;
        let fragments_size = num_fragments * 4; // @Constant

        // ---------- Align file_keys to 16 bytes
        let file_keys_offset = (fragments_offset + fragments_size + 15) & !15;
        let file_keys_size = num_files * size_of::<FileKey>();

        // ---------- file_metas follows file_key
        let file_metas_offset = file_keys_offset + file_keys_size;
        let file_metas_size = num_files * size_of::<FileMeta>();

        // ---------- file_bitsets follows (align to 8 bytes for u64)
        let file_bitsets_offset = (file_metas_offset + file_metas_size + 7) & !7;
        let bits_per_file_u64 = num_fragments.div_ceil(64);
        let file_bitsets_len = num_files * bits_per_file_u64;

        let expected_size = file_bitsets_offset + file_bitsets_len * size_of::<u64>();
        if bytes.len() < expected_size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "cache data truncated"));
        }

        // SAFETY: offsets were computed from the same alignment rules `save_to_disk` used to write this file.
        let fragment_hashes = unsafe {
            FatPtr::from_raw(bytes.as_ptr().add(fragments_offset) as *const u32, num_fragments)
        };
        let file_keys = unsafe {
            FatPtr::from_raw(bytes.as_ptr().add(file_keys_offset) as *const FileKey, num_files)
        };
        let file_metas = unsafe {
            FatPtr::from_raw(bytes.as_ptr().add(file_metas_offset) as *const FileMeta, num_files)
        };
        let file_bitsets = unsafe {
            FatPtr::from_raw(bytes.as_ptr().add(file_bitsets_offset) as *const u64, file_bitsets_len)
        };

        #[cfg(unix)]
        bytes.advise(memmap2::Advice::Sequential);

        // @Note: This is here to try to prevent possible major page faults in ensure_owned calls we do.
        #[cfg(unix)]
        bytes.advise(memmap2::Advice::WillNeed);

        // ---- Build lookup table
        let lookup_size = ((num_files * 2).max(1024)).next_power_of_two();
        let mut file_lookup = Box::<[u32]>::new_uninit_slice(lookup_size);
        unsafe {
            std::ptr::write_bytes(file_lookup.as_mut_ptr(), 0xFF, lookup_size);
        }
        let mut file_lookup = unsafe { file_lookup.assume_init() };

        let mask = lookup_size - 1;
        let mut next_index = (num_files > 0).then(|| (file_keys.get(0).hash() as usize) & mask);

        for file_id in 0..num_files {
            let index = unsafe { next_index.unwrap_unchecked() };

            if let Some(next_id) = (file_id + 1 < num_files).then_some(file_id + 1) {
                let nh = (file_keys.get(next_id).hash() as usize) & mask;
                prefetch_read(unsafe { file_lookup.as_ptr().add(nh) });
                next_index = Some(nh);
            }

            let mut probe = index;
            for _ in 0..16 {
                if file_lookup[probe] == FILE_LOOKUP_EMPTY {
                    file_lookup[probe] = file_id as u32;
                    break;
                }

                probe = (probe + 1) & mask;
            }
        }

        eprintln!(
            "Cache loaded: {} files, {} fragments, {:.2}MB in {:.2}ms",
            num_files, num_fragments,
            bytes.len() as f64 / (1024.0 * 1024.0),
            start.elapsed().as_millis() as f64
        );

        #[cfg(unix)]
        bytes.advise(memmap2::Advice::Random);

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

        Ok(Self {
            num_fragments: num_fragments as u32,
            num_files: num_files as u32,
            ring_pos: header.ring_pos,
            backing: Some(bytes),
            max_fragments: config.max_fragments as u32,
            max_files: config.max_files as u32,
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
            stats: AtomicCacheStats::default(),
            storage
        })
    }

    #[inline]
    pub fn save_to_disk(&self) -> io::Result<()> {
        if self.owned_file_keys.is_none() {
            // Never dirtied this run (ensure_owned() was never called),
            // on-disk cache is already current, nothing to write.
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
        file_key: FileKey,
        file_meta: FileMeta,
        required_fragment_hashes: &[u32],
    ) -> bool {
        let Some(file_id) = self.lookup_file_id(file_key) else {
            // ----- Fast path
            #[cfg(not(feature = "no-cache-stats"))] {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
            }

            return false;
        };

        // -------- Check if any required fragment is marked absent
        let num_fragments = self.num_fragments as usize;
        let bits_per_file_u64 = num_fragments.div_ceil(64).max(1);
        let offset = (file_id as usize) * bits_per_file_u64; // Start of this file's bitset

        // Computable from file_id alone -- no dependency on the metadata check
        // below. Fire it now so it has the width of stored_meta.matches() to
        // land before the fragment loop actually needs it.
        if let Some(&first_hash) = required_fragment_hashes.first() {
            if let Some(frag_index) = self.find_fragment_index(first_hash, num_fragments) {
                prefetch_read(unsafe { self.file_bitsets.ptr.add(offset + (frag_index >> 6)) });
            }
        }

        // ------- Validate metadata
        let stored_meta = self.file_metas.get(file_id as usize);
        if unlikely(!stored_meta.matches(file_meta)) {
            #[cfg(not(feature = "no-cache-stats"))] {
                self.stats.invalidations.fetch_add(1, Ordering::Relaxed);
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
            }

            return false;
        }

        for &frag_hash in required_fragment_hashes {
            let Some(frag_index) = self.find_fragment_index(frag_hash, num_fragments) else {
                continue;
            };

            let u64_index = offset + (frag_index >> 6); // Which u64 contains the bit
            let bit_index = frag_index & 63;            // Which bit contains the info

            let bitset_val = self.file_bitsets.get(u64_index);
            let is_absent = (bitset_val & (1u64 << bit_index)) != 0;

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
            let file_id = *unsafe { self.file_lookup.get_unchecked(index) };
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
    /// NOTE: Caller must call ensure_owned() first!
    fn add_fragment(&mut self, frag_hash: u32) -> u32 {
        let num_fragments = self.num_fragments as usize;

        if let Some(index) = self.find_fragment_index(frag_hash, num_fragments) {
            return index as u32;
        }

        if num_fragments < self.max_fragments as usize {
            // ------- Ring buffer is not full
            let index = num_fragments;
            let new_num_fragments = num_fragments + 1;

            unsafe {
                *self.owned_fragment_hashes.as_mut()
                    .unwrap_unchecked()
                    .get_unchecked_mut(index) = frag_hash;
            }

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
            let u64_offset        = index / 64;
            let bit_index         = index % 64;

            let owned_file_bitsets = unsafe { self.owned_file_bitsets.as_mut().unwrap_unchecked() };
            let owned_file_bitsets_len = owned_file_bitsets.len();

            for file_id in 0..num_files {
                let bitset_index = file_id * bits_per_file_u64 + u64_offset;
                if bitset_index < owned_file_bitsets_len {
                    unsafe {
                        *owned_file_bitsets.get_unchecked_mut(bitset_index) &= !(1u64 << bit_index);
                    }
                }
            }

            index as u32
        } else {
            // ------- Ring buffer is full
            // evict oldest (FIFO)

            let ring_pos = self.ring_pos as usize;
            let index = ring_pos;

            unsafe {
                *self.owned_fragment_hashes.as_mut()
                    .unwrap_unchecked()
                    .get_unchecked_mut(index) = frag_hash;
            }

            let next_pos = (ring_pos + 1) % (self.max_fragments as usize);
            self.ring_pos = next_pos as u32;

            //
            // Clear this fragment position for all files (unknown state)
            //

            // Ring buffer full means num_fragments == max_fragments,
            // so stride is already at its maximum and will never grow again
            let num_files = self.num_files as usize;
            let bits_per_file_u64 = num_fragments.div_ceil(64).max(1);
            let u64_offset = index / 64;
            let bit_index    = index % 64;

            let owned_file_bitsets = self.owned_file_bitsets.as_mut().unwrap();
            let owned_file_bitsets_len = owned_file_bitsets.len();

            for file_id in 0..num_files {
                let bitset_index = file_id * bits_per_file_u64 + u64_offset;
                if bitset_index < owned_file_bitsets_len {
                    // Clear the bit (unknown/must-check)
                    unsafe {
                        *owned_file_bitsets.get_unchecked_mut(bitset_index) &= !(1u64 << bit_index);
                    }
                }
            }

            index as u32
        }
    }

    /// Insert file into lookup table
    #[inline]
    fn insert_into_lookup(&mut self, file_key: FileKey, file_id: u32) {
        let hash = file_key.hash();
        let mask = self.file_lookup.len() - 1;
        let mut index = (hash as usize) & mask;

        // @Note: This might silently fail, which means this file will always
        // miss the cache, maybe we should return like a boolean or something.
        for _ in 0..16 {
            let existing = unsafe { *self.file_lookup.get_unchecked(index) };

            if existing == FILE_LOOKUP_EMPTY {
                unsafe {
                    *self.file_lookup.get_unchecked_mut(index) = file_id;
                }

                return;  // Successfully inserted
            }

            index = (index + 1) & mask;
        }
    }

    #[inline]
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
        let num_fragments = self.num_fragments as usize;
        let num_files = self.num_files as usize;

        let fragments_size = num_fragments * size_of::<u32>();
        let file_keys_size = num_files * size_of::<FileKey>();
        let file_metas_size = num_files * size_of::<FileMeta>();

        let bits_per_file = num_fragments.div_ceil(64) * 64;
        let file_bitsets_size = num_files * (bits_per_file / 8);

        let lookup_size = self.file_lookup.len() * size_of::<AtomicU32>();

        fragments_size + file_keys_size + file_metas_size + file_bitsets_size + lookup_size
    }

    #[inline]
    fn get_cache_path(cache_dir: Option<&Path>) -> io::Result<PathBuf> {
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
        Self::fix_ownership(&dir)?;

        Ok(dir.join("fragment_cache.bin"))
    }

    /// Ownership of the cache directory/file may fuck up and error out
    /// when we try to write/read from it.
    ///
    /// So this function is for preventing that.
    #[cfg(unix)]
    fn fix_ownership(path: &Path) -> io::Result<()> {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        let (sudo_uid, sudo_gid) = match (
            std::env::var("SUDO_UID").ok().and_then(|s| s.parse::<u32>().ok()),
            std::env::var("SUDO_GID").ok().and_then(|s| s.parse::<u32>().ok()),
        ) {
            (Some(uid), Some(gid)) => (uid, gid),
            _ => return Ok(()), // not running with sudo, nothing to fix
        };

        let path_cstr = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let ret = unsafe { libc::chown(path_cstr.as_ptr(), sudo_uid, sudo_gid) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    #[cfg(not(unix))]
    fn fix_ownership(_path: &Path) -> io::Result<()> {
        Ok(())
    }
}

/// Resolution of a single fragment hash against the current table.
/// Computed once per batch since fragment_hashes is shared by every file.
struct FragPlan {
    hash: u32,

    // Some if already in the table. None means apply_batch must add it.
    existing_index: Option<u32>,
}

/// Resolution of a single file against the current table.
struct FilePlan {
    file_index:   u32,         // index into the caller's file_keys/file_metas
    existing_id:  Option<u32>, // None means apply_batch must insert it
    meta_changed: bool,
}

struct BatchPlan {
    frags: Vec<FragPlan>,
    files: Vec<FilePlan>,

    // True if applying this plan would touch any stored byte.
    changed: bool,
}

impl<S: CacheStorage> FragmentCache<S> {
    /// Read-only resolution pass. Never touches owned_* buffers, safe to
    /// call before ensure_owned(). Shared by merge_updates() and
    /// merge_updates_if_changed() so the lookups only happen once no matter
    /// which caller ends up applying the result.
    fn plan_batch(
        &self,
        file_keys: &[FileKey],
        file_metas: &[FileMeta],
        fragment_hashes: &[u32],
        fragment_presence: &[u64],
    ) -> BatchPlan {
        let num_fragments = self.num_fragments as usize;
        let bits_per_file_u64 = num_fragments.div_ceil(64).max(1);
        let words_per_file = fragment_hashes.len().div_ceil(64);

        //
        // Resolve fragments once, shared across every file below.
        //
        let mut frags = Vec::with_capacity(fragment_hashes.len().min(100));
        let mut has_new_fragment = false;
        for &hash in fragment_hashes.iter().take(100) {
            let existing_index = self.find_fragment_index(hash, num_fragments).map(|index| index as u32);
            if existing_index.is_none() {
                has_new_fragment = true;
            }

            frags.push(FragPlan { hash, existing_index });
        }

        let mut files = Vec::with_capacity(file_keys.len());

        //
        // A new fragment always dirties the batch: add_fragment() clears
        // that bit for every existing file, which is a state change even
        // if every file's own presence data matches what's on disk already.
        //
        let mut changed = has_new_fragment;

        for file_index in 0..file_keys.len() {
            let file_key = file_keys[file_index];
            let file_meta = file_metas[file_index];

            let existing_id = self.lookup_file_id(file_key);
            let meta_changed = match existing_id {
                None => true,  // Brand-new file is always a change
                Some(id) => {
                    let stored_meta = self.file_metas.get(id as usize);
                    !stored_meta.matches(file_meta)
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
                let presence = &fragment_presence[
                    file_index * words_per_file
                     ..
                    (file_index + 1) * words_per_file
                ];

                for (frag_i, frag_plan) in frags.iter().enumerate() {
                    // has_new_fragment is false here, so this is always Some.
                    let frag_index = frag_plan.existing_index.unwrap() as usize;
                    let is_present = (presence[frag_i / 64] & (1 << (frag_i % 64))) != 0;
                    let expect_bit_set = !is_present;

                    let u64_index = offset + (frag_index >> 6);
                    let bit_index = frag_index & 63;
                    let actual_bit_set = (self.file_bitsets.get(u64_index) & (1u64 << bit_index)) != 0;

                    if actual_bit_set != expect_bit_set {
                        changed = true;
                        break;
                    }
                }
            }

            files.push(FilePlan { file_index: file_index as u32, existing_id, meta_changed });
        }

        BatchPlan { frags, files, changed }
    }

    /// Applies a plan produced by plan_batch(). Caller is responsible for
    /// checking plan.changed first, this does no checking of its own.
    fn apply_batch(
        &mut self,
        plan: &BatchPlan,
        file_keys: &[FileKey],
        file_metas: &[FileMeta],
        fragment_presence: &[u64],
    ) -> io::Result<()> {
        let words_per_file = plan.frags.len().div_ceil(64).max(1) as u32;

        // COW: copy mmap data to owned buffers before writing.
        self.ensure_owned();

        let needed_capacity = self.num_files as usize + plan.files.len();
        self.ensure_capacity(needed_capacity);

        let start = Instant::now();

        //
        // Resolve every fragment up front. fragment_hashes is shared
        // by the whole batch, so each new hash only needs adding once here.
        //
        let mut frag_indexes = Vec::with_capacity(plan.frags.len());
        for frag_plan in &plan.frags {
            let index = match frag_plan.existing_index {
                Some(index) => index,
                None => self.add_fragment(frag_plan.hash),
            };
            frag_indexes.push(index);
        }

        let original_num_files = self.num_files as usize;

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
        let mut seen_file_ids = std::collections::HashSet::with_capacity(plan.files.len());

        //
        //
        // Add all files and collect fragment data
        //
        //

        let mut dropped = 0u32;
        let mut file_updates = Vec::with_capacity(plan.files.len());

        for (i, file_plan) in plan.files.iter().enumerate() {
            let num_files = self.num_files as usize;
            if num_files >= self.file_capacity {
                //
                // self.file_capacity is capped at self.max_files (see ensure_capacity),
                // so once it's reached, every subsequent file in this batch, and every future
                // merge_updates call, will drop new files the same way until max_files is raised.
                //
                dropped = (plan.files.len() - i) as u32;
                break;
            }

            let file_key  = file_keys[file_plan.file_index as usize];
            let file_meta = file_metas[file_plan.file_index as usize];

            let file_id = match file_plan.existing_id {
                Some(id) => id as usize,
                None => {
                    let new_file_id = num_files;
                    self.num_files = (num_files + 1) as u32;

                    self.insert_into_lookup(file_key, new_file_id as u32);
                    new_file_id
                }
            };

            #[cfg(debug_assertions)]
            debug_assert!(
                seen_file_ids.insert(file_id),
                "apply_batch: file_id {} appears more than once in a single batch, \
                 caller must de-duplicate by file_key before calling merge_updates.",
                file_id,
            );

            //
            // Update metadata
            //

            self.owned_file_keys .as_mut().unwrap()[file_id] = file_key;
            self.owned_file_metas.as_mut().unwrap()[file_id] = file_meta;

            let needs_full_reset =
                file_plan.existing_id.is_none()
             || file_plan.meta_changed
             || file_id >= original_num_files;

            let presence = &fragment_presence[
                (file_plan.file_index       * words_per_file) as usize
                ..
                ((file_plan.file_index + 1) * words_per_file) as usize
            ];

            //
            // Add fragments and collect indexes with their presence status
            //
            let mut fragment_data = Vec::with_capacity(frag_indexes.len());
            for (frag_i, &frag_index) in frag_indexes.iter().enumerate() {
                let is_present = (presence[frag_i / 64] & (1 << (frag_i % 64))) != 0;
                fragment_data.push((frag_index, is_present));
            }

            file_updates.push((file_id, fragment_data, needs_full_reset));
        }

        if dropped > 0 {
            self.stats.dropped_at_capacity.fetch_add(dropped, Ordering::Relaxed);
            eprintln!(
                "FragmentCache dropped {} file(s), max_files ({}) reached; \
                 these files will never be cached until max_files is increased",
                dropped, self.max_files
            );
        }

        //
        //
        // Update all bitsets
        //
        //

        let num_fragments = self.num_fragments as usize;
        let bits_per_file_u64 = num_fragments.div_ceil(64).max(1);
        let owned_file_bitsets = self.owned_file_bitsets.as_mut().unwrap();

        for (file_id, fragment_data, needs_full_reset) in file_updates {
            let offset = file_id * bits_per_file_u64;

            if needs_full_reset {
                for i in 0..bits_per_file_u64 {
                    let index = offset + i;
                    if index < owned_file_bitsets.len() {
                        owned_file_bitsets[index] = 0u64;  // Unknown -- only checked fragments get marked
                    }
                }
            }

            for (frag_index, is_present) in fragment_data {
                let frag_index = frag_index as usize;

                let u64_index = offset + (frag_index / 64);
                let bit_index = frag_index % 64;

                if u64_index < owned_file_bitsets.len() {
                    if is_present {
                        // ----- Fragment PRESENT - clear bit (bit=0)
                        owned_file_bitsets[u64_index] &= !(1u64 << bit_index);
                    } else {
                        // ----- Fragment ABSENT - set bit (bit=1)
                        owned_file_bitsets[u64_index] |=   1u64 << bit_index;
                    }
                }
            }
        }

        let elapsed = start.elapsed();
        eprintln!("Cache updated: {} files in {:.2}ms", plan.files.len(), elapsed.as_millis() as f64);

        Ok(())
    }

    /// Unconditional merge, same behavior as before. Used by tests and any
    /// caller that already knows it wants to write.
    pub fn merge_updates(
        &mut self,
        file_keys: &[FileKey],
        file_metas: &[FileMeta],
        fragment_hashes: &[u32],
        fragment_presence: &[u64],
    ) -> io::Result<()> {
        if file_keys.is_empty() {
            return Ok(());
        }

        let plan = self.plan_batch(file_keys, file_metas, fragment_hashes, fragment_presence);
        self.apply_batch(&plan, file_keys, file_metas, fragment_presence)
    }

    /// Same as merge_updates(), but skips ensure_owned() and every mutation
    /// entirely if the batch would not change anything already on disk.
    /// Returns whether it actually wrote anything, so the caller knows
    /// whether save_to_disk() is worth calling.
    pub fn merge_updates_if_changed(
        &mut self,
        file_keys: &[FileKey],
        file_metas: &[FileMeta],
        fragment_hashes: &[u32],
        fragment_presence: &[u64],
    ) -> io::Result<bool> {
        if file_keys.is_empty() {
            return Ok(false);
        }

        let plan = self.plan_batch(file_keys, file_metas, fragment_hashes, fragment_presence);
        if !plan.changed {
            return Ok(false);
        }

        self.apply_batch(&plan, file_keys, file_metas, fragment_presence)?;

        Ok(true)
    }

    /// Adapter for `merge_updates` that accepts presence as a flat `Vec<bool>`
    /// (`fragment_presence[file_index * fragment_count + frag_index]`) instead of packed bits.
    ///
    /// Used only in tests.
    pub fn merge_updates_bool(
        &mut self,
        file_keys: Vec<FileKey>,
        file_metas: Vec<FileMeta>,
        fragment_hashes: &[u32],
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

        self.merge_updates(&file_keys, &file_metas, fragment_hashes, &packed)
    }
}
