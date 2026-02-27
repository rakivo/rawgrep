#![allow(clippy::needless_range_loop)]

// @Testing @Refactor @Architecture
//
//

use crate::util::{likely, unlikely};

use std::time::Instant;
use std::io::{self};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use memmap2::Mmap;
use smallvec::SmallVec;
use serde::{Serialize, Deserialize};

const FILE_LOOKUP_EMPTY: u32 = u32::MAX;

/// Uniquely identifies a file across reboots
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    pub hits: AtomicU32,
    pub misses: AtomicU32,
    pub invalidations: AtomicU32,
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_fragments: usize,
    pub max_files: usize,
    pub cache_dir: Option<PathBuf>,
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
    fn get(&self, idx: usize) -> T {
        let Self { ptr, len } = *self;
        debug_assert!(idx < len, "FatPtr: index {idx} out of bounds (len {len})");
        unsafe { *ptr.add(idx) }
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

#[cfg(test)]
#[derive(Default)]
pub struct MemoryStorage {
    data: std::sync::Mutex<Option<Vec<u8>>>,
}

#[cfg(test)]
impl CacheStorage for MemoryStorage {
    #[inline]
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.data.lock().unwrap().clone())

    }

    #[inline]
    fn save(&self, data: &[u8]) -> io::Result<()> {
        *self.data.lock().unwrap() = Some(data.to_vec());
        Ok(())
    }
}

/// Core Fragment cache
#[repr(C, align(64))]
pub struct FragmentCache<S: CacheStorage = DiskStorage> {
    num_fragments: AtomicU32,
    num_files: AtomicU32,
    ring_pos: AtomicU32,
    max_fragments: u32,
    max_files: u32,
    file_capacity: usize, // Current allocation capacity for file arrays

    // -------- File data indexed by file_id , immutable during search
    //

    // Read-only slice pointers (point into mmap or owned boxes)
    // Using FatPtr for bounds-checked access in debug builds
    //
    fragment_hashes: FatPtr<u32>, // hash of 4-byte fragment
    file_keys: FatPtr<FileKey>,   // file identifiers
    file_metas: FatPtr<FileMeta>, // for cache invalidation
    file_bitsets: FatPtr<u64>,    // flattened bitsets: file_id * num_fragments_in_u64 + bit_idx

    // Owned data (None when using mmap, populated on copy-on-write)
    owned_fragment_hashes: Option<Box<[u32]>>,
    owned_file_keys: Option<Box<[FileKey]>>,
    owned_file_metas: Option<Box<[FileMeta]>>,
    owned_file_bitsets: Option<Box<[u64]>>,

    //
    // ---------------------------------------------------------------

    // Keeps mmap alive (data pointers reference into this)
    _mmap: Option<Mmap>,

    file_lookup: Box<[AtomicU32]>, // open-addressed hash table

    stats: CacheStats,

    storage: S,
}

impl FragmentCache<DiskStorage> {
    /// Create new or load existing cache
    #[inline]
    pub fn new(config: &CacheConfig) -> io::Result<Self> {
        let storage = DiskStorage::new(Self::get_cache_path(&config.cache_dir)?);

        if !config.ignore_cache {
            if let Ok(cache) = Self::load_from_disk(storage.clone(), config) {
                return Ok(cache);
            }
        }

        Self::create_empty(config, storage)
    }
}

#[cfg(test)]
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

        let num_fragments = cache.num_fragments.load(Ordering::Relaxed) as usize;
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

                for (frag_idx, &present) in fragment_presence[file_id].iter().enumerate() {
                    if present {
                        let u64_idx = offset + frag_idx / 64;
                        let bit_idx = frag_idx % 64;
                        if u64_idx < owned_bits.len() {
                            owned_bits[u64_idx] &= !(1u64 << bit_idx);
                        }
                    }
                }
            }
        }

        cache.fragment_hashes = FatPtr::from_box(cache.owned_fragment_hashes.as_ref().unwrap());
        cache.file_keys       = FatPtr::from_box(cache.owned_file_keys.as_ref().unwrap());
        cache.file_metas      = FatPtr::from_box(cache.owned_file_metas.as_ref().unwrap());
        cache.file_bitsets    = FatPtr::from_box(cache.owned_file_bitsets.as_ref().unwrap());

        cache.num_files.store(num_files as u32, Ordering::Relaxed);

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
        let mut file_lookup = Box::<[AtomicU32]>::new_uninit_slice(lookup_size);
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
            num_fragments: AtomicU32::new(0),
            num_files: AtomicU32::new(0),
            ring_pos: AtomicU32::new(0),
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
            _mmap: None,
            file_lookup,
            stats: CacheStats::default(),
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

        let num_fragments = self.num_fragments.load(Ordering::Relaxed) as usize;
        let num_files = self.num_files.load(Ordering::Relaxed) as usize;

        // Allocate with growth headroom
        let new_capacity = (num_files * 4).max(64 * 1024).min(self.max_files as usize);

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
        // Copy existing data from mmap
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

        // ----------- Drop mmap
        self._mmap = None;

        let total_time = start.elapsed();
        eprintln!(
            "Cache copy-on-write: {} files (capacity {}), {} fragments in {:.2}ms (alloc: {:.2}ms, copy: {:.2}ms)",
            num_files,
            new_capacity,
            num_fragments,
            total_time.as_secs_f64() * 1000.0,
            alloc_time.as_secs_f64() * 1000.0,
            copy_time.as_secs_f64()  * 1000.0,
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

        let num_files = self.num_files.load(Ordering::Relaxed) as usize;
        let num_fragments = self.num_fragments.load(Ordering::Relaxed) as usize;
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
            let mut new_lookup = Box::<[AtomicU32]>::new_uninit_slice(needed_lookup_size);
            unsafe {
                std::ptr::write_bytes(new_lookup.as_mut_ptr(), 0xFF, needed_lookup_size);
            }
            let new_lookup = unsafe { new_lookup.assume_init() };

            //
            // Rehash all existing entries
            //
            let mask = needed_lookup_size - 1;
            for file_id in 0..num_files {
                let file_key = new_file_keys[file_id];
                let hash = file_key.hash();
                let mut idx = (hash as usize) & mask;
                for _ in 0..16 {
                    let existing = new_lookup[idx].load(Ordering::Relaxed);
                    if existing == FILE_LOOKUP_EMPTY {
                        new_lookup[idx].store(file_id as u32, Ordering::Relaxed);
                        break;
                    }
                    idx = (idx + 1) & mask;
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

        let num_files     = self.num_files.load(Ordering::Relaxed) as usize;
        let file_capacity = self.file_capacity;

        let old_bits = self.owned_file_bitsets.take().unwrap();
        let mut new_bits = vec![!0u64; file_capacity * new_stride].into_boxed_slice();

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

        let Some(bytes) = storage.load()? else {
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

        //
        // @Incomplete @Volatile
        //
        // Copy out of the byte buffer into owned allocations
        // We don't mmap here anymore cuz storage.load() already gave us a Vec<u8>.
        // We can a load_mmap() method to CacheStorage later tho.
        //

        let mut owned_fragment_hashes = Box::<[u32]>::new_uninit_slice(config.max_fragments);

        // Give 64K headroom above num_files so small merges don't trigger growth:
        let file_capacity = (num_files + 64 * 1024).min(config.max_files);
        let mut owned_file_keys  = Box::<[FileKey]>::new_uninit_slice(file_capacity);
        let mut owned_file_metas = Box::<[FileMeta]>::new_uninit_slice(file_capacity);
        let capacity_bitset_u64s = file_capacity * bits_per_file_u64;
        let mut owned_file_bitsets = Box::<[u64]>::new_uninit_slice(capacity_bitset_u64s);

        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(header_size) as *const u32,
                owned_fragment_hashes.as_mut_ptr() as *mut u32,
                num_fragments,
            );
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(file_keys_offset) as *const FileKey,
                owned_file_keys.as_mut_ptr() as *mut FileKey,
                num_files,
            );
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(file_metas_offset) as *const FileMeta,
                owned_file_metas.as_mut_ptr() as *mut FileMeta,
                num_files,
            );

            // Copy only what was saved - file_bitsets_len uses bits_per_file_u64 which
            // matches the serialized layout exactly
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(file_bitsets_offset) as *const u64,
                owned_file_bitsets.as_mut_ptr() as *mut u64,
                file_bitsets_len, // safe: dst has file_capacity * bits_per_file_u64 >= file_bitsets_len
            );
        }

        let owned_fragment_hashes = unsafe { owned_fragment_hashes.assume_init() };
        let owned_file_keys       = unsafe { owned_file_keys.assume_init() };
        let owned_file_metas      = unsafe { owned_file_metas.assume_init() };
        let owned_file_bitsets    = unsafe { owned_file_bitsets.assume_init() };

        let fragment_hashes = FatPtr::from_box(&owned_fragment_hashes);
        let file_keys       = FatPtr::from_box(&owned_file_keys);
        let file_metas      = FatPtr::from_box(&owned_file_metas);
        let file_bitsets    = FatPtr::from_box(&owned_file_bitsets);

        // ---- Build lookup table
        let lookup_size = ((num_files * 2).max(1024)).next_power_of_two();
        let mut file_lookup = Box::<[AtomicU32]>::new_uninit_slice(lookup_size);
        unsafe {
            std::ptr::write_bytes(file_lookup.as_mut_ptr(), 0xFF, lookup_size);
        }
        let file_lookup = unsafe { file_lookup.assume_init() };

        let mask = lookup_size - 1;
        for file_id in 0..num_files {
            let hash = owned_file_keys[file_id].hash();
            let mut idx = (hash as usize) & mask;
            for _ in 0..16 {
                if file_lookup[idx].load(Ordering::Relaxed) == FILE_LOOKUP_EMPTY {
                    file_lookup[idx].store(file_id as u32, Ordering::Relaxed);
                    break;
                }
                idx = (idx + 1) & mask;
            }
        }

        eprintln!(
            "Cache loaded: {} files, {} fragments, {:.2}MB in {:.2}ms",
            num_files, num_fragments,
            bytes.len() as f64 / (1024.0 * 1024.0),
            start.elapsed().as_secs_f64() * 1000.0,
        );

        let file_capacity = owned_file_keys.len();

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
            num_fragments: AtomicU32::new(num_fragments as u32),
            num_files: AtomicU32::new(num_files as u32),
            ring_pos: AtomicU32::new(header.ring_pos),
            max_fragments: config.max_fragments as u32,
            max_files: config.max_files as u32,
            file_capacity,
            fragment_hashes,
            file_keys,
            file_metas,
            file_bitsets,
            owned_fragment_hashes: Some(owned_fragment_hashes),
            owned_file_keys:       Some(owned_file_keys),
            owned_file_metas:      Some(owned_file_metas),
            owned_file_bitsets:    Some(owned_file_bitsets),
            _mmap: None,
            file_lookup,
            stats: CacheStats::default(),
            storage
        })
    }

    #[inline]
    pub fn save_to_disk(&self) -> io::Result<()> {
        let start = Instant::now();

        let num_fragments = self.num_fragments.load(Ordering::Relaxed) as usize;
        let num_files = self.num_files.load(Ordering::Relaxed) as usize;

        let header_size = size_of::<CacheHeader>();
        let fragments_size = num_fragments * 4;

        // ------- Calculate padding for alignment
        let pad1_size = ((header_size + fragments_size + (16 - 1)) & !(16 - 1)) - (header_size + fragments_size);
        let file_keys_size = num_files * size_of::<FileKey>();
        let file_metas_size = num_files * size_of::<FileMeta>();

        let after_metas = header_size + fragments_size + pad1_size + file_keys_size + file_metas_size;
        let pad2_size = ((after_metas + (8 - 1)) & !(8 - 1)) - after_metas;

        let bits_per_file_u64 = num_fragments.div_ceil(64);
        let file_bitsets_size = num_files * bits_per_file_u64 * size_of::<u64>();

        // ------- Header
        let total_size = header_size + fragments_size + pad1_size
            + file_keys_size + file_metas_size + pad2_size
            + file_bitsets_size;

        let mut buf = Vec::with_capacity(total_size);

        let header = CacheHeader {
            magic: CACHE_MAGIC,
            num_fragments: num_fragments as u32,
            num_files: num_files as u32,
            ring_pos: self.ring_pos.load(Ordering::Relaxed),
            _padding: 0,
        };

        // SAFETY: CacheHeader is repr(C), all fields are plain integers, no padding issues
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(&header as *const CacheHeader as *const u8, header_size)
        });
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(self.fragment_hashes.ptr as *const u8, fragments_size)
        });
        buf.resize(buf.len() + pad1_size, 0u8);
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(self.file_keys.ptr as *const u8, file_keys_size)
        });
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(self.file_metas.ptr as *const u8, file_metas_size)
        });
        buf.resize(buf.len() + pad2_size, 0u8);
        buf.extend_from_slice(unsafe {
            std::slice::from_raw_parts(self.file_bitsets.ptr as *const u8, file_bitsets_size)
        });

        debug_assert_eq!(buf.len(), total_size);

        self.storage.save(&buf)?;

        eprintln!(
            "Cache saved: {} files, {} fragments, {:.2}MB in {:.2}ms",
            num_files, num_fragments,
            total_size as f64 / (1024.0 * 1024.0),
            start.elapsed().as_secs_f64() * 1000.0,
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
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            return false;
        };

        // ------- Validate metadata
        let stored_meta = self.file_metas.get(file_id as usize);
        if unlikely(!stored_meta.matches(file_meta)) {
            self.stats.invalidations.fetch_add(1, Ordering::Relaxed);
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // -------- Check if any required fragment is marked absent
        let num_fragments = self.num_fragments.load(Ordering::Relaxed) as usize;
        let bits_per_file_u64 = num_fragments.div_ceil(64).max(1);
        let offset = (file_id as usize) * bits_per_file_u64; // Start of this file's bitset

        for &frag_hash in required_fragment_hashes {
            let Some(frag_idx) = self.find_fragment_index(frag_hash) else {
                continue;
            };

            let u64_idx = offset + (frag_idx >> 6); // Which u64 contains the bit
            let bit_idx = frag_idx & 63;            // Which bit contains the info

            let bitset_val = self.file_bitsets.get(u64_idx);
            let is_absent = (bitset_val & (1u64 << bit_idx)) != 0;

            if likely(is_absent) {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }

        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        false
    }

    #[inline(always)]
    fn find_fragment_index(&self, frag_hash: u32) -> Option<usize> {
        let num_fragments = self.num_fragments.load(Ordering::Relaxed) as usize;

        // small arrays (2-10 fragments) so linear is fastest
        (0..num_fragments).find(|&i| self.fragment_hashes.get(i) == frag_hash)
    }

    #[inline(always)]
    fn lookup_file_id(&self, file_key: FileKey) -> Option<u32> {
        let hash = file_key.hash();
        let mask = self.file_lookup.len() - 1;
        let mut idx = (hash as usize) & mask;

        for _ in 0..16 {
            let file_id = self.file_lookup[idx].load(Ordering::Acquire);
            if file_id == FILE_LOOKUP_EMPTY {
                return None;
            }

            let stored_key = self.file_keys.get(file_id as usize);
            if stored_key == file_key {
                return Some(file_id);
            }

            idx = (idx + 1) & mask;
        }

        None
    }

    /// Merge thread-local cache buffers into cache (called once after all workers finish)
    ///
    /// `fragment_presence` contains per-fragment presence info for each file:
    /// `fragment_presence[file_idx][frag_idx]` = true if that fragment is present in the file
    pub fn merge_updates(
        &mut self,
        file_keys: Vec<FileKey>,
        file_metas: Vec<FileMeta>,
        fragment_hashes: &[u32],
        fragment_presence: Vec<SmallVec<[bool; 32]>>,
    ) -> io::Result<()> {
        if file_keys.is_empty() {
            return Ok(());
        }

        // COW: copy mmap data to owned buffers before writing
        self.ensure_owned();

        // ------- Ensure we have capacity for all new files
        let current_files = self.num_files.load(Ordering::Relaxed) as usize;
        let needed_capacity = current_files + file_keys.len();
        self.ensure_capacity(needed_capacity);

        let start = Instant::now();

        //
        //
        // Add all files and collect fragment data
        //
        //

        let mut file_updates = Vec::with_capacity(file_keys.len());

        // ------- Track the original num_files to know which files are new
        let original_num_files = self.num_files.load(Ordering::Relaxed) as usize;

        for i in 0..file_keys.len() {
            let file_key = file_keys[i];
            let file_meta = file_metas[i];
            let presence = &fragment_presence[i];
            let num_files = self.num_files.load(Ordering::Relaxed) as usize;
            if num_files >= self.file_capacity {
                break; // at capacity (will grow on next merge if more files)
            }

            // --------- Find or insert file
            let file_id = match self.lookup_file_id(file_key) {
                Some(id) => id as usize,
                None => {
                    let new_file_id = num_files;
                    self.num_files.store((num_files + 1) as u32, Ordering::Relaxed);

                    let file_keys_slice = self.owned_file_keys.as_mut().unwrap();
                    let file_metas_slice = self.owned_file_metas.as_mut().unwrap();
                    file_keys_slice[new_file_id] = file_key;
                    file_metas_slice[new_file_id] = file_meta;

                    self.insert_into_lookup(file_key, new_file_id as u32);
                    new_file_id
                }
            };

            // --------- Update metadata
            self.owned_file_metas.as_mut().unwrap()[file_id] = file_meta;

            // --------- Add fragments and collect indices with their presence status
            //
            // Limit to 100 fragments per file
            //
            // @Constant @Tune
            let mut fragment_data = Vec::with_capacity(fragment_hashes.len().min(100));
            for (frag_i, &frag_hash) in fragment_hashes.iter().take(100).enumerate() {
                let frag_idx = self.add_fragment(frag_hash);
                let is_present = presence.get(frag_i).copied().unwrap_or(false);
                fragment_data.push((frag_idx, is_present));
            }

            // Track if this is a new file (needs bitset initialization)
            let is_new = file_id >= original_num_files;
            file_updates.push((file_id, fragment_data, is_new));
        }

        //
        //
        // Update all bitsets
        //
        //

        let num_fragments = self.num_fragments.load(Ordering::Relaxed) as usize;
        let bits_per_file_u64 = num_fragments.div_ceil(64).max(1);
        let owned_file_bitsets = self.owned_file_bitsets.as_mut().unwrap();

        for (file_id, fragment_data, is_new) in file_updates {
            let offset = file_id * bits_per_file_u64;

            // ----- Initialize new file's bitset to all !0 (all fragments absent)
            if is_new {
                for i in 0..bits_per_file_u64 {
                    let idx = offset + i;
                    if idx < owned_file_bitsets.len() {
                        owned_file_bitsets[idx] = !0u64;
                    }
                }
            }

            for (frag_idx, is_present) in fragment_data {
                let u64_idx = offset + (frag_idx / 64);
                let bit_idx = frag_idx % 64;
                if u64_idx < owned_file_bitsets.len() {
                    if is_present {
                        // ----- Fragment PRESENT - clear bit (bit=0)
                        owned_file_bitsets[u64_idx] &= !(1u64 << bit_idx);
                    } else {
                        // ----- Fragment ABSENT - set bit (bit=1)
                        owned_file_bitsets[u64_idx] |= 1u64 << bit_idx;
                    }
                }
            }
        }

        let elapsed = start.elapsed();
        eprintln!("Cache updated: {} files in {:.2}ms", file_keys.len(), elapsed.as_secs_f64() * 1000.0);

        Ok(())
    }

    /// Add pattern fragment to cache (called during initialization)
    #[inline]
    pub fn add_pattern_fragment(&mut self, frag_hash: u32) {
        self.ensure_owned();
        self.add_fragment(frag_hash);
    }

    /// Add fragment to ring buffer (returns index)
    /// NOTE: Caller must call ensure_owned() first!
    fn add_fragment(&mut self, frag_hash: u32) -> usize {
        if let Some(idx) = self.find_fragment_index(frag_hash) {
            return idx;
        }

        let num_fragments = self.num_fragments.load(Ordering::Relaxed) as usize;

        if num_fragments < self.max_fragments as usize {
            // ------- Ring buffer is not full
            let idx = num_fragments;
            let new_num_fragments = num_fragments + 1;

            // Write hash first
            self.owned_fragment_hashes.as_mut().unwrap()[idx] = frag_hash;

            //
            // Migrate bitset stride if we crossed a 64-boundary
            //

            // Pass num_fragments (old) and new_num_fragments explicitly
            // so ensure_fragment_capacity doesn't read the already-incremented atomic
            self.ensure_fragment_capacity(num_fragments, new_num_fragments);
            self.num_fragments.store(new_num_fragments as u32, Ordering::Relaxed);

            //
            //
            // Clear this fragment bit for ALL existing files
            // New fragments are "unknown" for existing files and we MUST check them
            //
            //

            let num_files = self.num_files.load(Ordering::Relaxed) as usize;
            let bits_per_file_u64 = new_num_fragments.div_ceil(64).max(1);
            let u64_offset = idx / 64;
            let bit_idx = idx % 64;

            let owned_file_bitsets = self.owned_file_bitsets.as_mut().unwrap();
            for file_id in 0..num_files {
                let bitset_idx = file_id * bits_per_file_u64 + u64_offset;
                if bitset_idx < owned_file_bitsets.len() {
                    owned_file_bitsets[bitset_idx] &= !(1u64 << bit_idx);
                }
            }

            idx
        } else {
            // ------- Ring buffer is full
            // evict oldest (FIFO)

            let ring_pos = self.ring_pos.load(Ordering::Relaxed) as usize;
            let idx = ring_pos;

            // Write hash first, then borrow bitsets
            self.owned_fragment_hashes.as_mut().unwrap()[idx] = frag_hash;

            let next_pos = (ring_pos + 1) % (self.max_fragments as usize);
            self.ring_pos.store(next_pos as u32, Ordering::Relaxed);

            //
            // Clear this fragment position for all files (unknown state)
            //

            // Ring buffer full means num_fragments == max_fragments,
            // so stride is already at its maximum and will never grow again
            let num_files = self.num_files.load(Ordering::Relaxed) as usize;
            let bits_per_file_u64 = num_fragments.div_ceil(64).max(1);
            let u64_offset = idx / 64;
            let bit_idx    = idx % 64;

            let owned_file_bitsets = self.owned_file_bitsets.as_mut().unwrap();

            for file_id in 0..num_files {
                let bitset_idx = file_id * bits_per_file_u64 + u64_offset;
                if bitset_idx < owned_file_bitsets.len() {
                    // clear the bit (unknown/must-check)
                    owned_file_bitsets[bitset_idx] &= !(1u64 << bit_idx);
                }
            }

            idx
        }
    }

    /// Insert file into lookup table
    #[inline]
    fn insert_into_lookup(&self, file_key: FileKey, file_id: u32) {
        let hash = file_key.hash();
        let mask = self.file_lookup.len() - 1;
        let mut idx = (hash as usize) & mask;

        for _ in 0..16 {
            let existing = self.file_lookup[idx].compare_exchange(
                FILE_LOOKUP_EMPTY,
                file_id,
                Ordering::Release,
                Ordering::Relaxed,
            );

            if existing.is_ok() {
                // successfully inserted
                return;
            }

            idx = (idx + 1) & mask;
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
        let num_fragments = self.num_fragments.load(Ordering::Relaxed) as usize;
        let num_files = self.num_files.load(Ordering::Relaxed) as usize;

        let fragments_size = num_fragments * size_of::<u32>();
        let file_keys_size = num_files * size_of::<FileKey>();
        let file_metas_size = num_files * size_of::<FileMeta>();

        let bits_per_file = num_fragments.div_ceil(64) * 64;
        let file_bitsets_size = num_files * (bits_per_file / 8);

        let lookup_size = self.file_lookup.len() * size_of::<AtomicU32>();

        fragments_size + file_keys_size + file_metas_size + file_bitsets_size + lookup_size
    }

    #[inline]
    fn get_cache_path(cache_dir: &Option<PathBuf>) -> io::Result<PathBuf> {
        let dir = if let Some(d) = cache_dir {
            d.clone()
        } else {
            let home = if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                //
                // ~/.cache/rawgrep/
                // When running with sudo, use the actual user's home directory
                //
                PathBuf::from("/home").join(sudo_user)
            } else {
                let home_str = std::env::var("HOME")
                    .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "HOME not set"))?;

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

// @Note: These tests are AI-generated, but its ok for a start I guess..

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use smallvec::SmallVec;

    // ─── Helpers ──────────────────────────────────────────────────────────────

    fn key(n: u64)              -> FileKey  { FileKey::new(1, n) }
    fn meta(mtime: i64, sz: u64) -> FileMeta { FileMeta::new(mtime, sz) }

    fn absent_presence(n: usize) -> Vec<bool> { vec![false; n] }
    fn present_presence(n: usize) -> Vec<bool> { vec![true; n] }

    // ─── can_skip_file ────────────────────────────────────────────────────────

    #[test]
    fn absent_fragment_allows_skip() {
        let hash_a = 0xAAAA_AAAA_u32;
        let hash_b = 0xBBBB_BBBB_u32;

        let cache = FragmentCache::with_test_data(
            vec![hash_a, hash_b],
            vec![key(1)],
            vec![meta(100, 200)],
            vec![vec![true, false]], // A present, B absent
        );

        assert!(cache.can_skip_file(key(1), meta(100, 200), &[hash_b]));
    }

    #[test]
    fn present_fragment_prevents_skip() {
        let hash_a = 0xAAAA_AAAA_u32;

        let cache = FragmentCache::with_test_data(
            vec![hash_a],
            vec![key(1)],
            vec![meta(100, 200)],
            vec![present_presence(1)],
        );

        assert!(!cache.can_skip_file(key(1), meta(100, 200), &[hash_a]));
    }

    #[test]
    fn unknown_file_is_not_skipped() {
        let cache = FragmentCache::new_in_memory(64, 64);
        assert!(!cache.can_skip_file(key(999), meta(1, 1), &[0xDEAD]));
    }

    #[test]
    fn stale_metadata_invalidates() {
        let hash = 0xDEAD_BEEF_u32;

        let cache = FragmentCache::with_test_data(
            vec![hash],
            vec![key(1)],
            vec![meta(100, 200)],
            vec![absent_presence(1)],
        );

        assert!(!cache.can_skip_file(key(1), meta(999, 200), &[hash]));
    }

    #[test]
    fn unknown_fragment_does_not_skip() {
        let cache = FragmentCache::with_test_data(
            vec![0x1111],
            vec![key(1)],
            vec![meta(1, 1)],
            vec![absent_presence(1)],
        );

        assert!(!cache.can_skip_file(key(1), meta(1, 1), &[0x9999_9999]));
    }

    // ─── merge_updates ────────────────────────────────────────────────────────

    #[test]
    fn merge_updates_absent_fragment_skippable() {
        let mut cache = FragmentCache::new_in_memory(64, 64);
        let hash = 0xCAFE_BABE_u32;

        cache.merge_updates(
            vec![key(42)],
            vec![meta(1234, 5678)],
            &[hash],
            vec![SmallVec::from_slice(&[false])],
        ).unwrap();

        assert!(cache.can_skip_file(key(42), meta(1234, 5678), &[hash]));
    }

    #[test]
    fn merge_updates_present_fragment_not_skippable() {
        let mut cache = FragmentCache::new_in_memory(64, 64);
        let hash = 0x1234_5678_u32;

        cache.merge_updates(
            vec![key(1)],
            vec![meta(1, 1)],
            &[hash],
            vec![SmallVec::from_slice(&[true])],
        ).unwrap();

        assert!(!cache.can_skip_file(key(1), meta(1, 1), &[hash]));
    }

    #[test]
    fn lookup_table_consistent_after_many_inserts() {
        let mut cache = FragmentCache::new_in_memory(32, 1024);
        let hash = 0xABCD_EF01_u32;

        let file_keys:  Vec<FileKey>  = (0..500).map(key).collect();
        let file_metas: Vec<FileMeta> = (0..500).map(|i| meta(i, i as u64)).collect();
        let presences: Vec<SmallVec<[bool; 32]>> = (0..500)
            .map(|_| SmallVec::from_slice(&[false]))
            .collect();

        cache.merge_updates(file_keys.clone(), file_metas.clone(), &[hash], presences).unwrap();

        for (i, &k) in file_keys.iter().enumerate() {
            assert!(
                cache.can_skip_file(k, file_metas[i], &[hash]),
                "file {i} not skippable after bulk insert"
            );
        }
    }

    // ─── ring buffer ─────────────────────────────────────────────────────────

    #[test]
    fn ring_buffer_eviction_clears_evicted_slot() {
        let mut cache = FragmentCache::new_in_memory(4, 64);
        let k = key(1);
        let m = meta(1, 1);

        let hashes: Vec<u32> = (0..4).map(|i| i as u32 * 0x1111).collect();
        cache.merge_updates(
            vec![k], vec![m], &hashes,
            vec![SmallVec::from_slice(&[false, false, false, false])],
        ).unwrap();

        // 5th fragment evicts slot 0
        let new_hash = 0xDEAD_DEAD_u32;
        cache.merge_updates(
            vec![k], vec![m], &[new_hash],
            vec![SmallVec::from_slice(&[false])],
        ).unwrap();

        // evicted fragment → unknown → cannot skip
        assert!(!cache.can_skip_file(k, m, &[hashes[0]]));
        // new fragment → absent → can skip
        assert!(cache.can_skip_file(k, m, &[new_hash]));
    }

    #[test]
    fn ring_buffer_wrap_does_not_panic() {
        const MAX: usize = 8;
        let mut cache = FragmentCache::new_in_memory(MAX, 32);

        for round in 0u32..3 {
            let k = key(round as u64);
            let m = meta(round as i64, round as u64);
            let hashes: Vec<u32> = (0..MAX).map(|i| round * 100 + i as u32).collect();
            let presence: SmallVec<[bool; 32]> = hashes.iter().map(|_| false).collect();

            cache.merge_updates(vec![k], vec![m], &hashes, vec![presence]).unwrap();
        }

        let _ = cache.memory_usage(); // just assert no corruption
    }

    // ─── proptest ─────────────────────────────────────────────────────────────

    proptest! {
        #[test]
        fn prop_ring_buffer_no_panic(
            max_frags in 1usize..=64,
            num_rounds in 1usize..=8,
            hashes in prop::collection::vec(any::<u32>(), 1..=16),
        ) {
            let mut cache = FragmentCache::new_in_memory(max_frags, 128);
            let k = key(1);
            let m = meta(1, 1);

            for _ in 0..num_rounds {
                let presence: Vec<SmallVec<[bool; 32]>> =
                    vec![hashes.iter().map(|_| false).collect()];
                cache.merge_updates(vec![k], vec![m], &hashes, presence).unwrap();
            }

            let _ = cache.memory_usage();
        }

        #[test]
        fn prop_random_insertions_lookup_consistent(
            num_files in 1usize..=256,
            seed in any::<u64>(),
        ) {
            let mut cache = FragmentCache::new_in_memory(32, 1024);
            let hash = 0xFEED_FACE_u32;

            let keys:   Vec<FileKey>  = (0..num_files).map(|i| key(seed ^ i as u64)).collect();
            let metas:  Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();
            let presences: Vec<SmallVec<[bool; 32]>> =
                (0..num_files).map(|_| SmallVec::from_slice(&[false])).collect();

            cache.merge_updates(keys.clone(), metas.clone(), &[hash], presences).unwrap();

            for i in 0..num_files {
                prop_assert!(
                    cache.can_skip_file(keys[i], metas[i], &[hash]),
                    "file {i} missing from lookup"
                );
            }
        }

        #[test]
        fn prop_bitset_absent_vs_present(
            frag_count in 1usize..=32,
            absent_mask in any::<u32>(),
        ) {
            let hashes: Vec<u32> = (0..frag_count).map(|i| (i as u32).wrapping_mul(0x1111_1111)).collect();
            let presence: Vec<bool> = (0..frag_count)
                .map(|i| (absent_mask >> (i % 32)) & 1 == 0)
                .collect();

            let cache = FragmentCache::with_test_data(
                hashes.clone(),
                vec![key(1)],
                vec![meta(1, 1)],
                vec![presence.clone()],
            );

            for (i, &hash) in hashes.iter().enumerate() {
                let is_absent  = !presence[i];
                let skippable  = cache.can_skip_file(key(1), meta(1, 1), &[hash]);
                prop_assert_eq!(
                    skippable, is_absent,
                    "frag {}: absent={} skippable={}", i, is_absent, skippable
                );
            }
        }
    }

    // ─── disk roundtrip (DiskStorage) ────────────────────────────────────────

    #[test]
    fn disk_roundtrip_preserves_data() {
        let dir = tempfile::tempdir().unwrap();
        let config = CacheConfig {
            max_fragments: 64,
            max_files: 256,
            cache_dir: Some(dir.path().to_path_buf()),
            ignore_cache: false,
        };

        let hash = 0xDEAD_BEEF_u32;
        let k    = key(77);
        let m    = meta(999, 1234);

        {
            let mut cache = FragmentCache::new(&config).unwrap();
            cache.merge_updates(
                vec![k], vec![m], &[hash],
                vec![SmallVec::from_slice(&[false])],
            ).unwrap();
            cache.save_to_disk().unwrap();
        }

        {
            let cache = FragmentCache::new(&config).unwrap();
            assert!(cache.can_skip_file(k, m, &[hash]));
        }
    }

    #[test]
    fn disk_roundtrip_alignment_odd_fragment_counts() {
        for num_frags in [1, 3, 7, 63, 64, 65] {
            let dir = tempfile::tempdir().unwrap();
            let config = CacheConfig {
                max_fragments: 128,
                max_files: 64,
                cache_dir: Some(dir.path().to_path_buf()),
                ignore_cache: false,
            };

            let hashes: Vec<u32> = (0..num_frags).map(|i| i as u32 * 3).collect();
            let k = key(1);
            let m = meta(1, 1);

            {
                let mut cache = FragmentCache::new(&config).unwrap();
                let presence: SmallVec<[bool; 32]> = hashes.iter().map(|_| false).collect();
                cache.merge_updates(vec![k], vec![m], &hashes, vec![presence]).unwrap();
                cache.save_to_disk().unwrap();
            }

            {
                let cache = FragmentCache::new(&config).unwrap();
                assert!(
                    cache.can_skip_file(k, m, &[hashes[0]]),
                    "round-trip failed for num_frags={num_frags}"
                );
            }
        }
    }

    #[test]
    fn disk_roundtrip_cow_preserves_old_data() {
        let dir = tempfile::tempdir().unwrap();
        let config = CacheConfig {
            max_fragments: 32,
            max_files: 128,
            cache_dir: Some(dir.path().to_path_buf()),
            ignore_cache: false,
        };

        let hash1 = 0xAAAA_AAAA_u32;
        let k1    = key(1);
        let m1    = meta(1, 1);

        {
            let mut cache = FragmentCache::new(&config).unwrap();
            cache.merge_updates(
                vec![k1], vec![m1], &[hash1],
                vec![SmallVec::from_slice(&[false])],
            ).unwrap();
            cache.save_to_disk().unwrap();
        }

        {
            let mut cache = FragmentCache::new(&config).unwrap();

            // insert new file → triggers CoW
            let hash2 = 0xBBBB_BBBB_u32;
            let k2    = key(2);
            let m2    = meta(2, 2);
            cache.merge_updates(
                vec![k2], vec![m2], &[hash2],
                vec![SmallVec::from_slice(&[false])],
            ).unwrap();

            assert!(cache.can_skip_file(k1, m1, &[hash1]), "old file lost after CoW");
            assert!(cache.can_skip_file(k2, m2, &[hash2]), "new file missing after CoW");
        }
    }

    // ─── False-positive absent: targeted regression tests ─────────────────────

    #[test]
    fn no_false_absent_basic() {
        // Simplest possible case: file has fragment, cache must not say absent
        let hash = 0xDEAD_BEEF_u32;
        let k = key(1);
        let m = meta(1, 1);

        let mut cache = FragmentCache::new_in_memory(64, 64);
        cache.merge_updates(
            vec![k], vec![m], &[hash],
            vec![SmallVec::from_slice(&[true])], // PRESENT
        ).unwrap();

        assert!(!cache.can_skip_file(k, m, &[hash]),
                "false absent: fragment is present but cache says skip");
    }

    #[test]
    fn no_false_absent_after_second_merge() {
        // File seen twice: first absent, then present (file changed)
        // After second merge, must NOT be skippable
        let hash = 0xAAAA_u32;
        let k = key(1);
        let m1 = meta(1, 100);
        let m2 = meta(2, 100); // mtime changed

        let mut cache = FragmentCache::new_in_memory(64, 64);

        // First scan: absent
        cache.merge_updates(
            vec![k], vec![m1], &[hash],
            vec![SmallVec::from_slice(&[false])],
        ).unwrap();

        assert!(cache.can_skip_file(k, m1, &[hash]), "should be skippable after absent");

        // Second scan: present (file was modified)
        cache.merge_updates(
            vec![k], vec![m2], &[hash],
            vec![SmallVec::from_slice(&[true])],
        ).unwrap();

        assert!(!cache.can_skip_file(k, m2, &[hash]),
                "false absent: fragment became present but cache still skips");
    }

    #[test]
    fn no_false_absent_stride_consistency_across_fragment_additions() {
        // Add files, then add MORE fragments - the stride changes.
        // Existing files must not become falsely skippable for fragments they have.
        let hash_a = 0x1111_u32;
        let hash_b = 0x2222_u32;
        let k = key(1);
        let m = meta(1, 1);

        let mut cache = FragmentCache::new_in_memory(64, 64);

        // Register file with fragment A present
        cache.merge_updates(
            vec![k], vec![m], &[hash_a],
            vec![SmallVec::from_slice(&[true])],
        ).unwrap();

        assert!(!cache.can_skip_file(k, m, &[hash_a]),
                "false absent before adding fragment B");

        // Now add fragment B in a second merge (different search pattern)
        // This changes num_fragments and potentially bits_per_file_u64
        cache.merge_updates(
            vec![key(99)], vec![meta(99, 99)], &[hash_b],
            vec![SmallVec::from_slice(&[false])],
        ).unwrap();

        // File 1 still has fragment A present - must NOT be skippable
        assert!(!cache.can_skip_file(k, m, &[hash_a]),
                "false absent after adding unrelated fragment B: stride corruption?");
    }

    #[test]
    fn no_false_absent_when_fragment_index_crosses_u64_boundary() {
        // Put fragments at positions 63 and 64 - straddles the u64 boundary
        // Wrong bit indexing would cause false absent here
        let mut cache = FragmentCache::new_in_memory(128, 64);
        let k = key(1);
        let m = meta(1, 1);

        // Fill 63 fragments as absent to push indices to boundary
        let filler: Vec<u32> = (0u32..63).map(|i| i * 7 + 1).collect();
        let filler_presence: SmallVec<[bool; 32]> = filler.iter().map(|_| false).collect();
        cache.merge_updates(vec![k], vec![m], &filler, vec![filler_presence]).unwrap();

        // Fragment at index 63 (last bit of first u64) - present
        let hash_63 = 0xBEEF_0063_u32;
        cache.merge_updates(
            vec![k], vec![m], &[hash_63],
            vec![SmallVec::from_slice(&[true])],
        ).unwrap();

        // Fragment at index 64 (first bit of second u64) - present
        let hash_64 = 0xBEEF_0064_u32;
        cache.merge_updates(
            vec![k], vec![m], &[hash_64],
            vec![SmallVec::from_slice(&[true])],
        ).unwrap();

        assert!(!cache.can_skip_file(k, m, &[hash_63]),
                "false absent at bit 63 (u64 boundary)");
        assert!(!cache.can_skip_file(k, m, &[hash_64]),
                "false absent at bit 64 (start of second u64)");
    }

    #[test]
    fn no_false_absent_after_capacity_growth() {
        // Force a capacity grow (ensure_capacity) and verify no files become
        // falsely skippable for fragments they have present
        let mut cache = FragmentCache::new_in_memory(32, 8);
        let hash = 0xCAFE_u32;

        // Insert files up to initial capacity to trigger growth
        let file_count = 200usize;
        let keys:   Vec<FileKey>  = (0..file_count).map(|i| key(i as u64)).collect();
        let metas:  Vec<FileMeta> = (0..file_count).map(|i| meta(i as i64, i as u64)).collect();
        // All files have fragment present
        let presences: Vec<SmallVec<[bool; 32]>> =
            (0..file_count).map(|_| SmallVec::from_slice(&[true])).collect();

        cache.merge_updates(keys.clone(), metas.clone(), &[hash], presences).unwrap();

        for i in 0..file_count {
            assert!(!cache.can_skip_file(keys[i], metas[i], &[hash]),
                    "false absent for file {i} after capacity growth");
        }
    }

    #[test]
    fn no_false_absent_ring_buffer_does_not_corrupt_present_bits() {
        // Fill ring buffer to capacity, then overflow it.
        // The evicted fragment slot is reused - if the clear-on-evict
        // incorrectly clears a PRESENT bit for another file, we get false absent.
        const MAX_FRAGS: usize = 8;
        let mut cache = FragmentCache::new_in_memory(MAX_FRAGS, 32);

        let target_hash = 0xDEAD_1234_u32; // fragment we care about
        let target_key  = key(1);
        let target_meta = meta(1, 1);

        // Register target file with target fragment PRESENT
        cache.merge_updates(
            vec![target_key], vec![target_meta], &[target_hash],
            vec![SmallVec::from_slice(&[true])],
        ).unwrap();

        // Now flood with other fragments to force ring buffer eviction of target_hash's slot
        for i in 0u32..(MAX_FRAGS as u32 * 3) {
            let filler_hash = 0xF000_0000 + i;
            let filler_key  = key(100 + i as u64);
            let filler_meta = meta(i as i64, i as u64);
            cache.merge_updates(
                vec![filler_key], vec![filler_meta], &[filler_hash],
                vec![SmallVec::from_slice(&[false])],
            ).unwrap();
        }

        // target_hash was evicted from the ring buffer, so it's "unknown" now -
        // can_skip_file should return FALSE (can't prove absent) not TRUE (false absent)
        assert!(!cache.can_skip_file(target_key, target_meta, &[target_hash]),
                "false absent after ring buffer evicted the fragment: \
                 eviction should make result unknown (no-skip), not absent (skip)");
    }

    #[test]
    fn no_false_absent_multiple_fragments_one_present() {
        // Query requires [A, B, C]. File has B present, A and C absent.
        // can_skip_file should return false because B might match.
        // (skip only happens when we can prove ALL required are absent -
        // actually the logic skips if ANY is absent. So this tests the
        // semantics: if A is absent, we skip even though B is present.
        // That's correct for OR-semantics grep but would be wrong for AND-semantics.
        // This test documents the actual semantics.)
        let hash_a = 0xAAAA_u32;
        let hash_b = 0xBBBB_u32;
        let hash_c = 0xCCCC_u32;
        let k = key(1);
        let m = meta(1, 1);

        let mut cache = FragmentCache::new_in_memory(64, 64);
        cache.merge_updates(
            vec![k], vec![m], &[hash_a, hash_b, hash_c],
            vec![SmallVec::from_slice(&[false, true, false])], // A absent, B present, C absent
        ).unwrap();

        // A is absent → can_skip returns true (skip because A definitely not in file)
        // This is correct for literal pattern fragments: if fragment A (part of pattern)
        // is absent, the full pattern can't match
        assert!(cache.can_skip_file(k, m, &[hash_a]),
                "should skip: fragment A is absent");

        // B is present → cannot skip
        assert!(!cache.can_skip_file(k, m, &[hash_b]),
                "false absent: fragment B is present");

        // Querying [A, B] together: A is absent so should return true (skip)
        // because finding ANY absent fragment is enough to skip
        assert!(cache.can_skip_file(k, m, &[hash_a, hash_b]),
                "should skip when at least one required fragment is absent");
    }

    // ─── Proptest: no false absents under random merges ───────────────────────

    proptest! {
        #[test]
        fn prop_no_false_absent_random_merges(
            num_files in 1usize..=50,
            num_frags in 1usize..=20,
            // presence[file][frag] packed as bits in a u64
            presence_bits in prop::collection::vec(any::<u64>(), 1..=50),
            seed in any::<u64>(),
        ) {
            let mut cache = FragmentCache::new_in_memory(num_frags.max(1), num_files.max(1));

            let hashes: Vec<u32> = (0..num_frags)
                .map(|i| (seed as u32).wrapping_add(i as u32).wrapping_mul(0x9e37_9769))
                .collect();

            let keys:   Vec<FileKey>  = (0..num_files).map(|i| key(seed ^ i as u64)).collect();
            let metas:  Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();

            // Build presence table: presence[file][frag]
            let presence_table: Vec<Vec<bool>> = (0..num_files)
                .map(|fi| {
                    let bits = presence_bits.get(fi % presence_bits.len()).copied().unwrap_or(0);
                    (0..num_frags).map(|fr| (bits >> (fr % 64)) & 1 == 1).collect()
                })
                .collect();

            let presences: Vec<SmallVec<[bool; 32]>> = presence_table.iter()
                .map(|p| p.iter().copied().collect())
                .collect();

            cache.merge_updates(keys.clone(), metas.clone(), &hashes, presences).unwrap();

            // For every file+fragment that is PRESENT, can_skip must be false
            for fi in 0..num_files {
                for fr in 0..num_frags {
                    if presence_table[fi][fr] {
                        let skippable = cache.can_skip_file(keys[fi], metas[fi], &[hashes[fr]]);
                        prop_assert!(
                            !skippable,
                            "false absent: file {} frag {} is present but can_skip=true",
                            fi, fr
                        );
                    }
                }
            }
        }

        #[test]
        fn prop_no_false_absent_across_multiple_merges(
            num_rounds in 2usize..=5,
            num_frags in 1usize..=16,
            seed in any::<u64>(),
        ) {
            let mut cache = FragmentCache::new_in_memory(num_frags * num_rounds, 64);

            // ground truth: file_id -> frag_hash -> is_present
            let mut ground_truth: std::collections::HashMap<u64, std::collections::HashMap<u32, bool>>
                = std::collections::HashMap::new();

            for round in 0..num_rounds {
                let k = key(round as u64);
                let m = meta(round as i64, round as u64);
                let round_hashes: Vec<u32> = (0..num_frags)
                    .map(|i| seed.wrapping_add(round as u64 * 1000 + i as u64) as u32)
                    .collect();

                // Alternate: even rounds present, odd rounds absent
                let present = round % 2 == 0;
                let presences: Vec<SmallVec<[bool; 32]>> =
                    vec![round_hashes.iter().map(|_| present).collect()];

                cache.merge_updates(vec![k], vec![m], &round_hashes, presences).unwrap();

                let entry = ground_truth.entry(round as u64).or_default();
                for &h in &round_hashes {
                    entry.insert(h, present);
                }
            }

            // Verify: no present fragment is falsely reported absent
            for (file_id, frags) in &ground_truth {
                let k = key(*file_id);
                let m = meta(*file_id as i64, *file_id);
                for (&hash, &present) in frags {
                    if present {
                        prop_assert!(
                            !cache.can_skip_file(k, m, &[hash]),
                            "false absent: file {} hash {:#x} is present but skipped",
                            file_id, hash
                        );
                    }
                }
            }
        }
    }

    // ─── Stride boundary stress tests ─────────────────────────────────────────

    #[test]
    fn no_false_absent_stride_jumps_at_64_boundary() {
        // Explicitly cross the 64-fragment boundary and verify no corruption.
        // This is the exact scenario that triggered the original bug.
        let mut cache = FragmentCache::new_in_memory(128, 32);

        let num_files = 8usize;
        let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(i as u64)).collect();
        let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();

        // Register all files with a known present fragment
        let anchor_hash = 0xA1C4_0000_u32;
        let anchor_presence: Vec<SmallVec<[bool; 32]>> =
            (0..num_files).map(|_| SmallVec::from_slice(&[true])).collect();
        cache.merge_updates(keys.clone(), metas.clone(), &[anchor_hash], anchor_presence).unwrap();

        // Add fragments one at a time, crossing the 64-boundary
        // Each addition must not corrupt the anchor_hash present bits
        for i in 0u32..70 {
            let filler_hash = 0xF000_0000u32.wrapping_add(i);
            // use a different file for each filler so we don't affect the anchor
            let filler_key  = key(1000 + i as u64);
            let filler_meta = meta(1000 + i as i64, 1000 + i as u64);
            cache.merge_updates(
                vec![filler_key], vec![filler_meta], &[filler_hash],
                vec![SmallVec::from_slice(&[false])],
            ).unwrap();

            // After every addition, all original files must still report anchor present
            for fi in 0..num_files {
                assert!(
                    !cache.can_skip_file(keys[fi], metas[fi], &[anchor_hash]),
                    "false absent after adding filler fragment {i}: \
                     file {fi} anchor present but can_skip=true \
                     (num_fragments now ~{})", i + 2
                );
            }
        }
    }

    #[test]
    fn no_false_absent_all_files_all_fragments_present_at_each_boundary() {
        // For each multiple-of-64 boundary, verify correctness right before,
        // at, and right after the crossing.
        for boundary in [64usize, 128, 192] {
            let mut cache = FragmentCache::new_in_memory(boundary + 4, 16);
            let num_files = 4usize;
            let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(i as u64 + boundary as u64 * 100)).collect();
            let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, boundary as u64 + i as u64)).collect();

            let mut present_hashes: Vec<u32> = Vec::new();

            // Fill up to boundary-2 with absent fragments to push count near boundary
            for i in 0u32..(boundary as u32 - 2) {
                let h = 0x0100_0000u32.wrapping_add(boundary as u32 * 1000).wrapping_add(i);
                let filler_key  = key(5000 + boundary as u64 * 1000 + i as u64);
                let filler_meta = meta(i as i64, i as u64);
                cache.merge_updates(
                    vec![filler_key], vec![filler_meta], &[h],
                    vec![SmallVec::from_slice(&[false])],
                ).unwrap();
            }

            // Now add fragments at boundary-1, boundary, boundary+1 as PRESENT for all files
            for offset in [0u32, 1, 2, 3] {
                let h = 0xBEEF_0000u32.wrapping_add(boundary as u32).wrapping_add(offset);
                present_hashes.push(h);
                let presences: Vec<SmallVec<[bool; 32]>> =
                    (0..num_files).map(|_| SmallVec::from_slice(&[true])).collect();
                cache.merge_updates(keys.clone(), metas.clone(), &[h], presences).unwrap();

                // Immediately verify all previously-added present hashes still not skippable
                for &ph in &present_hashes {
                    for fi in 0..num_files {
                        assert!(
                            !cache.can_skip_file(keys[fi], metas[fi], &[ph]),
                            "false absent at boundary {boundary}+{offset}: \
                             file {fi} hash {ph:#010x} present but skipped"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn no_false_absent_interleaved_files_and_fragments() {
        // Interleave adding new files and new fragments in alternating merges.
        // This is the hardest pattern: stride grows while file count also grows.
        let mut cache = FragmentCache::new_in_memory(200, 200);

        // ground truth: key_id -> hash -> present
        let mut ground_truth: Vec<(FileKey, FileMeta, u32, bool)> = Vec::new();

        for step in 0u32..80 {
            let k = key(step as u64);
            let m = meta(step as i64, step as u64);
            // Each step introduces a new fragment
            let h = 0x1000u32.wrapping_add(step.wrapping_mul(7919)); // prime multiplier
            let present = step % 3 != 0; // every 3rd file has it absent

            let presences = vec![SmallVec::from_slice(&[present])];
            cache.merge_updates(vec![k], vec![m], &[h], presences).unwrap();
            ground_truth.push((k, m, h, present));

            // After every step, verify ALL ground truth entries
            for &(gk, gm, gh, gpresent) in &ground_truth {
                if gpresent {
                    assert!(
                        !cache.can_skip_file(gk, gm, &[gh]),
                        "false absent at step {step}: previously present fragment {gh:#x} \
                         became skippable"
                    );
                }
            }
        }
    }

    #[test]
    fn no_false_absent_same_file_updated_across_stride_boundary() {
        // The same file is updated multiple times, with the stride crossing
        // 64 between updates. The final present state must be respected.
        let mut cache = FragmentCache::new_in_memory(130, 64);
        let k = key(42);
        let m = meta(1, 1);

        // Round 1: register file with hash_a present (stride=1, num_frags < 64)
        let hash_a = 0xAAAA_u32;
        cache.merge_updates(
            vec![k], vec![m], &[hash_a],
            vec![SmallVec::from_slice(&[true])],
        ).unwrap();

        // Push num_fragments past 64 using other files
        for i in 0u32..65 {
            let fk = key(100 + i as u64);
            let fm = meta(i as i64, i as u64);
            let fh = 0xF000u32.wrapping_add(i);
            cache.merge_updates(
                vec![fk], vec![fm], &[fh],
                vec![SmallVec::from_slice(&[false])],
            ).unwrap();
        }

        // Now stride=2. Re-register the same file with hash_a still present
        let hash_b = 0xBBBB_u32;
        cache.merge_updates(
            vec![k], vec![m], &[hash_a, hash_b],
            vec![SmallVec::from_slice(&[true, true])],
        ).unwrap();

        assert!(!cache.can_skip_file(k, m, &[hash_a]),
                "false absent: hash_a present across stride boundary");
        assert!(!cache.can_skip_file(k, m, &[hash_b]),
                "false absent: hash_b present after stride boundary");
    }

    // ─── Proptest: exhaustive stride stress ───────────────────────────────────

    proptest! {
        #[test]
        fn prop_no_false_absent_stride_stress(
            num_files in 1usize..=20,
            // Drive num_fragments through multiple 64-boundaries
            num_rounds in 1usize..=6,
            frags_per_round in 10usize..=25,
            seed in any::<u64>(),
            // which files have their fragment present in each round
            present_mask in any::<u32>(),
        ) {
            let max_frags = num_rounds * frags_per_round + 4;
            let mut cache = FragmentCache::new_in_memory(max_frags, num_files + 100);

            let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(seed ^ i as u64)).collect();
            let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();

            // ground_truth[file_id][hash] = present
            let mut ground_truth: Vec<std::collections::HashMap<u32, bool>> =
                (0..num_files).map(|_| std::collections::HashMap::new()).collect();

            for round in 0..num_rounds {
                let hashes: Vec<u32> = (0..frags_per_round)
                    .map(|i| {
                        let v = seed
                            .wrapping_add(round as u64 * 10000)
                            .wrapping_add(i as u64);
                        v as u32
                    })
                    .collect();

                // Each file's presence is determined by its bit in present_mask
                let presences: Vec<SmallVec<[bool; 32]>> = (0..num_files)
                    .map(|fi| {
                        let present = (present_mask >> (fi % 32)) & 1 == 1;
                        hashes.iter().map(|_| present).collect()
                    })
                    .collect();

                cache.merge_updates(keys.clone(), metas.clone(), &hashes, presences).unwrap();

                for fi in 0..num_files {
                    let present = (present_mask >> (fi % 32)) & 1 == 1;
                    for &h in &hashes {
                        ground_truth[fi].insert(h, present);
                    }
                }

                // Verify after every round - catches corruption the moment it happens
                for fi in 0..num_files {
                    for (&h, &present) in &ground_truth[fi] {
                        if present {
                            prop_assert!(
                                !cache.can_skip_file(keys[fi], metas[fi], &[h]),
                                "false absent: round={round} file={fi} hash={h:#010x} \
                                 present but skipped (num_fragments may have crossed 64-boundary)"
                            );
                        }
                    }
                }
            }
        }

        #[test]
        fn prop_no_false_absent_dense_cross_boundary(
            // Force num_fragments to land exactly on multiples of 64
            files_before_boundary in 1usize..=8,
            files_after_boundary in 1usize..=8,
            seed in any::<u64>(),
        ) {
            // Fill exactly to 63 fragments, then add files with present fragments
            // that straddle the boundary (63, 64, 65)
            let max_frags = 130usize;
            let mut cache = FragmentCache::new_in_memory(max_frags, 200);

            // Fill 62 slots with absent filler
            for i in 0u32..62 {
                let fk = key(9000 + i as u64);
                let fm = meta(i as i64, i as u64);
                let fh = 0xDEAD_0000u32.wrapping_add(seed as u32).wrapping_add(i);
                cache.merge_updates(
                    vec![fk], vec![fm], &[fh],
                    vec![SmallVec::from_slice(&[false])],
                ).unwrap();
            }

            prop_assert_eq!(
                cache.num_fragments.load(Ordering::Relaxed) as usize, 62,
                "setup: expected 62 fragments"
            );

            // Register files_before_boundary files with a present hash at index 62
            let hash_62 = 0xB062u32.wrapping_add(seed as u32);
            let before_keys:  Vec<FileKey>  = (0..files_before_boundary).map(|i| key(200 + i as u64)).collect();
            let before_metas: Vec<FileMeta> = (0..files_before_boundary).map(|i| meta(200 + i as i64, 200)).collect();
            let before_presences: Vec<SmallVec<[bool; 32]>> =
                (0..files_before_boundary).map(|_| SmallVec::from_slice(&[true])).collect();
            cache.merge_updates(before_keys.clone(), before_metas.clone(), &[hash_62], before_presences).unwrap();

            // This pushes num_fragments to 63. Now add hash at index 63 (crosses u64 boundary)
            let hash_63 = 0xB063u32.wrapping_add(seed as u32);
            let after_keys:  Vec<FileKey>  = (0..files_after_boundary).map(|i| key(300 + i as u64)).collect();
            let after_metas: Vec<FileMeta> = (0..files_after_boundary).map(|i| meta(300 + i as i64, 300)).collect();
            let after_presences: Vec<SmallVec<[bool; 32]>> =
                (0..files_after_boundary).map(|_| SmallVec::from_slice(&[true])).collect();
            cache.merge_updates(after_keys.clone(), after_metas.clone(), &[hash_63], after_presences).unwrap();

            // Verify before-boundary files still not skippable on hash_62
            for fi in 0..files_before_boundary {
                prop_assert!(
                    !cache.can_skip_file(before_keys[fi], before_metas[fi], &[hash_62]),
                    "false absent: before-boundary file {fi} hash_62 present but skipped \
                     after stride crossed 64"
                );
            }

            // Verify after-boundary files not skippable on hash_63
            for fi in 0..files_after_boundary {
                prop_assert!(
                    !cache.can_skip_file(after_keys[fi], after_metas[fi], &[hash_63]),
                    "false absent: after-boundary file {fi} hash_63 present but skipped"
                );
            }
        }
    }

    // ─── False present: cache must correctly identify absent fragments ─────────

    #[test]
    fn absent_fragment_skips_correctly_basic() {
        let hash = 0xDEAD_BEEF_u32;
        let k = key(1);
        let m = meta(1, 1);

        let mut cache = FragmentCache::new_in_memory(64, 64);
        cache.merge_updates(
            vec![k], vec![m], &[hash],
            vec![SmallVec::from_slice(&[false])], // explicitly absent
        ).unwrap();

        assert!(cache.can_skip_file(k, m, &[hash]),
                "fragment is absent but cache failed to skip");
    }

    #[test]
    fn absent_verified_independently_for_each_file() {
        // 10 files. Odd-indexed have fragment absent, even-indexed have it present.
        // Verify each file independently.
        let hash = 0x1234_5678_u32;
        let num_files = 10usize;
        let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(i as u64)).collect();
        let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();
        let presences: Vec<SmallVec<[bool; 32]>> = (0..num_files)
            .map(|i| SmallVec::from_slice(&[i % 2 == 0])) // even=present, odd=absent
            .collect();

        let mut cache = FragmentCache::new_in_memory(64, 64);
        cache.merge_updates(keys.clone(), metas.clone(), &[hash], presences).unwrap();

        for i in 0..num_files {
            if i % 2 == 0 {
                assert!(!cache.can_skip_file(keys[i], metas[i], &[hash]),
                        "file {i}: present fragment falsely skipped");
            } else {
                assert!(cache.can_skip_file(keys[i], metas[i], &[hash]),
                        "file {i}: absent fragment not skipped");
            }
        }
    }

    #[test]
    fn absent_only_for_specific_fragment_not_others() {
        // File has [A=present, B=absent, C=present].
        // Must skip on B, must not skip on A or C.
        let hash_a = 0xAAAA_u32;
        let hash_b = 0xBBBB_u32;
        let hash_c = 0xCCCC_u32;
        let k = key(1);
        let m = meta(1, 1);

        let mut cache = FragmentCache::new_in_memory(64, 64);
        cache.merge_updates(
            vec![k], vec![m], &[hash_a, hash_b, hash_c],
            vec![SmallVec::from_slice(&[true, false, true])],
        ).unwrap();

        assert!(!cache.can_skip_file(k, m, &[hash_a]), "A is present, must not skip");
        assert!( cache.can_skip_file(k, m, &[hash_b]), "B is absent, must skip");
        assert!(!cache.can_skip_file(k, m, &[hash_c]), "C is present, must not skip");

        // Query with all three: B is absent so should skip
        assert!( cache.can_skip_file(k, m, &[hash_a, hash_b, hash_c]),
                 "B absent in multi-fragment query, must skip");

        // Query with only present fragments: must not skip
        assert!(!cache.can_skip_file(k, m, &[hash_a, hash_c]),
                "all queried fragments present, must not skip");
    }

    #[test]
    fn absent_bits_survive_capacity_growth() {
        // Insert many files with absent fragments, force capacity growth,
        // verify all absent bits are still intact.
        let mut cache = FragmentCache::new_in_memory(32, 8); // small initial capacity

        let hash = 0xABCD_u32;
        let num_files = 300usize;
        let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(i as u64)).collect();
        let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();
        // All absent
        let presences: Vec<SmallVec<[bool; 32]>> =
            (0..num_files).map(|_| SmallVec::from_slice(&[false])).collect();

        cache.merge_updates(keys.clone(), metas.clone(), &[hash], presences).unwrap();

        for i in 0..num_files {
            assert!(cache.can_skip_file(keys[i], metas[i], &[hash]),
                    "file {i}: absent bit lost after capacity growth");
        }
    }

    #[test]
    fn absent_bits_survive_stride_boundary_crossing() {
        // Files registered as absent before the 64-fragment boundary
        // must still be skippable after the boundary is crossed.
        let mut cache = FragmentCache::new_in_memory(130, 64);

        let hash = 0x4853_0000_u32;  // this file has fragment absent
        let k = key(1);
        let m = meta(1, 1);

        cache.merge_updates(
            vec![k], vec![m], &[hash],
            vec![SmallVec::from_slice(&[false])],
        ).unwrap();

        assert!(cache.can_skip_file(k, m, &[hash]), "absent before boundary crossing");

        // Push past 64-fragment boundary
        for i in 0u32..70 {
            let fk = key(100 + i as u64);
            let fm = meta(i as i64, i as u64);
            let fh = 0xF000_0000u32.wrapping_add(i);
            cache.merge_updates(
                vec![fk], vec![fm], &[fh],
                vec![SmallVec::from_slice(&[false])],
            ).unwrap();
        }

        assert!(cache.can_skip_file(k, m, &[hash]),
                "absent bit lost after stride crossed 64-fragment boundary");
    }

    #[test]
    fn absent_bits_correct_at_each_u64_boundary_position() {
        // For fragment indices 0, 63, 64, 127, 128 - the boundary positions -
        // verify absent bits are set and read correctly.
        let boundary_indices = [0usize, 62, 63, 64, 65, 126, 127];
        let max_frags = 130;

        for &target_idx in &boundary_indices {
            let mut cache = FragmentCache::new_in_memory(max_frags, 32);
            let k = key(target_idx as u64);
            let m = meta(target_idx as i64, target_idx as u64);

            // Fill fragments up to target_idx with absent filler (different files)
            for i in 0u32..target_idx as u32 {
                let fk = key(1000 + target_idx as u64 * 200 + i as u64);
                let fm = meta(i as i64, i as u64);
                let fh = 0xF100_0000u32
                    .wrapping_add(target_idx as u32 * 1000)
                    .wrapping_add(i);
                cache.merge_updates(
                    vec![fk], vec![fm], &[fh],
                    vec![SmallVec::from_slice(&[false])],
                ).unwrap();
            }

            // Now add the target fragment as ABSENT for our file
            let target_hash = 0x7670_0000u32
                .wrapping_add(target_idx as u32);
            cache.merge_updates(
                vec![k], vec![m], &[target_hash],
                vec![SmallVec::from_slice(&[false])],
            ).unwrap();

            assert!(
                cache.can_skip_file(k, m, &[target_hash]),
                "absent bit wrong at fragment index {target_idx} (u64 boundary position)"
            );
        }
    }

    #[test]
    fn absent_preserved_after_same_file_re_registered() {
        // File is registered absent, then re-registered with same meta.
        // Must still be skippable.
        let hash = 0x9999_u32;
        let k = key(7);
        let m = meta(42, 42);

        let mut cache = FragmentCache::new_in_memory(64, 64);

        cache.merge_updates(
            vec![k], vec![m], &[hash],
            vec![SmallVec::from_slice(&[false])],
        ).unwrap();

        assert!(cache.can_skip_file(k, m, &[hash]), "absent after first registration");

        // Re-register same file, same meta, same fragment absent
        cache.merge_updates(
            vec![k], vec![m], &[hash],
            vec![SmallVec::from_slice(&[false])],
        ).unwrap();

        assert!(cache.can_skip_file(k, m, &[hash]),
                "absent bit cleared after re-registration of same file");
    }

    #[test]
    fn absent_not_confused_between_adjacent_files() {
        // File A has fragment absent. File B (adjacent in storage) has it present.
        // Must not mix up their bits.
        let hash = 0x5555_5555_u32;
        let ka = key(0);
        let kb = key(1);
        let ma = meta(1, 1);
        let mb = meta(2, 2);

        let mut cache = FragmentCache::new_in_memory(64, 64);
        cache.merge_updates(
            vec![ka, kb], vec![ma, mb], &[hash],
            vec![
                SmallVec::from_slice(&[false]), // A: absent
                SmallVec::from_slice(&[true]),  // B: present
            ],
        ).unwrap();

        assert!( cache.can_skip_file(ka, ma, &[hash]), "file A: absent, must skip");
        assert!(!cache.can_skip_file(kb, mb, &[hash]), "file B: present, must not skip");
    }

    #[test]
    fn absent_not_confused_between_adjacent_fragments() {
        // Fragment at index N is absent, N-1 and N+1 are present.
        // Must only skip on N.
        let hash_prev = 0x0001_u32;
        let hash_mid  = 0x0002_u32;
        let hash_next = 0x0003_u32;
        let k = key(1);
        let m = meta(1, 1);

        let mut cache = FragmentCache::new_in_memory(64, 64);
        cache.merge_updates(
            vec![k], vec![m], &[hash_prev, hash_mid, hash_next],
            vec![SmallVec::from_slice(&[true, false, true])], // mid absent
        ).unwrap();

        assert!(!cache.can_skip_file(k, m, &[hash_prev]), "prev present, must not skip");
        assert!( cache.can_skip_file(k, m, &[hash_mid]),  "mid absent, must skip");
        assert!(!cache.can_skip_file(k, m, &[hash_next]), "next present, must not skip");
    }

    // ─── Proptest: absent correctness ─────────────────────────────────────────

    proptest! {
        #[test]
        fn prop_absent_bits_survive_everything(
            num_files  in 1usize..=30,
            num_frags  in 1usize..=80, // deliberately crosses 64-boundary
            seed       in any::<u64>(),
            absent_mask in any::<u64>(), // bit fi*num_frags+fr = absent if 1
        ) {
            let mut cache = FragmentCache::new_in_memory(num_frags + 4, num_files + 4);

            let hashes: Vec<u32> = (0..num_frags)
                .map(|i| (seed as u32).wrapping_add(i as u32).wrapping_mul(0x9e37_9769))
                .collect();
            let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(seed ^ (i as u64 * 0x1111))).collect();
            let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();

            // Build presence: absent_mask bit (fi + fr) % 64 drives absence
            let presence_table: Vec<Vec<bool>> = (0..num_files)
                .map(|fi| (0..num_frags)
                     .map(|fr| (absent_mask >> ((fi * num_frags + fr) % 64)) & 1 == 0)
                     .collect())
                .collect();

            let presences: Vec<SmallVec<[bool; 32]>> = presence_table.iter()
                .map(|p| p.iter().copied().collect())
                .collect();

            cache.merge_updates(keys.clone(), metas.clone(), &hashes, presences).unwrap();

            for fi in 0..num_files {
                for fr in 0..num_frags {
                    let absent  = !presence_table[fi][fr];
                    let skipped = cache.can_skip_file(keys[fi], metas[fi], &[hashes[fr]]);
                    if absent {
                        prop_assert!(skipped,
                                     "false present: file={fi} frag={fr} absent but can_skip=false \
                                      (missed skip opportunity - could cause missed matches if inverted)");
                    } else {
                        prop_assert!(!skipped,
                                     "false absent: file={fi} frag={fr} present but can_skip=true \
                                      (correctness bug - matches would be missed)");
                    }
                }
            }
        }

        #[test]
        fn prop_absent_bits_survive_stride_crossings(
            rounds in 2usize..=8,
            frags_per_round in 8usize..=20,
            num_files in 1usize..=16,
            seed in any::<u64>(),
        ) {
            let max_frags = rounds * frags_per_round + 4;
            let mut cache = FragmentCache::new_in_memory(max_frags, num_files + 4);

            let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(seed ^ i as u64)).collect();
            let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();

            // ground truth: (file_id, hash) -> absent
            let mut ground_truth: Vec<(usize, u32, bool)> = Vec::new();

            for round in 0..rounds {
                let hashes: Vec<u32> = (0..frags_per_round)
                    .map(|i| (seed as u32)
                         .wrapping_add(round as u32 * 10000)
                         .wrapping_add(i as u32)
                         .wrapping_mul(0x517c_c1b7))
                    .collect();

                // Alternate absent/present per file based on round parity
                let presences: Vec<SmallVec<[bool; 32]>> = (0..num_files)
                    .map(|fi| {
                        let present = (round + fi) % 2 == 0;
                        hashes.iter().map(|_| present).collect()
                    })
                    .collect();

                cache.merge_updates(keys.clone(), metas.clone(), &hashes, presences).unwrap();

                for fi in 0..num_files {
                    let present = (round + fi) % 2 == 0;
                    for &h in &hashes {
                        ground_truth.push((fi, h, !present)); // absent = !present
                    }
                }

                // Verify after every round
                for &(fi, h, absent) in &ground_truth {
                    let skipped = cache.can_skip_file(keys[fi], metas[fi], &[h]);
                    if absent {
                        prop_assert!(skipped,
                                     "round={round} file={fi} hash={h:#x}: absent but not skipped");
                    } else {
                        prop_assert!(!skipped,
                                     "round={round} file={fi} hash={h:#x}: present but skipped");
                    }
                }
            }
        }
    }
}
