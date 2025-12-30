use crate::util::{likely, unlikely};

use std::fs::File;
use std::time::Instant;
use std::io::{self, Write};
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

/// Core Fragment cache
#[repr(C, align(64))]
pub struct FragmentCache {
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

    cache_path: PathBuf,
}

impl FragmentCache {
    /// Create new or load existing cache
    #[inline]
    pub fn new(config: &CacheConfig) -> io::Result<Self> {
        let cache_path = Self::get_cache_path(&config.cache_dir)?;

        if cache_path.exists() && !config.ignore_cache {
            if let Ok(cache) = Self::load_from_disk(&cache_path, config) {
                return Ok(cache);
            }
        }

        Self::create_empty(config, cache_path)
    }

    fn create_empty(config: &CacheConfig, cache_path: PathBuf) -> io::Result<Self> {
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

        // Start with small bitset allocation
        let bits_per_file_u64 = config.max_fragments.div_ceil(64);
        let initial_bitset_u64s = INITIAL_CAPACITY * bits_per_file_u64;
        let owned_file_bitsets = vec![!0u64; initial_bitset_u64s].into_boxed_slice();

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
            cache_path,
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

        // allocate with growth headroom
        let new_capacity = (num_files * 4).max(64 * 1024).min(self.max_files as usize);

        let alloc_start = Instant::now();
        let mut new_fragment_hashes = Box::<[u32]>::new_uninit_slice(self.max_fragments as usize);
        let mut new_file_keys = Box::<[FileKey]>::new_uninit_slice(new_capacity);
        let mut new_file_metas = Box::<[FileMeta]>::new_uninit_slice(new_capacity);

        let bits_per_file_u64 = (self.max_fragments as usize).div_ceil(64);
        let total_u64s = new_capacity * bits_per_file_u64;
        let used_u64s = num_files * bits_per_file_u64;

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
            // copy used bitsets from mmap
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
        let new_capacity = (needed * 4).min(self.max_files as usize);
        if new_capacity <= self.file_capacity {
            return; // at max capacity already
        }

        let num_files = self.num_files.load(Ordering::Relaxed) as usize;
        let bits_per_file_u64 = (self.max_fragments as usize).div_ceil(64);

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
                old_u64s,
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

    fn load_from_disk(path: &Path, config: &CacheConfig) -> io::Result<Self> {
        let start = Instant::now();

        let file = File::open(path)?;
        let file_open_time = start.elapsed();

        //
        //
        // Eagerly fault in all pages
        //
        //
        let mmap = unsafe {
            memmap2::MmapOptions::new().populate().map(&file)?
        };

        let mmap_time = start.elapsed();

        if mmap.len() < size_of::<CacheHeader>() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "cache file too small"));
        }

        let header = unsafe { &*(mmap.as_ptr() as *const CacheHeader) };

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

        // ---------- Validate file size
        let expected_size = file_bitsets_offset + file_bitsets_len * size_of::<u64>();
        if mmap.len() < expected_size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "cache file truncated"));
        }

        // Create pointers to point into mmap
        // SAFETY: mmap is valid, properly aligned, and kept alive by _mmap field
        let fragment_hashes = unsafe {
            let ptr = mmap.as_ptr().add(fragments_offset) as *const u32;
            FatPtr::from_raw(ptr, num_fragments)
        };
        let file_keys = unsafe {
            let ptr = mmap.as_ptr().add(file_keys_offset) as *const FileKey;
            FatPtr::from_raw(ptr, num_files)
        };
        let file_metas = unsafe {
            let ptr = mmap.as_ptr().add(file_metas_offset) as *const FileMeta;
            FatPtr::from_raw(ptr, num_files)
        };
        let file_bitsets = unsafe {
            let ptr = mmap.as_ptr().add(file_bitsets_offset) as *const u64;
            FatPtr::from_raw(ptr, file_bitsets_len)
        };

        // ----------- Build the lookup table
        let lookup_alloc_start = Instant::now();
        let lookup_size = ((num_files * 2).max(1024)).next_power_of_two();
        let mut file_lookup = Box::<[AtomicU32]>::new_uninit_slice(lookup_size);
        unsafe {
            std::ptr::write_bytes(file_lookup.as_mut_ptr(), FILE_LOOKUP_EMPTY as u8, lookup_size);
        }
        let file_lookup: Box<[AtomicU32]> = unsafe { file_lookup.assume_init() };
        let lookup_alloc_time = lookup_alloc_start.elapsed();

        let lookup_build_start = Instant::now();
        for file_id in 0..num_files {
            let file_key = file_keys.get(file_id);

            let hash = file_key.hash();
            let mask = file_lookup.len() - 1;
            let mut idx = (hash as usize) & mask;

            for _ in 0..16 {
                let existing = file_lookup[idx].load(Ordering::Relaxed);
                if existing == FILE_LOOKUP_EMPTY {
                    file_lookup[idx].store(file_id as u32, Ordering::Relaxed);
                    break;
                }
                idx = (idx + 1) & mask;
            }
        }
        let lookup_build_time = lookup_build_start.elapsed();

        let total_time = start.elapsed();
        eprintln!(
            "Cache loaded: {} files, {} fragments, {:.2}MB in {:.2}ms (open: {:.2}ms, mmap+populate: {:.2}ms, lookup_alloc: {:.2}ms, lookup_build: {:.2}ms)",
            num_files,
            num_fragments,
            mmap.len() as f64 / (1024.0 * 1024.0),
            total_time.as_secs_f64() * 1000.0,
            file_open_time.as_secs_f64() * 1000.0,
            (mmap_time - file_open_time).as_secs_f64() * 1000.0,
            lookup_alloc_time.as_secs_f64() * 1000.0,
            lookup_build_time.as_secs_f64() * 1000.0,
        );

        Ok(Self {
            num_fragments: AtomicU32::new(num_fragments as u32),
            num_files: AtomicU32::new(num_files as u32),
            ring_pos: AtomicU32::new(header.ring_pos),
            max_fragments: config.max_fragments as u32,
            max_files: config.max_files as u32,
            file_capacity: num_files, // mmap provides exactly num_files capacity
            fragment_hashes,
            file_keys,
            file_metas,
            file_bitsets,
            owned_fragment_hashes: None,
            owned_file_keys: None,
            owned_file_metas: None,
            owned_file_bitsets: None,
            _mmap: Some(mmap),
            file_lookup,
            stats: CacheStats::default(),
            cache_path: path.to_path_buf(),
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
        let header = CacheHeader {
            magic: CACHE_MAGIC,
            num_fragments: num_fragments as u32,
            num_files: num_files as u32,
            ring_pos: self.ring_pos.load(Ordering::Relaxed),
            _padding: 0,
        };
        let header_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(&header as *const CacheHeader as *const u8, header_size)
        };
        let fragments_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(self.fragment_hashes.ptr as *const u8, fragments_size)
        };
        let file_keys_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(self.file_keys.ptr as *const u8, file_keys_size)
        };
        let file_metas_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(self.file_metas.ptr as *const u8, file_metas_size)
        };
        let file_bitsets_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(self.file_bitsets.ptr as *const u8, file_bitsets_size)
        };

        // ------- Padding bytes
        let pad1 = [0u8; 16];
        let pad2 = [0u8; 8];

        let temp_path = self.cache_path.with_extension("tmp");
        let total_size = header_size +
            fragments_size +
            pad1_size +
            file_keys_size +
            file_metas_size +
            pad2_size +
            file_bitsets_size;

        let mut file = File::create(&temp_path)?;
        file.set_len(total_size as u64)?;

        file.write_all(header_bytes)?;
        file.write_all(fragments_bytes)?;
        if pad1_size > 0 {
            file.write_all(&pad1[..pad1_size])?;
        }
        file.write_all(file_keys_bytes)?;
        file.write_all(file_metas_bytes)?;
        if pad2_size > 0 {
            file.write_all(&pad2[..pad2_size])?;
        }
        file.write_all(file_bitsets_bytes)?;
        drop(file);

        Self::fix_ownership(&temp_path)?;
        std::fs::rename(&temp_path, &self.cache_path)?;
        Self::fix_ownership(&self.cache_path)?;

        let total_time = start.elapsed();
        eprintln!(
            "Cache saved: {} files, {} fragments, {:.2}MB in {:.2}ms",
            num_files, num_fragments,
            total_size as f64 / (1024.0 * 1024.0),
            total_time.as_secs_f64() * 1000.0,
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

        let bits_per_file_u64 = (num_fragments + 63) >> 6; // How many u64s per file

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

                    // Use raw pointer writes to avoid borrow issues
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
        let bits_per_file_u64 = num_fragments.div_ceil(64);
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

        let owned_fragment_hashes = self.owned_fragment_hashes.as_mut().unwrap();
        let owned_file_bitsets = self.owned_file_bitsets.as_mut().unwrap();

        let num_fragments = self.num_fragments.load(Ordering::Relaxed) as usize;

        if num_fragments < self.max_fragments as usize {
            // ------- Ring buffer is not full
            let idx = num_fragments;
            owned_fragment_hashes[idx] = frag_hash;
            self.num_fragments.store((num_fragments + 1) as u32, Ordering::Relaxed);

            //
            //
            // Clear this fragment bit for ALL existing files
            // New fragments are "unknown" for existing files and we MUST check them
            //
            //

            let num_files = self.num_files.load(Ordering::Relaxed) as usize;
            let bits_per_file_u64 = (num_fragments + 64) / 64;
            let u64_offset = idx / 64;
            let bit_idx = idx % 64;

            for file_id in 0..num_files {
                let bitset_idx = file_id * bits_per_file_u64 + u64_offset;
                if bitset_idx < owned_file_bitsets.len() {
                    // clear the bit
                    owned_file_bitsets[bitset_idx] &= !(1u64 << bit_idx);
                }
            }

            idx
        } else {
            // ------- Ring buffer is full
            // evict oldest (FIFO)

            let ring_pos = self.ring_pos.load(Ordering::Relaxed) as usize;
            let idx = ring_pos;

            owned_fragment_hashes[idx] = frag_hash;

            let next_pos = (ring_pos + 1) % (self.max_fragments as usize);
            self.ring_pos.store(next_pos as u32, Ordering::Relaxed);

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
