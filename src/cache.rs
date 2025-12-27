use crate::util::{likely, unlikely};

use std::io;
use std::fs::File;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use memmap2::Mmap;
use rkyv::with::AsVec;
use serde::{Serialize, Deserialize};
use rkyv::{Archive, Serialize as RkyvSerialize, Deserialize as RkyvDeserialize};

const FILE_LOOKUP_EMPTY: u32 = u32::MAX;

/// Uniquely identifies a file across reboots
#[repr(C, align(16))]
#[derive(Archive, RkyvSerialize, RkyvDeserialize)]
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
#[derive(Archive, RkyvSerialize, RkyvDeserialize)]
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

#[derive(Deserialize)]
#[derive(Archive, RkyvDeserialize)]
struct CacheOnDisk {
    fragments: Vec<u32>,
    ring_pos: usize,
    file_keys: Vec<FileKey>,
    file_metas: Vec<FileMeta>,
    file_bitsets: Vec<u64>,
    num_fragments: usize,
}

#[derive(Archive, RkyvSerialize)]
struct CacheOnDiskView<'a> {
    #[rkyv(with = AsVec)]
    fragments: &'a [u32],

    ring_pos: usize,

    #[rkyv(with = AsVec)]
    file_keys: &'a [FileKey],

    #[rkyv(with = AsVec)]
    file_metas: &'a [FileMeta],

    #[rkyv(with = AsVec)]
    file_bitsets: &'a [u64],

    num_fragments: usize,
}

/// Core Fragment cache
#[repr(C, align(64))]
pub struct FragmentCache {
    num_fragments: AtomicU32,
    num_files: AtomicU32,
    ring_pos: AtomicU32,
    max_fragments: u32,
    max_files: u32,

    // Fragment ring , immutable during search
    fragment_hashes: Box<[u32]>, // hash of 4-byte fragment

    // -------- File data indexed by file_id , immutable during search
    file_keys: Box<[FileKey]>,
    file_metas: Box<[FileMeta]>, // for cache invalidation
    file_bitsets: Box<[u64]>, // flattened bitsets: file_id * num_fragments_in_u64 + bit_idx

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

        let fragment_hashes = Box::<[u32]>::new_uninit_slice(config.max_fragments);
        let file_keys = Box::<[FileKey]>::new_uninit_slice(config.max_files);
        let file_metas = Box::<[FileMeta]>::new_uninit_slice(config.max_files);

        let fragment_hashes = unsafe { fragment_hashes.assume_init() };
        let file_keys = unsafe { file_keys.assume_init() };
        let file_metas = unsafe { file_metas.assume_init() };

        // ------ Bitsets: each file has max_fragments bits, packed into u64s
        // default to all 1s (all fragments absent until proven present)
        let bits_per_file = config.max_fragments.div_ceil(64) * 64; // round up to u64 boundary
        let total_u64s = config.max_files * (bits_per_file / 64);
        let file_bitsets = vec![!0u64; total_u64s].into_boxed_slice();

        // ------ File lookup: 2x size for load factor 0.5
        let lookup_size = (config.max_files * 2).next_power_of_two();
        let file_lookup: Box<[AtomicU32]> = (0..lookup_size)
            .map(|_| AtomicU32::new(FILE_LOOKUP_EMPTY))
            .collect();

        Ok(Self {
            num_fragments: AtomicU32::new(0),
            num_files: AtomicU32::new(0),
            ring_pos: AtomicU32::new(0),
            max_fragments,
            max_files,
            fragment_hashes,
            file_keys,
            file_metas,
            file_bitsets,
            file_lookup,
            stats: CacheStats::default(),
            cache_path,
        })
    }

    fn load_from_disk(path: &Path, config: &CacheConfig) -> io::Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        let cached = unsafe {
            rkyv::access_unchecked::<ArchivedCacheOnDisk>(&mmap[..])
        };

        let num_fragments = cached.fragments.len().min(config.max_fragments);
        let num_files = cached.file_keys.len().min(config.max_files);

        let mut fragment_hashes = Box::<[u32]>::new_uninit_slice(config.max_fragments);
        let mut file_keys = Box::<[FileKey]>::new_uninit_slice(config.max_files);
        let mut file_metas = Box::<[FileMeta]>::new_uninit_slice(config.max_files);

        let bits_per_file = config.max_fragments.div_ceil(64) * 64;
        let total_u64s = config.max_files * (bits_per_file / 64);
        let mut file_bitsets = Box::<[u64]>::new_uninit_slice(total_u64s);

        unsafe {
            std::ptr::copy_nonoverlapping(
                cached.fragments.as_ptr() as *const u32,
                fragment_hashes.as_mut_ptr() as *mut u32,
                num_fragments
            );

            std::ptr::copy_nonoverlapping(
                cached.file_keys.as_ptr() as *const FileKey,
                file_keys.as_mut_ptr() as *mut FileKey,
                num_files
            );

            std::ptr::copy_nonoverlapping(
                cached.file_metas.as_ptr() as *const FileMeta,
                file_metas.as_mut_ptr() as *mut FileMeta,
                num_files
            );

            std::ptr::copy_nonoverlapping(
                cached.file_bitsets.as_ptr() as *const u64,
                file_bitsets.as_mut_ptr() as *mut u64,
                cached.file_bitsets.len().min(total_u64s)
            );

            // zero init the unused portions
            std::ptr::write_bytes(
                fragment_hashes.as_mut_ptr().add(num_fragments) as *mut u32,
                0,
                config.max_fragments - num_fragments
            );

            std::ptr::write_bytes(
                file_keys.as_mut_ptr().add(num_files) as *mut FileKey,
                0,
                config.max_files - num_files
            );

            std::ptr::write_bytes(
                file_metas.as_mut_ptr().add(num_files) as *mut FileMeta,
                0,
                config.max_files - num_files
            );

            // fill unused stuff with !0 - all fragments absent
            let used_bitsets = cached.file_bitsets.len().min(total_u64s);
            for i in used_bitsets..total_u64s {
                file_bitsets.as_mut_ptr().add(i).write(MaybeUninit::new(!0u64));
            }
        }

        let fragment_hashes = unsafe { fragment_hashes.assume_init() };
        let file_keys = unsafe { file_keys.assume_init() };
        let file_metas = unsafe { file_metas.assume_init() };
        let file_bitsets = unsafe { file_bitsets.assume_init() };

        // --------- Build the tableeeeeee
        let lookup_size = (config.max_files * 2).next_power_of_two();
        let file_lookup: Box<[AtomicU32]> = (0..lookup_size)
            .map(|_| AtomicU32::new(FILE_LOOKUP_EMPTY))
            .collect();

        for file_id in 0..num_files {
            let file_key = file_keys[file_id];
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

        Ok(Self {
            num_fragments: AtomicU32::new(num_fragments as u32),
            num_files: AtomicU32::new(num_files as u32),
            ring_pos: AtomicU32::new(cached.ring_pos.to_native() as u32),
            max_fragments: config.max_fragments as u32,
            max_files: config.max_files as u32,
            fragment_hashes,
            file_keys,
            file_metas,
            file_bitsets,
            file_lookup,
            stats: CacheStats::default(),
            cache_path: path.to_path_buf(),
        })
    }

    #[inline]
    pub fn save_to_disk(&self) -> io::Result<()> {
        let start = std::time::Instant::now();
        let num_fragments = self.num_fragments.load(Ordering::Relaxed) as usize;
        let num_files = self.num_files.load(Ordering::Relaxed) as usize;

        let data = CacheOnDiskView {
            fragments: &self.fragment_hashes[..num_fragments],
            ring_pos: self.ring_pos.load(Ordering::Relaxed) as usize,
            file_keys: &self.file_keys[..num_files],
            file_metas: &self.file_metas[..num_files],
            file_bitsets: {
                let bits_per_file = num_fragments.div_ceil(64) * 64;
                let total_u64s = num_files * (bits_per_file / 64);
                &self.file_bitsets[..total_u64s]
            },
            num_fragments,
        };

        let serialize_start = std::time::Instant::now();
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&data)
            .map_err(|e| io::Error::other(e.to_string()))?;

        let serialize_time = serialize_start.elapsed();

        let temp_path = self.cache_path.with_extension("tmp");
        std::fs::write(&temp_path, &bytes)?;
        Self::fix_ownership(&temp_path)?;

        std::fs::rename(&temp_path, &self.cache_path)?;
        Self::fix_ownership(&self.cache_path)?;

        let total_time = start.elapsed();
        eprintln!(
            "Cache saved: {} files, {} fragments in {:.2}ms (serialize: {:.2}ms)",
            num_files, num_fragments,
            total_time.as_secs_f64() * 1000.0,
            serialize_time.as_secs_f64() * 1000.0
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
        // ----- Fast path
        let Some(file_id) = self.lookup_file_id(file_key) else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            return false;
        };

        // ------- Validate metadata
        if unlikely(!self.file_metas[file_id as usize].matches(file_meta)) {
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

            //
            // SAFETY: u64_idx is guaranteed to be in bounds because:
            // - offset = file_id * bits_per_file_u64
            // - frag_idx < num_fragments
            // - file_bitsets size = max_files * bits_per_file_u64
            // Thus u64_idx = file_id * bits_per_file_u64 + frag_idx/64 < file_bitsets.len()
            //
            let is_absent = unsafe {
                (*self.file_bitsets.get_unchecked(u64_idx) & (1u64 << bit_idx)) != 0
            };

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
        (0..num_fragments).find(|&i| unsafe {
            *self.fragment_hashes.get_unchecked(i)
        } == frag_hash)
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

            if self.file_keys[file_id as usize] == file_key {
                return Some(file_id);
            }

            idx = (idx + 1) & mask;
        }

        None
    }

    /// Merge thread-local cache buffers into cache (called once after all workers finish)
    pub fn merge_updates(
        &mut self,
        file_keys: Vec<FileKey>,
        file_metas: Vec<FileMeta>,
        fragment_hashes: &[u32],
        had_matches: Vec<bool>,
    ) -> io::Result<()> {
        if file_keys.is_empty() {
            return Ok(());
        }

        let start = std::time::Instant::now();

        //
        //
        // Add all files and collect fragment data
        //
        //

        let mut file_updates = Vec::with_capacity(file_keys.len());

        for i in 0..file_keys.len() {
            let file_key = file_keys[i];
            let file_meta = file_metas[i];
            let matched = had_matches[i];
            let num_files = self.num_files.load(Ordering::Relaxed) as usize;
            if num_files >= self.max_files as usize {
                break; // cache full
            }

            // --------- Find or insert file
            let file_id = self.lookup_file_id(file_key).map(|id| id as _).unwrap_or_else(|| {
                let new_file_id = num_files;
                self.num_files.store((num_files + 1) as u32, Ordering::Relaxed);
                self.file_keys[new_file_id] = file_key;
                self.file_metas[new_file_id] = file_meta;
                self.insert_into_lookup(file_key, new_file_id as u32);
                new_file_id
            });

            // --------- Update metadata
            self.file_metas[file_id] = file_meta;


            // --------- Add fragments and collect indices
            //
            // Limit to 100 fragments per file
            //
            // @Constant @Tune
            let mut fragment_indices = Vec::with_capacity(fragment_hashes.len().min(100));
            for &frag_hash in fragment_hashes.iter().take(100) {
                let frag_idx = self.add_fragment(frag_hash);
                fragment_indices.push(frag_idx);
            }

            file_updates.push((file_id, fragment_indices, matched));
        }

        //
        //
        // Update all bitsets
        //
        //

        let num_fragments = self.num_fragments.load(Ordering::Relaxed) as usize;
        let bits_per_file_u64 = num_fragments.div_ceil(64);

        for (file_id, fragment_indices, matched) in file_updates {
            let offset = file_id * bits_per_file_u64;

            for frag_idx in fragment_indices {
                let u64_idx = offset + (frag_idx / 64);
                let bit_idx = frag_idx % 64;
                if u64_idx < self.file_bitsets.len() {
                    if matched {
                        // Fragment PRESENT - clear bit (bit=0)
                        self.file_bitsets[u64_idx] &= !(1u64 << bit_idx);
                    } else {
                        // Fragment ABSENT - set bit (bit=1)
                        self.file_bitsets[u64_idx] |= 1u64 << bit_idx;
                    }
                }
            }
        }

        let elapsed = start.elapsed();
        eprintln!("Cache updated: {} files in {:.2}ms", file_keys.len(), elapsed.as_secs_f64() * 1000.0);

        Ok(())
    }

    /// Add pattern fragment to cache (called during initialization)
    pub fn add_pattern_fragment(&mut self, frag_hash: u32) {
        self.add_fragment(frag_hash);
    }

    /// Add fragment to ring buffer (returns index)
    fn add_fragment(&mut self, frag_hash: u32) -> usize {
        if let Some(idx) = self.find_fragment_index(frag_hash) {
            return idx;
        }

        let num_fragments = self.num_fragments.load(Ordering::Relaxed) as usize;

        if num_fragments < self.max_fragments as usize {
            // ------- Ring buffer is not full
            let idx = num_fragments;
            self.fragment_hashes[idx] = frag_hash;
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
                if bitset_idx < self.file_bitsets.len() {
                    // clear the bit
                    self.file_bitsets[bitset_idx] &= !(1u64 << bit_idx);
                }
            }

            idx
        } else {
            // ------- Ring buffer is full
            // evict oldest (FIFO)

            let ring_pos = self.ring_pos.load(Ordering::Relaxed) as usize;
            let idx = ring_pos;

            self.fragment_hashes[idx] = frag_hash;

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

        let fragments_size = num_fragments * std::mem::size_of::<u32>();
        let file_keys_size = num_files * std::mem::size_of::<FileKey>();
        let file_metas_size = num_files * std::mem::size_of::<FileMeta>();

        let bits_per_file = num_fragments.div_ceil(64) * 64;
        let file_bitsets_size = num_files * (bits_per_file / 8);

        let lookup_size = self.file_lookup.len() * std::mem::size_of::<AtomicU32>();

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
