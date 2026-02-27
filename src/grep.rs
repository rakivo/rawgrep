use std::sync::Arc;
use std::io::{self, BufWriter};
use std::fs::{File, OpenOptions};
use std::sync::atomic::{AtomicBool, AtomicUsize};

use crossbeam_channel::unbounded;
use crossbeam_deque::{Injector, Worker as DequeWorker};

use crate::apfs::{ApfsFs, ApfsVolume, APFS_NX_MAGIC};
use crate::cli::Cli;
use crate::matcher::Matcher;
use crate::{eprintln_red, tracy};
use crate::path_buf::SmallPathBuf;
use crate::stats::{AtomicStats, Stats};
use crate::platform::device_id;
use crate::ignore::{Gitignore, GitignoreChain};
use crate::cache::{CacheConfig, FragmentCache};
use crate::parser::{BufKind, FileId, FileNode, Parser, RawFs};
use crate::worker::{DirWork, OutputWorker, WorkItem, WorkerContext, WorkerResult};
use crate::ext4::{
    Ext4Fs,
    EXT4_MAGIC_OFFSET,
    EXT4_SUPERBLOCK_OFFSET,
    EXT4_SUPERBLOCK_SIZE,
    EXT4_SUPER_MAGIC,
};

pub struct RawGrepper<'a, F: RawFs> {
    cli: &'a Cli,
    fs: F,
    matcher: Matcher,
    cache: Option<FragmentCache>,
    fragment_hashes: Vec<u32>,
}

/// impl block for generic RawFs
impl<'a, F: RawFs> RawGrepper<'a, F> {
    pub fn new_with_fs(cli: &'a Cli, fs: F) -> io::Result<Self> {
        let matcher = create_matcher_or_exit(cli);
        let fragment_hashes = matcher.extract_fragment_hashes();

        let cache = if !cli.no_cache && !fragment_hashes.is_empty() {
            let mut config = CacheConfig::from_memory_mb(cli.cache_size_mb);
            config.cache_dir = cli.cache_dir.clone();
            config.ignore_cache = cli.rebuild_cache;

            match FragmentCache::new(&config) {
                Ok(mut cache) => {
                    for &frag_hash in &fragment_hashes {
                        cache.add_pattern_fragment(frag_hash);
                    }

                    Some(cache)
                }
                Err(e) => {
                    eprintln!("Warning: Failed to initialize cache: {e}");
                    None
                }
            }
        } else {
            None
        };

        Ok(RawGrepper { cli, fs, matcher, cache, fragment_hashes })
    }

    pub fn search(
        mut self,
        root_file_id: FileId,
        running: &AtomicBool,
        root_gi: Option<Gitignore>,
    ) -> io::Result<Stats> {
        let fs = &self.fs;
        let matcher = &self.matcher;
        let stats = &AtomicStats::new();

        let active_workers = &AtomicUsize::new(0);

        let (output_tx, output_rx) = unbounded();

        let injector = &Injector::new();
        injector.push(WorkItem::Directory(DirWork {
            file_id: root_file_id,
            path_bytes: Arc::default(),
            gitignore_chain: root_gi.map(GitignoreChain::from_root).unwrap_or_default(),
            depth: 0,
        }));

        let threads = self.cli.threads.get();

        let workers = (0..threads)
            .map(|_| DequeWorker::new_lifo())
            .collect::<Vec<_>>();

        let stealers = workers
            .iter()
            .map(|w| w.stealer())
            .collect::<Vec<_>>();

        self.warmup_filesystem();

        let num_cores = num_physical_cores_or(threads);

        let (all_file_keys, all_file_metas, all_fragment_presence) = std::thread::scope(|s| {
            let output_handle = s.spawn(move || {
                //
                // Pin output thread to last core (often an E-core on hybrid CPUs)
                //
                pin_thread_to_core(num_cores.saturating_sub(1));

                OutputWorker {
                    rx: output_rx,
                    writer: BufWriter::with_capacity(128 * 1024, io::stdout()),
                }.run();
            });

            let handles = workers.into_iter().enumerate().map(|(worker_id, local_worker)| {
                let stealers = &stealers;
                let output_tx = output_tx.clone();
                let cli = &self.cli;

                let cache = self.cache.as_ref();
                let fragment_hashes = &self.fragment_hashes;

                s.spawn(move || {
                    pin_thread_to_core(worker_id % num_cores);

                    let worker = WorkerContext {
                        cache,
                        fragment_hashes,
                        fs,
                        matcher,
                        cli,

                        stats: Stats::default(),
                        parser: Parser::default(),

                        path: SmallPathBuf::default(),
                        output_tx,
                        worker_id: worker_id as _,

                        pending_file_keys: Vec::new(),
                        pending_file_metas: Vec::new(),
                        pending_fragment_presence: Vec::new(),
                    };

                    let WorkerResult {
                        stats: worker_stats,
                        file_keys,
                        file_metas,
                        fragment_presence
                    } = worker.start_worker_loop(
                        running,
                        active_workers,
                        injector,
                        stealers,
                        &local_worker
                    );

                    worker_stats.merge_into(stats);

                    (file_keys, file_metas, fragment_presence)
                })
            }).collect::<Vec<_>>();

            let mut all_file_keys   = Vec::new();
            let mut all_file_metas  = Vec::new();
            let mut all_fragment_presence = Vec::new();

            for handle in handles {
                if let Ok((file_keys, file_metas, fragment_presence)) = handle.join() {
                    all_file_keys.extend(file_keys);
                    all_file_metas.extend(file_metas);
                    all_fragment_presence.extend(fragment_presence);
                }
            }

            drop(output_tx);
            _ = output_handle.join();

            (all_file_keys, all_file_metas, all_fragment_presence)
        });

        if let Some(cache) = &mut self.cache {
            if let Err(e) = cache.merge_updates(
                all_file_keys,
                all_file_metas,
                &self.fragment_hashes,
                all_fragment_presence
            ) {
                eprintln_red!("error: failed to merge cache updates: {e}");
            }
        }

        if let Some(cache) = &self.cache {
            if let Err(e) = cache.save_to_disk() {
                eprintln_red!("error: failed to save cache: {e}");
            }
        }

        Ok(stats.to_stats())
    }

    /// Resolve a path like "/usr/bin" or "etc" into a file ID.
    #[inline]
    pub fn try_resolve_path_to_file_id(&self, path: &str) -> io::Result<FileId> {
        let _span = tracy::span!("RawGrepper::try_resolve_path_to_file_id");

        if path == "/" || path.is_empty() {
            return Ok(self.fs.root_id());
        }

        let mut parser = Parser::default();
        let mut file_id = self.fs.root_id();

        for part in path.split('/').filter(|p| !p.is_empty()) {
            let node = self.fs.parse_node(file_id)?;

            if !node.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{path} is not a directory"),
                ));
            }

            let dir_size = node.size() as usize;
            self.fs.read_file_content(&mut parser, &node, dir_size, BufKind::Dir, false)?;

            file_id = parser.find_file_id_in_buf(
                &self.fs,
                part.as_bytes(),
                BufKind::Dir,
            ).ok_or_else(|| io::Error::new(
                io::ErrorKind::NotFound,
                format!("Component '{part}' not found"),
            ))?;
        }

        Ok(file_id)
    }

    /// Warm up filesystem metadata for faster traversal
    #[inline]
    fn warmup_filesystem(&self) {
        let _span = tracy::span!("RawGrepper::warmup_filesystem");

        // ...

        // Give the async prefetch time to start
        std::thread::yield_now();
    }
}

/// impl block for ext4-specific construction
impl<'a> RawGrepper<'a, Ext4Fs> {
    #[inline]
    pub fn new_ext4(cli: &'a Cli, _device_path: &str, file: File) -> io::Result<AnyGrepper<'a>> {
        let mut sb_bytes = [0u8; EXT4_SUPERBLOCK_SIZE];
        {
            use std::os::unix::fs::FileExt;
            file.read_at(&mut sb_bytes, EXT4_SUPERBLOCK_OFFSET)?;
        }

        let magic = u16::from_le_bytes([
            sb_bytes[EXT4_MAGIC_OFFSET + 0],
            sb_bytes[EXT4_MAGIC_OFFSET + 1],
        ]);
        if magic != EXT4_SUPER_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Not an ext4 filesystem".to_owned()
            ));
        }

        let sb = Ext4Fs::parse_superblock(&sb_bytes)?;
        let device_id = device_id(&file)?;
        let file_size = file.metadata()?.len();
        let max_block = file_size / sb.block_size as u64;

        let fs = Ext4Fs { sb, device_id, max_block, file };
        Self::new_with_fs(cli, fs).map(AnyGrepper::Ext4)
    }
}

/// impl block for apfs-specific construction
impl<'a> RawGrepper<'a, ApfsFs> {
    #[inline]
    pub fn new_apfs(cli: &'a Cli, _device_path: &str, file: File) -> io::Result<AnyGrepper<'a>> {
        // Read the first block (4096 bytes covers the NX superblock at block 0).
        // We don't know block_size yet, so read the maximum possible default.
        let mut block0 = [0u8; 4096];
        {
            use std::os::unix::fs::FileExt;
            file.read_at(&mut block0, 0)?;
        }

        let sb = ApfsFs::parse_container_superblock(&block0)?;

        let device_id = device_id(&file)?;

        let fs = ApfsFs { file, sb, device_id, volume: ApfsVolume { omap_root_paddr: 0, root_tree_paddr: 0 } };

        // parse_volume() needs self.file + self.sb, so we construct a temporary
        // ApfsFs first, resolve the volume, then patch it in.
        let volume = fs.parse_volume()?;
        let fs = ApfsFs { volume, ..fs };

        Self::new_with_fs(cli, fs).map(AnyGrepper::Apfs)
    }
}

#[inline]
pub fn open_device_and_detect_fs(device_path: &str) -> io::Result<(File, FsType)> {
    //
    // @Volatile
    //
    // I don't wanna force a sync of literally everything on the computer,
    // cuz on some systems it might be completely detrimental to the speed of this tool.
    //
    // While correctness must be the top priority, speed should be at least the second top priority,
    // hence I decided to instead do the `ioctl` call...
    //
    // Though, we'll see how reliable and cross-platform it is..
    //
    // {
    //     let t = std::time::Instant::now();
    //     unsafe { libc::sync(); }
    //     eprintln!("sync: {:.2}ms", t.elapsed().as_secs_f64() * 1000.0);
    // }
    //

    let file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(device_path)?;

    #[cfg(target_os = "linux")] {
        use std::os::unix::io::AsRawFd;
        const BLKFLSBUF: libc::c_ulong = 0x1261;
        unsafe { libc::ioctl(file.as_raw_fd(), BLKFLSBUF, 0) };
    }

    #[cfg(unix)] {
        use std::os::unix::io::AsRawFd;
        unsafe { libc::syncfs(file.as_raw_fd()); }
    }

    // Read enough to cover both magic locations:
    // APFS at offset 32, ext4 superblock at offset 1024+56=1080 -> 2048 bytes is sufficient
    let mut probe = [0u8; 2048];
    {
        use std::os::unix::fs::FileExt;
        file.read_at(&mut probe, 0)?;
    }

    let fs = detect_fs_type(&probe).expect("unexpected filesystem");

    Ok((file, fs))
}

#[inline]
pub fn create_matcher_or_exit(cli: &Cli) -> Matcher {
    match Matcher::new(cli) {
        Ok(m) => m,
        Err(e) => {
            match e.kind() {
                io::ErrorKind::InvalidInput => {
                    eprintln_red!("error: invalid pattern '{pattern}'", pattern = cli.pattern);
                    eprintln_red!("tip: test your regex with `grep -E` or a regex tester before running");
                    eprintln_red!("patterns must be valid regex or a literal/alternation extractable form");
                }
                io::ErrorKind::NotFound => {
                    eprintln_red!("error: referenced something that wasn't found: {e}");
                }
                _ => {
                    eprintln_red!("error: failed to build matcher: {e}");
                }
            }

            std::process::exit(1);
        }
    }
}

//
// CPU affinity helpers - gdt-cpus has bugs on macOS, so we provide fallbacks
//

/// Get number of physical cores, falling back to provided default
#[inline]
fn num_physical_cores_or(fallback: usize) -> usize {
    #[cfg(not(target_os = "macos"))]
    {
        gdt_cpus::num_physical_cores().unwrap_or(fallback)
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: use sysctl to get physical core count
        macos_num_physical_cores().unwrap_or(fallback)
    }
}

/// Pin current thread to a specific core (best-effort, ignores failures)
#[inline]
fn pin_thread_to_core(core_id: usize) {
    #[cfg(not(target_os = "macos"))]
    {
        _ = gdt_cpus::pin_thread_to_core(core_id);
    }
    #[cfg(target_os = "macos")]
    {
        // macOS doesn't support thread-to-core pinning via public APIs
        // Thread affinity hints are handled by the kernel
        _ = core_id;
    }
}

#[cfg(target_os = "macos")]
fn macos_num_physical_cores() -> Option<usize> {
    // sysctl hw.physicalcpu
    let mut count: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();

    let ret = unsafe {
        libc::sysctlbyname(
            c"hw.physicalcpu".as_ptr(),
            &mut count as *mut _ as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };

    if ret == 0 && count > 0 {
        Some(count as usize)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsType {
    Ext4,
    Apfs,
}

/// Peek at raw bytes to identify the filesystem type.
/// `block0` should be at least 2048 bytes (to cover the ext4 superblock at offset 1024).
pub fn detect_fs_type(block0: &[u8]) -> Option<FsType> {
    // APFS: NX magic at offset 32 in block 0
    if block0.len() >= 36 {
        let magic = u32::from_le_bytes(block0[32..36].try_into().unwrap());
        if magic == APFS_NX_MAGIC {
            return Some(FsType::Apfs);
        }
    }

    // ext4: magic at offset 1024 + 56 = 1080
    if block0.len() >= EXT4_SUPERBLOCK_OFFSET as usize + EXT4_MAGIC_OFFSET + 2 {
        let off = EXT4_SUPERBLOCK_OFFSET as usize + EXT4_MAGIC_OFFSET;
        let magic = u16::from_le_bytes(block0[off..off + 2].try_into().unwrap());
        if magic == EXT4_SUPER_MAGIC {
            return Some(FsType::Ext4);
        }
    }

    None
}

pub enum AnyGrepper<'a> {
    Ext4(RawGrepper<'a, Ext4Fs>),
    Apfs(RawGrepper<'a, ApfsFs>),
}

impl<'a> AnyGrepper<'a> {
    #[inline]
    pub fn search(
        self,
        root_file_id: FileId,
        running: &AtomicBool,
        root_gi: Option<Gitignore>,
    ) -> io::Result<Stats> {
        match self {
            AnyGrepper::Ext4(g) => g.search(root_file_id, running, root_gi),
            AnyGrepper::Apfs(g) => g.search(root_file_id, running, root_gi),
        }
    }

    #[inline]
    pub fn try_resolve_path_to_file_id(&self, path: &str) -> io::Result<FileId> {
        match self {
            AnyGrepper::Ext4(g) => g.try_resolve_path_to_file_id(path),
            AnyGrepper::Apfs(g) => g.try_resolve_path_to_file_id(path),
        }
    }
}
