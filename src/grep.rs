use std::sync::Arc;
use std::os::fd::AsRawFd;
use std::io::{self, BufWriter};
use std::fs::{File, OpenOptions};
use std::sync::atomic::{AtomicBool, AtomicUsize};

use memmap2::{Mmap, MmapOptions};
use crossbeam_channel::unbounded;
use crossbeam_deque::{Injector, Worker as DequeWorker};

use crate::cache::{CacheConfig, FragmentCache};
use crate::cli::Cli;
use crate::matcher::Matcher;
use crate::parser::{BufKind, FileId, FileNode, Parser, RawFs};
use crate::{eprintln_red, tracy};
use crate::path_buf::SmallPathBuf;
use crate::stats::{AtomicStats, Stats};
use crate::ignore::{Gitignore, GitignoreChain};
use crate::worker::{DirWork, OutputWorker, WorkItem, WorkerContext};
use crate::ext4::{
    Ext4Fs,
    BLKGETSIZE64,
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

/// impl block for ext4-specific construction
impl<'a> RawGrepper<'a, Ext4Fs<'a>> {
    pub fn new_ext4(device_path: &str, cli: &'a Cli, mmap: &'a Mmap) -> io::Result<Self> {
        let sb_bytes = &mmap[
            EXT4_SUPERBLOCK_OFFSET as usize..
            EXT4_SUPERBLOCK_OFFSET as usize + EXT4_SUPERBLOCK_SIZE
        ];

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

        let sb = Ext4Fs::parse_superblock(sb_bytes)?;

        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(device_path)?;

        let device_id = unsafe {
            let mut stat: libc::stat = std::mem::zeroed();
            if libc::fstat(file.as_raw_fd(), &mut stat) < 0 {
                return Err(io::Error::last_os_error());
            }
            stat.st_dev
        };

        let max_block = (mmap.len() / sb.block_size as usize) as u64;
        let fs = Ext4Fs { mmap, sb, device_id, max_block };

        Self::new_with_fs(cli, fs)
    }
}

/// impl block for generic RawFs
impl<'a, F: RawFs> RawGrepper<'a, F> {
    pub fn new_with_fs(cli: &'a Cli, fs: F) -> io::Result<Self> {
        let matcher = match Matcher::new(cli) {
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
        };

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

        #[cfg(target_os = "linux")]
        let topology = Arc::new(crate::core_topology::CoreTopology::detect());

        let (all_file_keys, all_file_metas, all_had_matches) = std::thread::scope(|s| {
            #[cfg(target_os = "linux")]
            let topology_output = &topology;

            let output_handle = s.spawn(move || {
                #[cfg(target_os = "linux")]
                if let Some(core_id) = topology_output.output_core() {
                    unsafe {
                        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
                        libc::CPU_SET(core_id, &mut cpuset);
                        libc::sched_setaffinity(0, std::mem::size_of_val(&cpuset), &cpuset);
                    }
                }

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

                #[cfg(target_os = "linux")]
                let topology_worker = &topology;

                s.spawn(move || {
                    #[cfg(target_os = "linux")]
                    {
                        let core_id = topology_worker.worker_core(worker_id);
                        unsafe {
                            let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
                            libc::CPU_SET(core_id, &mut cpuset);
                            libc::sched_setaffinity(0, std::mem::size_of_val(&cpuset), &cpuset);
                        }
                    }

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
                        pending_had_matches: Vec::new(),
                    };

                    let (worker_stats, file_keys, file_metas, had_matches) = worker.start_worker_loop(
                        running,
                        active_workers,
                        injector,
                        stealers,
                        &local_worker
                    );

                    worker_stats.merge_into(stats);

                    (file_keys, file_metas, had_matches)
                })
            }).collect::<Vec<_>>();

            let mut all_file_keys   = Vec::new();
            let mut all_file_metas  = Vec::new();
            let mut all_had_matches = Vec::new();

            for handle in handles {
                if let Ok((file_keys, file_metas, had_matches)) = handle.join() {
                    all_file_keys.extend(file_keys);
                    all_file_metas.extend(file_metas);
                    all_had_matches.extend(had_matches);
                }
            }

            drop(output_tx);
            _ = output_handle.join();

            (all_file_keys, all_file_metas, all_had_matches)
        });

        if let Some(cache) = &mut self.cache {
            if let Err(e) = cache.merge_updates(
                all_file_keys,
                all_file_metas,
                &self.fragment_hashes,
                all_had_matches
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

        // Prefetch first few megabytes which typically contain metadata
        self.fs.prefetch_region(0, 4 * 1024 * 1024);

        // Give the async prefetch time to start
        std::thread::yield_now();
    }
}

#[inline]
pub fn open_device(device_path: &str) -> io::Result<(File, Mmap)> {
    let file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(device_path)?;

    let size = device_size(&file)?;

    let mmap = unsafe {
        MmapOptions::new()
            .offset(0)
            .len(size as _)
            .map(&file)?
    };

    Ok((file, mmap))
}

#[inline]
pub fn device_size(fd: &File) -> io::Result<u64> {
    let mut size = 0u64;
    let res = unsafe {
        libc::ioctl(fd.as_raw_fd(), BLKGETSIZE64, &mut size)
    };

    if res < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(size)
}
