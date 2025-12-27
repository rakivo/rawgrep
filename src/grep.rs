use std::sync::Arc;
use std::time::Duration;
use std::os::fd::AsRawFd;
use std::io::{self, BufWriter};
use std::fs::{File, OpenOptions};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use memmap2::{Mmap, MmapOptions};
use crossbeam_channel::unbounded;
use crossbeam_deque::{Injector, Worker as DequeWorker};

use crate::cache::FragmentCache;
use crate::cli::Cli;
use crate::matcher::Matcher;
use crate::{eprintln_red, tracy};
use crate::path_buf::SmallPathBuf;
use crate::stats::{AtomicStats, Stats};
use crate::ignore::{Gitignore, GitignoreChain};
use crate::parser::{BufKind, Ext4Context, Parser};
use crate::worker::{DirWork, OutputWorker, WorkItem, WorkerContext};
use crate::ext4::{
    Ext4SuperBlock,
    INodeNum,
    BLKGETSIZE64,
    EXT4_MAGIC_OFFSET,
    EXT4_ROOT_INODE,
    EXT4_SUPERBLOCK_OFFSET,
    EXT4_SUPERBLOCK_SIZE,
    EXT4_SUPER_MAGIC,
    EXT4_S_IFDIR,
    EXT4_S_IFMT
};

pub struct RawGrepper<'a> {
    cli: &'a Cli,

    device_mmap: Mmap,
    device_id: u64,
    sb: Ext4SuperBlock,

    matcher: Matcher,

    cache: Option<FragmentCache>,
    fragment_hashes: Vec<u32>,
}

/// impl block of public API
impl<'a> RawGrepper<'a> {
    pub fn new(device_path: &str, cli: &'a Cli) -> io::Result<Self> {
        #[inline]
        fn device_size(fd: &File) -> io::Result<u64> {
            let mut size = 0u64;
            let res = unsafe {
                libc::ioctl(fd.as_raw_fd(), BLKGETSIZE64, &mut size)
            };

            if res < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(size)
        }

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
                        // unlikely for this constructor, but here for completeness
                        eprintln_red!("error: referenced something that wasn't found: {e}");
                    }
                    _ => {
                        eprintln_red!("error: failed to build matcher: {e}");
                    }
                }

                std::process::exit(1);
            }
        };

        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(device_path)?;

        let size = device_size(&file)?;

        let device_id = unsafe {
            let mut stat: libc::stat = std::mem::zeroed();
            if libc::fstat(file.as_raw_fd(), &mut stat) < 0 {
                return Err(io::Error::last_os_error());
            }
            stat.st_dev
        };

        let device_mmap = unsafe {
            MmapOptions::new()
                .offset(0)
                .len(size as _)
                .map(&file)?
        };

        let sb_bytes = &device_mmap[
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

        let sb = Parser::parse_superblock(sb_bytes)?;

        let fragment_hashes = matcher.extract_fragment_hashes();

        let cache = if !cli.no_cache && !fragment_hashes.is_empty() {
            let mut config = crate::cache::CacheConfig::from_memory_mb(cli.cache_size_mb);
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

        Ok(RawGrepper {
            sb,
            cli,
            matcher,
            device_mmap,
            device_id,
            cache,
            fragment_hashes,
        })
    }

    pub fn search_parallel(
        mut self,
        root_inode: INodeNum,
        running: &AtomicBool,
        root_gi: Option<Gitignore>,
    ) -> io::Result<Stats> {
        let device_mmap = &self.device_mmap;
        let matcher = &self.matcher;
        let stats = &AtomicStats::new();

        let active_workers = &AtomicUsize::new(0);
        let quit_now = &AtomicBool::new(false);

        let (output_tx, output_rx) = unbounded();

        let injector = &Injector::new();
        injector.push(WorkItem::Directory(DirWork {
            inode_num: root_inode,
            path_bytes: Arc::default(),
            gitignore_chain: root_gi.map(GitignoreChain::from_root).unwrap_or_default(),
            depth: 0,
        }));

        let threads = self.cli.threads.get(); // @Constant @Tune

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
            let topology_output = topology.clone();

            let output_handle = s.spawn(move || {
                // --------- Pin output worker to E-core if available
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
                    writer: BufWriter::with_capacity(128 * 1024, io::stdout()), // @Constant @Tune
                }.run();
            });

            let handles = workers.into_iter().enumerate().map(|(worker_id, local_worker)| {
                let stealers = stealers.clone();
                let output_tx = output_tx.clone();
                let sb = &self.sb;
                let device_id = self.device_id;
                let cli = &self.cli;

                let cache = self.cache.as_ref();
                let fragment_hashes = &self.fragment_hashes;

                #[cfg(target_os = "linux")]
                let topology_worker = topology.clone();

                s.spawn(move || {
                    // -------- Pin worker to P-core
                    #[cfg(target_os = "linux")]
                    {
                        let core_id = topology_worker.worker_core(worker_id);
                        unsafe {
                            let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
                            libc::CPU_SET(core_id, &mut cpuset);
                            libc::sched_setaffinity(0, std::mem::size_of_val(&cpuset), &cpuset);
                        }
                    }

                    let mut worker = WorkerContext {
                        cache,
                        fragment_hashes,
                        ext4: Ext4Context { device_mmap, sb, device_id },
                        matcher,
                        cli,

                        stats: Stats::default(),
                        buffers: Parser::default(),

                        path: SmallPathBuf::default(),
                        output_tx,
                        worker_id: worker_id as _,

                        pending_file_keys: Vec::new(),
                        pending_file_metas: Vec::new(),
                        pending_had_matches: Vec::new(),
                    };

                    worker.init();

                    let mut consecutive_steals = 0;
                    let mut idle_iterations = 0;

                    loop {
                        if quit_now.load(Ordering::Relaxed) || !running.load(Ordering::Relaxed) {
                            break;
                        }

                        let work = WorkerContext::find_work(
                            worker.worker_id,
                            &local_worker,
                            injector,
                            &stealers,
                            &mut consecutive_steals,
                        );

                        match work {
                            Some(work_item) => {
                                idle_iterations = 0;
                                active_workers.fetch_add(1, Ordering::Release);

                                match work_item {
                                    WorkItem::Directory(dir_work) => {
                                        _ = worker.dispatch_directory(
                                            dir_work,
                                            &local_worker,
                                            injector,
                                        );
                                    }
                                }

                                active_workers.fetch_sub(1, Ordering::Release);
                            }
                            None => {
                                idle_iterations += 1;

                                worker.flush_output();

                                if active_workers.load(Ordering::Acquire) == 0 {
                                    // Double-check
                                    if injector.is_empty() && local_worker.is_empty() {
                                        quit_now.store(true, Ordering::Release);
                                        break;
                                    }
                                }

                                // @Constant @Tune
                                if idle_iterations < 10 {
                                    std::hint::spin_loop();
                                } else if idle_iterations < 20 {
                                    std::thread::yield_now();
                                } else {
                                    std::thread::sleep(Duration::from_micros(10));
                                }
                            }
                        }
                    }

                    let (worker_stats, file_keys, file_metas, had_matches) = worker.finish();
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
            if !all_file_keys.is_empty() && let Err(e) = cache.merge_updates(
                all_file_keys,
                all_file_metas,
                &self.fragment_hashes,
                all_had_matches
            ) {
                eprintln!("Error: Failed to merge cache updates: {e}");
            }
        }

        if let Some(cache) = &self.cache {
            if let Err(e) = cache.save_to_disk() {
                eprintln!("Error: Failed to save cache: {e}");
            }
        }

        Ok(stats.to_stats())
    }

    #[inline(always)]
    const fn ext4_context(&'a self) -> Ext4Context<'a> {
        Ext4Context { device_mmap: &self.device_mmap, sb: &self.sb, device_id: self.device_id }
    }

    /// Resolve a path like "/usr/bin" or "etc" into an inode number.
    /// Uses a temporary WorkerContext to reuse existing ext4 parsing logic.
    pub fn try_resolve_path_to_inode(&self, path: &str) -> io::Result<INodeNum> {
        let _span = tracy::span!("RawGrepper::try_resolve_path_to_inode");

        if path == "/" || path.is_empty() {
            return Ok(EXT4_ROOT_INODE);
        }

        let ext4 = self.ext4_context();
        let mut buffers = Parser::default();

        let mut inode_num = EXT4_ROOT_INODE;

        for part in path.split('/').filter(|p| !p.is_empty()) {
            let inode = Parser::parse_inode(inode_num, &ext4)?;

            if inode.mode & EXT4_S_IFMT != EXT4_S_IFDIR {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{path} is not a directory"),
                ));
            }

            let dir_size = inode.size as usize;
            buffers.read_file_into_buf(&inode, dir_size, BufKind::Dir, false, &ext4)?;

            inode_num = buffers.find_entry_inode(
                part.as_bytes()
            ).ok_or_else(|| io::Error::new(
                io::ErrorKind::NotFound,
                format!("Component '{part}' not found"),
            ))?;
        }

        Ok(inode_num)
    }

    /// Warm up filesystem metadata for faster traversal
    fn warmup_filesystem(&self) {
        let _span = tracy::span!("RawGrepper::warmup_filesystem");

        let total_size = self.device_mmap.len();
        let block_size = self.sb.block_size as usize;
        let blocks_per_group = self.sb.blocks_per_group as u64;
        let inodes_per_group = self.sb.inodes_per_group as usize;
        let inode_size = self.sb.inode_size as usize;
        let desc_size = self.sb.desc_size as usize;

        let bytes_per_group = blocks_per_group as usize * block_size;
        let num_groups = total_size.div_ceil(bytes_per_group);

        // GDT offset (after superblock)
        // @Constant
        let gdt_offset = if block_size == 1024 { 2048 } else { block_size };
        let gdt_size = num_groups * desc_size;

        let ext4 = self.ext4_context();

        //
        // Prefetch group descriptor table
        //
        Parser::prefetch_region(gdt_offset, gdt_size.min(4 * 1024 * 1024), &ext4); // @Constant @Tune

        //
        // Prefetch inode tables for first N groups,
        // These contain the inodes we'll need for directory traversal
        //
        let groups_to_prefetch = num_groups.min(128); // @Constant @Tune

        for group in 0..groups_to_prefetch {
            let gd_offset = gdt_offset + group * desc_size;
            if gd_offset + 12 > total_size {
                break;
            }

            let inode_table_block = u32::from_le_bytes([
                self.device_mmap[gd_offset +  8],
                self.device_mmap[gd_offset +  9],
                self.device_mmap[gd_offset + 10],
                self.device_mmap[gd_offset + 11],
            ]) as usize;

            let inode_table_offset = inode_table_block * block_size;
            let inode_table_size = inodes_per_group * inode_size;

            // @Constant
            Parser::prefetch_region(inode_table_offset, inode_table_size.min(2 * 1024 * 1024), &ext4);
        }

        //
        // Just in case wait for the async prefetch to start
        //
        std::thread::yield_now();
    }
}
