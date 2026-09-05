use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::io::{self, BufWriter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bumpalo::Bump;
use parking_lot::{Condvar, Mutex, RwLock};

use ::tracing::debug;
use crossbeam_channel::{Receiver, Sender, unbounded};
use crossbeam_deque::{Injector, Stealer, Worker as DequeWorker};

use crate::error::Error;
use crate::RawGrepConfig;
use crate::path_buf::SmallPathBuf;
use crate::stdout::RawStdout;
use crate::{cli, ignore, platform};
use crate::parser::Parser;
use crate::cache::{FileKey, FileMeta, CacheStats};
use crate::stats::{AtomicStats, Stats};
use crate::grep::{AnyGrepper, FsType, RawGrepper, open_device_and_detect_fs};
use crate::worker::{DirWork, FileWork, MatchSink, OutputWorker, WorkItem, WorkerCtx, PathArena, FileEntryArena, SubdirsArena, FragmentPresenceBits, OUTPUTTER_FLUSH_BATCH, OutputMessage};

#[derive(Default)]
struct CacheAccumulator {
    file_keys:          Vec<FileKey>,
    file_metas:         Vec<FileMeta>,
    fragment_presence:  Vec<u64>,
}

/// Per-search data, swapped atomically between searches.
struct SearchJob<S: MatchSink> {
    grepper:   AnyGrepper<S>,
    stats:     AtomicStats,
    device:    Box<str>,
    cache_acc: Mutex<CacheAccumulator>,
}

/// Persistent search context - owns the worker "thread pool".
///
/// Create once per application lifetime, reuse across searches. Each call to
/// [`search`] cancels any in-flight search, swaps in new per-search data, and
/// wakes the idle workers.
#[derive(Clone)]
pub struct RawGrepCtx<S: MatchSink> {
    worker_count:   usize,

    injector:       Arc<Injector<WorkItem>>,
    running:        Arc<AtomicBool>,
    active_workers: Arc<AtomicUsize>,

    running_signal: Arc<(Mutex<()>, Condvar)>,    // notified when `running` flips false
    job_done:       Arc<(Mutex<usize>, Condvar)>, // counts workers still owing a finish for this job

    wake:           Arc<(Mutex<u64>, Condvar)>,
    current_job:    Arc<RwLock<Option<Arc<SearchJob<S>>>>>,

    output_tx:      Sender<OutputMessage>,
    flush_ack_rx:   Arc<Mutex<Receiver<()>>>,
}

impl<S: MatchSink + 'static> RawGrepCtx<S> {
    /// Spawn `num_threads` persistent worker threads and return the context.
    /// Threads immediately sleep on the condvar and consume no CPU until
    /// the first call to [`search`].
    pub fn new(num_threads: usize, running: Arc<AtomicBool>) -> Self {
        let injector       = Arc::default();
        let active_workers = Arc::default();
        let wake           = Arc::default();
        let running_signal = Arc::default();
        let job_done       = Arc::default();
        let job            = Arc::default();

        let (output_tx, output_rx)       = unbounded();
        let (flush_ack_tx, flush_ack_rx) = unbounded();

        _ = std::thread::spawn(move || {
            OutputWorker {
                rx: output_rx,
                flush_ack_tx,
                writer: BufWriter::with_capacity(OUTPUTTER_FLUSH_BATCH * 2, RawStdout::new()), // @Contant @Tune
            }.run();
        });

        let ctx = Self {
            injector,
            running,
            active_workers,
            job_done,
            running_signal,
            wake,
            current_job: job,
            output_tx,
            worker_count: num_threads,
            flush_ack_rx: Arc::new(Mutex::new(flush_ack_rx)),
        };

        let mut local_workers = Vec::with_capacity(num_threads);
        let mut stealers      = Vec::with_capacity(num_threads);
        for _ in 0..num_threads {
            let w = DequeWorker::new_lifo();
            stealers.push(w.stealer());
            local_workers.push(w);
        }

        let num_cores = crate::util::num_physical_cores_or(num_threads);

        let stealers = Arc::new(stealers);
        for (worker_id, local) in local_workers.into_iter().enumerate() {
            let ctx = ctx.clone();
            let stealers = stealers.clone();

            std::thread::spawn(move || {
                crate::util::pin_thread_to_core(worker_id % num_cores);

                worker_thread_main(
                    worker_id as _,
                    ctx,
                    &stealers,
                    local,
                );
            });
        }

        ctx
    }

    #[inline]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    #[inline]
    pub fn cancel(&self) {
        self.running.store(false, Ordering::SeqCst);
        {
            let (lock, cvar) = &*self.running_signal;
            let _guard = lock.lock();
            cvar.notify_all();
        }
    }

    #[inline]
    pub fn wait(&mut self) -> (Stats, Option<CacheStats>) {
        {
            let (lock, cvar) = &*self.running_signal;
            let mut guard = lock.lock();
            cvar.wait_while(&mut guard, |_| self.running.load(Ordering::SeqCst));
        }
        {
            let (lock, cvar) = &*self.job_done;
            let mut guard = lock.lock();
            cvar.wait_while(&mut guard, |remaining| *remaining > 0);
        }

        _ = self.output_tx.send(OutputMessage::FlushReq);
        _ = self.flush_ack_rx.lock().recv();

        self.current_job.read()
            .as_ref()
            .map(|j| (j.stats.to_stats(), j.grepper.cache().map(|c| c.stats.to_cache_stats())))
            .unwrap_or_default()
    }

    #[inline]
    pub fn wait_and_save_cache(&mut self) -> (Stats, Option<CacheStats>) {
        let stats = self.wait();

        self.save_cache();

        stats
    }

    #[inline]
    pub fn save_cache(&mut self) {
        debug!("[ctx] trying to save cache..");

        let mut guard = self.current_job.write();

        let Some(job_arc) = guard.as_mut() else {
            debug!("[ctx] self.job is None..");
            return;
        };
        let Some(job) = Arc::get_mut(job_arc) else {
            debug!("[ctx] couldn't get job unique pointer..");
            return;
        };

        let mut acc = job.cache_acc.lock();
        let file_keys         = std::mem::take(&mut acc.file_keys);
        let file_metas        = std::mem::take(&mut acc.file_metas);
        let fragment_presence = std::mem::take(&mut acc.fragment_presence);

        let (fragment_hashes, cache) = job.grepper.fragment_hashes_and_cache_mut();

        if let Some(cache) = cache {
            _ = cache.merge_updates(file_keys, file_metas, fragment_hashes, fragment_presence);
            _ = cache.save_to_disk();

            debug!("[ctx] successfully saved cache");
        } else {
            debug!("job.grepper.cache is None... (pattern < 4 bytes)");
        }
    }

    /// Start a new search, cancelling any in-flight one.
    ///
    /// Returns immediately - results arrive via `sink`.
    /// Returns `Err` if setup (device detection, fs detection, path
    /// resolution) fails before any work starts.
    pub fn search(
        &self,
        config: RawGrepConfig,
        sink: S,
        inspect_before_search: impl FnOnce(&Path, &str, FsType, &str) // (search root, device, fs, pattern)
    ) -> Result<(), Error> {
        let cli = config.to_cli();

        _ = cli::SHOULD_ENABLE_ANSI_COLORING.set(!config.no_color);

        debug!("[ctx] search() pattern={:?} root={:?}", config.pattern, config.search_root_path);

        //
        // Cancel previous search and wait for it to fully stop before touching
        // anything shared (current_job, injector) that the old generation's
        // workers might still be using.
        //
        self.running.store(false, Ordering::SeqCst);
        {
            let (lock, cvar) = &*self.running_signal;
            let mut guard = lock.lock();
            cvar.wait_while(&mut guard, |_| self.running.load(Ordering::SeqCst));
        }
        {
            let (lock, cvar) = &*self.job_done;
            let mut guard = lock.lock();
            cvar.wait_while(&mut guard, |remaining| *remaining > 0);
        }
        while self.injector.steal().is_success() {}

        // Now it's safe to arm the counter for the new generation.
        {
            let (lock, _) = &*self.job_done;
            *lock.lock() = self.worker_count;
        }

        //
        // Open device and detect fs
        //

        let search_root = if config.device.is_some() {
            fs::canonicalize(&*config.search_root_path)
                .unwrap_or_else(|_| PathBuf::from(&*config.search_root_path))
        } else {
            fs::canonicalize(&*config.search_root_path).map_err(|e| Error::PathNotFound {
                path:   config.search_root_path.clone(),
                source: e,
            })?
        };

        let device = match config.device.clone() {
            Some(d) => d,
            None    => platform::detect_partition_for_path(
                &search_root
            ).map(Into::into).map_err(Error::DeviceDetectionFailed)?,
        };

        #[cfg(target_os = "macos")]
        let device = crate::util::resolve_apfs_physical_store(&device)?;

        let (file, fs_type) = open_device_and_detect_fs(&device)
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound         => Error::DeviceNotFound(device.clone()),
                io::ErrorKind::PermissionDenied => Error::PermissionDenied(device.clone()),
                _                               => Error::Io(e),
            })?;

        debug!("[ctx] device={device:?} fs_type={fs_type:?}");

        //
        // Build grepper
        //

        let grepper = match fs_type {
            FsType::Apfs => RawGrepper::new_apfs(&cli, &device, file, sink),
            FsType::Ext4 => RawGrepper::new_ext4(&cli, &device, file, sink),
            FsType::Ntfs => RawGrepper::new_ntfs(&cli, &device, file, sink),
        }?;

        debug!("[ctx] grepper built ok");

        let is_ntfs = matches!(fs_type, FsType::Ntfs);
        if let AnyGrepper::Ntfs(g) = &grepper {
            g.fs().init_parallel_scan(self.worker_count);
        }

        inspect_before_search(
            &search_root, &device, fs_type, &cli.pattern
        );  // called after grepper is built, before workers wake

        //
        // Resolve root inode
        //

        let search_root_for_fs = if config.device.is_some() {
            platform::strip_mountpoint_prefix(&device, &search_root)
                .unwrap_or_else(|| search_root.to_string_lossy().into_owned())
        } else {
            search_root.to_string_lossy().into_owned()
        }.into_boxed_str();

        debug!("[ctx] search_root_for_fs={search_root_for_fs:?} root_file_id={root_file_id:?}");

        let root_gitignore = {
            let gi_path = search_root.join(".gitignore");
            ignore::build_gitignore_from_file(&gi_path.to_string_lossy())
        };
        debug!("[ctx] root_gitignore present={}", root_gitignore.is_some());

        // Non-NTFS can resolve immediately. NTFS needs workers to scan $MFT first.
        let mut root_file_id = if is_ntfs {
            None
        } else {
            Some(grepper.try_resolve_path_to_file_id(&search_root_for_fs).map_err(|e| Error::RootNotFound {
                path:   search_root_for_fs.clone(),
                device: device.clone(),
                source: e,
            })?)
        };

        {
            let mut guard = self.current_job.write();
            *guard = Some(SearchJob {
                grepper,
                device:    device.clone(),
                stats:     Default::default(),
                cache_acc: Default::default(),
            }.into());
        }
        debug!("[ctx] job swapped in");

        let wake_workers = || {
            let (lock, cvar) = &*self.wake;
            {
                let mut _gen = lock.lock();
                *_gen = _gen.wrapping_add(1);
            }
            cvar.notify_all();
        };

        if is_ntfs {
            // Workers scan disjoint $MFT slices; steal loop stays gated until
            // the root WorkItem is pushed (see NtfsFs::scan_mft_worker).
            wake_workers();

            let scan_result = {
                let job = self.current_job.read().as_ref().cloned();
                match job.as_ref() {
                    Some(job) => match &job.grepper {
                        AnyGrepper::Ntfs(g) => g.fs().wait_mft_ready(),
                        _ => Ok(()),
                    },
                    None => Ok(()),
                }
            };

            if let Err(e) = scan_result {
                self.running.store(false, Ordering::SeqCst);
                if let Some(job) = self.current_job.read().as_ref() {
                    if let AnyGrepper::Ntfs(g) = &job.grepper {
                        g.fs().release_work_gate();
                    }
                }
                return Err(Error::Io(e));
            }

            root_file_id = match {
                let guard = self.current_job.read();
                let job = guard.as_ref().expect("NTFS job");
                job.grepper.try_resolve_path_to_file_id(&search_root_for_fs)
            } {
                Ok(id) => Some(id),
                Err(e) => {
                    self.running.store(false, Ordering::SeqCst);
                    if let Some(job) = self.current_job.read().as_ref() {
                        if let AnyGrepper::Ntfs(g) = &job.grepper {
                            g.fs().release_work_gate();
                        }
                    }
                    return Err(Error::RootNotFound {
                        path:   search_root_for_fs.clone(),
                        device: device.clone(),
                        source: e,
                    });
                }
            };
        }

        debug!("[ctx] search_root_for_fs={search_root_for_fs:?} root_file_id={root_file_id:?}");

        let root_file_id = root_file_id.expect("root file id");
        let work = if std::fs::metadata(&search_root).is_ok_and(|m| m.is_file()) {
            WorkItem::File(FileWork {
                file_id:         root_file_id,
                gitignore_chain: root_gitignore
                    .map(crate::ignore::GitignoreChain::from_root)
                    .unwrap_or_default(),
            })
        } else {
            WorkItem::Directory(DirWork::new(
                root_file_id,
                &[], 0,
                root_gitignore.map(crate::ignore::GitignoreChain::from_root).unwrap_or_default()
            ))
        };
        self.injector.push(work);
        debug!("[ctx] root work item pushed to injector");

        self.running.store(true, Ordering::SeqCst);

        if is_ntfs {
            if let Some(job) = self.current_job.read().as_ref() {
                if let AnyGrepper::Ntfs(g) = &job.grepper {
                    g.fs().release_work_gate();
                }
            }
        } else {
            wake_workers();
        }
        debug!("[ctx] running=true, all workers notified");

        Ok(())
    }
}

fn worker_thread_main<S: MatchSink + 'static>(
    worker_id: u16,
    ctx:       RawGrepCtx<S>,
    stealers:  &[Stealer<WorkItem>],
    local:     DequeWorker<WorkItem>,
) {
    debug!("[ctx] worker {worker_id} started, waiting on condvar");

    let output_buffer_arena = Bump::new();

    // Parser buffers are owned by the thread and reused across searches,
    // saving allocations on every search restart.
    let mut parser                    = Parser::new(&output_buffer_arena);
    let mut path_buf                  = Box::new(SmallPathBuf::new());
    let mut swap_path_buf             = Box::new(SmallPathBuf::new());
    let mut newlines_scratch          = Vec::new();
    let mut ranges_scratch            = Vec::new();
    let mut fragment_presence_scratch = Vec::new();
    let mut path_arena                = PathArena::new();
    let mut file_entries_arena        = FileEntryArena::new();
    let mut subdirs_arena             = SubdirsArena::new();

    let mut file_keys                 = Vec::new();
    let mut file_metas                = Vec::new();
    let mut fragment_presence         = FragmentPresenceBits::default();

    let mut search_count = 0u32;
    let mut last_gen     = 0u64;

    loop {
        //
        // Sleep until a new search is ready
        //
        {
            let (lock, cvar) = ctx.wake.as_ref();
            let mut _gen = lock.lock();
            while *_gen == last_gen {
                cvar.wait(&mut _gen);
            }
            last_gen = *_gen;
        }

        search_count += 1;
        debug!("[ctx] worker {worker_id} woke up for search #{search_count}");

        // Grab the current job
        let job = {
            let guard = ctx.current_job.read();
            match guard.as_ref() {
                Some(j) => Arc::clone(j),
                None    => {
                    debug!("[ctx] worker {worker_id} no job found after wake, looping");
                    continue;
                }
            }
        };

        debug!("[ctx] worker {worker_id} got job device={:?}", job.device);

        if let AnyGrepper::Ntfs(g) = &job.grepper {
            g.fs().scan_mft_worker(worker_id as usize, ctx.worker_count);
        }

        //
        // Reset the buffers
        //
        unsafe { path_buf.set_len(0); }
        unsafe { swap_path_buf.set_len(0); }
        newlines_scratch.clear();
        ranges_scratch.clear();
        subdirs_arena.clear();
        path_arena.clear();
        if fragment_presence_scratch.is_empty() {
            let fragment_hash_count = job.grepper.fragment_hashes().len();
            fragment_presence_scratch.resize(fragment_hash_count.div_ceil(64), 0);
            fragment_presence = FragmentPresenceBits::new(fragment_hash_count);
        }

        macro_rules! dispatch {
            ($g:expr) => {
                WorkerCtx {
                    worker_id,
                    cache:            $g.cache(),
                    fragment_hashes:  $g.fragment_hashes(),
                    fs:               $g.fs(),
                    matcher:          $g.matcher(),
                    selected_fragment_hash_len: $g.selected_fragment_hash_len(),
                    cli:              $g.cli(),
                    sink:             $g.sink.clone(),
                    output_tx:        ctx.output_tx.clone(),
                    stats:            Default::default(),
                    parser,
                    path_buf,
                    subdirs_arena,
                    newlines_scratch,
                    ranges_scratch,
                    path_arena,
                    file_entries_arena,
                    swap_path_buf,
                    fragment_presence_scratch,

                    chunk_carry:      None, // @Memory: Cache this as well.

                    pending_file_keys: file_keys,
                    pending_file_metas: file_metas,
                    pending_fragment_presence: fragment_presence
                }.start_worker_loop(
                    &ctx.running,
                    &ctx.running_signal,
                    &ctx.active_workers,
                    &ctx.injector,
                    stealers,
                    &local,
                )
            };
        }
        let result = match &job.grepper {
            AnyGrepper::Ext4(g) => dispatch!(g),
            AnyGrepper::Apfs(g) => dispatch!(g),
            AnyGrepper::Ntfs(g) => dispatch!(g),
        };

        debug!(
            "[ctx] worker {worker_id} search #{search_count} done - \
             files_encountered={} files_searched={} files_with_matches={}",
            result.stats.files_encountered,
            result.stats.files_searched,
            result.stats.files_contained_matches,
        );

        parser = result.parser;
        file_entries_arena = result.file_entries_arena;
        subdirs_arena = result.subdirs_arena;
        path_arena = result.path_arena;
        newlines_scratch = result.newlines_scratch;
        ranges_scratch = result.ranges_scratch;
        fragment_presence_scratch = result.fragment_presence_scratch;
        path_buf = result.path_buf;
        swap_path_buf = result.swap_path_buf;
        result.stats.merge_into(&job.stats);

        // Deposit cache data
        {
            let mut acc = job.cache_acc.lock();
            acc.file_keys.extend_from_slice(&result.file_keys);
            acc.file_metas.extend_from_slice(&result.file_metas);
            acc.fragment_presence.extend_from_slice(&result.fragment_presence.words);

            file_keys = result.file_keys;
            file_metas = result.file_metas;
            fragment_presence = result.fragment_presence;
        }

        {
            let (lock, cvar) = &*ctx.job_done;
            let mut remaining = lock.lock();
            *remaining -= 1;
            if *remaining == 0 {
                cvar.notify_all();
            }
        }
    }
}
