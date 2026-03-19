use std::fs;
use std::path::Path;
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
use crate::{cli, ignore, platform};
use crate::parser::{Parser, RawFs};
use crate::cache::{FileKey, FileMeta};
use crate::stats::{AtomicStats, Stats};
use crate::grep::{AnyGrepper, FsType, RawGrepper, open_device_and_detect_fs};
use crate::worker::{DirWork, FileWork, MatchSink, OutputWorker, WorkItem, WorkerContext, WorkerResult};

#[derive(Default)]
struct CacheAccumulator {
    file_keys:          Vec<FileKey>,
    file_metas:         Vec<FileMeta>,
    fragment_presence:  Vec<bool>,
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
    injector:       Arc<Injector<WorkItem>>,
    running:        Arc<AtomicBool>,
    active_workers: Arc<AtomicUsize>,
    wake:           Arc<(Mutex<bool>, Condvar)>,
    current_job:    Arc<RwLock<Option<Arc<SearchJob<S>>>>>,

    output_tx:      Sender<&'static [u8]>,
    flush_req_tx:   Sender<()>,
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
        let job            = Arc::default();

        let (output_tx, output_rx) = unbounded();
        let (flush_req_tx, flush_req_rx) = unbounded();
        let (flush_ack_tx, flush_ack_rx) = unbounded();

        _ = std::thread::spawn(move || {
            OutputWorker {
                rx: output_rx,
                flush_req_rx,
                flush_ack_tx,
                writer: BufWriter::with_capacity(128 * 1024, io::stdout()), // @Contant @Tune
            }.run();
        });

        let ctx = Self {
            injector,
            running,
            active_workers,
            wake,
            current_job: job,
            output_tx,
            flush_req_tx,
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
    }

    #[inline]
    pub fn wait(&mut self) -> Stats {
        while self.running.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }

        // Spin until all workers have dropped their job Arc clones
        {
            let guard = self.current_job.read();
            if let Some(job_arc) = guard.as_ref() {
                while Arc::strong_count(job_arc) > 1 {
                    std::hint::spin_loop();
                }
            }
        }

        // Request flush and wait for ack
        _ = self.flush_req_tx.send(());
        _ = self.flush_ack_rx.lock().recv();

        self.current_job.read()
            .as_ref()
            .map(|j| j.stats.to_stats())
            .unwrap_or_default()
    }

    #[inline]
    pub fn wait_and_save_cache(&mut self) -> Stats {
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

        let fragment_hashes = job.grepper.fragment_hashes().to_owned();  // @Clone

        let mut acc = job.cache_acc.lock();
        let file_keys         = std::mem::take(&mut acc.file_keys);
        let file_metas        = std::mem::take(&mut acc.file_metas);
        let fragment_presence = std::mem::take(&mut acc.fragment_presence);

        if let Some(cache) = &mut job.grepper.cache_mut() {
            _ = cache.merge_updates(file_keys, file_metas, &fragment_hashes, fragment_presence);
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
        // Cancel previous search and wait for workers to go idle
        //
        {
            self.running.store(false, Ordering::SeqCst);
            while self.active_workers.load(Ordering::SeqCst) > 0 {
                std::hint::spin_loop();
            }

            // Clear the injector from potential stale work
            while self.injector.steal().is_success() {}
        }

        //
        // Open device and detect fs
        //

        let search_root = fs::canonicalize(&*config.search_root_path)
            .map_err(|e| Error::PathNotFound {
                path:   config.search_root_path.clone(),
                source: e,
            })?;

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

        let root_file_id = grepper
            .try_resolve_path_to_file_id(&search_root_for_fs)
            .map_err(|e| Error::RootNotFound {
                path:   search_root_for_fs.clone(),
                device: device.clone(),
                source: e,
            })?;

        debug!("[ctx] search_root_for_fs={search_root_for_fs:?} root_file_id={root_file_id:?}");

        //
        // Setup output channel and gitignore
        //
        let root_gitignore = {
            let gi_path = search_root.join(".gitignore");
            ignore::build_gitignore_from_file(&gi_path.to_string_lossy())
        };
        debug!("[ctx] root_gitignore present={}", root_gitignore.is_some());

        //
        // Swap in new job
        //
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

        //
        // Push root work item and wake workers
        //

        let work = if std::fs::metadata(&search_root).is_ok_and(|m| m.is_file()) {
            WorkItem::File(FileWork {
                file_id:         root_file_id,
                path_bytes:      Arc::default(),
                gitignore_chain: root_gitignore
                    .map(crate::ignore::GitignoreChain::from_root)
                    .unwrap_or_default(),
            })
        } else {
            WorkItem::Directory(DirWork {
                depth: 0,
                file_id:         root_file_id,
                path_bytes:      Arc::default(),
                gitignore_chain: root_gitignore
                    .map(crate::ignore::GitignoreChain::from_root)
                    .unwrap_or_default(),
            })
        };
        self.injector.push(work);
        debug!("[ctx] root work item pushed to injector");

        self.running.store(true, Ordering::SeqCst);
        let (lock, cvar) = &*self.wake;
        *lock.lock() = true;
        cvar.notify_all();
        debug!("[ctx] running=true, all workers notified");

        Ok(())
    }
}

#[allow(clippy::too_many_arguments)] // @Cleanup
fn dispatch_worker<'a, F: RawFs, S: MatchSink>(
    worker_id:      u16,

    g: &RawGrepper<F, S>,
    ctx: &RawGrepCtx<S>,

    parser: Parser<'a>,
    path_buf: Box<SmallPathBuf>,
    newlines_scratch: Vec<u32>,
    ranges_scratch: Vec<(u32, u32)>,

    stealers:       &[Stealer<WorkItem>],
    local:          &DequeWorker<WorkItem>,
) -> WorkerResult<'a> {
    WorkerContext {
        worker_id,
        cache:            g.cache(),
        fragment_hashes:  g.fragment_hashes(),
        fs:               g.fs(),
        matcher:          g.matcher(),
        cli:              g.cli(),
        sink:             g.sink.clone(),
        output_tx:        ctx.output_tx.clone(),
        stats:            Default::default(),
        parser,
        path_buf,
        newlines_scratch,
        ranges_scratch,

        chunk_carry:      None,

        pending_file_keys:         Vec::new(),
        pending_file_metas:        Vec::new(),
        pending_fragment_presence: Vec::new(),
    }.start_worker_loop(
        &ctx.running,
        &ctx.active_workers,
        &ctx.injector,
        stealers,
        local,
    )
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
    let mut parser = Parser::new(&output_buffer_arena);
    let mut path_buf = Box::new(SmallPathBuf::new());
    let mut newlines_scratch = Vec::new();
    let mut ranges_scratch = Vec::new();

    let mut search_count = 0u32;

    loop {
        //
        // Sleep until a search is ready
        //
        {
            let (lock, cvar) = ctx.wake.as_ref();
            let mut ready = lock.lock();
            cvar.wait(&mut ready);
            // Don't reset `ready` here - all workers need to see it true.
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

        //
        // Reset the buffers
        //
        unsafe { path_buf.set_len(0); }
        newlines_scratch.clear();
        ranges_scratch.clear();

        macro_rules! dispatch {
            ($g:expr) => {
                dispatch_worker(
                    worker_id, $g, &ctx,
                    parser, path_buf,
                    newlines_scratch, ranges_scratch,
                    stealers, &local
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
        newlines_scratch = result.newlines_scratch;
        ranges_scratch = result.ranges_scratch;
        path_buf = result.path_buf;
        result.stats.merge_into(&job.stats);

        // Deposit cache data
        {
            let mut acc = job.cache_acc.lock();
            acc.file_keys.extend(result.file_keys);
            acc.file_metas.extend(result.file_metas);
            acc.fragment_presence.extend(result.fragment_presence);
        }

        //
        // Reset wake flag when this worker's loop exits
        //
        let (lock, _) = ctx.wake.as_ref();
        if let Some(mut ready) = lock.try_lock() {
            *ready = false;
        }
    }
}
