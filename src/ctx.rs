use crate::debug;
use crate::pacer::FlushPacer;
use crate::error::Error;
use crate::slab::{SlotPool, SlotWriter};
use crate::RawGrepConfig;
use crate::path_buf::SmallPathBuf;
use crate::stdout::{RawStdout, OutputKind};
use crate::{cli, ignore, platform, CursorHide};
use crate::parser::Parser;
use crate::cache::{FileKey, FileMeta, CacheStats};
use crate::stats::{AtomicStats, Stats};
use crate::grep::{AnyGrepper, FsType, RawGrepper, open_device_and_detect_fs};
use crate::worker::{DirWork, FileWork, MatchSink, OutputWorker, WorkItem, WorkerCtx, PathArena, FileEntryArena, SubdirsArena, FragmentPresenceBits, OutputMessage, EntriesArena};

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::io::{self};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use parking_lot::{Condvar, Mutex, RwLock};
use crossbeam_channel::{Receiver, Sender, unbounded};
use crossbeam_deque::{Injector, Stealer, Worker as DequeWorker};

#[derive(Default)]
struct CacheAccumulator {
    file_keys:          Vec<FileKey>,
    file_metas:         Vec<FileMeta>,
    fragment_presence:  Vec<u64>,
}

/// Per-search data, swapped atomically between searches.
struct SearchJob<S: MatchSink> {
    gitignore_enabled: bool,
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

    stdout_is_being_redirected_to_dev_null: bool,

    injector:       Arc<Injector<WorkItem>>,
    running:        Arc<AtomicBool>,
    active_workers: Arc<AtomicUsize>,

    running_signal: Arc<(Mutex<()>, Condvar)>,    // notified when `running` flips false
    job_done:       Arc<(Mutex<usize>, Condvar)>, // counts workers still owing a finish for this job

    wake:           Arc<(Mutex<u64>, Condvar)>,
    current_job:    Arc<RwLock<Option<Arc<SearchJob<S>>>>>,

    output_tx:      Sender<OutputMessage>,
    flush_ack_rx:   Arc<Mutex<Receiver<()>>>,

    _cursor_hide_for_tty: Option<CursorHide>
}

impl<S: MatchSink + 'static> RawGrepCtx<S> {
    #[inline]
    pub fn new(num_threads: usize, running: Arc<AtomicBool>) -> Self {
        let plumbing = setup_output_plumbing();

        let ctx = Self {
            injector: Arc::default(),
            running,
            active_workers: Arc::default(),
            job_done: Arc::default(),
            running_signal: Arc::default(),
            wake: Arc::default(),
            _cursor_hide_for_tty: plumbing.cursor_hide,
            current_job: Arc::default(),
            output_tx: plumbing.output_tx,
            worker_count: num_threads,
            stdout_is_being_redirected_to_dev_null: plumbing.stdout_is_being_redirected_to_dev_null,
            flush_ack_rx: plumbing.flush_ack_rx,
        };

        ctx.spawn_workers(num_threads, plumbing.output_kind);
        ctx
    }

    fn spawn_workers(&self, num_threads: usize, output_kind: OutputKind) {
        let mut local_workers = Vec::with_capacity(num_threads);
        let mut stealers      = Vec::with_capacity(num_threads);
        for _ in 0..num_threads {
            let w = DequeWorker::new_lifo();
            stealers.push(w.stealer());
            local_workers.push(w);
        }

        let mut slot_pools = SlotPool::new_for_workers(num_threads);
        let num_cores      = crate::util::num_physical_cores_or(num_threads);
        let pacer_enabled  = !self.stdout_is_being_redirected_to_dev_null && output_kind == OutputKind::Tty;
        let pacer          = Arc::new(FlushPacer::new(pacer_enabled));
        let stealers       = Arc::new(stealers);

        for (worker_id, local) in local_workers.into_iter().enumerate() {
            let ctx       = self.clone();
            let stealers  = stealers.clone();
            let pacer     = pacer.clone();
            let slot_pool = slot_pools.pop().unwrap();

            std::thread::spawn(move || {
                crate::util::pin_thread_to_core(worker_id % num_cores);
                worker_thread_main(worker_id as _, ctx, &stealers, local, &pacer, slot_pool);
            });
        }
    }

    /// For a process that will call `search()` exactly once. Builds the
    /// job and pushes the root work item before any worker thread exists,
    /// then pre-arms the wake generation to 1. Each thread's local
    /// last_gen starts at 0, so its very first wake check already sees
    /// the job as ready and skips cvar.wait entirely.
    ///
    /// If this ctx will ever be handed a second search, don't use this,
    /// there is nothing here that helps search #2 onward, use `new` +
    /// `search` instead.
    pub fn new_for_single_search(
        num_threads: usize,
        running: Arc<AtomicBool>,
        config: &RawGrepConfig,
        sink: S,
        inspect_before_search: impl FnOnce(&Path, &str, FsType, &str),
    ) -> Result<Self, Error> {
        let (job, work) = build_job_and_initial_work(config, sink, inspect_before_search)?;
        let plumbing = setup_output_plumbing();

        let ctx = Self {
            injector: Arc::new(Injector::new()),
            running,
            active_workers: Arc::default(),
            job_done: Arc::new((Mutex::new(num_threads), Condvar::new())),
            running_signal: Arc::default(),
            wake: Arc::new((Mutex::new(1u64), Condvar::new())),
            _cursor_hide_for_tty: plumbing.cursor_hide,
            current_job: Arc::new(RwLock::new(Some(Arc::new(job)))),
            output_tx: plumbing.output_tx,
            worker_count: num_threads,
            stdout_is_being_redirected_to_dev_null: plumbing.stdout_is_being_redirected_to_dev_null,
            flush_ack_rx: plumbing.flush_ack_rx,
        };

        ctx.injector.push(work);
        ctx.running.store(true, Ordering::SeqCst);

        ctx.spawn_workers(num_threads, plumbing.output_kind);
        Ok(ctx)
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
    pub fn wait_and_save_cache(&mut self, config: &RawGrepConfig) -> (Stats, Option<CacheStats>) {
        let stats = self.wait();

        self.save_cache(config);

        stats
    }

    #[inline]
    pub fn save_cache(&mut self, config: &RawGrepConfig) {
        debug!("[ctx] trying to save cache..");

        if config.no_cache_write {
            debug!("[ctx] cache is disabled, exiting..");
            return;
        }

        let mut guard = self.current_job.write();

        let Some(job_arc) = guard.as_mut() else {
            debug!("[ctx] self.job is None..");
            return;
        };
        let Some(job) = Arc::get_mut(job_arc) else {
            debug!("[ctx] couldn't get job unique pointer..");
            return;
        };

        let acc = job.cache_acc.lock();
        let file_keys         = &acc.file_keys;
        let file_metas        = &acc.file_metas;
        let fragment_presence = &acc.fragment_presence;

        let (fragment_hashes, cache) = job.grepper.fragment_hashes_and_cache_mut();

        if let Some(cache) = cache {
            match cache.merge_updates_if_changed(file_keys, file_metas, fragment_hashes, fragment_presence) {
                Ok(true) => {
                    _ = cache.save_to_disk();
                    debug!("[ctx] successfully saved cache");
                }

                Ok(false) => {
                    debug!("[ctx] cache batch unchanged, skipping merge+save..");
                }

                Err(e) => {
                    debug!("[ctx] merge_updates_if_changed failed: {e}");
                }
            }
        } else {
            debug!("job.grepper.cache is None... (pattern < 3 bytes)");
        }
    }

    /// Start a new search, cancelling any in-flight one.
    ///
    /// Returns immediately - results arrive via `sink`.
    /// Returns `Err` if setup (device detection, fs detection, path
    /// resolution) fails before any work starts.
    pub fn search(
        &self,
        config: &RawGrepConfig,
        sink: S,
        inspect_before_search: impl FnOnce(&Path, &str, FsType, &str) // (search root, device, fs, pattern)
    ) -> Result<(), Error> {
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

        let (job, work) = build_job_and_initial_work(config, sink, inspect_before_search)?;

        //
        // Swap in new job
        //
        {
            let mut guard = self.current_job.write();
            *guard = Some(job.into());
        }
        debug!("[ctx] job swapped in");

        self.injector.push(work);
        debug!("[ctx] root work item pushed to injector");

        self.running.store(true, Ordering::SeqCst);
        let (lock, cvar) = &*self.wake;
        {
            let mut _gen = lock.lock();
            *_gen = _gen.wrapping_add(1);
        }
        cvar.notify_all();
        debug!("[ctx] running=true, all workers notified");

        Ok(())
    }
}

fn worker_thread_main<S: MatchSink + 'static>(
    worker_id: u16,
    ctx:       RawGrepCtx<S>,
    stealers:  &[Stealer<WorkItem>],
    local:     DequeWorker<WorkItem>,
    pacer:     &FlushPacer,
    slot_pool: SlotPool,
) {
    debug!("[ctx] worker {worker_id} started, waiting on condvar");

    // Parser buffers are owned by the thread and reused across searches,
    // saving allocations on every search restart.
    let mut parser                    = Parser::new(false);
    let mut path_buf                  = Box::new(SmallPathBuf::new());
    let mut swap_path_buf             = Box::new(SmallPathBuf::new());
    let mut newlines_scratch          = Vec::new();
    let mut ranges_scratch            = Vec::with_capacity(64); // @Speed @Note: If this reallocates we're gonna be really sad.
    let mut line_ranges_scratch       = Vec::with_capacity(64); // @Speed @Note: If this reallocates we're gonna be really sad.
    let mut fragment_presence_scratch = Vec::with_capacity(16);
    let mut path_arena                = PathArena::new();
    let mut file_entries_arena        = FileEntryArena::new();
    let mut subdirs_arena             = SubdirsArena::new();
    let mut entries_arena             = EntriesArena::new();
    let mut output                    = SlotWriter::new(slot_pool, ctx.output_tx.clone());

    let mut matcher_cache             = None;

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

        let cli = job.grepper.cli();

        //
        // Reset the buffers
        //
        unsafe { path_buf.set_len(0); }
        unsafe { swap_path_buf.set_len(0); }
        newlines_scratch.clear();
        ranges_scratch.clear();
        subdirs_arena.clear();
        path_arena.clear();
        entries_arena.clear();
        parser.dont_skip_dot_entries = cli.hidden;
        if fragment_presence_scratch.is_empty() {
            let fragment_hash_count = job.grepper.fragment_hashes().len();
            fragment_presence_scratch.resize(fragment_hash_count.div_ceil(64), 0);
            fragment_presence = FragmentPresenceBits::new(fragment_hash_count);
        }
        if matcher_cache.is_none() {
            matcher_cache = Some(job.grepper.matcher().create_cache().unwrap());
        }

        macro_rules! dispatch {
            ($g:expr) => {
                WorkerCtx {
                    worker_id,
                    cache:            $g.cache(),
                    stdout_is_being_redirected_to_dev_null: ctx.stdout_is_being_redirected_to_dev_null,
                    fragment_hashes:  $g.fragment_hashes(),
                    fs:               $g.fs(),
                    matcher:          $g.matcher(),
                    fragment_index:   $g.fragment_index(),
                    selected_fragment_hash_len: $g.selected_fragment_hash_len(),
                    cli:              $g.cli(),
                    sink:             $g.sink.clone(),
                    output_tx:        ctx.output_tx.clone(),
                    stats:            Default::default(),
                    pacer,
                    output,
                    parser,
                    path_buf,
                    swap_path_buf,
                    matcher_cache: matcher_cache.as_mut(),
                    gitignore_enabled: job.gitignore_enabled,
                    entries_arena,
                    subdirs_arena,
                    newlines_scratch,
                    line_ranges_scratch,
                    ranges_scratch,
                    path_arena,
                    file_entries_arena,
                    fragment_presence_scratch,

                    batch_size_cached: 0,
                    check_mask: 0x001F,
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
        let mut result = match &job.grepper {
            AnyGrepper::Ext4(g) => dispatch!(g),
            AnyGrepper::Apfs(g) => dispatch!(g),
            AnyGrepper::Ntfs(g) => dispatch!(g),
        };

        parser = result.parser;
        file_entries_arena = result.file_entries_arena;
        subdirs_arena = result.subdirs_arena;
        entries_arena = result.entries_arena;
        path_arena = result.path_arena;
        newlines_scratch = result.newlines_scratch;
        ranges_scratch = result.ranges_scratch;
        line_ranges_scratch = result.line_ranges_scratch;
        fragment_presence_scratch = result.fragment_presence_scratch;
        path_buf = result.path_buf;
        swap_path_buf = result.swap_path_buf;
        output = result.output;
        result.stats.merge_into(&job.stats);

        debug!(
            "[ctx] worker {worker_id} search #{search_count} done - \
             files_encountered={} files_searched={} files_with_matches={} slot_pool_spill_count={}",
            result.stats.files_encountered,
            result.stats.files_searched,
            result.stats.files_contained_matches,
            output.pool.spill_count()
        );

        // Deposit cache data
        if !cli.no_cache_write && !cli.no_cache {
            let mut acc = job.cache_acc.lock();
            acc.file_keys.append(&mut result.file_keys);
            acc.file_metas.append(&mut result.file_metas);
            acc.fragment_presence.append(&mut result.fragment_presence.words);
        }

        file_keys         = result.file_keys;
        file_metas        = result.file_metas;
        fragment_presence = result.fragment_presence;

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

// Shared job-building logic, pulled out of search() unchanged in behavior.
fn build_job_and_initial_work<S: MatchSink + 'static>(
    config: &RawGrepConfig,
    sink: S,
    inspect_before_search: impl FnOnce(&Path, &str, FsType, &str),
) -> Result<(SearchJob<S>, WorkItem), Error> {
    let cli = config.to_cli();
    _ = cli::SHOULD_ENABLE_ANSI_COLORING.set(!config.no_color);

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
        None    => platform::detect_partition_for_path(&search_root)
            .map(Into::into)
            .map_err(Error::DeviceDetectionFailed)?,
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

    //
    // Called after grepper is built, before workers wake
    //
    inspect_before_search(&search_root, &device, fs_type, &cli.pattern);

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

    let gitignore_enabled = !config.no_ignore
        && (config.no_require_git || crate::find_git_boundary(&search_root));

    //
    // Setup output channel and gitignore
    //

    let root_gitignore = gitignore_enabled.then(|| {
        let gi_path = search_root.join(".gitignore");
        ignore::build_gitignore_from_file(&gi_path.to_string_lossy())
    }).flatten();

    debug!("[ctx] root_gitignore present={}", root_gitignore.is_some());

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

    let job = SearchJob {
        grepper,
        gitignore_enabled,
        device:    device.clone(),
        stats:     Default::default(),
        cache_acc: Default::default(),
    };

    Ok((job, work))
}

struct OutputPlumbing {
    output_tx:    Sender<OutputMessage>,
    flush_ack_rx: Arc<Mutex<Receiver<()>>>,
    stdout_is_being_redirected_to_dev_null: bool,
    output_kind:  OutputKind,
    cursor_hide:  Option<CursorHide>,
}

fn setup_output_plumbing() -> OutputPlumbing {
    let (output_tx, output_rx)       = unbounded();
    let (flush_ack_tx, flush_ack_rx) = unbounded();

    let (raw_stdout, output_kind) = RawStdout::new();
    let stdout_is_being_redirected_to_dev_null = raw_stdout.is_none();

    let cursor_hide = if output_kind == OutputKind::Tty {
        CursorHide::new().ok()
    } else {
        None
    };

    if let Some((raw_stdout, _raw_fd)) = raw_stdout {
        _ = std::thread::spawn(move || {
            OutputWorker {
                rx: output_rx,
                flush_ack_tx,
                batch_bytes: 0,
                writer: raw_stdout,
                batch: Vec::with_capacity(256),
                iov_scratch: Vec::with_capacity(256),
            }.run();
        });
    }

    OutputPlumbing {
        output_tx,
        flush_ack_rx: Arc::new(Mutex::new(flush_ack_rx)),
        stdout_is_being_redirected_to_dev_null,
        output_kind,
        cursor_hide
    }
}
