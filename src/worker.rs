// PINNED TODOs:
//   TODO(#28): Daemon mode
//
// TODO(#1): Implement symlinks
// TODO(#24): Support for searching in large file(s). (detect that)

use crate::cache::{FileKey, FileMeta, FragmentCache};
use crate::cli::{should_enable_ansi_coloring, Cli};
use crate::ignore::{Gitignore, GitignoreChain};
use crate::matcher::Matcher;
use crate::binary::is_binary_ext;
use crate::path_buf::SmallPathBuf;
use crate::stats::Stats;
use crate::parser::{
    BufFatPtr, BufKind, FileId, FileNode, FileType, ParsedEntry, Parser, RawFs
};
use crate::util::{
    is_common_skip_dir,
    likely, unlikely,
    truncate_utf8,
};
use crate::{
    tracy,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_RED,
    COLOR_RESET
};

use std::mem;
use std::ops::Not;
use std::sync::Arc;
use std::time::Duration;
use std::io::{self, BufWriter, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use smallvec::SmallVec;
use crossbeam_channel::{Receiver, Sender};
use crossbeam_deque::{Injector, Steal, Stealer, Worker as DequeWorker};

pub const LARGE_DIR_THRESHOLD: usize = 256; // Split dirs with 1000+ entries @Tune
pub const FILE_BATCH_SIZE: usize = 64; // Process files in batches of 500 @Tune

pub const WORKER_FLUSH_BATCH: usize = 16 * 1024; // @Tune
pub const OUTPUTTER_FLUSH_BATCH: usize = 16 * 1024; // @Tune

pub const BINARY_CONTROL_COUNT: usize = 51; // @Tune
pub const BINARY_PROBE_BYTE_SIZE: usize = 0x1000; // @Tune

pub const MAX_EXTENTS_UNTIL_SPILL: usize = 64; // @Tune

pub const __MAX_FILE_BYTE_SIZE: usize = 8 * 1024 * 1024; // @Tune

pub enum WorkItem {
    Directory(DirWork)
}

pub struct DirWork {
    pub file_id: FileId,
    pub path_bytes: Arc<[u8]>,
    pub gitignore_chain: GitignoreChain,
    pub depth: u16
}

pub struct OutputWorker {
    pub rx: Receiver<Vec<u8>>,
    pub writer: BufWriter<io::Stdout>,
}

impl OutputWorker {
    #[inline]
    pub fn run(mut self) {
        let _span = tracy::span!("OutputThread::run");

        while let Ok(buf) = self.rx.recv() {
            _ = self.writer.write_all(&buf);

            if self.writer.buffer().len() > OUTPUTTER_FLUSH_BATCH {
                _ = self.writer.flush();
            }
        }

        _ = self.writer.flush();
    }
}

pub type WorkerResult = (Stats, Vec<FileKey>, Vec<FileMeta>, Vec<bool>);

pub struct WorkerContext<'a, F: RawFs> {
    pub cache: Option<&'a FragmentCache>,
    pub fragment_hashes: &'a [u32],
    pub fs: &'a F,
    pub matcher: &'a Matcher,
    pub cli: &'a Cli,

    pub stats: Stats,
    pub parser: Parser,

    pub path: SmallPathBuf,
    pub output_tx: Sender<Vec<u8>>,
    pub worker_id: u16,

    pub pending_file_keys: Vec<FileKey>,
    pub pending_file_metas: Vec<FileMeta>,
    pub pending_had_matches: Vec<bool>,
}

impl<F: RawFs> WorkerContext<'_, F> {
    #[inline(always)]
    fn init(&mut self) {
        let config = self.cli.get_buffer_config();
        self.parser.init(&config)
    }

    #[inline(always)]
    fn finish(mut self) -> WorkerResult {
        self.flush_output();
        (
            self.stats,
            self.pending_file_keys,
            self.pending_file_metas,
            self.pending_had_matches
        )
    }

    #[inline(always)]
    pub fn flush_output(&mut self) {
        if !self.parser.output.is_empty() {
            _ = self.output_tx.send(std::mem::replace(
                &mut self.parser.output,
                Vec::with_capacity(64 * 1024)
            ));
        }
    }

    #[inline(always)]
    const fn max_file_byte_size(&self) -> usize {
        if self.cli.should_ignore_size_filter() {
            usize::MAX
        } else {
            __MAX_FILE_BYTE_SIZE
        }
    }
}

// impl block of the core logic
impl<F: RawFs> WorkerContext<'_, F> {
    pub fn dispatch_directory(
        &mut self,
        mut work: DirWork,
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
    ) -> io::Result<()> {
        let _span = tracy::span!("process_directory_with_stealing");

        self.path.clear();
        self.path.extend_from_slice(&work.path_bytes);

        let Ok(node) = self.fs.parse_node(work.file_id) else {
            return Ok(());
        };

        if unlikely(!node.is_dir()) {
            return Ok(());
        }

        if likely(!work.path_bytes.is_empty()) {
            let last_segment = work.path_bytes
                .iter()
                .rposition(|&b| b == b'/')
                .map(|pos| &work.path_bytes[pos + 1..])
                .unwrap_or(&work.path_bytes);

            if is_common_skip_dir(last_segment) {
                self.stats.dirs_skipped_common += 1;
                return Ok(());
            }
        }

        let dir_size = node.size() as usize;
        self.fs.read_file_content(&mut self.parser, &node, dir_size, BufKind::Dir, false)?;
        self.stats.dirs_encountered += 1;

        let gitignore_chain = self.cli.should_ignore_gitignore().not().then(|| {
            self.find_gitignore_file_id_in_buf(BufKind::Dir).and_then(|gi_file_id|
                self.try_load_gitignore(gi_file_id)
            ).map(|gi| {
                let old_gi = mem::take(&mut work.gitignore_chain);
                old_gi.with_gitignore(work.depth, gi)
            })
        }).flatten().unwrap_or_else(|| work.gitignore_chain.clone());

        let scan = self.parser.scan_directory_entries(self.fs);

        self.process_directory(
            work,
            gitignore_chain,
            &scan.entries,
            local,
            injector,
        )?;

        Ok(())
    }

    fn process_directory(
        &mut self,
        work: DirWork,
        gitignore_chain: GitignoreChain,
        entries: &[ParsedEntry<FileId>],
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
    ) -> io::Result<()> {
        let _span = tracy::span!("process_small_directory_with_entries");

        let mut subdirs = SmallVec::<[DirWork; 16]>::new();
        let needs_slash = !work.path_bytes.is_empty();
        let parent_path_len = work.path_bytes.len();

        let mut file_entries: SmallVec<[_; 64]> = SmallVec::new();

        for entry in entries {
            let name_bytes = unsafe {
                self.parser.dir.get_unchecked(
                    entry.name_offset as usize..entry.name_offset as usize + entry.name_len as usize
                )
            };

            let ft = match entry.file_type {
                FileType::Other => {
                    // Unknown - parse node to get type
                    let Ok(child_node) = self.fs.parse_node(entry.file_id) else {
                        continue;
                    };
                    if child_node.is_dir() {
                        FileType::Dir
                    } else {
                        FileType::File
                    }
                }
                x => x
            };

            match ft {
                FileType::Dir => {
                    if is_common_skip_dir(name_bytes) {
                        continue;
                    }

                    let mut child_path: SmallVec<[u8; 512]> = SmallVec::new();
                    child_path.reserve_exact(
                        parent_path_len + needs_slash as usize + entry.name_len as usize
                    );
                    child_path.extend_from_slice(&work.path_bytes);
                    if needs_slash {
                        child_path.push(b'/');
                    }
                    child_path.extend_from_slice(name_bytes);

                    if !self.cli.should_ignore_gitignore() && !gitignore_chain.is_empty() {
                        if gitignore_chain.is_ignored(&child_path, true) {
                            self.stats.dirs_skipped_gitignore += 1;
                            continue;
                        }
                    }

                    subdirs.push(DirWork {
                        file_id: entry.file_id,
                        path_bytes: crate::util::smallvec_into_arc_slice_noshrink(child_path),
                        gitignore_chain: gitignore_chain.clone(),
                        depth: work.depth + 1,
                    });
                }

                FileType::File => {
                    file_entries.push((entry.file_id, BufFatPtr {
                        offset: entry.name_offset as _,
                        kind: BufKind::Dir,
                        len: entry.name_len as _
                    }));
                }

                _ => {}
            }
        }

        self.process_files(&file_entries, &work.path_bytes, &gitignore_chain)?;

        /// Decide how many subdirs to keep local vs push for stealing
        #[inline]
        fn work_distribution_strategy(depth: u16, subdir_count: usize) -> usize {
            if subdir_count == 0 {
                return 0;
            }

            match depth {
                0..=1 => 1,
                2..=3 => subdir_count.min(2),
                4..=6 => subdir_count.min(4),
                _ => subdir_count.min(8),
            }
        }

        let keep_local = work_distribution_strategy(work.depth, subdirs.len());
        for subdir in subdirs.drain(keep_local..).rev() {
            local.push(WorkItem::Directory(subdir));
        }

        for subdir in subdirs {
            self.dispatch_directory(subdir, local, injector)?;
        }

        Ok(())
    }

    fn process_files(
        &mut self,
        files: &[(FileId, BufFatPtr)],
        parent_path: &[u8],
        gitignore_chain: &GitignoreChain,
    ) -> io::Result<()> {
        if files.is_empty() {
            return Ok(());
        }

        let _span = tracy::span!("process_files");

        if let Some(&(first_file_id, _)) = files.first() {
            if let Ok(node) = self.fs.parse_node(first_file_id) {
                let size = (node.size() as usize).min(self.max_file_byte_size());
                self.fs.prefetch_file(&mut self.parser, &node, size);
            }
        }

        for i in 0..files.len() {
            let (file_id, name_fat_ptr) = files[i];

            // Prefetch NEXT file while we process current
            if i + 1 < files.len() {
                let (next_file_id, _) = files[i + 1];
                if let Ok(next_node) = self.fs.parse_node(next_file_id) {
                    let size = (next_node.size() as usize).min(self.max_file_byte_size());
                    self.fs.prefetch_file(&mut self.parser, &next_node, size);
                }
            }

            let Ok(node) = self.fs.parse_node(file_id) else {
                continue;
            };

            self.process_file(&node, name_fat_ptr, parent_path, gitignore_chain)?;

            if self.parser.output.len() > WORKER_FLUSH_BATCH {
                self.flush_output();
            }
        }

        Ok(())
    }

    fn process_file(
        &mut self,
        node: &F::Node,
        file_name_ptr: BufFatPtr,
        parent_path: &[u8],
        gitignore_chain: &GitignoreChain,
    ) -> io::Result<()> {
        let _span = tracy::span!("WorkerContext::process_file_not_batch");

        self.stats.files_encountered += 1;

        if !self.cli.should_ignore_all_filters() && node.size() > self.max_file_byte_size() as u64 {
            self.stats.files_skipped_large += 1;
            return Ok(());
        }

        let file_name = self.parser.buf_ptr(file_name_ptr);

        if !self.cli.should_search_binary() && is_binary_ext(file_name) {
            self.stats.files_skipped_as_binary_due_to_ext += 1;
            return Ok(());
        }

        // Build full path
        {
            let _span = tracy::span!("build full path");

            self.path.clear();
            self.path.extend_from_slice(parent_path);
            if likely(!parent_path.is_empty()) {
                self.path.push(b'/');
            }
            self.path.extend_from_slice(file_name);
        }

        if !self.cli.should_ignore_gitignore() && !gitignore_chain.is_empty() {
            if gitignore_chain.is_ignored(self.path.as_ref(), false) {
                self.stats.files_skipped_gitignore += 1;
                return Ok(());
            }
        }

        let cache_key = if self.cache.is_some() {
            Some((
                FileKey::new(self.fs.device_id(), node.file_id()),
                FileMeta::new(node.mtime(), node.size()),
            ))
        } else {
            None
        };

        if let Some(cache) = self.cache {
            let (file_key, file_meta) = unsafe { cache_key.unwrap_unchecked() };
            if cache.can_skip_file(file_key, file_meta, self.fragment_hashes) {
                self.stats.files_skipped_by_cache += 1;
                return Ok(());
            }
        }

        let size = (node.size() as usize).min(self.max_file_byte_size());

        if self.fs.read_file_content(&mut self.parser, node, size, BufKind::File, !self.cli.should_search_binary())? {
            self.stats.files_searched += 1;
            self.stats.bytes_searched += self.parser.file.len();

            let had_matches = self.find_and_print_matches()?;

            if let Some((file_key, file_meta)) = cache_key {
                self.pending_file_keys.push(file_key);
                self.pending_file_metas.push(file_meta);
                self.pending_had_matches.push(had_matches);
            }
        } else {
            self.stats.files_skipped_as_binary_due_to_probe += 1;
        }

        Ok(())
    }

    #[inline]
    fn find_and_print_matches(&mut self) -> io::Result<bool> {
        let _span = tracy::span!("find_and_print_matches_fast");

        let mut found_any = false;
        let buf = &self.parser.file;
        let buf_len = buf.len();

        if buf_len == 0 {
            return Ok(false);
        }

        let should_print_color = should_enable_ansi_coloring();

        let newlines: SmallVec<[usize; 512]> = memchr::memchr_iter(b'\n', buf).collect();

        let mut line_start = 0;

        let mut line_num = 1;
        let mut line_num_buf = itoa::Buffer::new();

        let mut newline_idx = 0;
        loop {
            let line_end = if newline_idx < newlines.len() {
                newlines[newline_idx]
            } else {
                buf_len
            };

            let line = &buf[line_start..line_end];

            let mut iter = self.matcher.find_matches(line).peekable();

            if iter.peek().is_some() {
                if !found_any {
                    found_any = true;

                    let needed = 4096 + buf_len.min(32 * 1024);
                    if self.parser.output.capacity() - self.parser.output.len() < needed {
                        self.parser.output.reserve(needed);
                    }

                    if !self.cli.jump {
                        if should_print_color {
                            self.parser.output.extend_from_slice(COLOR_GREEN.as_bytes());
                        }
                        // @Cuntpaste from above
                        {
                            let root = self.cli.search_root_path.as_bytes();
                            let ends_with_slash = root.last() == Some(&b'/');
                            self.parser.output.extend_from_slice(root);
                            if !ends_with_slash {
                                self.parser.output.push(b'/');
                            }
                            self.parser.output.extend_from_slice(&self.path);
                        }
                        if should_print_color {
                            self.parser.output.extend_from_slice(COLOR_RESET.as_bytes());
                        }
                        self.parser.output.extend_from_slice(b":\n");
                    }
                }

                if self.cli.jump {
                    if should_print_color {
                        self.parser.output.extend_from_slice(COLOR_GREEN.as_bytes());
                    }

                    {
                        let root = self.cli.search_root_path.as_bytes();
                        let ends_with_slash = root.last() == Some(&b'/');
                        self.parser.output.extend_from_slice(root);
                        if !ends_with_slash {
                            self.parser.output.push(b'/');
                        }
                        self.parser.output.extend_from_slice(&self.path);
                    }

                    if should_print_color {
                        self.parser.output.extend_from_slice(COLOR_RESET.as_bytes());
                    }

                    self.parser.output.extend_from_slice(b":");
                }

                if should_print_color {
                    self.parser.output.extend_from_slice(COLOR_CYAN.as_bytes());
                }

                let line_num = line_num_buf.format(line_num);
                self.parser.output.extend_from_slice(line_num.as_bytes());
                if should_print_color {
                    self.parser.output.extend_from_slice(COLOR_RESET.as_bytes());
                }
                self.parser.output.extend_from_slice(b": ");

                let display = truncate_utf8(line, 500);
                let mut last = 0;

                for (s, e) in iter {
                    if s >= display.len() { break; }

                    let e = e.min(display.len());

                    self.parser.output.extend_from_slice(&display[last..s]);
                    if should_print_color {
                        self.parser.output.extend_from_slice(COLOR_RED.as_bytes());
                    }
                    self.parser.output.extend_from_slice(&display[s..e]);
                    if should_print_color {
                        self.parser.output.extend_from_slice(COLOR_RESET.as_bytes());
                    }
                    last = e;
                }

                self.parser.output.extend_from_slice(&display[last..]);
                self.parser.output.push(b'\n');
            }

            if line_end >= buf_len { break }
            line_start = line_end + 1;
            line_num += 1;
            newline_idx += 1;
        }

        if found_any {
            self.stats.files_contained_matches += 1;
        }

        Ok(found_any)
    }
}

/// impl block of gitignore helper functions
impl<F: RawFs> WorkerContext<'_, F> {
    #[inline]
    fn try_load_gitignore(&mut self, gi_file_id: FileId) -> Option<Gitignore> {
        let _span = tracy::span!("WorkerContext::try_load_gitignore");

        if let Ok(gi_node) = self.fs.parse_node(gi_file_id) {
            let size = (gi_node.size() as usize).min(self.max_file_byte_size());
            if likely(self.fs.read_file_content(&mut self.parser, &gi_node, size, BufKind::Gitignore, true).is_ok()) {
                let matcher = crate::ignore::build_gitignore_from_bytes(
                    &self.parser.gitignore
                );
                return Some(matcher)
            }
        }

        None
    }

    #[inline]
    fn find_gitignore_file_id_in_buf(&self, kind: BufKind) -> Option<FileId> {
        self.parser.find_file_id_in_buf(self.fs, b".gitignore", kind)
    }
}

impl<F: RawFs> WorkerContext<'_, F> {
    pub fn start_worker_loop(
        mut self,

        running: &AtomicBool,
        active_workers: &AtomicUsize,

        injector: &Injector<WorkItem>,
        stealers: &[Stealer<WorkItem>],
        local_worker: &DequeWorker<WorkItem>,
    ) -> WorkerResult {
        self.init();

        let mut consecutive_steals = 0;
        let mut idle_iterations = 0;

        loop {
            if !running.load(Ordering::Relaxed) {
                break;
            }

            let work = self.find_work(
                local_worker,
                injector,
                stealers,
                &mut consecutive_steals,
            );

            match work {
                Some(work_item) => {
                    idle_iterations = 0;
                    active_workers.fetch_add(1, Ordering::Release);

                    match work_item {
                        WorkItem::Directory(dir_work) => {
                            _ = self.dispatch_directory(
                                dir_work,
                                local_worker,
                                injector,
                            );
                        }
                    }

                    active_workers.fetch_sub(1, Ordering::Release);
                }

                None => {
                    idle_iterations += 1;

                    self.flush_output();

                    if active_workers.load(Ordering::Acquire) == 0 {
                        if injector.is_empty() && local_worker.is_empty() {
                            running.store(false, Ordering::Release);
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

        self.finish()
    }

    fn find_work(
        &self,
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
        stealers: &[Stealer<WorkItem>],
        consecutive_steals: &mut usize,
    ) -> Option<WorkItem> {
        // Local queue
        if let Some(work) = local.pop() {
            *consecutive_steals = 0;
            return Some(work);
        }

        // Global injector
        loop {
            match injector.steal_batch_and_pop(local) {
                Steal::Success(work) => {
                    *consecutive_steals = 0;
                    return Some(work);
                }
                Steal::Empty => break,
                Steal::Retry => continue,
            }
        }

        // Steal from others
        let start = if *consecutive_steals < 3 {
            (self.worker_id as usize + 1) % stealers.len() // @Constant @Tune
        } else {
            fastrand::usize(..stealers.len())
        };

        for i in 0..stealers.len() {
            let victim_id = (start + i) % stealers.len();
            if victim_id == self.worker_id as usize {
                continue;
            }

            loop {
                match stealers[victim_id].steal_batch_and_pop(local) {
                    crossbeam_deque::Steal::Success(work) => {
                        *consecutive_steals += 1;
                        return Some(work);
                    }
                    crossbeam_deque::Steal::Empty => break,
                    crossbeam_deque::Steal::Retry => continue,
                }
            }
        }

        None
    }
}
