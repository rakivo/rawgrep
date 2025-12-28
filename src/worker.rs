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
    BufFatPtr,
    BufKind,
    Ext4Context,
    Parser
};
use crate::util::{
    is_common_skip_dir, is_dot_entry,
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
use crate::ext4::{
    raw,
    Ext4Inode,
    INodeNum,
    EXT4_FT_DIR,
    EXT4_FT_REG_FILE,
    EXT4_S_IFDIR,
    EXT4_S_IFMT,
    EXT4_S_IFREG
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
    pub inode_num: INodeNum,
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

/// Result of scanning directory entries
#[allow(dead_code, reason = "@Incomplete")]
struct DirScanResult {
    file_count: u32,
    dir_count: u32,
    /// Pre-parsed entries to avoid re-parsing
    entries: SmallVec<[ParsedEntry; 64]>,
}

#[derive(Clone, Copy)]
struct ParsedEntry {
    inode: u32,
    name_offset: u16, // Offset into dir_buf
    name_len: u8,
    file_type: u8,
}

pub type WorkerResult = (Stats, Vec<FileKey>, Vec<FileMeta>, Vec<bool>);

pub struct WorkerContext<'a> {
    pub cache: Option<&'a FragmentCache>,     // 8 bytes
    pub fragment_hashes: &'a [u32],           // 16 bytes
    pub ext4: Ext4Context<'a>,                // 16 bytes
    pub matcher: &'a Matcher,                 // 8 bytes
    pub cli: &'a Cli,                         // 8 bytes
    // ----------- 56 bytes

    pub stats: Stats,
    pub buffers: Parser,

    pub path: SmallPathBuf,
    pub output_tx: Sender<Vec<u8>>,
    pub worker_id: u16,

    pub pending_file_keys: Vec<FileKey>,
    pub pending_file_metas: Vec<FileMeta>,
    pub pending_had_matches: Vec<bool>,
}

impl<'a> WorkerContext<'a> {
    #[inline(always)]
    fn init(&mut self) {
        let config = self.cli.get_buffer_config();
        self.buffers.init(&config)
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
        if !self.buffers.output.is_empty() {
            _ = self.output_tx.send(std::mem::replace(
                &mut self.buffers.output,
                //  @Constant
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

    #[inline(always)]
    const fn get_buf(&self, kind: BufKind) -> &Vec<u8> {
        match kind {
            BufKind::File      => &self.buffers.file,
            BufKind::Dir       => &self.buffers.dir,
            BufKind::Gitignore => &self.buffers.gitignore,
        }
    }
}

// impl block of the core logic
impl WorkerContext<'_> {
    pub fn dispatch_directory(
        &mut self,
        mut work: DirWork,
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
    ) -> io::Result<()> {
        let _span = tracy::span!("process_directory_with_stealing");

        self.path.clear();
        self.path.extend_from_slice(&work.path_bytes);

        let Ok(inode) = Parser::parse_inode(work.inode_num, &self.ext4) else {
            return Ok(());
        };

        if unlikely((inode.mode & EXT4_S_IFMT) != EXT4_S_IFDIR) {
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

        let dir_size = inode.size as usize;
        self.buffers.read_file_into_buf(&inode, dir_size, BufKind::Dir, false, &self.ext4)?;
        self.stats.dirs_encountered += 1;

        let gitignore_chain = self.cli.should_ignore_gitignore().not().then(|| {
            self.find_gitignore_inode_in_buf(BufKind::Dir).and_then(|gi_inode|
                self.try_load_gitignore(gi_inode)
            ).map(|gi| {
                let old_gi = mem::take(&mut work.gitignore_chain);
                old_gi.with_gitignore(work.depth, gi)
            })
        }).flatten().unwrap_or_else(|| work.gitignore_chain.clone());

        let scan = self.scan_directory_entries();

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
        entries: &[ParsedEntry],
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
    ) -> io::Result<()> {
        let _span = tracy::span!("process_small_directory_with_entries");

        // @Constant
        let mut subdirs = SmallVec::<[DirWork; 16]>::new();
        let needs_slash = !work.path_bytes.is_empty();
        let parent_path_len = work.path_bytes.len();

        // @Constant
        let mut file_entries: SmallVec<[_; 64]> = SmallVec::new();

        for entry in entries {
            let name_bytes = unsafe {
                self.buffers.dir.get_unchecked(
                    entry.name_offset as usize..entry.name_offset as usize + entry.name_len as usize
                )
            };

            let ft = match entry.file_type {
                1 => EXT4_S_IFREG,
                2 => EXT4_S_IFDIR,
                0 => {
                    // Unknown - parse inode..
                    let Ok(child_inode) = Parser::parse_inode(entry.inode, &self.ext4) else {
                        continue;
                    };
                    child_inode.mode & EXT4_S_IFMT
                }
                _ => continue,
            };

            match ft {
                EXT4_S_IFDIR => {
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
                        inode_num: entry.inode,
                        path_bytes: crate::util::smallvec_into_arc_slice_noshrink(child_path),
                        gitignore_chain: gitignore_chain.clone(),
                        depth: work.depth + 1,
                    });
                }
                EXT4_S_IFREG => {
                    file_entries.push((entry.inode, BufFatPtr {
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
        /// At shallow depths: push more for parallelism
        /// At deep depths: keep more for cache locality
        #[inline]
        fn work_distribution_strategy(depth: u16, subdir_count: usize) -> usize {
            if subdir_count == 0 {
                return 0;
            }

            // @Constant
            match depth {
                0..=1 => 1,                           // Root level: push almost everything
                2..=3 => subdir_count.min(2),         // Shallow: keep 2
                4..=6 => subdir_count.min(4),         // Medium: keep more
                _ => subdir_count.min(8),             // Deep: keep most for locality
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

    fn scan_directory_entries(&self) -> DirScanResult {
        let _span = tracy::span!("scan_directory_entries");

        let mut file_count = 0;
        let mut dir_count = 0;
        let mut entries = SmallVec::new();
        let mut offset = 0;

        let entry_size = mem::size_of::<raw::Ext4DirEntry2>();

        while offset + entry_size <= self.buffers.dir.len() {
            let entry = match bytemuck::try_from_bytes::<raw::Ext4DirEntry2>(
                &self.buffers.dir[offset..offset + entry_size]
            ) {
                Ok(e) => e,
                Err(_) => break,
            };

            let entry_inode = u32::from_le(entry.inode);
            let rec_len = u16::from_le(entry.rec_len);
            let name_len = entry.name_len;
            let file_type = entry.file_type;

            if unlikely(rec_len == 0) {
                break;
            }

            if likely(entry_inode != 0 && name_len > 0) {
                let name_start = offset + entry_size;
                let name_end = name_start + name_len as usize;

                if name_end <= offset + rec_len as usize && name_end <= self.buffers.dir.len() {
                    // SAFETY: bounds checked above
                    let name_bytes = unsafe {
                        self.buffers.dir.get_unchecked(name_start..name_end)
                    };

                    if !is_dot_entry(name_bytes) {
                        entries.push(ParsedEntry {
                            inode: entry_inode,
                            name_offset: name_start as u16,
                            name_len,
                            file_type,
                        });

                        match file_type {
                            EXT4_FT_DIR => dir_count += 1,
                            EXT4_FT_REG_FILE => file_count += 1,
                            0 => {
                                // Unknown type - will resolve later
                                // Count as file for threshold purposes
                                file_count += 1;
                            }
                            _ => {}
                        }
                    }
                }
            }

            offset += rec_len as usize;
        }

        DirScanResult { file_count, dir_count, entries }
    }

    fn process_files(
        &mut self,
        files: &[(INodeNum, BufFatPtr)], // (inode_num, name_fat_ptr)
        parent_path: &[u8],
        gitignore_chain: &GitignoreChain,
    ) -> io::Result<()> {
        if files.is_empty() {
            return Ok(());
        }

        let _span = tracy::span!("process_files_pipelined");

        if let Some(&(first_inode_num, _)) = files.first() {
            if let Ok(inode) = Parser::parse_inode(first_inode_num, &self.ext4) {
                let size = (inode.size as usize).min(self.max_file_byte_size());
                self.buffers.prefetch_inode_data(&inode, size, &self.ext4);
            }
        }

        for i in 0..files.len() {
            let (inode_num, name_fat_ptr) = files[i];

            // Prefetch NEXT file while we process current (SSD parallel requests)
            if i + 1 < files.len() {
                let (next_inode_num, _) = files[i + 1];
                if let Ok(next_inode) = Parser::parse_inode(next_inode_num, &self.ext4) {
                    let size = (next_inode.size as usize).min(self.max_file_byte_size());
                    self.buffers.prefetch_inode_data(&next_inode, size, &self.ext4);
                }
            }

            let Ok(inode) = Parser::parse_inode(inode_num, &self.ext4) else {
                continue;
            };

            self.process_file(&inode, name_fat_ptr, parent_path, gitignore_chain)?;

            if self.buffers.output.len() > WORKER_FLUSH_BATCH {
                self.flush_output();
            }
        }

        Ok(())
    }

    fn process_file(
        &mut self,
        inode: &Ext4Inode,
        file_name_ptr: BufFatPtr,
        parent_path: &[u8],
        gitignore_chain: &GitignoreChain,
    ) -> io::Result<()> {
        let _span = tracy::span!("WorkerContext::process_file_not_batch");

        self.stats.files_encountered += 1;

        if !self.cli.should_ignore_all_filters() && inode.size > self.max_file_byte_size() as u64 {
            self.stats.files_skipped_large += 1;
            return Ok(());
        }

        let file_name = self.buffers.buf_ptr(file_name_ptr);

        if !self.cli.should_search_binary() && is_binary_ext(file_name) {
            self.stats.files_skipped_as_binary_due_to_ext += 1;
            return Ok(());
        }

        // Build full path
        // @Refactor @Cutnpaste from above
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
                FileKey::new(self.ext4.device_id, inode.inode_num),
                FileMeta::new(inode.mtime_sec, inode.size),
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

        let size = (inode.size as usize).min(self.max_file_byte_size());

        if self.buffers.read_file_into_buf(inode, size, BufKind::File, !self.cli.should_search_binary(), &self.ext4)? {
            self.stats.files_searched += 1;
            self.stats.bytes_searched += self.buffers.file.len();

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
        let buf = &self.buffers.file;
        let buf_len = buf.len();

        if buf_len == 0 {
            return Ok(false);
        }

        let should_print_color = should_enable_ansi_coloring();

        // @Constant @Tune
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
                // ------------ FIRST MATCH IN FILE - do lazy initialization
                if !found_any {
                    found_any = true;

                    // @Constant
                    let needed = 4096 + buf_len.min(32 * 1024);
                    if self.buffers.output.capacity() - self.buffers.output.len() < needed {
                        self.buffers.output.reserve(needed);
                    }

                    if !self.cli.jump {
                        if should_print_color {
                            self.buffers.output.extend_from_slice(COLOR_GREEN.as_bytes());
                        }
                        {
                            let root = self.cli.search_root_path.as_bytes();
                            let ends_with_slash = root.last() == Some(&b'/');
                            self.buffers.output.extend_from_slice(root);
                            if !ends_with_slash {
                                self.buffers.output.push(b'/');
                            }
                            self.buffers.output.extend_from_slice(&self.path);
                        }
                        if should_print_color {
                            self.buffers.output.extend_from_slice(COLOR_RESET.as_bytes());
                        }
                        self.buffers.output.extend_from_slice(b":\n");
                    }
                }

                if self.cli.jump {
                    if should_print_color {
                        self.buffers.output.extend_from_slice(COLOR_GREEN.as_bytes());
                    }

                    // @Cutnpaste from above
                    {
                        let root = self.cli.search_root_path.as_bytes();
                        let ends_with_slash = root.last() == Some(&b'/');
                        self.buffers.output.extend_from_slice(root);
                        if !ends_with_slash {
                            self.buffers.output.push(b'/');
                        }
                        self.buffers.output.extend_from_slice(&self.path);
                    }

                    if should_print_color {
                        self.buffers.output.extend_from_slice(COLOR_RESET.as_bytes());
                    }

                    self.buffers.output.extend_from_slice(b":");
                }

                if should_print_color {
                    self.buffers.output.extend_from_slice(COLOR_CYAN.as_bytes());
                }

                let line_num = line_num_buf.format(line_num);
                self.buffers.output.extend_from_slice(line_num.as_bytes());
                if should_print_color {
                    self.buffers.output.extend_from_slice(COLOR_RESET.as_bytes());
                }
                self.buffers.output.extend_from_slice(b": ");

                let display = truncate_utf8(line, 500);
                let mut last = 0;

                for (s, e) in iter {
                    if s >= display.len() { break; }

                    let e = e.min(display.len());

                    self.buffers.output.extend_from_slice(&display[last..s]);
                    if should_print_color {
                        self.buffers.output.extend_from_slice(COLOR_RED.as_bytes());
                    }
                    self.buffers.output.extend_from_slice(&display[s..e]);
                    if should_print_color {
                        self.buffers.output.extend_from_slice(COLOR_RESET.as_bytes());
                    }
                    last = e;
                }

                self.buffers.output.extend_from_slice(&display[last..]);
                self.buffers.output.push(b'\n');
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
impl WorkerContext<'_> {
    #[inline]
    fn try_load_gitignore(&mut self, gi_inode_num: INodeNum) -> Option<Gitignore> {
        let _span = tracy::span!("WorkerContext::try_load_gitignore");

        if let Ok(gi_inode) = Parser::parse_inode(gi_inode_num, &self.ext4) {
            let size = (gi_inode.size as usize).min(self.max_file_byte_size());
            if likely(self.buffers.read_file_into_buf(&gi_inode, size, BufKind::Gitignore, true, &self.ext4).is_ok()) {
                let matcher = crate::ignore::build_gitignore_from_bytes(
                    &self.buffers.gitignore
                );
                return Some(matcher)
            }
        }

        None
    }

    #[inline]
    fn find_gitignore_inode_in_buf(&self, kind: BufKind) -> Option<INodeNum> {
        let _span = tracy::span!("WorkerContext::find_gitignore_inode_in_buf");

        let mut offset = 0;

        while offset + 8 <= self.get_buf(kind).len() {
            let entry_inode = INodeNum::from_le_bytes([
                self.get_buf(kind)[offset + 0],
                self.get_buf(kind)[offset + 1],
                self.get_buf(kind)[offset + 2],
                self.get_buf(kind)[offset + 3],
            ]);
            let rec_len = u16::from_le_bytes([
                self.get_buf(kind)[offset + 4],
                self.get_buf(kind)[offset + 5]
            ]);
            let name_len = self.get_buf(kind)[offset + 6];

            if unlikely(rec_len == 0) {
                break;
            }

            // @Quickcheck: .gitignore is exactly 10 bytes
            if entry_inode != 0 && name_len == 10 {
                let name_end = offset + 8 + 10;
                if name_end <= offset + rec_len as usize &&
                    name_end <= self.get_buf(kind).len()
                {
                    let name_bytes = &self.get_buf(kind)[offset + 8..name_end];
                    if name_bytes == b".gitignore" {
                        return Some(entry_inode);
                    }
                }
            }

            offset += rec_len as usize;
        }

        None
    }
}

impl WorkerContext<'_> {
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
                        // Double-check
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
        let start = if *consecutive_steals < 3 { // @Constant @Tune
            (self.worker_id as usize + 1) % stealers.len()
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
