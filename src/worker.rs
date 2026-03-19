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
    is_common_skip_dir, likely, truncate_utf8, unlikely
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
use std::path::MAIN_SEPARATOR;
use std::sync::Arc;
use std::time::Duration;
use std::io::{self, BufWriter, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use smallvec::{smallvec, SmallVec};
use bumpalo::collections::Vec as BumpVec;
use crossbeam_channel::{Receiver, Sender};
use crossbeam_deque::{Injector, Steal, Stealer};
pub use crossbeam_deque::Worker as DequeWorker;

//
// @Important @Note
//
// `STREAMING_THRESHOLD` must be AT LEAST more than ~800 bytes,
// so when we're gonna try to stream a file, we won't stumble upon
// an NTFS resident file (implementation details...).
//
pub const STREAMING_THRESHOLD: usize = 10 * 1024 * 1024; // 10MB @Tune

pub const STREAMING_CHUNK_SIZE: usize = 512 * 1024;      // 512KB read buffer @Tune

pub const LARGE_DIR_THRESHOLD: usize = 256; // Split dirs with 1000+ entries @Tune
pub const FILE_BATCH_SIZE: usize = 64; // Process files in batches of 500 @Tune

pub const WORKER_FLUSH_BATCH: usize = 16 * 1024; // @Tune
pub const OUTPUTTER_FLUSH_BATCH: usize = 16 * 1024; // @Tune

pub const BINARY_CONTROL_COUNT: usize = 51; // @Tune
pub const BINARY_PROBE_BYTE_SIZE: usize = 0x1000; // @Tune

pub const MAX_EXTENTS_UNTIL_SPILL: usize = 64; // @Tune

pub const __MAX_FILE_BYTE_SIZE: usize = 8 * 1024 * 1024; // @Tune

pub enum WorkItem {
    File(FileWork),
    Directory(DirWork)
}

pub struct FileWork {
    pub file_id: FileId,
    pub path_bytes: Arc<[u8]>,
    pub gitignore_chain: GitignoreChain,
}

pub struct DirWork {
    pub file_id: FileId,
    pub path_bytes: Arc<[u8]>,
    pub gitignore_chain: GitignoreChain,
    pub depth: u16
}


pub trait MatchSink: Send + Sync + Clone {
    const STDOUT_NOP: bool;

    fn push(&self, path: &[u8], line_num: u32, text: &[u8], ranges: &[(u32, u32)]);
}

#[derive(Copy, Clone)]
pub struct NoSink;

impl MatchSink for NoSink {
    const STDOUT_NOP: bool = false;

    #[inline(always)]
    fn push(&self, _: &[u8], _: u32, _: &[u8], _: &[(u32, u32)]) {}
}

#[derive(Debug)]
pub struct RawMatch {
    pub path:     Box<[u8]>,          // full file path
    pub line_num: u32,                // 1-indexed line number
    pub text:     Box<[u8]>,          // the matched line content
    pub ranges:   Box<[(u32, u32)]>,  // byte ranges of match spans within text
}

#[derive(Clone)]
pub struct ChannelSink(pub Sender<RawMatch>);

impl MatchSink for ChannelSink {
    const STDOUT_NOP: bool = true;

    #[inline(always)]
    fn push(
        &self,
        path:   &[u8],
        line_num: u32,
        text:   &[u8],
        ranges: &[(u32, u32)]
    ) {
        self.0.send(RawMatch {
            path:     path.into(),
            line_num,
            text:     text.into(),
            ranges:   ranges.into(),
        }).ok();
    }
}

pub struct CallbackSink<F>(pub Arc<F>);

impl<F> Clone for CallbackSink<F>
where
    F: Fn(&[u8], u32, &[u8], &[(u32, u32)]) + Send + Sync
{
    #[inline]
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<F> MatchSink for CallbackSink<F>
where
    F: Fn(&[u8], u32, &[u8], &[(u32, u32)]) + Send + Sync
{
    const STDOUT_NOP: bool = true;

    #[inline(always)]
    fn push(&self, path: &[u8], line_num: u32, text: &[u8], ranges: &[(u32, u32)]) {
        (self.0)(path, line_num, text, ranges);
    }
}


pub struct OutputWorker {
    pub rx: Receiver<&'static [u8]>,
    pub flush_req_rx: Receiver<()>,
    pub flush_ack_tx: Sender<()>,
    pub writer: BufWriter<io::Stdout>,
}

impl OutputWorker {
    #[inline]
    pub fn run(mut self) {
        let _span = tracy::span!("OutputThread::run");

        loop {
            crossbeam_channel::select! {
                recv(self.rx) -> msg => match msg {
                    Ok(buf) => {
                        _ = self.writer.write_all(buf);
                        if self.writer.buffer().len() > OUTPUTTER_FLUSH_BATCH {
                            _ = self.writer.flush();
                        }
                    }

                    Err(_) => break,
                },

                recv(self.flush_req_rx) -> _ => {
                    // Drain remaining output first
                    for buf in self.rx.try_iter() {
                        _ = self.writer.write_all(buf);
                    }

                    _ = self.writer.flush();
                    _ = self.flush_ack_tx.send(());
                }
            }
        }

        _ = self.writer.flush();
    }
}

/// Carry state for streaming match across chunk boundaries
pub struct ChunkCarry {
    /// Incomplete last line carried from previous chunk
    pub tail: Vec<u8>,
    pub combine_buf: Vec<u8>,
    /// Any matches was found so far in this file
    pub found_any: bool,
    /// Line number counter across chunks
    pub line_num: u32,
}

impl ChunkCarry {
    #[inline]
    pub fn new() -> Self {
        Self {
            tail: Vec::new(),
            combine_buf: Vec::new(),
            found_any: false,
            line_num: 1
        }
    }

    #[inline]
    pub fn reset(&mut self) {
        self.tail.clear();
        self.found_any = false;
        self.line_num = 1;
    }
}

pub struct WorkerResult<'a> {
    pub stats: Box<Stats>,

    pub parser: Parser<'a>,

    pub file_keys: Vec<FileKey>,
    pub file_metas: Vec<FileMeta>,

    pub path_buf: Box<SmallPathBuf>,
    pub newlines_scratch: Vec<u32>,  // Reused across `find_and_print_matches` calls
    pub ranges_scratch: Vec<(u32, u32)>,  // Reused across `find_and_print_matches` calls

    /// Per-fragment presence: fragment_presence[file_idx * fragment_count..(file_idx + 1) * fragment_count][frag_idx] = true if fragment is in file
    pub fragment_presence: Vec<bool>
}

pub struct WorkerContext<'a, 'output_arena, F: RawFs, S: MatchSink> {
    pub fs: &'a F,                            // 0
    pub cache: Option<&'a FragmentCache>,     // 8
    pub fragment_hashes: &'a [u32],           // 16
    pub matcher: &'a Matcher,                 // 32
    pub cli: &'a Cli,                         // 40

    pub parser: Parser<'output_arena>,        // 48, spans lines 0-3

    // =============== Cache line 4 ======================

    // Reused across `find_and_print_matches` calls
    pub newlines_scratch: Vec<u32>,           // 224
    pub ranges_scratch: Vec<(u32, u32)>,      // 248

    pub chunk_carry: Option<Box<ChunkCarry>>, // 272

    // =============== Cache line 5 ======================

    pub pending_file_keys: Vec<FileKey>,      // 280
    pub pending_file_metas: Vec<FileMeta>,    // 304
    pub pending_fragment_presence: Vec<bool>, // 328

    pub sink: S,                              // 352
    pub output_tx: Sender<&'static [u8]>,     // 360

    // =============== Cache line 6 ======================

    pub path_buf: Box<SmallPathBuf>,          // 368
    pub stats: Box<Stats>,                    // 376
    pub worker_id: u16,                       // 384
}

impl<'a, 'output_arena, F: RawFs, S: MatchSink> WorkerContext<'a, 'output_arena, F, S> {
    #[inline(always)]
    fn init(&mut self) {
        let config = self.cli.get_buffer_config();
        self.parser.init(&config);
        self.newlines_scratch.reserve(1024);  // 4KB @Tune @Constant
    }

    #[inline(always)]
    fn finish(mut self) -> WorkerResult<'output_arena> {
        self.flush_output();
        WorkerResult {
            stats: self.stats,
            parser: self.parser,
            path_buf: self.path_buf,
            ranges_scratch: self.ranges_scratch,
            newlines_scratch: self.newlines_scratch,
            file_keys: self.pending_file_keys,
            file_metas: self.pending_file_metas,
            fragment_presence: self.pending_fragment_presence
        }
    }

    #[inline(always)]
    pub fn flush_output(&mut self) {
        if S::STDOUT_NOP {
            self.parser.output.clear();
            return;
        }

        if self.parser.output.is_empty() {
            return;
        }

        _ = self.output_tx.send(unsafe {  // @Cleanup
            core::mem::transmute::<&[u8], &[u8]>(self.parser.output.as_slice())
        });
        self.parser.output.clear();
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
impl<F: RawFs, S: MatchSink> WorkerContext<'_, '_, F, S> {
    pub fn dispatch_directory(
        &mut self,
        mut work: DirWork,
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
    ) -> io::Result<()> {
        let _span = tracy::span!("process_directory_with_stealing");

        self.path_buf.clear();
        self.path_buf.extend_from_slice(&work.path_bytes);

        let Ok(node) = self.fs.parse_node(work.file_id) else {
            return Ok(());
        };

        if unlikely(!node.is_dir()) {
            return Ok(());
        }

        if likely(!work.path_bytes.is_empty()) {
            let last_segment = work.path_bytes
                .iter()
                .rposition(|&b| b == MAIN_SEPARATOR as _)
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

    #[inline]
    pub fn dispatch_file(&mut self, work: FileWork) -> io::Result<()> {
        let Ok(node) = self.fs.parse_node(work.file_id) else {
            return Ok(());
        };

        let name_offset = work.path_bytes
            .iter()
            .rposition(|&b| b == MAIN_SEPARATOR as u8)
            .map(|pos| pos + 1)
            .unwrap_or(0);

        let name_fat_ptr = BufFatPtr {
            offset: name_offset as _,
            kind: BufKind::File,
            len: (work.path_bytes.len() - name_offset) as _,
        };

        self.path_buf.clear();
        self.path_buf.extend_from_slice(&work.path_bytes);

        self.process_file(&node, name_fat_ptr, &work.path_bytes, &work.gitignore_chain)?;

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
                        child_path.push(MAIN_SEPARATOR as _);
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

        self.fs.sort_entries(&mut file_entries);

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

        for &(file_id, name_fat_ptr) in files {
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

            self.path_buf.clear();
            self.path_buf.extend_from_slice(parent_path);
            if likely(!parent_path.is_empty()) {
                self.path_buf.push(MAIN_SEPARATOR as _);
            }
            self.path_buf.extend_from_slice(file_name);
        }

        if !self.cli.should_ignore_gitignore() && !gitignore_chain.is_empty() {
            if gitignore_chain.is_ignored(self.path_buf.as_ref(), false) {
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

        let max_size = (node.size() as usize).min(self.max_file_byte_size());
        let check_binary = !self.cli.should_search_binary();

        let found_any = if likely(max_size < STREAMING_THRESHOLD) {
            self.process_file_buffered(node, max_size, check_binary)?
        } else {
            self.process_file_streaming(node, max_size, check_binary)?
        };

        if let Some((file_key, file_meta)) = cache_key {
            let presence = self.check_fragment_presence(found_any);

            self.pending_file_keys.push(file_key);
            self.pending_file_metas.push(file_meta);
            self.pending_fragment_presence.extend_from_slice(&presence);
        }

        Ok(())
    }

    #[inline]
    fn process_file_buffered(
        &mut self,
        node: &F::Node,
        max_size: usize,
        check_binary: bool,
    ) -> io::Result<bool> {
        let is_binary = !self.fs.read_file_content(
            &mut self.parser,
            node,
            max_size, BufKind::File, check_binary
        )?;
        if is_binary {
            self.stats.files_skipped_as_binary_due_to_probe += 1;
            return Ok(false);
        }

        self.stats.files_searched += 1;
        self.stats.bytes_searched += self.parser.file.len() as u64;

        self.find_and_print_matches(node.is_dir())
    }

    #[inline(never)]
    fn process_file_streaming(
        &mut self,
        node: &F::Node,
        max_size: usize,
        check_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("WorkerContext::process_file_streaming");

        let mut carry = self.chunk_carry.take().unwrap_or_else(|| ChunkCarry::new().into());
        carry.reset();

        let Some(chunks) = self.fs.collect_file_chunks(
            &mut self.parser.scratch,
            &mut self.parser.scratch2,
            node,
            max_size,
            check_binary,
        )? else {
            self.stats.files_skipped_as_binary_due_to_probe += 1;
            self.chunk_carry = Some(carry);
            return Ok(false);
        };

        let mut bytes_searched = 0usize;

        for (disk_offset, len) in &chunks {
            self.parser.chunk.resize(*len, 0);

            let n = match self.fs.read_at_offset(&mut self.parser.chunk[..*len], *disk_offset) {
                Ok(n) => n,
                Err(_) => break,
            };

            if n == 0 { break; }
            bytes_searched += n;

            carry.combine_buf.clear();
            carry.combine_buf.extend_from_slice(&carry.tail);
            carry.combine_buf.extend_from_slice(&self.parser.chunk[..n]);
            carry.tail.clear();

            let combined = std::mem::take(&mut carry.combine_buf);
            self.find_and_print_matches_in_chunk(&combined, &mut carry, false, node.is_dir())?;
            carry.combine_buf = combined;
        }

        // Flush final partial line (no trailing newline)
        if !carry.tail.is_empty() {
            let tail = std::mem::take(&mut carry.tail);
            self.find_and_print_matches_in_chunk(&tail, &mut carry, true, node.is_dir())?;
            carry.tail = tail;
            carry.tail.clear();
        }

        self.stats.files_searched += 1;
        self.stats.bytes_searched += bytes_searched as u64;

        if carry.found_any {
            self.stats.files_contained_matches += 1;
        }

        let found_any = carry.found_any;
        self.chunk_carry = Some(carry);
        Ok(found_any)
    }

    #[inline]
    fn check_fragment_presence(&self, had_matches: bool) -> SmallVec<[bool; 32]> {
        let _span = tracy::span!("check_fragment_presence");

        // ----- Fast path: if pattern matched, all pattern fragments must be present
        if had_matches {
            return smallvec![true; self.fragment_hashes.len()];
        }

        crate::fragments::check_fragment_presence(&self.parser.file, self.fragment_hashes)
    }
}

// impl block for printng matches
impl<F: RawFs, S: MatchSink> WorkerContext<'_, '_, F, S> {
    fn find_and_print_matches(&mut self, is_dir: bool) -> io::Result<bool> {
        let _span = tracy::span!("find_and_print_matches");

        let buf = &self.parser.file;
        let buf_len = buf.len();
        if buf_len == 0 { return Ok(false); }

        self.newlines_scratch.clear();
        self.newlines_scratch.extend(memchr::memchr_iter(b'\n', buf).map(|i| i as u32));

        let should_print_color = should_enable_ansi_coloring();

        let mut found_any = false;
        let mut line_start = 0;
        let mut line_num = 1u32;

        for &newline_pos in self
            .newlines_scratch
            .iter()
            .chain([&(buf_len as u32)])
        {
            let line_end = newline_pos as usize;
            let line = &buf[line_start..line_end];

            self.ranges_scratch.clear();
            self.ranges_scratch.extend(
                self.matcher.find_matches(line).map(|(s, e)| (s as u32, e as u32))
            );

            if !self.ranges_scratch.is_empty() {
                if !found_any {
                    //
                    // First match!!
                    //

                    found_any = true;
                    let needed = 4096 + buf_len.min(32 * 1024); // @Constant @Tune
                    if self.parser.output.capacity() - self.parser.output.len() < needed {
                        self.parser.output.reserve(needed);
                    }
                    Self::write_file_header(&mut self.parser.output, self.cli, &self.path_buf, should_print_color, is_dir);
                }

                Self::write_match_line(
                    &mut self.parser.output,
                    self.cli,
                    &self.path_buf,
                    line,
                    line_num,
                    self.ranges_scratch.iter().copied(),
                    should_print_color,
                );

                if S::STDOUT_NOP {  // @Memory
                    self.sink.push(self.path_buf.as_ref(), line_num as _, line, &self.ranges_scratch);
                }
            }

            if line_end >= buf_len { break }
            line_start = line_end + 1;
            line_num += 1;
        }

        if found_any {
            self.stats.files_contained_matches += 1;
        }

        Ok(found_any)
    }

    fn find_and_print_matches_in_chunk(
        &mut self,
        data: &[u8],
        carry: &mut ChunkCarry,
        is_last: bool,
        is_dir: bool
    ) -> io::Result<()> {
        let _span = tracy::span!("match_chunk");

        if data.is_empty() { return Ok(()); }

        let should_print_color = should_enable_ansi_coloring();

        let process_until = if is_last {
            data.len()
        } else {
            match memchr::memrchr(b'\n', data) {
                Some(pos) => pos + 1,
                None => {
                    carry.tail.clear();
                    carry.tail.extend_from_slice(data);
                    return Ok(());
                }
            }
        };

        self.newlines_scratch.clear();
        self.newlines_scratch.extend(memchr::memchr_iter(b'\n', data).map(|i| i as u32));

        let data_len = data.len();
        let mut line_start = 0usize;

        for &newline_pos in self
            .newlines_scratch
            .iter()
            .chain([&(process_until as u32)])
        {
            let line_end = newline_pos as usize;
            let line = &data[line_start..line_end];

            self.ranges_scratch.clear();
            self.ranges_scratch.extend(
                self.matcher.find_matches(line).map(|(s, e)| (s as u32, e as u32))
            );

            if !self.ranges_scratch.is_empty() {
                if !carry.found_any {  // @Cutnpaste from find_and_print_matches
                    //
                    // First match!!
                    //

                    carry.found_any = true;
                    let needed = 4096 + data_len.min(32 * 1024); // @Constant @tune
                    if self.parser.output.capacity() - self.parser.output.len() < needed {
                        self.parser.output.reserve(needed);
                    }
                    Self::write_file_header(&mut self.parser.output, self.cli, &self.path_buf, should_print_color, is_dir);
                }

                Self::write_match_line(
                    &mut self.parser.output,
                    self.cli,
                    &self.path_buf,
                    line,
                    carry.line_num,
                    self.ranges_scratch.iter().copied(),
                    should_print_color,
                );

                if S::STDOUT_NOP { // @Memory @Cutnpaste from find_and_print_matches
                    self.sink.push(self.path_buf.as_ref(), carry.line_num as _, line, &self.ranges_scratch);
                }
            }

            if line_end >= process_until { break; }
            line_start = line_end + 1;
            carry.line_num += 1;
        }

        carry.tail.clear();
        if !is_last && process_until < data.len() {
            carry.tail.extend_from_slice(&data[process_until..]);
        }

        Ok(())
    }

    #[inline(always)]
    fn write_match_line(
        output:            &mut BumpVec<u8>,
        cli:               &Cli,
        path:              &[u8],
        line:              &[u8],
        line_num:          u32,
        matches:           impl Iterator<Item = (u32, u32)>,
        should_print_color: bool,
    ) {
        if cli.jump {
            if should_print_color { output.extend_from_slice(COLOR_GREEN.as_bytes()); }

            let root = cli.search_root_path.as_bytes();
            let ends_with_slash = root.last() == Some(&(MAIN_SEPARATOR as _));

            output.extend_from_slice(root);
            if !ends_with_slash { output.push(MAIN_SEPARATOR as _); }
            output.extend_from_slice(path);

            if should_print_color { output.extend_from_slice(COLOR_RESET.as_bytes()); }

            output.extend_from_slice(b":");
        }

        if should_print_color { output.extend_from_slice(COLOR_CYAN.as_bytes()); }
        output.extend_from_slice(itoa::Buffer::new().format(line_num).as_bytes());
        if should_print_color { output.extend_from_slice(COLOR_RESET.as_bytes()); }

        output.extend_from_slice(b": ");

        let display = truncate_utf8(line, 500);
        let mut last = 0;
        for (s, e) in matches {
            let s = s as usize;
            let e = e as usize;

            if s >= display.len() { break; }

            let e = e.min(display.len());
            output.extend_from_slice(&display[last..s]);

            if should_print_color { output.extend_from_slice(COLOR_RED.as_bytes()); }
            output.extend_from_slice(&display[s..e]);
            if should_print_color { output.extend_from_slice(COLOR_RESET.as_bytes()); }

            last = e;
        }

        output.extend_from_slice(&display[last..]);
        output.push(b'\n');
    }

    #[inline(always)]
    fn write_file_header(
        output:            &mut BumpVec<u8>,
        cli:               &Cli,
        path:              &[u8],
        should_print_color: bool,
        is_dir: bool
    ) {
        if cli.jump { return; } // jump mode writes path per-line, not as a header

        if should_print_color { output.extend_from_slice(COLOR_GREEN.as_bytes()); }

        let root = cli.search_root_path.as_bytes();
        let ends_with_slash = root.last() == Some(&(MAIN_SEPARATOR as _));

        output.extend_from_slice(root);
        if is_dir && !ends_with_slash { output.push(MAIN_SEPARATOR as _); }
        output.extend_from_slice(path);

        if should_print_color { output.extend_from_slice(COLOR_RESET.as_bytes()); }

        output.extend_from_slice(b":\n");
    }
}

/// impl block of gitignore helper functions
impl<F: RawFs, S: MatchSink> WorkerContext<'_, '_, F, S> {
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

impl<'a, 'output_arena, F: RawFs, S: MatchSink> WorkerContext<'a, 'output_arena, F, S> {
    pub fn start_worker_loop(
        mut self,

        running: &AtomicBool,
        active_workers: &AtomicUsize,

        injector: &Injector<WorkItem>,
        stealers: &[Stealer<WorkItem>],
        local_worker: &DequeWorker<WorkItem>,
    ) -> WorkerResult<'output_arena> {
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

                        WorkItem::File(file_work) => {
                            _ = self.dispatch_file(file_work);
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
