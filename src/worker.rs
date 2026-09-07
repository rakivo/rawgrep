// PINNED TODOs:
//   TODO(#28): Daemon mode
//
// TODO(#1): Implement symlinks
// TODO(#24): Support for searching in large file(s). (detect that)

use crate::liner::*;
use crate::pacer::FlushPacer;
use crate::cache::{FileKey, FileMeta, FragmentCache};
use crate::slab::{OutputSlab, SlotPool, SlotBuf, SLOTS_PER_WORKER};
use crate::cli::{should_enable_ansi_coloring, Cli};
use crate::ignore::{Gitignore, GitignoreChain};
use crate::matcher::Matcher;
use crate::binary::{is_binary_ext, is_reserved_tool_dir};
use crate::path_buf::SmallPathBuf;
use crate::fragments::FragmentLen;
use crate::stats::Stats;
use crate::stdout::{RawStdout, IOV_MAX};
use crate::thin_path_arc::ThinPathArc;
use crate::parser::{BufFatPtr, BufKind, FileId, FileNode, FileType, ParsedEntry, Parser, RawFs};
use crate::util::{likely, truncate_utf8, unlikely};
use crate::{tracy, COLOR_CYAN, COLOR_GREEN, COLOR_RED, COLOR_RESET};

use std::ops::Not;
use std::collections::VecDeque;
use std::path::MAIN_SEPARATOR;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::io::{self, Write, IoSlice};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use nohash_hasher::IntSet;
use crossbeam_channel::{Receiver, Sender};
use smallvec::SmallVec;
use parking_lot::{Mutex, Condvar};
use crossbeam_deque::{Injector, Steal, Stealer};
pub use crossbeam_deque::Worker as DequeWorker;

//
// @Important @Note
//
// `STREAMING_THRESHOLD` must be AT LEAST more than ~800 bytes,
// so when we're gonna try to stream a file, we won't stumble upon
// an NTFS resident file (implementation details...).
//
pub const STREAMING_THRESHOLD:     usize = 10 * 1024 * 1024; // 10MB @Tune

pub const STREAMING_CHUNK_SIZE:    usize = 512 * 1024;       // 512KB read buffer @Tune

pub const LARGE_DIR_THRESHOLD:     usize = 256;              // Split dirs with 1000+ entries @Tune
pub const FILE_BATCH_SIZE:         usize = 64;               // Process files in batches of 500 @Tune

pub const WORKER_FLUSH_BATCH:      usize = 16 * 1024;        // @Tune
pub const OUTPUTTER_FLUSH_BATCH:   usize = 512 * 1024;       // @Tune

pub const BINARY_CONTROL_COUNT:    usize = 51;               // @Tune
pub const BINARY_PROBE_BYTE_SIZE:  usize = 0x1000;           // @Tune

pub const MAX_EXTENTS_UNTIL_SPILL: usize = 64;               // @Tune

pub const __MAX_FILE_BYTE_SIZE:    usize = 30 * 1024 * 1024; // @Tune

// Below this size, a non-ASCII-encoded file is decoded to UTF-8 in one
// pass instead of line by line. Past it we keep the streaming
// decode_line-per-line path so a huge UTF-16 file doesn't get decoded
// into a second huge allocation up front.
const SMALL_FILE_DECODE_THRESHOLD: usize =       512 * 1024; // @Tune

pub enum WorkItem {
    File(FileWork),
    Directory(DirWork)
}

pub struct FileWork {
    pub file_id: FileId,
    pub gitignore_chain: GitignoreChain,
}

pub struct DirWork {
    pub file_id: FileId,
    pub path_bytes: ThinPathArc,
    pub gitignore_chain: GitignoreChain,
}

impl DirWork {
    #[inline]
    pub fn new(
        file_id: FileId,
        path: &[u8],
        depth: u16,
        gitignore_chain: GitignoreChain,
    ) -> Self {
        let path_bytes = ThinPathArc::new(depth, path);
        Self { file_id, path_bytes, gitignore_chain }
    }

    #[inline]
    pub fn path_bytes(&self) -> &[u8] {
        self.path_bytes.path_bytes()
    }

    #[inline]
    pub fn depth(&self) -> u16 {
        self.path_bytes.depth()
    }
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

#[cfg(target_os = "linux")]
pub enum PendingRelease {
    Slot(&'static OutputSlab, u16),
    Owned(Box<[u8]>), // kept alive here, not dropped, until confirmed drained
}

pub enum OutputMessage {
    Slot { slab: &'static OutputSlab, slot: u16, len: u32 },
    Owned(Box<[u8]>),
    FlushReq,
}

pub enum PendingBuf {
    Slot { slab: &'static OutputSlab, slot: u16, len: u32 },
    Owned(Box<[u8]>),
}

impl PendingBuf {
    /// # Safety
    /// Caller must hold read-side
    #[inline]
    pub unsafe fn as_slice(&self) -> &[u8] {
        match self {
            PendingBuf::Slot { slab, slot, len, .. } => unsafe {
                &slab.slot(*slot as usize)[..*len as usize]
            },

            PendingBuf::Owned(v) => v,
        }
    }
}

pub struct OutputWorker {
    pub rx: Receiver<OutputMessage>,
    pub flush_ack_tx: Sender<()>,
    pub writer: RawStdout,

    pub batch:       Vec<PendingBuf>,
    pub batch_bytes: usize,
    pub iov_scratch: Vec<IoSlice<'static>>,

    #[cfg(unix)]
    pub is_pipe: bool,

    #[cfg(unix)]
    pub raw_fd: std::os::unix::io::RawFd,

    // vmsplice() into a pipe doesn't copy bytes, it hands the kernel a page
    // reference into our own slab memory. That page isn't safe to reuse
    // (i.e. slab.release()'d and re-claimed by a producer thread) until the
    // reader has actually drained it out of the pipe. The kernel gives no
    // per-buffer completion callback for this, so we reconstruct one:
    // FIONREAD (valid on either end of a pipe fd, per pipe(7)) reports total
    // unread bytes still sitting in the pipe's ring buffer.
    //
    // Since a pipe is strictly FIFO, `pipe_bytes_written - unread` is a monotonic watermark
    // for "bytes the reader has confirmed consumed" -- we only release a slot once
    // that watermark has passed the slot's end offset.
    #[cfg(target_os = "linux")]
    pub pipe_bytes_written: u64,

    #[cfg(target_os = "linux")]
    pub pending_release: VecDeque<(u64, PendingRelease)>,

    #[cfg(target_os = "linux")]
    pub iov_pipe_scratch: Vec<crate::stdout::vmsplice::IoVec>,

    // If FIONREAD ever fails (unexpected fd type, permission stuff, whatever),
    // we cannot trust the drain watermark at all. Rather than propagate an io::Error
    // and have `absorb()` kill the whole worker thread on the next flush,
    // we permanently fall back to the original safe behavior for the rest of this worker's life...
    #[cfg(target_os = "linux")]
    pub fionread_broken: bool,
}

impl OutputWorker {
    #[inline]
    pub fn run(mut self) {
        let _span = tracy::span!("OutputThread::run");

        'outer: while let Ok(msg) = self.rx.recv() {
            if !self.absorb(msg) { break 'outer }

            while let Ok(msg) = self.rx.try_recv() {
                if !self.absorb(msg) { break 'outer } // absorb() already flushes when full
            }

            if self.flush_batch().is_err() { break 'outer }
        }

        _ = self.flush_batch();
    }

    #[inline]
    fn absorb(&mut self, msg: OutputMessage) -> bool {
        match msg {
            OutputMessage::Slot { slab, slot, len } => {
                self.batch_bytes += len as usize;
                self.batch.push(PendingBuf::Slot { slab, slot, len });
            }

            OutputMessage::Owned(v) => {
                self.batch_bytes += v.len();
                self.batch.push(PendingBuf::Owned(v));
            }

            OutputMessage::FlushReq => {
                if self.flush_batch().is_err() { return false; }
                _ = self.flush_ack_tx.send(());

                return true;
            }
        }

        // Trigger check happens on every message now, not just in the outer loop.
        if self.batch_bytes >= OUTPUTTER_FLUSH_BATCH || self.batch.len() >= IOV_MAX {
            if self.flush_batch().is_err() {
                return false;
            }
        }

        true
    }

    #[inline]
    fn flush_batch(&mut self) -> io::Result<()> {
        if self.batch.is_empty() { return Ok(()) }

        #[cfg(target_os = "linux")]
        if self.is_pipe {
            return self.flush_batch_pipe();
        }

        self.flush_batch_writev()
    }

    #[inline]
    fn flush_batch_writev(&mut self) -> io::Result<()> {
        self.iov_scratch.clear();

        for b in &self.batch {
            // SAFETY: Slot ownership moved to us via the channel send;
            // the sender relinquished it and cannot touch it again until we release it below.
            let bytes = unsafe { b.as_slice() };

            // SAFETY: Every referent here is kept alive by an Arc/Vec still
            // sitting in self.batch, which outlives this function's use of
            // iov_scratch (we don't drain batch until after writev_all() returns Ok).
            let bytes: &'static [u8] = unsafe { std::mem::transmute(bytes) };
            self.iov_scratch.push(IoSlice::new(bytes));
        }

        self.writev_all()?;

        for b in self.batch.drain(..) {
            if let PendingBuf::Slot { slab, slot, .. } = b {
                slab.release(slot as usize);
            }
        }
        self.batch_bytes = 0;

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn flush_batch_pipe(&mut self) -> io::Result<()> {
        if self.batch.is_empty() { return Ok(()); }

        if self.fionread_broken {
            //
            // Can't trust the drain watermark at all anymore -- copy
            // everything via write_all, same as the writev path.
            //
            return self.flush_batch_writev();
        }

        // SAFETY: every PendingBuf in self.batch is exclusively ours (moved
        // in via the channel) and stays alive in self.batch for the duration
        // of this function -- we don't drain it until after the syscalls
        // below return.
        self.iov_pipe_scratch.clear();
        for b in &self.batch {
            let bytes = unsafe { b.as_slice() };
            self.iov_pipe_scratch.push(crate::stdout::vmsplice::IoVec {
                iov_base: bytes.as_ptr() as *mut _,
                iov_len: bytes.len(),
            });
        }

        let spliced = match unsafe {
            crate::stdout::vmsplice::vmsplice_vectored(self.raw_fd, &self.iov_pipe_scratch)
        } {
            Ok(n) => n,
            // Pipe full or any vmsplice error: treat as "took nothing",
            // fall through to write_all below for the whole batch. Matches
            // the old per-buffer fallback behavior, just resolved once for
            // the batch instead of per buffer.
            Err(_) => 0,
        };

        //
        // Walk iovec lengths to find which buffer boundary `spliced` landed
        // on: full buffers [0, copy_from) were entirely accepted, buffer
        // copy_from (if any) was partially accepted at partial_off, and
        // everything after copy_from was not touched by vmsplice at all.
        //
        let mut remaining = spliced;
        let mut copy_from = self.iov_pipe_scratch.len();
        let mut partial_off = 0usize;
        for (i, iov) in self.iov_pipe_scratch.iter().enumerate() {
            if remaining >= iov.iov_len { remaining -= iov.iov_len; }
            else { copy_from = i; partial_off = remaining; break; }
        }

        //
        // Everything vmsplice didn't fully place goes through writev
        //
        if copy_from < self.iov_pipe_scratch.len() {
            self.iov_scratch.clear();
            for (i, b) in self.batch[copy_from..].iter().enumerate() {
                let bytes = unsafe { b.as_slice() };
                let off = if i == 0 { partial_off } else { 0 };

                // SAFETY: same lifetime argument as flush_batch_writev --
                // every referent is kept alive by self.batch until we drain
                // it below, which is after writev_all returns Ok.
                let bytes: &'static [u8] = unsafe { std::mem::transmute(&bytes[off..]) };
                self.iov_scratch.push(IoSlice::new(bytes));
            }

            self.writev_all()?; // blocks -- correct backpressure, pipe was full
        }

        for (i, b) in self.batch.drain(..).enumerate() {
            let len = self.iov_pipe_scratch[i].iov_len;
            self.pipe_bytes_written += len as u64;

            //
            // How much of *this* buffer went out via vmsplice
            // (kernel holds a live page reference, not a copy)
            // vs
            // write_all (kernel has its own copy already, safe to release now)?
            //
            let spliced_amount = if i < copy_from {
                len
            } else if i == copy_from {
                partial_off
            } else {
                0
            };

            if spliced_amount > 0 {
                let pending = match b {
                    PendingBuf::Owned(v) => PendingRelease::Owned(v),
                    PendingBuf::Slot { slab, slot, .. } => PendingRelease::Slot(slab, slot),
                };
                self.pending_release.push_back((self.pipe_bytes_written, pending));
            } else if let PendingBuf::Slot { slab, slot, .. } = b {
                slab.release(slot as usize);
            }

            // Owned with spliced_amount == 0: drops here normally, no
            // outstanding kernel reference.
        }

        self.batch_bytes = 0;
        self.reclaim_drained();
        Ok(())
    }

    // Releases every queued Slot the reader has actually drained.
    // Deliberately infallible: an ioctl error here must never take down
    // the worker thread (see `fionread_broken` doc comment above). If
    // FIONREAD fails, we stop trusting the watermark for the rest of this
    // worker's life -- flush_batch_pipe then stops attempting vmsplice on
    // Slot buffers, and everything queued so far simply never gets an
    // independent completion signal. To avoid leaking those slots forever,
    // we also drain the backlog by falling back to the always-safe
    // assumption that a full pipe capacity's worth of *newer* writes
    // implies the oldest entries were read (pipes are bounded and FIFO);
    // see the `pending_release.len()` guard below.
    #[cfg(target_os = "linux")]
    fn reclaim_drained(&mut self) {
        if self.pending_release.len() < SLOTS_PER_WORKER / 2 { return; }

        if self.fionread_broken {
            // Already stopped attempting vmsplice entirely once this trips.
            // Whatever's already queued may still be pinned -- for a
            // short-lived CLI process, leaving it until exit is fine.
            return;
        }

        let mut unread: libc::c_int = 0;
        if unsafe { libc::ioctl(self.raw_fd, libc::FIONREAD, &mut unread as *mut libc::c_int) } != 0 {
            self.fionread_broken = true;
            return;
        }

        let confirmed = self.pipe_bytes_written.saturating_sub(unread as u64);

        while let Some(&(end, _)) = self.pending_release.front() {
            if end > confirmed { break; }
            let (_, pending) = self.pending_release.pop_front().unwrap();
            match pending {
                PendingRelease::Slot(slab, slot) => slab.release(slot as usize),
                PendingRelease::Owned(_) => {}
            }
        }
    }

    #[inline]
    fn writev_all(&mut self) -> io::Result<()> {
        let mut slices = &mut self.iov_scratch[..];
        while !slices.is_empty() {
            match self.writer.write_vectored(slices) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "write_vectored wrote 0")),
                Ok(n) => IoSlice::advance_slices(&mut slices, n),

                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e)                 => return Err(e),
            }
        }

        Ok(())
    }
}

/// Carry state for streaming match across chunk boundaries
pub struct ChunkCarry {
    /// Any matches was found so far in this file
    pub found_any:   bool,

    /// Line number counter across chunks
    pub line_num:    u32,

    pub encoding:    Option<Encoding>,

    /// Incomplete last line carried from previous chunk
    pub tail:        Vec<u8>,
    pub combine_buf: Vec<u8>,
}

impl ChunkCarry {
    #[inline]
    pub fn new() -> Self {
        Self {
            encoding: None,
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

pub type FileEntryArena = Vec<(FileId, BufFatPtr)>;
pub type SubdirsArena   = Vec<PendingSubdir>;
pub type EntriesArena   = Vec<ParsedEntry>;

#[repr(transparent)]
pub struct PathArena {
    buf: Vec<u8>,
}

impl PathArena {
    #[inline(always)]
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(64 * 1024) }
    }

    #[inline(always)]
    fn len(&self) -> u32 {
        self.buf.len() as u32
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    #[inline(always)]
    fn truncate(&mut self, len: u32) {
        self.buf.truncate(len as usize);
    }

    #[inline(always)]
    fn push_path(&mut self, parent: &[u8], needs_slash: bool, name: &[u8]) -> (u32, u32) {
        let start = self.buf.len() as u32;

        self.buf.extend_from_slice(parent);
        if needs_slash {
            self.buf.push(MAIN_SEPARATOR as u8);
        }
        self.buf.extend_from_slice(name);

        (start, self.buf.len() as u32)
    }

    #[inline(always)]
    fn slice(&self, start: u32, end: u32) -> &[u8] {
        &self.buf[start as usize..end as usize]
    }
}

#[derive(Copy, Clone)]
pub struct PendingSubdir {
    file_id:    FileId,
    path_start: u32,
    path_len:   u16,
    depth:      u16,
}

/// Bitset of fragment presence, row-major: row `i` = fragments found in file `i`.
/// Row width is `words_per_file` u64s.
/// (almost always 1, since fragment_count is typically single digits to low dozens).
#[derive(Default)]
pub struct FragmentPresenceBits {
    pub words:          Vec<u64>,
    pub words_per_file: usize,
    pub fragment_count: usize,
}

impl FragmentPresenceBits {
    #[inline]
    pub fn new(fragment_count: usize) -> Self {
        Self {
            words: Vec::new(),
            words_per_file: fragment_count.div_ceil(64),
            fragment_count,
        }
    }

    #[inline]
    pub fn full_mask(&self) -> u64 {
        let rem = self.fragment_count % 64;
        if self.words_per_file == 0 { 0 }
        else if rem == 0            { u64::MAX }
        else                        { (1u64 << rem) - 1 }
    }

    #[inline]
    pub fn push_all_fragments_present(&mut self) {
        for w in 0..self.words_per_file {
            self.words.push(if w + 1 == self.words_per_file { self.full_mask() } else { u64::MAX });
        }
    }

    #[inline]
    pub fn push_row(&mut self, row: &[u64]) {
        debug_assert_eq!(row.len(), self.words_per_file);
        self.words.extend_from_slice(row);
    }

    #[inline]
    pub fn row(&self, file_idx: usize) -> &[u64] {
        let s = file_idx * self.words_per_file;
        &self.words[s..s + self.words_per_file]
    }

    #[inline]
    pub fn get(&self, file_idx: usize, frag_idx: usize) -> bool {
        self.row(file_idx)[frag_idx / 64] & (1 << (frag_idx % 64)) != 0
    }
}

pub struct WorkerResult {
    pub stats: Box<Stats>,

    pub parser: Parser,

    pub file_keys:  Vec<FileKey>,
    pub file_metas: Vec<FileMeta>,

    pub path_buf:      Box<SmallPathBuf>,
    pub swap_path_buf: Box<SmallPathBuf>,
    pub output:        SlotBuf,

    // Reused across `find_and_print_matches` calls
    pub          newlines_scratch: Vec<u32>,
    pub            ranges_scratch: SmallVec<[(u32, u32); 16]>,
    pub fragment_presence_scratch: SmallVec<[u64; 8]>,

    pub         path_arena: PathArena,
    pub file_entries_arena: FileEntryArena,
    pub      subdirs_arena: SubdirsArena,
    pub      entries_arena: EntriesArena,

    pub fragment_presence:  FragmentPresenceBits,
}

pub struct WorkerCtx<'a, 'output_arena, F: RawFs, S: MatchSink> {
    // ----- Setup-once
    pub fs:              &'a F,
    pub cache:    Option<&'a FragmentCache>,
    pub fragment_hashes: &'a [u32],
    pub matcher:         &'a Matcher,
    pub cli:             &'a Cli,
    pub slot_pool:       &'output_arena mut SlotPool,
    pub fragment_index:  &'a IntSet<u32>,
    pub pacer:           &'a FlushPacer,
    pub selected_fragment_hash_len: FragmentLen,
    pub stdout_is_being_redirected_to_dev_null: bool,

    pub parser: Parser,
    pub output: SlotBuf,

    // ----- Hot
    pub         path_arena: PathArena,          // 24
    pub file_entries_arena: FileEntryArena,     // 24
    pub      subdirs_arena: SubdirsArena,       // 24
    pub      entries_arena: EntriesArena,       // 24

    pub      path_buf:      Box<SmallPathBuf>,  // 8
    pub swap_path_buf:      Box<SmallPathBuf>,  // 8

    pub batch_size_cached:  u32,
    pub check_mask:         usize,
    pub stats:              Box<Stats>,         // 8

    // ----- Warm
    pub          newlines_scratch: Vec<u32>,
    pub            ranges_scratch: SmallVec<[(u32, u32); 16]>,
    pub fragment_presence_scratch: SmallVec<[u64; 8]>,

    pub chunk_carry:               Option<Box<ChunkCarry>>,

    pub pending_file_keys:         Vec<FileKey>,
    pub pending_file_metas:        Vec<FileMeta>,
    pub pending_fragment_presence: FragmentPresenceBits,

    pub worker_id:                 u16,

    // ----- Cold / output plumbing ----
    pub sink: S,
    pub output_tx: Sender<OutputMessage>,
}

impl<'a, 'output_arena, F: RawFs, S: MatchSink> WorkerCtx<'a, 'output_arena, F, S> {
    #[inline(always)]
    fn init(&mut self) {
        let config = self.cli.get_buffer_config();
        self.parser.init(&config);
        self.newlines_scratch.reserve(1024);  // 4KB @Tune @Constant
    }

    #[inline(always)]
    fn finish(mut self) -> WorkerResult {
        self.flush_output();

        WorkerResult {
            stats: self.stats,
            entries_arena: self.entries_arena,
            parser: self.parser,
            path_arena: self.path_arena,
            file_entries_arena: self.file_entries_arena,
            output: self.output,
            path_buf: self.path_buf,
            swap_path_buf: self.swap_path_buf,
            subdirs_arena: self.subdirs_arena,
            ranges_scratch: self.ranges_scratch,
            newlines_scratch: self.newlines_scratch,
            file_keys: self.pending_file_keys,
            fragment_presence_scratch: self.fragment_presence_scratch,
            file_metas: self.pending_file_metas,
            fragment_presence: self.pending_fragment_presence
        }
    }

    #[inline(always)]
    pub fn flush_output(&mut self) {
        if S::STDOUT_NOP {
            self.output.clear();
            return;
        }

        if self.output.is_empty() {
            return;
        }

        debug_assert!(!self.stdout_is_being_redirected_to_dev_null);

        let old = std::mem::replace(&mut self.output, self.slot_pool.acquire());
        _ = self.output_tx.send(old.finish());
        self.pacer.record_flush();
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
impl<F: RawFs, S: MatchSink> WorkerCtx<'_, '_, F, S> {
    pub fn dispatch_directory(
        &mut self,
        work: DirWork,
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
    ) -> io::Result<()> {
        let mark = self.path_arena.len();
        let (start, end) = self.path_arena.push_path(&[], false, work.path_bytes());

        let result = self.dispatch_directory_bytes(
            work.file_id, start, end, &work.gitignore_chain, work.depth(), local, injector,
        );

        //
        // Everything pushed under this subtree either got copied out into its
        // own Arc (for queued work) or is no longer needed (fully processed locally).
        //
        // Safe to reclaim the whole thing now that the top-level
        // call has returned.
        //
        self.path_arena.truncate(mark);

        result
    }

    #[inline]
    pub fn dispatch_file(&mut self, work: FileWork) -> io::Result<()> {
        let Ok(node) = self.fs.parse_node(work.file_id) else {
            return Ok(());
        };

        let name_fat_ptr = BufFatPtr {
            offset: 0,
            len: 0,
            kind: BufKind::File,
        };

        self.process_file(&node, name_fat_ptr, &[], &work.gitignore_chain)?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments, reason = "@Incomplete?..")]
    pub fn dispatch_directory_bytes(
        &mut self,
        file_id: u64,
        path_start: u32,
        path_end: u32,
        gitignore_chain: &GitignoreChain,
        depth: u16,
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
    ) -> io::Result<()> {
        let _span = tracy::span!("process_directory_with_stealing");

        self.path_buf.clear();
        self.path_buf.extend_from_slice(self.path_arena.slice(path_start, path_end));

        let Ok(node) = self.fs.parse_node(file_id) else {
            return Ok(());
        };

        if unlikely(!node.is_dir()) {
            return Ok(());
        }

        if likely(path_end > path_start) {
            let bytes = self.path_arena.slice(path_start, path_end);
            let last_segment = bytes
                .iter()
                .rposition(|&b| b == MAIN_SEPARATOR as _)
                .map(|pos| &bytes[pos + 1..])
                .unwrap_or(bytes);

            if !self.cli.should_ignore_reserved_tool_dir_filter() && is_reserved_tool_dir(last_segment) {
                self.stats.dirs_skipped_common += 1;
                return Ok(());
            }
        }

        let dir_size = node.size() as usize;
        self.fs.read_file_content(&mut self.parser, &node, dir_size, BufKind::Dir, false)?;
        self.stats.dirs_encountered += 1;

        let new_gitignore_chain = self.cli.should_ignore_gitignore().not().then(|| {
            let prefix_len = self.path_buf.len() as u32;
            self.find_gitignore_file_id_in_buf(BufKind::Dir)
                .and_then(|gi_file_id| self.try_load_gitignore(gi_file_id))
                .map(|gi| gitignore_chain.clone().with_gitignore(depth, prefix_len, gi))
        }).flatten().unwrap_or_else(|| gitignore_chain.clone());

        let scan = self.parser.scan_directory_entries(self.fs, &mut self.entries_arena);

        self.process_directory(
            depth,
            new_gitignore_chain,
            scan.entries_start, scan.entries_end,
            local, injector
        )?;

        Ok(())
    }

    fn process_directory(
        &mut self,
        depth: u16,
        gitignore_chain: GitignoreChain,
        entries_start: usize,
        entries_end: usize,
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
    ) -> io::Result<()> {
        let _span = tracy::span!("process_small_directory_with_entries");

        let needs_slash = !self.path_buf.is_empty();

        let subdir_mark = self.subdirs_arena.len();
        let   file_mark = self.file_entries_arena.len();
        let   path_mark = self.path_arena.len();

        let check_gitignore = !self.cli.should_ignore_gitignore() && !gitignore_chain.is_empty();
        let skip_reserved   = !self.cli.should_ignore_reserved_tool_dir_filter();

        for i in entries_start..entries_end {
            let entry = self.entries_arena[i];

            let name_bytes = unsafe {
                self.parser.dir.get_unchecked(
                    entry.name_offset as usize..entry.name_offset as usize + entry.name_len as usize
                )
            };

            let ft = match entry.file_type {
                FileType::Other => {
                    //
                    // Unknown - parse node to get the type...
                    //

                    let Ok(child_node) = self.fs.parse_node(entry.file_id) else {
                        continue
                    };

                    if child_node.is_dir() { FileType::Dir } else { FileType::File }
                }

                x => x
            };

            match ft {
                FileType::Dir => {
                    if skip_reserved && is_reserved_tool_dir(name_bytes) {
                        continue;
                    }

                    let (start, end) = self.path_arena.push_path(&self.path_buf, needs_slash, name_bytes);

                    if check_gitignore && gitignore_chain.is_ignored(self.path_arena.slice(start, end), true) {
                        self.stats.dirs_skipped_gitignore += 1;
                        self.path_arena.truncate(start);
                        continue;
                    }

                    let Ok(path_len) = u16::try_from(end - start) else {
                        // Path too long to fit our packed representation (>65535 bytes) --
                        // vanishingly rare on real filesystems, but don't let one
                        // pathological subtree crash the whole walk.

                        self.stats.dirs_skipped_path_too_long += 1;
                        self.path_arena.truncate(start);
                        continue;
                    };

                    self.subdirs_arena.push(PendingSubdir {
                        file_id: entry.file_id,
                        path_start: start,
                        path_len,
                        depth: depth + 1,
                    });
                }

                FileType::File => {
                    self.file_entries_arena.push((entry.file_id, BufFatPtr {
                        offset: entry.name_offset as _,
                        kind: BufKind::Dir,
                        len: entry.name_len as _
                    }));
                }

                _ => {}
            }
        }

        self.fs.sort_entries(&mut self.file_entries_arena[file_mark..]);

        let path_buf = std::mem::replace(&mut self.path_buf, std::mem::take(&mut self.swap_path_buf));
        let file_result = self.process_files(file_mark, self.file_entries_arena.len(), &path_buf, &gitignore_chain);

        self.swap_path_buf = std::mem::replace(&mut self.path_buf, path_buf);
        self.file_entries_arena.truncate(file_mark);

        //
        // Don't propagate yet -- subdirs still need to be queued/dispatched and
        // both arenas still need truncating regardless of whether file
        // processing in this directory succeeded.
        //
        let mut first_err = file_result.err();

        // Decide how many subdirs to keep local vs push for stealing
        #[inline]
        fn work_distribution_strategy(depth: u16, subdir_count: usize) -> usize {
            if subdir_count == 0 { return 0; }
            match depth {
                0..=1 => 1,
                2..=3 => subdir_count.min(2),
                4..=6 => subdir_count.min(4),
                _     => subdir_count.min(8),
            }
        }

        let n = self.subdirs_arena.len() - subdir_mark;
        let keep_local = work_distribution_strategy(depth, n);
        let queue_start = subdir_mark + keep_local;
        let queue_end = self.subdirs_arena.len();

        //
        // Tail -> queued
        //

        for i in (queue_start..queue_end).rev() {
            let p = *unsafe { self.subdirs_arena.get_unchecked(i) };
            local.push(WorkItem::Directory(DirWork::new(
                p.file_id,
                self.path_arena.slice(p.path_start, p.path_start + p.path_len as u32),
                p.depth,
                gitignore_chain.clone(),
            )));
        }

        //
        // Head -> dispatched locally
        //

        for i in subdir_mark..queue_start {
            let p = *unsafe { self.subdirs_arena.get_unchecked(i) };
            if let Err(e) = self.dispatch_directory_bytes(
                p.file_id,
                p.path_start,
                p.path_start + p.path_len as u32,
                &gitignore_chain,
                p.depth,
                local,
                injector,
            ) {
                first_err.get_or_insert(e);
            }
        }

        self.subdirs_arena.truncate(subdir_mark);
        self.path_arena.truncate(path_mark);
        self.entries_arena.truncate(entries_start);

        if let Some(e) = first_err { Err(e) } else { Ok(()) }
    }

    fn process_files(
        &mut self,
        start_files: usize,
        end_files: usize,
        parent_path: &[u8],
        gitignore_chain: &GitignoreChain,
    ) -> io::Result<()> {
        let _span = tracy::span!("process_files");

        for i in start_files..end_files {
            let (file_id, name_fat_ptr) = *unsafe { self.file_entries_arena.get_unchecked(i) };

            let Ok(node) = self.fs.parse_node(file_id) else {
                continue;
            };

            self.process_file(&node, name_fat_ptr, parent_path, gitignore_chain)?;

            if i & self.check_mask == 0 {
                let (should_flush, batch_hint, next_mask) = self.pacer.poll(!self.output.is_empty());
                self.batch_size_cached = batch_hint;
                self.check_mask = next_mask;
                if should_flush {
                    self.cold_flush();
                    continue;
                }
            }

            if self.output.len() as u32 > self.batch_size_cached {
                self.flush_output();
            }
        }

        Ok(())
    }

    #[cold]
    #[inline(never)]
    fn cold_flush(&mut self) {
        self.flush_output();
    }

    fn process_file(
        &mut self,
        node: &F::Node,
        file_name_ptr: BufFatPtr,
        parent_path: &[u8],
        gitignore_chain: &GitignoreChain,
    ) -> io::Result<()> {
        let _span = tracy::span!("WorkerCtx::process_file_not_batch");

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

        if !self.cli.should_ignore_gitignore() && !gitignore_chain.is_empty() {
            if gitignore_chain.is_ignored(self.path_buf.as_ref(), false) {
                self.stats.files_skipped_gitignore += 1;
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

        if !self.cli.no_cache_write && let Some((file_key, file_meta)) = cache_key {
            self.pending_file_keys.push(file_key);
            self.pending_file_metas.push(file_meta);

            if found_any {
                self.pending_fragment_presence.push_all_fragments_present();
            } else {
                self.check_fragment_presence();
                self.pending_fragment_presence.push_row(&self.fragment_presence_scratch);
            }
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

        self.find_and_print_matches()
    }

    #[inline(never)]
    fn process_file_streaming(
        &mut self,
        node: &F::Node,
        max_size: usize,
        check_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("WorkerCtx::process_file_streaming");

        let mut carry = self.chunk_carry.take().unwrap_or_else(|| ChunkCarry::new().into());
        carry.reset();

        let buf = Parser::get_buf_mut_impl(
            &mut self.parser.file,
            &mut self.parser.dir,
            &mut self.parser.gitignore,
            BufKind::File
        );
        buf.clear();

        if !self.fs.collect_file_chunks(
            &mut self.parser.scratch,
            &mut self.parser.scratch2,
            &mut self.parser.scratch_chunks,
            node,
            max_size,
            check_binary,
            buf
        )? {
            self.stats.files_skipped_as_binary_due_to_probe += 1;
            self.chunk_carry = Some(carry);
            return Ok(false);
        }

        let mut bytes_searched = 0usize;
        let chunks_len = self.parser.scratch_chunks.len();

        for chunk_index in 0..chunks_len {
            let (disk_offset, len) = self.parser.scratch_chunks[chunk_index];
            let len = len as usize;

            self.parser.chunk.clear();
            self.parser.chunk.reserve(len);
            unsafe { self.parser.chunk.set_len(len); }

            let n = match self.fs.read_at_offset(&mut self.parser.chunk[..len], disk_offset) {
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
            self.find_and_print_matches_in_chunk(&combined, &mut carry, false)?;
            carry.combine_buf = combined;
        }

        // Flush final partial line (no trailing newline)
        if !carry.tail.is_empty() {
            let tail = std::mem::take(&mut carry.tail);
            self.find_and_print_matches_in_chunk(&tail, &mut carry, true)?;
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
    fn check_fragment_presence(&mut self) {
        let _span = tracy::span!("check_fragment_presence");

        let t0 = Instant::now();

        // Reset all presence to false
        unsafe {
            std::ptr::write_bytes(
                self.fragment_presence_scratch.as_mut_ptr(),
                0,
                self.fragment_presence_scratch.len()
            );
        }

        crate::fragments::check_fragment_presence(
            &self.parser.file,
            self.fragment_hashes,
            &mut self.fragment_presence_scratch,
            self.fragment_index,
            self.selected_fragment_hash_len.as_usize()
        );

        self.stats.time_fragment_presence_checking_took_in_millis += t0.elapsed().as_millis() as u32;
    }
}

// impl block for printing matches
impl<F: RawFs, S: MatchSink> WorkerCtx<'_, '_, F, S> {
    #[inline]
    fn find_and_print_matches(&mut self) -> io::Result<bool> {
        let _span = tracy::span!("find_and_print_matches");

        if self.parser.file.is_empty() { return Ok(false); }

        match crate::binary::detect_byte_order_leading_mark_len(&self.parser.file) {
            Some(Encoding::Utf8)    => self.find_and_print_matches_impl::<RawCodec    >(3),
            Some(Encoding::Utf16LE) => self.find_and_print_matches_impl::<Utf16LeCodec>(2),
            Some(Encoding::Utf16BE) => self.find_and_print_matches_impl::<Utf16BeCodec>(2),
            Some(Encoding::Utf32LE) => self.find_and_print_matches_impl::<Utf32LeCodec>(4),
            Some(Encoding::Utf32BE) => self.find_and_print_matches_impl::<Utf32BeCodec>(4),
            None                    => self.find_and_print_matches_impl::<RawCodec    >(0),
        }
    }

    fn find_and_print_matches_impl<C: LineCodec>(&mut self, skip: usize) -> io::Result<bool> {
        let buf = &self.parser.file[skip..];

        let buf_len = buf.len();
        if buf_len == 0 { return Ok(false); }

        if !C::RAW_PASSTHROUGH && buf_len <= SMALL_FILE_DECODE_THRESHOLD {
            return self.find_and_print_matches_small_decode::<C>(skip);
        }

        // Collect every raw newline offset up front, so UTF-16/32 "\n"
        // sequences are found at the right stride instead of assuming one byte/line.
        self.newlines_scratch.clear();
        let mut scan_pos = 0usize;
        while let Some(rel) = C::find_newline(&buf[scan_pos..]) {
            let abs = scan_pos + rel;
            self.newlines_scratch.push(abs as u32);
            scan_pos = abs + C::UNIT_WIDTH;
        }

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
            let raw_line = C::strip_trailing_cr(&buf[line_start..line_end]);

            //
            // Non-UTF-8 sources get transcoded one line at a time into a
            // small reusable buffer, so that a huge UTF-16 file doesn't cost a second huge allocation.
            //
            let line: &[u8] = if C::RAW_PASSTHROUGH {
                raw_line
            } else {
                self.parser.scratch.clear();
                C::decode_line(raw_line, &mut self.parser.scratch);
                &self.parser.scratch[..]
            };

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

                    if !self.stdout_is_being_redirected_to_dev_null {
                        Self::write_file_header(&mut self.output, self.cli, &self.path_buf, should_print_color);
                    }
                }

                if !self.stdout_is_being_redirected_to_dev_null {
                    Self::write_match_line(
                        &mut self.output,
                        self.cli,
                        &self.path_buf,
                        line,
                        line_num,
                        self.ranges_scratch.iter().copied(),
                        should_print_color,
                    );
                }

                if S::STDOUT_NOP {  // @Memory
                    self.sink.push(self.path_buf.as_ref(), line_num as _, line, &self.ranges_scratch);
                }
            }

            if line_end >= buf_len { break }
            line_start = line_end + C::UNIT_WIDTH;
            line_num += 1;
        }

        if found_any {
            self.stats.files_contained_matches += 1;
        }

        Ok(found_any)
    }

    #[inline]
    fn find_and_print_matches_in_chunk(
        &mut self,
        data: &[u8],
        carry: &mut ChunkCarry,
        is_last: bool,
    ) -> io::Result<()> {
        let _span = tracy::span!("find_and_print_matches_in_chunk");

        if data.is_empty() { return Ok(()); }

        //
        // The encoding is only knowable from the very first chunk (that's where a BOM would live),
        // so sniff it once and remember it on the carry for every later chunk of this file.
        //
        let (encoding, skip) = match carry.encoding {
            Some(e) => (e, 0),
            None => match crate::binary::detect_byte_order_leading_mark_len(data) {
                Some(e) => { carry.encoding = Some(e); (e, e.bom_len()) }
                None    => { carry.encoding = Some(Encoding::Utf8); (Encoding::Utf8, 0) }
            },
        };

        match encoding {
            Encoding::Utf8    => self.find_and_print_matches_in_chunk_impl::<RawCodec    >(data, skip, carry, is_last),
            Encoding::Utf16LE => self.find_and_print_matches_in_chunk_impl::<Utf16LeCodec>(data, skip, carry, is_last),
            Encoding::Utf16BE => self.find_and_print_matches_in_chunk_impl::<Utf16BeCodec>(data, skip, carry, is_last),
            Encoding::Utf32LE => self.find_and_print_matches_in_chunk_impl::<Utf32LeCodec>(data, skip, carry, is_last),
            Encoding::Utf32BE => self.find_and_print_matches_in_chunk_impl::<Utf32BeCodec>(data, skip, carry, is_last),
        }
    }

    fn find_and_print_matches_in_chunk_impl<C: LineCodec>(
        &mut self,
        data: &[u8],
        skip: usize,
        carry: &mut ChunkCarry,
        is_last: bool,
    ) -> io::Result<()> {
        let data = &data[skip..];
        if data.is_empty() { return Ok(()) }

        let should_print_color = should_enable_ansi_coloring();

        //
        // Chunk reads must land on a multiple of C::UNIT_WIDTH bytes
        // (1 raw/UTF-8, 2 UTF-16, 4 UTF-32) for every chunk except the last,
        // otherwise a multi-byte code unit could straddle two chunks and
        // neither find_newline nor decode_line could see it whole. Round
        // the chunk-read size down to a multiple of 4 at the call site
        // and this holds for every encoding we support.
        //
        debug_assert!(is_last || data.len() % C::UNIT_WIDTH == 0);

        let process_until = if is_last {
            data.len()
        } else {
            match C::rfind_newline(data) {
                Some(pos) => pos + C::UNIT_WIDTH,
                None => {
                    carry.tail.clear();
                    carry.tail.extend_from_slice(data);
                    return Ok(());
                }
            }
        };

        self.newlines_scratch.clear();
        let mut scan_pos = 0usize;
        while let Some(rel) = C::find_newline(&data[scan_pos..]) {
            let abs = scan_pos + rel;
            self.newlines_scratch.push(abs as u32);
            scan_pos = abs + C::UNIT_WIDTH;
        }

        let mut line_start = 0usize;

        for &newline_pos in self
            .newlines_scratch
            .iter()
            .chain([&(process_until as u32)])
        {
            let line_end = newline_pos as usize;
            let raw_line = C::strip_trailing_cr(&data[line_start..line_end]);

            let line: &[u8] = if C::RAW_PASSTHROUGH {
                raw_line
            } else {
                self.parser.scratch.clear();
                C::decode_line(raw_line, &mut self.parser.scratch);
                &self.parser.scratch[..]
            };

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

                    if !self.stdout_is_being_redirected_to_dev_null {
                        Self::write_file_header(&mut self.output, self.cli, &self.path_buf, should_print_color);
                    }
                }

                if !self.stdout_is_being_redirected_to_dev_null {
                    Self::write_match_line(
                        &mut self.output,
                        self.cli,
                        &self.path_buf,
                        line,
                        carry.line_num,
                        self.ranges_scratch.iter().copied(),
                        should_print_color,
                    );
                }

                if S::STDOUT_NOP {  // @Memory @Cutnpaste from find_and_print_matches
                    self.sink.push(self.path_buf.as_ref(), carry.line_num as _, line, &self.ranges_scratch);
                }
            }

            if line_end >= process_until { break; }
            line_start = line_end + C::UNIT_WIDTH;
            carry.line_num += 1;
        }

        carry.tail.clear();
        if !is_last && process_until < data.len() {
            carry.tail.extend_from_slice(&data[process_until..]);
        }

        Ok(())
    }

    #[inline(never)]
    fn find_and_print_matches_small_decode<C: LineCodec>(&mut self, skip: usize) -> io::Result<bool> {
        let buf = &self.parser.file[skip..];
        let buf_len = buf.len();
        if buf_len == 0 { return Ok(false); }

        self.parser.scratch.clear();
        C::decode_line(buf, &mut self.parser.scratch);

        let decoded_len = self.parser.scratch.len();
        if decoded_len == 0 { return Ok(false); }

        //
        // Plain '\n' scan against decoded bytes
        //
        self.newlines_scratch.clear();
        {
            let decoded = &self.parser.scratch[..];
            let mut scan_pos = 0usize;
            while let Some(rel) = memchr::memchr(b'\n', &decoded[scan_pos..]) {
                let abs = scan_pos + rel;
                self.newlines_scratch.push(abs as u32);
                scan_pos = abs + 1;
            }
        }

        let should_print_color = should_enable_ansi_coloring();
        let mut found_any = false;
        let mut line_start = 0;
        let mut line_num = 1u32;

        for &newline_pos in self
            .newlines_scratch
            .iter()
            .chain([&(decoded_len as u32)])
        {
            let line_end = newline_pos as usize;
            let raw_line = &self.parser.scratch[line_start..line_end];
            let line = if raw_line.last() == Some(&0x0D) {
                &raw_line[..raw_line.len() - 1]
            } else {
                raw_line
            };

            self.ranges_scratch.clear();
            self.ranges_scratch.extend(
                self.matcher.find_matches(line).map(|(s, e)| (s as u32, e as u32))
            );

            if !self.ranges_scratch.is_empty() {
                if !found_any {
                    found_any = true;
                    if !self.stdout_is_being_redirected_to_dev_null {
                        Self::write_file_header(&mut self.output, self.cli, &self.path_buf, should_print_color);
                    }
                }

                if !self.stdout_is_being_redirected_to_dev_null {
                    Self::write_match_line(
                        &mut self.output,
                        self.cli,
                        &self.path_buf,
                        line,
                        line_num,
                        self.ranges_scratch.iter().copied(),
                        should_print_color,
                    );
                }

                if S::STDOUT_NOP {
                    self.sink.push(self.path_buf.as_ref(), line_num as _, line, &self.ranges_scratch);
                }
            }

            if line_end >= decoded_len { break }
            line_start = line_end + 1;
            line_num += 1;
        }

        if found_any {
            self.stats.files_contained_matches += 1;
        }

        Ok(found_any)
    }
}

impl<F: RawFs, S: MatchSink> WorkerCtx<'_, '_, F, S> {
    #[inline(always)]
    fn write_match_line(
        output:            &mut SlotBuf,
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
        output:            &mut SlotBuf,
        cli:               &Cli,
        path:              &[u8],
        should_print_color: bool,
    ) {
        if cli.jump { return; } // jump mode writes path per-line, not as a header

        if should_print_color { output.extend_from_slice(COLOR_GREEN.as_bytes()); }

        let root = cli.search_root_path.as_bytes();
        let ends_with_slash = root.last() == Some(&(MAIN_SEPARATOR as _));

        output.extend_from_slice(root);
        if !ends_with_slash { output.push(MAIN_SEPARATOR as _); }
        output.extend_from_slice(path);

        if should_print_color { output.extend_from_slice(COLOR_RESET.as_bytes()); }

        output.extend_from_slice(b":\n");
    }
}

/// impl block of gitignore helper functions
impl<F: RawFs, S: MatchSink> WorkerCtx<'_, '_, F, S> {
    #[inline]
    fn try_load_gitignore(&mut self, gi_file_id: FileId) -> Option<Gitignore> {
        let _span = tracy::span!("WorkerCtx::try_load_gitignore");

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

impl<'a, 'output_arena, F: RawFs, S: MatchSink> WorkerCtx<'a, 'output_arena, F, S> {
    pub fn start_worker_loop(
        mut self,

        running: &AtomicBool,
        running_signal: &(Mutex<()>, Condvar),
        active_workers: &AtomicUsize,

        injector: &Injector<WorkItem>,
        stealers: &[Stealer<WorkItem>],
        local_worker: &DequeWorker<WorkItem>,
    ) -> WorkerResult {
        self.init();

        let mut consecutive_steals = 0;
        let mut idle_iterations    = 0;

        loop {
            if !running.load(Ordering::Relaxed) {
                break;
            }

            active_workers.fetch_add(1, Ordering::Release);

            let work = self.find_work(
                local_worker,
                injector,
                stealers,
                &mut consecutive_steals,
            );

            match work {
                Some(work_item) => {
                    idle_iterations = 0;

                    _ = match work_item {
                        WorkItem::Directory(dir_work) => self.dispatch_directory(dir_work, local_worker, injector),
                        WorkItem::File(file_work)     => self.dispatch_file(file_work),
                    };

                    active_workers.fetch_sub(1, Ordering::Release);
                }

                None => {
                    // Didn't find anything this iteration, go back to idle
                    // before checking whether the whole search is done.
                    active_workers.fetch_sub(1, Ordering::Release);

                    idle_iterations += 1;
                    self.flush_output();

                    if active_workers.load(Ordering::Acquire) == 0 {
                        if injector.is_empty() && local_worker.is_empty() {
                            running.store(false, Ordering::Release);
                            {
                                let (lock, cvar) = running_signal;
                                let _guard = lock.lock();
                                cvar.notify_all();
                            }
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
