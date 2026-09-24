// PINNED TODOs:
//   TODO(#28): Daemon mode
//
// TODO(#1): Implement symlinks
// TODO(#24): Support for work splitting for large file(s). (detect that)

use crate::liner::*;
use crate::index_::{Index_, IndexMut_};
use crate::pacer::FlushPacer;
use crate::unwrap_::Unwrap_;
use crate::binary_verdicts::{self, BinaryVerdicts};
use crate::binary_verdicts::binary_worker_table::{self, DirTally};
use crate::cache::FragmentCache;
use crate::output::{OutputSlab, OutputSlotWriter, OutputSlotOwnedOverflow};
use crate::cli::{should_enable_ansi_coloring, Cli};
use crate::ignore::{Gitignore, GitignoreChain};
use crate::matcher::{Matcher, MatcherCache};
use crate::binary::{is_binary_ext, is_reserved_tool_dir};
use crate::path_buf::SmallPathBuf;
use crate::color::COLOR_RESET;
use crate::fragments::FragmentLen;
use crate::stats::Stats;
use crate::ext4::Ext4Fs;
use crate::apfs::ApfsFs;
use crate::ntfs::NtfsFs;
use crate::stdout::{RawStdout, IOV_MAX};
use crate::thin_path_arc::ThinPathArc;
use crate::parser::{BufFatPtr, FileIdentifier, BufKind, UniversalFileId, FileNode, FileType, ParsedEntry, Parser, RawFs, FileId};
use crate::util::{likely, truncate_utf8, unlikely, prefetch_read, RawAppend};
use crate::tracy;

use std::ops::Not;
use std::path::MAIN_SEPARATOR;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::io::{self, Write, IoSlice};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use nohash_hasher::IntSet;
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
pub const STREAMING_THRESHOLD:     usize = 10 * 1024 * 1024; // 10MB @Tune

pub const STREAMING_CHUNK_SIZE:    usize = 512 * 1024;       // 512KB read buffer @Tune

pub const OUTPUTTER_FLUSH_BATCH:   usize = 512 * 1024;       // @Tune

pub const BINARY_CONTROL_COUNT:    usize = 51;               // @Tune
pub const BINARY_PROBE_BYTE_SIZE:  usize = 0x1000;           // @Tune

pub const __MAX_FILE_BYTE_SIZE:    usize = 30 * 1024 * 1024; // @Tune

// Below this size, a non-ASCII-encoded file is decoded to UTF-8 in one
// pass instead of line by line. Past it we keep the streaming
// decode_line-per-line path so a huge UTF-16 file doesn't get decoded
// into a second huge allocation upfront.
const SMALL_FILE_DECODE_THRESHOLD: usize = 1024 * 1024;      // @Tune

pub const PREFETCH_AHEAD:          usize = 4;
pub const PREFETCH_MIN_CHUNKS:     usize = 2;

/// What lookahead_file worked out for a file, handed to process_file so it doesn't redo it.
/// NONE means 'not evaluated' (the lookahead returned early), process_file then does so itself.
#[derive(Clone, Copy)]
struct LookaheadResult {
    cache_skip: Option<bool>,
    binary:     Option<(bool /* known binary: skip */, bool /* likely binary: probe-sized reads */)>,
}

impl LookaheadResult {
    const NONE: LookaheadResult = LookaheadResult { cache_skip: None, binary: None };
}

#[inline(always)]
const fn average_newline_count_heuristic(buffer_length: usize) -> usize {
    buffer_length / 40 + 16
}

pub enum WorkItem {
    File(FileWork),
    Directory(DirWork)
}

pub struct FileWork {
    pub file_id: UniversalFileId,
    pub gitignore_chain: GitignoreChain,
}

pub struct DirWork {
    pub file_id: UniversalFileId,
    pub path_bytes: ThinPathArc,
    pub gitignore_chain: GitignoreChain,
}

impl DirWork {
    #[inline]
    pub fn new(
        file_id: UniversalFileId,
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
    pub path:     Box<[u8]>,          // Full file path
    pub line_num: u32,                // 1-indexed line number
    pub text:     Box<[u8]>,          // The matched line content
    pub ranges:   Box<[(u32, u32)]>,  // Byte ranges of match spans within text
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

pub enum OutputMessage {
    Slot { slab: &'static OutputSlab, slot: u16, len: u32 },
    Owned(OutputSlotOwnedOverflow),
    FlushReq,
}

pub enum PendingBuf {
    Slot { slab: &'static OutputSlab, slot: u16, len: u32 },
    Owned(OutputSlotOwnedOverflow),
}

impl PendingBuf {
    /// # Safety
    /// Caller must hold read-side
    #[inline]
    pub unsafe fn as_slice(&self) -> &[u8] {
        match self {
            PendingBuf::Slot { slab, slot, len, .. } => unsafe { slab.slot(*slot as usize) }.get_(..*len as usize),
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

/// Last (hash_len - 1) bytes of everything presence-scanned so far in this file. Max 3 (FragmentLen::MAX = 4).
#[derive(Clone, Copy)]
pub struct PresenceSeam { pub bytes: [u8; 3], pub len: u8 }

impl PresenceSeam { const EMPTY: Self = unsafe { core::mem::zeroed() }; }

/// Carry state for streaming match across chunk boundaries
pub struct ChunkCarry {
    /// Any matches was found so far in this file
    pub found_any: bool,

    /// Line number counter across chunks
    pub line_num:  u32,

    pub encoding:  Option<Encoding>,
    pub seam:      PresenceSeam,
    pub consumed: (usize, usize),

    /// Incomplete last line carried from previous chunk
    pub tail:      Vec<u8>,
}

impl ChunkCarry {
    #[inline]
    pub fn new() -> Self {
        Self {
            encoding: None,
            seam: PresenceSeam { bytes: [0; 3], len: 0 },
            tail: Vec::new(),
            consumed: (0, 0),
            found_any: false,
            line_num: 1
        }
    }

    #[inline]
    pub fn reset(&mut self) {
        self.tail.clear();
        self.found_any = false;
        self.consumed = (0, 0);
        self.line_num = 1;
        self.encoding  = None;
        self.seam.len  = 0;
    }
}

macro_rules! as_presence_checker_ctx {
    ($w:expr) => {
        WorkerPresenceCheckerCtx {
            scratch:                 &mut $w.parser.scratch,
            file:                    &mut $w.parser.file,
            selected_fragment_hash_len: $w.selected_fragment_hash_len.as_usize() as u32,
            fragment_hashes:         &$w.fragment_hashes,
            fragment_index:          &$w.fragment_index,
            fragment_presence_scratch: &mut $w.fragment_presence_scratch,
            stats:                   &mut $w.stats,
            ignore_case:             $w.ignore_case
        }
    };
}

macro_rules! dispatch_wide {
    ($self:expr, $enc:expr, narrow => $narrow:expr, wide => $method:ident($($args:expr),* $(,)?)) => {
        match $enc {
            None | Some(Encoding::Utf8) => $narrow,
            Some(Encoding::Utf16LE) => $self.$method::<Utf16LeCodec>($($args),*),
            Some(Encoding::Utf16BE) => $self.$method::<Utf16BeCodec>($($args),*),
            Some(Encoding::Utf32LE) => $self.$method::<Utf32LeCodec>($($args),*),
            Some(Encoding::Utf32BE) => $self.$method::<Utf32BeCodec>($($args),*),
        }
    };
    ($self:expr, $enc:expr, narrow => $narrow:expr, wide => return $method:ident($($args:expr),* $(,)?)) => {
        match $enc {
            None | Some(Encoding::Utf8) => $narrow,
            Some(Encoding::Utf16LE) => return $self.$method::<Utf16LeCodec>($($args),*),
            Some(Encoding::Utf16BE) => return $self.$method::<Utf16BeCodec>($($args),*),
            Some(Encoding::Utf32LE) => return $self.$method::<Utf32LeCodec>($($args),*),
            Some(Encoding::Utf32BE) => return $self.$method::<Utf32BeCodec>($($args),*),
        }
    };
}

pub type FileEntryArena<FileId> = Vec<(FileId, BufFatPtr)>;
pub type   SubdirsArena<FileId> = Vec<PendingSubdir<FileId>>;
pub type   EntriesArena<FileId> = Vec<ParsedEntry<FileId>>;

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

        let sep: &[u8] = if needs_slash { &[MAIN_SEPARATOR as u8][..] } else { &[][..] };
        crate::batch_extend_pod!(self.buf, [parent, sep, name]);

        (start, self.buf.len() as u32)
    }

    #[inline(always)]
    fn slice(&self, start: u32, end: u32) -> &[u8] {
        self.buf.get_(start as usize..end as usize)
    }
}

#[derive(Copy, Clone)]
pub struct PendingSubdir<FileId: Copy> {
    pub file_id:    FileId,
    pub path_start: u32,
    pub path_len:   u16,
    pub depth:      u16,
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
        self.words.get_(s..s + self.words_per_file)
    }

    #[inline]
    pub fn get(&self, file_idx: usize, frag_idx: usize) -> bool {
        *self.row(file_idx).get_(frag_idx / 64) & (1 << (frag_idx % 64)) != 0
    }
}

/// $Any:              the type-erased enum       (AnyFileEntryArena)
/// $Slot:             trait to take/erase per FS (FileEntryArenaSlot)
/// $Arena:            the generic alias          (FileEntryArena)
/// $Ext4/$Apfs/$Ntfs: the concrete RawFs implementor types
macro_rules! define_any_arena {
    ($Any:ident, $Slot:ident, $Arena:ident, $Ext4:ty, $Apfs:ty, $Ntfs:ty) => {
        pub enum $Any {
            Ext4($Arena<<$Ext4 as RawFs>::FileId>),
            Apfs($Arena<<$Apfs as RawFs>::FileId>),
            Ntfs($Arena<<$Ntfs as RawFs>::FileId>),
        }

        impl Default for $Any {
            fn default() -> Self { Self::Ext4(Default::default()) }
        }

        pub trait $Slot<F: RawFs> {
            /// Take the arena out, leaving an empty one of the same variant.
            /// Returns a fresh default if the last job was a different FS.
            fn take(&mut self) -> $Arena<F::FileId>;
            fn erase(arena: $Arena<F::FileId>) -> Self;
        }

        define_any_arena!(@impl $Any, $Slot, $Arena, Ext4, $Ext4);
        define_any_arena!(@impl $Any, $Slot, $Arena, Apfs, $Apfs);
        define_any_arena!(@impl $Any, $Slot, $Arena, Ntfs, $Ntfs);
    };

    (@impl $Any:ident, $Slot:ident, $Arena:ident, $V:ident, $Fs:ty) => {
        impl $Slot<$Fs> for $Any {
            #[inline]
            fn take(&mut self) -> $Arena<<$Fs as RawFs>::FileId> {
                match std::mem::replace(self, $Any::$V(Default::default())) {
                    $Any::$V(v) => v,
                    _ => Default::default(), // Last job on this thread was a different FS...
                }
            }
            #[inline]
            fn erase(arena: $Arena<<$Fs as RawFs>::FileId>) -> Self { $Any::$V(arena) }
        }
    };
}

// Replace Ext4Fs / ApfsFs / NtfsFs with the real types that implement RawFs.
define_any_arena!(AnyFileEntryArena, FileEntryArenaSlot, FileEntryArena, Ext4Fs, ApfsFs, NtfsFs);
define_any_arena!(AnySubdirsArena,   SubdirsArenaSlot,   SubdirsArena,   Ext4Fs, ApfsFs, NtfsFs);
define_any_arena!(AnyEntriesArena,   EntriesArenaSlot,   EntriesArena,   Ext4Fs, ApfsFs, NtfsFs);

pub struct WorkerResult {
    pub stats: Box<Stats>,

    pub parser: Parser,
    pub output: OutputSlotWriter,

    pub file_ids:             Vec<FileIdentifier>,
    pub verdict_fingerprints: Vec<u64>,

    pub path_buf:      Box<SmallPathBuf>,
    pub swap_path_buf: Box<SmallPathBuf>,

    // Reused across `find_and_print_matches` calls
    pub          newlines_scratch: Vec<u32>,
    pub            ranges_scratch: Vec<(u32, u32)>,
    pub       line_ranges_scratch: Vec<(u32, u32)>,
    pub fragment_presence_scratch: Vec<u64>,

    pub         path_arena: PathArena,
    pub file_entries_arena: AnyFileEntryArena,
    pub      subdirs_arena: AnySubdirsArena,
    pub      entries_arena: AnyEntriesArena,

    pub fragment_presence:  FragmentPresenceBits,
}

#[repr(C)]
pub struct WorkerCtx<'a, F: RawFs, S: MatchSink> {
    //
    // Every field here is read unconditionally in BOTH lookahead_file AND
    // process_file's early-exit checks, on every single file before any return.
    //
    pub fs:               &'a F,                      //  8  [  0]  file_identifier every file
    pub cache:     Option<&'a FragmentCache>,         //  8  [  8]  can_skip_file every file
    pub cli:              &'a Cli,                    //  8  [ 16]  multiple flag checks per file
    pub binary_verdicts:  &'a BinaryVerdicts,         //  8  [ 24]  binary_hints every file
    pub fragment_indexes: &'a [u32],                  // 16  [ 32]  can_skip_file argument; fat ptr
    pub stats:            Box<Stats>,                 //  8  [ 48]  files_encountered is first write in process_file
    pub check_mask:       usize,                      //  8  [ 56]  output flush guard, every iteration

    //
    // Still per-file hot. dir_tally and file_entries_arena are both
    // accessed in lookahead_file before any early return.
    //
    pub batch_size_cached:  u32,                      //  4  [ 64]  output flush threshold every file
    pub stdout_is_being_redirected_to_dev_null: bool, //  1  [ 68]  guards flush block
    pub print_line_numbers: bool,                     //  1  [ 69]  find_and_print_matches setup
    pub ignore_case:        bool,                     //  1  [ 70]  presence checker
    pub single_literal_fragments: bool,               //  1  [ 71]  cache record logic
    pub gitignore_enabled:  bool,                     //  1  [ 72]  should_ignore_gitignore()
    pub dir_tally:          DirTally,                 //  8  [ 76]  binary_hints + record every file
    pub file_entries_arena: FileEntryArena<F::FileId>,// 24  [ ??]  name lookup in lookahead + main loop

    //
    // output.len() is the final check every file iteration.
    // write_record only fires on matches (warm), but the len check is every file.
    // path_buf is built for every file that survives known_binary check.
    //
    pub output:             OutputSlotWriter,         //  ?         len check every file
    pub path_buf:           Box<SmallPathBuf>,        //  8         built per surviving file

    //
    // Accessed once per directory in process_directory; never in the tight
    // per-file loop (subdirs_arena, entries_arena are fully consumed before
    // process_files is called).
    //
    pub path_arena:         PathArena,                // 24
    pub subdirs_arena:      SubdirsArena<F::FileId>,  // 24
    pub entries_arena:      EntriesArena<F::FileId>,  // 24
    pub swap_path_buf:      Box<SmallPathBuf>,        //  8         swapped once per directory

    //
    // node_hot_scratch and node_cold_scratch are taken via mem::take at the
    // START of process_files and put back at the END - their Vec descriptors
    // in WorkerCtx are NOT accessed during the mid-loop per-file iterations.
    // node_cache is passed into parse_nodes_batch once per directory.
    //
    pub node_hot_scratch:   Vec<F::NodeHot>,       // 24
    pub node_cache:         F::NodeCache,          //  ?
    pub node_cold_scratch:  Vec<F::NodeCold>,      // 24

    //
    //
    // fragment_hashes + fragment_index: only in check_fragment_presence (warm).
    // matcher: only in find_and_print_matches (warm, match-found path).
    // pacer: only at i & check_mask == 0 intervals (rare).
    // selected_fragment_hash_len: only in presence checking.
    //
    pub fragment_hashes:        &'a [u32],         // 16
    pub fragment_index:         &'a IntSet<u32>,   //  8
    pub matcher:                &'a Matcher,       //  8
    pub pacer:                  &'a FlushPacer,    //  8
    pub selected_fragment_hash_len: FragmentLen,   //  4

    //
    // parser.dir is accessed via buf_ptr(BufKind::Dir) in lookahead_file for
    // every file's name lookup. parser.file/scratch/etc. are warm (read_file_content).
    //
    // Parser stays here rather than earlier because its ~200 byte footprint
    // would push cache lines further out if moved up. Once the first file in a
    // directory is processed, all of parser is in cache anyway.
    //
    pub parser:             Parser,

    //
    // Touched only when a file survives all early-outs and reaches find_and_print_matches
    // or the streaming path.
    //
    pub newlines_scratch:          Vec<u32>,
    pub ranges_scratch:            Vec<(u32, u32)>,
    pub line_ranges_scratch:       Vec<(u32, u32)>,  // @VerySad
    pub fragment_presence_scratch: Vec<u64>,
    pub chunk_carry:               Option<Box<ChunkCarry>>,
    pub matcher_cache:             Option<&'a mut MatcherCache>,
    pub worker_id:                 u16,
    pub num_workers:               u16,

    //
    // Written once per fully-scanned file
    //
    pub pending_verdict_fingerprints: Vec<u64>,
    pub pending_file_ids:             Vec<FileIdentifier>,
    pub pending_fragment_presence:    FragmentPresenceBits,

    //
    // Only touched when a match is actually output.
    //
    pub sink:  S,
    pub red:   &'static str,
    pub cyan:  &'static str,
    pub green: &'static str,
}

impl<'a, F: RawFs, S: MatchSink> WorkerCtx<'a, F, S> {
    #[inline(always)]
    fn init(&mut self) {
        let config = self.cli.get_buffer_config();
        self.parser.init(&config);
        self.newlines_scratch.reserve(1024);  // 4KB @Tune @Constant

        self.subdirs_arena.clear();
        self.entries_arena.clear();
    }

    #[inline(always)]
    fn finish(mut self) -> WorkerResult {
        self.flush_output();

        WorkerResult {
            stats: self.stats,
            verdict_fingerprints: self.pending_verdict_fingerprints,
            entries_arena: self.fs.erase_entries_arena(self.entries_arena),
            parser: self.parser,
            path_arena: self.path_arena,
            file_entries_arena: self.fs.erase_file_entry_arena(self.file_entries_arena),
            swap_path_buf: self.swap_path_buf,
            output: self.output,
            path_buf: self.path_buf,
            subdirs_arena: self.fs.erase_subdirs_arena(self.subdirs_arena),
            ranges_scratch: self.ranges_scratch,
            line_ranges_scratch: self.line_ranges_scratch,
            newlines_scratch: self.newlines_scratch,
            file_ids: self.pending_file_ids,
            fragment_presence_scratch: self.fragment_presence_scratch,
            fragment_presence: self.pending_fragment_presence
        }
    }

    #[inline]
    pub fn flush_output(&mut self) {
        if S::STDOUT_NOP || self.stdout_is_being_redirected_to_dev_null {
            self.output.clear();
            return;
        }

        if self.output.is_empty() {
            return;
        }

        self.output.flush();
        self.pacer.record_flush();
    }

    #[cold]
    #[inline(never)]
    pub fn cold_flush_output(&mut self) {
        self.flush_output();
    }

    #[inline(always)]
    const fn should_ignore_gitignore(&self) -> bool {
        !self.gitignore_enabled || self.cli.should_ignore_gitignore()
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

// impl block of gitignore helper functions
impl<F: RawFs, S: MatchSink> WorkerCtx<'_, F, S> {
    #[inline]
    fn try_load_gitignore(&mut self, gi_file_id: F::FileId) -> Option<Gitignore> {
        let _span = tracy::span!("WorkerCtx::try_load_gitignore");

        if let Ok(gi_node) = self.fs.parse_node(gi_file_id) {
            let size = (gi_node.size() as usize).min(self.max_file_byte_size());
            if likely(self.fs.read_file_content(&mut self.parser, &gi_node, size, BufKind::Gitignore, true, false).is_ok()) {
                let matcher = crate::ignore::build_gitignore_from_bytes(
                    &self.parser.gitignore
                );
                return Some(matcher)
            }
        }

        None
    }

    #[inline(always)]
    fn find_gitignore_file_id_in_buf(&self, kind: BufKind) -> Option<F::FileId> {
        self.parser.find_file_id_in_buf(self.fs, b".gitignore", kind)
    }
}

// impl block of the core logic
impl<F: RawFs, S: MatchSink> WorkerCtx<'_, F, S> {
    #[inline]
    pub fn dispatch_directory(
        &mut self,
        work: DirWork,
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
    ) -> io::Result<()> {
        let mark = self.path_arena.len();
        let (start, end) = self.path_arena.push_path(&[], false, work.path_bytes());

        let result = self.dispatch_directory_bytes(
            F::FileId::from_uni(work.file_id),
            start, end,
            &work.gitignore_chain,
            work.depth(),
            local, injector,
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
        let file_id = F::FileId::from_uni(work.file_id);

        let (result, cache_stats) = self.fs.parse_node_cached(file_id, &mut self.node_cache);
        self.stats.node_cache_hits   += cache_stats.hits;
        self.stats.node_cache_misses += cache_stats.misses;
        let Ok(node) = result else {
            return Ok(());
        };

        let name_fat_ptr = BufFatPtr {
            offset: 0,
            len: 0,
            kind: BufKind::File,
        };

        self.dir_tally.reset();

        let (hot, cold) = self.fs.split_node(node);
        self.process_file(hot, || cold, name_fat_ptr, &[], &work.gitignore_chain, LookaheadResult::NONE)?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments, reason = "@Incomplete?..")]
    pub fn dispatch_directory_bytes(
        &mut self,
        file_id: F::FileId,
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

        let (result, cache_stats) = self.fs.parse_node_cached(file_id, &mut self.node_cache);
        self.stats.node_cache_hits   += cache_stats.hits;
        self.stats.node_cache_misses += cache_stats.misses;
        let Ok(node) = result else {
            return Ok(());
        };

        if unlikely(!node.is_dir()) {
            return Ok(());
        }

        let dir_size = node.size() as usize;
        self.fs.read_file_content(&mut self.parser, &node, dir_size, BufKind::Dir, false, false)?;
        self.stats.dirs_encountered += 1;

        let new_gitignore_chain = self.should_ignore_gitignore().not().then(|| {
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

        let check_gitignore = !self.should_ignore_gitignore() && !gitignore_chain.is_empty();
        let skip_reserved   = !self.cli.should_ignore_reserved_tool_dir_filter();

        for entry_index in entries_start..entries_end {
            let entry = self.entries_arena.get_(entry_index);

            let name_bytes = self.parser.dir.get_(
                entry.name_offset as usize
                ..
                entry.name_offset as usize + entry.name_len as usize
            );

            let ft = match entry.file_type {
                FileType::Other => {
                    //
                    // Unknown - parse node to get the type...
                    //

                    let (child_result, cache_stats) = self.fs.parse_node_cached(entry.file_id, &mut self.node_cache);
                    self.stats.node_cache_hits   += cache_stats.hits;
                    self.stats.node_cache_misses += cache_stats.misses;
                    let Ok(child_node) = child_result else { continue };

                    if child_node.is_dir() { FileType::Dir } else { FileType::File }
                }

                x => x
            };

            match ft {
                FileType::Dir => {
                    if skip_reserved && is_reserved_tool_dir(name_bytes) {
                        self.stats.dirs_skipped_reserved += 1;
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

        self.fs.sort_entries_by_offset(self.file_entries_arena.get_mut_(file_mark..));

        let file_result;
        {
            std::mem::swap(&mut self.path_buf, &mut self.swap_path_buf);

            struct AbortOnDrop;
            impl Drop for AbortOnDrop {
                fn drop(&mut self) {
                    // process_files panicked while swap_path_buf's slot
                    // held a duplicate Box pointer.
                    // Unwinding here would double free. Abort instead.
                    std::process::abort();
                }
            }

            let path_buf: Box<SmallPathBuf> = unsafe { std::ptr::read(&self.swap_path_buf) };
            {
                let guard = AbortOnDrop;
                file_result = self.process_files(file_mark, self.file_entries_arena.len(), &path_buf, &gitignore_chain);
                std::mem::forget(guard);
            }
            unsafe { std::ptr::write(&mut self.swap_path_buf, path_buf) };

            std::mem::swap(&mut self.path_buf, &mut self.swap_path_buf);
        }

        self.file_entries_arena.truncate(file_mark);

        //
        // Don't propagate yet -- subdirs still need to be queued/dispatched and
        // both arenas still need truncating regardless of whether file
        // processing in this directory succeeded.
        //
        let mut first_err = file_result.err();

        // Decide how many subdirs to keep local vs push for stealing
        #[inline]
        fn work_distribution_strategy(depth: u16, subdir_count: usize, num_workers: u16) -> usize {
            if subdir_count == 0 { return 0; }

            // Near the root, an idle thread wastes the most total time, so stay
            // maximally aggressive about queueing regardless of thread count.
            //
            // Deeper in the tree, parallelism is normally already established,
            // so favor keeping siblings together on one thread (which is what
            // the inode-block cache actually benefits from) over further
            // distribution. Cap that preference at roughly half the worker
            // count, though, so there's always queueing headroom left to
            // rebalance a tree that turns out lopsided.
            let   max_cap = (num_workers / 2).max(1) as usize;
            let depth_cap = (1 + depth as usize / 2).min(max_cap);

            subdir_count.min(depth_cap)
        }

        //
        // Sort subdirs by disk offset, same rationale as the file sort above --
        // makes the local half (below) a contiguous cache-friendly run,
        // and gives the queued half a better starting order too.
        //
        self.fs.sort_subdirs_by_offset(self.subdirs_arena.get_mut_(subdir_mark..));

        let n = self.subdirs_arena.len() - subdir_mark;
        let keep_local = work_distribution_strategy(depth, n, self.num_workers);
        let queue_start = subdir_mark + keep_local;
        let queue_end = self.subdirs_arena.len();

        //
        // Tail -> queued
        //

        for i in (queue_start..queue_end).rev() {
            let p = *self.subdirs_arena.get_(i);
            local.push(WorkItem::Directory(DirWork::new(
                p.file_id.into_uni(),
                self.path_arena.slice(p.path_start, p.path_start + p.path_len as u32),
                p.depth,
                gitignore_chain.clone(),
            )));
        }

        //
        // Head -> dispatched locally
        //

        for i in subdir_mark..queue_start {
            let p = *self.subdirs_arena.get_(i);
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

        // One reset per directory: process_directory calls process_files exactly once, with the
        // directory's whole file range. Subdirectories are dispatched only after that call returns, so
        // nothing else uses the tally in between, and a child's own process_files resets it again.
        self.dir_tally.reset();

        self.node_hot_scratch.clear();
        self.node_cold_scratch.clear();
        let batch_stats = self.fs.parse_nodes_batch(
            self.file_entries_arena.get_(start_files..end_files),
            &mut self.node_cache,
            &mut self.node_hot_scratch,
            &mut self.node_cold_scratch,
        );

        self.stats.node_cache_hits   += batch_stats.hits;
        self.stats.node_cache_misses += batch_stats.misses;

        let mut nodes      = std::mem::take(&mut self.node_hot_scratch);
        let mut nodes_cold = std::mem::take(&mut self.node_cold_scratch);
        debug_assert_eq!(nodes.len(), end_files - start_files);

        //
        // How many files ahead of the one being processed get their head hinted,
        // each worker keeps roughly this many files' worth of I/O in flight.
        //
        // Ring size must exceed it: the ring memoizes the cache lookup for every file inside the window.
        //
        const FILE_PREFETCH_AHEAD: usize = 8;
        const FILE_RING: usize = 16;
        const _: () = assert!(FILE_PREFETCH_AHEAD < FILE_RING);
        const _: () = assert!((FILE_RING - FILE_PREFETCH_AHEAD).is_power_of_two());

        //
        // Every node is evaluated by lookahead_file exactly once,
        // FILE_PREFETCH_AHEAD files before it is processed.
        //
        // That evaluation hints the head of the files that will really be read, and hands back
        // the cache lookup result, memoized here so process_file doesn't repeat it.
        //
        let mut lookahead_ring = [LookaheadResult::NONE; FILE_RING];
        let mut ahead_up_to    = 0usize;

        // Is this directory's data cold? Sampled once by the first file that would be hinted.
        let mut batch_cold: Option<bool> = None;

        for node_index in 0..nodes.len() {
            let i = start_files + node_index;

            let window_end = (node_index + 1 + FILE_PREFETCH_AHEAD).min(nodes.len());
            while ahead_up_to < window_end {
                lookahead_ring[ahead_up_to % FILE_RING] = self.lookahead_file(
                    *nodes.get_(ahead_up_to),
                    || *nodes_cold.get_(ahead_up_to),
                    start_files + ahead_up_to,
                    &mut batch_cold
                );

                ahead_up_to += 1;
            }

            let node = *nodes.get_(node_index);
            if node.is_poisoned() { continue; }

            let (_, name_fat_ptr) = *self.file_entries_arena.get_(i);

            self.process_file(
                node, || *nodes_cold.get_(node_index),
                name_fat_ptr, parent_path,
                gitignore_chain, lookahead_ring[node_index % FILE_RING]
            )?;

            if !self.stdout_is_being_redirected_to_dev_null && i & self.check_mask == 0 {
                let (should_flush, batch_hint, next_mask) = self.pacer.poll(!self.output.is_empty());

                self.batch_size_cached = batch_hint;
                self.check_mask = next_mask;

                if should_flush {
                    self.cold_flush_output();
                    continue;
                }
            }

            if self.output.len() as u32 > self.batch_size_cached {
                self.flush_output();
            }
        }

        nodes.clear();
        nodes_cold.clear();
        self.node_hot_scratch = nodes;
        self.node_cold_scratch = nodes_cold;

        Ok(())
    }

    #[inline]
    fn binary_hints(&self, file_identifier: FileIdentifier, file_ext_or_name: &[u8]) -> (bool, bool) {
        let known = !self.binary_verdicts.is_empty() &&
            self.binary_verdicts.is_binary(binary_verdicts::fingerprint(
                file_identifier
            ));

        use binary_worker_table::Verdict;
        let likely = known || match binary_worker_table::verdict(file_ext_or_name) {
            Verdict::Binary  => true,
            Verdict::Text    => false,
            Verdict::Unknown => self.dir_tally.likely_binary(),
        };

        (known, likely)
    }

    //
    // Runs, ahead of time, the checks in process_file that decide whether a file's data is read at all
    // (size, binary extension, fragment cache) and hints the head of the ones that survive.
    //
    // Gitignore is deliberately not checked, it needs the full path, and it VERY RARELY rejects
    // on the corpora we currenly benchmark on (Chromium and Linux source trees).
    //
    #[inline]
    fn lookahead_file(
        &self,
        hot: F::NodeHot,
        cold: impl Fn() -> F::NodeCold,
        entry_index: usize,
        batch_cold: &mut Option<bool>
    ) -> LookaheadResult {
        if hot.is_poisoned() { return LookaheadResult::NONE; }

        if !self.cli.should_ignore_all_filters() && hot.size() > self.max_file_byte_size() as u64 {
            return LookaheadResult::NONE;
        }

        let check_binary = !self.cli.should_search_binary();

        let name = if check_binary {
            let (_, name_fat_ptr) = *self.file_entries_arena.get_(entry_index);
            let name = self.parser.buf_ptr(name_fat_ptr);

            let file_ext_pos     = memchr::memrchr(b'.', name);
            let file_ext_or_name = file_ext_pos
                .and_then(|p| if p + 1 < name.len() { Some(name.get_(p + 1..)) } else { None })
                .unwrap_or(name);

            if is_binary_ext(file_ext_or_name) {
                //
                // @Robustness: Not sure how correct this is, in a sense that
                // ... well it should be, since a file with a binary extension
                // is kinda guaranteed to be binary, and this whole branch is
                // only enabled if the --binary flag isn't passed.
                //
                return LookaheadResult { cache_skip: None, binary: Some((true, true)) };
            }

            Some(name)
        } else {
            None
        };

        //
        // Cache first
        //

        let file_identifier = self.fs.file_identifier(hot);

        let mut cache_skip = None;
        if let Some(cache) = self.cache {
            if cache.can_skip_file(file_identifier, self.fragment_indexes) {
                return LookaheadResult { cache_skip: Some(true), binary: None };
            }

            cache_skip = Some(false);
        }

        let binary = name.map(|name| self.binary_hints(file_identifier, name));

        //
        // Known binary from an earlier run, nothing will be read, therefore nothing to hint.
        //
        if let Some((true, _)) = binary { return LookaheadResult { cache_skip, binary } }

        let likely_binary = binary.is_some_and(|(_, likely)| likely);

        let max_size = (hot.size() as usize).min(self.max_file_byte_size());

        let mut node = None;
        if batch_cold.is_none() {
            node = Some(self.fs.merge_node(hot, cold()));
            *batch_cold = self.fs.head_is_cold(&node.unwrap_(), max_size);  // Stays None if it can't tell yet
        }

        if *batch_cold != Some(false) {
            //
            // For a file we expect the probe to reject, only the probe block is worth fetching
            //
            let hint_size = if likely_binary { max_size.min(binary_verdicts::PROBE_BYTES) } else { max_size };
            let node = node.unwrap_or_else(|| self.fs.merge_node(hot, cold()));
            self.fs.prefetch_file_head(&node, hint_size);
        }

        LookaheadResult { cache_skip, binary }
    }

    fn process_file(
        &mut self,
        hot: F::NodeHot,
        cold: impl FnOnce() -> F::NodeCold,
        file_name_ptr: BufFatPtr,
        parent_path: &[u8],
        gitignore_chain: &GitignoreChain,
        pre: LookaheadResult,
    ) -> io::Result<()> {
        let _span = tracy::span!("WorkerCtx::process_file_not_batch");

        self.stats.files_encountered += 1;

        if !self.cli.should_ignore_all_filters() && hot.size() > self.max_file_byte_size() as u64 {
            self.stats.files_skipped_large += 1;
            return Ok(());
        }

        let file_name        = self.parser.buf_ptr(file_name_ptr);
        let file_identifier  = self.fs.file_identifier(hot);

        if let Some(cache) = self.cache {
            let skip = match pre.cache_skip {
                Some(skip) => skip,
                None       => cache.can_skip_file(file_identifier, self.fragment_indexes),
            };

            if skip {
                self.stats.files_skipped_by_cache += 1;
                return Ok(());
            }
        }

        let check_binary = !self.cli.should_search_binary();

        let file_ext_pos     = memchr::memrchr(b'.', file_name);
        let file_ext_or_name = file_ext_pos
            .and_then(|p| if p + 1 < file_name.len() { Some(file_name.get_(p + 1..)) } else { None })
            .unwrap_or(file_name);

        //
        // Use what the lookahead already worked out, or do it now if a file skipped the lookahead
        //
        let (known_binary, likely_binary) = match (check_binary, pre.binary) {
            (true, Some((mut known, likely))) => {
                if !known { known = is_binary_ext(file_ext_or_name) }
                (known, likely)
            }

            (true, None) => {
                let (mut known, likely) = self.binary_hints(file_identifier, file_name);
                if !known { known = is_binary_ext(file_ext_or_name) }
                (known, likely)
            }

            (false, _) => (false, false),
        };

        if known_binary {
            self.stats.files_skipped_as_binary_cached += 1;
            return Ok(());
        }

        // Build full path
        {
            self.path_buf.clear();

            let sep: &[u8] = if likely(!parent_path.is_empty()) { &[MAIN_SEPARATOR as u8] } else { &[] };
            crate::batch_extend_pod!(self.path_buf, [parent_path, sep, file_name]);
        }

        if !self.should_ignore_gitignore() && !gitignore_chain.is_empty() {
            if gitignore_chain.is_ignored(self.path_buf.as_ref(), false) {
                self.stats.files_skipped_gitignore += 1;
                return Ok(());
            }
        }

        let max_size = (hot.size() as usize).min(self.max_file_byte_size());

        let rejected_before = self.stats.files_skipped_as_binary_due_to_probe;

        let streamed = max_size >= STREAMING_THRESHOLD;

        let node = self.fs.merge_node(hot, cold());

        let (found_any, presence_ready) = if likely(!streamed) {
            let found_any = self.process_file_buffered(&node, max_size, check_binary, likely_binary)?;
            (found_any, false)
        } else {
            self.process_file_streaming(&node, max_size, check_binary, likely_binary)?
        };

        if check_binary {
            let rejected = self.stats.files_skipped_as_binary_due_to_probe != rejected_before;

            let file_name = self.parser.buf_ptr(file_name_ptr);
            let file_ext_or_name = file_ext_pos
                .and_then(|p| if p + 1 < file_name.len() { Some(file_name.get_(p + 1..)) } else { None })
                .unwrap_or(file_name);

            binary_worker_table::record(file_ext_or_name, node.file_id().into_uni(), rejected);

            self.dir_tally.record(rejected);

            if rejected {
                let fp = binary_verdicts::fingerprint(file_identifier);
                self.pending_verdict_fingerprints.push(fp);
            }
        }

        if !self.cli.no_cache_write && !self.cli.no_cache {
            //
            // What to record for this file:
            //
            //   Some(true)  Every fragment present (it matched, so its fragments are there)
            //
            //   Some(false) The exact row in fragment_presence_scratch
            //
            //   None        Nothing: we can't vouch for a row, so the file stays out of
            //               the cache and is simply searched again next run.
            //

            let record = if found_any && self.single_literal_fragments {
                Some(true)
            } else if !streamed {
                as_presence_checker_ctx!(self).check_fragment_presence();
                Some(false)
            } else if presence_ready {
                //
                // A streamed file is never whole in parser.file (only its first block is), so
                // check_fragment_presence() would call every fragment in the rest of the file
                // ABSENT. process_file_streaming built the row chunk by chunk instead.
                //
                Some(false)
            } else {
                //
                // Read error, short read, or truncated to max_size: the row would be incomplete
                //
                None
            };

            if let Some(all_present) = record {
                self.pending_file_ids.push(file_identifier);

                if all_present {
                    self.pending_fragment_presence.push_all_fragments_present();
                } else {
                    self.pending_fragment_presence.push_row(&self.fragment_presence_scratch);
                }
            }
        }

        Ok(())
    }

    #[inline(always)]
    fn process_file_buffered(
        &mut self,
        node: &F::Node,
        max_size: usize,
        check_binary: bool,
        likely_binary: bool,
    ) -> io::Result<bool> {
        let is_binary = !self.fs.read_file_content(
            &mut self.parser,
            node,
            max_size, BufKind::File,
            check_binary, likely_binary
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
    #[allow(clippy::uninit_vec)]
    fn process_file_streaming(
        &mut self,
        node: &F::Node,
        max_size: usize,
        check_binary: bool,
        likely_binary: bool
    ) -> io::Result<(bool, bool)> {
        let _span = tracy::span!("WorkerCtx::process_file_streaming");

        //
        // Same condition process_file_impl uses to record a row. The row is built up piece by piece,
        // and only while the file hasn't matched: once it has, every fragment counts as present anyway.
        //
        let track_presence = self.cache.is_some() && !self.cli.no_cache_write;

        //
        // Single literal: A match already proves every fragment present, so stop early.
        // Multi  literal: A match on one branch says nothing about another branch's fragments, so keep going.
        //
        let stop_at_first_match = self.single_literal_fragments;

        let mut presence_checker: WorkerPresenceCheckerCtx;

        if track_presence {
            presence_checker = as_presence_checker_ctx!(self);
            presence_checker.reset_fragment_presence();
        }

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
            &mut self.parser.scratch3,
            &mut self.parser.scratch_chunks,
            node,
            max_size,
            check_binary,
            likely_binary,
            buf
        )? {
            self.stats.files_skipped_as_binary_due_to_probe += 1;
            self.chunk_carry = Some(carry);

            //
            // Same as the buffered path: a rejected file records an (all-ABSENT) row
            //
            return Ok((false, track_presence));
        }

        let mut bytes_searched = 0usize;
        let mut planned        = 0usize;  // Bytes we expect to search if nothing goes wrong

        //
        // The probed bytes are the first bytes of the file and the chunk list starts right
        // after them, so they have to be searched here. The loop below never looks at parser.file,
        // so without this a match in the first block of every streamed file is missed...
        //
        // Any partial last line lands in carry.tail and is picked up by chunk 0.
        //
        {
            let head = std::mem::take(Parser::get_buf_mut_impl(
                &mut self.parser.file,
                &mut self.parser.dir,
                &mut self.parser.gitignore,
                BufKind::File
            ));

            planned += head.len();

            let mut result = Ok(());
            if !head.is_empty() {
                bytes_searched += head.len();
                result = self.find_and_print_matches_in_chunk(&head, &mut carry, /* is_last */ false);

                if result.is_ok() && track_presence && (!carry.found_any || !stop_at_first_match) {
                    presence_checker = as_presence_checker_ctx!(self);
                    presence_checker.feed_presence(&mut carry, &head, &head);
                }
            }

            *Parser::get_buf_mut_impl(
                &mut self.parser.file,
                &mut self.parser.dir,
                &mut self.parser.gitignore,
                BufKind::File
            ) = head;

            result?;
        }

        // @Speed: do this in collect_file_chunks while merging...?
        //
        // collect_file_chunks merges disk-contiguous pieces without a size cap, so an unfragmented
        // file arrives as ONE chunk however small STREAMING_CHUNK_SIZE is.
        //
        // Split them back down: bounded memory (buf.reserve(total) below), and while chunk 'i' is searched,
        // the hints for the next PREFETCH_AHEAD chunks are in flight.
        //
        crate::parser::split_chunks(&mut self.parser.scratch_chunks, STREAMING_CHUNK_SIZE);

        let chunks_len = self.parser.scratch_chunks.len();
        planned += self.parser.scratch_chunks.iter().map(|&(_, len)| len as usize).sum::<usize>();

        //
        // Hinting is @Cutnpaste from Ext4Fs::read_file_content
        //

        #[cfg(unix)]
        use std::os::fd::AsRawFd;

        #[cfg(unix)]
        let fd = self.fs.device_file().as_raw_fd();

        #[cfg(unix)]
        {
            for &(offset, len) in self.parser.scratch_chunks.iter().take(PREFETCH_AHEAD) {
                unsafe {
                    libc::posix_fadvise(
                        fd, offset as i64, len as i64,
                        libc::POSIX_FADV_WILLNEED
                    );
                }
            }
        }

        #[cfg(unix)]
        let mut hinted_up_to = PREFETCH_AHEAD.min(chunks_len);

        for chunk_index in 0..chunks_len {
            let (disk_offset, len) = *self.parser.scratch_chunks.get_(chunk_index);
            let len = len as usize;

            #[cfg(unix)] {
                let want = chunk_index + 1;
                if want >= hinted_up_to {
                    if let Some(&(next_offset, next_len)) = self.parser.scratch_chunks.get(want) {
                        unsafe {
                            libc::posix_fadvise(
                                fd, next_offset as i64, next_len as i64,
                                libc::POSIX_FADV_WILLNEED
                            );
                        }
                    }

                    hinted_up_to = want + 1;
                }
            }

            let tail_len = carry.tail.len();
            let total = tail_len + len;

            let mut buf = std::mem::take(&mut self.parser.stream_chunk);
            {
                buf.clear();
                buf.reserve(total);
                unsafe { buf.set_len(total); }
                buf.get_mut_(..tail_len).copy_from_slice(&carry.tail);
            }

            //
            // read_at_offset can hand back fewer bytes than asked without that meaning EOF, so keep
            // asking for the rest of this chunk until it's full or we get an EOF/error.
            //
            let mut got = 0usize;
            let mut hard_error = false;

            while got < len {
                match self.fs.read_at_offset(buf.get_mut_(tail_len + got..total), disk_offset + got as u64) {
                    Ok(0)  => break,     // real EOF
                    Ok(n)  => got += n,  // short read, retry the rest
                    Err(_) => { hard_error = true; break; }
                }
            }

            if got == 0 { self.parser.stream_chunk = buf; break; }

            bytes_searched += got;
            carry.tail.clear();

            //
            // is_last should fire exactly once for the file. So, only true here if this is genuinely
            // the final chunk AND it ends cleanly on a newline, otherwise the tail flush below is the one
            // call carrying is_last.
            //
            let is_last_chunk  = chunk_index == chunks_len - 1 && got == len;
            let ends_on_newline = *buf.get_(tail_len + got - 1) == b'\n';
            let is_last = is_last_chunk && ends_on_newline;

            self.find_and_print_matches_in_chunk(buf.get_(..tail_len + got), &mut carry, is_last)?;

            //
            // Only the bytes read for this chunk without the carried partial line in front of them,
            // since those were already scanned as part of the previous chunk (and seam covers the join).
            //
            if track_presence && (!carry.found_any || !stop_at_first_match) {
                presence_checker = as_presence_checker_ctx!(self);
                presence_checker.feed_presence(
                    &mut carry,
                    buf.get_(        ..tail_len + got),
                    buf.get_(tail_len..tail_len + got)
                );
            }

            self.parser.stream_chunk = buf;

            if hard_error || got < len { break }  // Short of the full chunk
        }

        //
        // Flush final partial line
        //
        if !carry.tail.is_empty() {
            let tail = std::mem::take(&mut carry.tail);
            self.find_and_print_matches_in_chunk(&tail, &mut carry, /* is_last */ true)?;

            if track_presence && (!carry.found_any || !stop_at_first_match) {
                presence_checker = as_presence_checker_ctx!(self);
                presence_checker.feed_presence(&mut carry, &tail, &[]);
            }

            carry.tail = tail;
            carry.tail.clear();
        }

        self.stats.files_searched += 1;
        self.stats.bytes_searched += bytes_searched as u64;

        if carry.found_any {
            self.stats.files_contained_matches += 1;
        }

        //
        // A row is only trustworthy if every byte of the file was scanned: no read error or short
        // read (bytes_searched < planned), and no truncation to max_size.
        //
        let complete = bytes_searched == planned && max_size as u64 >= node.size();

        let found_any = carry.found_any;
        self.chunk_carry = Some(carry);
        Ok((found_any, track_presence && complete))
    }
}

pub struct WorkerPresenceCheckerCtx<'a> {
    pub scratch:                   &'a mut Vec<u8>,
    pub file:                      &'a mut Vec<u8>,

    pub selected_fragment_hash_len: u32,
    pub fragment_hashes:           &'a [u32],
    pub fragment_index:            &'a IntSet<u32>,

    pub fragment_presence_scratch: &'a mut Vec<u64>,

    pub stats:                     &'a mut Stats,

    pub ignore_case:                bool,
}

macro_rules! scan_taken {
    ($self:expr, $field:expr) => {{
        let taken = std::mem::take($field);
        $self.scan_fragments(&taken);
        *$field = taken;
    }};
}

impl WorkerPresenceCheckerCtx<'_> {
    #[inline(always)]
    fn feed_presence(&mut self, carry: &mut ChunkCarry, data: &[u8], new_bytes: &[u8]) {
        dispatch_wide!(
            self, carry.encoding,

            narrow => self.check_fragment_presence_in_seam(&mut carry.seam, new_bytes),
            wide   => presence_wide(&mut carry.seam, data.get_(carry.consumed.0 .. carry.consumed.1))
        )
    }

    #[inline(always)]
    fn reset_fragment_presence(&mut self) {
        unsafe {
            std::ptr::write_bytes(
                self.fragment_presence_scratch.as_mut_ptr(),
                0,
                self.fragment_presence_scratch.len()
            );
        }
    }

    #[inline(always)]
    fn scan_fragments(&mut self, data: &[u8]) {
        let t0 = Instant::now();

        crate::fragments::check_fragment_presence(
            data,
            self.fragment_hashes,
            self.fragment_presence_scratch,
            self.fragment_index,
            self.selected_fragment_hash_len as usize,
            self.ignore_case
        );

        self.stats.time_spent_fragment_presence_checking_in_nanos += t0.elapsed().as_nanos() as u64;
    }

    #[inline(always)]
    fn check_fragment_presence(&mut self) {
        let enc = crate::binary::detect_byte_order_leading_mark_len(self.file);
        dispatch_wide!(
            self, enc,

            narrow => {},
            wide   => return check_fragment_presence_wide(enc.unwrap_().bom_len())
        );

        let _span = tracy::span!("check_fragment_presence");

        self.reset_fragment_presence();
        scan_taken!(self, self.file);
    }

    #[cold]
    #[inline(never)]
    fn check_fragment_presence_wide<C: LineCodec>(&mut self, bom: usize) {
        let t0 = Instant::now();
        self.reset_fragment_presence();

        let file = std::mem::take(self.file);
        let body = file.get_(bom.min(file.len())..);

        if decode_whole_file_right_away(body.len()) {
            //
            // find_and_print_matches_small_decode already decoded the whole file into
            // 'parser.scratch' and left it there since there was no match.
            //
            // @Important: @Correctness requires that nothing touches 'parser.scratch' between
            // find_and_print_matches() and here...
            //
            scan_taken!(self, self.scratch);
        } else {
            let mut seam = PresenceSeam::EMPTY;
            self.presence_wide::<C>(&mut seam, body);
        }

        *self.file = file;
        self.stats.time_spent_fragment_presence_checking_in_nanos += t0.elapsed().as_nanos() as u64;
    }

    #[inline(never)]
    fn presence_wide<C: LineCodec>(&mut self, seam: &mut PresenceSeam, raw: &[u8]) {
        const DECODE_SPAN: usize = 64 * 1024;  // @Tune: How much raw input we decode per iteration

        let mut dec = std::mem::take(self.scratch);
        let mut pos = 0;
        while pos < raw.len() {
            let end = if raw.len() - pos <= DECODE_SPAN {
                raw.len()
            } else {
                match C::find_newline(raw.get_(pos + DECODE_SPAN..)) {
                    Some(rel) => pos + DECODE_SPAN + rel + C::UNIT_WIDTH,
                    None      => raw.len(),  // One giant line ... same HWM as the matcher
                }
            };

            dec.clear();
            C::decode_line(raw.get_(pos..end), &mut dec);
            self.check_fragment_presence_in_seam(seam, &dec);

            pos = end;
        }

        *self.scratch = dec;
    }

    //
    // Streaming counterpart of check_fragment_presence(): feed it the pieces of a file in order.
    //
    // 'seam' carries the last (fragment_length - 1) bytes seen so far, so fragments that
    // straddle two pieces are found too.
    //
    fn check_fragment_presence_in_seam(&mut self, seam: &mut PresenceSeam, data: &[u8]) {
        if data.is_empty() { return; }

        let keep = self.selected_fragment_hash_len as usize - 1; // 2 or 3

        self.scan_fragments(data);

        //
        // Fragments that start in the seam and end in this piece, at most 3 + 3 bytes.
        //
        let old = seam.len as usize;
        if old > 0 {
            let head = data.len().min(keep);

            let mut joined = [0u8; 8];  // Zero tail doubles as the < 4 pad
            joined.get_mut_(   ..old)       .copy_from_slice(seam.bytes.get_(..old));
            joined.get_mut_(old..old + head).copy_from_slice(data      .get_(..head));

            crate::fragments::check_fragment_presence(
                joined.get_(..old + head),
                self.fragment_hashes, self.fragment_presence_scratch,
                self.fragment_index, keep + 1, self.ignore_case,
            );
        }

        //
        // New seam = last 'keep' bytes of (old seam ++ data)
        //

        let d = data.len();
        if d >= keep {
            seam.bytes[..keep].copy_from_slice(&data[d - keep..]);
            seam.len = keep as u8;

            return;
        }

        let mut tmp = [0u8; 6];  // old <= 3, d < keep <= 3
        tmp.get_mut_(   ..old)    .copy_from_slice(seam.bytes.get_(..old));
        tmp.get_mut_(old..old + d).copy_from_slice(data);

        let total = old + d;
        let n = total.min(keep);

        seam.bytes.get_mut_(..n).copy_from_slice(tmp.get_(total - n..total));
        seam.len = n as u8;
    }
}

#[inline(always)]
pub const fn decode_whole_file_right_away(raw_len_after_bom: usize) -> bool {
    raw_len_after_bom != 0 && raw_len_after_bom <= SMALL_FILE_DECODE_THRESHOLD
}

macro_rules! as_print_ctx {
    ($w:expr) => {
        WorkerPrintCtx {
            scratch:                 &mut $w.parser.scratch,
            scratch2:                &mut $w.parser.scratch2,
            matcher:                 &mut $w.matcher,
            matcher_cache:           $w.matcher_cache.as_deref_mut(),
            ranges_scratch:          &mut $w.ranges_scratch,
            line_ranges_scratch:     &mut $w.line_ranges_scratch,
            newlines_scratch:        &mut $w.newlines_scratch,
            output:                  &mut $w.output,
            cli:                          $w.cli,
            path_buf:                &$w.path_buf,
            print_line_numbers:           $w.print_line_numbers,
            files_contained_matches: &mut $w.stats.files_contained_matches,
            sink:                    &mut $w.sink,
            red: $w.red, green: $w.green, cyan: $w.cyan,
        }
    };
}

// impl block for printing matches
#[allow(clippy::while_let_on_iterator)]
impl<F: RawFs, S: MatchSink> WorkerCtx<'_, F, S> {
    #[inline(always)]
    fn find_and_print_matches(&mut self) -> io::Result<bool> {
        as_print_ctx!(self).find_and_print_matches(&self.parser.file)
    }

    #[inline(always)]
    fn find_and_print_matches_in_chunk(
        &mut self,
        data: &[u8],
        carry: &mut ChunkCarry,
        is_last: bool,
    ) -> io::Result<()> {
        as_print_ctx!(self).find_and_print_matches_in_chunk(data, carry, is_last)
    }
}

pub struct WorkerPrintCtx<'a, S: MatchSink> {
    pub scratch:                 &'a mut Vec<u8>,
    pub scratch2:                &'a mut Vec<u8>,
    pub matcher:                 &'a Matcher,
    pub matcher_cache:    Option<&'a mut MatcherCache>,
    pub ranges_scratch:          &'a mut Vec<(u32, u32)>,
    pub line_ranges_scratch:     &'a mut Vec<(u32, u32)>,
    pub newlines_scratch:        &'a mut Vec<u32>,
    pub output:                  &'a mut OutputSlotWriter,
    pub cli:                     &'a Cli,
    pub path_buf:                &'a [u8],
    pub print_line_numbers:       bool,
    pub files_contained_matches: &'a mut u32,
    pub sink:                    &'a mut S,

    pub red:   &'static str,
    pub green: &'static str,
    pub cyan:  &'static str,
}

// impl block for printing matches
#[allow(clippy::while_let_on_iterator)]
impl<S: MatchSink> WorkerPrintCtx<'_, S> {
    #[inline(always)]
    pub fn find_and_print_matches(&mut self, file: &[u8]) -> io::Result<bool> {
        let _span = tracy::span!("find_and_print_matches");

        if file.is_empty() { return Ok(false); }

        let enc = crate::binary::detect_byte_order_leading_mark_len(file);

        match enc {
            None | Some(Encoding::Utf8) => {
                let skip = if enc.is_some() { 3 } else { 0 };
                self.find_and_print_matches_impl::<RawCodec>(file, skip)
            }

            Some(enc) => self.find_and_print_matches_wide(file, enc),
        }
    }

    #[cold]
    #[inline(never)]
    fn find_and_print_matches_wide(&mut self, file: &[u8], enc: Encoding) -> io::Result<bool> {
        match enc {
            Encoding::Utf16LE => self.find_and_print_matches_impl::<Utf16LeCodec>(file, 2),
            Encoding::Utf16BE => self.find_and_print_matches_impl::<Utf16BeCodec>(file, 2),
            Encoding::Utf32LE => self.find_and_print_matches_impl::<Utf32LeCodec>(file, 4),
            Encoding::Utf32BE => self.find_and_print_matches_impl::<Utf32BeCodec>(file, 4),
            Encoding::Utf8    => unsafe { std::hint::unreachable_unchecked() }
        }
    }

    #[inline(always)]
    fn find_and_print_matches_impl<C: LineCodec>(&mut self, file: &[u8], skip: usize) -> io::Result<bool> {
        let buf = file.get_(skip..);

        let buf_len = buf.len();
        if buf_len == 0 { return Ok(false); }

        if !C::RAW_PASSTHROUGH && decode_whole_file_right_away(buf_len) {
            return self.find_and_print_matches_small_decode::<C>(file, skip);
        }

        let should_print_color        = should_enable_ansi_coloring();
        let should_print_line_numbers = self.print_line_numbers;

        if C::RAW_PASSTHROUGH {
            //
            // Search the whole buffer first.
            //
            // Most files in a typical run contain zero matches, so
            // this lets us return before ever building newlines_scratch and so on.
            //

            debug_assert_eq!(C::UNIT_WIDTH, 1);

            self.ranges_scratch.clear();
            self.matcher.push_all_matches(
                buf,
                self.matcher_cache.as_deref_mut(),
                self.ranges_scratch,
            );

            if self.ranges_scratch.is_empty() {
                return Ok(false);
            }

            let mut found_any = false;
            let mut scan_pos  = 0usize;  // Start of the next line we haven't resolved yet
            let mut line_num  = 1u32;
            let mut i         = 0usize;

            while i < self.ranges_scratch.len() {
                let (m_start, line_start) = Self::resolve_match_line_bounds(
                    buf, self.ranges_scratch, i, scan_pos, &mut line_num, should_print_line_numbers,
                );

                //
                // The next newline at or after m_start, since we already know
                // where the line starts.
                //

                let line_end = C::find_newline(buf.get_(m_start..))
                    .map(|rel| m_start + rel)
                    .unwrap_or(buf_len);

                let line = C::strip_trailing_cr(buf.get_(line_start..line_end));

                Self::collect_line_ranges(
                    self.ranges_scratch,
                    self.line_ranges_scratch,
                    &mut i,
                    line_start, line_end, line.len(), |_| {},
                );

                self.scratch2.clear();

                Self::emit_match(
                    self.output,
                    self.scratch2,
                    self.cli,
                    self.path_buf,
                    &mut found_any,
                    line_num,
                    line,
                    self.line_ranges_scratch,
                    should_print_color,
                    should_print_line_numbers,
                    self.sink,
                    self.red, self.green, self.cyan,
                );

                scan_pos = (line_end + C::UNIT_WIDTH).min(buf_len);
                line_num += 1;
            }

            if found_any {
                *self.files_contained_matches += 1;
            }

            return Ok(found_any);
        }

        //
        // Collect every raw newline offset up front, so UTF-16/32 '\n'
        // sequences are found at the right stride instead of assuming one byte/line.
        //

        self.newlines_scratch.clear();
        self.newlines_scratch.reserve(average_newline_count_heuristic(buf_len));

        let mut scan_pos = 0usize;
        while let Some(rel) = C::find_newline(buf.get_(scan_pos..)) {
            let abs = scan_pos + rel;
            self.newlines_scratch.push(abs as u32);

            scan_pos = abs + C::UNIT_WIDTH;
        }

        let mut found_any  = false;
        let mut line_start = 0;
        let mut line_num   = 1u32;

        let last_newline_end = self.newlines_scratch.last().map(|&p| p as usize + C::UNIT_WIDTH).unwrap_or(0);
        let sentinel = (last_newline_end < buf_len).then_some(buf_len as u32);

        for &newline_pos in self.newlines_scratch.iter().chain(sentinel.iter()) {
            let line_end = newline_pos as usize;
            if line_end < buf_len {
                prefetch_read(unsafe { buf.as_ptr().add((line_end + C::UNIT_WIDTH).min(buf_len)) });
            }

            let raw_line = C::strip_trailing_cr(buf.get_(line_start..line_end));

            //
            // Non-UTF-8 sources get transcoded one line at a time into a
            // small reusable buffer, so that a huge UTF-16 file doesn't cost
            // a second huge allocation.
            //
            let line: &[u8] = {
                self.scratch.clear();
                C::decode_line(raw_line, self.scratch);
                self.scratch.as_slice()
            };

            //
            // This line hasn't been matched yet, so match its decoded bytes now.
            //
            let line_matches: &[(u32, u32)] = {
                self.ranges_scratch.clear();
                self.matcher.push_all_matches(
                    line,
                    self.matcher_cache.as_deref_mut(),
                    self.ranges_scratch,
                );

                self.ranges_scratch
            };

            if !line_matches.is_empty() {
                self.scratch2.clear(); // @Speed?

                Self::emit_match(
                    self.output,
                    self.scratch2,
                    self.cli,
                    self.path_buf,
                    &mut found_any,
                    line_num,
                    line,
                    line_matches,
                    should_print_color,
                    should_print_line_numbers,
                    self.sink,
                    self.red, self.green, self.cyan,
                );
            }

            if line_end >= buf_len { break }

            line_start = line_end + C::UNIT_WIDTH;
            line_num  += 1;
        }

        if found_any {
            *self.files_contained_matches += 1;
        }

        Ok(found_any)
    }

    pub fn find_and_print_matches_in_chunk(
        &mut self,
        data: &[u8],
        carry: &mut ChunkCarry,
        is_last: bool,
    ) -> io::Result<()> {
        let _span = tracy::span!("find_and_print_matches_in_chunk");

        carry.consumed = (0, 0);

        if data.is_empty() { return Ok(()); }

        //
        // The encoding is only knowable from the very first chunk, so sniff it
        // once and remember it on the carry for every later chunk of this file.
        //
        let (encoding, skip) = match carry.encoding {
            Some(e) => (e, 0),
            None => match crate::binary::detect_byte_order_leading_mark_len(data) {
                Some(e) => { carry.encoding = Some(e);              (e, e.bom_len())    }
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
        let data = data.get_(skip..);
        if data.is_empty() { return Ok(()) }

        let should_print_color        = should_enable_ansi_coloring();
        let should_print_line_numbers = self.print_line_numbers;

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

        if !C::RAW_PASSTHROUGH {
            carry.consumed = (skip, skip + process_until);
        }

        if C::RAW_PASSTHROUGH {
            debug_assert_eq!(C::UNIT_WIDTH, 1);

            let region = data.get_(..process_until);

            self.ranges_scratch.clear();
            self.matcher.push_all_matches(
                region,
                self.matcher_cache.as_deref_mut(),
                self.ranges_scratch,
            );

            if self.ranges_scratch.is_empty() {
                //
                // carry.line_num has to stay correct for whatever chunk comes next, but only
                // if it's ever actually read -- same guard as the non-chunk path.
                //
                if should_print_line_numbers || S::STDOUT_NOP {
                    carry.line_num += crate::bytecount::count(region, b'\n') as u32;
                }

                carry.tail.clear();
                if !is_last && process_until < data.len() {
                    carry.tail.extend_from_slice(data.get_(process_until..));
                }

                return Ok(());
            }

            let mut scan_pos = 0usize;
            let mut i        = 0usize;

            while i < self.ranges_scratch.len() {
                let (m_start, line_start) = Self::resolve_match_line_bounds(
                    region, self.ranges_scratch, i, scan_pos, &mut carry.line_num, should_print_line_numbers,
                );

                let line_end = memchr::memchr(b'\n', region.get_(m_start..))
                    .map(|rel| m_start + rel)
                    .unwrap_or(process_until);

                let line = C::strip_trailing_cr(region.get_(line_start..line_end));

                Self::collect_line_ranges(
                    self.ranges_scratch, self.line_ranges_scratch, &mut i,
                    line_start, line_end, line.len(), |_| {},
                );

                self.scratch2.clear();

                Self::emit_match(
                    self.output,
                    self.scratch2,
                    self.cli,
                    self.path_buf,
                    &mut carry.found_any,
                    carry.line_num,
                    line,
                    self.line_ranges_scratch,
                    should_print_color,
                    should_print_line_numbers,
                    self.sink,
                    self.red, self.green, self.cyan,
                );

                scan_pos = (line_end + 1).min(process_until);
                carry.line_num += 1;
            }

            carry.tail.clear();
            if !is_last && process_until < data.len() {
                carry.tail.extend_from_slice(data.get_(process_until..));
            }

            return Ok(());
        }

        self.newlines_scratch.clear();
        self.newlines_scratch.reserve(average_newline_count_heuristic(data.len()));

        let mut scan_pos = 0usize;
        while let Some(rel) = C::find_newline(data.get_(scan_pos..)) {
            let abs = scan_pos + rel;
            self.newlines_scratch.push(abs as u32);

            scan_pos = abs + C::UNIT_WIDTH;
        }

        let mut line_start = 0usize;

        //
        // The sentinel stands for a real unterminated final line -- content after the last
        // newline with no '\n' of its own.
        //
        // When the last real newline already reaches process_until (true on every non-last
        // streaming chunk, and on any buffered file/final chunk ending in '\n'), there is no
        // such line; adding the sentinel anyway makes the loop process a phantom empty 'line'
        // past the real content.
        //
        let last_newline_end = self.newlines_scratch.last().map(|&p| p as usize + C::UNIT_WIDTH).unwrap_or(0);
        let sentinel = (last_newline_end < process_until).then_some(process_until as u32);

        for &newline_pos in self.newlines_scratch.iter().chain(sentinel.iter()) {
            let line_end = newline_pos as usize;

            let raw_line = C::strip_trailing_cr(data.get_(line_start..line_end));

            self.scratch.clear();
            C::decode_line(raw_line, self.scratch);
            let line: &[u8] = self.scratch.as_slice();

            self.ranges_scratch.clear();
            self.matcher.push_all_matches(
                line,
                self.matcher_cache.as_deref_mut(),
                self.ranges_scratch,
            );

            if !self.ranges_scratch.is_empty() {
                self.scratch2.clear(); // @Speed?

                Self::emit_match(
                    self.output,
                    self.scratch2,
                    self.cli,
                    self.path_buf,
                    &mut carry.found_any,
                    carry.line_num,
                    line,
                    self.ranges_scratch,
                    should_print_color,
                    should_print_line_numbers,
                    self.sink,
                    self.red, self.green, self.cyan,
                );
            }

            if line_end >= process_until { break; }

            line_start = line_end + C::UNIT_WIDTH;
            carry.line_num += 1;
        }

        carry.tail.clear();
        if !is_last && process_until < data.len() {
            carry.tail.extend_from_slice(data.get_(process_until..));
        }

        Ok(())
    }

    #[inline(never)]
    fn find_and_print_matches_small_decode<C: LineCodec>(&mut self, file: &[u8], skip: usize) -> io::Result<bool> {
        //
        // This monomorphization firewall here reduces the executable size
        // by ~55KB, it's nice I guess.
        //

        let buf = file.get_(skip..);

        let buf_len = buf.len();
        if buf_len == 0 { return Ok(false); }

        self.scratch.clear();
        C::decode_line(buf, self.scratch);

        self.find_and_print_matches_small_decode_impl()
    }

    #[inline(never)]
    fn find_and_print_matches_small_decode_impl(&mut self) -> io::Result<bool> {
        let decoded_len = self.scratch.len();
        if decoded_len == 0 { return Ok(false); }

        //
        // Search the whole buffer first.
        //
        // Most files in a typical run contain zero matches, so this lets us
        // return before ever building newlines_scratch and so on.
        //
        // Note this walks the *decoded* buffer, so unlike the RAW_PASSTHROUGH
        // loops above it can't use C::find_newline / C::strip_trailing_cr --
        // decode_line has already normalized everything to plain bytes with
        // single-byte '\n's, regardless of what C originally was.
        //

        self.ranges_scratch.clear();
        {
            let decoded = self.scratch.as_slice();
            self.matcher.push_all_matches(
                decoded,
                self.matcher_cache.as_deref_mut(),
                self.ranges_scratch,
            );
        }
        if self.ranges_scratch.is_empty() { return Ok(false); }

        let should_print_color        = should_enable_ansi_coloring();
        let should_print_line_numbers = self.print_line_numbers;

        let mut found_any = false;
        let mut i         = 0;
        let mut scan_pos  = 0usize;
        let mut line_num  = 1u32;

        while i < self.ranges_scratch.len() {
            let decoded = self.scratch.as_slice();

            let (m_start, line_start) = Self::resolve_match_line_bounds(
                decoded,
                self.ranges_scratch, i, scan_pos,
                &mut line_num, should_print_line_numbers,
            );

            let line_end = memchr::memchr(b'\n', decoded.get_(m_start..))
                .map(|rel| m_start + rel)
                .unwrap_or(decoded_len);

            let raw_line = decoded.get_(line_start..line_end);
            let line = if raw_line.last() == Some(&0x0D) {
                raw_line.get_(..raw_line.len() - 1)
            } else {
                raw_line
            };

            let ranges_scratch_ptr: *const Vec<_> = &*self.ranges_scratch;
            Self::collect_line_ranges(
                self.ranges_scratch, self.line_ranges_scratch, &mut i, line_start, line_end, line.len(),

                |next_i| {
                    //
                    // Warm the next match's line while we process the current one.
                    //
                    // SAFETY: read-only prefetch hint, ranges_scratch isn't
                    // mutated between here and the read (same as original).
                    //
                    let ranges_scratch = unsafe { &*ranges_scratch_ptr };
                    if let Some(&(next_start, _)) = ranges_scratch.get(next_i) {
                        prefetch_read(unsafe { decoded.as_ptr().add(next_start as usize) });
                    }
                },
            );

            self.scratch2.clear();

            Self::emit_match(
                self.output,
                self.scratch2,
                self.cli,
                self.path_buf,
                &mut found_any,
                line_num,
                line,
                self.line_ranges_scratch,
                should_print_color,
                should_print_line_numbers,
                self.sink,
                self.red, self.green, self.cyan,
            );

            scan_pos = (line_end + 1).min(decoded_len);
            line_num += 1;
        }

        if found_any {
            *self.files_contained_matches += 1;
        }

        Ok(found_any)
    }

    /// Pulls the next candidate match out of `ranges_scratch[i]`, clamps it
    /// against `scan_pos`, and resolves the start of the line it falls on via
    /// a backward scan. Also bumps `line_num` by however many newlines were
    /// skipped over, when that count is actually observable.
    ///
    /// `buf` is whatever the match offsets are relative to, since this
    /// never touches codec-specific newline semantics (that's still up to
    /// the caller, per the RAW_PASSTHROUGH/decoded distinction below).
    #[inline(always)]
    fn resolve_match_line_bounds(
        buf: &[u8],
        ranges_scratch: &[(u32, u32)],
        i: usize,
        scan_pos: usize,
        line_num: &mut u32,
        should_print_line_numbers: bool,
    ) -> (usize, usize) {
        let m_start = ranges_scratch.get_(i).0 as usize;

        //
        // The matcher is expected to return sorted non-overlapping ranges.
        //

        debug_assert!(
            m_start >= scan_pos,
            "matcher returned an out-of-order or overlapping match: m_start={} scan_pos={}",
            m_start, scan_pos
        );

        let m_start = m_start.max(scan_pos);

        let line_start = match memchr::memrchr(b'\n', buf.get_(scan_pos..m_start)) {
            Some(rel) => scan_pos + rel + 1,
            None      => scan_pos,
        };

        //
        // line_num is only observable via the printed column or
        // S::push (which always takes one); skip the O(gap) count
        // otherwise so a sparse match in a huge file doesn't pay
        // for newlines it never reports.
        //
        if should_print_line_numbers || S::STDOUT_NOP {
            *line_num += crate::bytecount::count(buf.get_(scan_pos..line_start), b'\n') as u32;
        }

        (m_start, line_start)
    }

    /// Given a resolved 'line_end', groups every consecutive entry in
    /// 'ranges_scratch' starting at 'i' that still falls on this line,
    /// advances '*i' past them, and rewrites that group into 'line_ranges_scratch'
    /// as offsets relative to the line instead of the whole buffer.
    ///
    /// 'mid_hook' runs right after the group is found but before the relative
    /// ranges are built, and is handed the post-group index, small_decode uses
    /// this to prefetch the next match's line while this one is still being formatted.
    #[inline(always)]
    fn collect_line_ranges(
        ranges_scratch: &[(u32, u32)],
        line_ranges_scratch: &mut Vec<(u32, u32)>,
        i: &mut usize,
        line_start: usize,
        line_end: usize,
        line_len: usize,
        mid_hook: impl FnOnce(usize),
    ) {
        let group_start = *i;
        while *i < ranges_scratch.len()
        && (ranges_scratch.get_(*i).0 as usize) < line_end
        {
            *i += 1;
        }

        if *i == group_start { *i += 1; }

        let i = *i;

        mid_hook(i);

        let global_matches = ranges_scratch.get_(group_start..(i).min(ranges_scratch.len()));

        let line_start_u32 = line_start as u32;
        let line_len_u32   = line_len   as u32;

        line_ranges_scratch.clear();
        line_ranges_scratch.extend(global_matches.iter().map(|&(s, e)| {
            let rel_end   = e.saturating_sub(line_start_u32).min(line_len_u32);
            let rel_start = s.saturating_sub(line_start_u32).min(rel_end);
            (rel_start, rel_end)
        }));
    }

    /// The tail every printed match goes through: write the file header the
    /// first time this file/chunk produces a match, write the match line
    /// itself, and push it to the sink if the sink wants it.
    ///
    /// Assumes `scratch2` has already been cleared by the caller and `line` is
    /// bound at the call site.
    #[inline(always)]
    #[allow(clippy::too_many_arguments, reason = "alwaysinline")]
    fn emit_match(
        output:                                  &mut OutputSlotWriter,
        scratch2:                                &mut Vec<u8>,

        cli:                                     &Cli,
        path:                                    &[u8],

        found_any:                               &mut bool,

        line_num:                                 u32,
        line:                                    &[u8],
        matches:                                 &[(u32, u32)],

        should_print_color:                       bool,
        should_print_line_numbers:                bool,

        sink:                                    &mut S,

        red:   &'static str, green: &'static str, cyan:  &'static str,
    ) {
        if !*found_any {
            //
            // First match!!
            //

            *found_any = true;

            Self::write_file_header(scratch2, cli, path, should_print_color, green);
        }

        Self::write_match_line(
            output,
            scratch2,
            cli,
            path,
            line,
            line_num,
            matches,
            should_print_color,
            should_print_line_numbers,
            red, green, cyan,
        );

        if S::STDOUT_NOP {  // @Memory
            sink.push(path.as_ref(), line_num as _, line, matches);
        }
    }

    #[inline(always)]
    fn write_file_header(
        mut scratch:        &mut Vec<u8>,
        cli:                &Cli,
        path:               &[u8],

        should_print_color: bool,
        green: &'static str,
    ) {
        if cli.jump { return }

        let root = cli.search_root_path.as_bytes();
        let ends_with_slash = root.last() == Some(&(MAIN_SEPARATOR as _));

        let color_start: &[u8] = if should_print_color { green.as_bytes() }       else { &[] };
        let sep:         &[u8] = if ends_with_slash    { &[] }                    else { &[MAIN_SEPARATOR as u8] };
        let color_end:   &[u8] = if should_print_color { COLOR_RESET.as_bytes() } else { &[] };

        crate::batch_extend_pod!(scratch, [color_start, root, sep, path, color_end, b":\n"]);
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments, reason = "alwaysinline")]
    fn write_match_line(
        output:            &mut OutputSlotWriter,
        mut scratch:       &mut Vec<u8>,
        cli:               &Cli,
        path:              &[u8],
        line:              &[u8],
        line_num:           u32,
        matches:           &[(u32, u32)],

        should_print_color:       bool,
        should_print_line_number: bool,

        red:   &'static str,
        green: &'static str,
        cyan:  &'static str,
    ) {
        const MAX_DISPLAY: usize = 500;
        const ELLIPSIS:    &[u8] = b"...";

        let mut itoa_buf = itoa::Buffer::new();
        let line_num_str = if should_print_line_number {
            itoa_buf.format(line_num)
        } else {
            ""
        };

        if cli.jump {
            let root = cli.search_root_path.as_bytes();
            let ends_with_slash = root.last() == Some(&(MAIN_SEPARATOR as _));

            let color_start: &[u8] = if should_print_color { green.as_bytes() }       else { &[] };
            let sep:         &[u8] = if ends_with_slash    { &[] }                    else { &[MAIN_SEPARATOR as u8] };
            let color_end:   &[u8] = if should_print_color { COLOR_RESET.as_bytes() } else { &[] };

            crate::batch_extend_pod!(scratch, [color_start, root, sep, path, color_end, b":"]);
        }

        if !line_num_str.is_empty() {
            let color_start: &[u8] = if should_print_color { cyan.as_bytes() } else { &[] };
            let color_end:   &[u8] = if should_print_color { COLOR_RESET.as_bytes() } else { &[] };

            crate::batch_extend_pod!(scratch, [color_start, line_num_str.as_bytes(), color_end, b": "]);
        } else {
            scratch.push(b' ');
        }

        //
        // The whole line fits, just dump it.
        //
        if likely(line.len() <= MAX_DISPLAY) {
            let display = line;

            let mut reserve_len = display.len() + 1;
            if should_print_color {
                reserve_len += matches.len() * (crate::color::BOLD.len() + red.len() + COLOR_RESET.len());
            }
            scratch.reserve(reserve_len);

            let mut last = 0;
            let mut w = RawAppend::new(scratch);

            for &(s, e) in matches {
                let s = s as usize;
                let e = e as usize;

                if s >= display.len() { break; }
                let e = e.min(display.len());

                // SAFETY: the non-highlighted spans of 'display' (the 'last..s' pieces across
                // every iteration) sum to at most 'display.len()' since they partition it as
                // 'last' only advances, each iteration contributes at most one BOLD+red+reset
                // wrap, bounded by 'matches.len()'. Together that's exactly 'reserve_len'.
                unsafe {
                    w.extend(display.get_(last..s));

                    if should_print_color {
                        w.extend(crate::color::BOLD.as_bytes());
                        w.extend(red.as_bytes());
                    }

                    w.extend(display.get_(s..e));

                    if should_print_color { w.extend(COLOR_RESET.as_bytes()); }
                }

                last = e;
            }

            unsafe {
                w.extend(display.get_(last..));
                w.push(b'\n');
            }
            w.finish();

            output.write_record(scratch);
            return;
        }

        //
        // Slow path: ... needs truncation. Window is chosen around the first
        // match, with ellipsis markers on truncated sides.
        //
        let first_match_start = matches
            .first()
            .map(|&(s, _)| (s as usize).min(line.len()))
            .unwrap_or(0);

        //
        // Worst case budget reserves room for both ellipses; if only one
        // side ends up truncated we simply waste up to 3 bytes of width.
        //
        let content_budget = MAX_DISPLAY - ELLIPSIS.len() * 2;

        //
        // ~1/3 of the budget as leading context, the rest for the match + tail.
        //
        let context_before = content_budget / 3;
        let mut start = first_match_start.saturating_sub(context_before);

        //
        // Snap start down to a UTF-8 boundary.
        //
        while start > 0 && start < line.len() && (*line.get_(start) & 0xC0) == 0x80 {
            start -= 1;
        }

        let mut end = start + truncate_utf8(line.get_(start..), content_budget).len();

        //
        // If we reached EOL with budget to spare, pull `start` further back.
        //
        if end == line.len() && start > 0 {
            let slack = content_budget - (end - start);
            if slack > 0 {
                let mut new_start = start.saturating_sub(slack);

                while new_start > 0
                && new_start < line.len()
                && (*line.get_(new_start) & 0xC0) == 0x80
                {
                    new_start -= 1;
                }

                if line.len() - new_start <= content_budget {
                    start = new_start;
                    end   = line.len();
                }
            }
        }

        let pre_ell     = start > 0;
        let post_ell    = end < line.len();
        let display     = line.get_(start..end);
        let display_len = display.len();

        let mut reserve_len = display_len + 1;
        if pre_ell  { reserve_len += ELLIPSIS.len(); }
        if post_ell { reserve_len += ELLIPSIS.len(); }
        if should_print_color {
            reserve_len += matches.len() * (red.len() + COLOR_RESET.len());
        }
        scratch.reserve(reserve_len);

        let mut w = RawAppend::new(scratch);

        if pre_ell { unsafe { w.extend(ELLIPSIS); } }

        let mut last = 0usize;
        let abs_end = end;

        for &(s, e) in matches {
            let s = s as usize;
            let e = e as usize;

            if s >= abs_end  { break; }
            if e <= start    { continue; }

            let ds = s.saturating_sub(start).min(display_len);
            let de = e.saturating_sub(start).min(display_len);

            // SAFETY: same reasoning as the fast path above, non-highlight spans partition
            // 'display', at most 'matches.len()' red+reset wraps, matching 'reserve_len'.
            unsafe {
                w.extend(display.get_(last..ds));
                if should_print_color { w.extend(red.as_bytes()); }
                w.extend(display.get_(ds..de));
                if should_print_color { w.extend(COLOR_RESET.as_bytes()); }
            }

            last = de;
        }

        unsafe {
            w.extend(display.get_(last..));
            if post_ell { w.extend(ELLIPSIS); }
            w.push(b'\n');
        }
        w.finish();

        output.write_record(scratch);
    }
}

impl<'a, F: RawFs, S: MatchSink> WorkerCtx<'a, F, S> {
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
        let mut idle_iterations    = 0;

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
                    active_workers.fetch_add(1, Ordering::Release);
                    idle_iterations = 0;

                    _ = match work_item {
                        WorkItem::Directory(dir_work) => self.dispatch_directory(dir_work, local_worker, injector),
                        WorkItem::File(file_work)     => self.dispatch_file(file_work),
                    };

                    active_workers.fetch_sub(1, Ordering::Release);
                }

                None => {
                    idle_iterations += 1;
                    self.flush_output();

                    if active_workers.load(Ordering::Acquire) == 0
                        && injector.is_empty()
                        && local_worker.is_empty()
                    {
                        running.store(false, Ordering::Release);
                        break;
                    }

                    if idle_iterations < 10 {
                        std::hint::spin_loop();
                    } else if idle_iterations < 20 {
                        std::thread::yield_now();
                    } else {
                        std::thread::sleep(Duration::from_micros(20));
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
        //
        // Local queue
        //
        if let Some(work) = local.pop() {
            *consecutive_steals = 0;
            return Some(work);
        }

        //
        // Global injector
        //
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

        //
        // Steal from others
        //
        let start = fastrand::usize(..stealers.len());
        for i in 0..stealers.len() {
            let victim_id = (start + i) % stealers.len();
            let stealer = stealers.get_(victim_id);
            if victim_id == self.worker_id as usize || stealer.is_empty() {
                continue;
            }

            loop {
                match stealer.steal_batch_and_pop(local) {
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
