use crate::tracy;
use crate::index_::Index_;
use crate::grep::{AnyNodeCache, AnyNodeHotScratch, AnyNodeColdScratch, NodeCacheStats};
use crate::binary::{is_binary_chunk, is_dot_entry, is_hidden_entry};
use crate::worker::{BINARY_PROBE_BYTE_SIZE, PendingSubdir, STREAMING_CHUNK_SIZE};
use crate::cli::BufferConfig;

use std::fs::File;
use std::io;
use std::ops::ControlFlow;

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum BufKind {
    Dir,
    File,
    Gitignore
}

#[derive(Copy, Clone)]
pub struct BufFatPtr {
    pub offset: u32,
    pub len: u32,
    pub kind: BufKind
}

#[derive(Clone, Copy)]
pub struct ParsedEntry {
    pub file_id: FileId,
    pub name_offset: u32,
    pub name_len: u16,
    pub file_type: FileType
}

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum FileType {
    File,
    Dir,
    Other
}

/// Uniquely identifies a file across reboots
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileKey {
    pub device_id: u64,
    pub inode:     u64,
}

impl FileKey {
    #[inline(always)]
    pub const fn new(device_id: u64, inode: u64) -> Self {
        Self { device_id, inode }
    }

    #[inline(always)]
    pub const fn hash(&self) -> u32 {
        ((self.device_id ^ self.inode).wrapping_mul(0x9e3779b9)) as u32
    }
}

/// Metadata for cache invalidation
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    pub mtime_sec: i64, // @Incomplete: Make this into msec (millis)?
    pub size:      u64,
}

impl FileMeta {
    #[inline(always)]
    pub const fn new(mtime_sec: i64, size: u64) -> Self {
        Self { mtime_sec, size }
    }
}

#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentifier {
    pub key:  FileKey,
    pub meta: FileMeta
}

pub type FileId = u64;

/// Filesystem-agnostic file node info
pub trait FileNode: Copy {
    /// Sentinel written into a batch slot when `parse_node` fails, so callers
    /// get a fixed-size Vec<Node> back instead of Vec<Result<Node, _>> / Vec<Option<Node>>.
    const POISONED: Self;

    fn file_id(&self) -> FileId;
    fn size(&self) -> u64;
    fn mtime_sec(&self) -> i64;
    fn is_dir(&self) -> bool;
}

/// Raw filesystem abstraction
pub trait RawFs: Sync + Send {
    /// Filesystem-specific file node type (e.g., Ext4Inode)
    type Node: FileNode;

    type NodeHot:  Copy + FileNode;   // file_id, size, mtime_sec, mode/is_dir
    type NodeCold: Copy + Default;    // flags, blocks, whatever only a surviving file reads

    type NodeCache: Default;

    /// Filesystem-specific context (e.g., superblock + mmap reference)
    type Context<'a>: Copy where Self: 'a;

    /// Device ID for cache keys
    fn device_id(&self) -> u64;

    fn device_file(&self) -> &File;

    #[inline(always)]
    fn file_identifier<N: FileNode>(&self, node: N) -> FileIdentifier {
        FileIdentifier {
            key: FileKey::new(self.device_id(), node.file_id()),
            meta: FileMeta::new(node.mtime_sec(), node.size())
        }
    }

    fn split_node(&self, node: Self::Node) -> (Self::NodeHot, Self::NodeCold);
    fn merge_node(&self, hot: Self::NodeHot, cold: Self::NodeCold) -> Self::Node;

    #[inline]
    fn read_at_offset(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        crate::util::read_at_offset(self.device_file(), buf, offset)
    }

    /// Block size in bytes
    fn block_size(&self) -> u32;

    /// Root file ID
    fn root_id(&self) -> FileId;

    // @Incomplete
    fn parse_nodes_batch(
        &self,
        entries:  &[(FileId, BufFatPtr)],
        _cache:   &mut Self::NodeCache,
        hot_out:  &mut Vec<Self::NodeHot>,
        cold_out: &mut Vec<Self::NodeCold>,
    ) -> NodeCacheStats {
        hot_out.reserve(entries.len());
        cold_out.reserve(entries.len());

        for &(id, _) in entries {
            let (hot, cold) = match self.parse_node(id) {
                Ok(node) => self.split_node(node),
                Err(_)   => (Self::NodeHot::POISONED, Self::NodeCold::default()),
            };
            hot_out.push(hot);
            cold_out.push(cold);
        }

        NodeCacheStats { hits: 0, misses: entries.len() as u32 }
    }

    /// Parse file node by ID
    fn parse_node_cached(
        &self,
        file_id: FileId,
        cache: &mut Self::NodeCache
    ) -> (io::Result<Self::Node>, NodeCacheStats);

    /// Parse file node by ID
    fn parse_node(&self, file_id: FileId) -> io::Result<Self::Node>;

    #[inline]
    fn sort_entries_by_offset(&self, _entries: &mut [(FileId, BufFatPtr)]) {}

    #[inline]
    fn sort_subdirs_by_offset(&self, _subdirs: &mut [PendingSubdir]) {}

    #[cfg(unix)]
    fn prefetch_file_head(&self, _node: &Self::Node, _max_size: usize) {}

    #[cfg(unix)]
    fn head_is_cold(&self, _node: &Self::Node, _max_size: usize) -> Option<bool> { None }

    /// Read file content into buffer, returns false if binary detected
    fn read_file_content(
        &self,
        parser: &mut Parser,
        node: &Self::Node,
        max_size: usize,
        kind: BufKind,
        check_binary: bool,
        likely_binary: bool,
    ) -> io::Result<bool>;

    #[allow(clippy::type_complexity, clippy::too_many_arguments)] // @Cleanup
    fn collect_file_chunks(
        &self,
        _scratch: &mut Vec<u8>,
        _scratch2: &mut Vec<u8>,
        _scratch3: &mut Vec<u64>,
        _scratch_chunks: &mut Vec<(u64, u32)>,
        _node: &Self::Node,
        _max_size: usize,
        _check_binary: bool,
        _likely_binary: bool,
        _buf: &mut Vec<u8>
    ) -> io::Result<bool> {
        Ok(false)
    }

    fn directory_entry_count_hint(&self, buf: &[u8]) -> usize;

    /// Iterate directory entries from buffer
    fn with_directory_entries<R>(
        &self,
        buf: &[u8],
        callback: impl FnMut(FileId, usize, usize, FileType) -> ControlFlow<R>
    ) -> Option<R>;

    fn take_node_hot_scratch(&self,  _shared: &mut AnyNodeHotScratch)  -> Vec<Self::NodeHot>  { Default::default() } // @Incomplete
    fn take_node_cold_scratch(&self, _shared: &mut AnyNodeColdScratch) -> Vec<Self::NodeCold> { Default::default() } // @Incomplete
    fn take_node_cache(&self,        _shared: &mut AnyNodeCache)       -> Self::NodeCache     { Default::default() } // @Incomplete

    fn erase_node_hot_scratch(&self,  _scratch: Vec<Self::NodeHot>)  -> AnyNodeHotScratch  { Default::default() }    // @Incomplete
    fn erase_node_cold_scratch(&self, _scratch: Vec<Self::NodeCold>) -> AnyNodeColdScratch { Default::default() }    // @Incomplete
    fn erase_node_cache(&self,        _cache: Self::NodeCache)       -> AnyNodeCache      { Default::default() }     // @Incomplete
}

/// Result of scanning directory entries
pub struct DirScanResult {
    pub file_count:    u32,
    pub dir_count:     u32,
    pub entries_start: usize,
    pub entries_end:  usize,
}

/// Filesystem-agnostic parser with reusable buffers
///
/// Buffer lifetimes -- what's safe to repurpose and what isn't:
///
///  - 'file' / 'dir' / 'gitignore': One destination buffer per BufKind.
///    A directory's entries can still be live in 'dir' (mid-iteration)
///    while a file inside it is being read into 'file', with its '.gitignore' simultaneously
///    live in 'gitignore'. Each owns its content for as long as its own traversal needs it,
///    independent of the other two.
///
///  - 'scratch' / 'scratch3': Transient, used only inside 'collect_file_chunks'
///    (extent-tree bytes / child-block stack respectively).
///    Both are guaranteed consumed/truncated back before that call returns --
///    'scratch' is then reused a second time afterwards, as the wide-encoding decode buffer
///    during presence scanning (see the correctness note above 'check_fragment_presence_wide').
///
///  - 'scratch2': check_binary's probe scratch for the direct-blocks path in
///    'collect_file_chunks' (consumed before that call returns), and separately the
///    line/header text-building scratch for 'emit_match'/'write_match_line' during
///    printing.
///
///  - 'stream_chunk': per-chunk read staging for the streaming path
///    ('process_file_streaming' in worker.rs) -- tail carry + one freshly-read chunk.
///
///  - 'scratch_chunks': the chunk list 'collect_file_chunks' builds, consumed by both the
///    buffered read loop and the streaming loop. Live for the whole read -- not throwaway
///    scratch like the rest of this list.
///
#[repr(C)]
pub struct Parser {
    pub dir:            Vec<u8>,
    pub file:           Vec<u8>,
    pub scratch:        Vec<u8>,
    pub scratch2:       Vec<u8>,
    pub scratch3:       Vec<u64>,
    pub stream_chunk:   Vec<u8>,
    pub scratch_chunks: Vec<(u64, u32)>,
    pub gitignore:      Vec<u8>,

    pub dont_skip_dot_entries: bool,
}

impl Parser {
    #[inline(always)]
    pub fn new(dont_skip_dot_entries: bool) -> Self {
        Self {
            dont_skip_dot_entries,
            file: Vec::new(),
            dir: Vec::new(),
            scratch3: Vec::new(),
            gitignore: Vec::new(),
            scratch: Vec::new(),
            scratch_chunks: Vec::new(),
            scratch2: Vec::new(),
            stream_chunk: Vec::new(),
        }
    }

    #[inline(always)]
    pub fn init(&mut self, config: &BufferConfig) {
        self.dir.reserve(config.dir_buf);
        self.file.reserve(config.file_buf);
        self.gitignore.reserve(config.gitignore_buf);
        self.scratch.reserve(config.extent_buf * 8);  // Extents are ~8 bytes each
        self.stream_chunk.reserve(2 * STREAMING_CHUNK_SIZE); // Covers tail carry + one full chunk without growing
    }

    /// Find a file id by name in buf
    #[inline]
    pub fn find_file_id_in_buf<F: RawFs>(&self, fs: &F, name: &[u8], kind: BufKind) -> Option<FileId> {
        fs.with_directory_entries(
            self.get_buf(kind),
            |entry_id, name_start, name_len, _file_type| {
                let name_end = name_start + name_len;
                let name_bytes = self.dir.get_(name_start..name_end);

                if name_bytes == name {
                    ControlFlow::Break(entry_id)
                } else {
                    ControlFlow::Continue(())
                }
            }
        )
    }

    #[inline]
    pub fn scan_directory_entries<F: RawFs>(&self, fs: &F, entries_arena: &mut Vec<ParsedEntry>) -> DirScanResult {
        let _span = tracy::span!("scan_directory_entries");

        let mut file_count = 0;
        let mut  dir_count = 0;

        let entries_start = entries_arena.len();
        let hint = fs.directory_entry_count_hint(&self.dir);
        entries_arena.reserve(hint);

        fs.with_directory_entries(
            &self.dir,
            |entry_id, name_start, name_len, file_type| {
                let name_end = name_start + name_len;
                let name_bytes = self.dir.get_(name_start..name_end);

                let skip = (
                    !self.dont_skip_dot_entries && is_hidden_entry(name_bytes)
                ) || is_dot_entry(name_bytes);
                if skip {
                    return ControlFlow::<()>::Continue(());
                }

                entries_arena.push(ParsedEntry {
                    file_id: entry_id,
                    name_offset: name_start as _,
                    name_len: name_len as _,
                    file_type,
                });

                match file_type {
                    FileType::Dir   =>  dir_count += 1,
                    FileType::File  => file_count += 1,
                    FileType::Other => file_count += 1,
                }

                ControlFlow::<()>::Continue(())
            }
        );

        DirScanResult {
            file_count,
            dir_count,
            entries_start,
            entries_end: entries_arena.len(),
        }
    }

    #[inline(always)]
    pub const fn get_buf(&self, kind: BufKind) -> &Vec<u8> {
        match kind {
            BufKind::File      => &self.file,
            BufKind::Dir       => &self.dir,
            BufKind::Gitignore => &self.gitignore,
        }
    }

    #[inline(always)]
    pub fn get_buf_mut(&mut self, kind: BufKind) -> &mut Vec<u8> {
        Self::get_buf_mut_impl(&mut self.file, &mut self.dir, &mut self.gitignore, kind)
    }

    #[inline(always)]
    pub fn get_buf_mut_impl<'b>(
        file: &'b mut Vec<u8>,
        dir: &'b mut Vec<u8>,
        gitignore: &'b mut Vec<u8>,
        kind: BufKind
    ) -> &'b mut Vec<u8> {
        match kind {
            BufKind::File      => file,
            BufKind::Dir       => dir,
            BufKind::Gitignore => gitignore,
        }
    }

    #[inline(always)]
    pub fn buf_ptr(&self, ptr: BufFatPtr) -> &[u8] {
        self.get_buf(ptr.kind).get_(ptr.offset as usize..(ptr.offset+ptr.len) as usize)
    }
}

/// Helper for binary detection during file read
#[inline]
pub fn binary_probe(block: &[u8], file_size: usize) -> bool {
    let probe_size = file_size.min(BINARY_PROBE_BYTE_SIZE).min(block.len());
    is_binary_chunk(&block[..probe_size])
}

/// Appends a (disk_offset, len) chunk, merging with the previous chunk when
/// it's exactly contiguous on disk.
///
/// Chunks are generated in strictly ascending disk-offset order per node,
/// so only the tail entry is ever a merge candidate -- no need to scan or re-sort.
#[inline]
pub fn push_chunk(scratch_chunks: &mut Vec<(u64, u32)>, disk_offset: u64, len: u32) {
    if len == 0 { return }

    if let Some(last) = scratch_chunks.last_mut() {
        let merged_len = last.1 as u64 + len as u64;
        if last.0 + last.1 as u64 == disk_offset && merged_len <= crate::worker::STREAMING_CHUNK_SIZE as u64 {
            last.1 = merged_len as u32;
            return;
        }
    }

    scratch_chunks.push((disk_offset, len));
}

//
// Splits every (disk_offset, len) chunk longer than 'max' into pieces of at most 'max' bytes,
// in-place and in-order.
//
// A no-op scan (no allocation) when nothing is oversized, which is the
// common case for fragmented files.
//
pub fn split_chunks(chunks: &mut Vec<(u64, u32)>, max: usize) {
    debug_assert!(max > 0 && max <= u32::MAX as usize);

    let max = max as u64;

    let extra: usize = chunks.iter().map(|&(_, len)| (len as u64).div_ceil(max).saturating_sub(1) as usize).sum();
    if extra == 0 { return; }

    let old_len = chunks.len();
    chunks.resize(old_len + extra, (0, 0));

    //
    // Expand from the back so no unread chunk is overwritten: after handling source chunk 'r'
    // the write cursor is still >= r, because it sits exactly 'extra-not-yet-placed' above it.
    //
    let mut w = chunks.len();

    for r in (0..old_len).rev() {
        let (off, len) = *chunks.get_(r);
        let len = len as u64;

        for k in (0..len.div_ceil(max)).rev() {
            w -= 1;
            chunks[w] = (off + k * max, (len - k * max).min(max) as u32);
        }
    }

    debug_assert_eq!(w, 0);
}

/// Precomputed reciprocal for dividing a u64 by a fixed u32 divisor
/// without a hardware DIV on every call.
#[derive(Copy, Clone)]
pub struct FastDivU32 {
    divisor: u64,
    recip:   u64, // floor(2^64 / divisor) + 1
}

impl FastDivU32 {
    #[inline]
    pub const fn new(divisor: u32) -> Self {
        assert!(divisor != 0);

        let d = divisor as u64;
        let recip = (u64::MAX / d).wrapping_add(1);
        Self { divisor: d, recip }
    }

    #[inline(always)]
    pub const fn divmod(&self, n: u64) -> (u64, u64) {
        let q = ((self.recip as u128 * n as u128) >> 64) as u64;
        let r = n - q * self.divisor;
        (q, r)
    }
}
