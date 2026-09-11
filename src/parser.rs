use crate::tracy;
use crate::binary::{is_binary_chunk, is_dot_entry, is_hidden_entry};
use crate::worker::BINARY_PROBE_BYTE_SIZE;
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

pub type FileId = u64;

/// Filesystem-agnostic file node info
pub trait FileNode: Copy {
    fn file_id(&self) -> FileId;
    fn size(&self) -> u64;
    fn mtime(&self) -> i64;
    fn is_dir(&self) -> bool;
}

/// Raw filesystem abstraction
pub trait RawFs: Sync + Send {
    /// Filesystem-specific file node type (e.g., Ext4Inode)
    type Node: FileNode;

    /// Filesystem-specific context (e.g., superblock + mmap reference)
    type Context<'a>: Copy where Self: 'a;

    /// Device ID for cache keys
    fn device_id(&self) -> u64;

    fn device_file(&self) -> &File;

    #[inline]
    fn read_at_offset(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        crate::util::read_at_offset(self.device_file(), buf, offset)
    }

    /// Block size in bytes
    fn block_size(&self) -> u32;

    /// Root file ID
    fn root_id(&self) -> FileId;

    /// Parse file node by ID
    fn parse_node(&self, file_id: FileId) -> io::Result<Self::Node>;

    #[inline]
    fn sort_entries_by_offset(&self, _entries: &mut [(FileId, BufFatPtr)]) {}

    /// Read file content into buffer, returns false if binary detected
    fn read_file_content(
        &self,
        parser: &mut Parser,
        node: &Self::Node,
        max_size: usize,
        kind: BufKind,
        check_binary: bool,
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
        _buf: &mut Vec<u8>
    ) -> io::Result<bool> {
        Ok(false)
    }

    /// Iterate directory entries from buffer
    fn with_directory_entries<R>(
        &self,
        buf: &[u8],
        callback: impl FnMut(FileId, usize, usize, FileType) -> ControlFlow<R>
    ) -> Option<R>;

    fn directory_entry_count_hint(&self, buf: &[u8]) -> usize;
}

/// Result of scanning directory entries
pub struct DirScanResult {
    pub file_count:    u32,
    pub dir_count:     u32,
    pub entries_start: usize,
    pub entries_end:  usize,
}

/// Filesystem-agnostic parser with reusable buffers
pub struct Parser {
    pub dont_skip_dot_entries: bool,

    pub file:      Vec<u8>,                // 0

    // Filesystem-specific scratch space
    pub scratch:   Vec<u8>,                // 24
    pub scratch2:  Vec<u8>,                // 48
    pub scratch3:  Vec<u64>,               // 48

    // =============== Cache line ======================

    pub dir:       Vec<u8>,                // 72
    pub gitignore: Vec<u8>,                // 96
    pub chunk:     Vec<u8>,

    pub scratch_chunks:  Vec<(u64, u32)>,
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
            chunk: Vec::new(),
        }
    }

    #[inline(always)]
    pub fn init(&mut self, config: &BufferConfig) {
        self.dir.reserve(config.dir_buf);
        self.file.reserve(config.file_buf);
        self.gitignore.reserve(config.gitignore_buf);
        self.scratch.reserve(config.extent_buf * 8); // extents are ~8 bytes each
    }

    /// Find a file id by name in buf
    #[inline]
    pub fn find_file_id_in_buf<F: RawFs>(&self, fs: &F, name: &[u8], kind: BufKind) -> Option<FileId> {
        fs.with_directory_entries(
            self.get_buf(kind),
            |entry_id, name_start, name_len, _file_type| {
                let name_end = name_start + name_len;

                // SAFETY: bounds checked by with_directory_entries
                let name_bytes = unsafe {
                    self.dir.get_unchecked(name_start..name_end)
                };

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

                // SAFETY: bounds checked by with_directory_entries
                let name_bytes = unsafe {
                    self.dir.get_unchecked(name_start..name_end)
                };

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
        #[cfg(debug_assertions)] {
            &self.get_buf(ptr.kind)[ptr.offset as usize..(ptr.offset+ptr.len) as usize]
        }

        #[cfg(not(debug_assertions))]
        unsafe {
            self.get_buf(ptr.kind).get_unchecked(
                ptr.offset as usize..(ptr.offset+ptr.len) as usize
            )
        }
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
