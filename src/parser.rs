use crate::tracy;
use crate::binary::is_binary_chunk;
use crate::worker::BINARY_PROBE_BYTE_SIZE;
use crate::cli::BufferConfig;
use crate::util::is_dot_entry;

use std::fs::File;
use std::io;
use std::ops::ControlFlow;

use bumpalo::Bump;
use smallvec::SmallVec;
use bumpalo::collections::Vec as BumpVec;

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
pub struct ParsedEntry<Id> {
    pub file_id: Id,
    pub name_offset: u16,
    pub name_len: u8,
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
    fn sort_entries(&self, _entries: &mut [(FileId, BufFatPtr)]) {}

    /// Read file content into buffer, returns false if binary detected
    fn read_file_content(
        &self,
        parser: &mut Parser,
        node: &Self::Node,
        max_size: usize,
        kind: BufKind,
        check_binary: bool,
    ) -> io::Result<bool>;

    fn collect_file_chunks(
        &self,
        _scratch: &mut Vec<u8>,
        _scratch2: &mut Vec<u8>,
        _node: &Self::Node,
        _max_size: usize,
        _check_binary: bool,
    ) -> io::Result<Option<SmallVec<[(u64, usize); 32]>>> {
        Ok(None)
    }

    /// Iterate directory entries from buffer
    fn with_directory_entries<R>(
        &self,
        buf: &[u8],
        callback: impl FnMut(FileId, usize, usize, FileType) -> ControlFlow<R>
    ) -> Option<R>;
}

/// Result of scanning directory entries
#[allow(dead_code, reason = "@Incomplete")]
pub struct DirScanResult<const N: usize = 64> {
    pub file_count: u32,
    pub dir_count: u32,
    pub entries: SmallVec<[ParsedEntry<FileId>; N]>,
}

/// Filesystem-agnostic parser with reusable buffers
pub struct Parser<'a> {
    pub file: Vec<u8>,                      // 0
    // Filesystem-specific scratch space
    pub scratch: Vec<u8>,                   // 24
    pub scratch2: Vec<u8>,                  // 48

    // =============== Cache line ======================

    pub dir: Vec<u8>,                       // 72
    pub gitignore: Vec<u8>,                 // 96
    pub output: BumpVec<'a, u8>,            // 120

    // =============== Cache line ======================

    pub chunk: Vec<u8>,
}

impl<'a> Parser<'a> {
    #[inline(always)]
    pub fn new(bump: &'a Bump) -> Self {
        Self {
            file: Vec::new(),
            dir: Vec::new(),
            gitignore: Vec::new(),
            output: BumpVec::new_in(bump),
            scratch: Vec::new(),
            scratch2: Vec::new(),
            chunk: Vec::new()
        }
    }

    #[inline(always)]
    pub fn init(&mut self, config: &BufferConfig) {
        self.dir.reserve(config.dir_buf);
        self.file.reserve(config.file_buf);
        self.output.reserve(config.output_buf);
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
    pub fn scan_directory_entries<F: RawFs>(&self, fs: &F) -> DirScanResult {
        let _span = tracy::span!("scan_directory_entries");

        let mut file_count = 0;
        let mut dir_count = 0;
        let mut entries = SmallVec::new();

        fs.with_directory_entries(
            &self.dir,
            |entry_id, name_start, name_len, file_type| {
                let name_end = name_start + name_len;

                // SAFETY: bounds checked by with_directory_entries
                let name_bytes = unsafe {
                    self.dir.get_unchecked(name_start..name_end)
                };

                if !is_dot_entry(name_bytes) {
                    entries.push(ParsedEntry {
                        file_id: entry_id,
                        name_offset: name_start as _,
                        name_len: name_len as _,
                        file_type,
                    });

                    match file_type {
                        FileType::Dir => dir_count += 1,
                        FileType::File => file_count += 1,
                        FileType::Other => file_count += 1,
                    }
                }

                ControlFlow::<()>::Continue(())
            }
        );

        DirScanResult { file_count, dir_count, entries }
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
        match kind {
            BufKind::File      => &mut self.file,
            BufKind::Dir       => &mut self.dir,
            BufKind::Gitignore => &mut self.gitignore,
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
