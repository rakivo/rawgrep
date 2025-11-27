use crate::cli::Cli;
use crate::matcher::Matcher;
use crate::stats::Stats;
use crate::path_buf::FixedPathBuf;
use crate::{copy_data, tracy, COLOR_CYAN, COLOR_GREEN, COLOR_RED, COLOR_RESET};
use crate::binary::{is_binary_chunk, is_binary_ext};
use crate::util::{
    build_gitignore_from_bytes, is_common_skip_dir, is_dot_entry, is_gitignored, likely, truncate_utf8, unlikely
};

use std::io::{self, BufWriter, Write};
use std::fmt::Display;
use std::os::fd::AsRawFd;
use std::fs::{File, OpenOptions};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ignore::gitignore::Gitignore;
use memmap2::{Mmap, MmapOptions};
use smallvec::{SmallVec, smallvec};
use crossbeam_channel::{unbounded, Receiver, Sender};
use crossbeam_deque::{Injector, Stealer, Worker as DequeWorker};

pub type INodeNum = u32;

pub const LARGE_DIR_THRESHOLD: usize = 1000; // Split dirs with 1000+ entries
pub const FILE_BATCH_SIZE: usize = 500; // Process files in batches of 500

pub const BINARY_CONTROL_COUNT: usize = 51; // tuned
pub const BINARY_PROBE_BYTE_SIZE: usize = 0x1000;

pub const PATH_VERY_LONG_LENGTH: usize = 0x1000;

pub const MAX_EXTENTS_UNTIL_SPILL: usize = 64;

pub const _MAX_DIR_BYTE_SIZE: usize = 16 * 1024 * 1024;
pub const _MAX_FILE_BYTE_SIZE: usize = 8 * 1024 * 1024;
pub const MAX_SYMLINK_TARGET_SIZE: usize = 4096;
pub const FAST_SYMLINK_SIZE: usize = 60; // Symlinks < 60 bytes stored in inode

pub const BLKGETSIZE64: libc::c_ulong = 0x80081272;

pub const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
pub const EXT4_SUPERBLOCK_SIZE: usize = 1024;
pub const EXT4_SUPER_MAGIC: u16 = 0xEF53;
pub const EXT4_MAGIC_OFFSET: usize = 56;
pub const EXT4_INODE_SIZE_OFFSET: usize = 88;
pub const EXT4_INODES_PER_GROUP_OFFSET: usize = 40;
pub const EXT4_BLOCKS_PER_GROUP_OFFSET: usize = 32;
pub const EXT4_BLOCK_SIZE_OFFSET: usize = 24;
pub const EXT4_INODE_TABLE_OFFSET: usize = 8;
pub const EXT4_ROOT_INODE: INodeNum = 2;
pub const EXT4_DESC_SIZE_OFFSET: usize = 254;
pub const EXT4_INODE_MODE_OFFSET: usize = 0;
pub const EXT4_INODE_SIZE_OFFSET_LOW: usize = 4;
pub const EXT4_INODE_SIZE_OFFSET_HIGH: usize = 108;
pub const EXT4_INODE_BLOCK_OFFSET: usize = 40;
pub const EXT4_INODE_FLAGS_OFFSET: usize = 32;

pub const EXT4_BLOCK_POINTERS_COUNT: usize = 12;

pub const EXT4_S_IFMT: u16 = 0xF000;
pub const EXT4_S_IFREG: u16 = 0x8000;
pub const EXT4_S_IFLNK: u16 = 0xA000;
pub const EXT4_S_IFDIR: u16 = 0x4000;

pub const EXT4_EXTENTS_FL: u32 = 0x80000;

pub const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
pub const EXT4_EXTENT_HEADER_SIZE: usize = 12;
pub const EXT4_EXTENT_ENTRY_SIZE: usize = 12;

#[derive(Copy, Clone)]
pub enum BufKind { File, Dir, Gitignore }

#[derive(Copy, Clone)]
pub struct BufFatPtr {
    offset: usize,
    len: u32,
    kind: BufKind
}

pub struct Ext4SuperBlock {
    pub block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub desc_size: u16,
}

impl Display for Ext4SuperBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Block size: {} bytes", self.block_size)?;
        writeln!(f, "Blocks per group: {}", self.blocks_per_group)?;
        writeln!(f, "Inodes per group: {}", self.inodes_per_group)?;
        writeln!(f, "Inode size: {} bytes", self.inode_size)?;
        writeln!(f, "Descriptor size: {} bytes", self.desc_size)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Ext4Inode {
    pub mode: u16,
    pub size: u64,
    pub flags: u32,
    pub blocks: [u32; 15],
}

#[derive(Debug, Clone, Copy)]
pub struct Ext4Extent {
    pub start: u64,
    pub len: u16,
}

pub struct BufferConfig {
    pub output_buf: usize,
    pub dir_buf: usize,
    pub content_buf: usize,
    pub gitignore_buf: usize,
    pub extent_buf: usize,
}

enum WorkItem {
    Directory(DirWork),
    FileBatch(FileBatchWork),
}

struct DirWork {
    inode_num: INodeNum,
    path_bytes: Arc<[u8]>,
    gitignore: Option<Arc<Gitignore>>,
    depth: u16
}

struct FileBatchWork {
    // Instead of storing file inodes, store the directory entries raw
    parent_dir_inode: INodeNum,
    parent_path: Arc<[u8]>,
    gitignore: Option<Arc<Gitignore>>,
    // Raw directory entry data (multiple entries concatenated)
    entries: Box<[u8]>,
}

struct OutputThread {
    rx: Receiver<Vec<u8>>,
    writer: BufWriter<io::Stdout>,
}

impl OutputThread {
    fn run(mut self) {
        let _span = tracy::span!("OutputThread::run");

        while let Ok(buf) = self.rx.recv() {
            _ = self.writer.write_all(&buf);
            // Flush periodically, not every time
            if self.writer.buffer().len() > 32 * 1024 {
                _ = self.writer.flush();
            }
        }
        _ = self.writer.flush();
    }
}

struct WorkerContext<'a> {
    worker_id: usize,

    root_search_directory: &'a str,

    device_mmap: &'a Mmap,
    sb: &'a Ext4SuperBlock,
    cli: &'a Cli,
    matcher: &'a Matcher,
    stats: &'a ParallelStats,
    output_tx: Sender<Vec<u8>>,

    symlink_depth: u8,

    // Thread(Worker)-local buffers
    file_buf: Vec<u8>,
    dir_buf: Vec<u8>,
    gitignore_buf: Vec<u8>,
    extent_buf: Vec<Ext4Extent>,
    path_buf: FixedPathBuf,
    output_buf: Vec<u8>,
}

impl<'a> WorkerContext<'a> {
    fn init(&mut self, cli: &Cli) {
        let config = cli.get_buffer_config();
        self.dir_buf.reserve(config.dir_buf);
        self.file_buf.reserve(config.content_buf);
        self.output_buf.reserve(config.output_buf);
        self.gitignore_buf.reserve(config.gitignore_buf);
        self.extent_buf.reserve(config.extent_buf);
    }

    #[inline(always)]
    fn flush_output(&mut self) {
        if !self.output_buf.is_empty() {
            _ = self.output_tx.send(std::mem::replace(
                &mut self.output_buf,
                //  @Constant
                Vec::with_capacity(64 * 1024)
            ));
        }
    }

    #[inline(always)]
    fn max_file_byte_size(&self) -> usize {
        if self.cli.should_ignore_size_filter() {
            usize::MAX
        } else {
            _MAX_FILE_BYTE_SIZE
        }
    }

    #[inline(always)]
    fn max_dir_byte_size(&self) -> usize {
        if self.cli.should_ignore_size_filter() {
            usize::MAX
        } else {
            _MAX_DIR_BYTE_SIZE
        }
    }

    fn process_symlink_inline(
        &mut self,
        symlink_inode: &Ext4Inode,
        file_name_ptr: BufFatPtr,
        parent_path: &[u8],
        gitignore: Option<&Gitignore>,
        path_display_buf: &mut String,
    ) -> io::Result<()> {
        let target_inode_num = self.resolve_symlink(symlink_inode, parent_path.len());

        let target_inode_num = match target_inode_num {
            Ok(num) => num,
            Err(_) => {
                self.stats.symlinks_broken.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        };

        let Ok(target_inode) = self.parse_inode(target_inode_num) else {
            self.stats.symlinks_broken.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        };

        let target_ft = target_inode.mode & EXT4_S_IFMT;

        match target_ft {
            EXT4_S_IFREG => {
                self.stats.symlinks_followed.fetch_add(1, Ordering::Relaxed);

                // @Speed
                let name_bytes = self.buf_ptr(file_name_ptr);
                let name_bytes = name_bytes.to_vec();

                self.process_file_fast(
                    &target_inode,
                    &name_bytes,
                    parent_path,
                    gitignore,
                    path_display_buf
                )?;
            }
            _ => {
                // TODO: Search directories pointed by symlinks
                // ... skip directory symlinks to avoid potential loops
            }
        }

        Ok(())
    }

    fn resolve_symlink(
        &mut self,
        inode: &Ext4Inode,
        current_path_len: usize,
    ) -> io::Result<INodeNum> {
        let _span = tracy::span!("resolve_symlink");

        const MAX_SYMLINK_DEPTH: u8 = 8;

        if self.symlink_depth >= MAX_SYMLINK_DEPTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Too many symlink levels",
            ));
        }

        self.symlink_depth += 1;
        let result = {
            // Fast symlink (stored in inode)
            if inode.size as usize <= FAST_SYMLINK_SIZE {
                let target = unsafe {
                    std::slice::from_raw_parts(
                        inode.blocks.as_ptr() as *const u8,
                        inode.size as usize,
                    )
                };
                return self.resolve_symlink_path(target, current_path_len);
            }

            // Slow symlink (stored in blocks)
            let size = (inode.size as usize).min(MAX_SYMLINK_TARGET_SIZE);
            self.read_file_into_buf(inode, size, BufKind::Dir, false)?;

            // @StackLarge
            let target: SmallVec<[_; 0x1000]> = copy_data(&self.dir_buf[..size]);
            self.resolve_symlink_path(&target, current_path_len)
        };
        self.symlink_depth -= 1;

        result
    }

    fn resolve_symlink_path(
        &mut self,
        target: &[u8],
        current_path_len: usize,
    ) -> io::Result<INodeNum> {
        // Absolute path
        if target.get(0) == Some(&b'/') {
            return self.resolve_path_from_root(target);
        }

        // Relative path - resolve from current directory
        let mut resolved_path = FixedPathBuf::new();
        resolved_path.extend_from_slice(&self.path_buf.as_bytes()[..current_path_len]);

        for component in target.split(|&b| b == b'/') {
            if component.is_empty() || component == b"." {
                continue;
            }

            if component == b".." {
                // Go up
                if let Some(pos) = resolved_path.as_bytes().iter().rposition(|&b| b == b'/') {
                    resolved_path.truncate(pos);
                }
            } else {
                if !resolved_path.is_empty() && resolved_path.as_bytes().last() != Some(&b'/') {
                    resolved_path.push(b'/');
                }
                resolved_path.extend_from_slice(component);
            }
        }

        self.resolve_path_to_inode(&resolved_path)
    }

    fn resolve_path_from_root(&mut self, path: &[u8]) -> io::Result<INodeNum> {
        let mut resolved_path = FixedPathBuf::new();
        resolved_path.extend_from_slice(path);
        self.resolve_path_to_inode(&resolved_path)
    }

    fn resolve_path_to_inode(&mut self, path: &FixedPathBuf) -> io::Result<INodeNum> {
        let path_str = std::str::from_utf8(path.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))?;

        let mut inode_num = EXT4_ROOT_INODE;

        for component in path_str.split('/').filter(|s| !s.is_empty()) {
            let inode = self.parse_inode(inode_num)?;

            if (inode.mode & EXT4_S_IFMT) != EXT4_S_IFDIR {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Not a directory",
                ));
            }

            let dir_size = (inode.size as usize).min(self.max_dir_byte_size());
            self.read_file_into_buf(&inode, dir_size, BufKind::Dir, false)?;

            let mut found = None;
            let mut offset = 0;

            while offset + 8 <= self.dir_buf.len() {
                let entry_inode = INodeNum::from_le_bytes([
                    self.dir_buf[offset + 0],
                    self.dir_buf[offset + 1],
                    self.dir_buf[offset + 2],
                    self.dir_buf[offset + 3],
                ]);
                let rec_len = u16::from_le_bytes([
                    self.dir_buf[offset + 4],
                    self.dir_buf[offset + 5],
                ]);
                let name_len = self.dir_buf[offset + 6];

                if rec_len == 0 {
                    break;
                }

                if entry_inode != 0 && name_len > 0 {
                    let name_end = offset + 8 + name_len as usize;
                    if name_end <= offset + rec_len as usize && name_end <= self.dir_buf.len() {
                        let name_bytes = &self.dir_buf[offset + 8..name_end];
                        if name_bytes == component.as_bytes() {
                            found = Some(entry_inode);
                            break;
                        }
                    }
                }

                offset += rec_len as usize;
            }

            inode_num = found.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "Path component not found")
            })?;
        }

        Ok(inode_num)
    }
}

/// impl block of misc helper functions
impl WorkerContext<'_> {
    fn read_file_into_buf(
        &mut self,
        inode: &Ext4Inode,
        max_size: usize,
        kind: BufKind,
        check_and_stop_if_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("WorkerContext::read_file_into_buf");

        let buf = self.get_buf_mut(kind);
        buf.clear();

        let size_to_read = (inode.size as usize).min(max_size);
        buf.reserve(size_to_read);

        let file_size = inode.size as usize;

        let is_binary = |this: &mut WorkerContext| -> bool {
            let buf = this.get_buf(kind);
            if buf.len() >= BINARY_PROBE_BYTE_SIZE || buf.len() == file_size {
                if is_binary_chunk(&buf[..file_size.min(BINARY_PROBE_BYTE_SIZE)]) {
                    // It's binary!
                    this.get_buf_mut(kind).clear();
                    return true;
                }
            }

            false
        };

        let copy_block_to_buf = |this: &mut WorkerContext, block_num: u64| {
            let _span = tracy::span!("WorkerContext::read_file_into_buf::copy_block_to_buf");

            let offset = this.get_buf(kind).len();
            let remaining = size_to_read - offset;

            let (src_ptr, to_copy) = {
                let block_data = this.get_block(block_num.into());
                let to_copy = block_data.len().min(remaining);
                (block_data.as_ptr(), to_copy)
            };

            let buf = this.get_buf_mut(kind);
            let old_len = buf.len();
            buf.resize(old_len + to_copy, 0);

            // SAFETY: We obtain the source pointer from `block_data` while it's borrowed,
            // then drop that borrow before getting a mutable borrow to the destination buffer.
            // The source pointer remains valid because `get_block()` returns data from an mmap
            // that won't be invalidated during this operation. We ensure no overlap between
            // source and destination, and both pointers are valid for the copy length.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    src_ptr,
                    buf.as_mut_ptr().add(old_len),
                    to_copy
                );
            }
        };

        if inode.flags & EXT4_EXTENTS_FL != 0 {
            self.parse_extents(inode)?;

            let extent_count = self.extent_buf.len();
            // @StackLarge
            let extents_copy: SmallVec::<[_; MAX_EXTENTS_UNTIL_SPILL]> = copy_data(
                &self.extent_buf[..extent_count]
            );

            // ------- Prefetch the blooooooocks
            {
                let _span = tracy::span!("WorkerContext::read_file_into_buf::prefetch_blocks");

                // @StackLarge
                let mut blocks_to_prefetch = SmallVec::<[_; MAX_EXTENTS_UNTIL_SPILL]>::with_capacity(
                    MAX_EXTENTS_UNTIL_SPILL
                );
                for extent in &extents_copy {
                    for i in 0..extent.len.min((MAX_EXTENTS_UNTIL_SPILL / extents_copy.len().max(1)) as _) {
                        blocks_to_prefetch.push(extent.start + i as u64);
                        if blocks_to_prefetch.len() >= MAX_EXTENTS_UNTIL_SPILL {
                            break;
                        }
                    }
                    if blocks_to_prefetch.len() >= MAX_EXTENTS_UNTIL_SPILL {
                        break;
                    }
                }
                self.prefetch_blocks(&blocks_to_prefetch);
            }

            {
                let _span = tracy::span!("WorkerContext::read_file_into_buf::copy_blocks_to_buf_loop");

                for extent in &extents_copy {
                    if self.get_buf(kind).len() >= size_to_read { break; }

                    for j in 0..extent.len {
                        let len = self.get_buf(kind).len();
                        if len >= size_to_read { break }

                        let phys_block = extent.start + j as u64;
                        copy_block_to_buf(self, phys_block);

                        if check_and_stop_if_binary && is_binary(self) {
                            // It's binary!
                            self.get_buf_mut(kind).clear();
                            return Ok(false);
                        }
                    }
                }
            }
        } else {
            // ------- Prefetch the blooooooocks
            {
                let _span = tracy::span!("WorkerContext::read_file_into_buf::prefetch_blocks");

                let mut blocks_to_prefetch = SmallVec::<[_; EXT4_BLOCK_POINTERS_COUNT]>::with_capacity(
                    EXT4_BLOCK_POINTERS_COUNT
                );
                for &block in inode.blocks.iter().take(EXT4_BLOCK_POINTERS_COUNT) {
                    if block != 0 {
                        blocks_to_prefetch.push(block as _);
                    }
                }
                self.prefetch_blocks(&blocks_to_prefetch);
            }

            {
                let _span = tracy::span!("WorkerContext::read_file_into_buf::copy_blocks_to_buf_loop");
                for &block in inode.blocks.iter().take(EXT4_BLOCK_POINTERS_COUNT) {
                    if block == 0 || self.get_buf(kind).len() >= size_to_read {
                        break;
                    }

                    copy_block_to_buf(self, block.into());

                    if check_and_stop_if_binary && is_binary(self) {
                        // It's binary!
                        self.get_buf_mut(kind).clear();
                        return Ok(false);
                    }
                }
            }
        }

        self.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    /// Called when either checking if a path is gitignored or printing the matches
    #[inline(always)]
    fn display_path_into_buf<'a>(&self, buf: &'a mut String) -> &'a str {
        let _span = tracy::span!("WorkerContext::display_path_into_buf");

        buf.clear();
        buf.push_str(&String::from_utf8_lossy(self.path_buf.as_bytes()));
        buf.as_str()
    }

    #[inline(always)]
    fn buf_ptr(&self, ptr: BufFatPtr) -> &[u8] {
        &self.get_buf(ptr.kind)[ptr.offset..ptr.offset+ptr.len as usize]
    }

    #[inline(always)]
    fn get_buf(&self, kind: BufKind) -> &[u8] {
        match kind {
            BufKind::File      => &self.file_buf,
            BufKind::Dir       => &self.dir_buf,
            BufKind::Gitignore => &self.gitignore_buf,
        }
    }

    #[inline(always)]
    fn get_buf_mut(&mut self, kind: BufKind) -> &mut Vec<u8> {
        match kind {
            BufKind::File      => &mut self.file_buf,
            BufKind::Dir       => &mut self.dir_buf,
            BufKind::Gitignore => &mut self.gitignore_buf,
        }
    }

    // @Hot
    #[inline(always)]
    fn get_block(&self, block_num: u64) -> &[u8] {
        let offset = (block_num as usize).wrapping_mul(self.sb.block_size as usize);
        debug_assert!(
            self.device_mmap
                .get(offset..offset + self.sb.block_size as usize)
                .is_some()
        );
        unsafe {
            let ptr = self.device_mmap.as_ptr().add(offset);
            std::slice::from_raw_parts(ptr, self.sb.block_size as usize)
        }
    }

    #[inline(always)]
    fn prefetch_blocks(&self, blocks: &[u64]) {
        let _span = tracy::span!("WorkerContext::prefetch_blocks");

        if blocks.is_empty() {
            return;
        }

        let mut sorted: SmallVec<[_; 16]> = copy_data(blocks);
        sorted.sort_unstable();
        sorted.dedup();

        let mut range_start = sorted[0];
        let mut range_end = sorted[0];

        for &block in &sorted[1..] {
            if block == range_end + 1 {
                range_end = block;
            } else {
                self.advise_range(range_start, range_end);
                range_start = block;
                range_end = block;
            }
        }
        self.advise_range(range_start, range_end);
    }

    #[inline(always)]
    fn advise_range(&self, start_block: u64, end_block: u64) {
        let offset = start_block as usize * self.sb.block_size as usize;
        let length = (end_block - start_block + 1) as usize * self.sb.block_size as usize;

        if offset + length <= self.device_mmap.len() {
            unsafe {
                libc::madvise(
                    self.device_mmap.as_ptr().add(offset) as *mut _,
                    length,
                    libc::MADV_WILLNEED
                );
            }
        }
    }
}

/// impl block of gitignore helper functions
impl WorkerContext<'_> {
    #[inline]
    fn try_load_gitignore(
        &mut self,
        gi_inode_num: INodeNum,
        path_display_buf: &str
    ) -> Option<Gitignore> {
        let _span = tracy::span!("WorkerContext::try_load_gitignore");

        if let Ok(gi_inode) = self.parse_inode(gi_inode_num) {
            let size = (gi_inode.size as usize).min(self.max_file_byte_size());
            if likely(self.read_file_into_buf(&gi_inode, size, BufKind::Gitignore, true).is_ok()) {
                let matcher = build_gitignore_from_bytes(
                    path_display_buf.as_ref(),
                    &self.gitignore_buf,
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

/// impl block of ext4 parsing
impl WorkerContext<'_> {
    #[inline]
    fn parse_inode(&self, inode_num: INodeNum) -> io::Result<Ext4Inode> {
        let _span = tracy::span!("WorkerContext::parse_inode");

        if unlikely(inode_num == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid inode number 0"
            ));
        }

        let group = (inode_num - 1) / self.sb.inodes_per_group;
        let index = (inode_num - 1) % self.sb.inodes_per_group;

        let bg_desc_offset = if self.sb.block_size == 1024 {
            2048
        } else {
            self.sb.block_size as usize
        } + (group as usize * self.sb.desc_size as usize);

        let bg_desc = &self.device_mmap[
            bg_desc_offset..
            bg_desc_offset + self.sb.desc_size as usize
        ];

        let inode_table_block = u32::from_le_bytes([
            bg_desc[EXT4_INODE_TABLE_OFFSET + 0],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 1],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 2],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 3],
        ]);

        let inode_offset = inode_table_block as usize *
            self.sb.block_size as usize +
            index as usize *
            self.sb.inode_size as usize;

        let inode_bytes = &self.device_mmap[
            inode_offset..
            inode_offset + self.sb.inode_size as usize
        ];

        let mode = u16::from_le_bytes([
            inode_bytes[EXT4_INODE_MODE_OFFSET + 0],
            inode_bytes[EXT4_INODE_MODE_OFFSET + 1],
        ]);

        let size_low = u32::from_le_bytes([
            inode_bytes[EXT4_INODE_SIZE_OFFSET_LOW + 0],
            inode_bytes[EXT4_INODE_SIZE_OFFSET_LOW + 1],
            inode_bytes[EXT4_INODE_SIZE_OFFSET_LOW + 2],
            inode_bytes[EXT4_INODE_SIZE_OFFSET_LOW + 3],
        ]);

        let size_high = if self.sb.inode_size > 128
            && inode_bytes.len() > EXT4_INODE_SIZE_OFFSET_HIGH + 4
        {
            u32::from_le_bytes([
                inode_bytes[EXT4_INODE_SIZE_OFFSET_HIGH + 0],
                inode_bytes[EXT4_INODE_SIZE_OFFSET_HIGH + 1],
                inode_bytes[EXT4_INODE_SIZE_OFFSET_HIGH + 2],
                inode_bytes[EXT4_INODE_SIZE_OFFSET_HIGH + 3],
            ])
        } else {
            0
        };

        let size = ((size_high as u64) << 32) | (size_low as u64);

        let flags = u32::from_le_bytes([
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 0],
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 1],
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 2],
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 3],
        ]);

        let mut blocks = [0; 15];
        for (i, block) in blocks.iter_mut().enumerate() {
            let offset = EXT4_INODE_BLOCK_OFFSET + i * 4;
            *block = u32::from_le_bytes([
                inode_bytes[offset + 0],
                inode_bytes[offset + 1],
                inode_bytes[offset + 2],
                inode_bytes[offset + 3],
            ]);
        }

        Ok(Ext4Inode { mode, size, flags, blocks })
    }

    #[inline]
    fn parse_extents(&mut self, inode: &Ext4Inode) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::parse_extents");

        self.extent_buf.clear();

        let mut block_bytes: SmallVec<[_; 64]> = smallvec![0; 64];
        for (i, bytes) in inode.blocks.into_iter().map(u32::to_le_bytes).enumerate() {
            block_bytes[i * 4 + 0] = bytes[0];
            block_bytes[i * 4 + 1] = bytes[1];
            block_bytes[i * 4 + 2] = bytes[2];
            block_bytes[i * 4 + 3] = bytes[3];
        }

        self.parse_extent_node(&block_bytes, 0)?;
        Ok(())
    }

    fn parse_extent_node(&mut self, data: &[u8], level: usize) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::parse_extent_node");

        if data.len() < EXT4_EXTENT_HEADER_SIZE {
            return Ok(());
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != EXT4_EXTENT_MAGIC {
            return Ok(());
        }

        let entries = u16::from_le_bytes([data[2], data[3]]);
        let depth = u16::from_le_bytes([data[6], data[7]]);

        if depth == 0 {
            // -------- Leaf node
            for i in 0..entries {
                let base = EXT4_EXTENT_ENTRY_SIZE + (i as usize * EXT4_EXTENT_ENTRY_SIZE);
                if base + EXT4_EXTENT_ENTRY_SIZE > data.len() {
                    break;
                }

                let ee_len = u16::from_le_bytes([data[base + 4], data[base + 5]]);
                let ee_start_hi = u16::from_le_bytes([data[base + 6], data[base + 7]]);
                let ee_start_lo = u32::from_le_bytes([
                    data[base +  8],
                    data[base +  9],
                    data[base + 10],
                    data[base + 11]
                ]);

                let start_block = ((ee_start_hi as u64) << 32) | (ee_start_lo as u64);

                if ee_len > 0 && ee_len <= 32768 {
                    self.extent_buf.push(Ext4Extent {
                        start: start_block,
                        len: ee_len,
                    });
                }
            }
        } else {
            // -------- Internal node - collect block numbers first
            let mut child_blocks = SmallVec::<[_; 16]>::new();
            for i in 0..entries {
                let base = 12 + (i as usize * 12);
                if base + 12 > data.len() {
                    break;
                }

                let ei_leaf_lo = u32::from_le_bytes([
                    data[base + 4],
                    data[base + 5],
                    data[base + 6],
                    data[base + 7]
                ]);
                let ei_leaf_hi = u16::from_le_bytes([data[base + 8], data[base + 9]]);

                let leaf_block = ((ei_leaf_hi as u64) << 32) | (ei_leaf_lo as u64);
                child_blocks.push(leaf_block);
            }

            self.prefetch_blocks(&child_blocks);

            for child_block in child_blocks {
                // SAFETY:
                //
                // 1. `self.device_mmap` points to read-only memory and is never mutated for the entire
                //    lifetime of `WorkerContext`. No writes, no remapping, no replacement.
                // 2. `get_block()` returns slices that reference only this immutable mmap region.
                //    They must not alias any data that could be mutated through `&mut self`.
                // 3. `parse_extent_node()` must not cause `device_mmap` to change or become invalid.
                //    Fields like `extent_buf`, `content_buf`, etc may be modified, but `device_mmap`
                //    must remain stable and untouched.
                // 4. The returned `&[u8]` slices are used only within the duration of this call and are
                //    never stored, returned, or kept past recursion boundaries.
                // 5. No other code is allowed to obtain a mutable reference to the mmap contents.
                let block_data = unsafe {
                    let zelf: *const Self = self;
                    (&*zelf).get_block(child_block.into())
                };
                self.parse_extent_node(block_data, level + 1)?;
            }
        }

        Ok(())
    }
}

impl WorkerContext<'_> {
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
                crossbeam_deque::Steal::Success(work) => {
                    *consecutive_steals = 0;
                    return Some(work);
                }
                crossbeam_deque::Steal::Empty => break,
                crossbeam_deque::Steal::Retry => continue,
            }
        }

        // Steal from others
        let start = if *consecutive_steals < 3 {
            (self.worker_id + 1) % stealers.len()
        } else {
            fastrand::usize(..stealers.len())
        };

        for i in 0..stealers.len() {
            let victim_id = (start + i) % stealers.len();
            if victim_id == self.worker_id {
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

    fn process_directory_with_stealing(
        &mut self,
        work: DirWork,
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
        path_display_buf: &mut String
    ) -> io::Result<()> {
        let _span = tracy::span!("process_directory_with_stealing");

        self.path_buf.clear();
        self.path_buf.extend_from_slice(&work.path_bytes);

        let Ok(inode) = self.parse_inode(work.inode_num) else {
            return Ok(());
        };

        if unlikely((inode.mode & EXT4_S_IFMT) != EXT4_S_IFDIR) {
            return Ok(());
        }

        if !work.path_bytes.is_empty() {
            let last_segment = work.path_bytes
                .iter()
                .rposition(|&b| b == b'/')
                .map(|pos| &work.path_bytes[pos + 1..])
                .unwrap_or(&work.path_bytes);

            if is_common_skip_dir(last_segment) {
                self.stats.dirs_skipped_common.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        }

        let dir_size = (inode.size as usize).min(self.max_dir_byte_size());
        self.read_file_into_buf(&inode, dir_size, BufKind::Dir, false)?;
        self.stats.dirs_encountered.fetch_add(1, Ordering::Relaxed);

        let current_gi = if !self.cli.should_ignore_gitignore() {
            if let Some(gi_inode) = self.find_gitignore_inode_in_buf(BufKind::Dir) {
                self.display_path_into_buf(path_display_buf);
                self.try_load_gitignore(gi_inode, path_display_buf)
                    .map(Arc::new)
                    .or_else(|| work.gitignore.clone())
            } else {
                work.gitignore.clone()
            }
        } else {
            work.gitignore.clone()
        };

        let (file_count, _) = self.count_directory_entries();

        // If many files, split into batches
        if file_count > LARGE_DIR_THRESHOLD {
            self.process_large_directory(
                work,
                current_gi,
                local,
                injector,
                path_display_buf
            )?;
        } else {
            self.process_normal_directory(
                work,
                current_gi,
                local,
                injector,
                path_display_buf
            )?;
        }

        Ok(())
    }

    fn count_directory_entries(&self) -> (usize, usize) {
        let mut file_count = 0;
        let mut dir_count = 0;
        let mut offset = 0;

        while offset + 8 <= self.dir_buf.len() {
            let entry_inode = INodeNum::from_le_bytes([
                self.dir_buf[offset + 0],
                self.dir_buf[offset + 1],
                self.dir_buf[offset + 2],
                self.dir_buf[offset + 3],
            ]);
            let rec_len = u16::from_le_bytes([
                self.dir_buf[offset + 4],
                self.dir_buf[offset + 5],
            ]);
            let name_len = self.dir_buf[offset + 6];
            let file_type = self.dir_buf[offset + 7];

            if rec_len == 0 {
                break;
            }

            if entry_inode != 0 && name_len > 0 {
                let name_end = offset + 8 + name_len as usize;
                if name_end <= offset + rec_len as usize && name_end <= self.dir_buf.len() {
                    let name_bytes = &self.dir_buf[offset + 8..name_end];

                    if !is_dot_entry(name_bytes) {
                        // Use file_type hint from dir entry
                        match file_type {
                            // @Constant
                            2 => dir_count += 1,      // DT_DIR
                            1 | 8 => file_count += 1, // DT_REG or DT_REG
                            _ => {
                                // Fallback: parse inode (slower)
                                if let Ok(child_inode) = self.parse_inode(entry_inode) {
                                    match child_inode.mode & EXT4_S_IFMT {
                                        EXT4_S_IFDIR => dir_count += 1,
                                        EXT4_S_IFREG => file_count += 1,
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }

            offset += rec_len as usize;
        }

        (file_count, dir_count)
    }

    fn process_large_directory(
        &mut self,
        work: DirWork,
        current_gi: Option<Arc<Gitignore>>,
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
        path_display_buf: &mut String
    ) -> io::Result<()> {
        let _span = tracy::span!("WorkerContext::process_large_directory");

        let mut subdirs = SmallVec::<[_; 16]>::new();

        // Split files into batches
        // @StackLarge
        let mut current_batch = SmallVec::<[_; 0x1000]>::new();
        let mut files_in_batch = 0;

        let mut offset = 0;

        while offset + 8 <= self.dir_buf.len() {
            let entry_inode = INodeNum::from_le_bytes([
                self.dir_buf[offset + 0],
                self.dir_buf[offset + 1],
                self.dir_buf[offset + 2],
                self.dir_buf[offset + 3],
            ]);
            let rec_len = u16::from_le_bytes([
                self.dir_buf[offset + 4],
                self.dir_buf[offset + 5],
            ]);
            let name_len = self.dir_buf[offset + 6];

            if rec_len == 0 {
                break;
            }

            let rec_len_usize = rec_len as usize;

            if entry_inode != 0 && name_len > 0 {
                let name_end = offset + 8 + name_len as usize;
                if name_end <= offset + rec_len_usize && name_end <= self.dir_buf.len() {
                    let name_bytes = &self.dir_buf[offset + 8..name_end];

                    if !is_dot_entry(name_bytes) {
                        let Ok(child_inode) = self.parse_inode(entry_inode) else {
                            offset += rec_len_usize;
                            continue;
                        };

                        let ft = child_inode.mode & EXT4_S_IFMT;

                        match ft {
                            EXT4_S_IFDIR => {
                                if !is_common_skip_dir(name_bytes) {
                                    let mut child_path: SmallVec<[u8; 512]> = SmallVec::new();
                                    child_path.extend_from_slice(&work.path_bytes);
                                    if !child_path.is_empty() {
                                        child_path.push(b'/');
                                    }
                                    child_path.extend_from_slice(name_bytes);

                                    subdirs.push(DirWork {
                                        inode_num: entry_inode,
                                        path_bytes: crate::util::smallvec_into_arc_slice_noshrink(
                                            child_path
                                        ),
                                        gitignore: current_gi.clone(),
                                        depth: work.depth + 1,
                                    });
                                }
                            }
                            EXT4_S_IFREG => {
                                // Store the raw directory entry for batch processing
                                // Format: [inode(4), name_len(1), name(name_len)]
                                current_batch.extend_from_slice(&entry_inode.to_le_bytes());
                                current_batch.push(name_len);
                                current_batch.extend_from_slice(name_bytes);

                                files_in_batch += 1;

                                if files_in_batch >= FILE_BATCH_SIZE {
                                    local.push(WorkItem::FileBatch(FileBatchWork {
                                        parent_dir_inode: work.inode_num,
                                        parent_path: Arc::clone(&work.path_bytes),
                                        gitignore: current_gi.as_ref().map(Arc::clone),
                                        entries: crate::util::smallvec_into_boxed_slice_noshrink(
                                            core::mem::take(&mut current_batch)
                                        )
                                    }));
                                    files_in_batch = 0;
                                }
                            }
                            EXT4_S_IFLNK => {
                                self.process_symlink_inline(
                                    &child_inode,
                                    BufFatPtr {
                                        kind: BufKind::Dir,
                                        offset: offset + 8,
                                        len: name_len as _
                                    },
                                    &work.path_bytes,
                                    current_gi.as_deref(),
                                    path_display_buf,
                                )?;
                            }
                            _ => {}
                        }
                    }
                }
            }

            offset += rec_len_usize;
        }

        if files_in_batch > 0 {
            local.push(WorkItem::FileBatch(FileBatchWork {
                parent_dir_inode: work.inode_num,
                parent_path: work.path_bytes.clone(),
                gitignore: current_gi.clone(),
                entries: crate::util::smallvec_into_boxed_slice_noshrink(
                    current_batch
                ),
            }));
        }

        // Push subdirectories
        let keep_local = subdirs.len().min(2);
        for subdir in subdirs.drain(keep_local..).rev() {
            local.push(WorkItem::Directory(subdir));
        }

        for subdir in subdirs {
            self.process_directory_with_stealing(subdir, local, injector, path_display_buf)?;
        }

        Ok(())
    }

    fn process_file_batch(
        &mut self,
        batch: FileBatchWork,
        path_display_buf: &mut String
    ) -> io::Result<()> {
        let _span = tracy::span!("process_file_batch");

        let parent_path_len = batch.parent_path.len();
        let mut offset = 0;

        while offset < batch.entries.len() {
            // Parse entry: [inode(4), name_len(1), name(name_len)]
            if offset + 5 > batch.entries.len() {
                break;
            }

            let entry_inode = INodeNum::from_le_bytes([
                batch.entries[offset],
                batch.entries[offset + 1],
                batch.entries[offset + 2],
                batch.entries[offset + 3],
            ]);
            let name_len = batch.entries[offset + 4] as usize;
            offset += 5;

            if offset + name_len > batch.entries.len() {
                break;
            }

            let name_bytes = &batch.entries[offset..offset + name_len];
            offset += name_len;

            // Build full path
            {
                self.path_buf.clear();
                self.path_buf.extend_from_slice(&batch.parent_path);
                if parent_path_len > 0 && self.path_buf.as_bytes()[parent_path_len - 1] != b'/' {
                    self.path_buf.push(b'/');
                }
                self.path_buf.extend_from_slice(name_bytes);
            }

            let Ok(inode) = self.parse_inode(entry_inode) else {
                continue;
            };

            self.process_file_fast(
                &inode,
                name_bytes,
                &batch.parent_path,
                batch.gitignore.as_deref(),
                path_display_buf
            )?;

            // @Constant
            if self.output_buf.len() > 16 * 1024 {
                self.flush_output();
            }
        }

        Ok(())
    }

    fn process_normal_directory(
        &mut self,
        work: DirWork,
        current_gi: Option<Arc<Gitignore>>,
        local: &DequeWorker<WorkItem>,
        injector: &Injector<WorkItem>,
        path_display_buf: &mut String
    ) -> io::Result<()> {
        let _span = tracy::span!("WorkerContext::process_large_directory");

        let mut subdirs = SmallVec::<[DirWork; 16]>::new();
        let mut offset = 0;

        while offset + 8 <= self.dir_buf.len() {
            let entry_inode = INodeNum::from_le_bytes([
                self.dir_buf[offset + 0],
                self.dir_buf[offset + 1],
                self.dir_buf[offset + 2],
                self.dir_buf[offset + 3],
            ]);
            let rec_len = u16::from_le_bytes([
                self.dir_buf[offset + 4],
                self.dir_buf[offset + 5],
            ]);
            let name_len = self.dir_buf[offset + 6];

            if rec_len == 0 {
                break;
            }

            let rec_len_usize = rec_len as usize;

            if entry_inode != 0 && name_len > 0 {
                let name_end = offset + 8 + name_len as usize;
                if name_end <= offset + rec_len_usize && name_end <= self.dir_buf.len() {
                    let name_bytes = &self.dir_buf[offset + 8..name_end];

                    if !is_dot_entry(name_bytes) {
                        let Ok(child_inode) = self.parse_inode(entry_inode) else {
                            offset += rec_len_usize;
                            continue;
                        };

                        let ft = child_inode.mode & EXT4_S_IFMT;

                        match ft {
                            EXT4_S_IFDIR => {
                                if !is_common_skip_dir(name_bytes) {
                                    let mut child_path: SmallVec<[u8; 512]> = SmallVec::new();
                                    child_path.extend_from_slice(&work.path_bytes);
                                    if !child_path.is_empty() {
                                        child_path.push(b'/');
                                    }
                                    child_path.extend_from_slice(name_bytes);

                                    subdirs.push(DirWork {
                                        inode_num: entry_inode,
                                        path_bytes: crate::util::smallvec_into_arc_slice_noshrink(
                                            child_path
                                        ),
                                        gitignore: current_gi.clone(),
                                        depth: work.depth + 1,
                                    });
                                }
                            }
                            EXT4_S_IFREG => {
                                // @Speed
                                let name_bytes = name_bytes.to_vec();
                                self.process_file_fast(
                                    &child_inode,
                                    &name_bytes,
                                    &work.path_bytes,
                                    current_gi.as_deref(),
                                    path_display_buf
                                )?;

                                if self.output_buf.len() > 16 * 1024 {
                                    self.flush_output();
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            offset += rec_len_usize;
        }

        let keep_local = subdirs.len().min(2);
        for subdir in subdirs.drain(keep_local..).rev() {
            local.push(WorkItem::Directory(subdir));
        }

        for subdir in subdirs {
            self.process_directory_with_stealing(subdir, local, injector, path_display_buf)?;
        }

        Ok(())
    }

    #[inline]
    fn process_file_fast(
        &mut self,
        inode: &Ext4Inode,
        file_name: &[u8],
        parent_path: &[u8],
        gitignore: Option<&Gitignore>,
        path_display_buf: &mut String
    ) -> io::Result<()> {
        self.stats.files_encountered.fetch_add(1, Ordering::Relaxed);

        if !self.cli.should_ignore_all_filters() && inode.size > self.max_file_byte_size() as u64 {
            self.stats.files_skipped_large.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        if !self.cli.should_search_binary() && is_binary_ext(file_name) {
            self.stats.files_skipped_as_binary_due_to_ext.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        if !self.cli.should_ignore_gitignore() {
            if let Some(gi) = gitignore {
                self.display_path_into_buf(path_display_buf);
                if is_gitignored(gi, path_display_buf.as_ref(), false) {
                    self.stats.files_skipped_gitignore.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
            }
        }

        // Build full path
        {
            self.path_buf.clear();
            self.path_buf.extend_from_slice(parent_path);
            if !parent_path.is_empty() {
                self.path_buf.push(b'/');
            }
            self.path_buf.extend_from_slice(file_name);
            self.display_path_into_buf(path_display_buf);
        }

        let size = (inode.size as usize).min(self.max_file_byte_size());

        match self.read_file_into_buf(inode, size, BufKind::File, !self.cli.should_search_binary())? {
            true => {
                self.stats.files_searched.fetch_add(1, Ordering::Relaxed);
                self.stats.bytes_searched.fetch_add(self.file_buf.len() as u64, Ordering::Relaxed);

                // Only build display path if we have matches
                if self.matcher.is_match(&self.file_buf) {
                    self.display_path_into_buf(path_display_buf);
                    self.find_and_print_matches_fast(path_display_buf)?;
                }
            }
            false => {
                self.stats.files_skipped_as_binary_due_to_probe.fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(())
    }

    #[inline]
    fn find_and_print_matches_fast(
        &mut self,
        path_display_buf: &mut String
    ) -> io::Result<()> {
        let mut found_any = false;
        let buf = &self.file_buf;
        let buf_len = buf.len();

        // @Constant
        let needed = 4096 + buf_len.min(32 * 1024);
        if self.output_buf.capacity() - self.output_buf.len() < needed {
            self.output_buf.reserve(needed);
        }

        let mut line_num: u32 = 1;
        let mut line_start = 0;

        while line_start < buf_len {
            let line_end = memchr::memchr(b'\n', &buf[line_start..])
                .map(|p| line_start + p)
                .unwrap_or(buf_len);

            let line = &buf[line_start..line_end];

            if self.matcher.is_match(line) {
                if !found_any {
                    //
                    // `path_display_buf` contains the `child path`,
                    //  e.g. the path to the file without the root search directory.
                    //

                    let root = self.root_search_directory.as_bytes();
                    let root_len = root.len();
                    let ends_with_slash = root.last() == Some(&b'/');

                    let add = root_len + (!ends_with_slash as usize); // total bytes to insert
                    let old_len = path_display_buf.len();

                    path_display_buf.reserve(add);

                    unsafe {
                        let ptr = path_display_buf.as_mut_ptr();

                        // move tail bytes forward must copy backwards to avoid overlap corruption
                        core::ptr::copy(ptr, ptr.add(add), old_len);

                        core::ptr::copy_nonoverlapping(root.as_ptr(), ptr, root_len);

                        if !ends_with_slash {
                            *ptr.add(root_len) = b'/';
                        }

                        path_display_buf.as_mut_vec().set_len(old_len + add);
                    }

                    self.output_buf.extend_from_slice(COLOR_GREEN.as_bytes());
                    self.output_buf.extend_from_slice(path_display_buf.as_bytes());
                    self.output_buf.extend_from_slice(COLOR_RESET.as_bytes());
                    self.output_buf.extend_from_slice(b":\n");
                    found_any = true;
                }

                self.output_buf.extend_from_slice(COLOR_CYAN.as_bytes());
                let mut line_num_buf = itoa::Buffer::new();
                let line_num = line_num_buf.format(line_num);
                self.output_buf.extend_from_slice(line_num.as_bytes());
                self.output_buf.extend_from_slice(COLOR_RESET.as_bytes());
                self.output_buf.extend_from_slice(b": ");

                let display = truncate_utf8(line, 500);
                let mut last = 0;

                for (s, e) in self.matcher.find_matches(line) {
                    if s >= display.len() {
                        break;
                    }
                    let e = e.min(display.len());

                    self.output_buf.extend_from_slice(&display[last..s]);
                    self.output_buf.extend_from_slice(COLOR_RED.as_bytes());
                    self.output_buf.extend_from_slice(&display[s..e]);
                    self.output_buf.extend_from_slice(COLOR_RESET.as_bytes());
                    last = e;
                }

                self.output_buf.extend_from_slice(&display[last..]);
                self.output_buf.push(b'\n');
            }

            line_start = if line_end < buf_len { line_end + 1 } else { buf_len };
            line_num += 1;
        }

        if found_any {
            self.stats.files_contained_matches.fetch_add(1, Ordering::Relaxed);
        }

        Ok(())
    }
}

pub struct RawGrepper {
    device_mmap: Mmap,
    sb: Ext4SuperBlock,

    pub cli: Cli,

    matcher: Matcher,

    // ------------- reused buffers
    //    --- 3 main buffers
      content_buf: Vec<u8>, // `DirKind::File`
          dir_buf: Vec<u8>, // `DirKind::Dir`
    gitignore_buf: Vec<u8>, // `DirKind::Gitignore`
       extent_buf: Vec<Ext4Extent>,
}

pub struct ParallelStats {
    pub files_encountered: AtomicU64,
    pub files_searched: AtomicU64,
    pub files_contained_matches: AtomicU64,
    pub bytes_searched: AtomicU64,
    pub dirs_encountered: AtomicU64,
    pub dirs_skipped_common: AtomicU64,
    pub dirs_skipped_gitignore: AtomicU64,
    pub files_skipped_large: AtomicU64,
    pub files_skipped_as_binary_due_to_ext: AtomicU64,
    pub files_skipped_as_binary_due_to_probe: AtomicU64,
    pub files_skipped_gitignore: AtomicU64,
    pub symlinks_followed: AtomicU64,
    pub symlinks_broken: AtomicU64,
}

impl ParallelStats {
    fn new() -> Self {
        Self {
            files_encountered: AtomicU64::new(0),
            files_searched: AtomicU64::new(0),
            files_contained_matches: AtomicU64::new(0),
            bytes_searched: AtomicU64::new(0),
            dirs_encountered: AtomicU64::new(0),
            dirs_skipped_common: AtomicU64::new(0),
            dirs_skipped_gitignore: AtomicU64::new(0),
            files_skipped_large: AtomicU64::new(0),
            files_skipped_as_binary_due_to_ext: AtomicU64::new(0),
            files_skipped_as_binary_due_to_probe: AtomicU64::new(0),
            files_skipped_gitignore: AtomicU64::new(0),
            symlinks_followed: AtomicU64::new(0),
            symlinks_broken: AtomicU64::new(0),
        }
    }

    fn to_stats(&self) -> Stats {
        Stats {
            files_skipped_unreadable: 0,
            files_encountered: self.files_encountered.load(Ordering::Relaxed) as _,
            files_searched: self.files_searched.load(Ordering::Relaxed) as _,
            files_contained_matches: self.files_contained_matches.load(Ordering::Relaxed) as _,
            bytes_searched: self.bytes_searched.load(Ordering::Relaxed) as _,
            dirs_encountered: self.dirs_encountered.load(Ordering::Relaxed) as _,
            dirs_skipped_common: self.dirs_skipped_common.load(Ordering::Relaxed) as _,
            dirs_skipped_gitignore: self.dirs_skipped_gitignore.load(Ordering::Relaxed) as _,
            files_skipped_large: self.files_skipped_large.load(Ordering::Relaxed) as _,
            files_skipped_as_binary_due_to_ext: self.files_skipped_as_binary_due_to_ext.load(Ordering::Relaxed) as _,
            files_skipped_as_binary_due_to_probe: self.files_skipped_as_binary_due_to_probe.load(Ordering::Relaxed) as _,
            files_skipped_gitignore: self.files_skipped_gitignore.load(Ordering::Relaxed) as _,
            symlinks_followed: self.symlinks_followed.load(Ordering::Relaxed) as _,
            symlinks_broken: self.symlinks_broken.load(Ordering::Relaxed) as _,
        }
    }
}

/// impl block of public API
impl RawGrepper {
    pub fn new(device_path: &str, cli: Cli) -> io::Result<Self> {
        #[inline]
        fn device_size(fd: &File) -> io::Result<u64> {
            let mut size = 0u64;
            let res = unsafe {
                libc::ioctl(fd.as_raw_fd(), BLKGETSIZE64, &mut size)
            };

            if res < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(size)
        }

        let matcher = match Matcher::new(&cli.pattern) {
            Ok(m) => m,
            Err(e) => {
                eprint!("{COLOR_RED}");
                match e.kind() {
                    io::ErrorKind::InvalidInput => {
                        eprintln!("error: invalid pattern '{pattern}'", pattern = cli.pattern);
                        eprintln!("help: patterns must be valid regex or a literal/alternation extractable form");
                        eprintln!("tip: test your regex with `grep -E` or a regex tester before running");
                    }
                    io::ErrorKind::NotFound => {
                        // unlikely for this constructor, but here for completeness
                        eprintln!("error: referenced something that wasn't found: {e}");
                    }
                    _ => {
                        eprintln!("error: failed to build matcher: {e}");
                    }
                }
                eprint!("{COLOR_RESET}");

                std::process::exit(1);
            }
        };

        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(device_path)?;

        let size = device_size(&file)?;
        let device_mmap = unsafe {
            MmapOptions::new()
                .offset(0)
                .len(size as _)
                .map(&file)?
        };

        let sb_bytes = &device_mmap[
            EXT4_SUPERBLOCK_OFFSET as usize..
            EXT4_SUPERBLOCK_OFFSET as usize + EXT4_SUPERBLOCK_SIZE
        ];

        let magic = u16::from_le_bytes([
            sb_bytes[EXT4_MAGIC_OFFSET + 0],
            sb_bytes[EXT4_MAGIC_OFFSET + 1],
        ]);

        if magic != EXT4_SUPER_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Not an ext4 filesystem".to_owned()
            ));
        }

        let sb = Self::parse_superblock(sb_bytes)?;

        Ok(RawGrepper {
            device_mmap: device_mmap.into(),
            sb: sb.into(),
            cli: cli.into(),
            matcher: matcher.into(),
            dir_buf: Vec::default(),
            content_buf: Vec::default(),
            gitignore_buf: Vec::default(),
            extent_buf: Vec::default(),
        })
    }

    pub fn search_parallel(
        self,
        root_inode: INodeNum,
        root_search_directory: &str,
        running: &AtomicBool,
        root_gitignore: Option<Gitignore>,
        num_threads: usize,
    ) -> io::Result<(Cli, Stats)> {
        let threads = if num_threads == 0 {
            std::thread::available_parallelism()
                .map_or(1, |n| n.get())
                .min(12)
        } else {
            num_threads
        };

        let device_mmap = &self.device_mmap;
        let matcher = &self.matcher;
        let stats = &ParallelStats::new();

        let root_gi = root_gitignore.map(Arc::new);

        let active_workers = &AtomicUsize::new(0);
        let quit_now = &AtomicBool::new(false);

        let (output_tx, output_rx) = unbounded::<Vec<u8>>();

        let injector = Arc::new(Injector::<_>::new());
        injector.push(WorkItem::Directory(DirWork {
            inode_num: root_inode,
            path_bytes: Arc::default(),
            gitignore: root_gi,
            depth: 0,
        }));

        let workers = (0..threads)
            .map(|_| DequeWorker::new_lifo())
            .collect::<Vec<_>>();

        let stealers: Vec<Stealer<_>> = workers
            .iter()
            .map(|w| w.stealer())
            .collect();

        self.warmup_filesystem();

        std::thread::scope(|s| {
            let output_handle = s.spawn(|| {
                OutputThread {
                    rx: output_rx,
                    writer: BufWriter::with_capacity(128 * 1024, io::stdout()),
                }.run();
            });

            let handles: Vec<_> = workers
                .into_iter()
                .enumerate()
                .map(|(worker_id, local_worker)|
            {
                let injector = injector.clone();
                let stealers = stealers.clone();
                let output_tx = output_tx.clone();
                let sb = &self.sb;
                let cli = &self.cli;

                s.spawn(move || {
                    let mut worker = WorkerContext {
                        worker_id,

                        symlink_depth: 0,

                        root_search_directory,
                        device_mmap: &device_mmap,
                        sb: &sb,
                        cli: &cli,
                        matcher: &matcher,
                        stats: &stats,
                        output_tx,

                        file_buf: Vec::new(),
                        dir_buf: Vec::new(),
                        gitignore_buf: Vec::new(),
                        extent_buf: Vec::new(),
                        path_buf: FixedPathBuf::new(),
                        output_buf: Vec::with_capacity(64 * 1024)
                    };

                    worker.init(&cli);

                    let mut consecutive_steals = 0;
                    let mut idle_iterations = 0;

                    let mut path_display_buf = String::with_capacity(0x1000);

                    loop {
                        if quit_now.load(Ordering::Relaxed) || !running.load(Ordering::Relaxed) {
                            break;
                        }

                        let work = worker.find_work(
                            &local_worker,
                            &injector,
                            &stealers,
                            &mut consecutive_steals,
                        );

                        match work {
                            Some(work_item) => {
                                idle_iterations = 0;
                                active_workers.fetch_add(1, Ordering::Release);

                                match work_item {
                                    WorkItem::Directory(dir_work) => {
                                        _ = worker.process_directory_with_stealing(
                                            dir_work,
                                            &local_worker,
                                            &injector,
                                            &mut path_display_buf
                                        );
                                    }
                                    WorkItem::FileBatch(batch_work) => {
                                        _ = worker.process_file_batch(batch_work, &mut path_display_buf);
                                    }
                                }

                                active_workers.fetch_sub(1, Ordering::Release);
                            }
                            None => {
                                idle_iterations += 1;

                                worker.flush_output();

                                if active_workers.load(Ordering::Acquire) == 0 {
                                    // Double-check
                                    if injector.is_empty() && local_worker.is_empty() {
                                        quit_now.store(true, Ordering::Release);
                                        break;
                                    }
                                }

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

                    worker.flush_output();
                })
            }).collect::<Vec<_>>();

            for handle in handles {
                _ = handle.join();
            }

            drop(output_tx);
            _ = output_handle.join();
        });

        Ok((self.cli, stats.to_stats()))
    }

    /// Resolve a path like "/usr/bin" or "etc" into an inode number.
    /// @Note: Clobbers into `dir_buf`
    pub fn try_resolve_path_to_inode(&mut self, path: &str) -> io::Result<INodeNum> {
        let _span = tracy::span!("RawGrepper::try_resolve_path_to_inode");

        let mut inode_num = EXT4_ROOT_INODE;
        if path == "/" || path.is_empty() {
            // @CornerCase
            return Ok(inode_num);
        }

        for part in path.split('/').filter(|p| !p.is_empty()) {
            let inode = self.parse_inode(inode_num)?;
            if inode.mode & EXT4_S_IFMT != EXT4_S_IFDIR {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{path} is not a directory"),
                ));
            }

            let dir_size = (inode.size as usize).min(self.max_dir_byte_size());
            self.read_file_into_buf(&inode, dir_size, BufKind::Dir, false)?;

            // ---------- Scan for matching entry
            let mut found = None;
            let mut offset = 0;
            let part_bytes = part.as_bytes();
            while offset + 8 <= self.dir_buf.len() {
                let entry_inode = INodeNum::from_le_bytes([
                    self.dir_buf[offset + 0],
                    self.dir_buf[offset + 1],
                    self.dir_buf[offset + 2],
                    self.dir_buf[offset + 3],
                ]);
                let rec_len = u16::from_le_bytes([
                    self.dir_buf[offset + 4],
                    self.dir_buf[offset + 5],
                ]);
                let name_len = self.dir_buf[offset + 6];

                if rec_len == 0 {
                    break;
                }

                if entry_inode != 0 && name_len > 0 {
                    let name_end = offset + 8 + name_len as usize;
                    if name_end <= offset + rec_len as usize && name_end <= self.dir_buf.len() {
                        let name_bytes = &self.dir_buf[offset + 8..name_end];
                        if name_bytes == part_bytes {
                            found = Some(entry_inode);
                            break;
                        }
                    }
                }

                offset += rec_len as usize;
            }

            inode_num = found.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Component '{part}' not found"),
                )
            })?;
        }

        Ok(inode_num)
    }

    fn warmup_filesystem(&self) {
        let _span = tracy::span!("RawGrepper::warmup_filesystem");

        unsafe {
            libc::madvise(
                self.device_mmap.as_ptr() as *mut _,
                self.device_mmap.len(),
                libc::MADV_WILLNEED | libc::MADV_SEQUENTIAL,
            );
        }

        let block_size = self.sb.block_size as u64;
        let blocks_per_group = self.sb.blocks_per_group as u64;
        let inodes_per_group = self.sb.inodes_per_group as u64;
        let inode_size = self.sb.inode_size as u64;
        let desc_size = self.sb.desc_size as u64;

        // Estimate number of block groups from mmap size
        let total_size = self.device_mmap.len() as u64;
        let bytes_per_group = blocks_per_group * block_size;
        let num_groups = ((total_size + bytes_per_group - 1) / bytes_per_group) as usize;

        // Prefetch group descriptor table (starts after superblock)
        let gdt_offset = if block_size == 1024 { 2048 } else { block_size };
        // @Constant
        let gdt_size = (num_groups as u64 * desc_size).min(1024 * 1024); // Cap at 1MB

        // Touch group descriptor table pages
        for i in (0..gdt_size).step_by(4096) {
            let offset = gdt_offset + i;
            if offset < total_size {
                _ = unsafe {
                    std::ptr::read_volatile(
                        self.device_mmap.as_ptr().add(offset as usize)
                    )
                };
            }
        }

        // Prefetch first few inode tables (where most commonly accessed files are)
        for group in 0..num_groups.min(64) {
            let gd_offset = gdt_offset + (group as u64 * desc_size);
            if gd_offset + 8 > total_size {
                break;
            }

            // Read inode table block number from group descriptor (offset 8 in GD)
            let inode_table_block = u32::from_le_bytes([
                self.device_mmap[gd_offset as usize +  8],
                self.device_mmap[gd_offset as usize +  9],
                self.device_mmap[gd_offset as usize + 10],
                self.device_mmap[gd_offset as usize + 11],
            ]);

            let inode_table_offset = inode_table_block as u64 * block_size;
            // @Constant
            let inode_table_size = (inodes_per_group * inode_size).min(1024 * 1024);

            // Touch inode table pages
            // @Constant
            for i in (0..inode_table_size).step_by(4096) {
                let offset = inode_table_offset + i;
                if offset < total_size {
                    _ = unsafe {
                        std::ptr::read_volatile(
                            self.device_mmap.as_ptr().add(offset as usize)
                        )
                    };
                }
            }
        }
    }
}

/// impl block of misc helper functions
impl RawGrepper {
    fn read_file_into_buf(
        &mut self,
        inode: &Ext4Inode,
        max_size: usize,
        kind: BufKind,
        check_and_stop_if_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("RawGrepper::read_file_into_buf");

        let buf = self.get_buf_mut(kind);
        buf.clear();

        let size_to_read = (inode.size as usize).min(max_size);
        buf.reserve(size_to_read);

        let file_size = inode.size as usize;

        let is_binary = |this: &mut RawGrepper| -> bool {
            let buf = this.get_buf(kind);
            if buf.len() >= BINARY_PROBE_BYTE_SIZE || buf.len() == file_size {
                if is_binary_chunk(&buf[..file_size.min(BINARY_PROBE_BYTE_SIZE)]) {
                    // It's binary! Clear and exit.
                    this.get_buf_mut(kind).clear();
                    return true;
                }
            }

            false
        };

        let copy_block_to_buf = |this: &mut RawGrepper, block_num: u64| {
            let _span = tracy::span!("RawGrepper::read_file_into_buf::copy_block_to_buf");

            let offset = this.get_buf(kind).len();
            let remaining = size_to_read - offset;

            let (src_ptr, to_copy) = {
                let block_data = this.get_block(block_num.into());
                let to_copy = block_data.len().min(remaining);
                (block_data.as_ptr(), to_copy)
            };

            let buf = this.get_buf_mut(kind);
            let old_len = buf.len();
            buf.resize(old_len + to_copy, 0);

            // SAFETY: We obtain the source pointer from `block_data` while it's borrowed,
            // then drop that borrow before getting a mutable borrow to the destination buffer.
            // The source pointer remains valid because `get_block()` returns data from an mmap
            // that won't be invalidated during this operation. We ensure no overlap between
            // source and destination, and both pointers are valid for the copy length.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    src_ptr,
                    buf.as_mut_ptr().add(old_len),
                    to_copy
                );
            }
        };

        if inode.flags & EXT4_EXTENTS_FL != 0 {
            self.parse_extents(inode)?;

            let extent_count = self.extent_buf.len();
            // @StackLarge
            let extents_copy: SmallVec::<[_; MAX_EXTENTS_UNTIL_SPILL]> = copy_data(
                &self.extent_buf[..extent_count]
            );

            // ------- Prefetch the blooooooocks
            {
                let _span = tracy::span!("RawGrepper::read_file_into_buf::prefetch_blocks");

                // @StackLarge
                let mut blocks_to_prefetch = SmallVec::<[_; MAX_EXTENTS_UNTIL_SPILL]>::with_capacity(
                    MAX_EXTENTS_UNTIL_SPILL
                );
                for extent in &extents_copy {
                    for i in 0..extent.len.min((MAX_EXTENTS_UNTIL_SPILL / extents_copy.len().max(1)) as _) {
                        blocks_to_prefetch.push(extent.start + i as u64);
                        if blocks_to_prefetch.len() >= MAX_EXTENTS_UNTIL_SPILL {
                            break;
                        }
                    }
                    if blocks_to_prefetch.len() >= MAX_EXTENTS_UNTIL_SPILL {
                        break;
                    }
                }
                self.prefetch_blocks(&blocks_to_prefetch);
            }

            {
                let _span = tracy::span!("RawGrepper::read_file_into_buf::copy_blocks_to_buf_loop");

                for extent in &extents_copy {
                    if self.get_buf(kind).len() >= size_to_read { break; }

                    for j in 0..extent.len {
                        let len = self.get_buf(kind).len();
                        if len >= size_to_read { break }

                        let phys_block = extent.start + j as u64;
                        copy_block_to_buf(self, phys_block);

                        if check_and_stop_if_binary && is_binary(self) {
                            // It's binary! Clear and exit.
                            self.get_buf_mut(kind).clear();
                            return Ok(false);
                        }
                    }
                }
            }
        } else {
            // ------- Prefetch the blooooooocks
            {
                let _span = tracy::span!("RawGrepper::read_file_into_buf::prefetch_blocks");

                let mut blocks_to_prefetch = SmallVec::<[_; EXT4_BLOCK_POINTERS_COUNT]>::with_capacity(
                    EXT4_BLOCK_POINTERS_COUNT
                );
                for &block in inode.blocks.iter().take(EXT4_BLOCK_POINTERS_COUNT) {
                    if block != 0 {
                        blocks_to_prefetch.push(block as _);
                    }
                }
                self.prefetch_blocks(&blocks_to_prefetch);
            }

            {
                let _span = tracy::span!("RawGrepper::read_file_into_buf::copy_blocks_to_buf_loop");
                for &block in inode.blocks.iter().take(EXT4_BLOCK_POINTERS_COUNT) {
                    if block == 0 || self.get_buf(kind).len() >= size_to_read {
                        break;
                    }

                    copy_block_to_buf(self, block.into());

                    if check_and_stop_if_binary && is_binary(self) {
                        // It's binary! Clear and exit.
                        self.get_buf_mut(kind).clear();
                        return Ok(false);
                    }
                }
            }
        }

        self.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    #[inline(always)]
    fn get_buf(&self, kind: BufKind) -> &Vec<u8> {
        match kind {
            BufKind::File      => &self.content_buf,
            BufKind::Dir       => &self.dir_buf,
            BufKind::Gitignore => &self.gitignore_buf,
        }
    }

    #[inline(always)]
    fn get_buf_mut(&mut self, kind: BufKind) -> &mut Vec<u8> {
        match kind {
            BufKind::File      => &mut self.content_buf,
            BufKind::Dir       => &mut self.dir_buf,
            BufKind::Gitignore => &mut self.gitignore_buf,
        }
    }

    #[inline(always)]
    fn max_file_byte_size(&self) -> usize {
        if self.cli.should_ignore_size_filter() {
            usize::MAX
        } else {
            _MAX_FILE_BYTE_SIZE
        }
    }

    #[inline(always)]
    fn max_dir_byte_size(&self) -> usize {
        if self.cli.should_ignore_size_filter() {
            usize::MAX
        } else {
            _MAX_DIR_BYTE_SIZE
        }
    }

    // @Hot
    #[inline(always)]
    fn get_block(&self, block_num: u64) -> &[u8] {
        let offset = (block_num as usize).wrapping_mul(self.sb.block_size as usize);
        debug_assert!(
            self.device_mmap
                .get(offset..offset + self.sb.block_size as usize)
                .is_some()
        );
        unsafe {
            let ptr = self.device_mmap.as_ptr().add(offset);
            std::slice::from_raw_parts(ptr, self.sb.block_size as usize)
        }
    }

    #[inline(always)]
    fn prefetch_blocks(&self, blocks: &[u64]) {
        let _span = tracy::span!("RawGrepper::prefetch_blocks");

        if blocks.is_empty() {
            return;
        }

        let mut sorted: SmallVec<[_; 16]> = copy_data(blocks);
        sorted.sort_unstable();
        sorted.dedup();

        let mut range_start = sorted[0];
        let mut range_end = sorted[0];

        for &block in &sorted[1..] {
            if block == range_end + 1 {
                range_end = block;
            } else {
                self.advise_range(range_start, range_end);
                range_start = block;
                range_end = block;
            }
        }
        self.advise_range(range_start, range_end);
    }

    #[inline(always)]
    fn advise_range(&self, start_block: u64, end_block: u64) {
        let offset = start_block as usize * self.sb.block_size as usize;
        let length = (end_block - start_block + 1) as usize * self.sb.block_size as usize;

        if offset + length <= self.device_mmap.len() {
            unsafe {
                libc::madvise(
                    self.device_mmap.as_ptr().add(offset) as *mut _,
                    length,
                    libc::MADV_WILLNEED
                );
            }
        }
    }
}

/// impl block of ext4 parsing
impl RawGrepper {
    #[inline]
    fn parse_superblock(data: &[u8]) -> io::Result<Ext4SuperBlock> {
        let _span = tracy::span!("RawGrepper::parse_superblock");

        let block_size_log = u32::from_le_bytes([
            data[EXT4_BLOCK_SIZE_OFFSET + 0],
            data[EXT4_BLOCK_SIZE_OFFSET + 1],
            data[EXT4_BLOCK_SIZE_OFFSET + 2],
            data[EXT4_BLOCK_SIZE_OFFSET + 3],
        ]);
        let block_size = 1024 << block_size_log;

        let blocks_per_group = u32::from_le_bytes([
            data[EXT4_BLOCKS_PER_GROUP_OFFSET + 0],
            data[EXT4_BLOCKS_PER_GROUP_OFFSET + 1],
            data[EXT4_BLOCKS_PER_GROUP_OFFSET + 2],
            data[EXT4_BLOCKS_PER_GROUP_OFFSET + 3],
        ]);

        let inodes_per_group = u32::from_le_bytes([
            data[EXT4_INODES_PER_GROUP_OFFSET + 0],
            data[EXT4_INODES_PER_GROUP_OFFSET + 1],
            data[EXT4_INODES_PER_GROUP_OFFSET + 2],
            data[EXT4_INODES_PER_GROUP_OFFSET + 3],
        ]);

        let inode_size = u16::from_le_bytes([
            data[EXT4_INODE_SIZE_OFFSET + 0],
            data[EXT4_INODE_SIZE_OFFSET + 1],
        ]);

        let desc_size = if data.len() > EXT4_DESC_SIZE_OFFSET + 1 {
            let ds = u16::from_le_bytes([
                data[EXT4_DESC_SIZE_OFFSET + 0],
                data[EXT4_DESC_SIZE_OFFSET + 1],
            ]);
            if ds >= 32 { ds } else { 32 }
        } else {
            32
        };

        Ok(Ext4SuperBlock {
            block_size,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            desc_size,
        })
    }

    #[inline]
    fn parse_inode(&mut self, inode_num: INodeNum) -> io::Result<Ext4Inode> {
        let _span = tracy::span!("RawGrepper::parse_inode");

        if unlikely(inode_num == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid inode number 0"
            ));
        }

        let group = (inode_num - 1) / self.sb.inodes_per_group;
        let index = (inode_num - 1) % self.sb.inodes_per_group;

        let bg_desc_offset = if self.sb.block_size == 1024 {
            2048
        } else {
            self.sb.block_size as usize
        } + (group as usize * self.sb.desc_size as usize);

        let bg_desc = &self.device_mmap[
            bg_desc_offset..
            bg_desc_offset + self.sb.desc_size as usize
        ];

        let inode_table_block = u32::from_le_bytes([
            bg_desc[EXT4_INODE_TABLE_OFFSET + 0],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 1],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 2],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 3],
        ]);

        let inode_offset = inode_table_block as usize *
            self.sb.block_size as usize +
            index as usize *
            self.sb.inode_size as usize;

        let inode_bytes = &self.device_mmap[
            inode_offset..
            inode_offset + self.sb.inode_size as usize
        ];

        let mode = u16::from_le_bytes([
            inode_bytes[EXT4_INODE_MODE_OFFSET + 0],
            inode_bytes[EXT4_INODE_MODE_OFFSET + 1],
        ]);

        let size_low = u32::from_le_bytes([
            inode_bytes[EXT4_INODE_SIZE_OFFSET_LOW + 0],
            inode_bytes[EXT4_INODE_SIZE_OFFSET_LOW + 1],
            inode_bytes[EXT4_INODE_SIZE_OFFSET_LOW + 2],
            inode_bytes[EXT4_INODE_SIZE_OFFSET_LOW + 3],
        ]);

        let size_high = if self.sb.inode_size > 128
            && inode_bytes.len() > EXT4_INODE_SIZE_OFFSET_HIGH + 4
        {
            u32::from_le_bytes([
                inode_bytes[EXT4_INODE_SIZE_OFFSET_HIGH + 0],
                inode_bytes[EXT4_INODE_SIZE_OFFSET_HIGH + 1],
                inode_bytes[EXT4_INODE_SIZE_OFFSET_HIGH + 2],
                inode_bytes[EXT4_INODE_SIZE_OFFSET_HIGH + 3],
            ])
        } else {
            0
        };

        let size = ((size_high as u64) << 32) | (size_low as u64);

        let flags = u32::from_le_bytes([
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 0],
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 1],
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 2],
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 3],
        ]);

        let mut blocks = [0; 15];
        for (i, block) in blocks.iter_mut().enumerate() {
            let offset = EXT4_INODE_BLOCK_OFFSET + i * 4;
            *block = u32::from_le_bytes([
                inode_bytes[offset + 0],
                inode_bytes[offset + 1],
                inode_bytes[offset + 2],
                inode_bytes[offset + 3],
            ]);
        }

        Ok(Ext4Inode { mode, size, flags, blocks })
    }

    #[inline]
    fn parse_extents(&mut self, inode: &Ext4Inode) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::parse_extents");

        self.extent_buf.clear();

        let mut block_bytes: SmallVec<[_; 64]> = smallvec![0; 64];
        for (i, bytes) in inode.blocks.into_iter().map(u32::to_le_bytes).enumerate() {
            block_bytes[i * 4 + 0] = bytes[0];
            block_bytes[i * 4 + 1] = bytes[1];
            block_bytes[i * 4 + 2] = bytes[2];
            block_bytes[i * 4 + 3] = bytes[3];
        }

        self.parse_extent_node(&block_bytes, 0)?;
        Ok(())
    }

    fn parse_extent_node(&mut self, data: &[u8], level: usize) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::parse_extent_node");

        if data.len() < EXT4_EXTENT_HEADER_SIZE {
            return Ok(());
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != EXT4_EXTENT_MAGIC {
            return Ok(());
        }

        let entries = u16::from_le_bytes([data[2], data[3]]);
        let depth = u16::from_le_bytes([data[6], data[7]]);

        if depth == 0 {
            // -------- Leaf node
            for i in 0..entries {
                let base = EXT4_EXTENT_ENTRY_SIZE + (i as usize * EXT4_EXTENT_ENTRY_SIZE);
                if base + EXT4_EXTENT_ENTRY_SIZE > data.len() {
                    break;
                }

                let ee_len = u16::from_le_bytes([data[base + 4], data[base + 5]]);
                let ee_start_hi = u16::from_le_bytes([data[base + 6], data[base + 7]]);
                let ee_start_lo = u32::from_le_bytes([
                    data[base +  8],
                    data[base +  9],
                    data[base + 10],
                    data[base + 11]
                ]);

                let start_block = ((ee_start_hi as u64) << 32) | (ee_start_lo as u64);

                if ee_len > 0 && ee_len <= 32768 {
                    self.extent_buf.push(Ext4Extent {
                        start: start_block,
                        len: ee_len,
                    });
                }
            }
        } else {
            // -------- Internal node - collect block numbers first
            let mut child_blocks = SmallVec::<[_; 16]>::new();
            for i in 0..entries {
                let base = 12 + (i as usize * 12);
                if base + 12 > data.len() {
                    break;
                }

                let ei_leaf_lo = u32::from_le_bytes([
                    data[base + 4],
                    data[base + 5],
                    data[base + 6],
                    data[base + 7]
                ]);
                let ei_leaf_hi = u16::from_le_bytes([data[base + 8], data[base + 9]]);

                let leaf_block = ((ei_leaf_hi as u64) << 32) | (ei_leaf_lo as u64);
                child_blocks.push(leaf_block);
            }

            self.prefetch_blocks(&child_blocks);

            for child_block in child_blocks {
                // SAFETY:
                //
                // 1. `self.device_mmap` points to read-only memory and is never mutated for the entire
                //    lifetime of `RawGrepper`. No writes, no remapping, no replacement.
                // 2. `get_block()` returns slices that reference only this immutable mmap region.
                //    They must not alias any data that could be mutated through `&mut self`.
                // 3. `parse_extent_node()` must not cause `device_mmap` to change or become invalid.
                //    Fields like `extent_buf`, `content_buf`, etc may be modified, but `device_mmap`
                //    must remain stable and untouched.
                // 4. The returned `&[u8]` slices are used only within the duration of this call and are
                //    never stored, returned, or kept past recursion boundaries.
                // 5. No other code is allowed to obtain a mutable reference to the mmap contents.
                let block_data = unsafe {
                    let zelf: *const Self = self;
                    (&*zelf).get_block(child_block.into())
                };
                self.parse_extent_node(block_data, level + 1)?;
            }
        }

        Ok(())
    }
}
