// TODO(#1): Implement symlinks
// TODO(#24): Support for searching in large file(s). (detect that)

use crate::cli::{should_enable_ansi_coloring, Cli};
use crate::matcher::Matcher;
use crate::path_buf::SmallPathBuf;
use crate::stats::{ParallelStats, Stats};
use crate::{copy_data, eprintln_red, tracy, COLOR_CYAN, COLOR_GREEN, COLOR_RED, COLOR_RESET};
use crate::binary::{is_binary_chunk, is_binary_ext};
use crate::util::{
    build_gitignore_from_bytes,
    is_common_skip_dir, is_dot_entry, is_gitignored,
    likely, unlikely,
    truncate_utf8,
};

use std::mem;
use std::sync::Arc;
use std::borrow::Cow;
use std::fmt::Display;
use std::time::Duration;
use std::os::fd::AsRawFd;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytemuck::{Pod, Zeroable};
use ignore::gitignore::Gitignore;
use memmap2::{Mmap, MmapOptions};
use smallvec::{SmallVec, smallvec};
use crossbeam_channel::{unbounded, Receiver, Sender};
use crossbeam_deque::{Injector, Steal, Stealer, Worker as DequeWorker};

pub type INodeNum = u32;

pub const LARGE_DIR_THRESHOLD: usize = 1000; // Split dirs with 1000+ entries
pub const FILE_BATCH_SIZE: usize = 500; // Process files in batches of 500

pub const WORKER_FLUSH_BATCH: usize = 16 * 1024;
pub const OUTPUTTER_FLUSH_BATCH: usize = 32 * 1024;

pub const BINARY_CONTROL_COUNT: usize = 51; // tuned
pub const BINARY_PROBE_BYTE_SIZE: usize = 0x1000;

// pub const PATH_VERY_LONG_LENGTH: usize = 0x1000;

pub const MAX_EXTENTS_UNTIL_SPILL: usize = 64;

pub const _MAX_DIR_BYTE_SIZE: usize = 16 * 1024 * 1024;
pub const _MAX_FILE_BYTE_SIZE: usize = 8 * 1024 * 1024;
// pub const MAX_SYMLINK_TARGET_SIZE: usize = 4096;
// pub const FAST_SYMLINK_SIZE: usize = 60; // Symlinks < 60 bytes stored in inode

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

// pub const EXT4_FT_UNKNOWN: u8 =	0;
pub const EXT4_FT_REG_FILE: u8 = 1;
pub const EXT4_FT_DIR: u8 = 2;
// pub const EXT4_FT_CHRDEV: u8 = 3;
// pub const EXT4_FT_BLKDEV: u8 = 4;
// pub const EXT4_FT_FIFO: u8 = 5;
// pub const EXT4_FT_SOCK: u8 = 6;
// pub const EXT4_FT_SYMLINK: u8 = 7;

pub const EXT4_S_IFMT: u16 = 0xF000;
pub const EXT4_S_IFREG: u16 = 0x8000;
// pub const EXT4_S_IFLNK: u16 = 0xA000;
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
    pub file_buf: usize,
    pub gitignore_buf: usize,
    pub extent_buf: usize,
}

mod raw {
    use super::*;

    // Source: Linux kernel: fs/ext4/ext4.h
    // struct ext4_inode {
    //     __le16	i_mode;		/* File mode */
    //     __le16	i_uid;		/* Low 16 bits of Owner Uid */
    //     __le32	i_size_lo;	/* Size in bytes */
    //     __le32	i_atime;	/* Access time */
    //     __le32	i_ctime;	/* Inode Change time */
    //     __le32	i_mtime;	/* Modification time */
    //     __le32	i_dtime;	/* Deletion Time */
    //     __le16	i_gid;		/* Low 16 bits of Group Id */
    //     __le16	i_links_count;	/* Links count */
    //     __le32	i_blocks_lo;	/* Blocks count */
    //     __le32	i_flags;	/* File flags */
    //     union {
    //         struct {
    //             __le32  l_i_version;
    //         } linux1;
    //         struct {
    //             __u32  h_i_translator;
    //         } hurd1;
    //         struct {
    //             __u32  m_i_reserved1;
    //         } masix1;
    //     } osd1;				/* OS dependent 1 */
    //     __le32	i_block[EXT4_N_BLOCKS];/* Pointers to blocks */
    //     __le32	i_generation;	/* File version (for NFS) */
    //     __le32	i_file_acl_lo;	/* File ACL */
    //     __le32	i_size_high;
    //     __le32	i_obso_faddr;	/* Obsoleted fragment address */
    //     union {
    //         struct {
    //             __le16	l_i_blocks_high; /* were l_i_reserved1 */
    //             __le16	l_i_file_acl_high;
    //             __le16	l_i_uid_high;	/* these 2 fields */
    //             __le16	l_i_gid_high;	/* were reserved2[0] */
    //             __le16	l_i_checksum_lo;/* crc32c(uuid+inum+inode) LE */
    //             __le16	l_i_reserved;
    //         } linux2;
    //         struct {
    //             __le16	h_i_reserved1;	/* Obsoleted fragment number/size which are removed in ext4 */
    //             __u16	h_i_mode_high;
    //             __u16	h_i_uid_high;
    //             __u16	h_i_gid_high;
    //             __u32	h_i_author;
    //         } hurd2;
    //         struct {
    //             __le16	h_i_reserved1;	/* Obsoleted fragment number/size which are removed in ext4 */
    //             __le16	m_i_file_acl_high;
    //             __u32	m_i_reserved2[2];
    //         } masix2;
    //     } osd2;				/* OS dependent 2 */
    //     __le16	i_extra_isize;
    //     __le16	i_checksum_hi;	/* crc32c(uuid+inum+inode) BE */
    //     __le32  i_ctime_extra;  /* extra Change time      (nsec << 2 | epoch) */
    //     __le32  i_mtime_extra;  /* extra Modification time(nsec << 2 | epoch) */
    //     __le32  i_atime_extra;  /* extra Access time      (nsec << 2 | epoch) */
    //     __le32  i_crtime;       /* File Creation time */
    //     __le32  i_crtime_extra; /* extra FileCreationtime (nsec << 2 | epoch) */
    //     __le32  i_version_hi;	/* high 32 bits for 64-bit version */
    //     __le32	i_projid;	/* Project ID */
    // };

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct Ext4Inode {
        pub mode: u16,              // 0x00
        pub uid: u16,               // 0x02
        pub size_lo: u32,           // 0x04
        pub atime: u32,             // 0x08
        pub ctime: u32,             // 0x0C
        pub mtime: u32,             // 0x10
        pub dtime: u32,             // 0x14
        pub gid: u16,               // 0x18
        pub links_count: u16,       // 0x1A
        pub blocks_lo: u32,         // 0x1C
        pub flags: u32,             // 0x20
        pub osd1: u32,              // 0x24
        pub block: [[u8; 12]; 5],   // 0x28 - 60 bytes as 5x12 (bytemuck supports [T; 12])
        pub generation: u32,        // 0x64
        pub file_acl_lo: u32,       // 0x68
        pub size_high: u32,         // 0x6C
        pub obso_faddr: u32,        // 0x70
        pub osd2: [u8; 12],         // 0x74
        pub extra_isize: u16,       // 0x80
        pub checksum_hi: u16,       // 0x82
        pub ctime_extra: u32,       // 0x84
        pub mtime_extra: u32,       // 0x88
        pub atime_extra: u32,       // 0x8C
        pub crtime: u32,            // 0x90
        pub crtime_extra: u32,      // 0x94
        pub version_hi: u32,        // 0x98
        pub projid: u32,            // 0x9C
    }

    // Source: Linux kernel: fs/ext4/ext4.h
    // struct ext4_dir_entry_2 {
    //     __le32	inode;			/* Inode number */
    //     __le16	rec_len;		/* Directory entry length */
    //     __u8	name_len;		/* Name length */
    //     __u8	file_type;		/* See file type macros EXT4_FT_* below */
    //     char	name[EXT4_NAME_LEN];	/* File name */
    // };

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct Ext4DirEntry2 {
        pub inode: u32,        // 0x00
        pub rec_len: u16,      // 0x04
        pub name_len: u8,      // 0x06
        pub file_type: u8,     // 0x07
        // name follows immediately after
    }

    // Source: Linux kernel: fs/ext4/ext4_extents.h
    // struct ext4_extent_header {
    //     __le16	eh_magic;	/* probably will support different formats */
    //     __le16	eh_entries;	/* number of valid entries */
    //     __le16	eh_max;		/* capacity of store in entries */
    //     __le16	eh_depth;	/* has tree real underlying blocks? */
    //     __le32	eh_generation;	/* generation of the tree */
    // };

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct Ext4ExtentHeader {
        pub eh_magic: u16,          // 0x00 - must be 0xF30A
        pub eh_entries: u16,        // 0x02 - number of valid entries
        pub eh_max: u16,            // 0x04 - max entries that could follow
        pub eh_depth: u16,          // 0x06 - tree depth (0 = leaf)
        pub eh_generation: u32,     // 0x08
    }

    // Source: Linux kernel: fs/ext4/ext4_extents.h
    // struct ext4_extent {
    //     __le32	ee_block;	/* first logical block extent covers */
    //     __le16	ee_len;		/* number of blocks covered by extent */
    //     __le16	ee_start_hi;	/* high 16 bits of physical block */
    //     __le32	ee_start_lo;	/* low 32 bits of physical block */
    // };

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct Ext4Extent {
        pub ee_block: u32,          // 0x00 - first logical block extent covers
        pub ee_len: u16,            // 0x04 - number of blocks covered
        pub ee_start_hi: u16,       // 0x06 - high 16 bits of physical block
        pub ee_start_lo: u32,       // 0x08 - low 32 bits of physical block
    }

    // Source: Linux kernel: fs/ext4/ext4_extents.h
    // struct ext4_extent_idx {
    //     __le32	ei_block;	/* index covers logical blocks from 'block' */
    //     __le32	ei_leaf_lo;	/* pointer to the physical block of the next *
    //                  * level. leaf or next index could be there */
    //     __le16	ei_leaf_hi;	/* high 16 bits of physical block */
    //     __u16	ei_unused;
    // };

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct Ext4ExtentIdx {
        pub ei_block: u32,          // 0x00 - index covers logical blocks from 'block'
        pub ei_leaf_lo: u32,        // 0x04 - low 32 bits of physical block pointer
        pub ei_leaf_hi: u16,        // 0x08 - high 16 bits of physical block pointer
        pub ei_unused: u16,         // 0x0A
    }
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
    parent_path: Arc<[u8]>,
    gitignore: Option<Arc<Gitignore>>,
    // Raw directory entry data (multiple entries concatenated)
    entries: Box<[u8]>,
}

struct Outputter {
    rx: Receiver<Vec<u8>>,
    writer: BufWriter<io::Stdout>,
}

impl Outputter {
    #[inline]
    fn run(mut self) {
        let _span = tracy::span!("OutputThread::run");

        while let Ok(buf) = self.rx.recv() {
            _ = self.writer.write_all(&buf);
            // Flush periodically, not every time
            if self.writer.buffer().len() > OUTPUTTER_FLUSH_BATCH {
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

    // Thread(Worker)-local buffers
    file_buf: Vec<u8>,
    dir_buf: Vec<u8>,
    gitignore_buf: Vec<u8>,
    extent_buf: Vec<Ext4Extent>,
    path_buf: SmallPathBuf,
    output_buf: Vec<u8>,
}

impl<'a> WorkerContext<'a> {
    #[inline(always)]
    fn init(&mut self) {
        let config = self.cli.get_buffer_config();
        self.dir_buf.reserve(config.dir_buf);
        self.file_buf.reserve(config.file_buf);
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

    #[allow(unused)]
    fn resolve_path_from_root(&mut self, path: &[u8]) -> io::Result<INodeNum> {
        let mut resolved_path = SmallPathBuf::new();
        resolved_path.extend_from_slice(path);
        self.resolve_path_to_inode(&resolved_path)
    }

    #[allow(unused)]
    fn resolve_path_to_inode(&mut self, path: &SmallPathBuf) -> io::Result<INodeNum> {
        let path_str = std::str::from_utf8(path.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8"))?;

        let mut inode_num = EXT4_ROOT_INODE;

        for component in path_str.split('/').filter(|s| !s.is_empty()) {
            let inode = self.parse_inode(inode_num)?;

            if unlikely((inode.mode & EXT4_S_IFMT) != EXT4_S_IFDIR) {
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

                if unlikely(rec_len == 0) {
                    break;
                }

                if likely(entry_inode != 0 && name_len > 0) {
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
    #[inline]
    fn read_file_into_buf(
        &mut self,
        inode: &Ext4Inode,
        max_size: usize,
        kind: BufKind,
        check_and_stop_if_binary: bool,
    ) -> io::Result<bool> {
        let buf = self.get_buf_mut(kind);
        buf.clear();

        let file_size = inode.size as usize;
        let size_to_read = file_size.min(max_size);
        buf.reserve(size_to_read);

        if inode.flags & EXT4_EXTENTS_FL != 0 {
            self.read_extents(inode, size_to_read, file_size, kind, check_and_stop_if_binary)
        } else {
            self.read_direct_blocks(inode, size_to_read, file_size, kind, check_and_stop_if_binary)
        }
    }

    #[inline]
    fn read_extents(
        &mut self,
        inode: &Ext4Inode,
        size_to_read: usize,
        file_size: usize,
        kind: BufKind,
        check_binary: bool,
    ) -> io::Result<bool> {
        self.parse_extents(inode)?;

        let extent_count = self.extent_buf.len();

        let extents: SmallVec<[_; MAX_EXTENTS_UNTIL_SPILL]> = copy_data(
            &self.extent_buf[..extent_count]
        );

        self.prefetch_extent_blocks(&extents, size_to_read);

        // Binary check: Only check FIRST block if enabled
        if check_binary {
            if let Some(first_extent) = extents.first() {
                let first_block = self.get_block(first_extent.start);
                let probe_size = file_size.min(BINARY_PROBE_BYTE_SIZE).min(first_block.len());

                if is_binary_chunk(&first_block[..probe_size]) {
                    self.get_buf_mut(kind).clear();
                    return Ok(false);
                }
            }
        }

        // Fast path: Copy all blocks without binary checks
        self.copy_extents_to_buf(&extents, size_to_read, kind);

        self.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    #[inline]
    fn read_direct_blocks(
        &mut self,
        inode: &Ext4Inode,
        size_to_read: usize,
        file_size: usize,
        kind: BufKind,
        check_binary: bool,
    ) -> io::Result<bool> {
        let mut blocks = SmallVec::<[_; EXT4_BLOCK_POINTERS_COUNT]>::new();
        for &block in inode.blocks.iter().take(EXT4_BLOCK_POINTERS_COUNT) {
            if likely(block != 0) {
                blocks.push(block as u64);
            }
        }
        self.prefetch_blocks(Cow::Borrowed(&blocks));

        // Binary check: Only check FIRST block if enabled
        if check_binary && let Some(&first_block_num) = blocks.first() {
            let first_block = self.get_block(first_block_num);
            let probe_size = file_size.min(BINARY_PROBE_BYTE_SIZE).min(first_block.len());

            if is_binary_chunk(&first_block[..probe_size]) {
                self.get_buf_mut(kind).clear();
                return Ok(false);
            }
        }

        let mut copied = 0;

        for block_num in blocks {
            if copied >= size_to_read { break; }

            let (src_ptr, src_len) = {
                let block_data = self.get_block(block_num);
                (block_data.as_ptr(), block_data.len())
            };

            let remaining = size_to_read - copied;
            let to_copy = src_len.min(remaining);

            let buf = self.get_buf_mut(kind);
            let old_len = buf.len();
            buf.resize(old_len + to_copy, 0);

            // SAFETY: Same as above
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src_ptr,
                    buf.as_mut_ptr().add(old_len),
                    to_copy
                );
            }

            copied += to_copy;
        }

        self.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    #[inline]
    fn prefetch_extent_blocks(&self, extents: &[Ext4Extent], size_to_read: usize) {
        let block_size = self.sb.block_size as usize;
        let blocks_needed = size_to_read.div_ceil(block_size);

        let mut blocks = SmallVec::<[_; MAX_EXTENTS_UNTIL_SPILL]>::new();
        let mut total = 0;

        for extent in extents {
            let extent_blocks = (extent.len as usize).min(blocks_needed - total);

            for i in 0..extent_blocks {
                blocks.push(extent.start + i as u64);
            }

            total += extent_blocks;
            if total >= blocks_needed { break; }
        }

        self.prefetch_blocks(Cow::Owned(blocks));
    }

    #[inline]
    fn copy_extents_to_buf(
        &mut self,
        extents: &[Ext4Extent],
        size_to_read: usize,
        kind: BufKind,
    ) {
        let mut copied = 0;

        for extent in extents {
            if copied >= size_to_read { break; }

            for block_offset in 0..extent.len {
                if copied >= size_to_read { break; }

                let phys_block = extent.start + block_offset as u64;

                let (src_ptr, src_len) = {
                    let block_data = self.get_block(phys_block);
                    (block_data.as_ptr(), block_data.len())
                };

                let remaining = size_to_read - copied;
                let to_copy = src_len.min(remaining);

                let buf = self.get_buf_mut(kind);
                let old_len = buf.len();
                buf.resize(old_len + to_copy, 0);

                // SAFETY: src_ptr points to mmap'd data that remains valid.
                // We've ensured no overlap and both pointers are valid.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        src_ptr,
                        buf.as_mut_ptr().add(old_len),
                        to_copy
                    );
                }

                copied += to_copy;
            }
        }
    }

    /// Called when either checking if a path is gitignored or printing the matches
    #[inline(always)]
    fn display_path_into_buf<'a>(&self, buf: &'a mut String) -> &'a str {
        let _span = tracy::span!("WorkerContext::display_path_into_buf");

        buf.clear();
        // @Speed
        buf.push_str(&String::from_utf8_lossy(self.path_buf.as_slice()));
        buf.as_str()
    }

    #[allow(unused)]
    #[inline(always)]
    fn buf_ptr(&self, ptr: BufFatPtr) -> &[u8] {
        #[cfg(debug_assertions)] {
            &self.get_buf(ptr.kind)[ptr.offset..ptr.offset+ptr.len as usize]
        }

        // SAFETY: safety is on caller
        #[cfg(not(debug_assertions))]
        unsafe {
            &self.get_buf(ptr.kind).get_unchecked(
                ptr.offset..ptr.offset+ptr.len as usize
            )
        }
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
            core::slice::from_raw_parts(ptr, self.sb.block_size as usize)
        }
    }

    #[inline(always)]
    fn prefetch_blocks<const N: usize>(&self, blocks: Cow<SmallVec<[u64; N]>>) {
        let _span = tracy::span!("WorkerContext::prefetch_blocks");

        // Only prefetch if we have significant non-contiguous ranges
        // @Constant
        if blocks.len() < 3 {
            return;
        }

        let mut sorted = match blocks {
            Cow::Borrowed(bw) => copy_data(bw),
            Cow::Owned(ow) => ow,
        };
        sorted.sort_unstable();

        let mut gaps = 0;
        for i in 1..sorted.len() {
            if sorted[i] > sorted[i-1] + 1 {
                gaps += 1;
            }
        }

        // Only worth prefetching if significantly fragmented
        // @Constant
        if gaps < 2 { return; }

        sorted.dedup();

        let mut range_start = sorted[0];
        let mut range_end = sorted[0];

        for &block in &sorted[1..] {
            // Merge adjacent or close blocks (within 32 blocks)
            // @Constant
            if block <= range_end + 32 {
                range_end = block;
            } else {
                // Only advise ranges >= 128KB
                // @Constant
                if (range_end - range_start) * self.sb.block_size as u64 >= 128 * 1024 {
                    self.advise_range(range_start, range_end);
                }
                range_start = block;
                range_end = block;
            }
        }

        // @Constant
        if (range_end - range_start) * self.sb.block_size as u64 >= 128 * 1024 {
            self.advise_range(range_start, range_end);
        }
    }

    #[inline(always)]
    fn advise_range(&self, start_block: u64, end_block: u64) {
        let offset = start_block as usize * self.sb.block_size as usize;
        let length = (end_block - start_block + 1) as usize * self.sb.block_size as usize;

        debug_assert!(offset + length <= self.device_mmap.len());

        unsafe {
            libc::madvise(
                self.device_mmap.as_ptr().add(offset) as *mut _,
                length,
                libc::MADV_WILLNEED
            );
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

        // @Refactor
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

        let raw = bytemuck::try_from_bytes::<raw::Ext4Inode>(
            &inode_bytes[..std::mem::size_of::<raw::Ext4Inode>().min(inode_bytes.len())]
        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid inode data"))?;

        let mode = u16::from_le(raw.mode);
        let size_low = u32::from_le(raw.size_lo);
        let flags = u32::from_le(raw.flags);

        let size_high = if self.sb.inode_size > 128 {
            u32::from_le(raw.size_high)
        } else {
            0
        };

        let size = ((size_high as u64) << 32) | (size_low as u64);

        // Parse blocks - manually unroll for performance
        // The blocks are stored as [u8; 60] which is 15 x u32
        let raw_block = [raw.block];
        let block_bytes = bytemuck::cast_slice::<[[u8; 12]; 5], u8>(&raw_block);

        let blocks = [
            u32::from_le_bytes([block_bytes[ 0], block_bytes[ 1], block_bytes[ 2], block_bytes[ 3]]),
            u32::from_le_bytes([block_bytes[ 4], block_bytes[ 5], block_bytes[ 6], block_bytes[ 7]]),
            u32::from_le_bytes([block_bytes[ 8], block_bytes[ 9], block_bytes[10], block_bytes[11]]),
            u32::from_le_bytes([block_bytes[12], block_bytes[13], block_bytes[14], block_bytes[15]]),
            u32::from_le_bytes([block_bytes[16], block_bytes[17], block_bytes[18], block_bytes[19]]),
            u32::from_le_bytes([block_bytes[20], block_bytes[21], block_bytes[22], block_bytes[23]]),
            u32::from_le_bytes([block_bytes[24], block_bytes[25], block_bytes[26], block_bytes[27]]),
            u32::from_le_bytes([block_bytes[28], block_bytes[29], block_bytes[30], block_bytes[31]]),
            u32::from_le_bytes([block_bytes[32], block_bytes[33], block_bytes[34], block_bytes[35]]),
            u32::from_le_bytes([block_bytes[36], block_bytes[37], block_bytes[38], block_bytes[39]]),
            u32::from_le_bytes([block_bytes[40], block_bytes[41], block_bytes[42], block_bytes[43]]),
            u32::from_le_bytes([block_bytes[44], block_bytes[45], block_bytes[46], block_bytes[47]]),
            u32::from_le_bytes([block_bytes[48], block_bytes[49], block_bytes[50], block_bytes[51]]),
            u32::from_le_bytes([block_bytes[52], block_bytes[53], block_bytes[54], block_bytes[55]]),
            u32::from_le_bytes([block_bytes[56], block_bytes[57], block_bytes[58], block_bytes[59]]),
        ];

        Ok(Ext4Inode { mode, size, flags, blocks })
    }

    #[inline]
    fn parse_extents(&mut self, inode: &Ext4Inode) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::parse_extents");

        self.extent_buf.clear();
        let block_bytes = bytemuck::cast_slice(&inode.blocks);
        self.parse_extent_node(block_bytes, 0)?;

        Ok(())
    }

    fn parse_extent_node(&mut self, data: &[u8], level: usize) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::parse_extent_node");

        if likely(data.len() < mem::size_of::<raw::Ext4ExtentHeader>()) {
            return Ok(());
        }

        let header = bytemuck::try_from_bytes::<raw::Ext4ExtentHeader>(
            &data[..mem::size_of::<raw::Ext4ExtentHeader>()]
        ).map_err(|_|
            io::Error::new(
                io::ErrorKind::InvalidData, "Invalid extent header"
            )
        )?;

        if likely(u16::from_le(header.eh_magic) != EXT4_EXTENT_MAGIC) {
            return Ok(());
        }

        let entries = u16::from_le(header.eh_entries);
        let depth = u16::from_le(header.eh_depth);

        if depth == 0 {
            // Leaf node
            self.extent_buf.reserve(entries as usize);

            let extent_size = mem::size_of::<raw::Ext4Extent>();
            let extents_start = mem::size_of::<raw::Ext4ExtentHeader>();

            for i in 0..entries as usize {
                let offset = extents_start + i * extent_size;
                if unlikely(offset + extent_size > data.len()) {
                    break;
                }

                let extent = bytemuck::try_from_bytes::<raw::Ext4Extent>(
                    &data[offset..offset + extent_size]
                ).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid extent data"
                    )
                })?;

                let ee_len = u16::from_le(extent.ee_len);
                let ee_start_hi = u16::from_le(extent.ee_start_hi);
                let ee_start_lo = u32::from_le(extent.ee_start_lo);

                let start_block = ((ee_start_hi as u64) << 32) | (ee_start_lo as u64);

                // Validate extent length (max 32768 blocks = 128MB for 4K blocks)
                if likely(ee_len > 0 && ee_len <= 32768) {
                    self.extent_buf.push(Ext4Extent {
                        start: start_block,
                        len: ee_len,
                    });
                }
            }
        } else {
            // Internal node
            // @Constant
            let mut child_blocks = SmallVec::<[_; 16]>::new();

            let index_size = mem::size_of::<raw::Ext4ExtentIdx>();
            let indices_start = mem::size_of::<raw::Ext4ExtentHeader>();

            for i in 0..entries as usize {
                let offset = indices_start + i * index_size;
                if likely(offset + index_size > data.len()) {
                    break;
                }

                let idx = bytemuck::try_from_bytes::<raw::Ext4ExtentIdx>(
                    &data[offset..offset + index_size]
                ).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Couldn't parse extent"
                    )
                })?;

                let ei_leaf_hi = u16::from_le(idx.ei_leaf_hi);
                let ei_leaf_lo = u32::from_le(idx.ei_leaf_lo);

                let leaf_block = ((ei_leaf_hi as u64) << 32) | (ei_leaf_lo as u64);
                child_blocks.push(leaf_block);
            }

            self.prefetch_blocks(Cow::Borrowed(&child_blocks));

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
                    (&*zelf).get_block(child_block)
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

        if likely(!work.path_bytes.is_empty()) {
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
            self.find_gitignore_inode_in_buf(BufKind::Dir).and_then(|gi_inode| {
                self.display_path_into_buf(path_display_buf);
                self.try_load_gitignore(gi_inode, path_display_buf).map(Arc::new)
            }).or_else(|| work.gitignore.clone())
        } else {
            work.gitignore.as_ref().map(Arc::clone)
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
            self.process_not_large_directory(
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
        let _span = tracy::span!("count_directory_entries");

        let mut file_count = 0;
        let mut dir_count = 0;
        let mut offset = 0;

        let entry_size = mem::size_of::<raw::Ext4DirEntry2>();

        while offset + entry_size <= self.dir_buf.len() {
            let entry = match bytemuck::try_from_bytes::<raw::Ext4DirEntry2>(
                &self.dir_buf[offset..offset + entry_size]
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

            // @Refactor @Cutnpaste from process_not_large_directory
            if likely(entry_inode != 0 && name_len > 0) {
                let name_end = offset + entry_size + name_len as usize;
                if likely(name_end <= offset + rec_len as usize && name_end <= self.dir_buf.len()) {
                    // SAFETY: `self.dir_buf` contains valid Ext4DirEntry2 data
                    let name_bytes = unsafe {
                        self.dir_buf.get_unchecked(offset + entry_size..name_end)
                    };

                    if is_dot_entry(name_bytes) {
                        offset += rec_len as usize;
                        continue;
                    }

                    match file_type {
                        EXT4_FT_DIR => dir_count += 1,
                        EXT4_FT_REG_FILE => file_count += 1,
                        _ => {
                            // Slow fallback for unknown types
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
        // @Constant
        let mut current_batch = SmallVec::<[_; 0x1000]>::new();
        let mut files_in_batch = 0;

        // @Constant
        let entry_size = mem::size_of::<raw::Ext4DirEntry2>();

        let mut offset = 0;

        // Pre-calculate path components that don't change
        let needs_slash = !work.path_bytes.is_empty();

        while offset + entry_size <= self.dir_buf.len() {
            let entry = match bytemuck::try_from_bytes::<raw::Ext4DirEntry2>(
                &self.dir_buf[offset..offset + entry_size]
            ) {
                Ok(e) => e,
                Err(_) => break,
            };

            let entry_inode = u32::from_le(entry.inode);
            let rec_len = u16::from_le(entry.rec_len);
            let name_len = entry.name_len;

            if rec_len == 0 {
                break;
            }

            let rec_len_usize = rec_len as usize;

            if likely(entry_inode != 0 && name_len > 0) {
                let name_start = offset + entry_size;
                let name_end = name_start + name_len as usize;

                if likely(name_end <= offset + rec_len_usize && name_end <= self.dir_buf.len()) {
                    // SAFETY: `self.dir_buf` contains valid Ext4DirEntry2 data
                    let name_bytes = unsafe {
                        self.dir_buf.get_unchecked(name_start..name_end)
                    };

                    if likely(!is_dot_entry(name_bytes)) {
                        let Ok(child_inode) = self.parse_inode(entry_inode) else {
                            offset += rec_len_usize;
                            continue;
                        };

                        let ft = child_inode.mode & EXT4_S_IFMT;
                        match ft {
                            EXT4_S_IFDIR => {
                                if !is_common_skip_dir(name_bytes) {
                                    let mut child_path: SmallVec<[u8; 512]> = SmallVec::new();
                                    child_path.reserve_exact(
                                        work.path_bytes.len() + needs_slash as usize + name_len as usize
                                    );
                                    child_path.extend_from_slice(&work.path_bytes);
                                    if needs_slash {
                                        child_path.push(b'/');
                                    }
                                    child_path.extend_from_slice(name_bytes);

                                    subdirs.push(DirWork {
                                        inode_num: entry_inode,
                                        path_bytes: crate::util::smallvec_into_arc_slice_noshrink(
                                            child_path
                                        ),
                                        gitignore: current_gi.as_ref().map(Arc::clone),
                                        depth: work.depth + 1,
                                    });
                                }
                            }
                            EXT4_S_IFREG => {
                                current_batch.reserve(5 + name_len as usize);
                                current_batch.extend_from_slice(&entry_inode.to_le_bytes());
                                current_batch.push(name_len);
                                current_batch.extend_from_slice(name_bytes);
                                files_in_batch += 1;

                                if files_in_batch >= FILE_BATCH_SIZE {
                                    local.push(WorkItem::FileBatch(FileBatchWork {
                                        parent_path: Arc::clone(&work.path_bytes),
                                        gitignore: current_gi.as_ref().map(Arc::clone),
                                        entries: crate::util::smallvec_into_boxed_slice_noshrink(
                                            mem::take(&mut current_batch)
                                        )
                                    }));
                                    files_in_batch = 0;
                                }
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
                parent_path: Arc::clone(&work.path_bytes),
                gitignore: current_gi.as_ref().map(Arc::clone),
                entries: crate::util::smallvec_into_boxed_slice_noshrink(current_batch),
            }));
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

    fn process_not_large_directory(
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

        // @Constant
        let entry_size = mem::size_of::<raw::Ext4DirEntry2>();

        // Pre-calculate path components that don't change
        let needs_slash = !work.path_bytes.is_empty();

        while offset + entry_size <= self.dir_buf.len() {
            let entry = match bytemuck::try_from_bytes::<raw::Ext4DirEntry2>(
                &self.dir_buf[offset..offset + entry_size]
            ) {
                Ok(e) => e,
                Err(_) => break,
            };

            let entry_inode = u32::from_le(entry.inode);
            let rec_len = u16::from_le(entry.rec_len);
            let name_len = entry.name_len;

            if (rec_len == 0 || rec_len < entry_size as u16) ||
                offset + rec_len as usize > self.dir_buf.len()
            {
                break; // Corrupted directory
            }

            let rec_len_usize = rec_len as usize;

            if entry_inode != 0 && name_len > 0 {
                let name_start = offset + entry_size;
                let name_end = name_start + name_len as usize;

                if name_end <= offset + rec_len_usize && name_end <= self.dir_buf.len() {
                    // SAFETY: `self.dir_buf` contains valid Ext4DirEntry2 data
                    let name_bytes = unsafe {
                        self.dir_buf.get_unchecked(name_start..name_end)
                    };

                    if !is_dot_entry(name_bytes) {
                        // Unknown type - parse inode to determine
                        let Ok(child_inode) = self.parse_inode(entry_inode) else {
                            offset += rec_len_usize;
                            continue;
                        };

                        // @Speed
                        // TODO(#3): Dispatch on inode.file_type when possible
                        let ft = child_inode.mode & EXT4_S_IFMT;
                        match ft {
                            EXT4_S_IFDIR => {
                                if !is_common_skip_dir(name_bytes) {
                                    // @Constant
                                    let mut child_path: SmallVec<[u8; 512]> = SmallVec::new();
                                    child_path.reserve_exact(
                                        work.path_bytes.len() + needs_slash as usize + name_len as usize
                                    );
                                    child_path.extend_from_slice(&work.path_bytes);
                                    if needs_slash {
                                        child_path.push(b'/');
                                    }
                                    child_path.extend_from_slice(name_bytes);

                                    subdirs.push(DirWork {
                                        inode_num: entry_inode,
                                        path_bytes: crate::util::smallvec_into_arc_slice_noshrink(
                                            child_path
                                        ),
                                        gitignore: current_gi.as_ref().map(Arc::clone),
                                        depth: work.depth + 1,
                                    });
                                }
                            }
                            EXT4_S_IFREG => {
                                // @Speed
                                let name_bytes = name_bytes.to_vec();
                                self.process_file(
                                    &child_inode,
                                    &name_bytes,
                                    &work.path_bytes,
                                    current_gi.as_deref(),
                                    path_display_buf
                                )?;

                                if self.output_buf.len() > WORKER_FLUSH_BATCH {
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
                if parent_path_len > 0 && self.path_buf.as_slice()[parent_path_len - 1] != b'/' {
                    self.path_buf.push(b'/');
                }
                self.path_buf.extend_from_slice(name_bytes);
            }

            let Ok(inode) = self.parse_inode(entry_inode) else {
                continue;
            };

            self.process_file(
                &inode,
                name_bytes,
                &batch.parent_path,
                batch.gitignore.as_deref(),
                path_display_buf
            )?;

            if self.output_buf.len() > WORKER_FLUSH_BATCH {
                self.flush_output();
            }
        }

        Ok(())
    }

    fn process_file(
        &mut self,
        inode: &Ext4Inode,
        file_name: &[u8],
        parent_path: &[u8],
        gitignore: Option<&Gitignore>,
        path_display_buf: &mut String
    ) -> io::Result<()> {
        let _span = tracy::span!("WorkerContext::process_file_not_batch");

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
        // @Refactor @Cutnpaste from above
        {
            let _span = tracy::span!("build full path");

            self.path_buf.clear();
            self.path_buf.extend_from_slice(parent_path);
            if !parent_path.is_empty() {
                self.path_buf.push(b'/');
            }
            self.path_buf.extend_from_slice(file_name);
        }

        let size = (inode.size as usize).min(self.max_file_byte_size());

        match self.read_file_into_buf(inode, size, BufKind::File, !self.cli.should_search_binary())? {
            true => {
                self.stats.files_searched.fetch_add(1, Ordering::Relaxed);
                self.stats.bytes_searched.fetch_add(self.file_buf.len() as u64, Ordering::Relaxed);

                // Only build display path if we have matches
                if self.matcher.is_match(&self.file_buf) {
                    self.display_path_into_buf(path_display_buf);
                    self.find_and_print_matches(path_display_buf)?;
                }
            }
            false => {
                self.stats.files_skipped_as_binary_due_to_probe.fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(())
    }

    #[inline]
    fn find_and_print_matches(&mut self, path_display_buf: &mut String) -> io::Result<()> {
        let _span = tracy::span!("find_and_print_matches_fast");

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

        let should_print_color = should_enable_ansi_coloring();

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

                    if !self.cli.jump {
                        if should_print_color {
                            self.output_buf.extend_from_slice(COLOR_GREEN.as_bytes());
                        }
                        self.output_buf.extend_from_slice(path_display_buf.as_bytes());
                        if should_print_color {
                            self.output_buf.extend_from_slice(COLOR_RESET.as_bytes());
                        }
                        self.output_buf.extend_from_slice(b":\n");
                    }

                    found_any = true;
                }

                if self.cli.jump {
                    if should_print_color {
                        self.output_buf.extend_from_slice(COLOR_GREEN.as_bytes());
                    }
                    self.output_buf.extend_from_slice(path_display_buf.as_bytes());
                    if should_print_color {
                        self.output_buf.extend_from_slice(COLOR_RESET.as_bytes());
                    }
                    self.output_buf.extend_from_slice(b":");
                }

                if should_print_color {
                    self.output_buf.extend_from_slice(COLOR_CYAN.as_bytes());
                }
                let mut line_num_buf = itoa::Buffer::new();
                let line_num = line_num_buf.format(line_num);
                self.output_buf.extend_from_slice(line_num.as_bytes());
                if should_print_color {
                    self.output_buf.extend_from_slice(COLOR_RESET.as_bytes());
                }
                self.output_buf.extend_from_slice(b": ");

                let display = truncate_utf8(line, 500);
                let mut last = 0;

                for (s, e) in self.matcher.find_matches(line) {
                    if s >= display.len() { break; }

                    let e = e.min(display.len());

                    self.output_buf.extend_from_slice(&display[last..s]);
                    if should_print_color {
                        self.output_buf.extend_from_slice(COLOR_RED.as_bytes());
                    }
                    self.output_buf.extend_from_slice(&display[s..e]);
                    if should_print_color {
                        self.output_buf.extend_from_slice(COLOR_RESET.as_bytes());
                    }
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

        let matcher = match Matcher::new(&cli) {
            Ok(m) => m,
            Err(e) => {
                match e.kind() {
                    io::ErrorKind::InvalidInput => {
                        eprintln_red!("error: invalid pattern '{pattern}'", pattern = cli.pattern);
                        eprintln_red!("help: patterns must be valid regex or a literal/alternation extractable form");
                        eprintln_red!("tip: test your regex with `grep -E` or a regex tester before running");
                    }
                    io::ErrorKind::NotFound => {
                        // unlikely for this constructor, but here for completeness
                        eprintln_red!("error: referenced something that wasn't found: {e}");
                    }
                    _ => {
                        eprintln_red!("error: failed to build matcher: {e}");
                    }
                }

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

        unsafe {
            // MADV_SEQUENTIAL: Tell kernel we're reading sequentially
            // This makes kernel do aggressive readahead and drop pages behind us
            libc::madvise(
                device_mmap.as_ptr() as *mut _,
                device_mmap.len(),
                libc::MADV_SEQUENTIAL,
            );

            // MADV_WILLNEED on first chunk to start prefetching immediately
            // Prefetch first 256MB to get started
            // @Constant
            let prefetch_size = (256 * 1024 * 1024).min(device_mmap.len());
            libc::madvise(
                device_mmap.as_ptr() as *mut _,
                prefetch_size,
                libc::MADV_WILLNEED,
            );
        }

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
            sb,
            cli,
            matcher,
            device_mmap,
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
    ) -> io::Result<(Cli, Stats)> {
        let device_mmap = &self.device_mmap;
        let matcher = &self.matcher;
        let stats = &ParallelStats::new();

        let root_gi = root_gitignore.map(Arc::new);

        let active_workers = &AtomicUsize::new(0);
        let quit_now = &AtomicBool::new(false);

        let (output_tx, output_rx) = unbounded();

        let injector = &Injector::new();
        injector.push(WorkItem::Directory(DirWork {
            inode_num: root_inode,
            path_bytes: Arc::default(),
            gitignore: root_gi,
            depth: 0,
        }));

        let threads = self.cli.threads.get().min(12);

        let workers = (0..threads)
            .map(|_| DequeWorker::new_lifo())
            .collect::<Vec<_>>();

        let stealers = workers
            .iter()
            .map(|w| w.stealer())
            .collect::<Vec<_>>();

        self.warmup_filesystem();

        std::thread::scope(|s| {
            let output_handle = s.spawn(|| {
                Outputter {
                    rx: output_rx,
                    writer: BufWriter::with_capacity(128 * 1024, io::stdout()),
                }.run();
            });

            let handles = workers.into_iter().enumerate().map(|(worker_id, local_worker)| {
                let stealers = stealers.clone();
                let output_tx = output_tx.clone();
                let sb = &self.sb;
                let cli = &self.cli;

                s.spawn(move || {
                    let mut worker = WorkerContext {
                        worker_id,

                        root_search_directory,
                        device_mmap,
                        sb,
                        cli,
                        matcher,
                        stats,
                        output_tx,

                        file_buf: Vec::new(),
                        dir_buf: Vec::new(),
                        gitignore_buf: Vec::new(),
                        extent_buf: Vec::new(),
                        path_buf: SmallPathBuf::new(),
                        output_buf: Vec::with_capacity(64 * 1024)
                    };

                    worker.init();

                    let mut consecutive_steals = 0;
                    let mut idle_iterations = 0;

                    // @Constant
                    let mut path_display_buf = String::with_capacity(0x1000);

                    loop {
                        if quit_now.load(Ordering::Relaxed) || !running.load(Ordering::Relaxed) {
                            break;
                        }

                        let work = worker.find_work(
                            &local_worker,
                            injector,
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
                                            injector,
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

                                // @Constant
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
        let num_groups = total_size.div_ceil(bytes_per_group) as usize;

        // Prefetch group descriptor table (starts after superblock)
        // @Constant
        let gdt_offset = if block_size == 1024 { 2048 } else { block_size };
        // @Constant
        let gdt_size = (num_groups as u64 * desc_size).min(1024 * 1024); // Cap at 1MB

        // Touch group descriptor table pages
        // @Constant
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

//
// There's a lot of code-repetition down here, and these methods
// are needed in `RawGrepper` ONLY for finding the root inode (from where to start searching).
//
// Two ways to fix that:
//   1. Factor out ext4 parsing logic into some sort of a short-lived struct that reuses the
//      buffers.
//
//   2: Just use the `WorkerContext` instead .. too hacky IMO.
//
// TODO(#2): Eliminate ext4 parsing code-repetition
//

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
                let block_data = this.get_block(block_num);
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

    #[allow(unused)]
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
            core::slice::from_raw_parts(ptr, self.sb.block_size as usize)
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
                    (&*zelf).get_block(child_block)
                };
                self.parse_extent_node(block_data, level + 1)?;
            }
        }

        Ok(())
    }
}
