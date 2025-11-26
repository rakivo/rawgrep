#![cfg_attr(feature = "use_nightly", allow(internal_features))]
#![cfg_attr(feature = "use_nightly", feature(core_intrinsics))]

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod util;
mod binary;
mod matcher;
mod path_buf;
use util::{likely, unlikely};

use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::{self, BufWriter, Write};

use smallvec::{SmallVec, smallvec};
use ignore::gitignore::Gitignore;
use memmap2::{Mmap, MmapOptions};

use crate::binary::{is_binary_chunk, is_binary_ext};
use crate::matcher::Matcher as Matcher;
use crate::path_buf::FixedPathBuf;
use crate::util::{build_gitignore, build_gitignore_from_bytes, display_bytes_into_display_buf, is_common_skip_dir, is_dot_entry, is_gitignored, truncate_utf8, write_int};

const BINARY_CONTROL_COUNT: usize = 51;
const BINARY_PROBE_BYTE_SIZE: usize = 0x1000;

const MAX_DIR_BYTE_SIZE: usize = 16 * 1024 * 1024;
const MAX_FILE_BYTE_SIZE: usize = 5 * 1024 * 1024;

const EXT4_SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_SUPERBLOCK_SIZE: usize = 1024;
const EXT4_SUPER_MAGIC: u16 = 0xEF53;
const EXT4_MAGIC_OFFSET: usize = 56;
const EXT4_INODE_SIZE_OFFSET: usize = 88;
const EXT4_INODES_PER_GROUP_OFFSET: usize = 40;
const EXT4_BLOCKS_PER_GROUP_OFFSET: usize = 32;
const EXT4_BLOCK_SIZE_OFFSET: usize = 24;
const EXT4_INODE_TABLE_OFFSET: usize = 8;
const EXT4_ROOT_INODE: INodeNum = 2;
const EXT4_DESC_SIZE_OFFSET: usize = 254;

const EXT4_INODE_MODE_OFFSET: usize = 0;
const EXT4_INODE_SIZE_OFFSET_LOW: usize = 4;
const EXT4_INODE_BLOCK_OFFSET: usize = 40;
const EXT4_INODE_FLAGS_OFFSET: usize = 32;
const EXT4_S_IFMT: u16 = 0xF000;
const EXT4_S_IFREG: u16 = 0x8000;
const EXT4_S_IFDIR: u16 = 0x4000;
const EXT4_EXTENTS_FL: u32 = 0x80000;

const COLOR_RED: &[u8] = b"\x1b[1;31m";
const COLOR_GREEN: &[u8] = b"\x1b[1;32m";
const COLOR_CYAN: &[u8] = b"\x1b[1;36m";
const COLOR_RESET: &[u8] = b"\x1b[0m";

const CURSOR_HIDE: &[u8] = b"\x1b[?25l";
const CURSOR_UNHIDE: &[u8] = b"\x1b[?25h";

type INodeNum = u32;
type BlockNum = u32;

/// Function used to indicate that we copy some amount of copiable data (bytes) into a newly allocated memory
#[inline(always)]
fn copy_data<A, T>(bytes: &[T]) -> SmallVec<A>
where
    A: smallvec::Array<Item = T>,
    T: Copy
{
    SmallVec::from_slice(bytes)
}

#[derive(Copy, Clone)]
enum BufKind { Content, Dir, Gitignore }

struct DirFrame {
    inode_num: INodeNum,
    parent_len: usize,   // Length of parent path (before this directory)
    name_offset: usize,  // Offset into `dir_name_buf`
    name_len: usize,     // Length of directory name
}

struct GitignoreFrame { matcher: Gitignore }

pub struct BatchWriter {
    writer: BufWriter<io::Stdout>,
}

impl BatchWriter {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            // 256KB buffer - reduces syscalls dramatically
            writer: BufWriter::with_capacity(256 * 1024, io::stdout()),
        }
    }

    #[inline(always)]
    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(data)
    }

    #[inline(always)]
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[derive(Debug)]
struct Ext4SuperBlock {
    block_size: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    desc_size: u16,
}

impl Display for Ext4SuperBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Block size: {} bytes", self.block_size)?;
        writeln!(f, "Blocks per group: {}", self.blocks_per_group)?;
        writeln!(f, "Inodes per group: {}", self.inodes_per_group)?;
        writeln!(f, "Inode size: {} bytes", self.inode_size)?;
        write!  (f, "Descriptor size: {} bytes\n", self.desc_size)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct Ext4Inode {
    mode: u16,
    size: u64,
    flags: u32,
    blocks: [BlockNum; 15],
}

#[derive(Debug, Clone, Copy)]
struct Ext4Extent {
    start_lo: u32,
    len: u16,
}

#[derive(Default)]
struct Stats {
    files_searched: usize,
    files_contained_matches: usize,
    files_skipped_large: usize,
    files_skipped_unreadable: usize,
    files_skipped_as_binary_due_to_ext: usize,
    files_skipped_as_binary_due_to_probe: usize,
    files_skipped_gitignore: usize,

    dirs_skipped_common: usize,
    dirs_skipped_gitignore: usize,
    dirs_parsed: usize,
}

impl Stats {
    pub fn print(&self) {
        let total_files = self.files_searched;

        let total_dirs = self.dirs_parsed
            + self.dirs_skipped_common
            + self.dirs_skipped_gitignore;

        eprintln!("\n\x1b[1;32mSearch complete\x1b[0m");

        eprintln!("\x1b[1;34mFiles Summary:\x1b[0m");
        macro_rules! file_row {
            ($label:expr, $count:expr) => {
                let pct = if total_files == 0 { 0.0 } else { ($count as f64 / total_files as f64) * 100.0 };
                eprintln!("  {:<25} {:>8} ({:>5.1}%)", $label, $count, pct);
            };
        }

        file_row!("Files searched", self.files_searched);
        file_row!("Files contained matches", self.files_contained_matches);
        file_row!("Skipped (large)", self.files_skipped_large);
        file_row!("Skipped (binary ext)", self.files_skipped_as_binary_due_to_ext);
        file_row!("Skipped (binary probe)", self.files_skipped_as_binary_due_to_probe);
        file_row!("Skipped (unreadable)", self.files_skipped_unreadable);
        file_row!("Skipped (gitignore)", self.files_skipped_gitignore);

        eprintln!("\n\x1b[1;34mDirectories Summary:\x1b[0m");
        macro_rules! dir_row {
            ($label:expr, $count:expr) => {
                let pct = if total_dirs == 0 { 0.0 } else { ($count as f64 / total_dirs as f64) * 100.0 };
                eprintln!("  {:<25} {:>8} ({:>5.1}%)", $label, $count, pct);
            };
        }

        dir_row!("Dirs parsed", self.dirs_parsed);
        dir_row!("Skipped (common)", self.dirs_skipped_common);
        dir_row!("Skipped (gitignore)", self.dirs_skipped_gitignore);
    }
}

struct RawGrepper {
    device_mmap: Mmap,
    superblock: Ext4SuperBlock,

    stats: Stats,

    // ----- reused buffers
       extent_buf: Vec<Ext4Extent>,
       output_buf: Vec<u8>,
      content_buf: Vec<u8>,
          dir_buf: Vec<u8>,
    gitignore_buf: Vec<u8>,
}

impl RawGrepper {
    fn new(device_path: &str) -> io::Result<Self> {
        fn device_size(fd: &File) -> io::Result<u64> {
            const BLKGETSIZE64: libc::c_ulong = 0x80081272;

            let mut size: u64 = 0;
            let res = unsafe {
                libc::ioctl(fd.as_raw_fd(), BLKGETSIZE64, &mut size)
            };

            if res < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(size)
        }

        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(device_path)?;

        let size = device_size(&file)?;
        let mmap = unsafe {
            MmapOptions::new()
                .offset(0)
                .len(size as _)
                .map(&file)?
        };

        #[cfg(unix)]
        unsafe {
            libc::madvise(
                mmap.as_ptr() as *mut _,
                mmap.len(),
                libc::MADV_SEQUENTIAL | libc::MADV_WILLNEED
            );
        }

        let sb_bytes = &mmap[
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
                format!("Not an ext4 filesystem")
            ));
        }

        let superblock = Self::parse_superblock(sb_bytes)?;

        Ok(RawGrepper {
            device_mmap: mmap,
            superblock,
            stats: Stats::default(),
            dir_buf: Vec::with_capacity(256 * 1024),      // 256 KB for directories
            content_buf: Vec::with_capacity(1024 * 1024), // 1 MB for file content
            gitignore_buf: Vec::with_capacity(64 * 1024), // 64 KB for .gitignore
            extent_buf: Vec::with_capacity(256),
            output_buf: Vec::with_capacity(64 * 1024),
        })
    }

    #[inline(always)]
    const fn get_buf(&self, kind: BufKind) -> &Vec<u8> {
        match kind {
            BufKind::Content   => &self.content_buf,
            BufKind::Dir       => &self.dir_buf,
            BufKind::Gitignore => &self.gitignore_buf,
        }
    }

    #[inline(always)]
    const fn get_buf_mut(&mut self, kind: BufKind) -> &mut Vec<u8> {
        match kind {
            BufKind::Content   => &mut self.content_buf,
            BufKind::Dir       => &mut self.dir_buf,
            BufKind::Gitignore => &mut self.gitignore_buf,
        }
    }

    #[inline]
    fn probe_is_binary(&mut self, inode: &Ext4Inode) -> bool {
        let file_size = inode.size as usize;
        if file_size == 0 {
            return false;
        }

        let bytes_to_check = file_size.min(BINARY_PROBE_BYTE_SIZE);

        if inode.flags & EXT4_EXTENTS_FL != 0 {
            if self.parse_extents(inode).is_ok() {
                if let Some(extent) = self.extent_buf.first() {
                    let block = self.get_block(extent.start_lo);
                    let first_block_file_bytes = file_size.min(block.len());
                    let to_check = first_block_file_bytes.min(bytes_to_check);
                    return is_binary_chunk(&block[..to_check]);
                }
            }
        } else {
            for &block_num in inode.blocks.iter().take(12) {
                if block_num != 0 {
                    let block = self.get_block(block_num);
                    let first_block_file_bytes = file_size.min(block.len());
                    let to_check = first_block_file_bytes.min(bytes_to_check);
                    return is_binary_chunk(&block[..to_check]);
                }
            }
        }

        false
    }

    /// Resolve a path like "/usr/bin" or "etc" into an inode number.
    /// @Note: Clobbers into `dir_buf`
    fn try_resolve_path_to_inode(&mut self, path: &str) -> io::Result<INodeNum> {
        let mut inode_num = EXT4_ROOT_INODE;
        if path == "/" || path.is_empty() {
            return Ok(inode_num);
        }

        for part in path.split('/').filter(|p| !p.is_empty()) {
            let inode = self.read_inode(inode_num)?;
            if inode.mode & EXT4_S_IFMT != EXT4_S_IFDIR {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{path} is not a directory"),
                ));
            }

            let dir_size = (inode.size as usize).min(MAX_DIR_BYTE_SIZE);
            self.read_file_into_buf(&inode, dir_size, BufKind::Dir)?;

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

    #[inline]
    fn parse_superblock(data: &[u8]) -> io::Result<Ext4SuperBlock> {
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

    // @Hot
    #[inline(always)]
    fn get_block(&self, block_num: BlockNum) -> &[u8] {
        let offset = (block_num as usize).wrapping_mul(self.superblock.block_size as usize);
        debug_assert!(
            self.device_mmap
                .get(offset..offset + self.superblock.block_size as usize)
                .is_some()
        );
        unsafe {
            let ptr = self.device_mmap.as_ptr().add(offset);
            std::slice::from_raw_parts(ptr, self.superblock.block_size as usize)
        }
    }

    #[cfg(unix)]
    #[inline(always)]
    fn prefetch_blocks(&self, blocks: &[BlockNum]) {
        if blocks.is_empty() {
            return;
        }

        let mut sorted: SmallVec<[BlockNum; 16]> = copy_data(blocks);
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

    #[cfg(unix)]
    #[inline]
    fn advise_range(&self, start_block: BlockNum, end_block: BlockNum) {
        let offset = start_block as usize * self.superblock.block_size as usize;
        let length = (end_block - start_block + 1) as usize * self.superblock.block_size as usize;

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

    #[inline]
    fn read_inode(&mut self, inode_num: INodeNum) -> io::Result<Ext4Inode> {
        if unlikely(inode_num == 0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid inode number 0"));
        }

        let group = (inode_num - 1) / self.superblock.inodes_per_group;
        let index = (inode_num - 1) % self.superblock.inodes_per_group;

        let bg_desc_offset = if self.superblock.block_size == 1024 {
            2048
        } else {
            self.superblock.block_size as usize
        } + (group as usize * self.superblock.desc_size as usize);

        let bg_desc = &self.device_mmap[
            bg_desc_offset..
            bg_desc_offset + self.superblock.desc_size as usize
        ];

        let inode_table_block = BlockNum::from_le_bytes([
            bg_desc[EXT4_INODE_TABLE_OFFSET + 0],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 1],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 2],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 3],
        ]);

        let inode_offset = inode_table_block as usize *
            self.superblock.block_size as usize +
            index as usize *
            self.superblock.inode_size as usize;

        let inode_bytes = &self.device_mmap[
            inode_offset..
            inode_offset + self.superblock.inode_size as usize
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

        let flags = u32::from_le_bytes([
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 0],
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 1],
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 2],
            inode_bytes[EXT4_INODE_FLAGS_OFFSET + 3],
        ]);

        let mut blocks = [0; 15];
        for (i, block) in blocks.iter_mut().enumerate() {
            let offset = EXT4_INODE_BLOCK_OFFSET + i * 4;
            *block = BlockNum::from_le_bytes([
                inode_bytes[offset + 0],
                inode_bytes[offset + 1],
                inode_bytes[offset + 2],
                inode_bytes[offset + 3],
            ]);
        }

        Ok(Ext4Inode { mode, size: size_low as u64, flags, blocks })
    }

    #[inline]
    fn parse_extents(&mut self, inode: &Ext4Inode) -> io::Result<()> {
        self.extent_buf.clear();

        let mut block_bytes: SmallVec<[u8; 64]> = smallvec![0; 60];
        for (i, bytes) in inode.blocks.into_iter().map(BlockNum::to_le_bytes).enumerate() {
            block_bytes[i * 4 + 0] = bytes[0];
            block_bytes[i * 4 + 1] = bytes[1];
            block_bytes[i * 4 + 2] = bytes[2];
            block_bytes[i * 4 + 3] = bytes[3];
        }

        self.parse_extent_node(&block_bytes, 0)?;
        Ok(())
    }

    fn parse_extent_node(&mut self, data: &[u8], level: usize) -> io::Result<()> {
        if data.len() < 12 {
            return Ok(());
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != 0xF30A {
            return Ok(());
        }

        let entries = u16::from_le_bytes([data[2], data[3]]);
        let depth = u16::from_le_bytes([data[6], data[7]]);

        if depth == 0 {
            // -------- Leaf node
            for i in 0..entries {
                let base = 12 + (i as usize * 12);
                if base + 12 > data.len() {
                    break;
                }

                let ee_len = u16::from_le_bytes([data[base + 4], data[base + 5]]);
                let ee_start_hi = u16::from_le_bytes([data[base + 6], data[base + 7]]);
                let ee_start_lo = u32::from_le_bytes([
                    data[base + 08],
                    data[base + 09],
                    data[base + 10],
                    data[base + 11]
                ]);

                let start_block = ((ee_start_hi as u64) << 32) | (ee_start_lo as u64);

                if ee_len > 0 && ee_len <= 32768 {
                    self.extent_buf.push(Ext4Extent {
                        start_lo: start_block as BlockNum,
                        len: ee_len,
                    });
                }
            }
        } else {
            // -------- Internal node - collect block numbers first
            let mut child_blocks = SmallVec::<[BlockNum; 16]>::new();
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
                child_blocks.push(leaf_block as BlockNum);
            }

            #[cfg(unix)]
            self.prefetch_blocks(&child_blocks);

            for child_block in child_blocks {
                let block_data = self.get_block(child_block);
                let block_copy: SmallVec<[u8; 4096]> = copy_data(block_data);
                self.parse_extent_node(&block_copy, level + 1)?;
            }
        }

        Ok(())
    }

    pub fn search(
        &mut self,
        root_inode: INodeNum,
        path: &mut FixedPathBuf,
        path_display_buf: &mut String,
        matcher: &Matcher,
        writer: &mut BatchWriter,
        running: &Arc<AtomicBool>,
        root_gitignore: Gitignore,
    ) -> io::Result<()> {
        let mut dir_stack = Vec::with_capacity(1024);
        let mut gi_stack = Vec::with_capacity(64);
        // TODO: Move dir_name_buf and path_display_buf into `RawGrepper`
        let mut dir_name_buf = Vec::with_capacity(4096); // Shared buffer for all directory names

        dir_stack.push(DirFrame {
            inode_num: root_inode,
            parent_len: path.len(),
            name_offset: 0,
            name_len: 0, // Root has no name to add
        });
        gi_stack.push(GitignoreFrame { matcher: root_gitignore });

        while let Some(frame) = dir_stack.pop() {
            if unlikely(!running.load(Ordering::Relaxed)) {
                break;
            }

            path.truncate(frame.parent_len);
            if frame.name_len > 0 {
                if likely(frame.parent_len > 0)
                    && path.as_bytes().get(frame.parent_len - 1) != Some(&b'/')
                {
                    path.push(b'/');
                }
                let name = &dir_name_buf[
                    frame.name_offset..
                    frame.name_offset + frame.name_len
                ];
                path.extend_from_slice(name);
            }

            let Ok(inode) = self.read_inode(frame.inode_num) else {
                continue;
            };

            if unlikely((inode.mode & EXT4_S_IFMT) != EXT4_S_IFDIR) {
                continue;
            }

            let last_segment = match path.as_bytes().iter().rposition(|&b| b == b'/') {
                Some(pos) => &path.as_bytes()[pos + 1..],
                None => path.as_bytes(),
            };
            if is_common_skip_dir(last_segment) {
                self.stats.dirs_skipped_common += 1;
                continue;
            }

            display_bytes_into_display_buf(path_display_buf, path.as_bytes());
            if is_gitignored(&gi_stack, path_display_buf.as_ref(), true) {
                self.stats.dirs_skipped_gitignore += 1;
                continue;
            }

            if self.process_directory(
                &inode,
                path,
                path_display_buf,
                matcher,
                writer,
                &mut dir_stack,
                &mut gi_stack,
                path.len(),
                &mut dir_name_buf
            ).is_err() {
                continue;
            }
        }

        Ok(())
    }

    #[inline]
    fn process_directory(
        &mut self,
        inode: &Ext4Inode,
        path: &mut FixedPathBuf,
        path_display_buf: &mut String,
        matcher: &Matcher,
        writer: &mut BatchWriter,
        dir_stack: &mut Vec<DirFrame>,
        gi_stack: &mut Vec<GitignoreFrame>,
        current_dir_path_len: usize,
        dir_name_buf: &mut Vec<u8>,
    ) -> io::Result<()> {
        let dir_size = (inode.size as usize).min(MAX_DIR_BYTE_SIZE);
        self.read_file_into_buf(inode, dir_size, BufKind::Dir)?;
        self.stats.dirs_parsed += 1;

        // ------------- Quick scan for .gitignore
        let gitignore_inode = self.find_gitignore_inode_in_buf(BufKind::Dir);

        // ------------- Load .gitignore if found
        let pushed_gi = if let Some(gi_inode_num) = gitignore_inode {
            self.load_gitignore(gi_inode_num, path_display_buf, gi_stack)
        } else {
            false
        };

        // ------------- Process all entries
        let mut offset = 0;
        while offset + 8 <= self.dir_buf.len() {
            let entry_inode = INodeNum::from_le_bytes([
                self.dir_buf[offset + 0],
                self.dir_buf[offset + 1],
                self.dir_buf[offset + 2],
                self.dir_buf[offset + 3],
            ]);
            let rec_len = u16::from_le_bytes([self.dir_buf[offset + 4], self.dir_buf[offset + 5]]);
            let name_len = self.dir_buf[offset + 6];

            if unlikely(rec_len == 0) { break; }

            let rec_len_usize = rec_len as usize;

            if unlikely(offset + rec_len_usize > self.dir_buf.len()) { break; }

            if likely(entry_inode != 0 && name_len > 0) {
                let name_end = offset + 8 + name_len as usize;
                if likely(name_end <= offset + rec_len_usize) {
                    let name_bytes = &self.dir_buf[offset + 8..name_end];

                    // reject . and ..
                    if unlikely(is_dot_entry(name_bytes)) {
                        offset += rec_len_usize;
                        continue;
                    }

                    let name_bytes_copy: SmallVec::<[_; 256]> = copy_data(
                        &self.dir_buf[offset + 8..name_end]
                    );

                    self.process_entry(
                        entry_inode,
                        &name_bytes_copy,
                        path,
                        path_display_buf,
                        matcher,
                        writer,
                        dir_stack,
                        gi_stack,
                        current_dir_path_len,
                        dir_name_buf,
                    )?;
                }
            }

            offset += rec_len_usize;
        }

        if pushed_gi {
            gi_stack.pop();
        }

        Ok(())
    }

    #[inline]
    fn process_entry(
        &mut self,
        entry_inode: INodeNum,
        name: &[u8],
        path: &mut FixedPathBuf,
        path_display_buf: &mut String,
        matcher: &Matcher,
        writer: &mut BatchWriter,
        dir_stack: &mut Vec<DirFrame>,
        gi_stack: &[GitignoreFrame],
        current_dir_path_len: usize,
        dir_name_buf: &mut Vec<u8>,
    ) -> io::Result<()> {
        if is_common_skip_dir(name) {
            self.stats.dirs_skipped_common += 1;
            return Ok(());
        }

        // ------ Ensure we start from the current directory path
        path.truncate(current_dir_path_len);

        // ------ Build the full path: current_dir + '/' + name
        if likely(current_dir_path_len > 0)
            && path.as_bytes().get(current_dir_path_len - 1) != Some(&b'/')
        {
            path.push(b'/');
        }
        path.extend_from_slice(name);

        let Ok(child_inode) = self.read_inode(entry_inode) else {
            path.truncate(current_dir_path_len);
            return Ok(());
        };

        let ft = child_inode.mode & EXT4_S_IFMT;

        if ft == EXT4_S_IFDIR {
            // ------ Store directory name in shared buffer
            let name_offset = dir_name_buf.len();
            dir_name_buf.extend_from_slice(name);
            let name_len = name.len();

            // ----- For directories: push with name stored in buffer
            dir_stack.push(DirFrame {
                inode_num: entry_inode,
                parent_len: current_dir_path_len, // parent path length (before this dir)
                name_offset,
                name_len,
            });
        } else if likely(ft == EXT4_S_IFREG) {
            // ----- For files: path now contains the full path including filename
            self.process_file(
                &child_inode,
                name,
                path.as_bytes(),
                path_display_buf,
                matcher,
                writer,
                gi_stack,
            )?;
        }

        path.truncate(current_dir_path_len);

        Ok(())
    }

    #[inline]
    fn process_file(
        &mut self,
        child_inode: &Ext4Inode,
        name: &[u8],
        path_bytes: &[u8],
        path_display_buf: &mut String,
        matcher: &Matcher,
        writer: &mut BatchWriter,
        gi_stack: &[GitignoreFrame],
    ) -> io::Result<()> {
        // -------------------- Rejection by size
        if unlikely(child_inode.size > MAX_FILE_BYTE_SIZE as u64) {
            self.stats.files_skipped_large += 1;
            return Ok(());
        }

        // -------------------- Rejection by extension
        if is_binary_ext(name) {
            self.stats.files_skipped_as_binary_due_to_ext += 1;
            return Ok(());
        }

        // -------------------- Build display path
        // path_bytes contains the full path including filename
        display_bytes_into_display_buf(path_display_buf, path_bytes);

        // -------------------- Rejection by .gitignore
        if is_gitignored(gi_stack, path_display_buf.as_ref(), false) {
            self.stats.files_skipped_gitignore += 1;
            return Ok(());
        }

        // -------------------- Rejection by a binary probe
        if self.probe_is_binary(child_inode) {
            self.stats.files_skipped_as_binary_due_to_probe += 1;
            return Ok(());
        }

        let size = (child_inode.size as usize).min(MAX_FILE_BYTE_SIZE);
        if likely(self.read_file_into_buf(child_inode, size, BufKind::Content).is_ok()) {
            self.stats.files_searched += 1;
            self.find_and_print_matches(matcher, path_display_buf, writer)?;
        } else {
            self.stats.files_skipped_unreadable += 1;
        }

        Ok(())
    }

    #[inline]
    fn load_gitignore(
        &mut self,
        gi_inode_num: INodeNum,
        path_display_buf: &str,
        gi_stack: &mut Vec<GitignoreFrame>,
    ) -> bool {
        if let Ok(gi_inode) = self.read_inode(gi_inode_num) {
            let size = (gi_inode.size as usize).min(MAX_FILE_BYTE_SIZE);
            if self.read_file_into_buf(&gi_inode, size, BufKind::Gitignore).is_ok() {
                let matcher = build_gitignore_from_bytes(
                    path_display_buf.as_ref(),
                    &self.gitignore_buf,
                );
                gi_stack.push(GitignoreFrame { matcher });
                return true;
            }
        }
        false
    }

    fn read_file_into_buf(
        &mut self,
        inode: &Ext4Inode,
        max_size: usize,
        kind: BufKind
    ) -> io::Result<()> {
        self.get_buf_mut(kind).clear();
        let size_to_read = (inode.size as usize).min(max_size);
        self.get_buf_mut(kind).reserve(size_to_read);

        let mut temp_buf: SmallVec<[u8; 4096]> = SmallVec::new();

        if inode.flags & EXT4_EXTENTS_FL != 0 {
            self.parse_extents(inode)?;
            let extents = self.extent_buf.clone();

            #[cfg(unix)]
            {
                let mut blocks_to_prefetch = SmallVec::<[_; 16]>::with_capacity(extents.len() * 4);
                for extent in &extents {
                    for i in 0..extent.len {
                        blocks_to_prefetch.push(extent.start_lo + i as BlockNum);
                    }
                }
                self.prefetch_blocks(&blocks_to_prefetch);
            }

            for extent in &extents {
                if self.get_buf(kind).len() >= size_to_read {
                    break;
                }

                for i in 0..extent.len {
                    if self.get_buf(kind).len() >= size_to_read {
                        break;
                    }

                    let phys_block = extent.start_lo + i as BlockNum;

                    {
                        let block_data = self.get_block(phys_block);
                        let remaining = size_to_read - self.get_buf(kind).len();
                        let to_read = block_data.len().min(remaining);

                        temp_buf.clear();
                        temp_buf.extend_from_slice(&block_data[..to_read]);
                    }

                    self.get_buf_mut(kind).extend_from_slice(&temp_buf);
                }
            }
        } else {
            // Direct blocks
            #[cfg(unix)]
            {
                let mut blocks_to_prefetch = SmallVec::<[_; 12]>::with_capacity(12);
                for i in 0..12 {
                    if inode.blocks[i] != 0 {
                        blocks_to_prefetch.push(inode.blocks[i]);
                    }
                }
                self.prefetch_blocks(&blocks_to_prefetch);
            }

            for i in 0..12 {
                if self.get_buf(kind).len() >= size_to_read {
                    break;
                }

                let block = inode.blocks[i];
                if block == 0 {
                    continue;
                }

                {
                    let block_data = self.get_block(block);
                    let remaining = size_to_read - self.get_buf(kind).len();
                    let to_read = block_data.len().min(remaining);

                    temp_buf.clear();
                    temp_buf.extend_from_slice(&block_data[..to_read]);
                }

                self.get_buf_mut(kind).extend_from_slice(&temp_buf);
            }
        }

        self.get_buf_mut(kind).truncate(size_to_read);
        Ok(())
    }

    #[inline]
    fn find_gitignore_inode_in_buf(&self, kind: BufKind) -> Option<INodeNum> {
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

            // Quick check: .gitignore is exactly 10 bytes
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

    #[inline]
    pub fn find_and_print_matches(
        &mut self,
        matcher: &Matcher,
        path: &str,
        writer: &mut BatchWriter,
    ) -> io::Result<()> {
        let buf = &self.content_buf;

        if unlikely(!matcher.is_match(buf)) {
            return Ok(());
        }

        self.output_buf.clear();
        let mut found_any = false;

        let mut line_start = 0;
        let mut line_num = 1;

        let buf_len = buf.len();

        for nl in memchr::memchr_iter(b'\n', buf).chain(std::iter::once(buf_len)) {
            let line = if nl == buf_len && line_start < buf_len {
                &buf[line_start..]
            } else if nl == buf_len {
                break; // No last line to process
            } else {
                &buf[line_start..nl]
            };

            if likely(matcher.is_match(line)) {
                if unlikely(!found_any) {
                    self.output_buf.extend_from_slice(COLOR_GREEN);
                    self.output_buf.extend_from_slice(path.as_bytes());
                    self.output_buf.extend_from_slice(COLOR_RESET);
                    self.output_buf.extend_from_slice(b":\n");
                    found_any = true;
                }

                self.output_buf.extend_from_slice(COLOR_CYAN);
                write_int(&mut self.output_buf, line_num);
                self.output_buf.extend_from_slice(COLOR_RESET);
                self.output_buf.extend_from_slice(b": ");

                let display = truncate_utf8(line, 500);

                let mut last = 0;
                for (s, e) in matcher.find_matches(line) {
                    if unlikely(s >= display.len()) {
                        break;
                    }
                    let e = e.min(display.len());

                    self.output_buf.extend_from_slice(&display[last..s]);
                    self.output_buf.extend_from_slice(COLOR_RED);
                    self.output_buf.extend_from_slice(&display[s..e]);
                    self.output_buf.extend_from_slice(COLOR_RESET);
                    last = e;
                }

                self.output_buf.extend_from_slice(&display[last..]);
                self.output_buf.push(b'\n');

                if unlikely(self.output_buf.len() > 64 * 1024) {
                    writer.write(&self.output_buf)?;
                    self.output_buf.clear();
                }
            }

            line_start = nl + 1;
            line_num += 1;
        }

        if likely(found_any) {
            writer.write(&self.output_buf)?;
            writer.flush()?;

            self.stats.files_contained_matches += 1;
        }

        Ok(())
    }
}

fn setup_signal_handler() -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
        {
            let mut handle = io::stdout().lock();
            _ = handle.write_all(CURSOR_UNHIDE);
        }
        _ = io::stdout().flush();
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    running
}

struct CursorHide;

impl CursorHide {
    fn new() -> io::Result<Self> {
        io::stdout().lock().write_all(CURSOR_HIDE)?;
        io::stdout().flush()?;
        Ok(CursorHide)
    }
}

impl Drop for CursorHide {
    fn drop(&mut self) {
        _ = io::stdout().lock().write_all(CURSOR_UNHIDE);
        _ = io::stdout().flush();
    }
}

fn main() -> io::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() < 4 {
        eprintln!("usage: {} <device> <dir_path> <pattern>", args[0]);
        eprintln!("example: {} /dev/sda1 'error|warning'", args[0]);
        eprintln!("note: Requires root/sudo to read raw devices");
        std::process::exit(1);
    }

    let device   = &args[1];
    let pattern  = &args[3];
    let dir_path = &args[2];

    let dir_path = match std::fs::canonicalize(dir_path) {
        Ok(ok) => ok,
        Err(e) => {
            eprintln!("error: couldn't canonicalize '{dir_path}': {e}");
            std::process::exit(1);
        }
    };
    let dir_path = dir_path.to_string_lossy();
    let dir_path = dir_path.as_ref();

    // TODO: Detect the partition automatically
    let mut reader = match RawGrepper::new(device) {
        Ok(ok) => ok,
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    eprintln!("error: device or partition not found: '{device}'");
                }
                std::io::ErrorKind::PermissionDenied => {
                    eprintln!("error: permission denied. Try running with sudo/root to read raw devices.");
                }
                std::io::ErrorKind::InvalidData => {
                    eprintln!("error: invalid ext4 filesystem on this path: {e}");
                    eprintln!("help: make sure the path points to a partition (e.g., /dev/sda1) and not a whole disk (e.g., /dev/sda)");
                    eprintln!("tip: try running `df -Th /` to find your root partition");
                }
                _ => {
                    eprintln!("error: failed to initialize ext4 reader: {e}");
                }
            }

            std::process::exit(1);
        }
    };

    eprintln!("\x1b[1;36mSearching\x1b[0m '{device}' for pattern: \x1b[1;31m'{pattern}'\x1b[0m\n");

    let _cur = CursorHide::new();

    let start_inode = match reader.try_resolve_path_to_inode(&dir_path) {
        Ok(ok) => ok,
        Err(e) => {
            eprintln!("error: couldn't find {dir_path} in {device}: {e}");
            std::process::exit(1);
        }
    };

    let mut path = FixedPathBuf::from_bytes(dir_path.as_bytes());
    let matcher = Matcher::new(&pattern)?;
    let mut writer = BatchWriter::new();
    let running = setup_signal_handler();
    let gitignore = build_gitignore(dir_path.as_ref());
    reader.search(
        start_inode,
        &mut path,
        &mut dir_path.to_string(),
        &matcher,
        &mut writer,
        &running,
        gitignore
    )?;

    reader.stats.print();

    Ok(())
}
