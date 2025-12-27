use std::borrow::Cow;
use std::{io, mem};

use memmap2::Mmap;
use smallvec::SmallVec;

use crate::binary::is_binary_chunk;
use crate::worker::{BINARY_PROBE_BYTE_SIZE, MAX_EXTENTS_UNTIL_SPILL};
use crate::{copy_data, tracy};
use crate::cli::BufferConfig;
use crate::ext4::{
    raw,
    Ext4Extent,
    Ext4Inode,
    Ext4SuperBlock,
    INodeNum,
    EXT4_BLOCKS_PER_GROUP_OFFSET,
    EXT4_BLOCK_POINTERS_COUNT,
    EXT4_BLOCK_SIZE_OFFSET,
    EXT4_DESC_SIZE_OFFSET,
    EXT4_EXTENTS_FL,
    EXT4_EXTENT_MAGIC,
    EXT4_INODES_PER_GROUP_OFFSET,
    EXT4_INODE_SIZE_OFFSET,
    EXT4_INODE_TABLE_OFFSET,
};
use crate::util::{likely, unlikely};

pub struct Ext4Context<'a> {
    pub device_mmap: &'a Mmap,
    pub sb: &'a Ext4SuperBlock,
    pub device_id: u64,
}

#[derive(Copy, Clone)]
pub enum BufKind {
    Dir,
    File,
    Gitignore
}

#[derive(Copy, Clone)]
pub struct BufFatPtr {
    pub offset: u32, // Offset into the buffer
    pub len: u32,
    pub kind: BufKind
}

#[derive(Default)]
pub struct Parser {
    pub file: Vec<u8>,
    pub dir: Vec<u8>,
    pub gitignore: Vec<u8>,
    pub extents: Vec<Ext4Extent>,
    pub output: Vec<u8>,
}

impl Parser {
    #[inline]
    pub fn init(&mut self, config: &BufferConfig) {
        self.dir.reserve(config.dir_buf);
        self.file.reserve(config.file_buf);
        self.output.reserve(config.output_buf);
        self.gitignore.reserve(config.gitignore_buf);
        self.extents.reserve(config.extent_buf);
    }

    /// Find an entry by name in the current dir_buf contents.
    /// Returns the inode number if found.
    pub fn find_entry_inode(&self, name: &[u8]) -> Option<INodeNum> {
        let mut offset = 0;

        while offset + 8 <= self.dir.len() {
            let entry_inode = INodeNum::from_le_bytes([
                self.dir[offset + 0],
                self.dir[offset + 1],
                self.dir[offset + 2],
                self.dir[offset + 3],
            ]);
            let rec_len = u16::from_le_bytes([
                self.dir[offset + 4],
                self.dir[offset + 5],
            ]);
            let name_len = self.dir[offset + 6];

            if rec_len == 0 {
                break;
            }

            if entry_inode != 0 && name_len > 0 {
                let name_end = offset + 8 + name_len as usize;
                if name_end <= offset + rec_len as usize && name_end <= self.dir.len() {
                    if &self.dir[offset + 8..name_end] == name {
                        return Some(entry_inode);
                    }
                }
            }

            offset += rec_len as usize;
        }

        None
    }

    #[inline]
    pub fn read_file_into_buf(
        &mut self,
        inode: &Ext4Inode,
        max_size: usize,
        kind: BufKind,
        check_and_stop_if_binary: bool,
        ext4: &Ext4Context
    ) -> io::Result<bool> {
        let _span = tracy::span!("WorkerContext::read_file_into_buf");

        let buf = self.get_buf_mut(kind);
        buf.clear();

        let file_size = inode.size as usize;
        let size_to_read = file_size.min(max_size);
        buf.reserve(size_to_read);

        if inode.flags & EXT4_EXTENTS_FL != 0 {
            self.read_extents(inode, size_to_read, file_size, kind, check_and_stop_if_binary, ext4)
        } else {
            self.read_direct_blocks(inode, size_to_read, file_size, kind, check_and_stop_if_binary, ext4)
        }
    }

    #[inline]
    pub fn parse_extents(
        &mut self,
        inode: &Ext4Inode,
        ext4: &Ext4Context,
    ) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::parse_extents");

        self.extents.clear();
        let block_bytes = bytemuck::cast_slice(&inode.blocks);
        self.parse_extent_node(block_bytes, 0, ext4)?;

        Ok(())
    }

    pub fn parse_extent_node(
        &mut self,
        data: &[u8],
        level: usize,
        ext4: &Ext4Context,
    ) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::parse_extent_node");

        if likely(data.len() < mem::size_of::<raw::Ext4ExtentHeader>()) {
            return Ok(());
        }

        let header = bytemuck::try_from_bytes::<raw::Ext4ExtentHeader>(
            &data[..mem::size_of::<raw::Ext4ExtentHeader>()]
        ).map_err(|_| io::Error::new(
            io::ErrorKind::InvalidData, "Invalid extent header"
        ))?;

        if likely(u16::from_le(header.eh_magic) != EXT4_EXTENT_MAGIC) {
            return Ok(());
        }

        let entries = u16::from_le(header.eh_entries);
        let depth = u16::from_le(header.eh_depth);

        if depth == 0 {
            // Leaf node
            self.extents.reserve(entries as usize);

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
                if likely(ee_len > 0 && ee_len <= 32768) { // @Constant
                    self.extents.push(Ext4Extent {
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

            Self::prefetch_blocks(Cow::Borrowed(&child_blocks), ext4);

            for child_block in child_blocks {
                let block_data = Self::get_block(child_block, ext4);
                self.parse_extent_node(block_data, level + 1, ext4)?;
            }
        }

        Ok(())
    }

    pub fn parse_inode(inode_num: INodeNum, ext4: &Ext4Context) -> io::Result<Ext4Inode> {
        let _span = tracy::span!("WorkerContext::parse_inode");

        if unlikely(inode_num == 0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid inode number 0"
            ));
        }

        let group = (inode_num - 1) / ext4.sb.inodes_per_group;
        let index = (inode_num - 1) % ext4.sb.inodes_per_group;

        // @Refactor
        let bg_desc_offset = if ext4.sb.block_size == 1024 {
            2048
        } else {
            ext4.sb.block_size as usize
        } + (group as usize * ext4.sb.desc_size as usize);

        let bg_desc = &ext4.device_mmap[
            bg_desc_offset..
            bg_desc_offset + ext4.sb.desc_size as usize
        ];

        let inode_table_block = u32::from_le_bytes([
            bg_desc[EXT4_INODE_TABLE_OFFSET + 0],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 1],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 2],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 3],
        ]);

        let inode_offset = inode_table_block as usize *
            ext4.sb.block_size as usize +
            index as usize *
            ext4.sb.inode_size as usize;

        let inode_bytes = &ext4.device_mmap[
            inode_offset..
            inode_offset + ext4.sb.inode_size as usize
        ];

        let raw = bytemuck::try_from_bytes::<raw::Ext4Inode>(
            &inode_bytes[..std::mem::size_of::<raw::Ext4Inode>().min(inode_bytes.len())]
        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid inode data"))?;

        let mode = u16::from_le(raw.mode);
        let size_low = u32::from_le(raw.size_lo);
        let flags = u32::from_le(raw.flags);
        let mtime_sec = u32::from_le(raw.mtime) as i64;

        let size_high = if ext4.sb.inode_size > 128 {
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

        Ok(Ext4Inode {
            inode_num: inode_num as u64,
            mode,
            size,
            flags,
            mtime_sec,
            blocks,
        })
    }

    #[inline]
    pub fn parse_superblock(data: &[u8]) -> io::Result<Ext4SuperBlock> {
        let _span = tracy::span!("WorkerBuffers::parse_superblock");

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
    pub fn get_block<'a>(
        block_num: u64,
        ext4: &Ext4Context,
    ) -> &'a [u8] {
        let offset = (block_num as usize).wrapping_mul(ext4.sb.block_size as usize);
        debug_assert!(
            ext4.device_mmap.get(offset..offset + ext4.sb.block_size as usize).is_some()
        );
        unsafe {
            let ptr = ext4.device_mmap.as_ptr().add(offset);
            core::slice::from_raw_parts(ptr, ext4.sb.block_size as usize)
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
    pub const fn get_buf_mut(&mut self, kind: BufKind) -> &mut Vec<u8> {
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

        // SAFETY: safety is on caller
        #[cfg(not(debug_assertions))]
        unsafe {
            &self.get_buf(ptr.kind).get_unchecked(
                ptr.offset as usize..(ptr.offset+ptr.len) as usize
            )
        }
    }

    #[inline(always)]
    pub fn prefetch_blocks<const N: usize>(blocks: Cow<SmallVec<[u64; N]>>, ext4: &Ext4Context) {
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
                if (range_end - range_start) * ext4.sb.block_size as u64 >= 128 * 1024 {
                    Self::advise_range(range_start, range_end, ext4);
                }
                range_start = block;
                range_end = block;
            }
        }

        // @Constant
        if (range_end - range_start) * ext4.sb.block_size as u64 >= 128 * 1024 {
            Self::advise_range(range_start, range_end, ext4);
        }
    }

    /// Prefetch all blocks for an inode (call before reading file)
    #[inline]
    pub fn prefetch_inode_data(
        &mut self,
        inode: &Ext4Inode,
        size_to_read: usize,
        ext4: &Ext4Context
    ) {
        if inode.flags & EXT4_EXTENTS_FL != 0 {
            // Parse extents and prefetch
            if self.parse_extents(inode, ext4).is_ok() {
                let extent_count = self.extents.len();
                // Borrow extent_buf data before calling prefetch
                let extents: SmallVec<[_; MAX_EXTENTS_UNTIL_SPILL]> =
                    self.extents[..extent_count].iter().copied().collect();

                Parser::prefetch_extent_blocks(&extents, size_to_read, ext4);
            }
        } else {
            // Direct blocks
            // @Constant
            let blocks: SmallVec<[u64; 12]> = inode
                .blocks
                .iter()
                .take(EXT4_BLOCK_POINTERS_COUNT)
                .filter(|&&b| b != 0)
                .map(|&b| b as u64)
                .collect();

            Parser::prefetch_direct_blocks(&blocks, ext4);
        }
    }

    #[inline(always)]
    pub fn advise_range(start_block: u64, end_block: u64, ext4: &Ext4Context) {
        let offset = start_block as usize * ext4.sb.block_size as usize;
        let length = (end_block - start_block + 1) as usize * ext4.sb.block_size as usize;

        debug_assert!(offset + length <= ext4.device_mmap.len());

        unsafe {
            libc::madvise(
                ext4.device_mmap.as_ptr().add(offset) as *mut _,
                length,
                libc::MADV_WILLNEED
            );
        }
    }

    fn read_extents(
        &mut self,
        inode: &Ext4Inode,
        size_to_read: usize,
        file_size: usize,
        kind: BufKind,
        check_binary: bool,
        ext4: &Ext4Context
    ) -> io::Result<bool> {
        let _span = tracy::span!("WorkerContext::read_extents");

        self.parse_extents(inode, ext4)?;

        let extent_count = self.extents.len();

        let extents: SmallVec<[_; MAX_EXTENTS_UNTIL_SPILL]> = copy_data(
            &self.extents[..extent_count]
        );

        Self::prefetch_extent_blocks(&extents, size_to_read, ext4);

        if check_binary {
            // Binary check: Only check FIRST block
            if let Some(first_extent) = extents.first() {
                let first_block = Self::get_block(first_extent.start, ext4);
                let probe_size = file_size.min(BINARY_PROBE_BYTE_SIZE).min(first_block.len());

                if is_binary_chunk(&first_block[..probe_size]) {
                    self.get_buf_mut(kind).clear();
                    return Ok(false);
                }
            }
        }

        self.copy_extents_to_buf(&extents, size_to_read, kind, ext4);

        self.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    fn read_direct_blocks(
        &mut self,
        inode: &Ext4Inode,
        size_to_read: usize,
        file_size: usize,
        kind: BufKind,
        check_binary: bool,
        ext4: &Ext4Context
    ) -> io::Result<bool> {
        let _span = tracy::span!("WorkerContext::read_direct_blocks");

        let blocks: SmallVec<[u64; EXT4_BLOCK_POINTERS_COUNT]> = inode
            .blocks
            .iter()
            .take(EXT4_BLOCK_POINTERS_COUNT)
            .filter(|&&b| b != 0)
            .map(|&b| b as u64)
            .collect();

        Self::prefetch_direct_blocks(&blocks, ext4);

        if check_binary && let Some(&first_block_num) = blocks.first() {
            // Binary check: Only check FIRST block
            let first_block = Self::get_block(first_block_num, ext4);
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
                let block_data = Self::get_block(block_num, ext4);
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

    /// Prefetch for extent-based files
    #[inline]
    pub fn prefetch_extent_blocks(extents: &[Ext4Extent], size_to_read: usize, ext4: &Ext4Context) {
        let _span = tracy::span!("WorkerContext::prefetch_extent_blocks");

        let block_size = ext4.sb.block_size as usize;
        let mut remaining = size_to_read;

        for extent in extents {
            if remaining == 0 { break }

            let extent_bytes = extent.len as usize * block_size;
            let bytes_to_prefetch = extent_bytes.min(remaining);
            let blocks_to_prefetch = bytes_to_prefetch.div_ceil(block_size);

            let offset = extent.start as usize * block_size;
            let length = blocks_to_prefetch * block_size;

            if offset + length <= ext4.device_mmap.len() {
                unsafe {
                    libc::madvise(
                        ext4.device_mmap.as_ptr().add(offset) as *mut _,
                        length,
                        libc::MADV_WILLNEED,
                    );
                }
            }

            remaining = remaining.saturating_sub(extent_bytes);
        }
    }

    /// Prefetch blocks for direct-block files (small/old files)
    #[inline]
    pub fn prefetch_direct_blocks(blocks: &[u64], ext4: &Ext4Context) {
        if blocks.is_empty() {
            return;
        }

        let block_size = ext4.sb.block_size as usize;
        let mmap_len = ext4.device_mmap.len();

        // Direct blocks are usually contiguous or close together
        // Just prefetch each one - kernel will coalesce
        for &block in blocks {
            let offset = block as usize * block_size;
            if offset + block_size > mmap_len { continue }

            unsafe {
                libc::madvise(
                    ext4.device_mmap.as_ptr().add(offset) as *mut _,
                    block_size,
                    libc::MADV_WILLNEED,
                );
            }
        }
    }

    /// Asynchronously prefetch a memory region
    #[inline]
    pub fn prefetch_region(
        offset: usize,
        length: usize,
        ext4: &Ext4Context
    ) {
        if offset + length > ext4.device_mmap.len() {
            return;
        }

        //
        // Align to page boundaries
        //
        let page_size = 4096; // @Refactor should we make page-size dynamic?
        let aligned_offset = offset & !(page_size - 1);
        let aligned_length = ((offset + length + page_size - 1) & !(page_size - 1)) - aligned_offset;

        unsafe {
            libc::madvise(
                ext4.device_mmap.as_ptr().add(aligned_offset) as *mut _,
                aligned_length,
                libc::MADV_WILLNEED,
            );
        }
    }

    #[inline]
    fn copy_extents_to_buf(
        &mut self,
        extents: &[Ext4Extent],
        size_to_read: usize,
        kind: BufKind,
        ext4: &Ext4Context
    ) {
        let _span = tracy::span!("WorkerContext::copy_extents_to_buf");

        let mut copied = 0;

        for extent in extents {
            if copied >= size_to_read { break; }

            for block_offset in 0..extent.len {
                if copied >= size_to_read { break; }

                let phys_block = extent.start + block_offset as u64;

                let (src_ptr, src_len) = {
                    let block_data = Self::get_block(phys_block, ext4);
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
}
