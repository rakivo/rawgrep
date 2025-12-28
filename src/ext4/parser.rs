//! ext4 filesystem implementation of RawFs trait

use crate::tracy;
use crate::copy_data;
use crate::util::{likely, unlikely};
use crate::worker::MAX_EXTENTS_UNTIL_SPILL;
use crate::parser::{BufKind, FileId, FileNode, FileType, Parser, RawFs, check_first_block_binary};

use super::{
    raw, Ext4Extent, Ext4Inode, Ext4SuperBlock, INodeNum,
    EXT4_BLOCKS_PER_GROUP_OFFSET, EXT4_BLOCK_POINTERS_COUNT, EXT4_BLOCK_SIZE_OFFSET,
    EXT4_DESC_SIZE_OFFSET, EXT4_EXTENTS_FL, EXT4_INLINE_DATA_FL, EXT4_EXTENT_MAGIC, EXT4_FT_DIR,
    EXT4_FT_REG_FILE, EXT4_INODES_PER_GROUP_OFFSET, EXT4_INODE_SIZE_OFFSET,
    EXT4_INODE_TABLE_OFFSET, EXT4_ROOT_INODE,
};

use std::{io, mem};
use std::borrow::Cow;
use std::ops::ControlFlow;

use memmap2::Mmap;
use smallvec::SmallVec;

/// Ext4 filesystem context
pub struct Ext4Fs<'a> {
    pub mmap: &'a Mmap,
    pub sb: Ext4SuperBlock,
    pub device_id: u64,
    pub max_block: u64,
}

impl FileNode for Ext4Inode {
    #[inline(always)]
    fn file_id(&self) -> FileId {
        self.inode_num
    }

    #[inline(always)]
    fn size(&self) -> u64 {
        self.size
    }

    #[inline(always)]
    fn mtime(&self) -> i64 {
        self.mtime_sec
    }

    #[inline(always)]
    fn is_dir(&self) -> bool {
        (self.mode & super::EXT4_S_IFMT) == super::EXT4_S_IFDIR
    }
}

impl<'a> RawFs for Ext4Fs<'a> {
    type Node = Ext4Inode;
    type Context<'b> = &'b Self where Self: 'b;

    #[inline(always)]
    fn device_id(&self) -> u64 {
        self.device_id
    }

    #[inline(always)]
    fn block_size(&self) -> u32 {
        self.sb.block_size
    }

    #[inline(always)]
    fn root_id(&self) -> FileId {
        EXT4_ROOT_INODE as FileId
    }

    fn parse_node(&self, file_id: FileId) -> io::Result<Self::Node> {
        let _span = tracy::span!("Ext4Fs::parse_node");

        let inode_num = file_id as INodeNum;

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

        let bg_desc = &self.mmap[
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

        let inode_bytes = &self.mmap[
            inode_offset..
            inode_offset + self.sb.inode_size as usize
        ];

        let raw = bytemuck::try_from_bytes::<raw::Ext4Inode>(
            &inode_bytes[..std::mem::size_of::<raw::Ext4Inode>().min(inode_bytes.len())]
        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid inode data"))?;

        let mode = u16::from_le(raw.mode);
        let size_low = u32::from_le(raw.size_lo);
        let flags = u32::from_le(raw.flags);
        let mtime_sec = u32::from_le(raw.mtime) as i64;

        let size_high = if self.sb.inode_size > 128 {
            u32::from_le(raw.size_high)
        } else {
            0
        };

        let size = ((size_high as u64) << 32) | (size_low as u64);

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

    #[inline(always)]
    fn get_block(&self, block_num: u64) -> &[u8] {
        let offset = (block_num as usize).wrapping_mul(self.sb.block_size as usize);
        debug_assert!(
            self.mmap.get(offset..offset + self.sb.block_size as usize).is_some()
        );
        unsafe {
            let ptr = self.mmap.as_ptr().add(offset);
            core::slice::from_raw_parts(ptr, self.sb.block_size as usize)
        }
    }

    #[inline]
    fn read_file_content(
        &self,
        parser: &mut Parser,
        node: &Self::Node,
        max_size: usize,
        kind: BufKind,
        check_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("Ext4Fs::read_file_content");

        let buf = parser.get_buf_mut(kind);
        buf.clear();

        let file_size = node.size as usize;
        let size_to_read = file_size.min(max_size);
        buf.reserve(size_to_read);

        // Inline data: file content stored directly in inode's block array
        if node.flags & EXT4_INLINE_DATA_FL != 0 {
            return self.read_inline_data(parser, node, size_to_read, kind, check_binary);
        }

        if node.flags & EXT4_EXTENTS_FL != 0 {
            self.read_extents(parser, node, size_to_read, file_size, kind, check_binary)
        } else {
            self.read_direct_blocks(parser, node, size_to_read, file_size, kind, check_binary)
        }
    }

    #[inline]
    fn prefetch_file(&self, parser: &mut Parser, node: &Self::Node, size_to_read: usize) {
        // Inline data is already in the inode - nothing to prefetch
        if node.flags & EXT4_INLINE_DATA_FL != 0 {
            return;
        }

        if node.flags & EXT4_EXTENTS_FL != 0 {
            if self.parse_extents_into_scratch(parser, node).is_ok() {
                let extents = Self::scratch_as_extents(&parser.scratch);
                self.prefetch_extent_blocks(extents, size_to_read);
            }
        } else {
            // Direct blocks
            let max_block = self.max_block;
            let blocks: SmallVec<[u64; 12]> = node
                .blocks
                .iter()
                .take(EXT4_BLOCK_POINTERS_COUNT)
                .filter(|&&b| b != 0 && (b as u64) < max_block)
                .map(|&b| b as u64)
                .collect();

            self.prefetch_direct_blocks(&blocks);
        }
    }

    fn with_directory_entries<R>(
        &self,
        buf: &[u8],
        mut callback: impl FnMut(FileId, usize, usize, FileType) -> ControlFlow<R>
    ) -> Option<R> {
        let _span = tracy::span!("Ext4Fs::with_directory_entries");

        let mut offset = 0;
        let entry_size = mem::size_of::<raw::Ext4DirEntry2>();

        while offset + entry_size <= buf.len() {
            let entry = match bytemuck::try_from_bytes::<raw::Ext4DirEntry2>(
                &buf[offset..offset + entry_size]
            ) {
                Ok(e) => e,
                Err(_) => break,
            };

            let entry_inode = u32::from_le(entry.inode) as FileId;
            let rec_len = u16::from_le(entry.rec_len);
            let name_len = entry.name_len;
            let file_type = entry.file_type;

            if unlikely(rec_len == 0) {
                break;
            }

            let old_offset = offset;
            offset += rec_len as usize;

            if unlikely(entry_inode == 0 || name_len == 0) {
                continue;
            }

            let name_start = old_offset + entry_size;
            let name_end = name_start + name_len as usize;

            if name_end > old_offset + rec_len as usize || name_end > buf.len() {
                continue;
            }

            let file_type = match file_type {
                EXT4_FT_REG_FILE => FileType::File,
                EXT4_FT_DIR => FileType::Dir,
                _ => FileType::Other,
            };

            match callback(entry_inode, name_start, name_len as usize, file_type) {
                ControlFlow::Break(b) => return Some(b),
                ControlFlow::Continue(_) => {}
            }
        }

        None
    }

    #[inline]
    fn prefetch_region(&self, offset: usize, length: usize) {
        if offset + length > self.mmap.len() {
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
                self.mmap.as_ptr().add(aligned_offset) as *mut _,
                aligned_length,
                libc::MADV_WILLNEED,
            );
        }
    }
}

// ext4-specific helper methods
impl Ext4Fs<'_> {
    /// Read inline data from inode's block array (max 60 bytes)
    fn read_inline_data(
        &self,
        parser: &mut Parser,
        node: &Ext4Inode,
        size_to_read: usize,
        kind: BufKind,
        check_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("Ext4Fs::read_inline_data");

        // blocks array is [u32; 15] = 60 bytes of inline data
        let inline_bytes: &[u8] = bytemuck::cast_slice(&node.blocks);
        let actual_size = size_to_read.min(inline_bytes.len());

        if check_binary && check_first_block_binary(&inline_bytes[..actual_size], actual_size) {
            return Ok(false);
        }

        let buf = parser.get_buf_mut(kind);
        buf.extend_from_slice(&inline_bytes[..actual_size]);
        Ok(true)
    }

    pub fn parse_superblock(data: &[u8]) -> io::Result<Ext4SuperBlock> {
        let _span = tracy::span!("Ext4Fs::parse_superblock");

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

    /// Parse extents into parser.scratch as [Ext4Extent]
    fn parse_extents_into_scratch(&self, parser: &mut Parser, node: &Ext4Inode) -> io::Result<()> {
        let _span = tracy::span!("Ext4Fs::parse_extents_into_scratch");

        parser.scratch.clear();
        let block_bytes = bytemuck::cast_slice(&node.blocks);
        self.parse_extent_node(parser, block_bytes, 0)?;
        Ok(())
    }

    #[inline]
    fn scratch_as_extents(scratch: &[u8]) -> &[Ext4Extent] {
        bytemuck::cast_slice(scratch)
    }

    #[inline]
    fn push_extent_to_scratch(parser: &mut Parser, extent: Ext4Extent) {
        let bytes = bytemuck::bytes_of(&extent);
        parser.scratch.extend_from_slice(bytes);
    }

    fn parse_extent_node(
        &self,
        parser: &mut Parser,
        data: &[u8],
        level: usize,
    ) -> io::Result<()> {
        let _span = tracy::span!("Ext4Fs::parse_extent_node");

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
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid extent data")
                })?;

                let ee_len = u16::from_le(extent.ee_len);
                let ee_start_hi = u16::from_le(extent.ee_start_hi);
                let ee_start_lo = u32::from_le(extent.ee_start_lo);

                let start_block = ((ee_start_hi as u64) << 32) | (ee_start_lo as u64);

                if likely(ee_len > 0 && ee_len <= 32768) {
                    Self::push_extent_to_scratch(parser, Ext4Extent {
                        start: start_block,
                        len: ee_len,
                        _pad: [0; 6],
                    });
                }
            }
        } else {
            let mut child_blocks = SmallVec::<[u64; 16]>::new();

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
                    io::Error::new(io::ErrorKind::InvalidData, "Couldn't parse extent idx")
                })?;

                let ei_leaf_hi = u16::from_le(idx.ei_leaf_hi);
                let ei_leaf_lo = u32::from_le(idx.ei_leaf_lo);

                let leaf_block = ((ei_leaf_hi as u64) << 32) | (ei_leaf_lo as u64);
                child_blocks.push(leaf_block);
            }

            self.prefetch_blocks(Cow::Borrowed(&child_blocks));

            for child_block in child_blocks {
                let block_data = self.get_block(child_block);
                self.parse_extent_node(parser, block_data, level + 1)?;
            }
        }

        Ok(())
    }

    fn read_extents(
        &self,
        parser: &mut Parser,
        node: &Ext4Inode,
        size_to_read: usize,
        file_size: usize,
        kind: BufKind,
        check_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("Ext4Fs::read_extents");

        self.parse_extents_into_scratch(parser, node)?;

        let extents: SmallVec<[Ext4Extent; MAX_EXTENTS_UNTIL_SPILL]> =
            copy_data(Self::scratch_as_extents(&parser.scratch));

        self.prefetch_extent_blocks(&extents, size_to_read);

        if check_binary {
            if let Some(first_extent) = extents.first() {
                let first_block = self.get_block(first_extent.start);
                if check_first_block_binary(first_block, file_size) {
                    parser.get_buf_mut(kind).clear();
                    return Ok(false);
                }
            }
        }

        self.copy_extents_to_buf(parser, &extents, size_to_read, kind);

        //
        //
        //
        // Release mmap pages back to OS after copying
        // @Constant @Tune - threshold for when madvise overhead is worth it
        //
        //
        if size_to_read >= 64 * 1024 {
            self.release_extent_pages(&extents, size_to_read);
        }

        parser.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    fn read_direct_blocks(
        &self,
        parser: &mut Parser,
        node: &Ext4Inode,
        size_to_read: usize,
        file_size: usize,
        kind: BufKind,
        check_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("Ext4Fs::read_direct_blocks");

        let max_block = self.max_block;
        let blocks: SmallVec<[u64; EXT4_BLOCK_POINTERS_COUNT]> = node
            .blocks
            .iter()
            .take(EXT4_BLOCK_POINTERS_COUNT)
            .filter(|&&b| b != 0 && (b as u64) < max_block)
            .map(|&b| b as u64)
            .collect();

        // No valid blocks - file may be sparse or corrupted
        if blocks.is_empty() {
            return Ok(true);
        }

        self.prefetch_direct_blocks(&blocks);

        if check_binary && let Some(&first_block_num) = blocks.first() {
            let first_block = self.get_block(first_block_num);
            if check_first_block_binary(first_block, file_size) {
                parser.get_buf_mut(kind).clear();
                return Ok(false);
            }
        }

        let mut copied = 0;

        for &block_num in &blocks {
            if copied >= size_to_read { break; }

            let block_data = self.get_block(block_num);
            let remaining = size_to_read - copied;
            let to_copy = block_data.len().min(remaining);

            let buf = parser.get_buf_mut(kind);
            let old_len = buf.len();
            buf.resize(old_len + to_copy, 0);

            unsafe {
                core::ptr::copy_nonoverlapping(
                    block_data.as_ptr(),
                    buf.as_mut_ptr().add(old_len),
                    to_copy
                );
            }

            copied += to_copy;
        }

        parser.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    fn prefetch_blocks<const N: usize>(&self, blocks: Cow<SmallVec<[u64; N]>>) {
        let _span = tracy::span!("Ext4Fs::prefetch_blocks");

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

        if (range_end - range_start) * self.sb.block_size as u64 >= 128 * 1024 {
            self.advise_range(range_start, range_end);
        }
    }

    #[inline(always)]
    fn advise_range(&self, start_block: u64, end_block: u64) {
        let offset = start_block as usize * self.sb.block_size as usize;
        let length = (end_block - start_block + 1) as usize * self.sb.block_size as usize;

        debug_assert!(offset + length <= self.mmap.len());

        unsafe {
            libc::madvise(
                self.mmap.as_ptr().add(offset) as *mut _,
                length,
                libc::MADV_WILLNEED
            );
        }
    }

    #[inline]
    fn prefetch_extent_blocks(&self, extents: &[Ext4Extent], size_to_read: usize) {
        let _span = tracy::span!("Ext4Fs::prefetch_extent_blocks");

        let block_size = self.sb.block_size as usize;
        let mut remaining = size_to_read;

        for extent in extents {
            if remaining == 0 { break }

            let extent_bytes = extent.len as usize * block_size;
            let bytes_to_prefetch = extent_bytes.min(remaining);
            let blocks_to_prefetch = bytes_to_prefetch.div_ceil(block_size);

            let offset = extent.start as usize * block_size;
            let length = blocks_to_prefetch * block_size;

            if offset + length <= self.mmap.len() {
                unsafe {
                    libc::madvise(
                        self.mmap.as_ptr().add(offset) as *mut _,
                        length,
                        libc::MADV_WILLNEED,
                    );
                }
            }

            remaining = remaining.saturating_sub(extent_bytes);
        }
    }

    #[inline]
    fn prefetch_direct_blocks(&self, blocks: &[u64]) {
        if blocks.is_empty() {
            return;
        }

        let block_size = self.sb.block_size as usize;
        let mmap_len = self.mmap.len();

        for &block in blocks {
            let offset = block as usize * block_size;
            if offset + block_size > mmap_len { continue }

            unsafe {
                libc::madvise(
                    self.mmap.as_ptr().add(offset) as *mut _,
                    block_size,
                    libc::MADV_WILLNEED,
                );
            }
        }
    }

    #[inline]
    fn release_extent_pages(&self, extents: &[Ext4Extent], size_to_read: usize) {
        let block_size = self.sb.block_size as usize;
        let mmap_len = self.mmap.len();
        let mut remaining = size_to_read;

        for extent in extents {
            if remaining == 0 { break }

            let extent_bytes = extent.len as usize * block_size;
            let bytes_to_release = extent_bytes.min(remaining);
            let blocks_to_release = bytes_to_release.div_ceil(block_size);

            let offset = extent.start as usize * block_size;
            let length = blocks_to_release * block_size;

            if offset + length <= mmap_len {
                unsafe {
                    libc::madvise(
                        self.mmap.as_ptr().add(offset) as *mut _,
                        length,
                        libc::MADV_FREE,
                    );
                }
            }

            remaining = remaining.saturating_sub(extent_bytes);
        }
    }

    #[inline]
    fn copy_extents_to_buf(
        &self,
        parser: &mut Parser,
        extents: &[Ext4Extent],
        size_to_read: usize,
        kind: BufKind,
    ) {
        let _span = tracy::span!("Ext4Fs::copy_extents_to_buf");

        let mut copied = 0;

        for extent in extents {
            if copied >= size_to_read { break; }

            for block_offset in 0..extent.len {
                if copied >= size_to_read { break; }

                let phys_block = extent.start + block_offset as u64;
                let block_data = self.get_block(phys_block);

                let remaining = size_to_read - copied;
                let to_copy = block_data.len().min(remaining);

                let buf = parser.get_buf_mut(kind);
                let old_len = buf.len();
                buf.resize(old_len + to_copy, 0);

                // SAFETY: src_ptr points to mmap'd data that remains valid.
                // We've ensured no overlap and both pointers are valid.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        block_data.as_ptr(),
                        buf.as_mut_ptr().add(old_len),
                        to_copy
                    );
                }

                copied += to_copy;
            }
        }
    }
}
