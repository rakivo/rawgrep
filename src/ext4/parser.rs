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

use std::fs::File;
use std::{io, mem};
use std::ops::ControlFlow;

use smallvec::SmallVec;

/// Ext4 filesystem context
pub struct Ext4Fs {
    pub file: File,
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

impl RawFs for Ext4Fs {
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
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid inode number 0"));
        }

        let group = (inode_num - 1) / self.sb.inodes_per_group;
        let index = (inode_num - 1) % self.sb.inodes_per_group;

        let bg_desc_offset = if self.sb.block_size == 1024 {
            2048
        } else {
            self.sb.block_size as usize
        } + (group as usize * self.sb.desc_size as usize);

        let mut bg_desc_buf = [0u8; 64]; // desc_size is at most 64 bytes
        let desc_size = self.sb.desc_size as usize;
        self.read_at_offset(&mut bg_desc_buf[..desc_size], bg_desc_offset as u64)?;

        let inode_table_block = u32::from_le_bytes([
            bg_desc_buf[EXT4_INODE_TABLE_OFFSET + 0],
            bg_desc_buf[EXT4_INODE_TABLE_OFFSET + 1],
            bg_desc_buf[EXT4_INODE_TABLE_OFFSET + 2],
            bg_desc_buf[EXT4_INODE_TABLE_OFFSET + 3],
        ]);

        let inode_offset = inode_table_block as usize *
            self.sb.block_size as usize +
            index as usize *
            self.sb.inode_size as usize;

        let mut inode_buf = [0u8; 512]; // inode_size is at most 512 bytes in practice
        let inode_size = self.sb.inode_size as usize;
        let to_read = inode_size.min(inode_buf.len());
        self.read_at_offset(&mut inode_buf[..to_read], inode_offset as _)?;

        let raw = bytemuck::try_from_bytes::<raw::Ext4Inode>(
            &inode_buf[..std::mem::size_of::<raw::Ext4Inode>().min(to_read)]
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

        // eprintln!("parse_node: inode={} group={} index={} bg_desc_offset={} inode_table_block={} inode_offset={} size={}",
        //           inode_num, group, index, bg_desc_offset, inode_table_block, inode_offset, size);

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

        //
        // If previous file left a huge buffer, release it before reserving for this file
        // @Constant @Tune - 4MB threshold, files larger than this won't bloat next iteration
        //
        if buf.capacity() > 4 * 1024 * 1024 && size_to_read < buf.capacity() / 4 {
            *buf = Vec::with_capacity(size_to_read);
        } else {
            buf.reserve(size_to_read);
        }

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
}

// ext4-specific helper methods
impl Ext4Fs {
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

            for child_block in child_blocks {
                let offset = child_block * self.sb.block_size as u64;
                let block_size = self.sb.block_size as usize;
                let mut block_buf = vec![0u8; block_size];
                if self.read_at_offset(&mut block_buf, offset).is_ok() {
                    self.parse_extent_node(parser, &block_buf, level + 1)?;
                }
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

        if check_binary {
            if let Some(first_extent) = extents.first() {
                let mut first_block_buf = vec![0u8; self.sb.block_size as usize];
                let offset = first_extent.start * self.sb.block_size as u64;
                if self.read_at_offset(&mut first_block_buf, offset).is_err() {
                    return Ok(true); // can't read, just search it
                }
                if check_first_block_binary(&first_block_buf, file_size) {
                    parser.get_buf_mut(kind).clear();
                    return Ok(false);
                }
            }
        }

        self.copy_extents_to_buf(parser, &extents, size_to_read, kind);

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
        let block_size = self.sb.block_size as u64;

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

        if check_binary {
            if let Some(&first_block_num) = blocks.first() {
                let mut first_block_buf = [0u8; 4096];
                let offset = first_block_num * block_size;
                let to_read = (block_size as usize).min(first_block_buf.len());
                let n = self.read_at_offset(&mut first_block_buf[..to_read], offset).unwrap_or(0);
                if check_first_block_binary(&first_block_buf[..n], file_size) {
                    parser.get_buf_mut(kind).clear();
                    return Ok(false);
                }
            }
        }

        let mut copied = 0;
        for &block_num in &blocks {
            if copied >= size_to_read { break; }

            let offset = block_num * block_size;
            let remaining = size_to_read - copied;
            let to_read = (block_size as usize).min(remaining);

            let buf = parser.get_buf_mut(kind);
            let old_len = buf.len();
            buf.resize(old_len + to_read, 0);

            match self.read_at_offset(&mut buf[old_len..], offset) {
                Ok(n) => {
                    buf.truncate(old_len + n);
                    copied += n;
                }
                Err(_) => {
                    buf.truncate(old_len);
                    break;
                }
            }
        }

        parser.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    #[inline]
    fn copy_extents_to_buf(
        &self,
        parser: &mut Parser,
        extents: &[Ext4Extent],
        size_to_read: usize,
        kind: BufKind,
    ) {
        let block_size = self.sb.block_size as u64;
        let mut copied = 0;

        for extent in extents {
            if copied >= size_to_read { break; }

            let offset = extent.start * block_size;
            let extent_bytes = extent.len as usize * block_size as usize;
            let remaining = size_to_read - copied;
            let to_read = extent_bytes.min(remaining);

            let buf = parser.get_buf_mut(kind);
            let old_len = buf.len();
            buf.resize(old_len + to_read, 0);

            match self.read_at_offset(&mut buf[old_len..], offset) {
                Ok(n) => {
                    buf.truncate(old_len + n);
                    copied += n;
                }
                Err(_) => {
                    buf.truncate(old_len);
                    break;
                }
            }
        }
    }

    #[inline]
    fn read_at_offset(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        #[cfg(unix)] {
            use std::os::unix::fs::FileExt;
            self.file.read_at(buf, offset)
        }
        #[cfg(windows)] {
            use std::os::windows::fs::FileExt;
            self.file.seek_read(buf, offset)
        }
    }
}
