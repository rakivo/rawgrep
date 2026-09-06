//! ext4 filesystem implementation of RawFs trait

use crate::tracy;
use crate::util::{likely, unlikely};
use crate::parser::{BufFatPtr, BufKind, FileId, FileNode, FileType, Parser, RawFs, binary_probe};
use crate::worker::STREAMING_CHUNK_SIZE;

use super::*;

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
    pub inode_table_blocks: Vec<u64>,
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
    fn device_file(&self) -> &File {
        &self.file
    }

    #[inline(always)]
    fn block_size(&self) -> u32 {
        self.sb.block_size
    }

    #[inline(always)]
    fn root_id(&self) -> FileId {
        EXT4_ROOT_INODE as FileId
    }

    #[inline]
    fn parse_node(&self, file_id: FileId) -> io::Result<Self::Node> {
        let _span = tracy::span!("Ext4Fs::parse_node");

        let inode_num = file_id as INodeNum;

        if unlikely(inode_num == 0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid inode number 0"));
        }

        let inode_offset = self.inode_disk_offset(file_id);

        let mut inode_buf = [0u8; 256];  // Ext4 inode_size is 128 or 256 in virtually all real deployments
        debug_assert!(self.sb.inode_size as usize <= inode_buf.len());

        let inode_size = self.sb.inode_size as usize;
        let to_read = inode_size.min(inode_buf.len());
        self.read_at_offset(&mut inode_buf[..to_read], inode_offset as _)?;          // @Cache @Syscall

        let raw = bytemuck::try_from_bytes::<raw::Ext4Inode>(
            &inode_buf[..std::mem::size_of::<raw::Ext4Inode>().min(to_read)]
        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid inode data"))?;

        let mode      = u16::from_le(raw.mode);
        let size_low  = u32::from_le(raw.size_lo);
        let flags     = u32::from_le(raw.flags);
        let mtime_sec = u32::from_le(raw.mtime) as i64;

        let size_high = if self.sb.inode_size > 128 {
            u32::from_le(raw.size_high)
        } else {
            0
        };

        let size = ((size_high as u64) << 32) | (size_low as u64);

        let raw_block = [raw.block];
        let block_bytes = bytemuck::cast_slice::<[[u8; 12]; 5], u8>(&raw_block);

        #[cfg(target_endian = "little")]
        let blocks: [u32; 15] = {
            // On a little-endian host, on-disk LE u32s are already in native order.
            let as_u32: &[u32] = bytemuck::cast_slice(block_bytes);
            as_u32.try_into().expect("block array is always exactly 60 bytes / 15 u32s")
        };

        #[cfg(target_endian = "big")]
        let blocks: [u32; 15] = {
            let as_u32: &[u32] = bytemuck::cast_slice(block_bytes);
            std::array::from_fn(|i| u32::from_le(as_u32[i]))
        };

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
    fn sort_entries(&self, entries: &mut [(FileId, BufFatPtr)]) {
        entries.sort_unstable_by_key(|(file_id, _)| self.inode_disk_offset(*file_id));
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

        let buf = Parser::get_buf_mut_impl(&mut parser.file, &mut parser.dir, &mut parser.gitignore, kind);
        buf.clear();

        let file_size = node.size as usize;
        let size_to_read = file_size.min(max_size);

        // Inline data: file content stored directly in inode's block array
        if node.flags & EXT4_INLINE_DATA_FL != 0 {
            return self.read_inline_data(parser, node, size_to_read, kind, check_binary);
        }

        if !self.collect_file_chunks(
            &mut parser.scratch,
            &mut parser.scratch2,
            &mut parser.scratch_chunks,
            node,
            size_to_read,
            check_binary,
            buf
        )? {
            parser.get_buf_mut(kind).clear();
            return Ok(false);
        }

        for &(disk_offset, len) in &parser.scratch_chunks {
            let buf = Parser::get_buf_mut_impl(&mut parser.file, &mut parser.dir, &mut parser.gitignore, kind);

            let old_len = buf.len();
            buf.resize(old_len + len as usize, 0);
            match self.read_at_offset(&mut buf[old_len..], disk_offset) {
                Ok(n) => buf.truncate(old_len + n),
                Err(_) => { buf.truncate(old_len); break; }
            }
        }

        parser.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    fn collect_file_chunks(
        &self,
        scratch: &mut Vec<u8>,
        scratch2: &mut Vec<u8>, // Probe buffer, only touched (and only sized) when check_binary
        scratch_chunks: &mut Vec<(u64, u32)>,
        node: &Ext4Inode,
        max_size: usize,
        check_binary: bool,
        buf: &mut Vec<u8>,      // Destination buffer -- probed bytes get written straight in here
    ) -> io::Result<bool> {
        let _span = tracy::span!("Ext4Fs::collect_file_chunks");

        let file_size = node.size as usize;
        let block_size = self.sb.block_size as u64;

        // Inline data has no disk offsets - caller handles it via read_file_content
        if node.flags & EXT4_INLINE_DATA_FL != 0 {
            return Ok(true);
        }

        scratch.clear();
        scratch_chunks.clear();

        if node.flags & EXT4_EXTENTS_FL != 0 {
            //
            // Parse extents into scratch
            //
            let block_bytes = bytemuck::cast_slice(&node.blocks);
            self.parse_extent_node_into(scratch, block_bytes, 0)?;

            let extents = Self::scratch_as_extents(scratch);

            // Bytes of the very first extent already pulled into `buf` by the probe below,
            // still owed to the chunk-building loop as a "skip" so it doesn't re-read them.
            let mut skip_first = 0usize;

            if check_binary && let Some(first) = extents.first() {
                // Binary probe

                let probe_len = (block_size as usize).min(max_size);
                scratch2.clear();
                scratch2.resize(probe_len, 0);

                let offset = first.start * block_size;
                match self.read_at_offset(scratch2, offset) {
                    Ok(n) => {
                        if binary_probe(&scratch2[..n], file_size) {
                            return Ok(false);                    // binary
                        }

                        buf.extend_from_slice(&scratch2[..n]);
                        skip_first = n;
                    }

                    Err(_) => return Ok(true), // unreadable
                }
            }

            let mut total = 0usize;

            for extent in extents {
                if total >= max_size { break; }

                let extent_bytes = extent.len as usize * block_size as usize;
                let mut extent_offset = 0usize;

                while extent_offset < extent_bytes {
                    if total >= max_size { break; }

                    let remaining = max_size - total;
                    let mut to_read = STREAMING_CHUNK_SIZE.min(remaining).min(extent_bytes - extent_offset);
                    let mut disk_offset = extent.start * block_size + extent_offset as u64;

                    // Only ever fires on the first extent's first bytes -- skip whatever the
                    // probe already read so we don't fetch it a second time.
                    if skip_first > 0 {
                        let skip = skip_first.min(to_read);
                        disk_offset   += skip as u64;
                        to_read       -= skip;
                        extent_offset += skip;
                        total         += skip;
                        skip_first    -= skip;
                        if to_read == 0 { continue; }
                    }

                    if to_read > 0 {
                        crate::parser::push_chunk(scratch_chunks, disk_offset, to_read as u32);
                        total += to_read;
                        extent_offset += to_read;
                    }
                }
            }

            Ok(true)
        } else {
            //
            // Direct blocks
            //

            let blocks = &node.blocks[..EXT4_BLOCK_POINTERS_COUNT];

            if blocks.iter().all(|&b| b == 0 || b as u64 >= self.max_block) {
                return Ok(true);
            }

            let mut skip_first = 0usize;

            if check_binary && let Some(&first) = blocks.iter().find(|&&b| b != 0 && (b as u64) < self.max_block) {
                // Binary probe

                let probe_len = (block_size as usize).min(max_size);
                scratch2.clear();
                scratch2.resize(probe_len, 0);

                //
                // A failed probe read here is treated as "read nothing",
                // not as "bail out", unlike the extents branch.
                //
                let n = self.read_at_offset(scratch2, first as u64 * block_size).unwrap_or(0);
                if binary_probe(&scratch2[..n], file_size) {
                    return Ok(false); // binary
                }

                buf.extend_from_slice(&scratch2[..n]);
                skip_first = n;
            }

            let mut total = 0usize;

            for &block_num in blocks.iter() {
                if block_num == 0 || block_num as u64 >= self.max_block { continue; }
                if total >= max_size { break; }

                let remaining = max_size - total;
                let mut to_read = (block_size as usize).min(remaining);
                let mut disk_offset = block_num as u64 * block_size;

                if skip_first > 0 {
                    let skip = skip_first.min(to_read);
                    disk_offset += skip as u64;
                    to_read     -= skip;
                    total       += skip;
                    skip_first  -= skip;
                    if to_read == 0 { continue; }
                }

                crate::parser::push_chunk(scratch_chunks, disk_offset, to_read as _);
                total += to_read;
            }

            Ok(true)
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
            let inode     = unsafe { (buf.as_ptr().add(offset) as *const u32).read_unaligned() }.to_le();
            let rec_len   = unsafe { (buf.as_ptr().add(offset + 4) as *const u16).read_unaligned() }.to_le() as usize;
            let name_len  = buf[offset + 6];
            let file_type = buf[offset + 7];

            //
            // ext4 spec: rec_len is always a multiple of 4 and at least entry_size.
            // Slack space can violate this. Bail the block rather than desync offset
            // or crawl through garbage one byte at a time.
            //
            if unlikely(rec_len == 0 || rec_len < entry_size || rec_len & 3 != 0) {
                break;
            }

            let old_offset = offset;
            offset += rec_len;

            if unlikely(inode == 0 || name_len == 0) {
                continue;
            }

            let name_start = old_offset + entry_size;
            let name_end = name_start + name_len as usize;

            if name_end > old_offset + rec_len || name_end > buf.len() {
                continue;
            }

            let file_type = match file_type {
                EXT4_FT_REG_FILE => FileType::File,
                EXT4_FT_DIR => FileType::Dir,
                _ => FileType::Other,
            };

            match callback(inode as FileId, name_start, name_len as usize, file_type) {
                ControlFlow::Break(b) => return Some(b),
                ControlFlow::Continue(_) => {}
            }
        }

        None
    }
}

// ext4-specific helper methods
impl Ext4Fs {
    #[inline]
    pub fn inode_disk_offset(&self, inode_num: u64) -> u64 {
        let group = (inode_num - 1) / self.sb.inodes_per_group as u64;
        let index = (inode_num - 1) % self.sb.inodes_per_group as u64;
        self.inode_table_blocks[group as usize] * self.sb.block_size as u64
            + index * self.sb.inode_size as u64
    }

    /// Read inline data from inode's block array (max 60 bytes)
    #[inline]
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

        if check_binary && binary_probe(&inline_bytes[..actual_size], actual_size) {
            return Ok(false);
        }

        let buf = parser.get_buf_mut(kind);
        buf.extend_from_slice(&inline_bytes[..actual_size]);
        Ok(true)
    }

    #[inline]
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

    #[inline]
    fn scratch_as_extents(scratch: &[u8]) -> &[Ext4Extent] {
        bytemuck::cast_slice(scratch)
    }

    fn parse_extent_node_into(
        &self,
        scratch: &mut Vec<u8>,
        data: &[u8],
        level: usize,
    ) -> io::Result<()> {
        let _span = tracy::span!("Ext4Fs::parse_extent_node");

        if unlikely(data.len() < mem::size_of::<raw::Ext4ExtentHeader>()) {
            return Ok(());
        }

        const EXT4_MAX_EXTENT_DEPTH: usize = 5;
        if unlikely(level > EXT4_MAX_EXTENT_DEPTH) {
            return Ok(());
        }

        //
        // SAFETY: bounds checked above. read_unaligned makes the alignment
        // of `data` irrelevant, so a stack allocated `probe` array
        // (1 byte aligned) is fine here.
        //
        let eh_magic   = unsafe { read_u16_unaligned_le(data, 0) };
        let eh_entries = unsafe { read_u16_unaligned_le(data, 2) };
        let eh_depth   = unsafe { read_u16_unaligned_le(data, 6) };

        if unlikely(u16::from_le(eh_magic) != EXT4_EXTENT_MAGIC) {
            return Ok(());
        }

        if eh_depth == 0 {
            let extent_size = mem::size_of::<raw::Ext4Extent>();
            let extents_start = mem::size_of::<raw::Ext4ExtentHeader>();

            for i in 0..eh_entries as usize {
                let offset = extents_start + i * extent_size;
                if unlikely(offset + extent_size > data.len()) {
                    break;
                }

                let ee_len      = unsafe { read_u16_unaligned_le(data, offset + 4) };
                let ee_start_hi = unsafe { read_u16_unaligned_le(data, offset + 6) };
                let ee_start_lo = unsafe { read_u32_unaligned_le(data, offset + 8) };

                let start_block = ((ee_start_hi as u64) << 32) | (ee_start_lo as u64);

                if likely(ee_len > 0 && ee_len <= 32768) {
                    let extent = Ext4Extent {
                        start: start_block,
                        len: ee_len,
                        _pad: [0; 6],
                    };
                    let bytes = bytemuck::bytes_of(&extent);
                    scratch.extend_from_slice(bytes);
                }
            }
        } else {
            let mut child_blocks = SmallVec::<[u64; 16]>::new(); // @Memory @Speed...?

            let index_size    = mem::size_of::<raw::Ext4ExtentIdx>();
            let indices_start = mem::size_of::<raw::Ext4ExtentHeader>();

            for i in 0..eh_entries as usize {
                let offset = indices_start + i * index_size;
                if unlikely(offset + index_size > data.len()) {
                    break;
                }

                let ei_leaf_lo = unsafe { read_u32_unaligned_le(data, offset + 4) };
                let ei_leaf_hi = unsafe { read_u16_unaligned_le(data, offset + 8) };

                let leaf_block = ((ei_leaf_hi as u64) << 32) | (ei_leaf_lo as u64);
                child_blocks.push(leaf_block);
            }

            for child_block in child_blocks {
                let mut probe = [0u8; 8192];  // ext4 block size is at most 8192 bytes
                let probe = &mut probe[..self.sb.block_size as usize];

                let offset = child_block * self.sb.block_size as u64;
                if self.read_at_offset(probe, offset).is_ok() {
                    self.parse_extent_node_into(scratch, probe, level + 1)?;
                }
            }
        }

        Ok(())
    }
}

#[inline(always)]
unsafe fn read_u16_unaligned_le(data: &[u8], offset: usize) -> u16 {
    unsafe { (data.as_ptr().add(offset) as *const u16).read_unaligned().to_le() }
}

#[inline(always)]
unsafe fn read_u32_unaligned_le(data: &[u8], offset: usize) -> u32 {
    unsafe { (data.as_ptr().add(offset) as *const u32).read_unaligned().to_le() }
}
