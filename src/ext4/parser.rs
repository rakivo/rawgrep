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

        let mut inode_buf = [0u8; 512]; // inode_size is at most 512 bytes in practice
        let inode_size = self.sb.inode_size as usize;
        let to_read = inode_size.min(inode_buf.len());
        self.read_at_offset(&mut inode_buf[..to_read], inode_offset as _)?;          // @Cache @Syscall

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

        let Some(chunks) = self.collect_file_chunks(
            &mut parser.scratch,
            &mut parser.scratch2,
            node,
            size_to_read,
            check_binary,
            buf
        )? else {
            parser.get_buf_mut(kind).clear();
            return Ok(false);
        };

        for (disk_offset, len) in &chunks {
            let buf = parser.get_buf_mut(kind);
            let old_len = buf.len();
            buf.resize(old_len + len, 0);
            match self.read_at_offset(&mut buf[old_len..], *disk_offset) {
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
        node: &Ext4Inode,
        max_size: usize,
        check_binary: bool,
        buf: &mut Vec<u8>,      // Destination buffer -- probed bytes get written straight in here
    ) -> io::Result<Option<SmallVec<[(u64, usize); 32]>>> {
        let _span = tracy::span!("Ext4Fs::collect_file_chunks");

        let file_size = node.size as usize;
        let block_size = self.sb.block_size as u64;

        // Inline data has no disk offsets - caller handles it via read_file_content
        if node.flags & EXT4_INLINE_DATA_FL != 0 {
            return Ok(Some(SmallVec::new()));
        }

        scratch.clear();

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
                            return Ok(None);                    // binary
                        }

                        buf.extend_from_slice(&scratch2[..n]);
                        skip_first = n;
                    }

                    Err(_) => return Ok(Some(SmallVec::new())), // unreadable
                }
            }

            let mut chunks = SmallVec::new();
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

                    chunks.push((disk_offset, to_read));

                    extent_offset += to_read;
                    total += to_read;
                }
            }

            Ok(Some(chunks))
        } else {
            //
            // Direct blocks
            //

            let blocks = &node.blocks[..EXT4_BLOCK_POINTERS_COUNT];

            if blocks.iter().all(|&b| b == 0 || b as u64 >= self.max_block) {
                return Ok(Some(SmallVec::new()));
            }

            let mut skip_first = 0usize;

            if check_binary && let Some(&first) = blocks.iter().find(|&&b| b != 0 && (b as u64) < self.max_block) {
                // Binary probe

                let probe_len = (block_size as usize).min(max_size);
                scratch2.clear();
                scratch2.resize(probe_len, 0);

                // A failed probe read here is treated as "read nothing",
                // not as "bail out", unlike the extents branch.
                let n = self.read_at_offset(scratch2, first as u64 * block_size).unwrap_or(0);
                if binary_probe(&scratch2[..n], file_size) {
                    return Ok(None); // binary
                }

                buf.extend_from_slice(&scratch2[..n]);
                skip_first = n;
            }

            let mut chunks = SmallVec::new();
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

                chunks.push((disk_offset, to_read));
                total += to_read;
            }

            Ok(Some(chunks))
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

        let header = bytemuck::try_from_bytes::<raw::Ext4ExtentHeader>(
            &data[..mem::size_of::<raw::Ext4ExtentHeader>()]
        ).map_err(|_| io::Error::new(
            io::ErrorKind::InvalidData, "Invalid extent header"
        ))?;

        if unlikely(u16::from_le(header.eh_magic) != EXT4_EXTENT_MAGIC) {
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
            let mut child_blocks = SmallVec::<[u64; 16]>::new();

            let index_size = mem::size_of::<raw::Ext4ExtentIdx>();
            let indices_start = mem::size_of::<raw::Ext4ExtentHeader>();

            for i in 0..entries as usize {
                let offset = indices_start + i * index_size;
                if unlikely(offset + index_size > data.len()) {
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
