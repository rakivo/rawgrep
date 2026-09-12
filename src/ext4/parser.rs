//! ext4 filesystem implementation of RawFs trait

use crate::{tracy, util};
use crate::util::{likely, unlikely, read_u16_unaligned_le, read_u32_unaligned_le, read_u8_unaligned};
use crate::grep::{AnyNodeScratch, AnyNodeCache, NodeCacheStats};
use crate::parser::{BufFatPtr, BufKind, FileId, FileNode, FileType, Parser, RawFs, binary_probe, FastDivU32};
use crate::worker::STREAMING_CHUNK_SIZE;

use super::*;

#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::fs::File;
use std::{io, mem};
use std::ops::ControlFlow;

pub struct InodeBlockCache {
    pub buf: Box<[u8; 8192]>,
    pub block_start: u64, // u64::MAX = empty
}

impl Default for InodeBlockCache {
    fn default() -> Self {
        Self {
            buf: {
                let b: Box<std::mem::MaybeUninit<_>> = Box::new_uninit();
                unsafe { b.assume_init() } // buf is only ever written before being read
            },
            block_start: u64::MAX,
        }
    }
}

/// Ext4 filesystem context
pub struct Ext4Fs {
    pub file: File,
    pub sb: Ext4SuperBlock,
    pub device_id: u64,
    pub max_block: u64,
    pub dont_skip_dot_entries: bool,
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
    type NodeCache = InodeBlockCache;

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
    fn parse_nodes_batch(
        &self,
        entries: &[(FileId, BufFatPtr)],
        cache: &mut InodeBlockCache,
        out: &mut Vec<io::Result<Ext4Inode>>,
    ) -> NodeCacheStats {
        let block_size = self.sb.block_size as u64;
        let inode_size = self.sb.inode_size as usize;

        let mut stats = NodeCacheStats::default();

        for &(file_id, _) in entries {
            let inode_num = file_id as INodeNum;
            if unlikely(inode_num == 0) {
                out.push(Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid inode number 0")));
                continue;
            }

            let inode_offset = self.inode_disk_offset(file_id);
            let block_start = (inode_offset / block_size) * block_size;

            if block_start != cache.block_start {
                stats.misses += 1;

                let read_len = (block_size as usize).min(cache.buf.len());
                if let Err(e) = self.read_at_offset(&mut cache.buf[..read_len], block_start) {
                    out.push(Err(e));  // @Speed: How much of these actually out there?... We most likely just should return the first error.
                    continue;
                }

                cache.block_start = block_start;
            } else {
                stats.hits += 1;
            }

            let in_block = (inode_offset - block_start) as usize;
            let end = (in_block + inode_size).min(cache.buf.len());
            out.push(Self::decode_inode(inode_num as u64, &cache.buf[in_block..end], self.sb.inode_size));
        }

        stats
    }

    #[inline]
    fn parse_node(&self, file_id: FileId) -> io::Result<Ext4Inode> {
        let _span = tracy::span!("Ext4Fs::parse_node");

        let inode_offset = self.inode_disk_offset(file_id);

        let mut buf = std::mem::MaybeUninit::<[u8; 256]>::uninit();
        let buf = unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, self.sb.inode_size as usize)
        };

        self.read_at_offset(buf, inode_offset as _)?;

        Self::decode_inode(file_id as u64, buf, self.sb.inode_size)
    }

    #[inline(always)]
    fn sort_entries_by_offset(&self, entries: &mut [(FileId, BufFatPtr)]) {
        #[cfg(feature = "profile-sort-lens")]
        eprintln!("{}", entries.len());

        entries.sort_unstable_by_key(|(file_id, _)| self.inode_disk_offset(*file_id));
    }

    #[inline]
    #[allow(clippy::uninit_vec)]
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
            &mut parser.scratch3,
            &mut parser.scratch_chunks,
            node,
            size_to_read,
            check_binary,
            buf
        )? {
            parser.get_buf_mut(kind).clear();
            return Ok(false);
        }

        buf.reserve(size_to_read);

        #[cfg(unix)]
        let fd = self.file.as_raw_fd();

        #[cfg(unix)]
        const PREFETCH_AHEAD: usize = 4;

        #[cfg(unix)]
        {
            for &(offset, len) in parser.scratch_chunks.iter().take(PREFETCH_AHEAD) {
                unsafe {
                    libc::posix_fadvise(
                        fd, offset as i64, len as i64,
                        libc::POSIX_FADV_WILLNEED
                    );
                }
            }
        }

        //
        // Index of the furthest chunk already fadvise'd (by the burst above).
        // The rolling hint below only ever advances this -- it must never
        // re-hint a range the burst (or a prior iteration) already covered.
        //
        #[cfg(unix)]
        let mut hinted_up_to = PREFETCH_AHEAD.min(parser.scratch_chunks.len());

        for (i, &(disk_offset, len)) in parser.scratch_chunks.iter().enumerate() {
            #[cfg(unix)] {
                let want = i + 1;
                if want >= hinted_up_to {
                    if let Some(&(next_offset, next_len)) = parser.scratch_chunks.get(want) {
                        unsafe {
                            libc::posix_fadvise(
                                fd, next_offset as i64, next_len as i64,
                                libc::POSIX_FADV_WILLNEED
                            );
                        }
                    }

                    hinted_up_to = want + 1;
                }
            }

            let buf = Parser::get_buf_mut_impl(&mut parser.file, &mut parser.dir, &mut parser.gitignore, kind);

            let old_len = buf.len();
            let new_len = old_len + len as usize;

            unsafe { buf.set_len(new_len); }  // @ProbablySafe...

            match self.read_at_offset(unsafe { buf.get_unchecked_mut(old_len..) }, disk_offset) {
                Ok(n) => buf.truncate(old_len + n),
                Err(_) => { buf.truncate(old_len); break; }
            }
        }

        parser.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    #[allow(clippy::uninit_vec)]
    #[inline(always)]
    fn collect_file_chunks(
        &self,
        scratch:  &mut Vec<u8>,
        scratch2: &mut Vec<u8>,  // Probe buffer, only touched (and only sized) when check_binary
        scratch3: &mut Vec<u64>, // For children blocks
        scratch_chunks: &mut Vec<(u64, u32)>,
        node: &Ext4Inode,
        max_size: usize,
        check_binary: bool,
        buf: &mut Vec<u8>,       // Destination buffer -- probed bytes get written straight in here
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
            let block_bytes = util::cast_slice(&node.blocks);
            self.parse_extent_node_into(scratch, scratch3, block_bytes, 0)?;

            let extents = Self::scratch_as_extents(scratch);

            //
            // Bytes of the very first extent already pulled into 'buf' by the probe below,
            // still owed to the chunk-building loop as a "skip" so it doesn't re-read them.
            //
            let mut skip_first = 0usize;

            if check_binary && let Some(first) = extents.first() {
                // Binary check

                let probe_len = (block_size as usize).min(max_size);
                buf.reserve(probe_len);
                unsafe { buf.set_len(probe_len); }  // @ProbablySafe...

                let offset = first.start * block_size;
                match self.read_at_offset(unsafe { buf.get_unchecked_mut(..probe_len) }, offset) {
                    Ok(n) => {
                        buf.truncate(n);
                        debug_assert!(buf.len() >= n);

                        if binary_probe(unsafe { buf.get_unchecked(..n) }, file_size) {
                            buf.clear();
                            return Ok(false);                    // binary
                        }

                        skip_first = n;
                    }

                    Err(_) => { buf.clear(); return Ok(true); }  // unreachable
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

            let blocks = unsafe { node.blocks.get_unchecked(..EXT4_BLOCK_POINTERS_COUNT) };

            if blocks.iter().all(|&b| b == 0 || b as u64 >= self.max_block) {
                return Ok(true);
            }

            let mut skip_first = 0usize;

            if check_binary && let Some(&first) = blocks.iter().find(|&&b| b != 0 && (b as u64) < self.max_block) {
                // Binary probe

                let probe_len = (block_size as usize).min(max_size);
                scratch2.clear();
                scratch2.reserve(probe_len);
                unsafe { scratch2.set_len(probe_len); }  // @ProbablySafe...

                //
                // A failed probe read here is treated as "read nothing",
                // not as "bail out", unlike the extents branch.
                //
                let n = self.read_at_offset(scratch2, first as u64 * block_size).unwrap_or(0);

                debug_assert!(scratch2.len() >= n);
                let probe = unsafe { scratch2.get_unchecked(..n) };

                if binary_probe(probe, file_size) {
                    return Ok(false); // binary
                }

                buf.extend_from_slice(probe);
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

                if let Some(last) = scratch_chunks.last_mut() {
                    if last.0 + last.1 as u64 == disk_offset {
                        last.1 += to_read as u32;
                        total += to_read;
                        continue;
                    }
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
        const ENTRY_SIZE: usize = mem::size_of::<raw::Ext4DirEntry2>();

        while offset + ENTRY_SIZE <= buf.len() {
            let inode     = read_u32_unaligned_le(buf, offset);
            let rec_len   = read_u16_unaligned_le(buf, offset + 4) as usize;
            let name_len  = read_u8_unaligned(    buf, offset + 6);
            let file_type = read_u8_unaligned(    buf, offset + 7);

            //
            // ext4 spec: rec_len is always a multiple of 4 and at least ENTRY_SIZE.
            // Slack space can violate this. Bail the block rather than desync offset
            // or crawl through garbage one byte at a time.
            //
            if unlikely(rec_len == 0 || rec_len < ENTRY_SIZE || rec_len & 3 != 0) {
                break;
            }

            let old_offset = offset;
            offset += rec_len;

            if unlikely(inode == 0 || name_len == 0) {
                continue;
            }

            let name_start = old_offset + ENTRY_SIZE;
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

    #[inline]
    fn directory_entry_count_hint(&self, buf: &[u8]) -> usize {
        // 8-byte fixed header + 1-byte name, rounded up to ext4's 4-byte rec_len alignment.
        const MIN_ENTRY: usize = 12;
        buf.len() / MIN_ENTRY
    }

    #[inline]
    fn take_node_scratch(&self, shared: &mut AnyNodeScratch) -> Vec<io::Result<Ext4Inode>> {
        match std::mem::replace(shared, AnyNodeScratch::Ext4(Vec::new())) {
            AnyNodeScratch::Ext4(v) => v,
            _ => Vec::new(), // Last job on this thread was a different FS...
        }
    }

    #[inline]
    fn take_node_cache(&self, shared: &mut AnyNodeCache) -> InodeBlockCache {
        match std::mem::replace(shared, AnyNodeCache::Ext4(InodeBlockCache::default())) {
            AnyNodeCache::Ext4(c) => c,
            _ => InodeBlockCache::default(),
        }
    }

    #[inline]
    fn erase_node_scratch(&self, scratch: Vec<io::Result<Ext4Inode>>) -> AnyNodeScratch { AnyNodeScratch::Ext4(scratch) }

    #[inline]
    fn erase_node_cache(&self, cache: InodeBlockCache) -> AnyNodeCache { AnyNodeCache::Ext4(cache) }
}

// ext4-specific helper methods
impl Ext4Fs {
    #[inline(always)]
    pub fn inode_disk_offset(&self, inode_num: u64) -> u64 {
        let (group, index) = self.sb.inodes_per_group_recip.divmod(inode_num - 1);

        debug_assert!(self.inode_table_blocks.len() >= group as usize);

        unsafe {
            self.inode_table_blocks.get_unchecked(group as usize)
            * self.sb.block_size as u64
            + index * self.sb.inode_size as u64
        }
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
        let inline_bytes: &[u8] = util::cast_slice(&node.blocks);
        let actual_size = size_to_read.min(inline_bytes.len());

        let inline_bytes = unsafe { inline_bytes.get_unchecked(..actual_size) };
        if check_binary && binary_probe(inline_bytes, actual_size) {
            return Ok(false);
        }

        let buf = parser.get_buf_mut(kind);
        buf.extend_from_slice(inline_bytes);
        Ok(true)
    }

    #[inline]
    pub fn parse_superblock(data: &[u8]) -> io::Result<Ext4SuperBlock> {
        let _span = tracy::span!("Ext4Fs::parse_superblock");

        let block_size_log = read_u32_unaligned_le(data, EXT4_BLOCK_SIZE_OFFSET);

        let block_size = 1024 << block_size_log;

        let blocks_per_group = read_u32_unaligned_le(data, EXT4_BLOCKS_PER_GROUP_OFFSET);

        let inodes_per_group = read_u32_unaligned_le(data, EXT4_INODES_PER_GROUP_OFFSET);

        let inode_size = read_u16_unaligned_le(data, EXT4_INODE_SIZE_OFFSET);

        let desc_size = if data.len() > EXT4_DESC_SIZE_OFFSET + 1 {
            let ds = read_u16_unaligned_le(data, EXT4_DESC_SIZE_OFFSET);
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
            inodes_per_group_recip: FastDivU32::new(inodes_per_group)
        })
    }

    #[inline]
    fn scratch_as_extents(scratch: &[u8]) -> &[Ext4Extent] {
        util::cast_slice(scratch)
    }

    fn parse_extent_node_into(
        &self,
        scratch: &mut Vec<u8>,
        child_blocks: &mut Vec<u64>,
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
        let eh_magic   = read_u16_unaligned_le(data, 0);
        let eh_entries = read_u16_unaligned_le(data, 2);
        let eh_depth   = read_u16_unaligned_le(data, 6);

        if unlikely(u16::from_le(eh_magic) != EXT4_EXTENT_MAGIC) {
            return Ok(());
        }

        scratch.reserve(eh_entries as usize * mem::size_of::<raw::Ext4Extent>());

        if eh_depth == 0 {
            let extent_size   = mem::size_of::<raw::Ext4Extent>();
            let extents_start = mem::size_of::<raw::Ext4ExtentHeader>();

            for i in 0..eh_entries as usize {
                let offset = extents_start + i * extent_size;
                if unlikely(offset + extent_size > data.len()) {
                    break;
                }

                let ee_len      = read_u16_unaligned_le(data, offset + 4);
                let ee_start_hi = read_u16_unaligned_le(data, offset + 6);
                let ee_start_lo = read_u32_unaligned_le(data, offset + 8);

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
            const INDEX_SIZE:    usize = mem::size_of::<raw::Ext4ExtentIdx>();
            const INDICES_START: usize = mem::size_of::<raw::Ext4ExtentHeader>();

            let mark = child_blocks.len();

            for i in 0..eh_entries as usize {
                let offset = INDICES_START + i * INDEX_SIZE;
                if unlikely(offset + INDEX_SIZE > data.len()) {
                    break;
                }

                let ei_leaf_lo = read_u32_unaligned_le(data, offset + 4);
                let ei_leaf_hi = read_u16_unaligned_le(data, offset + 8);

                let leaf_block = ((ei_leaf_hi as u64) << 32) | (ei_leaf_lo as u64);
                child_blocks.push(leaf_block);
            }

            let block_size = self.sb.block_size as u64;

            #[cfg(unix)]
            {
                let fd = self.file.as_raw_fd();
                for &cb in &child_blocks[mark..] {
                    unsafe {
                        libc::posix_fadvise(
                            fd,
                            (cb * block_size) as libc::off_t,
                            block_size as libc::off_t,
                            libc::POSIX_FADV_WILLNEED,
                        );
                    }
                }
            }

            let count = child_blocks.len() - mark;

            for child in 0..count {
                let child_block = child_blocks[mark + child];

                let mut probe = std::mem::MaybeUninit::<[u8; 8192]>::uninit();  // ext4 block size is at most 8192 bytes

                let probe = unsafe {
                    std::slice::from_raw_parts_mut(probe.as_mut_ptr() as *mut u8, block_size as usize)
                };

                let offset = child_block * block_size;
                if self.read_at_offset(probe, offset).is_ok() {
                    self.parse_extent_node_into(scratch, child_blocks, probe, level + 1)?;
                }
            }

            child_blocks.truncate(mark);
        }

        Ok(())
    }

    /// Decode one inode from a byte slice already containing its raw record.
    fn decode_inode(inode_num: u64, mode_flags_src: &[u8], inode_size_field: u16) -> io::Result<Ext4Inode> {
        let raw_size = mem::size_of::<raw::Ext4Inode>().min(mode_flags_src.len());
        let raw = bytemuck::try_from_bytes::<raw::Ext4Inode>(  // @Speed
            &mode_flags_src[..raw_size]
        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid inode data"))?;

        let mode      = u16::from_le(raw.mode);
        let size_low  = u32::from_le(raw.size_lo);
        let flags     = u32::from_le(raw.flags);
        let mtime_sec = u32::from_le(raw.mtime) as i64;

        let size_high = if inode_size_field > 128 {
            u32::from_le(raw.size_high)
        } else {
            0
        };

        let size = ((size_high as u64) << 32) | (size_low as u64);

        #[cfg(target_endian = "little")]
        let blocks: [u32; 15] = bytemuck::cast(raw.block);

        #[cfg(target_endian = "big")]
        let blocks: [u32; 15] = {
            let raw_block = [raw.block];
            let block_bytes = util::cast_slice::<[[u8; 12]; 5], u8>(&raw_block);
            let as_u32: &[u32] = util::cast_slice(block_bytes);
            std::array::from_fn(|i| u32::from_le(as_u32[i]))
        };

        Ok(Ext4Inode { inode_num, mode, size, flags, mtime_sec, blocks })
    }
}
