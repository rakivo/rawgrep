//! ext4 filesystem implementation of RawFs trait

#[cfg(unix)]
use crate::run_temperature;
use crate::{tracy, util, stale};
use crate::index_::{Index_, IndexMut_};
use crate::binary_verdicts;
use crate::util::{likely, unlikely, read_u16_unaligned_le, read_u32_unaligned_le, read_u64_unaligned_le, read_u64_as_u32_and_u16_unaligned_le};
use crate::grep::NodeCacheStats;
use crate::parser::{BufFatPtr, BufKind, FileNode, FileType, Parser, RawFs, binary_probe, FastDivU32};
use crate::worker::{STREAMING_CHUNK_SIZE, PendingSubdir};

use super::*;

use std::os::fd::{RawFd, AsRawFd};
use std::fs::File;
use std::{io, mem};
use std::ops::ControlFlow;

//
// Cross-file prefetch (see RawFs::prefetch_file_head): how much of the head of a file to hint a few
// files before it is processed. Files up to this size are hinted whole, so both the probe read and
// the read of the rest hit the page cache; bigger ones get their first PREFETCH_HEAD_BYTES
// (the probe plus the start of chunk 0). Bounds the waste on files that then turn out to be binary.
//
#[cfg(unix)]
const PREFETCH_HEAD_BYTES: u64 = 64 * 1024;

//
// Every file in a directory needs its inode decoded before any data is read
// (parse_nodes_batch), and each distinct inode-table block is a synchronous 4K read: queue depth 1
// per thread on a cold cache. The ids are known up front, so hint all the blocks at once.
//
// Every block hinted is one the caller is about to read anyway, so nothing is wasted. The only cost
// is the syscall itself (one per run of adjacent blocks), which is why small batches are skipped.
//
#[cfg(unix)]
const HINT_BATCH_INODES: bool = true;

#[cfg(unix)]
const HINT_SUBDIR_INODES: bool = true;

#[cfg(unix)]
const INODE_HINT_MIN_ENTRIES: usize = 16;

const MAX_EXTENT_DEPTH: usize = 5;

const   EXTENT_SIZE: usize = mem::size_of::<raw::Ext4Extent>();
const    INDEX_SIZE: usize = mem::size_of::<raw::Ext4ExtentIdx>();
const EXTENTS_START: usize = mem::size_of::<raw::Ext4ExtentHeader>();

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
    pub file_as_fd: RawFd,
    pub sb: Ext4SuperBlock,
    pub device_id: u64,
    pub max_block: u64,
    pub inode_table_blocks: Vec<u64>,
}

impl FileNode<ext4::FileId> for Ext4Node {
    const POISONED: Self = Self::POISONED;
    #[inline(always)] fn file_id(&self) -> ext4::FileId { self.hot.file_id() }
    #[inline(always)] fn size(&self) -> u64 { self.hot.size() }
    #[inline(always)] fn mtime_sec(&self) -> i64 { self.hot.mtime_sec() }
    #[inline(always)] fn is_dir(&self) -> bool { self.hot.is_dir() }
}

impl FileNode<ext4::FileId> for Ext4NodeHot {
    const POISONED: Self = Self::POISONED;

    #[inline(always)]
    fn file_id(&self) -> ext4::FileId { self.inode_num }

    #[inline(always)]
    fn size(&self) -> u64 { self.size }

    #[inline(always)]
    fn mtime_sec(&self) -> i64 { self.mtime_sec }

    #[inline(always)]
    fn is_dir(&self) -> bool { (self.mode & super::EXT4_S_IFMT) == super::EXT4_S_IFDIR }
}

impl RawFs for Ext4Fs {
    type Node      = Ext4Node;
    type NodeCold  = Ext4NodeCold;
    type NodeHot   = Ext4NodeHot;
    type NodeCache = InodeBlockCache;
    type FileId    = ext4::FileId;

    const FILE_SYSTEM: crate::grep::FileSystem = crate::grep::FileSystem::Ext4;

    type Context<'b> = &'b Self where Self: 'b;

    #[inline(always)]
    fn device_id(&self) -> u64 { self.device_id }

    #[inline(always)]
    fn device_file(&self) -> &File { &self.file }

    #[inline(always)]
    fn block_size(&self) -> u32 { self.sb.block_size }

    #[inline(always)]
    fn root_id(&self) -> Self::FileId { EXT4_ROOT_INODE }

    #[inline(always)]
    fn read_at_offset(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        crate::util::read_at_offset_impl(self.file_as_fd, buf, offset)
    }

    #[inline(always)]
    fn split_node(&self, node: Self::Node) -> (Self::NodeHot, Self::NodeCold) {
        (node.hot, node.cold)
    }
    #[inline(always)]
    fn merge_node(&self, hot: Self::NodeHot, cold: Self::NodeCold) -> Self::Node {
        Self::Node { hot, cold }
    }

    #[inline(always)]
    fn parse_node_cached(
        &self,
        file_id: Self::FileId,
        cache: &mut InodeBlockCache
    ) -> (io::Result<Ext4Node>, NodeCacheStats) {
        let inode_num = file_id as InodeNum;
        if unlikely(inode_num == 0) {
            return (
                Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid inode number 0")),
                NodeCacheStats::default()
            );
        }

        let block_size = self.sb.block_size as u64;
        let inode_size = self.sb.inode_size as usize;

        let inode_offset = self.inode_disk_offset(file_id as _);
        let block_start  = (inode_offset / block_size) * block_size;

        let mut stats = NodeCacheStats::default();

        if block_start != cache.block_start {
            stats.misses = 1;

            let read_len = (block_size as usize).min(cache.buf.len());
            if let Err(e) = self.read_at_offset(&mut cache.buf[..read_len], block_start) {
                return (Err(e), stats);
            }

            cache.block_start = block_start;
        } else {
            stats.hits = 1;
        }

        let in_block = (inode_offset - block_start) as usize;
        let end = (in_block + inode_size).min(cache.buf.len());
        (Ok(Self::decode_inode(inode_num, &cache.buf[in_block..end], self.sb.inode_size)), stats)
    }

    #[inline(always)]
    fn parse_nodes_batch(
        &self,
        entries: &[(Self::FileId, BufFatPtr)],
        cache: &mut InodeBlockCache,
        hot_out:  &mut Vec<Self::NodeHot>,
        cold_out: &mut Vec<Self::NodeCold>,
    ) -> NodeCacheStats {
        let mut total = NodeCacheStats::default();

        #[cfg(unix)]
        if HINT_BATCH_INODES && entries.len() >= INODE_HINT_MIN_ENTRIES {
            self.hint_inode_blocks(entries.iter().map(|&(file_id, _)| file_id));
        }

        for &(file_id, _) in entries {
            let (node_result, stats) = self.parse_node_cached(file_id, cache);

            let node = match node_result { Ok(node) => node, Err(_) => Ext4Node::POISONED };

            let (hot, cold) = self.split_node(node);

             hot_out.push(hot);
            cold_out.push(cold);

            total.hits   += stats.hits;
            total.misses += stats.misses;
        }

        total
    }

    #[inline]
    fn parse_node(&self, file_id: Self::FileId) -> io::Result<Ext4Node> {
        let _span = tracy::span!("Ext4Fs::parse_node");

        let inode_offset = self.inode_disk_offset(file_id as _);

        let mut buf = std::mem::MaybeUninit::<[u8; 256]>::uninit();
        let buf = unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, self.sb.inode_size as usize)
        };

        self.read_at_offset(buf, inode_offset as _)?;

        Ok(Self::decode_inode(file_id as InodeNum, buf, self.sb.inode_size))
    }

    #[inline(always)]
    fn sort_entries_by_offset(&self, entries: &mut [(Self::FileId, BufFatPtr)]) {
        #[cfg(feature = "profile-sort-lens")]
        eprintln!("{}", entries.len());

        entries.sort_unstable_by_key(|(file_id, _)| self.inode_disk_offset(*file_id));
    }

    #[inline(always)]
    fn sort_subdirs_by_offset(&self, subdirs: &mut [PendingSubdir<Self::FileId>]) {
        subdirs.sort_unstable_by_key(|subdir| self.inode_disk_offset(subdir.file_id));

        //
        // These get their inode read later, when they're popped (possibly by another worker), so
        // there's time for the hint to land. The page cache is shared between threads.
        //
        #[cfg(unix)]
        if HINT_SUBDIR_INODES {
            self.hint_inode_blocks(subdirs.iter().map(|subdir| subdir.file_id));
        }
    }

    // Is the head of this file already in the page cache? None: can't tell yet, so callers assume cold.
    #[cfg(unix)]
    #[inline]
    fn head_is_cold(&self, node: &Ext4Node, max_size: usize) -> Option<bool> {
        use run_temperature::{DATA, HEAD_SAMPLE_BYTES};

        if DATA.want_sample() {
            let sampled = match self.head_hint_range(node, max_size) {
                Some((offset, _)) => {
                    let len = HEAD_SAMPLE_BYTES.min(max_size as u64).max(1);
                    self.sample_temperature(&DATA, offset, len, false).is_some()
                }
                None => false,
            };

            // Nothing to go on yet: the batch asks again on its next file
            if !sampled && DATA.is_unknown() { return None; }
        }

        Some(!DATA.is_warm())
    }

    //
    // Called by the worker a few files ahead of the one being processed, for files it is going
    // to read. The inode is already decoded, and for a depth-0 extent tree the first extent
    // lives in it, so finding the disk location costs no I/O. Deeper trees are skipped: locating
    // their first extent needs a read, which would defeat the point.
    //
    #[cfg(unix)]
    #[inline]
    fn prefetch_file_head(&self, node: &Ext4Node, max_size: usize) {
        let Some((offset, len)) = self.head_hint_range(node, max_size) else {
            return;
        };

        debug_assert!(offset + len <= self.max_block * self.sb.block_size as u64);

        unsafe {
            libc::posix_fadvise(
                self.file.as_raw_fd(),
                offset as libc::off_t,
                len    as libc::off_t,
                libc::POSIX_FADV_WILLNEED
            );
        }
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
        likely_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("Ext4Fs::read_file_content");

        let buf = crate::parser::get_buf_mut!(parser, kind);
        buf.clear();

        let file_size = node.size() as usize;
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
            likely_binary,
            buf
        )? {
            parser.get_buf_mut(kind).clear();
            return Ok(false);
        }

        buf.reserve(size_to_read);

        #[cfg(unix)]
        let fd = self.device_file().as_raw_fd();

        #[cfg(unix)]
        const PREFETCH_AHEAD: usize = 4;

        //
        // A file read from process_files had the head of its data hinted a few files earlier
        // or deliberately not, if that batch looked warm. Either way a chunk that lies entirely
        // inside that range needs no second hint. Directories and other reads (kind != File) never got one,
        // so they're hinted here.
        //
        #[cfg(unix)]
        let covered = if matches!(kind, BufKind::File) { self.head_hint_range(node, size_to_read) } else { None };

        #[cfg(unix)]
        let already_hinted = |offset: u64, len: u32| {
            covered.is_some_and(|(start, covered_len)| offset >= start && offset + len as u64 <= start + covered_len)
        };

        #[cfg(unix)]
        {
            for &(offset, len) in parser.scratch_chunks.iter().take(PREFETCH_AHEAD) {
                if already_hinted(offset, len) { continue; }

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
                        if !already_hinted(next_offset, next_len) {
                            unsafe {
                                libc::posix_fadvise(
                                    fd, next_offset as i64, next_len as i64,
                                    libc::POSIX_FADV_WILLNEED
                                );
                            }
                        }
                    }

                    hinted_up_to = want + 1;
                }
            }

            let buf = crate::parser::get_buf_mut!(parser, kind);

            let old_len = buf.len();
            let new_len = old_len + len as usize;

            unsafe { buf.set_len(new_len); }  // @ProbablySafe...

            match self.read_at_offset(buf.get_mut_(old_len..), disk_offset) {
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
        node: &Ext4Node,
        max_size: usize,
        check_binary: bool,
        likely_binary: bool,
        buf: &mut Vec<u8>,       // Destination buffer -- probed bytes get written straight in here
    ) -> io::Result<bool> {
        #[inline]
        fn first_read_len(block_size: usize, max_size: usize, likely_binary: bool) -> usize {
            let cap = if likely(!likely_binary) {
                const SMALL_FILE_ONE_SHOT_CAP: usize = 64 * 1024;

                //
                // The file isn't likely to be binary, so read more on the first read
                //
                block_size.max(SMALL_FILE_ONE_SHOT_CAP)
            } else {
                binary_verdicts::PROBE_BYTES
            };

            max_size.min(cap)
        }

        let _span = tracy::span!("Ext4Fs::collect_file_chunks");

        let file_size = node.size() as usize;
        let block_size = self.sb.block_size as u64;

        // Inline data has no disk offsets - caller handles it via read_file_content
        if node.flags & EXT4_INLINE_DATA_FL != 0 {
            return Ok(true);
        }

        scratch.clear();
        scratch_chunks.clear();

        if node.flags & EXT4_EXTENTS_FL != 0 {
            let block_bytes = util::cast_slice(&node.cold.blocks);

            //
            // Probe before walking the whole extent tree. A depth-0 tree lives in the inode, so
            // finding the first extent is free; a deeper one costs one block read per level down
            // the leftmost path, instead of reading (and hinting) every index and leaf block.
            //
            // If the first extent can't be found cheaply we fall back and parse and then probe it
            //
            let mut parsed = false;

            //
            // @Volatile
            //
            // The device's page cache can hold pre-edit copies of this file's data blocks
            // (writeback goes around it), so a file that may have changed since boot gets its clean device pages
            // dropped before anything below reads them. See `crate::stale`.
            //
            // This needs the whole extent list, so it's parsed here rather than after the probe.
            //
            #[cfg(target_os = "linux")]
            if unlikely(!node.is_dir() && stale::needs_invalidation(node.file_id() as _, node.cold.ctime_sec)) {
                self.parse_extent_node_into(scratch, scratch3, block_bytes, 0)?;
                parsed = true;

                let ok = self.drop_stale_extents(Self::scratch_as_extents(scratch), max_size);
                stale::note_invalidated(node.file_id() as _, node.cold.ctime_sec, ok && max_size >= file_size);
            }

            let mut first_start = if !check_binary {
                None
            } else if parsed {
                Self::scratch_as_extents(scratch).first().map(|e| e.start)
            } else {
                self.first_extent_start(block_bytes)
            };

            if check_binary && first_start.is_none() && !parsed {
                self.parse_extent_node_into(scratch, scratch3, block_bytes, 0)?;
                parsed = true;

                first_start = Self::scratch_as_extents(scratch).first().map(|e| e.start);
            }

            //
            // Bytes of the very first extent already pulled into 'buf' by the probe below,
            // still owed to the chunk-building loop as a 'skip' so it doesn't re-read them.
            //
            let mut skip_first = 0usize;

            if let Some(first_start) = first_start {
                //
                // Binary probe
                //

                let probe_len = first_read_len(block_size as usize, max_size, likely_binary);
                buf.reserve(probe_len);
                unsafe { buf.set_len(probe_len); }  // @ProbablySafe...

                let offset = first_start * block_size;
                match self.read_at_offset(buf.get_mut_(..probe_len), offset) {
                    Ok(n) => {
                        buf.truncate(n);

                        if binary_probe(buf.get_(..n), file_size) {
                            buf.clear();
                            return Ok(false);                    // binary
                        }

                        skip_first = n;
                    }

                    Err(_) => { buf.clear(); return Ok(true); }  // unreachable
                }
            }

            if !parsed {
                self.parse_extent_node_into(scratch, scratch3, block_bytes, 0)?;
            }

            let extents = Self::scratch_as_extents(scratch);

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
                    }

                    if to_read == 0 { continue; }

                    //
                    // Merge disk-contiguous pieces into one chunk (fewer preads for the buffered path),
                    // but never past what the u32 length can hold ... a contiguous file over 4 gigs
                    // used to wrap silently here.
                    //
                    // The streaming path additionally splits chunks down to STREAMING_CHUNK_SIZE,
                    // see split_chunks in worker. Most likely that should be done here for @Speed...
                    //
                    if let Some(last) = scratch_chunks.last_mut() {
                        if last.0 + last.1 as u64 == disk_offset
                        && last.1 as u64 + to_read as u64 <= u32::MAX as u64
                        {
                            last.1 += to_read as u32;

                            total += to_read;
                            extent_offset += to_read;

                            continue;
                        }
                    }

                    crate::parser::push_chunk(scratch_chunks, disk_offset, to_read as u32);

                    total += to_read;
                    extent_offset += to_read;
                }
            }

            return Ok(true)
        }

        //
        //
        // Direct blocks
        //
        //

        let blocks = node.cold.blocks.get_(..EXT4_BLOCK_POINTERS_COUNT);

        if blocks.iter().all(|&b| b == 0 || b as u64 >= self.max_block) {
            return Ok(true);
        }

        //
        // Same as in the extents branch ...
        //
        #[cfg(target_os = "linux")]
        if unlikely(!node.is_dir() && stale::needs_invalidation(node.file_id() as _, node.cold.ctime_sec)) {
            let mut left = max_size as u64;
            let mut ok   = true;

            for &b in blocks.iter() {
                if b == 0 || b as u64 >= self.max_block { continue; }
                if left == 0 { break; }

                let n = left.min(block_size);
                left -= n;

                ok &= self.drop_stale_range(b as u64 * block_size, n);
            }

            stale::note_invalidated(node.file_id() as _, node.cold.ctime_sec, ok && max_size >= file_size);
        }

        let mut skip_first = 0usize;

        if check_binary && let Some(&first) = blocks.iter().find(|&&b| b != 0 && (b as u64) < self.max_block) {
            //
            // Binary probe
            //

            let probe_len = first_read_len(block_size as usize, max_size, likely_binary);
            scratch2.clear();
            scratch2.reserve(probe_len);
            unsafe { scratch2.set_len(probe_len); }  // @ProbablySafe...

            //
            // A failed probe read here is treated as 'read nothing', not as 'bail out',
            // unlike the extents branch above.
            //
            let n = self.read_at_offset(scratch2, first as u64 * block_size).unwrap_or(0);

            let probe = scratch2.get_(..n);

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
                if last.0 + last.1 as u64 == disk_offset
                    && last.1 as u64 + to_read as u64 <= u32::MAX as u64
                {
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

    fn with_directory_entries<R>(
        &self,
        buf: &[u8],
        mut callback: impl FnMut(Self::FileId, usize, usize, FileType) -> ControlFlow<R>
    ) -> Option<R> {
        let _span = tracy::span!("Ext4Fs::with_directory_entries");

        let mut offset = 0;
        const ENTRY_SIZE: usize = mem::size_of::<raw::Ext4DirEntry2>();

        while offset + ENTRY_SIZE <= buf.len() {
            let word      = read_u64_unaligned_le(buf, offset);

            let inode     = word as u32;
            let rec_len   = ((word >> 32) & 0xFFFF) as usize; // +4
            let name_len  = ((word >> 48) & 0xFF)   as u8;    // +6
            let file_type = ((word >> 56) & 0xFF)   as u8;    // +7

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
                EXT4_FT_DIR      => FileType::Dir,
                _ => FileType::Other,
            };

            match callback(inode, name_start, name_len as usize, file_type) {
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

    crate::impl_node_scratch!(Ext4);
}

// ext4-specific helper methods
impl Ext4Fs {
    #[inline(always)]
    pub fn inode_disk_offset(&self, inode_num: u32) -> u64 {
        let (group, index) = self.sb.inodes_per_group_recip.divmod(inode_num as u64 - 1);

        self.inode_table_blocks.get_(group as usize)
            * self.sb.block_size as u64
            + index * self.sb.inode_size as u64
    }

    /// Read inline data from inode's block array (max 60 bytes)
    #[inline]
    fn read_inline_data(
        &self,
        parser: &mut Parser,
        node: &Ext4Node,
        size_to_read: usize,
        kind: BufKind,
        check_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("Ext4Fs::read_inline_data");

        // blocks array is [u32; 15] = 60 bytes of inline data
        let inline_bytes: &[u8] = util::cast_slice(&node.cold.blocks);
        let actual_size = size_to_read.min(inline_bytes.len());

        let inline_bytes = inline_bytes.get_(..actual_size);
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

        let block_size_log   = read_u32_unaligned_le(data, EXT4_BLOCK_SIZE_OFFSET);
        let blocks_per_group = read_u32_unaligned_le(data, EXT4_BLOCKS_PER_GROUP_OFFSET);
        let inodes_per_group = read_u32_unaligned_le(data, EXT4_INODES_PER_GROUP_OFFSET);
        let inode_size       = read_u16_unaligned_le(data, EXT4_INODE_SIZE_OFFSET);

        let desc_size = if data.len() > EXT4_DESC_SIZE_OFFSET + 1 {
            let ds = read_u16_unaligned_le(data, EXT4_DESC_SIZE_OFFSET);
            if ds >= 32 { ds } else { 32 }
        } else {
            32
        };

        Ok(Ext4SuperBlock {
            block_size: 1024 << block_size_log,
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

        if unlikely(data.len() < EXTENTS_START) {
            return Ok(());
        }

        if unlikely(level > MAX_EXTENT_DEPTH) {
            return Ok(());
        }

        let Some((eh_entries, eh_depth)) = parse_extent_header(data) else {
            return Ok(());
        };

        scratch.reserve(eh_entries as usize * EXTENT_SIZE);

        if eh_depth == 0 {
            for_each_valid_leaf_extent(data, eh_entries, |start, len| {
                let extent = Ext4Extent { start, len, _pad: [0; 6] };
                let bytes  = util::cast_slice(core::slice::from_ref(&extent));
                scratch.extend_from_slice(bytes);
                false  // Keep collecting
            });

            return Ok(());
        }

        let mark = child_blocks.len();

        for i in 0..eh_entries as usize {
            match extent_index_child_block(data, i) {
                Some(leaf_block) => child_blocks.push(leaf_block),
                None => break,
            }
        }

        let block_size = self.sb.block_size as u64;

        //
        // Queue every child index block up front so they load concurrently while we work
        // through them in order below.
        //
        #[cfg(unix)]
        {
            let fd = self.device_file().as_raw_fd();
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

        let mut probe = std::mem::MaybeUninit::<[u8; 8192]>::uninit();  // ext4 block size is at most 8192 bytes  // @Memory @Speed

        for child in 0..count {
            let child_block = child_blocks[mark + child];

            let probe = unsafe {
                std::slice::from_raw_parts_mut(probe.as_mut_ptr() as *mut u8, block_size as usize)
            };

            let offset = child_block * block_size;
            if self.read_at_offset(probe, offset).is_ok() {
                self.parse_extent_node_into(scratch, child_blocks, probe, level + 1)?;
            }
        }

        child_blocks.truncate(mark);

        Ok(())
    }

    /// (start block, length in blocks) of the first valid extent of a depth-0 extent tree,
    /// i.e. one that lives entirely in the inode's block array.
    //
    /// Never does I/O; None for deeper trees or when there is no valid extent.
    /// Same validity rules as parse_extent_node_into.
    #[cfg(unix)]
    #[inline]
    fn first_inline_extent(data: &[u8]) -> Option<(u64, u16)> {
        if unlikely(data.len() < EXTENTS_START) { return None; }

        let (eh_entries, eh_depth) = parse_extent_header(data)?;
        if unlikely(eh_depth != 0) { return None; }

        let mut result = None;
        for_each_valid_leaf_extent(data, eh_entries, |start, len| {
            result = Some((start, len));
            true
        });
        result
    }

    /// Start block of the leftmost valid extent, found by walking only the leftmost path of the
    /// extent tree: no I/O for a depth-0 tree (it lives in the inode), one block read per level otherwise.
    ///
    /// Returns None whenever it can't decide cheaply, because of a corrupt header, unreadable block, or a
    /// leftmost leaf with no valid extent -- and the caller falls back to parsing the whole tree.
    fn first_extent_start(&self, block_bytes: &[u8]) -> Option<u64> {
        let _span = tracy::span!("Ext4Fs::first_extent_start");

        let block_size = self.sb.block_size as usize;
        if unlikely(block_size > 8192) { return None; }

        let mut block = std::mem::MaybeUninit::<[u8; 8192]>::uninit();  // ext4 block size is at most 8192 bytes

        let block = unsafe {
            std::slice::from_raw_parts_mut(block.as_mut_ptr() as *mut u8, block_size)
        };

        let mut data: &[u8] = block_bytes;

        for level in 0..=MAX_EXTENT_DEPTH {
            if unlikely(data.len() < EXTENTS_START) { return None; }

            let (eh_entries, eh_depth) = parse_extent_header(data)?;
            if unlikely(eh_entries == 0) { return None; }

            if eh_depth == 0 {
                let mut result = None;
                for_each_valid_leaf_extent(data, eh_entries, |start, _len| {
                    result = Some(start);
                    true
                });
                return result;
            }

            if level == MAX_EXTENT_DEPTH { return None; }

            let leaf_block = extent_index_child_block(data, 0)?;

            // 'data' is done with here, so the buffer can be reused for the next level
            match self.read_at_offset(block, leaf_block * block_size as u64) {
                Ok(n) if n == block_size => {}
                _ => return None,
            }

            data = &*block;
        }

        None
    }

    /// Decode one inode from a byte slice already containing its raw record.
    #[inline]
    fn decode_inode(inode_num: u32, src: &[u8], inode_size_field: u16) -> Ext4Node {
        const I_MODE:       usize = 0x00;
        const I_CTIME:      usize = 0x0C;
        const I_MTIME:      usize = 0x10;
        const I_FLAGS:      usize = 0x20;
        const I_BLOCK:      usize = 0x28;
        const I_SIZE_HIGH:  usize = 0x6C;

        const I_BLOCK_LEN:  usize = 60;  // 15 u32 block pointers / the extent header + extents
        const I_HEADER_MIN: usize = I_SIZE_HIGH + 4;

        let word      = read_u64_unaligned_le(src, I_MODE);
        let mode      = word as u16;
        let size_lo   = ((word >> 32) & 0xFFFF_FFFF) as u32;
        let mtime_sec = read_u32_unaligned_le(src, I_MTIME) as i64;
        let ctime_sec = read_u32_unaligned_le(src, I_CTIME) as i64;
        let flags     = read_u32_unaligned_le(src, I_FLAGS);

        let size_high = if inode_size_field > 128 && src.len() >= I_HEADER_MIN {
            read_u32_unaligned_le(src, I_SIZE_HIGH)
        } else {
            0
        };

        let size = ((size_high as u64) << 32) | (size_lo as u64);

        let mut blocks = [0u32; 15];

        #[cfg(target_endian = "little")]
        unsafe {
            std::ptr::copy_nonoverlapping(
                src.as_ptr().add(I_BLOCK),
                blocks.as_mut_ptr() as *mut u8,
                I_BLOCK_LEN,
            );
        }

        #[cfg(target_endian = "big")]
        {
            let mut i = 0;
            while i < 15 {
                blocks[i] = read_u32_unaligned_le(src, I_BLOCK + i * 4);
                i += 1;
            }
        }

        Ext4Node {
            hot: Ext4NodeHot { inode_num, size, mtime_sec, mode, flags },
            cold: Ext4NodeCold { ctime_sec, blocks }
        }
    }
}

impl Ext4Fs {
    /// Disk range (byte offset, length) worth hinting for the first read of this file: the whole file
    /// if it is at most PREFETCH_HEAD_BYTES, else its first PREFETCH_HEAD_BYTES, clipped to the first extent.
    ///
    /// The inode is already decoded and a depth-0 extent tree lives in it, so this costs no I/O.
    ///
    /// None when there's nothing to hint or the location can't be known without a read
    /// (deeper trees / inline data / empty files / etc).
    #[cfg(unix)]
    #[inline]
    fn head_hint_range(&self, node: &Ext4Node, max_size: usize) -> Option<(u64, u64)> {
        if PREFETCH_HEAD_BYTES == 0 || max_size == 0 || node.flags & EXT4_INLINE_DATA_FL != 0 {
            return None;
        }

        let block_size = self.sb.block_size as u64;

        let (start_block, extent_bytes) = if node.flags & EXT4_EXTENTS_FL != 0 {
            let (start, len) = Self::first_inline_extent(util::cast_slice(&node.cold.blocks))?;
            (start, len as u64 * block_size)

        } else {
            //
            // Block-mapped file: the probe reads the first mapped direct block
            //

            let first = *node.cold.blocks.iter()
                .take(EXT4_BLOCK_POINTERS_COUNT)
                .find(|&&b| b != 0 && (b as u64) < self.max_block)?;

            (first as u64, block_size)
        };

        let len = (max_size as u64).min(PREFETCH_HEAD_BYTES).min(extent_bytes);

        Some((start_block * block_size, len))
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn is_page_cached(&self, _offset: u64) -> Option<bool> { None }

    /// Answers the question 'is the page at this device offset in the page cache?' without any I/O,
    /// via a one-byte preadv2(RWF_NOWAIT), which fails with EAGAIN instead of waiting for the disk.
    ///
    /// None if can't tell
    #[cfg(target_os = "linux")]
    fn is_page_cached(&self, offset: u64) -> Option<bool> {
        use std::sync::atomic::{AtomicBool, Ordering};

        static NOWAIT_UNSUPPORTED: AtomicBool = AtomicBool::new(false);
        if NOWAIT_UNSUPPORTED.load(Ordering::Relaxed) { return None; }

        let mut byte = 0u8;
        let iov = libc::iovec { iov_base: &mut byte as *mut u8 as *mut libc::c_void, iov_len: 1 };

        let n = unsafe {
            libc::preadv2(self.file.as_raw_fd(), &iov, 1, offset as libc::off_t, libc::RWF_NOWAIT)
        };

        if n >= 0 { return Some(true); }

        match io::Error::last_os_error().raw_os_error() {
            Some(libc::EAGAIN) => Some(false),
            Some(libc::EINTR)  => None,
            _ => {
                NOWAIT_UNSUPPORTED.store(true, Ordering::Relaxed);
                None
            }
        }
    }

    /// WILLNEED for the disk blocks holding these inodes, as few fadvise calls as possible: blocks
    /// that are equal or adjacent (the common case once ids are sorted by inode_disk_offset)
    /// collapse into one range. Unsorted input is still correct, just coalesces less.
    #[cfg(unix)]
    fn hint_inode_blocks(&self, file_ids: impl Iterator<Item = ext4::FileId>) {
        use run_temperature::INODES;

        let mut want_sample = INODES.want_sample();

        if INODES.is_warm() && !want_sample { return; }

        let fd         = self.file.as_raw_fd();
        let block_size = self.sb.block_size as u64;

        let flush = |start: u64, end: u64| {
            if end > start {
                run_temperature::note_inode_hint(start, end - start);

                unsafe {
                    libc::posix_fadvise(
                        fd, start as libc::off_t, (end - start) as libc::off_t,
                        libc::POSIX_FADV_WILLNEED
                    );
                }
            }
        };

        let mut start = 0u64;  // Current run is [start, end), empty while start == end
        let mut end   = 0u64;
        let mut tries = 0u32;

        for file_id in file_ids {
            if unlikely(file_id == 0) { continue; }  // Poisoned...

            let offset      = self.inode_disk_offset(file_id);
            let block_start = offset - offset % block_size;

            //
            // One look at the first usable block decides the batch: if it's cached and we're warm,
            // hinting would be pure syscall overhead. A block we hinted ourselves says nothing, so
            // that sample is skipped and the next block is tried (a few times at most).
            //
            if want_sample {
                tries += 1;

                match self.sample_temperature(&INODES, block_start, block_size, true) {
                    Some(hit) => {
                        want_sample = false;
                        if hit && INODES.is_warm() { return; }
                    }
                    None if tries >= 4 => {
                        want_sample = false;
                        if INODES.is_warm() { return; }  // Warm and can't check: don't hint
                    }
                    None => {}
                }
            }

            if block_start >= start && block_start < end   { continue; }                     // Already covered
            if block_start == end   && end         > start { end += block_size; continue; }  // Adjacent, extend

            flush(start, end);

            start = block_start;
            end   = block_start + block_size;
        }

        flush(start, end);
    }

    #[cfg(unix)]
    fn cache_residency(&self, offset: u64, len: u64) -> Option<(u32, u32)> {
        if let Some(r) = run_temperature::cachestat::residency(self.file.as_raw_fd(), offset, len) {
            return Some(r);
        }

        #[cfg(target_os = "linux")] {
            self.is_page_cached(offset).map(|cached| (cached as u32, 1))
        }

        #[cfg(not(target_os = "linux"))] { None }
    }

    #[cfg(unix)]
    fn sample_temperature(
        &self,
        temp: &run_temperature::Temperature,
        offset: u64, len: u64,
        avoid_own_hints: bool,
    ) -> Option<bool> {
        if avoid_own_hints && run_temperature::recently_hinted(offset, len) {
            return None;
        }

        let (cached, total) = self.cache_residency(offset, len)?;
        let hit = run_temperature::is_hit(cached, total);

        temp.observe(hit);
        Some(hit)
    }
}

#[inline(always)]
fn parse_extent_header(data: &[u8]) -> Option<(u16, u16)> {
    let word     = read_u64_unaligned_le(data, 0);
    let eh_magic = word as u16;

    if unlikely(u16::from_le(eh_magic) != EXT4_EXTENT_MAGIC) {
        return None;
    }

    Some(((word >> 16) as u16, (word >> 48) as u16))
}

/// Walks up to 'eh_entries' leaf extent records starting at EXTENTS_START in 'data',
/// calling 'f(start, len)' for each one with a valid ee_len (0 < ee_len <= 32768).
///
/// Stops as soon as 'f' returns true.
#[inline(always)]
fn for_each_valid_leaf_extent(data: &[u8], eh_entries: u16, mut f: impl FnMut(u64, u16) -> bool) {
    for i in 0..eh_entries as usize {
        let offset = EXTENTS_START + i * EXTENT_SIZE;
        if unlikely(offset + EXTENT_SIZE > data.len()) {
            break;
        }

        let word   = read_u64_unaligned_le(data, offset + 4);
        let ee_len = word as u16;

        if likely(ee_len > 0 && ee_len <= 32768) {
            let ee_start_hi = (word >> 16) & 0xFFFF;
            let ee_start_lo = (word >> 32) & 0xFFFF_FFFF;

            if f((ee_start_hi << 32) | ee_start_lo, ee_len) {
                break;
            }
        }
    }
}

/// The child block referenced by index entry 'i' in 'data', or None if out of bounds.
#[inline(always)]
fn extent_index_child_block(data: &[u8], i: usize) -> Option<u64> {
    let offset = EXTENTS_START + i * INDEX_SIZE;
    if unlikely(offset + INDEX_SIZE > data.len()) {
        return None;
    }

    let (ei_leaf_lo, ei_leaf_hi) = read_u64_as_u32_and_u16_unaligned_le(data, offset + 4);
    Some(((ei_leaf_hi as u64) << 32) | (ei_leaf_lo as u64))
}


#[cfg(target_os = "linux")]
impl Ext4Fs {
    /// Drops the clean pages of the block-device's page cache backing [offset, offset + len).
    ///
    /// Rounded outwards to whole pages: fadvise(DONTNEED) skips partial pages at the edges, which
    /// would leave stale sub-page blocks behind on filesystems with block_size < page size.
    fn drop_stale_range(&self, offset: u64, len: u64) -> bool {
        let page = stale::page_size();
        let lo   = offset & !(page - 1);
        let hi   = (offset + len + page - 1) & !(page - 1);

        unsafe {
            libc::posix_fadvise(
                self.file.as_raw_fd(),
                lo as libc::off_t,
                (hi - lo) as libc::off_t,
                libc::POSIX_FADV_DONTNEED,
            ) == 0
        }
    }

    /// Same, for the first 'max_size' bytes of a file's extent list, only what is about to be
    /// read, so a huge file with a small read cap doesn't lose its whole cache.
    fn drop_stale_extents(&self, extents: &[Ext4Extent], max_size: usize) -> bool {
        let block_size = self.sb.block_size as u64;

        let mut left = max_size as u64;
        let mut ok   = true;

        for e in extents {
            if left == 0 { break; }

            let bytes = (e.len as u64 * block_size).min(left);
            left -= bytes;

            ok &= self.drop_stale_range(e.start * block_size, bytes);
        }

        ok
    }
}
