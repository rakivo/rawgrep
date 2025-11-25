#![cfg_attr(feature = "use_nightly", allow(internal_features))]
#![cfg_attr(feature = "use_nightly", feature(core_intrinsics))]

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod util;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use memmap2::{Mmap, MmapOptions};
use util::{likely, unlikely};

use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::{self, BufWriter, Write};

use aho_corasick::AhoCorasick;

use memchr::memmem::Finder;
use regex::bytes::Regex;
use smallvec::{SmallVec, smallvec};

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
const EXT4_ROOT_INODE: u32 = 2;
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

struct DirFrame {
    inode_num: u32,
}

struct GitignoreFrame {
    matcher: Arc<Gitignore>,
}

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

static BYTE_CLASS: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = match i as u8 {
            0x09 | 0x0A | 0x0D | 0x20..=0x7E | 0x80..=0xFF => true,
            _ => false,
        };
        i += 1;
    }
    table
};

/// SIMD-accelerated binary detection (x86_64 only)
#[cfg(target_arch = "x86_64")]
#[inline]
fn is_binary_chunk(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // NUL check (already SIMD with memchr)
    if memchr::memchr(0, data).is_some() {
        return true;
    }

    if is_x86_feature_detected!("sse2") {
        unsafe { is_binary_chunk_simd_sse2(data) }
    } else {
        is_binary_chunk_nosimd(data)
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn is_binary_chunk_simd_sse2(data: &[u8]) -> bool {
    let check_len = data.len().min(512);
    let mut control_count = 0;

    // Process 16 bytes at a time with SSE2
    let chunks = check_len / 16;
    let ptr = data.as_ptr();

    for i in 0..chunks {
        let chunk = unsafe { _mm_loadu_si128(ptr.add(i * 16) as *const __m128i) };

        // Check for control characters (< 0x20 and not tab/LF/CR)
        let low = _mm_set1_epi8(0x20);
        let cmp = _mm_cmplt_epi8(chunk, low);

        let mask = _mm_movemask_epi8(cmp) as u32;
        control_count += mask.count_ones() as usize;

        if control_count > 51 {
            return true;
        }
    }

    // Handle remaining bytes
    for &byte in &data[chunks * 16..check_len] {
        if !BYTE_CLASS[byte as usize] {
            control_count += 1;
            if control_count > 51 {
                return true;
            }
        }
    }

    false
}

#[inline]
fn is_binary_chunk_nosimd(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    // NUL check with SIMD memchr
    if memchr::memchr(0, data).is_some() {
        return true;
    }

    // Only check first 512 bytes
    let check_len = data.len().min(512);
    let mut control_count = 0;

    // Unrolled loop for better performance
    let mut i = 0;
    while i + 4 <= check_len {
        // Process 4 bytes at once (helps with instruction-level parallelism)
        control_count += !BYTE_CLASS[data[i] as usize] as usize;
        control_count += !BYTE_CLASS[data[i+1] as usize] as usize;
        control_count += !BYTE_CLASS[data[i+2] as usize] as usize;
        control_count += !BYTE_CLASS[data[i+3] as usize] as usize;

        if control_count > 51 {
            return true;
        }
        i += 4;
    }

    // Handle remaining bytes
    while i < check_len {
        control_count += !BYTE_CLASS[data[i] as usize] as usize;
        if control_count > 51 {
            return true;
        }
        i += 1;
    }

    false
}

// Skip dirs: tiny set, just match strings directly
#[inline(always)]
fn is_skip_dir(dir: &[u8]) -> bool {
    match dir {
        b"node_modules" | b"target" | b".git" | b".hg" | b".svn" => true,
        _ => false,
    }
}

#[inline(always)]
fn is_binary_ext(ext: &[u8]) -> bool {
    // Binary extensions: tiny set, use slice search (fast for <20 items)
    const BINARY_EXTS: &[&[u8]] = &[
        b"png",b"jpg",b"jpeg",b"gif",b"class",b"so",b"o",b"a",
        b"pdf",b"zip",b"tar",b"gz",b"7z",b"exe",b"dll",b"bin",
    ];

    BINARY_EXTS.contains(&ext)
}

#[inline(always)]
fn is_gitignored(frames: &[GitignoreFrame], path: &Path, is_dir: bool) -> bool {
    for frame in frames.iter().rev() {
        if frame.matcher.matched(path, is_dir).is_ignore() {
            return true;
        }
    }
    false
}

#[inline(always)]
fn build_gitignore(root: &Path) -> Gitignore {
    let mut builder = GitignoreBuilder::new(root);
    builder.add(root.join(".gitignore"));
    builder.build().unwrap()
}

/// Build a Gitignore matcher from raw file content (bytes), for a given parent directory
#[inline(always)]
fn build_gitignore_from_bytes(parent_path: &Path, bytes: &[u8]) -> Arc<Gitignore> {
    let mut builder = GitignoreBuilder::new(parent_path);
    for line in bytes.split(|&b| b == b'\n') {
        if let Ok(s) = std::str::from_utf8(line) {
            builder.add_line(None, s).ok();
        }
    }
    Arc::new(builder.build().unwrap_or_else(|_| Gitignore::empty()))
}

#[inline(always)]
fn write_int(buf: &mut Vec<u8>, mut n: usize) {
    if n == 0 {
        buf.push(b'0');
        return;
    }

    if n < 10 {
        buf.push(b'0' + n as u8);
        return;
    }

    if n < 100 {
        buf.push(b'0' + (n / 10) as u8);
        buf.push(b'0' + (n % 10) as u8);
        return;
    }

    let mut temp = [0u8; 20];
    let mut i = temp.len();

    while n > 0 {
        i -= 1;
        temp[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }

    buf.extend_from_slice(&temp[i..]);
}

#[inline(always)]
fn truncate_utf8(s: &[u8], max: usize) -> &[u8] {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && (s[end] & 0b1100_0000) == 0b1000_0000 {
        end -= 1;
    }
    &s[..end]
}

pub enum FastMatcher {
    Literal(Finder<'static>),  // Single literal: "error"
    MultiLiteral(AhoCorasick), // Multiple: "error|warning|fatal"
    Regex(Regex),              // Complex patterns
}

impl FastMatcher {
    pub fn new(pattern: &str) -> io::Result<Self> {
        // Try literal extraction first
        if let Some(literal) = extract_literal(pattern) {
            let finder = Finder::new(&literal).into_owned();
            return Ok(FastMatcher::Literal(finder));
        }

        // Try alternation extraction: "foo|bar|baz"
        if let Some(literals) = extract_alternation_literals(pattern) {
            let ac = AhoCorasick::builder()
                .match_kind(aho_corasick::MatchKind::LeftmostFirst)
                .build(&literals)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            return Ok(FastMatcher::MultiLiteral(ac));
        }

        // Fallback to regex
        let re = Regex::new(pattern)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(FastMatcher::Regex(re))
    }

    #[inline(always)]
    fn is_match(&self, haystack: &[u8]) -> bool {
        match self {
            FastMatcher::Literal(finder) => finder.find(haystack).is_some(),
            FastMatcher::MultiLiteral(ac) => ac.is_match(haystack),
            FastMatcher::Regex(re) => re.is_match(haystack),
        }
    }

    #[inline]
    fn find_matches<'a>(&'a self, haystack: &'a [u8], matches: &mut SmallVec<[(usize, usize); 4]>) {
        matches.clear();
        match self {
            FastMatcher::Literal(finder) => {
                let needle_len = finder.needle().len();
                for pos in finder.find_iter(haystack) {
                    matches.push((pos, pos + needle_len));
                }
            }
            FastMatcher::MultiLiteral(ac) => {
                for m in ac.find_iter(haystack) {
                    matches.push((m.start(), m.end()));
                }
            }
            FastMatcher::Regex(re) => {
                for m in re.find_iter(haystack) {
                    matches.push((m.start(), m.end()));
                }
            }
        }
    }
}

fn extract_literal(pattern: &str) -> Option<Vec<u8>> {
    let trimmed = pattern.trim_start_matches('^').trim_end_matches('$');

    // Check for regex metacharacters
    if trimmed.chars().any(|c| ".*+?[]{}()|\\^$".contains(c)) {
        return None;
    }

    Some(trimmed.as_bytes().to_vec())
}

fn extract_alternation_literals(pattern: &str) -> Option<Vec<Vec<u8>>> {
    if !pattern.contains('|') {
        return None;
    }

    let parts: Vec<_> = pattern.split('|').collect();
    let mut literals = Vec::new();

    for part in parts {
        let trimmed = part.trim_start_matches('^').trim_end_matches('$');
        if trimmed.chars().any(|c| ".*+?[]{}()\\^$".contains(c)) {
            return None; // Contains regex metacharacters
        }
        literals.push(trimmed.as_bytes().to_vec());
    }

    Some(literals)
}

// ============================================================
// Batched output writer - critical for performance
// ============================================================

pub struct BatchWriter {
    writer: BufWriter<io::Stdout>,
    batch_size: usize,
}

impl BatchWriter {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            // 256KB buffer - reduces syscalls dramatically
            writer: BufWriter::with_capacity(256 * 1024, io::stdout()),
            batch_size: 64 * 1024, // Flush every 64KB
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
    blocks: [u32; 15],
}

#[derive(Debug, Clone, Copy)]
struct Ext4Extent {
    block: u32,
    start_lo: u32,
    len: u16,
}

#[derive(Default)]
struct Stats {
    files_read: usize,
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
        let total_files = self.files_read
            + self.files_skipped_large
            + self.files_skipped_unreadable
            + self.files_skipped_as_binary_due_to_ext
            + self.files_skipped_as_binary_due_to_probe
            + self.files_skipped_gitignore;

        let total_dirs = self.dirs_parsed
            + self.dirs_skipped_common
            + self.dirs_skipped_gitignore;

        eprintln!("\n\x1b[1;32mSearch complete\x1b[0m");
        eprintln!("============================================================");

        eprintln!("\x1b[1;34mFiles Summary:\x1b[0m");
        macro_rules! file_row {
            ($label:expr, $count:expr) => {
                let pct = if total_files == 0 { 0.0 } else { ($count as f64 / total_files as f64) * 100.0 };
                eprintln!("  {:<25} {:>8} ({:>5.1}%)", $label, $count, pct);
            };
        }

        file_row!("Files read", self.files_read);
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

        eprintln!("============================================================");

        eprintln!(
            "\x1b[1;33mTotals: {:>6} files, {:>6} dirs\x1b[0m",
            total_files, total_dirs
        );
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

        // Hint: sequential access pattern
        #[cfg(unix)]
        unsafe {
            libc::madvise(
                mmap.as_ptr() as *mut _,
                mmap.len(),
                libc::MADV_SEQUENTIAL | libc::MADV_WILLNEED
            );
        }

        // Parse superblock directly from mmap
        let sb_bytes = &mmap[EXT4_SUPERBLOCK_OFFSET as usize..EXT4_SUPERBLOCK_OFFSET as usize + EXT4_SUPERBLOCK_SIZE];

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
            extent_buf: Vec::with_capacity(256),
            output_buf: Vec::with_capacity(64 * 1024),
            content_buf: Vec::with_capacity(1024 * 1024),
        })
    }

    fn quick_is_binary(&mut self, inode: &Ext4Inode) -> bool {
        let file_size = inode.size as usize;
        if file_size == 0 {
            return false;
        }

        let bytes_to_check = file_size.min(BINARY_PROBE_BYTE_SIZE);

        if inode.flags & EXT4_EXTENTS_FL != 0 {
            if self.parse_extents(inode).is_ok() {
                if let Some(extent) = self.extent_buf.first() {
                    let block = self.get_block(extent.start_lo);
                    let to_check = block.len().min(bytes_to_check);
                    return is_binary_chunk(&block[..to_check]);
                }
            }
        } else {
            for &block_num in inode.blocks.iter().take(12) {
                if block_num != 0 {
                    let block = self.get_block(block_num);
                    let to_check = block.len().min(bytes_to_check);
                    return is_binary_chunk(&block[..to_check]);
                }
            }
        }

        false
    }

    /// Resolve a path like "/usr/bin" or "etc" into an inode number.
    fn try_resolve_path_to_inode(&mut self, path: &str) -> io::Result<u32> {
        let mut inode_num = EXT4_ROOT_INODE;
        if path == "/" || path.is_empty() {
            return Ok(inode_num);
        }

        // Split and skip empty segments
        for part in path.split('/').filter(|p| !p.is_empty()) {
            let inode = self.read_inode(inode_num)?;
            if inode.mode & EXT4_S_IFMT != EXT4_S_IFDIR {
                return Err(io::Error::new(io::ErrorKind::InvalidInput,
                    format!("{} is not a directory", part)));
            }

            let entries = self.read_directory_entries(&inode)?;
            let mut found = None;

            for (child_inode, name) in entries {
                if name.as_slice() == part.as_bytes() {
                    found = Some(child_inode);
                    break;
                }
            }

            inode_num = found.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound,
                    format!("Component '{}' not found", part))
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
    fn get_block(&self, block_num: u32) -> &[u8] {
        let offset = (block_num as usize).wrapping_mul(self.superblock.block_size as usize);
        debug_assert!(self.device_mmap.get(offset..offset + self.superblock.block_size as usize).is_some());
        unsafe {
            let ptr = self.device_mmap.as_ptr().add(offset);
            std::slice::from_raw_parts(ptr, self.superblock.block_size as usize)
        }
    }

    #[cfg(unix)]
    #[inline(always)]
    fn prefetch_blocks(&self, blocks: &[u32]) {
        if blocks.is_empty() {
            return;
        }

        // Sort blocks to find contiguous ranges
        let mut sorted = SmallVec::<[u32; 16]>::from(blocks);
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
    fn advise_range(&self, start_block: u32, end_block: u32) {
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
    fn read_inode(&mut self, inode_num: u32) -> io::Result<Ext4Inode> {
        if inode_num == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid inode number 0"));
        }

        let group = (inode_num - 1) / self.superblock.inodes_per_group;
        let index = (inode_num - 1) % self.superblock.inodes_per_group;

        let bg_desc_offset = if self.superblock.block_size == 1024 {
            2048
        } else {
            self.superblock.block_size as usize
        } + (group as usize * self.superblock.desc_size as usize);

        // Direct read from mmap - no seek!
        let bg_desc = &self.device_mmap[bg_desc_offset..bg_desc_offset + self.superblock.desc_size as usize];

        let inode_table_block = u32::from_le_bytes([
            bg_desc[EXT4_INODE_TABLE_OFFSET + 0],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 1],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 2],
            bg_desc[EXT4_INODE_TABLE_OFFSET + 3],
        ]);

        let inode_offset = inode_table_block as usize * self.superblock.block_size as usize
            + index as usize * self.superblock.inode_size as usize;

        let inode_bytes = &self.device_mmap[inode_offset..inode_offset + self.superblock.inode_size as usize];

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

        let mut blocks = [0u32; 15];
        for (i, block) in blocks.iter_mut().enumerate() {
            let offset = EXT4_INODE_BLOCK_OFFSET + i * 4;
            *block = u32::from_le_bytes([
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

                let ee_block = u32::from_le_bytes([
                    data[base + 0],
                    data[base + 1],
                    data[base + 2],
                    data[base + 3]
                ]);
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
                        block: ee_block,
                        start_lo: start_block as u32,
                        len: ee_len,
                    });
                }
            }
        } else {
            // -------- Internal node - collect block numbers first
            let mut child_blocks = SmallVec::<[u32; 16]>::new();
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
                child_blocks.push(leaf_block as u32);
            }

            #[cfg(unix)]
            self.prefetch_blocks(&child_blocks);

            for child_block in child_blocks {
                let block_data = self.get_block(child_block);
                let block_copy: SmallVec<[u8; 4096]> = SmallVec::from_slice(block_data);
                self.parse_extent_node(&block_copy, level + 1)?;
            }
        }

        Ok(())
    }

    fn read_file_content(&mut self, inode: &Ext4Inode, max_size: usize) -> io::Result<()> {
        self.content_buf.clear();
        let size_to_read = std::cmp::min(inode.size as usize, max_size);
        self.content_buf.reserve(size_to_read);

        // Reusable temp buffer
        let mut temp_buf: SmallVec<[u8; 4096]> = SmallVec::new();

        if inode.flags & EXT4_EXTENTS_FL != 0 {
            self.parse_extents(inode)?;
            let extents = self.extent_buf.clone();

            let mut blocks_to_prefetch = Vec::with_capacity(extents.len() * 4);
            for extent in &extents {
                for i in 0..extent.len {
                    blocks_to_prefetch.push(extent.start_lo + i as u32);
                }
            }

            #[cfg(unix)]
            self.prefetch_blocks(&blocks_to_prefetch);

            for extent in &extents {
                if self.content_buf.len() >= size_to_read {
                    break;
                }

                for i in 0..extent.len {
                    if self.content_buf.len() >= size_to_read {
                        break;
                    }

                    let phys_block = extent.start_lo + i as u32;

                    // Copy to temp buffer to drop the borrow
                    {
                        let block_data = self.get_block(phys_block);
                        let remaining = size_to_read - self.content_buf.len();
                        let to_read = std::cmp::min(block_data.len(), remaining);

                        temp_buf.clear();
                        temp_buf.extend_from_slice(&block_data[..to_read]);
                    } // block_data borrow dropped here

                    self.content_buf.extend_from_slice(&temp_buf);
                }
            }
        } else {
            // Direct blocks - same pattern
            let mut blocks_to_prefetch = Vec::with_capacity(12);
            for i in 0..12 {
                if inode.blocks[i] != 0 {
                    blocks_to_prefetch.push(inode.blocks[i]);
                }
            }

            #[cfg(unix)]
            self.prefetch_blocks(&blocks_to_prefetch);

            for &block in &blocks_to_prefetch {
                if self.content_buf.len() >= size_to_read {
                    break;
                }

                {
                    let block_data = self.get_block(block);
                    let remaining = size_to_read - self.content_buf.len();
                    let to_read = std::cmp::min(block_data.len(), remaining);

                    temp_buf.clear();
                    temp_buf.extend_from_slice(&block_data[..to_read]);
                }

                self.content_buf.extend_from_slice(&temp_buf);
            }
        }

        self.content_buf.truncate(size_to_read);
        Ok(())
    }

    fn read_directory_entries(
        &mut self,
        inode: &Ext4Inode,
    ) -> io::Result<Vec<(u32, SmallVec<[u8; 256]>)>> {
        let dir_size = inode.size as usize;

        let to_read = std::cmp::min(dir_size, MAX_DIR_BYTE_SIZE);
        self.read_file_content(inode, to_read)?;

        let mut entries = Vec::with_capacity(256);
        let mut offset = 0usize;
        let buf = &self.content_buf;

        while offset + 8 <= buf.len() {
            // safe slices because of the earlier bound check
            let entry_inode = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
            let rec_len = u16::from_le_bytes(buf[offset + 4..offset + 6].try_into().unwrap());
            let name_len = buf[offset + 6];

            if rec_len == 0 {
                // corrupted dir; stop parsing to avoid infinite loop
                break;
            }

            let rec_len_usize = rec_len as usize;
            if offset + rec_len_usize > buf.len() {
                // truncated directory data: stop parsing
                break;
            }

            if entry_inode != 0 && name_len > 0 {
                let name_end = offset + 8 + name_len as usize;
                if name_end <= offset + rec_len_usize {
                    let name_bytes = &buf[offset + 8..name_end];
                    let mut name = SmallVec::new();
                    name.extend_from_slice(name_bytes);
                    entries.push((entry_inode, name));
                }
            }

            offset += rec_len_usize;
        }

        Ok(entries)
    }

    pub fn search_iterative(
        &mut self,
        root_inode: u32,
        path: &mut Vec<u8>,
        matcher: &FastMatcher,
        writer: &mut BatchWriter,
        running: &Arc<AtomicBool>,
        root_gitignore: Arc<Gitignore>,
    ) -> io::Result<()> {
        #[inline(always)]
        fn display_bytes_into_display_buf<'a>(buf: &'a mut String, path_bytes: &[u8]) -> &'a str {
            buf.clear();
            buf.push_str(&String::from_utf8_lossy(path_bytes));
            buf
        }

        let mut dir_stack = Vec::with_capacity(1024);
        let mut gi_stack = Vec::with_capacity(64);
        let mut path_display_buf = String::with_capacity(512);

        // start with root
        dir_stack.push(DirFrame { inode_num: root_inode });
        gi_stack.push(GitignoreFrame { matcher: root_gitignore });

        while let Some(frame) = dir_stack.pop() {
            if !running.load(Ordering::Relaxed) {
                break;
            }

            // read dir inode
            let inode = match self.read_inode(frame.inode_num) {
                Ok(i) => i,
                Err(_) => continue,
            };

            // we only push directories onto stack, but guard anyway
            if (inode.mode & EXT4_S_IFMT) != EXT4_S_IFDIR {
                continue;
            }

            let last_segment = match path.iter().rposition(|&b| b == b'/') {
                Some(pos) => &path[pos+1..],
                None => &path[..],
            };

            if is_skip_dir(last_segment) {
                self.stats.dirs_skipped_common += 1;
                continue;
            }

            let path_str = display_bytes_into_display_buf(
                &mut path_display_buf,
                path
            );
            if is_gitignored(&gi_stack, path_str.as_ref(), true) {
                self.stats.dirs_skipped_gitignore += 1;
                continue;
            }

            // read entries
            let entries = match self.read_directory_entries(&inode) {
                Ok(v) => v,
                Err(_) => continue,
            };
            self.stats.dirs_parsed += 1;

            // Check if current dir contains a .gitignore and push its matcher if present.
            let mut pushed_gi = false;
            for (entry_inode, name) in entries.iter() {
                if name.as_slice() == b".gitignore" {
                    if let Ok(gi_inode) = self.read_inode(*entry_inode) {
                        if let Ok(()) = self.read_file_content(&gi_inode, MAX_FILE_BYTE_SIZE) {
                            let buf = &self.content_buf;
                            let matcher = build_gitignore_from_bytes(path_str.as_ref(), buf);
                            gi_stack.push(GitignoreFrame { matcher });
                            pushed_gi = true;
                        }
                    }
                    break;
                }
            }

            // iterate children; push directories, process files
            for (entry_inode, name) in entries.into_iter().rev() {
                if name.as_slice() == b"." || name.as_slice() == b".." { continue; }

                // cheap name-only SKIP_DIRS check (avoid changing path first)
                if is_skip_dir(&name) {
                    self.stats.dirs_skipped_common += 1;
                    continue;
                }

                let old_path_len = path.len();
                if old_path_len > 1 { // Don't add '/' if we're at root "/"
                    path.push(b'/');
                }
                path.extend_from_slice(&name);

                // read child inode header to decide file/dir
                let child_inode = match self.read_inode(entry_inode) {
                    Ok(i) => i,
                    Err(_) => {
                        path.truncate(old_path_len);
                        continue;
                    }
                };

                let ft = child_inode.mode & EXT4_S_IFMT;
                if ft == EXT4_S_IFDIR {
                    dir_stack.push(DirFrame { inode_num: entry_inode });
                } else if ft == EXT4_S_IFREG {
                    if child_inode.size > MAX_FILE_BYTE_SIZE as u64 {
                        self.stats.files_skipped_large += 1;
                        path.truncate(old_path_len);
                        continue;
                    }

                    if is_binary_ext(&name) {
                        self.stats.files_skipped_as_binary_due_to_ext += 1;
                        path.truncate(old_path_len);
                        continue;
                    }

                    let path_str = display_bytes_into_display_buf(
                        &mut path_display_buf,
                        path
                    );

                    if is_gitignored(&gi_stack, path_str.as_ref(), false) {
                        self.stats.files_skipped_gitignore += 1;
                        path.truncate(old_path_len);
                        continue;
                    }

                    if self.quick_is_binary(&child_inode) {
                        self.stats.files_skipped_as_binary_due_to_probe += 1;
                        path.truncate(old_path_len);
                        continue;
                    }

                    // full read and match
                    match self.read_file_content(&child_inode, MAX_FILE_BYTE_SIZE) {
                        Ok(()) => {
                            self.stats.files_read += 1;
                            _ = self.find_and_print_matches(
                                matcher,
                                path_str,
                                writer
                            );
                        }
                        Err(_) => {
                            self.stats.files_skipped_unreadable += 1;
                        }
                    }
                }

                // restore path
                path.truncate(old_path_len);
            } // end for entries

            if pushed_gi {
                gi_stack.pop();
            }
        } // end while stack

        Ok(())
    }

    #[inline]
    pub fn find_and_print_matches(
        &mut self,
        matcher: &FastMatcher,
        path: &str,
        writer: &mut BatchWriter,
    ) -> io::Result<()> {
        let buf = &self.content_buf;

        // Quick rejection
        if unlikely(!matcher.is_match(buf)) {
            return Ok(());
        }

        self.output_buf.clear();
        let mut found_any = false;
        let mut matches = SmallVec::<[(usize, usize); 4]>::new();

        let mut line_start = 0;
        let mut line_num = 1;

        // Manual loop unrolling for better performance
        let mut newlines: SmallVec<[usize; 256]> = SmallVec::new();
        newlines.extend(memchr::memchr_iter(b'\n', buf));

        for &nl in &newlines {
            let line = &buf[line_start..nl];

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
                matcher.find_matches(line, &mut matches);

                let mut last = 0;
                for &(s, e) in &matches {
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

                // Periodic flush
                if unlikely(self.output_buf.len() > 64 * 1024) {
                    writer.write(&self.output_buf)?;
                    self.output_buf.clear();
                }
            }

            line_start = nl + 1;
            line_num += 1;
        }

        // Last line
        if line_start < buf.len() {
            let line = &buf[line_start..];
            if matcher.is_match(line) {
                if !found_any {
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
                matcher.find_matches(line, &mut matches);

                let mut last = 0;
                for &(s, e) in &matches {
                    if s >= display.len() {
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
            }
        }

        if found_any {
            writer.write(&self.output_buf)?;
            writer.flush()?;
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

    let mut path = dir_path.as_bytes().to_vec();
    let matcher = FastMatcher::new(&pattern)?;
    let mut writer = BatchWriter::new();
    let running = setup_signal_handler();
    let gitignore = build_gitignore(dir_path.as_ref());
    reader.search_iterative(
        start_inode,
        &mut path,
        &matcher,
        &mut writer,
        &running,
        gitignore.into(),
    )?;

    reader.stats.print();

    Ok(())
}
