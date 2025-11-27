use crate::cli::Cli;
use crate::matcher::Matcher;
use crate::stats::Stats;
use crate::writer::SmoothWriter;
use crate::path_buf::FixedPathBuf;
use crate::{copy_data, tracy, COLOR_CYAN, COLOR_GREEN, COLOR_RED, COLOR_RESET};
use crate::binary::{is_binary_chunk, is_binary_ext};
use crate::util::{
    likely,
    unlikely,
    build_gitignore_from_bytes,
    is_common_skip_dir,
    is_dot_entry,
    is_gitignored,
    truncate_utf8,
};

use std::io;
use std::fmt::Display;
use std::os::fd::AsRawFd;
use std::fs::{File, OpenOptions};
use std::sync::atomic::{AtomicBool, Ordering};

use smallvec::{SmallVec, smallvec};
use ignore::gitignore::Gitignore;
use memmap2::{Mmap, MmapOptions};

pub type INodeNum = u32;

pub const BINARY_CONTROL_COUNT: usize = 51; // tuned
pub const BINARY_PROBE_BYTE_SIZE: usize = 0x1000;

pub const NON_TTY_BATCH_SIZE: usize = 0x8000; // tuned
pub const TTY_BATCH_SIZE: usize = 0x1000; // tuned

pub const MAX_EXTENTS_UNTIL_SPILL: usize = 64;

pub const PATH_VERY_LONG_LENGTH: usize = 0x1000;

pub const MAX_DIR_BYTE_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_FILE_BYTE_SIZE: usize = 5 * 1024 * 1024;
pub const MAX_SYMLINK_TARGET_SIZE: usize = 4096;
pub const FAST_SYMLINK_SIZE: usize = 60; // Symlinks < 60 bytes stored in inode

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

pub const EXT4_S_IFMT: u16 = 0xF000;
pub const EXT4_S_IFREG: u16 = 0x8000;
pub const EXT4_S_IFLNK: u16 = 0xA000;
pub const EXT4_S_IFDIR: u16 = 0x4000;

pub const EXT4_EXTENTS_FL: u32 = 0x80000;

pub const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
pub const EXT4_EXTENT_HEADER_SIZE: usize = 12;
pub const EXT4_EXTENT_ENTRY_SIZE: usize = 12;

#[derive(Copy, Clone)]
pub enum BufKind { Content, Dir, Gitignore }

struct DirFrame {
    pub inode_num: INodeNum,
    pub parent_len: usize,   // Length of parent path (before this directory)
    pub name_offset: usize,  // Offset into `dir_name_buf`
    pub name_len: usize,     // Length of directory name
}

pub struct GitignoreFrame {
    pub matcher: Gitignore
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
    pub dir_name_buf: usize,
    pub dir_buf: usize,
    pub content_buf: usize,
    pub gitignore_buf: usize,
    pub extent_buf: usize,
}

pub struct RawGrepper {
    device_mmap: Mmap,
    sb: Ext4SuperBlock,

    pub stats: Stats,

    pub cli: Cli,

    writer: SmoothWriter,
    matcher: Matcher,

    // ------------- reused buffers
    //    --- 3 main buffers
      content_buf: Vec<u8>, // `DirKind::Content`
          dir_buf: Vec<u8>, // `DirKind::Dir`
    gitignore_buf: Vec<u8>, // `DirKind::Gitignore`

       extent_buf: Vec<Ext4Extent>,
         path_buf: FixedPathBuf,
     dir_name_buf: Vec<u8>,
}

/// impl block of public API
impl RawGrepper {
    pub fn new(
        device_path: &str,
        search_root_path: &str,
        cli: Cli
    ) -> io::Result<Self> {
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

        let matcher = match Matcher::new(&cli.pattern) {
            Ok(m) => m,
            Err(e) => {
                eprint!("{COLOR_RED}");
                match e.kind() {
                    io::ErrorKind::InvalidInput => {
                        eprintln!("error: invalid pattern '{pattern}'", pattern = cli.pattern);
                        eprintln!("help: patterns must be valid regex or a literal/alternation extractable form");
                        eprintln!("tip: test your regex with `grep -E` or a regex tester before running");
                    }
                    io::ErrorKind::NotFound => {
                        // unlikely for this constructor, but here for completeness
                        eprintln!("error: referenced something that wasn't found: {e}");
                    }
                    _ => {
                        eprintln!("error: failed to build matcher: {e}");
                    }
                }
                eprint!("{COLOR_RESET}");

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
            libc::madvise(
                device_mmap.as_ptr() as *mut _,
                device_mmap.len(),
                libc::MADV_SEQUENTIAL | libc::MADV_WILLNEED
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
                "Not an ext4 filesystem".to_string()
            ));
        }

        let sb = Self::parse_superblock(sb_bytes)?;

        Ok(RawGrepper {
            device_mmap,
            sb,
            cli,
            matcher,
            path_buf: FixedPathBuf::from_bytes(search_root_path.as_bytes()),
            writer: SmoothWriter::new(),
            stats: Stats::default(),
            dir_name_buf: Vec::default(),
            dir_buf: Vec::default(),
            content_buf: Vec::default(),
            gitignore_buf: Vec::default(),
            extent_buf: Vec::default(),
        })
    }

    #[inline(always)]
    fn init(&mut self) {
        let config = self.cli.get_buffer_config();
        self.dir_name_buf.reserve(config.dir_name_buf);
        self.dir_buf.reserve(config.dir_buf);
        self.content_buf.reserve(config.content_buf);
        self.gitignore_buf.reserve(config.gitignore_buf);
        self.extent_buf.reserve(config.extent_buf);
    }

    pub fn search(
        mut self,
        root_inode: INodeNum,
        path_display_buf: &mut String,
        running: &AtomicBool,
        root_gitignore: Option<Gitignore>,
    ) -> io::Result<(Cli, Stats)> {
        let _span = tracy::span!("RawGrepper::search");

        let mut dir_stack = Vec::with_capacity(1024);
        let mut gi_stack = if self.cli.should_ignore_gitignore() {
            Vec::new()
        } else {
            Vec::with_capacity(64)
        };

        dir_stack.push(DirFrame {
            inode_num: root_inode,
            parent_len: self.path_buf.len(),
            name_offset: 0,
            name_len: 0, // Root has no name to add
        });
        if let Some(root_gitignore) = root_gitignore {
            gi_stack.push(GitignoreFrame { matcher: root_gitignore });
        }

        self.init();

        while let Some(frame) = dir_stack.pop() {
            if unlikely(!running.load(Ordering::Relaxed)) {
                break;
            }

            self.path_buf.truncate(frame.parent_len);
            if frame.name_len > 0 {
                if likely(frame.parent_len > 0)
                    && self.path_buf.as_bytes().get(frame.parent_len - 1) != Some(&b'/')
                {
                    self.path_buf.push(b'/');
                }
                let name = &self.dir_name_buf[
                    frame.name_offset..
                    frame.name_offset + frame.name_len
                ];
                self.path_buf.extend_from_slice(name);
            }

            let Ok(inode) = self.parse_inode(frame.inode_num) else {
                continue;
            };

            if unlikely((inode.mode & EXT4_S_IFMT) != EXT4_S_IFDIR) {
                continue;
            }

            let last_segment = match self.path_buf.as_bytes().iter().rposition(|&b| b == b'/') {
                Some(pos) => &self.path_buf.as_bytes()[pos + 1..],
                None => self.path_buf.as_bytes(),
            };
            if is_common_skip_dir(last_segment) {
                self.stats.dirs_skipped_common += 1;
                continue;
            }

            self.display_path_into_buf(path_display_buf);
            if !self.cli.should_ignore_gitignore() &&
                is_gitignored(&gi_stack, path_display_buf.as_ref(), true)
            {
                self.stats.dirs_skipped_gitignore += 1;
                continue;
            }

            if self.process_directory(
                &inode,
                path_display_buf,
                &mut dir_stack,
                &mut gi_stack,
                self.path_buf.len(),
            ).is_err() {
                continue;
            }
        }

        // Just in case ..
        self.writer.flush()?;

        Ok((self.cli, self.stats))
    }

    /// Resolve a path like "/usr/bin" or "etc" into an inode number.
    /// @Note: Clobbers into `dir_buf`
    pub fn try_resolve_path_to_inode(&mut self, path: &str) -> io::Result<INodeNum> {
        let _span = tracy::span!("RawGrepper::try_resolve_path_to_inode");

        let mut inode_num = EXT4_ROOT_INODE;
        if path == "/" || path.is_empty() {
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

            let dir_size = (inode.size as usize).min(MAX_DIR_BYTE_SIZE);
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
}

/// impl block of core processing
impl RawGrepper {
    fn process_directory(
        &mut self,
        inode: &Ext4Inode,
        path_display_buf: &mut String,
        dir_stack: &mut Vec<DirFrame>,
        gi_stack: &mut Vec<GitignoreFrame>,
        current_dir_path_len: usize,
    ) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::process_directory");

        let dir_size = (inode.size as usize).min(MAX_DIR_BYTE_SIZE);
        self.read_file_into_buf(inode, dir_size, BufKind::Dir, false)?;
        self.stats.dirs_encountered += 1;

        // ------------- Quick scan for .gitignore
        let gitignore_inode = if self.cli.should_ignore_gitignore() {
            None
        } else {
            self.find_gitignore_inode_in_buf(BufKind::Dir)
        };

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
                        path_display_buf,
                        dir_stack,
                        gi_stack,
                        current_dir_path_len,
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

    fn process_entry(
        &mut self,
        entry_inode: INodeNum,
        name: &[u8],
        path_display_buf: &mut String,
        dir_stack: &mut Vec<DirFrame>,
        gi_stack: &[GitignoreFrame],
        current_dir_path_len: usize,
    ) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::process_entry");

        if is_common_skip_dir(name) {
            self.stats.dirs_skipped_common += 1;
            return Ok(());
        }

        // ------ Ensure we start from the current directory path
        self.path_buf.truncate(current_dir_path_len);

        // ------ Build the full path: current_dir + '/' + name
        if likely(current_dir_path_len > 0)
            && self.path_buf.as_bytes().get(current_dir_path_len - 1) != Some(&b'/')
        {
            self.path_buf.push(b'/');
        }
        self.path_buf.extend_from_slice(name);

        let Ok(child_inode) = self.parse_inode(entry_inode) else {
            self.path_buf.truncate(current_dir_path_len);
            return Ok(());
        };

        let ft = child_inode.mode & EXT4_S_IFMT;

        match ft {
            EXT4_S_IFDIR => {
                let name_offset = self.dir_name_buf.len();
                self.dir_name_buf.extend_from_slice(name);
                let name_len = name.len();

                dir_stack.push(DirFrame {
                    inode_num: entry_inode,
                    parent_len: current_dir_path_len,
                    name_offset,
                    name_len,
                });
            }
            EXT4_S_IFREG => {
                self.process_file(
                    &child_inode,
                    name,
                    path_display_buf,
                    gi_stack,
                )?;
            }
            EXT4_S_IFLNK => {
                self.process_symlink(
                    &child_inode,
                    name,
                    path_display_buf,
                    gi_stack,
                    current_dir_path_len
                ).inspect_err(|_| {
                    self.stats.symlinks_broken += 1;
                })?;
            }
            _ => {
                // ... skip special files (devices, FIFOs, sockets, etc.)
            }
        }

        self.path_buf.truncate(current_dir_path_len);

        Ok(())
    }

    #[inline]
    fn process_symlink(
        &mut self,
        child_inode: &Ext4Inode,
        name: &[u8],
        path_display_buf: &mut String,
        gi_stack: &[GitignoreFrame],
        current_dir_path_len: usize
    ) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::process_symlink");

        if unlikely(current_dir_path_len > self.path_buf.capacity()) {
            self.stats.symlinks_broken += 1;
            return Ok(());
        }

        let target_inode_num = self.resolve_symlink(&child_inode, current_dir_path_len)?;
        let target_inode = self.parse_inode(target_inode_num)?;
        let target_ft = target_inode.mode & EXT4_S_IFMT;

        if target_ft == EXT4_S_IFREG {
            self.stats.symlinks_followed += 1;
            self.process_file(
                &target_inode,
                name,
                path_display_buf,
                gi_stack,
            )?;
        } else {
            // ... skip directory symlinks to avoid potential loops
        }

        Ok(())
    }

    #[inline]
    fn process_file(
        &mut self,
        child_inode: &Ext4Inode,
        name: &[u8],
        path_display_buf: &mut String,
        gi_stack: &[GitignoreFrame],
    ) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::process_file");

        self.stats.files_encountered += 1;

        // -------------------- Rejection by size
        if !self.cli.should_ignore_all_filters() &&
            unlikely(child_inode.size > MAX_FILE_BYTE_SIZE as u64)
        {
            self.stats.files_skipped_large += 1;
            return Ok(());
        }

        // -------------------- Rejection by extension
        if !self.cli.should_search_binary() &&
            is_binary_ext(name)
        {
            self.stats.files_skipped_as_binary_due_to_ext += 1;
            return Ok(());
        }

        // -------------------- Build display path
        // path_bytes contains the full path including filename
        self.display_path_into_buf(path_display_buf);

        // -------------------- Rejection by .gitignore
        if !self.cli.should_ignore_gitignore() &&
            is_gitignored(gi_stack, path_display_buf.as_ref(), false)
        {
            self.stats.files_skipped_gitignore += 1;
            return Ok(());
        }

        let size = (child_inode.size as usize).min(MAX_FILE_BYTE_SIZE);

        match self.read_file_into_buf(
            child_inode,
            size,
            BufKind::Content,
            !self.cli.should_search_binary()
        )? {
            true => {
                // Success: file is loaded and is not binary (or we allow binary)
                self.stats.files_searched += 1;
                self.stats.bytes_searched += self.get_buf(BufKind::Content).len();
                self.find_and_print_matches(path_display_buf)?;
            }
            false => {
                // Read stopped early because binary was detected
                self.stats.files_skipped_as_binary_due_to_probe += 1;
            }
        }

        Ok(())
    }
}

/// impl block of symlink helpers
impl RawGrepper {
    /// Resolve a symlink to its target inode number
    #[inline]
    fn resolve_symlink(
        &mut self,
        inode: &Ext4Inode,
        current_dir_len: usize
    ) -> io::Result<INodeNum> {
        let _span = tracy::span!("RawGrepper::resolve_symlink");

        if unlikely(current_dir_len > PATH_VERY_LONG_LENGTH) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Path too long (possible symlink loop)"
            ));
        }

        // symlink targets < `FAST_SYMLINK_SIZE` bytes are stored directly in inode.blocks
        if inode.size < FAST_SYMLINK_SIZE as u64 {
            let target = unsafe {
                std::slice::from_raw_parts(
                    inode.blocks.as_ptr() as *const u8,
                    inode.size as usize
                )
            };
            return self.resolve_symlink_target(target, current_dir_len);
        }

        // slow symlinks: target stored in file blocks
        let size = (inode.size as usize).min(MAX_SYMLINK_TARGET_SIZE);
        self.read_file_into_buf(inode, size, BufKind::Content, false)?;

        let target: SmallVec<[_; 256]> = copy_data(&self.content_buf[..]);
        self.resolve_symlink_target(&target, current_dir_len)
    }

    /// Resolve the symlink target path to an inode number
    fn resolve_symlink_target(
        &mut self,
        target: &[u8],
        current_dir_len: usize
    ) -> io::Result<INodeNum> {
        let _span = tracy::span!("RawGrepper::resolve_symlink_target");

        if target.first() == Some(&b'/') {
            // This is an absolute path
            let path_str = String::from_utf8_lossy(target);
            return self.try_resolve_path_to_inode(&path_str);
        }

        let current_dir = &self.path_buf.as_bytes()[..current_dir_len];

        let mut resolved_path = SmallVec::<[_; 512]>::new();
        resolved_path.extend_from_slice(current_dir);

        for component in target.split(|&b| b == b'/') {
            if component.is_empty() || component == b"." {
                continue;
            }

            if component == b".." {
                // Go up one directory - find last '/'
                if let Some(pos) = resolved_path.iter().rposition(|&b| b == b'/') {
                    resolved_path.truncate(pos);
                } else {
                    // Already at root
                    resolved_path.clear();
                }
                continue;
            }

            // Add component to path
            if !resolved_path.is_empty() && resolved_path.last() != Some(&b'/') {
                resolved_path.push(b'/');
            }
            resolved_path.extend_from_slice(component);

            if unlikely(resolved_path.len() > PATH_VERY_LONG_LENGTH) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Path too long during symlink resolution"
                ));
            }
        }

        let path_str = String::from_utf8_lossy(&resolved_path);
        self.try_resolve_path_to_inode(&path_str)
    }
}

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
                let block_data = this.get_block(block_num.into());
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
            let extents_copy: SmallVec::<[_; MAX_EXTENTS_UNTIL_SPILL]> = copy_data(
                &self.extent_buf[..extent_count]
            );

            // ------- Prefetch the blooooooocks
            {
                let _span = tracy::span!("RawGrepper::read_file_into_buf::prefetch_blocks");

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

    /// Called when either checking if a path is gitignored or printing the matches
    #[inline(always)]
    fn display_path_into_buf<'a>(&self, buf: &'a mut String) -> &'a str {
        buf.clear();
        buf.push_str(&String::from_utf8_lossy(self.path_buf.as_bytes()));
        buf.as_str()
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
            std::slice::from_raw_parts(ptr, self.sb.block_size as usize)
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

/// impl block of gitignore helper functions
impl RawGrepper {
    #[inline]
    fn load_gitignore(
        &mut self,
        gi_inode_num: INodeNum,
        path_display_buf: &str,
        gi_stack: &mut Vec<GitignoreFrame>,
    ) -> bool {
        let _span = tracy::span!("RawGrepper::load_gitignore");

        if let Ok(gi_inode) = self.parse_inode(gi_inode_num) {
            let size = (gi_inode.size as usize).min(MAX_FILE_BYTE_SIZE);
            if likely(self.read_file_into_buf(&gi_inode, size, BufKind::Gitignore, true).is_ok()) {
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

    #[inline]
    fn find_gitignore_inode_in_buf(&self, kind: BufKind) -> Option<INodeNum> {
        let _span = tracy::span!("RawGrepper::find_gitignore_inode_in_buf");

        let mut offset = 0;

        while offset + 8 <= self.get_buf(kind).len() {
            let entry_inode = INodeNum::from_le_bytes([
                self.get_buf(kind)[offset],
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

/// impl block of matching and printing
impl RawGrepper {
    #[inline(never)]
    fn find_and_print_matches(&mut self, path: &str) -> io::Result<()> {
        let _span = tracy::span!("RawGrepper::find_and_print_matches");

        let buf = &self.content_buf;
        if unlikely(!self.matcher.is_match(buf)) {
            return Ok(());
        }

        let mut found_any = false;
        let mut line_start = 0;
        let mut line_num = 1;
        let buf_len = buf.len();

        for nl in memchr::memchr_iter(b'\n', buf).chain(std::iter::once(buf_len)) {
            let line = if nl < buf_len {
                &buf[line_start..nl]
            } else {
                debug_assert!(nl == buf_len);
                if line_start < buf_len {
                    &buf[line_start..]
                } else {
                    break;
                }
            };

            if {
                let _span = tracy::span!("RawGrepper::find_and_print_matches::is_match");

                self.matcher.is_match(line)
            } {
                if unlikely(!found_any) {
                    // green `path:`
                    self.writer.write_all(COLOR_GREEN.as_bytes())?;
                    self.writer.write_all(path.as_bytes())?;
                    self.writer.write_all(COLOR_RESET.as_bytes())?;
                    self.writer.write_all(b":\n")?;
                    found_any = true;
                }

                // cyan `line_num:`
                self.writer.write_all(COLOR_CYAN.as_bytes())?;
                self.writer.write_int(line_num)?;
                self.writer.write_all(COLOR_RESET.as_bytes())?;
                self.writer.write_all(b": ")?;

                let display = truncate_utf8(line, 500);
                let mut last = 0;

                for (s, e) in self.matcher.find_matches(line) {
                    if unlikely(s >= display.len()) {
                        break;
                    }
                    let e = e.min(display.len());

                    // text before match
                    self.writer.write_all(&display[last..s])?;
                    // red `match`
                    self.writer.write_all(COLOR_RED.as_bytes())?;
                    self.writer.write_all(&display[s..e])?;
                    self.writer.write_all(COLOR_RESET.as_bytes())?;
                    last = e;
                }

                // stuff after the match
                self.writer.write_all(&display[last..])?;
                self.writer.write_all(b"\n")?;
            }

            line_start = nl + 1;
            line_num += 1;
        }

        if likely(found_any) {
            self.stats.files_contained_matches += 1;
        }

        Ok(())
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
                let block_data = self.get_block(child_block.into());
                let block_copy: SmallVec<[_; 4096]> = copy_data(block_data);
                self.parse_extent_node(&block_copy, level + 1)?;
            }
        }

        Ok(())
    }
}
