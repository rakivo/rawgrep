use std::path::{MAIN_SEPARATOR, MAIN_SEPARATOR_STR};
use std::io;
use std::fs::{File, OpenOptions};

use bumpalo::Bump;

use crate::apfs::{ApfsFs, ApfsVolume, APFS_NX_MAGIC};
use crate::cli::Cli;
use crate::matcher::Matcher;
use crate::ntfs::NtfsFs;
use crate::util::read_at_offset;
use crate::{Result, Error, tracy};
use crate::platform::device_id;
use crate::cache::{CacheConfig, FragmentCache};
use crate::parser::{BufKind, FileId, FileNode, Parser, RawFs};
use crate::worker::{MatchSink, NoSink};
use crate::ext4::{
    Ext4Fs,
    EXT4_MAGIC_OFFSET,
    EXT4_SUPERBLOCK_OFFSET,
    EXT4_SUPERBLOCK_SIZE,
    EXT4_SUPER_MAGIC,
};

pub struct RawGrepper<F: RawFs, S: MatchSink = NoSink> {
    cli: Cli,
    fs: F,
    matcher: Matcher,
    cache: Option<FragmentCache>,
    fragment_hashes: Vec<u32>,
    pub sink: S
}

/// impl block for generic RawFs
impl<F: RawFs, S: MatchSink> RawGrepper<F, S> {
    pub fn new_with_fs(cli: &Cli, fs: F, sink: S) -> Result<Self> {
        let matcher = make_matcher(cli)?;
        let fragment_hashes = matcher.extract_fragment_hashes();

        let cache = if !cli.no_cache && !fragment_hashes.is_empty() {
            let mut config = CacheConfig::from_memory_mb(cli.cache_size_mb);
            config.cache_dir = cli.cache_dir.clone();
            config.ignore_cache = cli.rebuild_cache;

            match FragmentCache::new(&config) {
                Ok(mut cache) => {
                    for &frag_hash in &fragment_hashes {
                        cache.add_pattern_fragment(frag_hash);
                    }

                    Some(cache)
                }
                Err(e) => {
                    eprintln!("Warning: Failed to initialize cache: {e}");
                    None
                }
            }
        } else {
            None
        };

        Ok(RawGrepper { cli: cli.clone(), fs, matcher, cache, fragment_hashes, sink })
    }

    /// Resolve a path like "/usr/bin" or "etc" into a file ID.
    #[inline]
    pub fn try_resolve_path_to_file_id(&self, path: &str) -> io::Result<FileId> {
        let _span = tracy::span!("RawGrepper::try_resolve_path_to_file_id");

        if path == MAIN_SEPARATOR_STR || path.is_empty() {
            return Ok(self.fs.root_id());
        }

        let bump = Bump::new();
        let mut parser = Parser::new(&bump);
        let mut file_id = self.fs.root_id();

        for part in path.split(MAIN_SEPARATOR).filter(|p| !p.is_empty()) {
            let node = self.fs.parse_node(file_id)?;

            if !node.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{path} is not a directory"),
                ));
            }

            let dir_size = node.size() as usize;
            self.fs.read_file_content(&mut parser, &node, dir_size, BufKind::Dir, false)?;

            file_id = parser.find_file_id_in_buf(
                &self.fs,
                part.as_bytes(),
                BufKind::Dir,
            ).ok_or_else(|| io::Error::new(
                io::ErrorKind::NotFound,
                format!("Component '{part}' not found"),
            ))?;
        }

        Ok(file_id)
    }
}

/// impl block for ext4-specific construction
impl<S: MatchSink> RawGrepper<Ext4Fs, S> {
    #[inline]
    pub fn new_ext4(cli: &Cli, _device_path: &str, file: File, sink: S) -> Result<AnyGrepper<S>> {
        let mut sb_bytes = [0u8; EXT4_SUPERBLOCK_SIZE];
        read_at_offset(&file, &mut sb_bytes, EXT4_SUPERBLOCK_OFFSET)?;

        let magic = u16::from_le_bytes([
            sb_bytes[EXT4_MAGIC_OFFSET + 0],
            sb_bytes[EXT4_MAGIC_OFFSET + 1],
        ]);
        if magic != EXT4_SUPER_MAGIC {
            return Err(Error::UnknownFilesystem(
                "make sure the path points to a partition (e.g. /dev/sda1), \
                 not a whole disk (e.g. /dev/sda)\n\
                 tip: run `df -Th /` to find your root partition".into())
            );
        }

        let sb = Ext4Fs::parse_superblock(&sb_bytes)?;
        let device_id = device_id(&file)?;
        let file_size = file.metadata()?.len();
        let max_block = file_size / sb.block_size as u64;

        let fs = Ext4Fs { sb, device_id, max_block, file };
        Self::new_with_fs(cli, fs, sink).map(AnyGrepper::Ext4)
    }
}

/// impl block for apfs-specific construction
impl<S: MatchSink> RawGrepper<ApfsFs, S> {
    #[inline]
    pub fn new_apfs(cli: &Cli, _device_path: &str, file: File, sink: S) -> Result<AnyGrepper<S>> {
        // Read the first block (4096 bytes covers the NX superblock at block 0).
        // We don't know block_size yet, so read the maximum possible default.
        let mut block0 = [0u8; 4096];
        read_at_offset(&file, &mut block0, 0)?;

        let sb = ApfsFs::parse_container_superblock(&block0)?;

        let device_id = device_id(&file)?;

        let fs = ApfsFs { file, sb, device_id, volume: ApfsVolume { omap_root_paddr: 0, root_tree_paddr: 0 } };

        // parse_volume() needs self.file + self.sb, so we construct a temporary
        // ApfsFs first, resolve the volume, then patch it in.
        let volume = fs.parse_volume()?;
        let fs = ApfsFs { volume, ..fs };

        Self::new_with_fs(cli, fs, sink).map(AnyGrepper::Apfs)
    }
}

/// impl block for ntfs-specific construction
impl<S: MatchSink> RawGrepper<NtfsFs, S> {
    #[inline]
    pub fn new_ntfs(cli: &Cli, _device_path: &str, file: File, sink: S) -> Result<AnyGrepper<S>> {
        let mut boot = [0u8; 512];
        read_at_offset(&file, &mut boot, 0)?;

        if &boot[3..11] != b"NTFS    " {
            return Err(Error::UnknownFilesystem("not an NTFS filesystem".into()))
        }

        let device_id = device_id(&file)?;
        let fs = NtfsFs::new(file, device_id)?;
        Self::new_with_fs(cli, fs, sink).map(AnyGrepper::Ntfs)
    }
}

#[inline]
pub fn open_device(path: &str) -> io::Result<File> {
    open_device_impl(path, false)
}

#[cfg(windows)]
#[inline]
pub fn open_device_impl(path: &str, _uncached: bool) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_NO_BUFFERING;

    OpenOptions::new()
        .read(true)
        .share_mode(0x3) // FILE_SHARE_READ | FILE_SHARE_WRITE
        .custom_flags(FILE_FLAG_NO_BUFFERING) // required for raw volume reads
        .open(path)
}

#[cfg(unix)]
#[inline]
pub fn open_device_impl(path: &str, uncached: bool) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = OpenOptions::new();
    opts.read(true).write(false);

    if uncached {
        opts.custom_flags(libc::O_DIRECT).open(path)
    } else {
        opts.open(path)
    }
}

#[inline]
pub fn open_device_and_detect_fs(device_path: &str) -> io::Result<(File, FsType)> {
    {
        let t = std::time::Instant::now();
        unsafe { libc::sync(); }
        eprintln!("sync: {:.2}ms", t.elapsed().as_secs_f64() * 1000.0);
    }

    let file = open_device(device_path)?;

    //
    // @Volatile
    //
    // We need to flush all the stale stuff from the VFS.
    //
    //
    // And it turns out that `syncfs()` is not realiable for our case...
    //
    // Although, while calling `ioctl` with `BLKFLSBUF` is,
    // it slows down our reads to oblivion, meaning there's no point..
    //
    // #[cfg(target_os = "linux")]
    // {
    //     use std::os::unix::io::AsRawFd;
    //     const BLKFLSBUF: libc::c_ulong = 0x1261;
    //     let ret = unsafe { libc::ioctl(file.as_raw_fd(), BLKFLSBUF, 0) };
    //     if ret != 0 {
    //         eprintln!("BLKFLSBUF failed: {}", io::Error::last_os_error());
    //     }
    // }
    // #[cfg(target_os = "macos")] {
    //     // macOS has no syncfs() or BLKFLSBUF.
    //     // F_FULLFSYNC flushes the volume containing the fd to physical storage,
    //     // which is the closest equivalent for ensuring we read committed data.
    //     use std::os::unix::io::AsRawFd;
    //     unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC); }
    // }
    //
    //
    // And by the way, having a separate handle for the device but with O_DIRECT,
    // and doing aligned inode reads from there using `POSIX_FADV_DONTNEED`
    // did not work as well. But maybe its because I misdiagnosed that the inodes
    // parsing was the problem..
    //
    //
    // In any way, `sync()` seems to work just fine for us, adding just
    // few tens of milliseconds to the walltime...
    //
    // But even though this seems to be correct 100% of the time,
    // fixing all the bugs we had regarding VFS staleness,
    // I'm kinda disappointed with this approach.
    //
    // I truly want this program to decimate all other grep-like tools
    // in walltime, proving that it's actually THE fastest one,
    // but when there's still short-lived spilling allocations
    // in medium to hot paths in this program, it doesn't really make sense
    // to focus on that `sync()` stuff....
    //

    // Read enough to cover both magic locations:
    // APFS at offset 32, ext4 superblock at offset 1024+56=1080 -> 2048 bytes is sufficient
    let mut probe = [0u8; 2048];
    read_at_offset(&file, &mut probe, 0)?;

    let fs = detect_fs_type(&probe).expect("unexpected filesystem");

    Ok((file, fs))
}

#[inline]
pub fn make_matcher(cli: &Cli) -> Result<Matcher> {
    Matcher::new(cli).map_err(|e| match e.kind() {
        io::ErrorKind::InvalidInput => Error::InvalidPattern(cli.pattern.clone()),
        _ => Error::Io(e),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsType {
    Ext4, Apfs, Ntfs
}

/// Peek at raw bytes to identify the filesystem type.
/// `block0` should be at least 2048 bytes (to cover the ext4 superblock at offset 1024).
pub fn detect_fs_type(block0: &[u8]) -> Option<FsType> {
    // NTFS: OEM ID at offset 3, 8 bytes: "NTFS    "
    if block0.len() >= 11 {
        if &block0[3..11] == b"NTFS    " {
            return Some(FsType::Ntfs);
        }
    }

    // APFS: NX magic at offset 32 in block 0
    if block0.len() >= 36 {
        let magic = u32::from_le_bytes(block0[32..36].try_into().unwrap());
        if magic == APFS_NX_MAGIC {
            return Some(FsType::Apfs);
        }
    }

    // ext4: magic at offset 1024 + 56 = 1080
    if block0.len() >= EXT4_SUPERBLOCK_OFFSET as usize + EXT4_MAGIC_OFFSET + 2 {
        let off = EXT4_SUPERBLOCK_OFFSET as usize + EXT4_MAGIC_OFFSET;
        let magic = u16::from_le_bytes(block0[off..off + 2].try_into().unwrap());
        if magic == EXT4_SUPER_MAGIC {
            return Some(FsType::Ext4);
        }
    }

    None
}

pub enum AnyGrepper<S: MatchSink = NoSink> {
    Ext4(RawGrepper<Ext4Fs, S>),
    Apfs(RawGrepper<ApfsFs, S>),
    Ntfs(RawGrepper<NtfsFs, S>),
}

impl<S: MatchSink> AnyGrepper<S> {
    #[inline]
    pub fn try_resolve_path_to_file_id(&self, path: &str) -> io::Result<FileId> {
        match self {
            AnyGrepper::Ext4(g) => g.try_resolve_path_to_file_id(path),
            AnyGrepper::Apfs(g) => g.try_resolve_path_to_file_id(path),
            AnyGrepper::Ntfs(g) => g.try_resolve_path_to_file_id(path),
        }
    }
}

impl<F: RawFs, S: MatchSink> RawGrepper<F, S> {
    #[inline]
    pub fn cli(&self) -> &Cli {
        &self.cli
    }

    #[inline]
    pub fn matcher(&self) -> &Matcher {
        &self.matcher
    }

    #[inline]
    pub fn fs(&self) -> &F {
        &self.fs
    }

    #[inline]
    pub fn fragment_hashes(&self) -> &[u32] {
        &self.fragment_hashes
    }

    #[inline]
    pub fn cache(&self) -> Option<&FragmentCache> {
        self.cache.as_ref()
    }

    #[inline]
    pub fn cache_mut(&mut self) -> Option<&mut FragmentCache> {
        self.cache.as_mut()
    }
}

impl<S: MatchSink> AnyGrepper<S> {
    #[inline]
    pub fn cli(&self) -> &Cli {
        match self {
            AnyGrepper::Ext4(g) => g.cli(),
            AnyGrepper::Apfs(g) => g.cli(),
            AnyGrepper::Ntfs(g) => g.cli(),
        }
    }

    #[inline]
    pub fn matcher(&self) -> &Matcher {
        match self {
            AnyGrepper::Ext4(g) => g.matcher(),
            AnyGrepper::Apfs(g) => g.matcher(),
            AnyGrepper::Ntfs(g) => g.matcher(),
        }
    }

    #[inline]
    pub fn fragment_hashes(&self) -> &[u32] {
        match self {
            AnyGrepper::Ext4(g) => g.fragment_hashes(),
            AnyGrepper::Apfs(g) => g.fragment_hashes(),
            AnyGrepper::Ntfs(g) => g.fragment_hashes(),
        }
    }

    #[inline]
    pub fn cache(&self) -> Option<&FragmentCache> {
        match self {
            AnyGrepper::Ext4(g) => g.cache(),
            AnyGrepper::Apfs(g) => g.cache(),
            AnyGrepper::Ntfs(g) => g.cache(),
        }
    }

    #[inline]
    pub fn cache_mut(&mut self) -> Option<&mut FragmentCache> {
        match self {
            AnyGrepper::Ext4(g) => g.cache_mut(),
            AnyGrepper::Apfs(g) => g.cache_mut(),
            AnyGrepper::Ntfs(g) => g.cache_mut(),
        }
    }
}
