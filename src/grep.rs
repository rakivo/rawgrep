use crate::debug;
use crate::unwrap_::Unwrap_;
use crate::apfs::{ApfsFs, ApfsVolume, APFS_NX_MAGIC, ApfsNodeHot, ApfsNodeCold};
use crate::cli::Cli;
use crate::matcher::Matcher;
use crate::ntfs::{NtfsFs, NtfsNodeHot, NtfsNodeCold};
use crate::fragments::FragmentLen;
use crate::util::read_at_offset;
use crate::{Result, Error, tracy};
use crate::platform::device_id;
use crate::cache::{CacheConfig, FragmentCache};
use crate::parser::{BufKind, UniversalFileId, FileNode, Parser, RawFs, FileId};
use crate::binary_verdicts::BinaryVerdicts;
use crate::sink::{MatchSink, NoSink};
use crate::ext4::parser::InodeBlockCache;
use crate::ext4::{
    EXT4_INODE_TABLE_OFFSET, EXT4_MAGIC_OFFSET, EXT4_SUPER_MAGIC, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE, Ext4Fs, Ext4NodeHot,Ext4NodeCold
};

use std::time::Instant;
use std::os::fd::AsRawFd;
use std::path::{MAIN_SEPARATOR, MAIN_SEPARATOR_STR};
use std::io::{self, Seek};
use std::fs::{File, OpenOptions};

use nohash_hasher::IntSet;

pub struct RawGrepper<F: RawFs, S: MatchSink = NoSink> {
    cli: Cli,
    fs: F,
    matcher: Matcher,
    cache: Option<FragmentCache>,
    pub binary_verdicts: BinaryVerdicts,

    fragment_hashes: Vec<u32>,
    fragment_indexes: Vec<u32>,
    fragment_index: IntSet<u32>,
    selected_fragment_hash_len: FragmentLen,

    pub ignore_case: bool,
    pub single_literal_fragments: bool,

    pub sink: S
}

/// impl block for generic RawFs
impl<F: RawFs, S: MatchSink> RawGrepper<F, S> {
    pub fn new_with_fs(cli: &Cli, fs: F, sink: S) -> Result<Self> {
        let t0 = Instant::now();

        let matcher = Matcher::new(cli)?;

        // `None` means the pattern is too short for any window to be useful -- treat that the same as "no fragments".
        let (fragment_hashes, selected_fragment_hash_len, ignore_case, single_literal_fragments) = match matcher.extract_fragment_hashes() {
            Some((hashes, fragment_len, ignore_case, single_literal)) => (
                hashes, FragmentLen::from_fragment_len(fragment_len),
                ignore_case, single_literal
            ),

            None => (Vec::new(), FragmentLen::Four, cli.ignore_case, true), // moot: fragment_hashes empty, cache stays None below
        };

        let fragment_index = fragment_hashes.iter().copied().collect();

        let mut fragment_indexes = Vec::new();

        let mut config = CacheConfig::from_memory_mb(cli.cache_size_mb);
        config.cache_dir = cli.cache_dir.clone().map(Into::into);
        config.ignore_cache = cli.rebuild_cache;

        let cache = if !cli.no_cache && !fragment_hashes.is_empty() {
            match FragmentCache::new(&config) {
                Ok(cache) => {
                    cache.resolve_fragment_indexes(&fragment_hashes, &mut fragment_indexes);
                    Some(cache)
                }

                Err(e) => {
                    debug!("Warning: Failed to initialize cache: {e}");
                    None
                }
            }
        } else {
            None
        };

        let binary_verdicts_path = if !cli.should_search_binary() {
            crate::cache::get_cache_path(config.cache_dir.as_deref(), "binary-verdicts.bin").ok()
        } else {
            None
        };
        let binary_verdicts = match &binary_verdicts_path {
            Some(p) => BinaryVerdicts::load(p),
            None    => BinaryVerdicts::empty(),
        };

        #[cfg(unix)]
        {
            let mut holder_paths = Vec::with_capacity(3);

            if let Some(cache) = cache.as_ref() {
                if cache.loaded_from_disk {
                    if let Ok(p) = crate::cache::get_cache_path(config.cache_dir.as_deref(), "fragment-cache.bin") {
                        holder_paths.push(p);
                    }
                }
            }

            if !binary_verdicts.is_empty() {
                if let Some(p) = &binary_verdicts_path {
                    holder_paths.push(p.clone());
                }
            }

            #[cfg(target_os = "linux")]
            if let Some(p) = crate::stale::holder_path() {
                holder_paths.push(p);
            }

            crate::holder::ensure(&holder_paths);
        }

        debug!("prepared RawGrepper in {}ms", t0.elapsed().as_millis() as f64);

        Ok(RawGrepper {
            cli: cli.clone(),
            fs,
            matcher,
            single_literal_fragments,
            ignore_case,
            binary_verdicts,
            cache,
            fragment_hashes,
            fragment_indexes,
            sink,
            selected_fragment_hash_len,
            fragment_index
        })
    }

    /// Resolve a path like "/usr/bin" or "etc" into a file ID.
    #[inline]
    pub fn try_resolve_path_to_file_id(&self, path: &str) -> io::Result<UniversalFileId> {
        let _span = tracy::span!("RawGrepper::try_resolve_path_to_file_id");

        if path == MAIN_SEPARATOR_STR || path.is_empty() {
            return Ok(self.fs.root_id().into_uni());
        }

        let mut parser = Parser::new(false);
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
            self.fs.read_file_content(&mut parser, &node, dir_size, BufKind::Dir, false, false)?;

            file_id = parser.find_file_id_in_buf(
                &self.fs,
                part.as_bytes(),
                BufKind::Dir,
            ).ok_or_else(|| io::Error::new(
                io::ErrorKind::NotFound,
                format!("Component '{part}' not found"),
            ))?;
        }

        Ok(file_id.into_uni())
    }
}

/// impl block for ext4-specific construction
impl<S: MatchSink> RawGrepper<Ext4Fs, S> {
    #[inline]
    pub fn new_ext4(cli: &Cli, device_path: &str, mut file: File, sink: S) -> Result<AnyGrepper<S>> {
        let t0 = Instant::now();

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
        let file_size = file.seek(std::io::SeekFrom::End(0))?;
        file.seek(std::io::SeekFrom::Start(0))?; // Just in case
        let max_block = file_size / sb.block_size as u64;

        #[cfg(unix)]
        unsafe {
            use std::os::fd::AsRawFd;
            libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        }

        //
        // Pre-cache inode table block offsets for all block groups
        //

        let num_blocks = max_block;
        let num_groups = num_blocks.div_ceil(sb.blocks_per_group as u64);
        let mut inode_table_blocks = Vec::with_capacity(num_groups as usize);
        for group in 0..num_groups {
            let bg_desc_offset = if sb.block_size == 1024 {
                2048
            } else {
                sb.block_size as usize
            } + (group as usize * sb.desc_size as usize);

            let mut bg_desc_buf = [0u8; 64];
            read_at_offset(&file, &mut bg_desc_buf[..sb.desc_size as usize], bg_desc_offset as u64)?;
            let inode_table_block = u32::from_le_bytes([
                bg_desc_buf[EXT4_INODE_TABLE_OFFSET + 0],
                bg_desc_buf[EXT4_INODE_TABLE_OFFSET + 1],
                bg_desc_buf[EXT4_INODE_TABLE_OFFSET + 2],
                bg_desc_buf[EXT4_INODE_TABLE_OFFSET + 3],
            ]);
            inode_table_blocks.push(inode_table_block as u64);
        }

        debug!("read ext4 block groups in {}ms", t0.elapsed().as_millis() as f64);

        #[cfg(target_os = "linux")]
        crate::stale::init(device_path);

        let fs = Ext4Fs {
            file_as_fd: file.as_raw_fd(), file,
            sb, device_id, max_block, inode_table_blocks
        };
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

        let fs = ApfsFs {
            file_as_fd: file.as_raw_fd(), file, sb,
            device_id, volume: ApfsVolume { omap_root_paddr: 0, root_tree_paddr: 0 }
        };

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
        let fs = NtfsFs::new(file, device_id, cli)?;
        Self::new_with_fs(cli, fs, sink).map(AnyGrepper::Ntfs)
    }
}

#[inline]
pub fn open_device(path: &str) -> io::Result<File> {
    open_device_impl(path)
}

#[cfg(windows)]
#[inline]
pub fn open_device_impl(path: &str) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_NO_BUFFERING;

    OpenOptions::new().read(true).share_mode(0x3).open(path)
}

#[cfg(unix)]
#[inline]
pub fn open_device_impl(path: &str) -> io::Result<File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOATIME)
        .open(path)
        .or_else(|_| OpenOptions::new().read(true).write(false).open(path))?;

    let fd = file.as_raw_fd();
    unsafe { libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_RANDOM); }

    Ok(file)
}

#[inline]
pub fn open_device_and_detect_fs(device_path: &str) -> Result<(File, FileSystem)> {
    let file = open_device(device_path).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound         => Error::DeviceNotFound(device_path.into()),
        io::ErrorKind::PermissionDenied => Error::PermissionDenied(device_path.into()),
        _                               => Error::Io(e),
    })?;

    //
    // @Volatile
    //
    // We need to flush all the stale stuff from the VFS.
    //
    // And it turns out that `syncfs()` is not realiable for our case...
    //

    {
        let t = std::time::Instant::now();

        #[cfg(unix)]
        {
            #[cfg(target_os = "linux")]
            fn sync_mounted_fs(dev: &File) -> bool {
                use std::os::fd::AsRawFd;
                use std::os::unix::fs::MetadataExt;

                let Ok(rdev) = dev.metadata().map(|m| m.rdev())                  else { return false };
                let want = format!("{}:{}", libc::major(rdev), libc::minor(rdev));

                let Ok(mounts) = std::fs::read_to_string("/proc/self/mountinfo") else { return false };

                for line in mounts.lines() {
                    let mut f = line.split(' ');

                    // Fields: id, parent id, major:minor, root, mount point, ...
                    let (Some(devno), Some(mnt)) = (f.nth(2), f.nth(1))          else { continue };
                    if devno != want { continue; }

                    let Ok(dir) = File::open(mnt.replace("\\040", " "))          else { continue };

                    // Something else mounted on top of the path would make syncfs sync the wrong fs
                    if !dir.metadata().is_ok_and(|m| m.dev() == rdev) { continue; }

                    return unsafe { libc::syncfs(dir.as_raw_fd()) } == 0;
                }

                false
            }

            #[cfg(target_os = "linux")] {
                crate::stale::mark_run_start();
                if !sync_mounted_fs(&file) {
                    unsafe { libc::sync(); }
                }
            }

            #[cfg(not(target_os = "linux"))] {
                libc::sync();
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;
            use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

            let handle = file.as_raw_handle();
            let result = unsafe { FlushFileBuffers(handle as _) };
            if result == 0 {
                let err = io::Error::last_os_error();

                //
                // A read-only handle has nothing to flush -- FlushFileBuffers
                // requires GENERIC_WRITE, so ERROR_ACCESS_DENIED here just means
                // 'this handle can't flush' ...
                //
                if err.raw_os_error() != Some(ERROR_ACCESS_DENIED as i32) {
                    return Err(err);
                } else {
                    debug!("FlushFileBuffers skipped: handle not opened for write");
                }
            }

            if let Ok(sector_size) = crate::platform::windows::query_sector_size(&file) {
                _ = crate::util::SECTOR_SIZE.set(sector_size);
            }
        }

        debug!("sync: {:.2}ms", t.elapsed().as_millis() as f64);
    }

    // Read enough to cover both magic locations:
    // APFS at offset 32, ext4 superblock at offset 1024+56=1080 -> 2048 bytes is sufficient
    let mut probe = [0u8; 2048];
    read_at_offset(&file, &mut probe, 0)?;

    match detect_fs_type(&file, &probe) {
        FileSystemProbe::Supported(fs) => Ok((file, fs)),
        FileSystemProbe::Recognized(name) => Err(Error::UnsupportedFilesystem {
            device: device_path.into(),
            fs: name.into(),
        }),
        FileSystemProbe::Unknown => Err(Error::UnknownFilesystem(device_path.into())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSystem {
    Ext4, Apfs, Ntfs
}

/// Result of probing a device's boot sector / superblock region.
pub enum FileSystemProbe {
    /// A filesystem rawgrep knows how to search.
    Supported(FileSystem),
    /// A filesystem we recognized the magic for, but don't support searching yet.
    Recognized(&'static str),
    /// Nothing we recognize -- probably the wrong partition, an unpartitioned
    /// disk, or a filesystem we've never added a signature for.
    Unknown,
}

/// Peek at raw bytes to identify the filesystem type.
///
/// 'block0' should be at least 2048 bytes -- enough to cover ext4's
/// superblock (offset 1024), HFS+'s magic (also 1024), the FAT/exFAT
/// boot-sector fields, and XFS's magic at offset 0. Btrfs' magic sits
/// much further in, so if nothing in 'block0' matches, this does one
/// extra small read via 'file' before giving up.
pub fn detect_fs_type(file: &File, block0: &[u8]) -> FileSystemProbe {
    const XFS_MAGIC: [u8; 4]      = *b"XFSB";
    const EXFAT_OEM_ID: [u8; 8]   = *b"EXFAT   ";
    const BTRFS_MAGIC: [u8; 8]    = *b"_BHRfS_M";
    const BTRFS_MAGIC_OFFSET: u64 = 0x10040; // 65600
    const HFSPLUS_MAGIC: u16      = 0x482B; // "H+"
    const HFSX_MAGIC: u16         = 0x4858;    // "HX"

    // ext4 (and ext2/ext3, which share the same magic): offset 1024 + 56
    if block0.len() >= EXT4_SUPERBLOCK_OFFSET as usize + EXT4_MAGIC_OFFSET + 2 {
        let off = EXT4_SUPERBLOCK_OFFSET as usize + EXT4_MAGIC_OFFSET;
        let magic = u16::from_le_bytes(block0[off..off + 2].try_into().unwrap_());
        if magic == EXT4_SUPER_MAGIC {
            return FileSystemProbe::Supported(FileSystem::Ext4);
        }
    }

    // NTFS: OEM ID at offset 3, 8 bytes: "NTFS    "
    if block0.len() >= 11 && &block0[3..11] == b"NTFS    " {
        return FileSystemProbe::Supported(FileSystem::Ntfs);
    }

    // APFS: NX magic at offset 32 in block 0
    if block0.len() >= 36 {
        let magic = u32::from_le_bytes(block0[32..36].try_into().unwrap_());
        if magic == APFS_NX_MAGIC {
            return FileSystemProbe::Supported(FileSystem::Apfs);
        }
    }

    // --- recognized, but unsupported, from here down ---

    // XFS: "XFSB" at offset 0
    if block0.len() >= 4 && block0[0..4] == XFS_MAGIC {
        return FileSystemProbe::Recognized("XFS");
    }

    // exFAT: OEM ID at offset 3, 8 bytes: "EXFAT   "
    if block0.len() >= 11 && block0[3..11] == EXFAT_OEM_ID {
        return FileSystemProbe::Recognized("exFAT");
    }

    // FAT12/16/32: 0x55AA boot signature at 510..512, plus a FAT-ish label
    // in the BPB so we don't false-positive on any old boot-sectored disk.
    if block0.len() >= 512
        && block0[510] == 0x55
        && block0[511] == 0xAA
        && (block0.get(54..62) == Some(b"FAT12   ".as_slice())
            || block0.get(54..62) == Some(b"FAT16   ".as_slice())
            || block0.get(82..90) == Some(b"FAT32   ".as_slice()))
    {
        return FileSystemProbe::Recognized("FAT");
    }

    // HFS+ / HFSX: "H+" or "HX" at offset 1024
    if block0.len() >= 1026 {
        let magic = u16::from_be_bytes(block0[1024..1026].try_into().unwrap_());
        if magic == HFSPLUS_MAGIC || magic == HFSX_MAGIC {
            return FileSystemProbe::Recognized("HFS+");
        }
    }

    // Btrfs: fixed absolute offset far past block0, so only reach for it
    // once everything cheaper has failed.
    let mut btrfs_magic = [0u8; 8];
    if read_at_offset(file, &mut btrfs_magic, BTRFS_MAGIC_OFFSET).is_ok()
        && btrfs_magic == BTRFS_MAGIC
    {
        return FileSystemProbe::Recognized("Btrfs");
    }

    FileSystemProbe::Unknown
}

#[derive(Default, Clone, Copy)]
pub struct NodeCacheStats {
    pub hits:   u32,
    pub misses: u32,
}

pub enum AnyNodeHotScratch {
    Ext4(Vec<Ext4NodeHot>),
    Apfs(Vec<ApfsNodeHot>),
    Ntfs(Vec<NtfsNodeHot>),
}

pub enum AnyNodeColdScratch {
    Ext4(Vec<Ext4NodeCold>),
    Apfs(Vec<ApfsNodeCold>),
    Ntfs(Vec<NtfsNodeCold>),
}

pub enum AnyNodeCache {
    Ext4(InodeBlockCache),
    Apfs(()),
    Ntfs(()),
}

impl Default for AnyNodeHotScratch {
    fn default() -> Self { AnyNodeHotScratch::Ext4(Vec::new()) }
}
impl Default for AnyNodeColdScratch {
    fn default() -> Self { AnyNodeColdScratch::Ext4(Vec::new()) }
}

impl Default for AnyNodeCache {
    fn default() -> Self {
        AnyNodeCache::Ext4(InodeBlockCache::default())
    }
}

pub enum AnyGrepper<S: MatchSink = NoSink> {
    Ext4(RawGrepper<Ext4Fs, S>),
    Apfs(RawGrepper<ApfsFs, S>),
    Ntfs(RawGrepper<NtfsFs, S>),
}

impl<S: MatchSink> AnyGrepper<S> {
    #[inline]
    pub fn try_resolve_path_to_file_id(&self, path: &str) -> io::Result<UniversalFileId> {
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
    pub fn ignore_case(&self) -> bool {
        self.ignore_case
    }

    #[inline]
    pub fn single_literal_fragments(&self) -> bool {
        self.single_literal_fragments
    }

    #[inline]
    pub fn fragment_index(&self) -> &IntSet<u32> {
        &self.fragment_index
    }

    #[inline]
    pub fn fs(&self) -> &F {
        &self.fs
    }

    #[inline]
    pub fn fragment_hashes_and_cache_mut(&mut self) -> (&[u32], Option<&mut FragmentCache>) {
        (&self.fragment_hashes, self.cache.as_mut())
    }

    #[inline]
    pub fn selected_fragment_hash_len(&self) -> FragmentLen {
        self.selected_fragment_hash_len
    }

    #[inline]
    pub fn fragment_hashes(&self) -> &[u32] {
        &self.fragment_hashes
    }

    #[inline]
    pub fn fragment_indexes(&self) -> &[u32] {
        &self.fragment_indexes
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
    pub fn fragment_index(&self) -> &IntSet<u32> {
        match self {
            AnyGrepper::Ext4(g) => g.fragment_index(),
            AnyGrepper::Apfs(g) => g.fragment_index(),
            AnyGrepper::Ntfs(g) => g.fragment_index(),
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
    pub fn fragment_indexes(&self) -> &[u32] {
        match self {
            AnyGrepper::Ext4(g) => g.fragment_indexes(),
            AnyGrepper::Apfs(g) => g.fragment_indexes(),
            AnyGrepper::Ntfs(g) => g.fragment_indexes(),
        }
    }

    #[inline]
    pub fn selected_fragment_hash_len(&self) -> FragmentLen {
        match self {
            AnyGrepper::Ext4(g) => g.selected_fragment_hash_len(),
            AnyGrepper::Apfs(g) => g.selected_fragment_hash_len(),
            AnyGrepper::Ntfs(g) => g.selected_fragment_hash_len(),
        }
    }

    #[inline]
    pub fn binary_verdicts(&self) -> &BinaryVerdicts {
        match self {
            AnyGrepper::Ext4(g) => &g.binary_verdicts,
            AnyGrepper::Apfs(g) => &g.binary_verdicts,
            AnyGrepper::Ntfs(g) => &g.binary_verdicts,
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

    #[inline]
    pub fn matcher(&self) -> &Matcher {
        match self {
            AnyGrepper::Ext4(g) => g.matcher(),
            AnyGrepper::Apfs(g) => g.matcher(),
            AnyGrepper::Ntfs(g) => g.matcher(),
        }
    }

    #[inline]
    pub fn ignore_case(&self) -> bool {
        match self {
            AnyGrepper::Ext4(g) => g.ignore_case(),
            AnyGrepper::Apfs(g) => g.ignore_case(),
            AnyGrepper::Ntfs(g) => g.ignore_case(),
        }
    }

    #[inline]
    pub fn single_literal_fragments(&self) -> bool {
        match self {
            AnyGrepper::Ext4(g) => g.single_literal_fragments(),
            AnyGrepper::Apfs(g) => g.single_literal_fragments(),
            AnyGrepper::Ntfs(g) => g.single_literal_fragments(),
        }
    }

    #[inline]
    pub fn fragment_hashes_and_cache_mut(&mut self) -> (&[u32], Option<&mut FragmentCache>) {
        match self {
            AnyGrepper::Ext4(g) => g.fragment_hashes_and_cache_mut(),
            AnyGrepper::Apfs(g) => g.fragment_hashes_and_cache_mut(),
            AnyGrepper::Ntfs(g) => g.fragment_hashes_and_cache_mut(),
        }
    }
}
