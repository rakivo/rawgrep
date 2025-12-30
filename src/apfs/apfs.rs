//! APFS on-disk structures and constants
//!
//! References:
//! - Apple's APFS Reference: https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
//! - Various reverse-engineering efforts

use std::fmt::Display;

/// Container superblock magic: "NXSB" in ASCII (little-endian)
pub const NX_MAGIC: u32 = 0x4253_584E;

/// Volume superblock magic: "APSB" in ASCII (little-endian)
pub const APFS_MAGIC: u32 = 0x4253_5041;

pub const OBJ_TYPE_NX_SUPERBLOCK: u32 = 0x01;
pub const OBJ_TYPE_BTREE: u32 = 0x02;
pub const OBJ_TYPE_BTREE_NODE: u32 = 0x03;
pub const OBJ_TYPE_OMAP: u32 = 0x0b;
pub const OBJ_TYPE_APFS_SUPERBLOCK: u32 = 0x0d;
pub const OBJ_TYPE_FSTREE: u32 = 0x0e;
pub const OBJ_TYPE_BLOCKREFTREE: u32 = 0x0f;
pub const OBJ_TYPE_SNAPTREE: u32 = 0x10;

/// Object type mask (lower 16 bits)
pub const OBJ_TYPE_MASK: u32 = 0x0000_ffff;

/// Object storage type flags (upper 16 bits of type field)
pub const OBJ_STORAGETYPE_MASK: u32 = 0xc000_0000;
pub const OBJ_VIRTUAL: u32 = 0x0000_0000;
pub const OBJ_EPHEMERAL: u32 = 0x8000_0000;
pub const OBJ_PHYSICAL: u32 = 0x4000_0000;

// ============================================================================
// B-tree constants
// ============================================================================

pub const BTREE_NODE_FIXED_KV_SIZE: u16 = 0x0004;
pub const BTREE_NODE_LEAF: u16 = 0x0002;
pub const BTREE_NODE_ROOT: u16 = 0x0001;

// ============================================================================
// Inode/catalog record types
// ============================================================================

pub const DREC_TYPE_MASK: u16 = 0x000f;

pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;
pub const DT_WHT: u8 = 14;

/// File mode masks (same as POSIX)
pub const S_IFMT: u16 = 0o170000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFLNK: u16 = 0o120000;

// ============================================================================
// J-key types (catalog entry types)
// ============================================================================

pub const APFS_TYPE_ANY: u8 = 0;
pub const APFS_TYPE_SNAP_METADATA: u8 = 1;
pub const APFS_TYPE_EXTENT: u8 = 2;
pub const APFS_TYPE_INODE: u8 = 3;
pub const APFS_TYPE_XATTR: u8 = 4;
pub const APFS_TYPE_SIBLING_LINK: u8 = 5;
pub const APFS_TYPE_DSTREAM_ID: u8 = 6;
pub const APFS_TYPE_CRYPTO_STATE: u8 = 7;
pub const APFS_TYPE_FILE_EXTENT: u8 = 8;
pub const APFS_TYPE_DIR_REC: u8 = 9;
pub const APFS_TYPE_DIR_STATS: u8 = 10;
pub const APFS_TYPE_SNAP_NAME: u8 = 11;
pub const APFS_TYPE_SIBLING_MAP: u8 = 12;
pub const APFS_TYPE_FILE_INFO: u8 = 13;

/// Mask for type in j_key_t obj_id_and_type
pub const OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;
pub const OBJ_TYPE_SHIFT: u64 = 60;

// ============================================================================
// Special inode numbers
// ============================================================================

/// Root directory inode number
pub const APFS_ROOT_DIR_INO_NUM: u64 = 2;

/// Invalid inode number
pub const APFS_INVALID_INO_NUM: u64 = 0;

// ============================================================================
// Block/offset constants
// ============================================================================

/// Default APFS block size
pub const APFS_DEFAULT_BLOCK_SIZE: u32 = 4096;

/// Container superblock is at block 0
pub const NX_SUPERBLOCK_BLOCK: u64 = 0;

// ============================================================================
// Parsed structures (high-level, not raw on-disk)
// ============================================================================

/// Parsed container (NX) superblock
#[derive(Debug, Clone)]
pub struct NxSuperblock {
    pub magic: u32,
    pub block_size: u32,
    pub block_count: u64,
    pub omap_oid: u64,
    pub fs_oid: [u64; 100], // Volume OIDs (max 100 volumes per container)
    pub fs_count: u32,
}

impl Display for NxSuperblock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "APFS Container:")?;
        writeln!(f, "  Block size: {} bytes", self.block_size)?;
        writeln!(f, "  Block count: {}", self.block_count)?;
        writeln!(f, "  Volume count: {}", self.fs_count)?;
        writeln!(f, "  Object map OID: 0x{:x}", self.omap_oid)?;
        Ok(())
    }
}

/// Parsed volume (APFS) superblock
#[derive(Debug, Clone)]
pub struct ApfsSuperblock {
    pub magic: u32,
    pub fs_index: u32,
    pub block_size: u32,
    pub root_tree_oid: u64,
    pub omap_oid: u64,
    pub root_dir_id: u64,
}

impl Display for ApfsSuperblock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "APFS Volume:")?;
        writeln!(f, "  Block size: {} bytes", self.block_size)?;
        writeln!(f, "  Root tree OID: 0x{:x}", self.root_tree_oid)?;
        writeln!(f, "  Object map OID: 0x{:x}", self.omap_oid)?;
        writeln!(f, "  Root dir ID: {}", self.root_dir_id)?;
        Ok(())
    }
}

/// Parsed APFS inode
#[derive(Clone, Copy, Debug)]
pub struct ApfsInode {
    pub ino: u64,
    pub parent_id: u64,
    pub mode: u16,
    pub size: u64,
    pub mtime_ns: i64,
    pub nchildren: u32, // for directories
}

/// Parsed file extent
#[derive(Clone, Copy, Debug)]
pub struct ApfsExtent {
    pub logical_offset: u64,
    pub physical_block: u64,
    pub length: u64,
}

// ============================================================================
// Raw on-disk structures (packed, for bytemuck)
// ============================================================================

pub mod raw {
    use bytemuck::{Pod, Zeroable};

    /// Object header - all APFS objects start with this (32 bytes)
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct ObjPhys {
        pub cksum: [u8; 8],      // 0x00 Fletcher-64 checksum
        pub oid: u64,           // 0x08 Object ID
        pub xid: u64,           // 0x10 Transaction ID
        pub type_and_flags: u32, // 0x18 Object type + flags
        pub subtype: u32,       // 0x1C Subtype
    }

    // NxSuperblockRaw - parsed manually due to large array
    // Container superblock offsets (relative to start of block):
    pub const NX_MAGIC_OFF: usize = 0x20;
    pub const NX_BLOCK_SIZE_OFF: usize = 0x24;
    pub const NX_BLOCK_COUNT_OFF: usize = 0x28;
    pub const NX_OMAP_OID_OFF: usize = 0xA0;
    pub const NX_FS_OID_OFF: usize = 0xB8;
    pub const NX_MAX_FILESYSTEMS: usize = 100;

    // ApfsSuperblockRaw - parsed manually due to alignment issues
    // Volume superblock offsets:
    pub const APSB_MAGIC_OFF: usize = 0x20;
    pub const APSB_FS_INDEX_OFF: usize = 0x24;
    pub const APSB_OMAP_OID_OFF: usize = 0x90;
    pub const APSB_ROOT_TREE_OID_OFF: usize = 0x98;

    /// Object map physical structure
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct OmapPhys {
        pub obj: ObjPhys,
        pub flags: u32,
        pub snap_count: u32,
        pub tree_type: u32,
        pub snapshot_tree_type: u32,
        pub tree_oid: u64,
        pub snapshot_tree_oid: u64,
        pub most_recent_snap: u64,
        pub pending_revert_min: u64,
        pub pending_revert_max: u64,
    }

    /// B-tree info (fixed part at end of node)
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct BtreeInfo {
        pub fixed: BtreeInfoFixed,
        pub longest_key: u32,
        pub longest_val: u32,
        pub key_count: u64,
        pub node_count: u64,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct BtreeInfoFixed {
        pub flags: u32,
        pub node_size: u32,
        pub key_size: u32,
        pub val_size: u32,
    }

    /// B-tree node header
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct BtreeNodePhys {
        pub obj: ObjPhys,
        pub flags: u16,
        pub level: u16,
        pub nkeys: u32,
        pub table_space_off: u16,
        pub table_space_len: u16,
        pub free_space_off: u16,
        pub free_space_len: u16,
        pub key_free_list_off: u16,
        pub key_free_list_len: u16,
        pub val_free_list_off: u16,
        pub val_free_list_len: u16,
        // Followed by: toc entries, then keys area, then free space, then values area
    }

    /// Table of contents entry for B-tree node (variable size keys/values)
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct KvOff {
        pub key_off: u16,
        pub key_len: u16,
        pub val_off: u16,
        pub val_len: u16,
    }

    /// Table of contents entry for fixed-size keys/values
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct KvLoc {
        pub key_off: u16,
        pub val_off: u16,
    }

    /// Object map key
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct OmapKey {
        pub oid: u64,
        pub xid: u64,
    }

    /// Object map value
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct OmapVal {
        pub flags: u32,
        pub size: u32,
        pub paddr: u64,
    }

    /// J-key (catalog key header)
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct JKey {
        pub obj_id_and_type: u64,
    }

    /// Directory record key header (after j_key_t)
    /// Note: Variable length - name follows immediately after
    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct JDrecHashedKey {
        pub obj_id_and_type: u64, // j_key_t
        pub name_len_and_hash: u32,
        // name bytes follow (variable length)
    }

    /// Directory record value (packed to avoid padding issues)
    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct JDrecVal {
        pub file_id: u64,
        pub date_added: u64,
        pub flags: u16,
        // xfields follow (variable)
    }

    /// Inode key
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct JInodeKey {
        pub obj_id_and_type: u64,
    }

    // JInodeVal - parsed manually due to alignment requirements
    // Inode value offsets (relative to value start):
    pub const JINODE_PARENT_ID_OFF: usize = 0x00;
    pub const JINODE_PRIVATE_ID_OFF: usize = 0x08;
    pub const JINODE_CREATE_TIME_OFF: usize = 0x10;
    pub const JINODE_MOD_TIME_OFF: usize = 0x18;
    pub const JINODE_CHANGE_TIME_OFF: usize = 0x20;
    pub const JINODE_ACCESS_TIME_OFF: usize = 0x28;
    pub const JINODE_INTERNAL_FLAGS_OFF: usize = 0x30;
    pub const JINODE_NCHILDREN_OFF: usize = 0x38;
    pub const JINODE_MODE_OFF: usize = 0x50;
    pub const JINODE_UNCOMPRESSED_SIZE_OFF: usize = 0x58;
    pub const JINODE_MIN_SIZE: usize = 0x60; // minimum inode value size

    // JDrecVal - parsed manually (packed struct)
    // Directory record value offsets:
    pub const JDREC_FILE_ID_OFF: usize = 0x00;
    pub const JDREC_DATE_ADDED_OFF: usize = 0x08;
    pub const JDREC_FLAGS_OFF: usize = 0x10;
    pub const JDREC_MIN_SIZE: usize = 0x12; // 8 + 8 + 2 = 18 bytes

    /// File extent key
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct JFileExtentKey {
        pub obj_id_and_type: u64,
        pub logical_addr: u64,
    }

    /// File extent value
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct JFileExtentVal {
        pub len_and_flags: u64,
        pub phys_block_num: u64,
        pub crypto_id: u64,
    }

    /// Dstream (data stream) ID value - links inode to extents
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct JDstreamIdVal {
        pub refcnt: u32,
    }

    /// Dstream structure (contains file size info)
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct JDstream {
        pub size: u64,
        pub alloced_size: u64,
        pub default_crypto_id: u64,
        pub total_bytes_written: u64,
        pub total_bytes_read: u64,
    }
}
