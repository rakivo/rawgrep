use std::fmt::Display;

pub type ObjId = u64;

// ─── Container Superblock (NX) ───────────────────────────────────────────────

pub const APFS_NX_MAGIC: u32                = 0x4253584E; // 'NXSB'
pub const APFS_BLOCK_SIZE_DEFAULT: u32      = 4096;

/// Byte offset inside the container's block 0
pub const APFS_NX_BLOCK_SIZE_OFFSET: usize = 8;   // __le32 nx_block_size
pub const APFS_NX_BLOCK_COUNT_OFFSET: usize = 12; // __le64 nx_block_count (starts at 12)

/// Object-map B-tree root is reachable from the NX superblock at offset 48
pub const APFS_NX_OMAP_OID_OFFSET: usize   = 160; // __le64 nx_omap_oid
pub const APFS_NX_FS_OID_OFFSET: usize     = 176; // __le64 nx_fs_oid[100] – first entry is the volume

// ─── Volume Superblock (APSB) ─────────────────────────────────────────────────

pub const APFS_APSB_MAGIC: u32             = 0x42535041; // 'APSB'
pub const APFS_APSB_ROOT_TREE_OID_OFFSET: usize = 128;  // __le64 apfs_root_tree_oid
pub const APFS_APSB_OMAP_OID_OFFSET: usize      = 120;  // __le64 apfs_omap_oid

// ─── Object types ─────────────────────────────────────────────────────────────

pub const APFS_OBJ_TYPE_NX_SUPERBLOCK: u16 = 0x0001;
pub const APFS_OBJ_TYPE_BTREE: u16         = 0x0002;
pub const APFS_OBJ_TYPE_BTREE_NODE: u16    = 0x0003;
pub const APFS_OBJ_TYPE_FS: u16            = 0x000D; // volume superblock

// ─── Object map / B-tree node header ─────────────────────────────────────────

/// Every APFS block starts with a 32-byte object header (obj_phys_t)
pub const APFS_OBJ_HDR_SIZE: usize         = 32;
/// Offset of the 8-byte OID field inside the object header
pub const APFS_OBJ_HDR_OID_OFFSET: usize   = 8;
/// Offset of the 2-byte object type field (low 16 bits of __le32 o_type)
pub const APFS_OBJ_HDR_TYPE_OFFSET: usize  = 24;

// ─── B-tree node header (btree_node_phys_t) ──────────────────────────────────

pub const APFS_BTNODE_HDR_SIZE: usize      = 56; // obj header (32) + btn header (24)
pub const APFS_BTNODE_FLAGS_OFFSET: usize  = 32; // __le16 btn_flags inside node
pub const APFS_BTNODE_NKEYS_OFFSET: usize  = 36; // __le32 btn_nkeys
pub const APFS_BTNODE_TOC_OFFSET: usize    = 40; // __le16 btn_table_space.off
pub const APFS_BTNODE_TOC_LEN_OFFSET: usize = 42;
pub const APFS_BTNODE_FREE_SPACE_OFFSET: usize = 44;
pub const APFS_BTNODE_KEY_FREE_LIST_OFFSET: usize = 48;
pub const APFS_BTNODE_VAL_FREE_LIST_OFFSET: usize = 52;

pub const APFS_BTNODE_FLAG_LEAF: u16       = 0x0004;
pub const APFS_BTNODE_FLAG_FIXED_KV: u16   = 0x0004; // same bit, re-used name for clarity

// ─── Object-map value (omap_val_t) ───────────────────────────────────────────

pub const APFS_OMAP_VAL_SIZE: usize        = 16; // flags (4) + size (4) + paddr (8)
pub const APFS_OMAP_VAL_PADDR_OFFSET: usize = 8; // __le64 ov_paddr

// ─── File-system record types (j_obj_types) ──────────────────────────────────

pub const APFS_TYPE_INODE: u8              = 3;
pub const APFS_TYPE_XATTR: u8             = 4;
pub const APFS_TYPE_FILE_EXTENT: u8        = 8;  // physical extent record
pub const APFS_TYPE_DIR_REC: u8            = 9;  // directory entry (j_drec_hashed_key_t)

// ─── Inode flags ─────────────────────────────────────────────────────────────

pub const APFS_INODE_IS_APFS_PRIVATE: u64 = 0x0001;
pub const APFS_INODE_MAINTAIN_DIR_STATS: u64 = 0x0040;

// ─── Mode bits ───────────────────────────────────────────────────────────────

pub const S_IFMT: u16  = 0xF000;
pub const S_IFREG: u16 = 0x8000;
pub const S_IFDIR: u16 = 0x4000;
pub const S_IFLNK: u16 = 0xA000;

// ─── Directory entry file types ───────────────────────────────────────────────

pub const DT_UNKNOWN: u8 = 0;
pub const DT_REG: u8     = 8;
pub const DT_DIR: u8     = 4;
pub const DT_LNK: u8     = 10;

// ─── Root inode number ────────────────────────────────────────────────────────

pub const APFS_ROOT_DIR_INO_NUM: u64 = 2;

// ─── Compressed file xattr name ──────────────────────────────────────────────

pub const APFS_XATTR_DECMPFS: &[u8] = b"com.apple.decmpfs";
pub const APFS_XATTR_RSRC_FORK: &[u8] = b"com.apple.ResourceFork";

// ─── High-level parsed structures ────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct ApfsSuperBlock {
    /// Block size in bytes (always a power of two, default 4096)
    pub block_size: u32,
    /// Physical block address of the container's object map B-tree root
    pub omap_root_paddr: u64,
    /// Physical OID of the first (usually only) volume superblock
    pub volume_oid: u64,
}

impl Display for ApfsSuperBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Block size: {} bytes", self.block_size)?;
        writeln!(f, "Omap root paddr: {}", self.omap_root_paddr)?;
        writeln!(f, "Volume OID: {}", self.volume_oid)?;
        Ok(())
    }
}

/// Resolved volume metadata we need at runtime
#[derive(Clone, Copy)]
pub struct ApfsVolume {
    /// Physical block address of this volume's object map B-tree root
    pub omap_root_paddr: u64,
    /// Physical block address of the volume's fs-record B-tree root
    pub root_tree_paddr: u64,
}

/// Parsed APFS inode (j_inode_val_t + key)
#[derive(Clone, Copy)]
pub struct ApfsInode {
    pub inode_num: u64,
    pub mode: u16,
    pub size: u64,
    pub mtime_sec: i64,
    /// BSD flags / inode flags (j_inode_flags)
    pub flags: u64,
}

pub mod raw {
    use bytemuck::{Pod, Zeroable};

    // ── obj_phys_t ──────────────────────────────────────────────────────────
    // Every APFS block on-disk starts with this 32-byte header.
    //
    // struct obj_phys_t {
    //     uint8_t  o_cksum[8];   // Fletcher-64 checksum
    //     uint64_t o_oid;        // object ID
    //     uint64_t o_xid;        // transaction ID
    //     uint32_t o_type;       // object type | flags
    //     uint32_t o_subtype;    // object sub-type
    // };
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct ObjPhys {
        pub o_cksum:   [u8; 8],  // 0x00
        pub o_oid:     u64,      // 0x08
        pub o_xid:     u64,      // 0x10
        pub o_type:    u32,      // 0x18
        pub o_subtype: u32,      // 0x1C
    }

    // ── btree_node_phys_t ───────────────────────────────────────────────────
    //
    // struct btree_node_phys_t {
    //     obj_phys_t  btn_o;
    //     uint16_t    btn_flags;
    //     uint16_t    btn_level;
    //     uint32_t    btn_nkeys;
    //     nloc_t      btn_table_space;
    //     nloc_t      btn_free_space;
    //     nloc_t      btn_key_free_list;
    //     nloc_t      btn_val_free_list;
    //     uint64_t    btn_data[];   // key/value table
    // };
    //
    // nloc_t = { uint16_t off; uint16_t len; }
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct BtreeNodePhys {
        pub btn_o:              ObjPhys,  // 0x00 – 32 bytes
        pub btn_flags:          u16,      // 0x20
        pub btn_level:          u16,      // 0x22
        pub btn_nkeys:          u32,      // 0x24
        pub btn_table_space_off: u16,     // 0x28  (nloc_t.off)
        pub btn_table_space_len: u16,     // 0x2A  (nloc_t.len)
        pub btn_free_space_off:  u16,     // 0x2C
        pub btn_free_space_len:  u16,     // 0x2E
        pub btn_key_free_off:    u16,     // 0x30
        pub btn_key_free_len:    u16,     // 0x32
        pub btn_val_free_off:    u16,     // 0x34
        pub btn_val_free_len:    u16,     // 0x36
        // btn_data[] follows at 0x38
    }

    // ── kvoff_t – used inside the ToC for variable-length nodes ────────────
    //
    // struct kvoff_t { uint16_t k; uint16_t v; }
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct KvOff {
        pub k: u16,
        pub v: u16,
    }

    // ── kvloc_t – used inside the ToC for fixed-length nodes ───────────────
    //
    // struct kvloc_t { nloc_t k; nloc_t v; }
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct KvLoc {
        pub k_off: u16,
        pub k_len: u16,
        pub v_off: u16,
        pub v_len: u16,
    }

    // ── j_key_t – every fs-record key starts with this ─────────────────────
    //
    // struct j_key_t { uint64_t obj_id_and_type; }
    //   bits 63-60 = record type
    //   bits 59-0  = object ID
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct JKey {
        pub obj_id_and_type: u64,
    }

    // ── j_inode_val_t ───────────────────────────────────────────────────────
    //
    // (only the fields we actually use; the struct is larger on disk)
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct JInodeVal {
        pub parent_id:   u64,  // 0x00
        pub private_id:  u64,  // 0x08
        pub create_time: u64,  // 0x10  nanoseconds
        pub mod_time:    u64,  // 0x18  nanoseconds
        pub change_time: u64,  // 0x20  nanoseconds
        pub access_time: u64,  // 0x28  nanoseconds
        pub internal_flags: u64, // 0x30
        pub nchildren_or_nlink: u32, // 0x38  (union)
        pub default_protection_class: u32, // 0x3C
        pub write_generation_counter: u32, // 0x40
        pub bsd_flags: u32,    // 0x44
        pub owner:  u32,       // 0x48
        pub group:  u32,       // 0x4C
        pub mode:   u16,       // 0x50
        pub pad1:   u16,       // 0x52
        pub uncompressed_size_lo: u32, // 0x54
        pub uncompressed_size_hi: u32, // 0x58
        pub _pad2:  u32,       // 0x5C
    }

    // ── j_drec_hashed_key_t ─────────────────────────────────────────────────
    //
    // struct j_drec_hashed_key_t {
    //     j_key_t  hdr;
    //     uint32_t name_len_and_hash;  // bits 9-0 = name_len+1, bits 31-10 = hash
    //     uint8_t  name[];
    // }
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct JDrecHashedKey {
        pub hdr:               JKey, // 0x00 – 8 bytes
        pub name_len_and_hash: u32,  // 0x08
        pub _pad:              u32,  // 0x0C – explicit pad so sizeof == 16, no implicit padding
        // name bytes follow immediately after this fixed header in the key area
    }

    // ── j_drec_val_t ────────────────────────────────────────────────────────
    //
    // struct j_drec_val_t {
    //     uint64_t file_id;
    //     uint64_t date_added;
    //     uint16_t flags;       // dir-entry type in low 4 bits (dt_type)
    //     xf_blob_t xfields[];
    // }
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct JDrecVal {
        pub file_id:    u64,      // 0x00
        pub date_added: u64,      // 0x08
        pub flags:      u16,      // 0x10  low 4 bits = file type
        pub _pad:       [u8; 6],  // 0x12  explicit pad; sizeof == 24, matches on-disk xfield alignment
    }

    // ── omap_key_t / omap_val_t ─────────────────────────────────────────────
    //
    // struct omap_key_t  { uint64_t ok_oid; uint64_t ok_xid; }
    // struct omap_val_t  { uint32_t ov_flags; uint32_t ov_size; uint64_t ov_paddr; }
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct OmapKey {
        pub ok_oid: u64,
        pub ok_xid: u64,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct OmapVal {
        pub ov_flags: u32,
        pub ov_size:  u32,
        pub ov_paddr: u64,
    }

    // ── j_phys_ext_key_t / j_phys_ext_val_t (file extents) ──────────────────
    //
    // struct j_phys_ext_key_t { j_key_t hdr; uint64_t logical_addr; }
    // struct j_phys_ext_val_t { uint64_t len_and_flags; uint64_t phys_block_num; uint64_t crypto_id; }
    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct JPhysExtKey {
        pub hdr:          JKey,
        pub logical_addr: u64,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct JPhysExtVal {
        pub len_and_flags: u64,  // bits 55-0 = byte length, bits 63-56 = flags
        pub phys_block_num: u64,
        pub crypto_id:      u64,
    }
}
