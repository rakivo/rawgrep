use std::fmt::Display;

pub type MftRecordNum = u64;

// Boot sector
pub const NTFS_SIGNATURE: &[u8; 8] = b"NTFS    ";
pub const NTFS_BOOT_SECTOR_SIZE: usize = 512;
pub const NTFS_OEM_ID_OFFSET: usize = 3;
pub const NTFS_BYTES_PER_SECTOR_OFFSET: usize = 11;
pub const NTFS_SECTORS_PER_CLUSTER_OFFSET: usize = 13;
pub const NTFS_MFT_LCN_OFFSET: usize = 48;       // Logical Cluster Number of $MFT
pub const NTFS_MFT_MIRROR_LCN_OFFSET: usize = 56;
pub const NTFS_CLUSTERS_PER_MFT_RECORD_OFFSET: usize = 64;
pub const NTFS_VOLUME_SIZE_OFFSET: usize = 40;    // Total sectors

// MFT record
pub const NTFS_FILE_MAGIC: u32 = 0x454C4946; // "FILE"
pub const NTFS_MFT_RECORD_SIZE: usize = 1024;      // Default; overridden by boot sector
pub const NTFS_MFT_RECORD_ATTRS_OFFSET: usize = 20; // offset of first attribute in record header
pub const NTFS_MFT_RECORD_FLAGS_OFFSET: usize = 22;
pub const NTFS_MFT_RECORD_FLAG_IN_USE: u16 = 0x01;
pub const NTFS_MFT_RECORD_FLAG_IS_DIR: u16 = 0x02;
pub const NTFS_MFT_RECORD_NUM_OFFSET: usize = 44; // low 32 bits of record number

// Well-known MFT record numbers
pub const NTFS_MFT_RECORD_MFT: MftRecordNum = 0;
pub const NTFS_ROOT_DIR_RECORD: MftRecordNum = 5;

// Attribute types
pub const NTFS_ATTR_STANDARD_INFORMATION: u32 = 0x10;
pub const NTFS_ATTR_FILE_NAME: u32 = 0x30;
pub const NTFS_ATTR_DATA: u32 = 0x80;
pub const NTFS_ATTR_INDEX_ROOT: u32 = 0x90;
pub const NTFS_ATTR_INDEX_ALLOCATION: u32 = 0xA0;
pub const NTFS_ATTR_END: u32 = 0xFFFF_FFFF;
pub const NTFS_FILE_ATTR_DIRECTORY: u32 = 0x10000000;

// Attribute header (common part, both resident and non-resident)
pub const NTFS_ATTR_TYPE_OFFSET: usize = 0;
pub const NTFS_ATTR_LEN_OFFSET: usize = 4;
pub const NTFS_ATTR_NON_RESIDENT_OFFSET: usize = 8; // u8, 0 = resident, 1 = non-resident
pub const NTFS_ATTR_NAME_LEN_OFFSET: usize = 9;
pub const NTFS_ATTR_NAME_OFF_OFFSET: usize = 10;    // u16

// Resident attribute
pub const NTFS_ATTR_RES_VALUE_LEN_OFFSET: usize = 16; // u32
pub const NTFS_ATTR_RES_VALUE_OFF_OFFSET: usize = 20; // u16

// Non-resident attribute
pub const NTFS_ATTR_NONRES_ALLOC_SIZE_OFFSET: usize = 24;  // u64
pub const NTFS_ATTR_NONRES_DATA_SIZE_OFFSET: usize = 32;   // u64
pub const NTFS_ATTR_NONRES_RUNLIST_OFFSET: usize = 32;     // u16, offset from attr start
pub const NTFS_ATTR_NONRES_RUNLIST_OFF_FIELD: usize = 32;  // u16

// $FILE_NAME attribute content offsets (within value)
pub const NTFS_FN_PARENT_MFT_OFFSET: usize = 0;   // u64 (48-bit record + 16-bit seq)
pub const NTFS_FN_CTIME_OFFSET: usize = 8;         // u64 Windows FILETIME
pub const NTFS_FN_MTIME_OFFSET: usize = 16;        // u64
pub const NTFS_FN_ALLOC_SIZE_OFFSET: usize = 40;   // u64
pub const NTFS_FN_DATA_SIZE_OFFSET: usize = 48;    // u64
pub const NTFS_FN_FLAGS_OFFSET: usize = 56;        // u32
pub const NTFS_FN_NAME_LEN_OFFSET: usize = 64;     // u8 (in UTF-16 chars)
pub const NTFS_FN_NAMESPACE_OFFSET: usize = 65;    // u8
pub const NTFS_FN_NAME_OFFSET: usize = 66;         // UTF-16LE name starts here

// $STANDARD_INFORMATION offsets (within value)
pub const NTFS_SI_MTIME_OFFSET: usize = 16;        // u64 Windows FILETIME

// Index entry flags
pub const NTFS_INDEX_ENTRY_NODE: u16 = 0x01;      // Has sub-node (VCN at end)
pub const NTFS_INDEX_ENTRY_LAST: u16 = 0x02;      // Last entry in node

// Index block magic
pub const NTFS_INDX_MAGIC: u32 = 0x58444E49; // "INDX"

// Windows FILETIME epoch offset to Unix epoch (100ns intervals)
// 1601-01-01 to 1970-01-01
pub const FILETIME_EPOCH_OFFSET: u64 = 11644473600 * 10_000_000;

pub struct NtfsSuperBlock {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub cluster_size: u32,       // bytes
    pub mft_lcn: u64,            // LCN of $MFT
    pub mft_record_size: u32,    // bytes per MFT record
}

impl NtfsSuperBlock {
    pub fn mft_offset(&self) -> u64 {
        self.mft_lcn * self.cluster_size as u64
    }
}

impl Display for NtfsSuperBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Bytes per sector: {}", self.bytes_per_sector)?;
        writeln!(f, "Sectors per cluster: {}", self.sectors_per_cluster)?;
        writeln!(f, "Cluster size: {} bytes", self.cluster_size)?;
        writeln!(f, "MFT LCN: {}", self.mft_lcn)?;
        writeln!(f, "MFT record size: {} bytes", self.mft_record_size)?;
        Ok(())
    }
}

/// Parsed MFT record / inode equivalent
#[derive(Clone, Copy)]
pub struct NtfsNode {
    pub record_num: MftRecordNum,
    pub flags: u16,
    pub size: u64,          // from $FILE_NAME data size
    pub mtime_sec: i64,     // from $STANDARD_INFORMATION, Unix epoch seconds
}

/// A single run (extent) in an NTFS runlist
#[derive(Clone, Copy, Debug, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct NtfsExtent {
    pub lcn: u64,       // logical cluster number on disk (absolute); u64::MAX = sparse
    pub vcn: u64,       // virtual cluster number (offset within file)
    pub len: u64,       // length in clusters
}
