use memmap2::Mmap;

use crate::{apfs::{APFS_DEFAULT_BLOCK_SIZE, NX_MAGIC, NX_SUPERBLOCK_BLOCK}, ext4::{EXT4_MAGIC_OFFSET, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPER_MAGIC}};

#[derive(Debug, Clone, Copy)]
pub enum FsType { Ext4, Apfs, Unknown }

impl std::fmt::Display for FsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ext4 => "ext4",
            Self::Apfs => "apfs",
            Self::Unknown => "unknown",
        })
    }
}

impl FsType {
    pub fn detect(mmap: &Mmap) -> Self {
        // ext4: magic at superblock (1024) + offset 0x38
        let ext4_off = EXT4_SUPERBLOCK_OFFSET as usize + EXT4_MAGIC_OFFSET;
        if mmap.len() > ext4_off + 2 {
            let magic = u16::from_le_bytes([mmap[ext4_off], mmap[ext4_off + 1]]);
            if magic == EXT4_SUPER_MAGIC {
                return Self::Ext4;
            }
        }

        // APFS: container magic at block 0, offset 0x20
        let apfs_off = (NX_SUPERBLOCK_BLOCK * APFS_DEFAULT_BLOCK_SIZE as u64) as usize + 0x20;
        if mmap.len() > apfs_off + 4 {
            let magic = u32::from_le_bytes([
                mmap[apfs_off], mmap[apfs_off + 1], mmap[apfs_off + 2], mmap[apfs_off + 3]
            ]);
            if magic == NX_MAGIC {
                return Self::Apfs;
            }
        }

        Self::Unknown
    }
}
