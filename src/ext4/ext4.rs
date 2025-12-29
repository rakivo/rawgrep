use std::fmt::Display;

pub type INodeNum = u32;

// pub const MAX_SYMLINK_TARGET_SIZE: usize = 4096;
// pub const FAST_SYMLINK_SIZE: usize = 60; // Symlinks < 60 bytes stored in inode

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

// pub const EXT4_FT_UNKNOWN: u8 =	0;
pub const EXT4_FT_REG_FILE: u8 = 1;
pub const EXT4_FT_DIR: u8 = 2;
// pub const EXT4_FT_CHRDEV: u8 = 3;
// pub const EXT4_FT_BLKDEV: u8 = 4;
// pub const EXT4_FT_FIFO: u8 = 5;
// pub const EXT4_FT_SOCK: u8 = 6;
// pub const EXT4_FT_SYMLINK: u8 = 7;

pub const EXT4_S_IFMT: u16 = 0xF000;
pub const EXT4_S_IFREG: u16 = 0x8000;
// pub const EXT4_S_IFLNK: u16 = 0xA000;
pub const EXT4_S_IFDIR: u16 = 0x4000;

pub const EXT4_EXTENTS_FL: u32 = 0x80000;
pub const EXT4_INLINE_DATA_FL: u32 = 0x10000000;

pub const EXT4_EXTENT_MAGIC: u16 = 0xF30A;
pub const EXT4_EXTENT_HEADER_SIZE: usize = 12;
pub const EXT4_EXTENT_ENTRY_SIZE: usize = 12;

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

#[derive(Clone, Copy)]
pub struct Ext4Inode {
    pub inode_num: u64,
    pub mode: u16,
    pub size: u64,
    pub flags: u32,
    pub mtime_sec: i64,
    pub blocks: [u32; 15],
}

#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct Ext4Extent {
    pub start: u64,
    pub len: u16,
    pub _pad: [u8; 6], // Align to 16 bytes for Pod
}

pub mod raw {
    use bytemuck::{Pod, Zeroable};

    // Source: Linux kernel: fs/ext4/ext4.h
    // struct ext4_inode {
    //     __le16	i_mode;		/* File mode */
    //     __le16	i_uid;		/* Low 16 bits of Owner Uid */
    //     __le32	i_size_lo;	/* Size in bytes */
    //     __le32	i_atime;	/* Access time */
    //     __le32	i_ctime;	/* Inode Change time */
    //     __le32	i_mtime;	/* Modification time */
    //     __le32	i_dtime;	/* Deletion Time */
    //     __le16	i_gid;		/* Low 16 bits of Group Id */
    //     __le16	i_links_count;	/* Links count */
    //     __le32	i_blocks_lo;	/* Blocks count */
    //     __le32	i_flags;	/* File flags */
    //     union {
    //         struct {
    //             __le32  l_i_version;
    //         } linux1;
    //         struct {
    //             __u32  h_i_translator;
    //         } hurd1;
    //         struct {
    //             __u32  m_i_reserved1;
    //         } masix1;
    //     } osd1;				/* OS dependent 1 */
    //     __le32	i_block[EXT4_N_BLOCKS];/* Pointers to blocks */
    //     __le32	i_generation;	/* File version (for NFS) */
    //     __le32	i_file_acl_lo;	/* File ACL */
    //     __le32	i_size_high;
    //     __le32	i_obso_faddr;	/* Obsoleted fragment address */
    //     union {
    //         struct {
    //             __le16	l_i_blocks_high; /* were l_i_reserved1 */
    //             __le16	l_i_file_acl_high;
    //             __le16	l_i_uid_high;	/* these 2 fields */
    //             __le16	l_i_gid_high;	/* were reserved2[0] */
    //             __le16	l_i_checksum_lo;/* crc32c(uuid+inum+inode) LE */
    //             __le16	l_i_reserved;
    //         } linux2;
    //         struct {
    //             __le16	h_i_reserved1;	/* Obsoleted fragment number/size which are removed in ext4 */
    //             __u16	h_i_mode_high;
    //             __u16	h_i_uid_high;
    //             __u16	h_i_gid_high;
    //             __u32	h_i_author;
    //         } hurd2;
    //         struct {
    //             __le16	h_i_reserved1;	/* Obsoleted fragment number/size which are removed in ext4 */
    //             __le16	m_i_file_acl_high;
    //             __u32	m_i_reserved2[2];
    //         } masix2;
    //     } osd2;				/* OS dependent 2 */
    //     __le16	i_extra_isize;
    //     __le16	i_checksum_hi;	/* crc32c(uuid+inum+inode) BE */
    //     __le32  i_ctime_extra;  /* extra Change time      (nsec << 2 | epoch) */
    //     __le32  i_mtime_extra;  /* extra Modification time(nsec << 2 | epoch) */
    //     __le32  i_atime_extra;  /* extra Access time      (nsec << 2 | epoch) */
    //     __le32  i_crtime;       /* File Creation time */
    //     __le32  i_crtime_extra; /* extra FileCreationtime (nsec << 2 | epoch) */
    //     __le32  i_version_hi;	/* high 32 bits for 64-bit version */
    //     __le32	i_projid;	/* Project ID */
    // };

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct Ext4Inode {
        pub mode: u16,              // 0x00
        pub uid: u16,               // 0x02
        pub size_lo: u32,           // 0x04
        pub atime: u32,             // 0x08
        pub ctime: u32,             // 0x0C
        pub mtime: u32,             // 0x10
        pub dtime: u32,             // 0x14
        pub gid: u16,               // 0x18
        pub links_count: u16,       // 0x1A
        pub blocks_lo: u32,         // 0x1C
        pub flags: u32,             // 0x20
        pub osd1: u32,              // 0x24
        pub block: [[u8; 12]; 5],   // 0x28 - 60 bytes as 5x12 (bytemuck supports [T; 12])
        pub generation: u32,        // 0x64
        pub file_acl_lo: u32,       // 0x68
        pub size_high: u32,         // 0x6C
        pub obso_faddr: u32,        // 0x70
        pub osd2: [u8; 12],         // 0x74
        pub extra_isize: u16,       // 0x80
        pub checksum_hi: u16,       // 0x82
        pub ctime_extra: u32,       // 0x84
        pub mtime_extra: u32,       // 0x88
        pub atime_extra: u32,       // 0x8C
        pub crtime: u32,            // 0x90
        pub crtime_extra: u32,      // 0x94
        pub version_hi: u32,        // 0x98
        pub projid: u32,            // 0x9C
    }

    // Source: Linux kernel: fs/ext4/ext4.h
    // struct ext4_dir_entry_2 {
    //     __le32	inode;			/* Inode number */
    //     __le16	rec_len;		/* Directory entry length */
    //     __u8	name_len;		/* Name length */
    //     __u8	file_type;		/* See file type macros EXT4_FT_* below */
    //     char	name[EXT4_NAME_LEN];	/* File name */
    // };

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct Ext4DirEntry2 {
        pub inode: u32,        // 0x00
        pub rec_len: u16,      // 0x04
        pub name_len: u8,      // 0x06
        pub file_type: u8,     // 0x07
        // name follows immediately after
    }

    // Source: Linux kernel: fs/ext4/ext4_extents.h
    // struct ext4_extent_header {
    //     __le16	eh_magic;	/* probably will support different formats */
    //     __le16	eh_entries;	/* number of valid entries */
    //     __le16	eh_max;		/* capacity of store in entries */
    //     __le16	eh_depth;	/* has tree real underlying blocks? */
    //     __le32	eh_generation;	/* generation of the tree */
    // };

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct Ext4ExtentHeader {
        pub eh_magic: u16,          // 0x00 - must be 0xF30A
        pub eh_entries: u16,        // 0x02 - number of valid entries
        pub eh_max: u16,            // 0x04 - max entries that could follow
        pub eh_depth: u16,          // 0x06 - tree depth (0 = leaf)
        pub eh_generation: u32,     // 0x08
    }

    // Source: Linux kernel: fs/ext4/ext4_extents.h
    // struct ext4_extent {
    //     __le32	ee_block;	/* first logical block extent covers */
    //     __le16	ee_len;		/* number of blocks covered by extent */
    //     __le16	ee_start_hi;	/* high 16 bits of physical block */
    //     __le32	ee_start_lo;	/* low 32 bits of physical block */
    // };

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct Ext4Extent {
        pub ee_block: u32,          // 0x00 - first logical block extent covers
        pub ee_len: u16,            // 0x04 - number of blocks covered
        pub ee_start_hi: u16,       // 0x06 - high 16 bits of physical block
        pub ee_start_lo: u32,       // 0x08 - low 32 bits of physical block
    }

    // Source: Linux kernel: fs/ext4/ext4_extents.h
    // struct ext4_extent_idx {
    //     __le32	ei_block;	/* index covers logical blocks from 'block' */
    //     __le32	ei_leaf_lo;	/* pointer to the physical block of the next *
    //                  * level. leaf or next index could be there */
    //     __le16	ei_leaf_hi;	/* high 16 bits of physical block */
    //     __u16	ei_unused;
    // };

    #[repr(C)]
    #[derive(Copy, Clone, Pod, Zeroable)]
    pub struct Ext4ExtentIdx {
        pub ei_block: u32,          // 0x00 - index covers logical blocks from 'block'
        pub ei_leaf_lo: u32,        // 0x04 - low 32 bits of physical block pointer
        pub ei_leaf_hi: u16,        // 0x08 - high 16 bits of physical block pointer
        pub ei_unused: u16,         // 0x0A
    }
}
