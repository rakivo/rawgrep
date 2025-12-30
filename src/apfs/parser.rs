//! APFS filesystem implementation of RawFs trait

use crate::tracy;
use crate::parser::{BufKind, FileId, FileNode, FileType, Parser, RawFs, check_first_block_binary};

use super::{
    raw, ApfsExtent, ApfsInode, ApfsSuperblock, NxSuperblock,
    NX_MAGIC, APFS_MAGIC, APFS_ROOT_DIR_INO_NUM,
    APFS_TYPE_INODE, APFS_TYPE_DIR_REC, APFS_TYPE_FILE_EXTENT,
    OBJ_ID_MASK, OBJ_TYPE_SHIFT,
    BTREE_NODE_LEAF, BTREE_NODE_FIXED_KV_SIZE,
    DT_REG, DT_DIR,
    S_IFMT, S_IFDIR,
};
use super::raw::{
    NX_MAGIC_OFF, NX_BLOCK_SIZE_OFF, NX_BLOCK_COUNT_OFF, NX_OMAP_OID_OFF, NX_FS_OID_OFF,
    APSB_MAGIC_OFF, APSB_OMAP_OID_OFF, APSB_ROOT_TREE_OID_OFF,
    JINODE_PARENT_ID_OFF, JINODE_MOD_TIME_OFF, JINODE_NCHILDREN_OFF,
    JINODE_MODE_OFF, JINODE_UNCOMPRESSED_SIZE_OFF, JINODE_MIN_SIZE,
    JDREC_FILE_ID_OFF, JDREC_FLAGS_OFF, JDREC_MIN_SIZE,
};

use std::{io, mem};
use std::ops::ControlFlow;

use memmap2::Mmap;

/// APFS filesystem context
pub struct ApfsFs<'a> {
    pub mmap: &'a Mmap,
    pub nx_sb: NxSuperblock,
    pub vol_sb: ApfsSuperblock,
    pub device_id: u64,
    pub max_block: u64,
    /// Cached container omap B-tree root block
    container_omap_root: u64,
    /// Cached volume omap B-tree root block
    volume_omap_root: u64,
    /// Cached catalog (fstree) B-tree root block
    catalog_root: u64,
}

impl FileNode for ApfsInode {
    #[inline(always)]
    fn file_id(&self) -> FileId {
        self.ino
    }

    #[inline(always)]
    fn size(&self) -> u64 {
        self.size
    }

    #[inline(always)]
    fn mtime(&self) -> i64 {
        // APFS stores time in nanoseconds since Unix epoch
        self.mtime_ns / 1_000_000_000
    }

    #[inline(always)]
    fn is_dir(&self) -> bool {
        (self.mode & S_IFMT) == S_IFDIR
    }
}

impl<'a> RawFs for ApfsFs<'a> {
    type Node = ApfsInode;
    type Context<'b> = &'b Self where Self: 'b;

    #[inline(always)]
    fn device_id(&self) -> u64 {
        self.device_id
    }

    #[inline(always)]
    fn block_size(&self) -> u32 {
        self.vol_sb.block_size
    }

    #[inline(always)]
    fn root_id(&self) -> FileId {
        APFS_ROOT_DIR_INO_NUM
    }

    fn parse_node(&self, file_id: FileId) -> io::Result<Self::Node> {
        let _span = tracy::span!("ApfsFs::parse_node");

        // Look up inode in catalog B-tree
        self.lookup_inode(file_id)
    }

    #[inline(always)]
    fn get_block(&self, block_num: u64) -> &[u8] {
        let block_size = self.vol_sb.block_size as usize;
        let offset = (block_num as usize).wrapping_mul(block_size);
        debug_assert!(
            self.mmap.get(offset..offset + block_size).is_some(),
            "Block {} out of bounds", block_num
        );
        unsafe {
            let ptr = self.mmap.as_ptr().add(offset);
            core::slice::from_raw_parts(ptr, block_size)
        }
    }

    fn read_file_content(
        &self,
        parser: &mut Parser,
        node: &Self::Node,
        max_size: usize,
        kind: BufKind,
        check_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("ApfsFs::read_file_content");

        let buf = parser.get_buf_mut(kind);
        buf.clear();

        let file_size = node.size as usize;
        let size_to_read = file_size.min(max_size);

        if size_to_read == 0 {
            return Ok(true);
        }

        buf.reserve(size_to_read);

        // Get file extents from catalog
        let extents = self.get_file_extents(parser, node.ino)?;

        if extents.is_empty() {
            // File might be empty or inline - return empty buffer
            return Ok(true);
        }

        // Check first block for binary content
        if check_binary {
            if let Some(first_extent) = extents.first() {
                let first_block = self.get_block(first_extent.physical_block);
                if check_first_block_binary(first_block, file_size) {
                    return Ok(false);
                }
            }
        }

        // Copy extent data to buffer
        self.copy_extents_to_buf(parser, &extents, size_to_read, kind);

        parser.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    fn prefetch_file(&self, parser: &mut Parser, node: &Self::Node, size_to_read: usize) {
        let _span = tracy::span!("ApfsFs::prefetch_file");

        if let Ok(extents) = self.get_file_extents(parser, node.ino) {
            self.prefetch_extents(&extents, size_to_read);
        }
    }

    fn with_directory_entries<R>(
        &self,
        buf: &[u8],
        mut callback: impl FnMut(FileId, usize, usize, FileType) -> ControlFlow<R>
    ) -> Option<R> {
        let _span = tracy::span!("ApfsFs::with_directory_entries");

        // Buffer contains serialized directory entries from read_file_content
        // Format: [file_id: u64][file_type: u8][name_len: u16][name: bytes]...
        let mut offset = 0;

        while offset + 11 <= buf.len() { // minimum: 8 + 1 + 2 = 11 bytes
            let file_id = u64::from_le_bytes([
                buf[offset], buf[offset+1], buf[offset+2], buf[offset+3],
                buf[offset+4], buf[offset+5], buf[offset+6], buf[offset+7],
            ]);
            let file_type_raw = buf[offset + 8];
            let name_len = u16::from_le_bytes([buf[offset+9], buf[offset+10]]) as usize;

            offset += 11;

            if offset + name_len > buf.len() {
                break;
            }

            let name_start = offset;
            offset += name_len;

            if file_id == 0 || name_len == 0 {
                continue;
            }

            let file_type = match file_type_raw {
                DT_REG => FileType::File,
                DT_DIR => FileType::Dir,
                _ => FileType::Other,
            };

            match callback(file_id, name_start, name_len, file_type) {
                ControlFlow::Break(b) => return Some(b),
                ControlFlow::Continue(_) => {}
            }
        }

        None
    }

    #[inline]
    fn prefetch_region(&self, offset: usize, length: usize) {
        if offset + length > self.mmap.len() {
            return;
        }

        let page_size = 4096;
        let aligned_offset = offset & !(page_size - 1);
        let aligned_length = ((offset + length + page_size - 1) & !(page_size - 1)) - aligned_offset;

        let ptr = unsafe { self.mmap.as_ptr().add(aligned_offset) as *mut _ };
        _ = memadvise::advise(ptr, aligned_length, memadvise::Advice::WillNeed);
    }
}

// APFS-specific helper methods
impl<'a> ApfsFs<'a> {
    /// Parse container superblock from mmap data using manual offsets
    pub fn parse_container_superblock(mmap: &Mmap) -> io::Result<NxSuperblock> {
        let _span = tracy::span!("ApfsFs::parse_container_superblock");

        // Minimum size needed: NX_FS_OID_OFF + 100 * 8 bytes for fs_oid array
        let min_size = NX_FS_OID_OFF + 100 * 8;
        if mmap.len() < min_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "File too small for APFS container superblock"
            ));
        }

        let data = &mmap[..];

        let magic = u32::from_le_bytes([
            data[NX_MAGIC_OFF], data[NX_MAGIC_OFF + 1],
            data[NX_MAGIC_OFF + 2], data[NX_MAGIC_OFF + 3],
        ]);

        if magic != NX_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid APFS container magic: 0x{:08x} (expected 0x{:08x})", magic, NX_MAGIC)
            ));
        }

        let block_size = u32::from_le_bytes([
            data[NX_BLOCK_SIZE_OFF], data[NX_BLOCK_SIZE_OFF + 1],
            data[NX_BLOCK_SIZE_OFF + 2], data[NX_BLOCK_SIZE_OFF + 3],
        ]);

        let block_count = u64::from_le_bytes([
            data[NX_BLOCK_COUNT_OFF], data[NX_BLOCK_COUNT_OFF + 1],
            data[NX_BLOCK_COUNT_OFF + 2], data[NX_BLOCK_COUNT_OFF + 3],
            data[NX_BLOCK_COUNT_OFF + 4], data[NX_BLOCK_COUNT_OFF + 5],
            data[NX_BLOCK_COUNT_OFF + 6], data[NX_BLOCK_COUNT_OFF + 7],
        ]);

        let omap_oid = u64::from_le_bytes([
            data[NX_OMAP_OID_OFF], data[NX_OMAP_OID_OFF + 1],
            data[NX_OMAP_OID_OFF + 2], data[NX_OMAP_OID_OFF + 3],
            data[NX_OMAP_OID_OFF + 4], data[NX_OMAP_OID_OFF + 5],
            data[NX_OMAP_OID_OFF + 6], data[NX_OMAP_OID_OFF + 7],
        ]);

        let mut fs_oid = [0u64; 100];
        let mut fs_count = 0u32;
        for i in 0..100 {
            let off = NX_FS_OID_OFF + i * 8;
            let oid = u64::from_le_bytes([
                data[off], data[off + 1], data[off + 2], data[off + 3],
                data[off + 4], data[off + 5], data[off + 6], data[off + 7],
            ]);
            if oid != 0 {
                fs_oid[i] = oid;
                fs_count += 1;
            }
        }

        Ok(NxSuperblock {
            magic,
            block_size,
            block_count,
            omap_oid,
            fs_oid,
            fs_count,
        })
    }

    /// Create new APFS filesystem context
    pub fn new(mmap: &'a Mmap, device_id: u64) -> io::Result<Self> {
        let _span = tracy::span!("ApfsFs::new");

        let nx_sb = Self::parse_container_superblock(mmap)?;
        let block_size = nx_sb.block_size as usize;

        // Get container object map to resolve virtual OIDs
        let container_omap_root = Self::get_omap_btree_root(mmap, nx_sb.omap_oid, block_size)?;

        // Find first volume
        let vol_oid = nx_sb.fs_oid.iter()
            .find(|&&oid| oid != 0)
            .copied()
            .ok_or_else(|| io::Error::new(
                io::ErrorKind::NotFound,
                "No volumes found in APFS container"
            ))?;

        // Resolve volume OID to physical block
        let vol_paddr = Self::resolve_oid_static(mmap, container_omap_root, vol_oid, block_size)?;

        // Parse volume superblock
        let vol_sb = Self::parse_volume_superblock(mmap, vol_paddr, block_size)?;

        // Get volume object map
        let volume_omap_root = Self::get_omap_btree_root(mmap, vol_sb.omap_oid, block_size)?;

        // Resolve catalog tree OID
        let catalog_root = Self::resolve_oid_static(mmap, volume_omap_root, vol_sb.root_tree_oid, block_size)?;

        let max_block = nx_sb.block_count;

        Ok(ApfsFs {
            mmap,
            nx_sb,
            vol_sb,
            device_id,
            max_block,
            container_omap_root,
            volume_omap_root,
            catalog_root,
        })
    }

    /// Parse volume superblock using manual offsets
    fn parse_volume_superblock(mmap: &Mmap, block: u64, block_size: usize) -> io::Result<ApfsSuperblock> {
        let _span = tracy::span!("ApfsFs::parse_volume_superblock");

        let offset = block as usize * block_size;
        // Need at least APSB_ROOT_TREE_OID_OFF + 8 bytes
        let min_end = offset + APSB_ROOT_TREE_OID_OFF + 8;

        if min_end > mmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Volume superblock out of bounds"
            ));
        }

        let data = &mmap[offset..];

        let magic = u32::from_le_bytes([
            data[APSB_MAGIC_OFF], data[APSB_MAGIC_OFF + 1],
            data[APSB_MAGIC_OFF + 2], data[APSB_MAGIC_OFF + 3],
        ]);

        if magic != APFS_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid APFS volume magic: 0x{:08x} (expected 0x{:08x})", magic, APFS_MAGIC)
            ));
        }

        let fs_index = u32::from_le_bytes([
            data[0x24], data[0x25], data[0x26], data[0x27],
        ]);

        let omap_oid = u64::from_le_bytes([
            data[APSB_OMAP_OID_OFF], data[APSB_OMAP_OID_OFF + 1],
            data[APSB_OMAP_OID_OFF + 2], data[APSB_OMAP_OID_OFF + 3],
            data[APSB_OMAP_OID_OFF + 4], data[APSB_OMAP_OID_OFF + 5],
            data[APSB_OMAP_OID_OFF + 6], data[APSB_OMAP_OID_OFF + 7],
        ]);

        let root_tree_oid = u64::from_le_bytes([
            data[APSB_ROOT_TREE_OID_OFF], data[APSB_ROOT_TREE_OID_OFF + 1],
            data[APSB_ROOT_TREE_OID_OFF + 2], data[APSB_ROOT_TREE_OID_OFF + 3],
            data[APSB_ROOT_TREE_OID_OFF + 4], data[APSB_ROOT_TREE_OID_OFF + 5],
            data[APSB_ROOT_TREE_OID_OFF + 6], data[APSB_ROOT_TREE_OID_OFF + 7],
        ]);

        Ok(ApfsSuperblock {
            magic,
            fs_index,
            block_size: block_size as u32,
            root_tree_oid,
            omap_oid,
            root_dir_id: APFS_ROOT_DIR_INO_NUM,
        })
    }

    /// Get object map B-tree root block
    fn get_omap_btree_root(mmap: &Mmap, omap_oid: u64, block_size: usize) -> io::Result<u64> {
        let _span = tracy::span!("ApfsFs::get_omap_btree_root");

        let offset = omap_oid as usize * block_size;
        let end = offset + mem::size_of::<raw::OmapPhys>();

        if end > mmap.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Object map out of bounds"
            ));
        }

        let omap = bytemuck::try_from_bytes::<raw::OmapPhys>(
            &mmap[offset..offset + mem::size_of::<raw::OmapPhys>()]
        ).map_err(|_| io::Error::new(
            io::ErrorKind::InvalidData,
            "Failed to parse object map"
        ))?;

        Ok(u64::from_le(omap.tree_oid))
    }

    /// Resolve virtual OID to physical address using object map B-tree
    fn resolve_oid_static(mmap: &Mmap, omap_root: u64, oid: u64, block_size: usize) -> io::Result<u64> {
        let _span = tracy::span!("ApfsFs::resolve_oid_static");

        Self::search_omap_btree(mmap, omap_root, oid, block_size)
    }

    /// Resolve virtual OID to physical address
    fn resolve_oid(&self, oid: u64) -> io::Result<u64> {
        // Try volume omap first, then container omap
        let block_size = self.vol_sb.block_size as usize;

        Self::search_omap_btree(self.mmap, self.volume_omap_root, oid, block_size)
            .or_else(|_| Self::search_omap_btree(self.mmap, self.container_omap_root, oid, block_size))
    }

    /// Search object map B-tree for OID
    fn search_omap_btree(mmap: &Mmap, root_block: u64, target_oid: u64, block_size: usize) -> io::Result<u64> {
        let _span = tracy::span!("ApfsFs::search_omap_btree");

        let mut current_block = root_block;

        loop {
            let offset = current_block as usize * block_size;
            if offset + mem::size_of::<raw::BtreeNodePhys>() > mmap.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "B-tree node out of bounds"));
            }

            let node = bytemuck::try_from_bytes::<raw::BtreeNodePhys>(
                &mmap[offset..offset + mem::size_of::<raw::BtreeNodePhys>()]
            ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse B-tree node"))?;

            let flags = u16::from_le(node.flags);
            let nkeys = u32::from_le(node.nkeys);
            let is_leaf = (flags & BTREE_NODE_LEAF) != 0;
            let is_fixed = (flags & BTREE_NODE_FIXED_KV_SIZE) != 0;

            let toc_start = offset + mem::size_of::<raw::BtreeNodePhys>();

            if is_leaf {
                // Search leaf node for exact match
                for i in 0..nkeys {
                    let (key_off, val_off) = if is_fixed {
                        let loc_off = toc_start + i as usize * mem::size_of::<raw::KvLoc>();
                        let loc = bytemuck::try_from_bytes::<raw::KvLoc>(
                            &mmap[loc_off..loc_off + mem::size_of::<raw::KvLoc>()]
                        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse KvLoc"))?;
                        (u16::from_le(loc.key_off), u16::from_le(loc.val_off))
                    } else {
                        let kv_off = toc_start + i as usize * mem::size_of::<raw::KvOff>();
                        let kv = bytemuck::try_from_bytes::<raw::KvOff>(
                            &mmap[kv_off..kv_off + mem::size_of::<raw::KvOff>()]
                        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse KvOff"))?;
                        (u16::from_le(kv.key_off), u16::from_le(kv.val_off))
                    };

                    // Keys are at end of block, growing backwards
                    let keys_start = offset + mem::size_of::<raw::BtreeNodePhys>() +
                        u16::from_le(node.table_space_off) as usize +
                        u16::from_le(node.table_space_len) as usize;

                    let key_offset = keys_start + key_off as usize;
                    if key_offset + mem::size_of::<raw::OmapKey>() > mmap.len() {
                        continue;
                    }

                    let key = bytemuck::try_from_bytes::<raw::OmapKey>(
                        &mmap[key_offset..key_offset + mem::size_of::<raw::OmapKey>()]
                    ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse OmapKey"))?;

                    let key_oid = u64::from_le(key.oid);

                    if key_oid == target_oid {
                        // Values are at end of block
                        let val_offset = offset + block_size - val_off as usize - mem::size_of::<raw::OmapVal>();
                        if val_offset + mem::size_of::<raw::OmapVal>() > mmap.len() {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "OmapVal out of bounds"));
                        }

                        let val = bytemuck::try_from_bytes::<raw::OmapVal>(
                            &mmap[val_offset..val_offset + mem::size_of::<raw::OmapVal>()]
                        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse OmapVal"))?;

                        return Ok(u64::from_le(val.paddr));
                    }
                }

                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("OID 0x{:x} not found in object map", target_oid)
                ));
            } else {
                // Internal node - find child to descend into
                let mut next_block = None;

                for i in 0..nkeys {
                    let (key_off, val_off) = if is_fixed {
                        let loc_off = toc_start + i as usize * mem::size_of::<raw::KvLoc>();
                        let loc = bytemuck::try_from_bytes::<raw::KvLoc>(
                            &mmap[loc_off..loc_off + mem::size_of::<raw::KvLoc>()]
                        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse KvLoc"))?;
                        (u16::from_le(loc.key_off), u16::from_le(loc.val_off))
                    } else {
                        let kv_off = toc_start + i as usize * mem::size_of::<raw::KvOff>();
                        let kv = bytemuck::try_from_bytes::<raw::KvOff>(
                            &mmap[kv_off..kv_off + mem::size_of::<raw::KvOff>()]
                        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse KvOff"))?;
                        (u16::from_le(kv.key_off), u16::from_le(kv.val_off))
                    };

                    let keys_start = offset + mem::size_of::<raw::BtreeNodePhys>() +
                        u16::from_le(node.table_space_off) as usize +
                        u16::from_le(node.table_space_len) as usize;

                    let key_offset = keys_start + key_off as usize;
                    if key_offset + mem::size_of::<raw::OmapKey>() > mmap.len() {
                        continue;
                    }

                    let key = bytemuck::try_from_bytes::<raw::OmapKey>(
                        &mmap[key_offset..key_offset + mem::size_of::<raw::OmapKey>()]
                    ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse OmapKey"))?;

                    let key_oid = u64::from_le(key.oid);

                    if key_oid > target_oid {
                        break;
                    }

                    // Value is child block pointer
                    let val_offset = offset + block_size - val_off as usize - 8;
                    if val_offset + 8 > mmap.len() {
                        continue;
                    }

                    let child_ptr = u64::from_le_bytes([
                        mmap[val_offset], mmap[val_offset+1], mmap[val_offset+2], mmap[val_offset+3],
                        mmap[val_offset+4], mmap[val_offset+5], mmap[val_offset+6], mmap[val_offset+7],
                    ]);

                    next_block = Some(child_ptr);
                }

                match next_block {
                    Some(block) => current_block = block,
                    None => return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("OID 0x{:x} not found", target_oid)
                    )),
                }
            }
        }
    }

    /// Look up inode in catalog B-tree
    fn lookup_inode(&self, ino: u64) -> io::Result<ApfsInode> {
        let _span = tracy::span!("ApfsFs::lookup_inode");

        // Search catalog for inode record
        let target_key = (ino & OBJ_ID_MASK) | ((APFS_TYPE_INODE as u64) << OBJ_TYPE_SHIFT);

        self.search_catalog_for_inode(self.catalog_root, target_key, ino)
    }

    /// Search catalog B-tree for inode
    fn search_catalog_for_inode(&self, root_block: u64, target_key: u64, ino: u64) -> io::Result<ApfsInode> {
        let _span = tracy::span!("ApfsFs::search_catalog_for_inode");

        let block_size = self.vol_sb.block_size as usize;
        let mut current_block = root_block;

        loop {
            // Resolve virtual OID to physical if needed
            let phys_block = self.resolve_oid(current_block).unwrap_or(current_block);

            let offset = phys_block as usize * block_size;
            if offset + mem::size_of::<raw::BtreeNodePhys>() > self.mmap.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Catalog node out of bounds"));
            }

            let node = bytemuck::try_from_bytes::<raw::BtreeNodePhys>(
                &self.mmap[offset..offset + mem::size_of::<raw::BtreeNodePhys>()]
            ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse catalog node"))?;

            let flags = u16::from_le(node.flags);
            let nkeys = u32::from_le(node.nkeys);
            let is_leaf = (flags & BTREE_NODE_LEAF) != 0;

            let toc_start = offset + mem::size_of::<raw::BtreeNodePhys>();
            let keys_start = toc_start +
                u16::from_le(node.table_space_off) as usize +
                u16::from_le(node.table_space_len) as usize;

            if is_leaf {
                // Search for inode record
                for i in 0..nkeys {
                    let kv_off = toc_start + i as usize * mem::size_of::<raw::KvOff>();
                    if kv_off + mem::size_of::<raw::KvOff>() > self.mmap.len() {
                        continue;
                    }

                    let kv = bytemuck::try_from_bytes::<raw::KvOff>(
                        &self.mmap[kv_off..kv_off + mem::size_of::<raw::KvOff>()]
                    ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse KvOff"))?;

                    let key_off = u16::from_le(kv.key_off);
                    let val_off = u16::from_le(kv.val_off);

                    let key_offset = keys_start + key_off as usize;
                    if key_offset + 8 > self.mmap.len() {
                        continue;
                    }

                    let key_data = u64::from_le_bytes([
                        self.mmap[key_offset], self.mmap[key_offset+1],
                        self.mmap[key_offset+2], self.mmap[key_offset+3],
                        self.mmap[key_offset+4], self.mmap[key_offset+5],
                        self.mmap[key_offset+6], self.mmap[key_offset+7],
                    ]);

                    let key_oid = key_data & OBJ_ID_MASK;
                    let key_type = (key_data >> OBJ_TYPE_SHIFT) as u8;

                    if key_oid == ino && key_type == APFS_TYPE_INODE {
                        // Found inode record - parse value using manual offsets
                        let val_offset = offset + block_size - val_off as usize - JINODE_MIN_SIZE;
                        if val_offset + JINODE_MIN_SIZE > self.mmap.len() {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "Inode value out of bounds"));
                        }

                        let val_data = &self.mmap[val_offset..];

                        let parent_id = u64::from_le_bytes([
                            val_data[JINODE_PARENT_ID_OFF], val_data[JINODE_PARENT_ID_OFF + 1],
                            val_data[JINODE_PARENT_ID_OFF + 2], val_data[JINODE_PARENT_ID_OFF + 3],
                            val_data[JINODE_PARENT_ID_OFF + 4], val_data[JINODE_PARENT_ID_OFF + 5],
                            val_data[JINODE_PARENT_ID_OFF + 6], val_data[JINODE_PARENT_ID_OFF + 7],
                        ]);

                        let mod_time = u64::from_le_bytes([
                            val_data[JINODE_MOD_TIME_OFF], val_data[JINODE_MOD_TIME_OFF + 1],
                            val_data[JINODE_MOD_TIME_OFF + 2], val_data[JINODE_MOD_TIME_OFF + 3],
                            val_data[JINODE_MOD_TIME_OFF + 4], val_data[JINODE_MOD_TIME_OFF + 5],
                            val_data[JINODE_MOD_TIME_OFF + 6], val_data[JINODE_MOD_TIME_OFF + 7],
                        ]);

                        let nchildren = u32::from_le_bytes([
                            val_data[JINODE_NCHILDREN_OFF], val_data[JINODE_NCHILDREN_OFF + 1],
                            val_data[JINODE_NCHILDREN_OFF + 2], val_data[JINODE_NCHILDREN_OFF + 3],
                        ]);

                        let mode = u16::from_le_bytes([
                            val_data[JINODE_MODE_OFF], val_data[JINODE_MODE_OFF + 1],
                        ]);

                        let uncompressed_size = u64::from_le_bytes([
                            val_data[JINODE_UNCOMPRESSED_SIZE_OFF], val_data[JINODE_UNCOMPRESSED_SIZE_OFF + 1],
                            val_data[JINODE_UNCOMPRESSED_SIZE_OFF + 2], val_data[JINODE_UNCOMPRESSED_SIZE_OFF + 3],
                            val_data[JINODE_UNCOMPRESSED_SIZE_OFF + 4], val_data[JINODE_UNCOMPRESSED_SIZE_OFF + 5],
                            val_data[JINODE_UNCOMPRESSED_SIZE_OFF + 6], val_data[JINODE_UNCOMPRESSED_SIZE_OFF + 7],
                        ]);

                        return Ok(ApfsInode {
                            ino,
                            parent_id,
                            mode,
                            size: uncompressed_size,
                            mtime_ns: mod_time as i64,
                            nchildren,
                        });
                    }
                }

                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Inode {} not found in catalog", ino)
                ));
            } else {
                // Internal node - descend
                let mut next_block = None;

                for i in 0..nkeys {
                    let kv_off = toc_start + i as usize * mem::size_of::<raw::KvOff>();
                    if kv_off + mem::size_of::<raw::KvOff>() > self.mmap.len() {
                        continue;
                    }

                    let kv = bytemuck::try_from_bytes::<raw::KvOff>(
                        &self.mmap[kv_off..kv_off + mem::size_of::<raw::KvOff>()]
                    ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse KvOff"))?;

                    let key_off = u16::from_le(kv.key_off);
                    let val_off = u16::from_le(kv.val_off);

                    let key_offset = keys_start + key_off as usize;
                    if key_offset + 8 > self.mmap.len() {
                        continue;
                    }

                    let key_data = u64::from_le_bytes([
                        self.mmap[key_offset], self.mmap[key_offset+1],
                        self.mmap[key_offset+2], self.mmap[key_offset+3],
                        self.mmap[key_offset+4], self.mmap[key_offset+5],
                        self.mmap[key_offset+6], self.mmap[key_offset+7],
                    ]);

                    if key_data > target_key {
                        break;
                    }

                    // Value is child OID
                    let val_offset = offset + block_size - val_off as usize - 8;
                    if val_offset + 8 > self.mmap.len() {
                        continue;
                    }

                    let child_oid = u64::from_le_bytes([
                        self.mmap[val_offset], self.mmap[val_offset+1],
                        self.mmap[val_offset+2], self.mmap[val_offset+3],
                        self.mmap[val_offset+4], self.mmap[val_offset+5],
                        self.mmap[val_offset+6], self.mmap[val_offset+7],
                    ]);

                    next_block = Some(child_oid);
                }

                match next_block {
                    Some(block) => current_block = block,
                    None => return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Inode {} not found", ino)
                    )),
                }
            }
        }
    }

    /// Get file extents from catalog
    fn get_file_extents(&self, _parser: &mut Parser, ino: u64) -> io::Result<Vec<ApfsExtent>> {
        let _span = tracy::span!("ApfsFs::get_file_extents");

        let mut extents = Vec::new();

        // Search catalog for file extent records
        self.search_catalog_for_extents(self.catalog_root, ino, &mut extents)?;

        // Sort by logical offset
        extents.sort_by_key(|e| e.logical_offset);

        Ok(extents)
    }

    /// Search catalog for file extent records
    fn search_catalog_for_extents(&self, root_block: u64, ino: u64, extents: &mut Vec<ApfsExtent>) -> io::Result<()> {
        let _span = tracy::span!("ApfsFs::search_catalog_for_extents");

        let block_size = self.vol_sb.block_size as usize;

        // Simple scan of catalog for this file's extents
        // A more efficient implementation would do a proper B-tree range search
        self.scan_btree_for_extents(root_block, ino, extents, block_size)
    }

    fn scan_btree_for_extents(&self, block_oid: u64, target_ino: u64, extents: &mut Vec<ApfsExtent>, block_size: usize) -> io::Result<()> {
        let phys_block = self.resolve_oid(block_oid).unwrap_or(block_oid);
        let offset = phys_block as usize * block_size;

        if offset + mem::size_of::<raw::BtreeNodePhys>() > self.mmap.len() {
            return Ok(());
        }

        let node = bytemuck::try_from_bytes::<raw::BtreeNodePhys>(
            &self.mmap[offset..offset + mem::size_of::<raw::BtreeNodePhys>()]
        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse B-tree node"))?;

        let flags = u16::from_le(node.flags);
        let nkeys = u32::from_le(node.nkeys);
        let is_leaf = (flags & BTREE_NODE_LEAF) != 0;

        let toc_start = offset + mem::size_of::<raw::BtreeNodePhys>();
        let keys_start = toc_start +
            u16::from_le(node.table_space_off) as usize +
            u16::from_le(node.table_space_len) as usize;

        if is_leaf {
            for i in 0..nkeys {
                let kv_off = toc_start + i as usize * mem::size_of::<raw::KvOff>();
                if kv_off + mem::size_of::<raw::KvOff>() > self.mmap.len() {
                    continue;
                }

                let kv = match bytemuck::try_from_bytes::<raw::KvOff>(
                    &self.mmap[kv_off..kv_off + mem::size_of::<raw::KvOff>()]
                ) {
                    Ok(k) => k,
                    Err(_) => continue,
                };

                let key_off = u16::from_le(kv.key_off);
                let val_off = u16::from_le(kv.val_off);

                let key_offset = keys_start + key_off as usize;
                if key_offset + mem::size_of::<raw::JFileExtentKey>() > self.mmap.len() {
                    continue;
                }

                // Check if this is a file extent key
                let key_data = u64::from_le_bytes([
                    self.mmap[key_offset], self.mmap[key_offset+1],
                    self.mmap[key_offset+2], self.mmap[key_offset+3],
                    self.mmap[key_offset+4], self.mmap[key_offset+5],
                    self.mmap[key_offset+6], self.mmap[key_offset+7],
                ]);

                let key_oid = key_data & OBJ_ID_MASK;
                let key_type = (key_data >> OBJ_TYPE_SHIFT) as u8;

                if key_oid == target_ino && key_type == APFS_TYPE_FILE_EXTENT {
                    // Parse extent key for logical offset
                    if key_offset + 16 > self.mmap.len() {
                        continue;
                    }

                    let logical_offset = u64::from_le_bytes([
                        self.mmap[key_offset+8], self.mmap[key_offset+9],
                        self.mmap[key_offset+10], self.mmap[key_offset+11],
                        self.mmap[key_offset+12], self.mmap[key_offset+13],
                        self.mmap[key_offset+14], self.mmap[key_offset+15],
                    ]);

                    // Parse extent value
                    let val_offset = offset + block_size - val_off as usize - mem::size_of::<raw::JFileExtentVal>();
                    if val_offset + mem::size_of::<raw::JFileExtentVal>() > self.mmap.len() {
                        continue;
                    }

                    let val = match bytemuck::try_from_bytes::<raw::JFileExtentVal>(
                        &self.mmap[val_offset..val_offset + mem::size_of::<raw::JFileExtentVal>()]
                    ) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let len_and_flags = u64::from_le(val.len_and_flags);
                    let length = len_and_flags & 0x00ff_ffff_ffff_ffff; // Lower 56 bits
                    let phys_block = u64::from_le(val.phys_block_num);

                    if phys_block != 0 && length > 0 {
                        extents.push(ApfsExtent {
                            logical_offset,
                            physical_block: phys_block,
                            length,
                        });
                    }
                }
            }
        } else {
            // Recurse into child nodes
            for i in 0..nkeys {
                let kv_off = toc_start + i as usize * mem::size_of::<raw::KvOff>();
                if kv_off + mem::size_of::<raw::KvOff>() > self.mmap.len() {
                    continue;
                }

                let kv = match bytemuck::try_from_bytes::<raw::KvOff>(
                    &self.mmap[kv_off..kv_off + mem::size_of::<raw::KvOff>()]
                ) {
                    Ok(k) => k,
                    Err(_) => continue,
                };

                let val_off = u16::from_le(kv.val_off);
                let val_offset = offset + block_size - val_off as usize - 8;

                if val_offset + 8 > self.mmap.len() {
                    continue;
                }

                let child_oid = u64::from_le_bytes([
                    self.mmap[val_offset], self.mmap[val_offset+1],
                    self.mmap[val_offset+2], self.mmap[val_offset+3],
                    self.mmap[val_offset+4], self.mmap[val_offset+5],
                    self.mmap[val_offset+6], self.mmap[val_offset+7],
                ]);

                self.scan_btree_for_extents(child_oid, target_ino, extents, block_size)?;
            }
        }

        Ok(())
    }

    /// Read directory entries into buffer for with_directory_entries
    pub fn read_directory(&self, parser: &mut Parser, dir_ino: u64) -> io::Result<()> {
        let _span = tracy::span!("ApfsFs::read_directory");

        let buf = parser.get_buf_mut(BufKind::Dir);
        buf.clear();

        // Scan catalog for directory records with this parent
        self.scan_catalog_for_dirents(self.catalog_root, dir_ino, buf)
    }

    fn scan_catalog_for_dirents(&self, block_oid: u64, parent_ino: u64, buf: &mut Vec<u8>) -> io::Result<()> {
        let block_size = self.vol_sb.block_size as usize;
        let phys_block = self.resolve_oid(block_oid).unwrap_or(block_oid);
        let offset = phys_block as usize * block_size;

        if offset + mem::size_of::<raw::BtreeNodePhys>() > self.mmap.len() {
            return Ok(());
        }

        let node = bytemuck::try_from_bytes::<raw::BtreeNodePhys>(
            &self.mmap[offset..offset + mem::size_of::<raw::BtreeNodePhys>()]
        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse B-tree node"))?;

        let flags = u16::from_le(node.flags);
        let nkeys = u32::from_le(node.nkeys);
        let is_leaf = (flags & BTREE_NODE_LEAF) != 0;

        let toc_start = offset + mem::size_of::<raw::BtreeNodePhys>();
        let keys_start = toc_start +
            u16::from_le(node.table_space_off) as usize +
            u16::from_le(node.table_space_len) as usize;

        if is_leaf {
            for i in 0..nkeys {
                let kv_off = toc_start + i as usize * mem::size_of::<raw::KvOff>();
                if kv_off + mem::size_of::<raw::KvOff>() > self.mmap.len() {
                    continue;
                }

                let kv = match bytemuck::try_from_bytes::<raw::KvOff>(
                    &self.mmap[kv_off..kv_off + mem::size_of::<raw::KvOff>()]
                ) {
                    Ok(k) => k,
                    Err(_) => continue,
                };

                let key_off = u16::from_le(kv.key_off);
                let _key_len = u16::from_le(kv.key_len);
                let val_off = u16::from_le(kv.val_off);

                let key_offset = keys_start + key_off as usize;
                if key_offset + 12 > self.mmap.len() { // minimum drec key size
                    continue;
                }

                let key_data = u64::from_le_bytes([
                    self.mmap[key_offset], self.mmap[key_offset+1],
                    self.mmap[key_offset+2], self.mmap[key_offset+3],
                    self.mmap[key_offset+4], self.mmap[key_offset+5],
                    self.mmap[key_offset+6], self.mmap[key_offset+7],
                ]);

                let key_oid = key_data & OBJ_ID_MASK;
                let key_type = (key_data >> OBJ_TYPE_SHIFT) as u8;

                if key_oid == parent_ino && key_type == APFS_TYPE_DIR_REC {
                    // Parse directory record
                    let name_len_and_hash = u32::from_le_bytes([
                        self.mmap[key_offset+8], self.mmap[key_offset+9],
                        self.mmap[key_offset+10], self.mmap[key_offset+11],
                    ]);
                    let name_len = (name_len_and_hash & 0x3ff) as usize;

                    if key_offset + 12 + name_len > self.mmap.len() {
                        continue;
                    }

                    let name_bytes = &self.mmap[key_offset + 12..key_offset + 12 + name_len];

                    // Parse value for file_id and type using manual offsets
                    let val_offset = offset + block_size - val_off as usize - JDREC_MIN_SIZE;
                    if val_offset + JDREC_MIN_SIZE > self.mmap.len() {
                        continue;
                    }

                    let val_data = &self.mmap[val_offset..];

                    let file_id = u64::from_le_bytes([
                        val_data[JDREC_FILE_ID_OFF], val_data[JDREC_FILE_ID_OFF + 1],
                        val_data[JDREC_FILE_ID_OFF + 2], val_data[JDREC_FILE_ID_OFF + 3],
                        val_data[JDREC_FILE_ID_OFF + 4], val_data[JDREC_FILE_ID_OFF + 5],
                        val_data[JDREC_FILE_ID_OFF + 6], val_data[JDREC_FILE_ID_OFF + 7],
                    ]);

                    let flags = u16::from_le_bytes([
                        val_data[JDREC_FLAGS_OFF], val_data[JDREC_FLAGS_OFF + 1],
                    ]);
                    let file_type = (flags & 0x000f) as u8; // Lower 4 bits

                    // Serialize entry: [file_id: u64][type: u8][name_len: u16][name]
                    buf.extend_from_slice(&file_id.to_le_bytes());
                    buf.push(file_type);
                    buf.extend_from_slice(&(name_len as u16).to_le_bytes());
                    buf.extend_from_slice(name_bytes);
                }
            }
        } else {
            // Recurse into child nodes
            for i in 0..nkeys {
                let kv_off = toc_start + i as usize * mem::size_of::<raw::KvOff>();
                if kv_off + mem::size_of::<raw::KvOff>() > self.mmap.len() {
                    continue;
                }

                let kv = match bytemuck::try_from_bytes::<raw::KvOff>(
                    &self.mmap[kv_off..kv_off + mem::size_of::<raw::KvOff>()]
                ) {
                    Ok(k) => k,
                    Err(_) => continue,
                };

                let val_off = u16::from_le(kv.val_off);
                let val_offset = offset + block_size - val_off as usize - 8;

                if val_offset + 8 > self.mmap.len() {
                    continue;
                }

                let child_oid = u64::from_le_bytes([
                    self.mmap[val_offset], self.mmap[val_offset+1],
                    self.mmap[val_offset+2], self.mmap[val_offset+3],
                    self.mmap[val_offset+4], self.mmap[val_offset+5],
                    self.mmap[val_offset+6], self.mmap[val_offset+7],
                ]);

                self.scan_catalog_for_dirents(child_oid, parent_ino, buf)?;
            }
        }

        Ok(())
    }

    fn copy_extents_to_buf(
        &self,
        parser: &mut Parser,
        extents: &[ApfsExtent],
        size_to_read: usize,
        kind: BufKind,
    ) {
        let _span = tracy::span!("ApfsFs::copy_extents_to_buf");

        let block_size = self.vol_sb.block_size as usize;
        let mut copied = 0;

        for extent in extents {
            if copied >= size_to_read {
                break;
            }

            let blocks_in_extent = (extent.length as usize + block_size - 1) / block_size;

            for block_idx in 0..blocks_in_extent {
                if copied >= size_to_read {
                    break;
                }

                let phys_block = extent.physical_block + block_idx as u64;
                let block_data = self.get_block(phys_block);

                let remaining = size_to_read - copied;
                let to_copy = block_data.len().min(remaining);

                let buf = parser.get_buf_mut(kind);
                let old_len = buf.len();
                buf.resize(old_len + to_copy, 0);

                unsafe {
                    core::ptr::copy_nonoverlapping(
                        block_data.as_ptr(),
                        buf.as_mut_ptr().add(old_len),
                        to_copy
                    );
                }

                copied += to_copy;
            }
        }
    }

    fn prefetch_extents(&self, extents: &[ApfsExtent], size_to_read: usize) {
        let _span = tracy::span!("ApfsFs::prefetch_extents");

        let block_size = self.vol_sb.block_size as usize;
        let mut remaining = size_to_read;

        for extent in extents {
            if remaining == 0 {
                break;
            }

            let extent_bytes = extent.length as usize;
            let bytes_to_prefetch = extent_bytes.min(remaining);
            let blocks_to_prefetch = (bytes_to_prefetch + block_size - 1) / block_size;

            let offset = extent.physical_block as usize * block_size;
            let length = blocks_to_prefetch * block_size;

            if offset + length <= self.mmap.len() {
                let ptr = unsafe { self.mmap.as_ptr().add(offset) as *mut _ };
                _ = memadvise::advise(ptr, length, memadvise::Advice::WillNeed);
            }

            remaining = remaining.saturating_sub(extent_bytes);
        }
    }
}
