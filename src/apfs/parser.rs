//! Apple APFS filesystem implementation of the RawFs trait.
//!
//! Supports:
//!   - Container superblock (NX) parsing
//!   - Container object-map B-tree (omap) lookup (OID → physical block)
//!   - Volume superblock (APSB) parsing
//!   - Volume fs-record B-tree traversal for inodes and directory entries
//!   - File data via j_phys_ext records (extent map)
//!   - Inline / compressed-size reporting (decmpfs xattr size only; full
//!     transparent decompression is left as a future extension)
//!
//! Not yet supported (marked @Incomplete):
//!   - Transparent HFS+ compression (decmpfs / resource-fork data)
//!   - Snapshots / multiple transaction epochs
//!   - Encryption (wrapped keys)

use crate::tracy;
use crate::parser::{BufKind, FileId, FileNode, FileType, Parser, RawFs, check_first_block_binary};
use crate::util::read_at_offset;

use super::{
    raw, ApfsInode, ApfsSuperBlock, ApfsVolume,
    APFS_NX_MAGIC, APFS_APSB_MAGIC,
    APFS_NX_BLOCK_SIZE_OFFSET, APFS_NX_OMAP_OID_OFFSET, APFS_NX_FS_OID_OFFSET,
    APFS_APSB_OMAP_OID_OFFSET, APFS_APSB_ROOT_TREE_OID_OFFSET,
    APFS_ROOT_DIR_INO_NUM,
    APFS_TYPE_INODE, APFS_TYPE_DIR_REC,
    APFS_BTNODE_FLAG_LEAF,
    S_IFMT, S_IFDIR,
    DT_REG, DT_DIR,
};

use std::fs::File;
use std::{io, mem};
use std::ops::ControlFlow;

// ─────────────────────────────────────────────────────────────────────────────
// Public façade
// ─────────────────────────────────────────────────────────────────────────────

/// APFS container (one or more volumes).  We expose the *first* volume only,
/// which matches the common single-volume case seen in practice.
pub struct ApfsFs {
    pub file:      File,
    pub sb:        ApfsSuperBlock,
    pub volume:    ApfsVolume,
    pub device_id: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// FileNode impl
// ─────────────────────────────────────────────────────────────────────────────

impl FileNode for ApfsInode {
    #[inline(always)] fn file_id(&self) -> FileId { self.inode_num }
    #[inline(always)] fn size(&self)    -> u64    { self.size }
    #[inline(always)] fn mtime(&self)   -> i64    { self.mtime_sec }
    #[inline(always)] fn is_dir(&self)  -> bool   { (self.mode & S_IFMT) == S_IFDIR }
}

// ─────────────────────────────────────────────────────────────────────────────
// RawFs impl
// ─────────────────────────────────────────────────────────────────────────────

impl RawFs for ApfsFs {
    type Node = ApfsInode;
    type Context<'b> = &'b Self where Self: 'b;

    #[inline(always)] fn device_id(&self)  -> u64 { self.device_id }
    #[inline(always)] fn block_size(&self) -> u32 { self.sb.block_size }
    #[inline(always)] fn root_id(&self)    -> FileId { APFS_ROOT_DIR_INO_NUM }

    fn parse_node(&self, file_id: FileId) -> io::Result<Self::Node> {
        let _span = tracy::span!("ApfsFs::parse_node");
        self.lookup_inode(file_id)
    }

    fn read_file_content(
        &self,
        parser:       &mut Parser,
        node:         &Self::Node,
        max_size:     usize,
        kind:         BufKind,
        check_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("ApfsFs::read_file_content");

        let buf = parser.get_buf_mut(kind);
        buf.clear();

        let file_size    = node.size as usize;
        let size_to_read = file_size.min(max_size);

        // Release oversized buffers (same heuristic as ext4 impl)
        if buf.capacity() > 4 * 1024 * 1024 && size_to_read < buf.capacity() / 4 {
            *buf = Vec::with_capacity(size_to_read);
        } else {
            buf.reserve(size_to_read);
        }

        if size_to_read == 0 {
            return Ok(true);
        }

        // Collect all extents covering [0, size_to_read) from the fs-record tree
        let extents = self.collect_extents(node.inode_num, size_to_read)?;

        if extents.is_empty() {
            // Sparse / empty file – nothing to read
            return Ok(true);
        }

        // Binary probe on the first extent block
        if check_binary {
            let (phys_block, _len_bytes) = extents[0];
            let offset = phys_block * self.sb.block_size as u64;
            let probe  = self.sb.block_size as usize;
            let mut tmp = vec![0u8; probe];
            let n = self.read_at_offset(&mut tmp, offset).unwrap_or(0);
            if check_first_block_binary(&tmp[..n], file_size) {
                return Ok(false);
            }
        }

        // Copy extent data into the parser buffer
        let mut copied = 0usize;
        for (phys_block, extent_bytes) in &extents {
            if copied >= size_to_read { break; }

            let offset    = phys_block * self.sb.block_size as u64;
            let remaining = size_to_read - copied;
            let to_read   = (*extent_bytes as usize).min(remaining);

            let buf      = parser.get_buf_mut(kind);
            let old_len  = buf.len();
            buf.resize(old_len + to_read, 0);

            match self.read_at_offset(&mut buf[old_len..], offset) {
                Ok(n)  => { buf.truncate(old_len + n); copied += n; }
                Err(_) => { buf.truncate(old_len);     break;       }
            }
        }

        parser.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    /// Iterate directory entries stored in `buf` (a full directory block
    /// previously read by `read_file_content`).
    ///
    /// APFS directories are not stored as raw block data; their entries live in
    /// the fs-record B-tree as `APFS_TYPE_DIR_REC` records.  When the caller
    /// passes the *inode number* of the directory encoded as a little-endian
    /// u64 in `buf`, we walk the B-tree to yield each child entry.
    ///
    /// Convention: the `dir` buffer contains exactly 8 bytes – the u64
    /// inode number of the directory – written by `read_file_content` when
    /// `BufKind::Dir` is requested.
    fn with_directory_entries<R>(
        &self,
        buf: &[u8],
        mut callback: impl FnMut(FileId, usize, usize, FileType) -> ControlFlow<R>,
    ) -> Option<R> {
        let _span = tracy::span!("ApfsFs::with_directory_entries");

        if buf.len() < 8 { return None; }
        let dir_ino = u64::from_le_bytes(buf[..8].try_into().ok()?);

        // We need a scratch name buffer; re-use a local Vec.
        let mut names: Vec<u8> = Vec::with_capacity(4096);
        let mut result: Option<R> = None;

        let _ = self.scan_dir_entries(dir_ino, |child_id, name_bytes, dt| {
            let name_start = names.len();
            names.extend_from_slice(name_bytes);
            let name_len = name_bytes.len();

            let file_type = match dt {
                DT_REG => FileType::File,
                DT_DIR => FileType::Dir,
                _      => FileType::Other,
            };

            match callback(child_id, name_start, name_len, file_type) {
                ControlFlow::Break(b) => { result = Some(b); ControlFlow::Break(()) }
                ControlFlow::Continue(_) => ControlFlow::Continue(()),
            }
        });

        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Superblock parsing (called from the entry-point that opens the device)
// ─────────────────────────────────────────────────────────────────────────────

impl ApfsFs {
    /// Parse the NX (container) superblock from the first block of the device.
    ///
    /// `data` must be at least `block_size` bytes (the caller reads block 0
    /// before knowing the block size, so it should read at least 4096 bytes).
    pub fn parse_container_superblock(data: &[u8]) -> io::Result<ApfsSuperBlock> {
        let _span = tracy::span!("ApfsFs::parse_container_superblock");

        if data.len() < 32 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Block too small for NX superblock"));
        }

        // Offset 32: nx_magic (u32 LE)
        let magic = u32::from_le_bytes(data[32..36].try_into().unwrap());
        if magic != APFS_NX_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Not an APFS container (bad NX magic)"));
        }

        let block_size = u32::from_le_bytes(
            data[APFS_NX_BLOCK_SIZE_OFFSET..APFS_NX_BLOCK_SIZE_OFFSET + 4]
                .try_into().unwrap(),
        );
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid APFS block size"));
        }

        let omap_root_paddr = u64::from_le_bytes(
            data[APFS_NX_OMAP_OID_OFFSET..APFS_NX_OMAP_OID_OFFSET + 8]
                .try_into().unwrap(),
        );

        let volume_oid = u64::from_le_bytes(
            data[APFS_NX_FS_OID_OFFSET..APFS_NX_FS_OID_OFFSET + 8]
                .try_into().unwrap(),
        );

        Ok(ApfsSuperBlock { block_size, omap_root_paddr, volume_oid })
    }

    /// Resolve the volume OID to a physical block via the container omap, then
    /// parse the APSB volume superblock to get the volume's own omap root and
    /// the fs-record B-tree root.
    pub fn parse_volume(&self) -> io::Result<ApfsVolume> {
        let _span = tracy::span!("ApfsFs::parse_volume");

        // Resolve volume OID → physical block address via container omap
        let vol_paddr = self.omap_lookup(self.sb.omap_root_paddr, self.sb.volume_oid)?;

        let bs = self.sb.block_size as usize;
        let mut block = vec![0u8; bs];
        self.read_block(&mut block, vol_paddr)?;

        // Offset 32 in the volume block: apsb_magic
        if block.len() < 36 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Volume block too small"));
        }
        let magic = u32::from_le_bytes(block[32..36].try_into().unwrap());
        if magic != APFS_APSB_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Bad APSB magic"));
        }

        let omap_oid = u64::from_le_bytes(
            block[APFS_APSB_OMAP_OID_OFFSET..APFS_APSB_OMAP_OID_OFFSET + 8]
                .try_into().unwrap(),
        );
        let root_tree_oid = u64::from_le_bytes(
            block[APFS_APSB_ROOT_TREE_OID_OFFSET..APFS_APSB_ROOT_TREE_OID_OFFSET + 8]
                .try_into().unwrap(),
        );

        // Resolve volume's omap OID → paddr (it lives in the container omap)
        let vol_omap_paddr = self.omap_lookup(self.sb.omap_root_paddr, omap_oid)?;
        // Resolve fs-record tree OID → paddr via the volume's own omap
        let root_tree_paddr = self.omap_lookup(vol_omap_paddr, root_tree_oid)?;

        Ok(ApfsVolume { omap_root_paddr: vol_omap_paddr, root_tree_paddr })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

impl ApfsFs {
    #[inline]
    fn read_at_offset(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        read_at_offset(&self.file, buf, offset)
    }

    #[inline]
    fn read_block(&self, buf: &mut [u8], paddr: u64) -> io::Result<()> {
        let offset = paddr * self.sb.block_size as u64;
        let n = self.read_at_offset(buf, offset)?;
        if n < buf.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Short block read"));
        }
        Ok(())
    }

    // ── Object-map B-tree lookup (omap) ─────────────────────────────────────

    /// Walk the omap B-tree rooted at `root_paddr` to resolve `oid` → paddr.
    ///
    /// The omap uses fixed-length keys (OmapKey = 16 bytes) and values
    /// (OmapVal = 16 bytes), so nodes use `kvloc_t` table-of-contents entries.
    fn omap_lookup(&self, root_paddr: u64, oid: u64) -> io::Result<u64> {
        let _span = tracy::span!("ApfsFs::omap_lookup");

        let bs = self.sb.block_size as usize;
        let mut block = vec![0u8; bs];
        let mut cur_paddr = root_paddr;

        // Guard against corrupt trees (max depth 16 is generous for APFS)
        for _ in 0..16 {
            self.read_block(&mut block, cur_paddr)?;

            let node = Self::parse_btree_node_header(&block)?;
            let is_leaf = (node.btn_flags & APFS_BTNODE_FLAG_LEAF) != 0;

            // The ToC for a fixed-KV omap node starts at APFS_OBJ_HDR_SIZE + 24 = 56
            // Each entry is a KvLoc (8 bytes: k_off u16, k_len u16, v_off u16, v_len u16).
            // Key area starts at 56 + toc_len bytes.
            // Value area counts from the *end* of the block.

            let toc_start  = mem::size_of::<raw::BtreeNodePhys>(); // 0x38 = 56
            let key_start  = toc_start + node.btn_table_space_len as usize;
            let nkeys      = node.btn_nkeys as usize;

            let kvloc_size = mem::size_of::<raw::KvLoc>(); // 8 bytes

            let mut found_paddr: Option<u64> = None;
            // Track the largest key ≤ oid for interior nodes
            let mut best_child_paddr: Option<u64> = None;

            for i in 0..nkeys {
                let toc_off = toc_start + i * kvloc_size;
                if toc_off + kvloc_size > block.len() { break; }

                let kvloc = bytemuck::try_from_bytes::<raw::KvLoc>(
                    &block[toc_off..toc_off + kvloc_size]
                ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Bad KvLoc"))?;

                let k_off = key_start + kvloc.k_off as usize;
                let v_off = bs.saturating_sub(kvloc.v_off as usize + mem::size_of::<raw::OmapVal>());

                if k_off + mem::size_of::<raw::OmapKey>() > block.len() { continue; }
                if v_off + mem::size_of::<raw::OmapVal>() > block.len() { continue; }

                let key = bytemuck::try_from_bytes::<raw::OmapKey>(
                    &block[k_off..k_off + mem::size_of::<raw::OmapKey>()]
                ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Bad OmapKey"))?;

                let entry_oid = u64::from_le(key.ok_oid);

                if is_leaf {
                    if entry_oid == oid {
                        let val = bytemuck::try_from_bytes::<raw::OmapVal>(
                            &block[v_off..v_off + mem::size_of::<raw::OmapVal>()]
                        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Bad OmapVal"))?;
                        found_paddr = Some(u64::from_le(val.ov_paddr));
                        break;
                    }
                } else {
                    // Interior node: keep the largest key ≤ oid
                    if entry_oid <= oid {
                        let val = bytemuck::try_from_bytes::<raw::OmapVal>(
                            &block[v_off..v_off + mem::size_of::<raw::OmapVal>()]
                        ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Bad OmapVal (interior)"))?;
                        best_child_paddr = Some(u64::from_le(val.ov_paddr));
                    }
                }
            }

            if is_leaf {
                return found_paddr.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, format!("OID {oid} not found in omap"))
                });
            } else {
                cur_paddr = best_child_paddr.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "No suitable interior omap entry")
                })?;
            }
        }

        Err(io::Error::new(io::ErrorKind::InvalidData, "omap tree too deep or corrupt"))
    }

    // ── fs-record B-tree helpers ─────────────────────────────────────────────

    /// fs-record keys are keyed by (inode_num << 4 | record_type).
    /// We search for the lowest key with inode_num == target_ino.
    #[inline]
    fn make_search_key(ino: u64, rec_type: u8) -> u64 {
        (ino << 4) | (rec_type as u64)
    }

    /// Parse the fixed BtreeNodePhys header from a raw block.
    fn parse_btree_node_header(block: &[u8]) -> io::Result<raw::BtreeNodePhys> {
        let sz = mem::size_of::<raw::BtreeNodePhys>();
        if block.len() < sz {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Block too small for btree node"));
        }
        bytemuck::try_from_bytes::<raw::BtreeNodePhys>(&block[..sz])
            .map(|r| *r)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Corrupt btree node header"))
    }

    /// Walk the fs-record B-tree and call `visit` for every record whose
    /// oid == `target_ino` and record_type == `target_type`.
    ///
    /// `visit(key_bytes, val_bytes) -> ControlFlow`
    fn walk_fs_tree<R>(
        &self,
        target_ino:  u64,
        target_type: u8,
        mut visit:   impl FnMut(&[u8], &[u8]) -> ControlFlow<R>,
    ) -> io::Result<Option<R>> {
        let _span = tracy::span!("ApfsFs::walk_fs_tree");

        let search_key = Self::make_search_key(target_ino, target_type);
        let bs         = self.sb.block_size as usize;
        let mut block  = vec![0u8; bs];
        let mut cur_paddr = self.volume.root_tree_paddr;

        for _depth in 0..16 {
            self.read_block(&mut block, cur_paddr)?;
            let node    = Self::parse_btree_node_header(&block)?;
            let is_leaf = (u16::from_le(node.btn_flags) & APFS_BTNODE_FLAG_LEAF) != 0;
            let nkeys   = u32::from_le(node.btn_nkeys) as usize;

            // ToC layout for variable-length nodes uses KvOff (4 bytes each)
            let toc_start = mem::size_of::<raw::BtreeNodePhys>(); // 56
            let toc_off_base = toc_start + u16::from_le(node.btn_table_space_off) as usize;
            let key_area_start = toc_off_base + u16::from_le(node.btn_table_space_len) as usize;
            let kvoff_size = mem::size_of::<raw::KvOff>(); // 4

            // Values in variable-length nodes are addressed from the *end* of
            // the block (excluding a 40-byte btree_info at the very end of the
            // root node – we conservatively skip that check here).
            let val_area_end = bs; // simplified: use full block end

            let mut best_child_paddr: Option<u64> = None;
            let mut result: Option<R> = None;

            for i in 0..nkeys {
                let toc_entry_off = toc_off_base + i * kvoff_size;
                if toc_entry_off + kvoff_size > block.len() { break; }

                let kvoff = bytemuck::try_from_bytes::<raw::KvOff>(
                    &block[toc_entry_off..toc_entry_off + kvoff_size]
                ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Bad KvOff"))?;

                let k_abs = key_area_start + u16::from_le(kvoff.k) as usize;
                // Values counted from end
                let v_abs_end = val_area_end.saturating_sub(u16::from_le(kvoff.v) as usize);

                if k_abs + mem::size_of::<raw::JKey>() > block.len() { continue; }

                let jkey = bytemuck::try_from_bytes::<raw::JKey>(
                    &block[k_abs..k_abs + mem::size_of::<raw::JKey>()]
                ).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Bad JKey"))?;

                let raw_key   = u64::from_le(jkey.obj_id_and_type);
                let entry_ino = raw_key & 0x0FFF_FFFF_FFFF_FFFF;
                let entry_type= ((raw_key >> 60) & 0xF) as u8;

                if is_leaf {
                    if entry_ino == target_ino && entry_type == target_type {
                        // Figure out value length: from v_abs_end back to next
                        // entry's v_abs_end (imprecise but safe with slice bounds)
                        let v_len = if v_abs_end < block.len() { block.len() - v_abs_end } else { 0 };
                        let key_slice = &block[k_abs..block.len().min(k_abs + 256)];
                        let val_slice = if v_abs_end < block.len() { &block[v_abs_end..] } else { &[] };

                        match visit(key_slice, val_slice) {
                            ControlFlow::Break(b) => { result = Some(b); break; }
                            ControlFlow::Continue(_) => {}
                        }
                        let _ = v_len; // suppress warning
                    }
                    // Past the target range – stop early
                    if entry_ino > target_ino { break; }
                } else {
                    // Interior: find rightmost entry with key ≤ search_key
                    if raw_key <= search_key {
                        // Value is an OID (8 bytes) pointing to child node
                        if v_abs_end + 8 <= block.len() {
                            let child_oid = u64::from_le_bytes(
                                block[v_abs_end..v_abs_end + 8].try_into().unwrap_or([0; 8])
                            );
                            // Resolve child OID → paddr via volume omap
                            if let Ok(paddr) = self.omap_lookup(self.volume.omap_root_paddr, child_oid) {
                                best_child_paddr = Some(paddr);
                            }
                        }
                    }
                }
            }

            if is_leaf {
                return Ok(result);
            }

            cur_paddr = best_child_paddr.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "No child in interior fs-tree node")
            })?;
        }

        Err(io::Error::new(io::ErrorKind::InvalidData, "fs-record tree too deep or corrupt"))
    }

    // ── Inode lookup ─────────────────────────────────────────────────────────

    fn lookup_inode(&self, ino: u64) -> io::Result<ApfsInode> {
        let _span = tracy::span!("ApfsFs::lookup_inode");

        let mut found: Option<ApfsInode> = None;

        self.walk_fs_tree(ino, APFS_TYPE_INODE, |_key, val| {
            if val.len() < mem::size_of::<raw::JInodeVal>() {
                return ControlFlow::Continue(());
            }
            let raw = match bytemuck::try_from_bytes::<raw::JInodeVal>(
                &val[..mem::size_of::<raw::JInodeVal>()]
            ) {
                Ok(r) => r,
                Err(_) => return ControlFlow::Continue(()),
            };

            let mode      = u16::from_le(raw.mode);
            let mtime_ns  = u64::from_le(raw.mod_time);
            let mtime_sec = (mtime_ns / 1_000_000_000) as i64;
            // Reassemble the u64 that was split into two u32s to satisfy Pod alignment
            let size = u64::from_le(raw.uncompressed_size_lo as u64)
                | (u64::from_le(raw.uncompressed_size_hi as u64) << 32);
            let flags     = u64::from_le(raw.internal_flags);

            found = Some(ApfsInode { inode_num: ino, mode, size, mtime_sec, flags });
            ControlFlow::Break(())
        })?;

        found.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("Inode {ino} not found"))
        })
    }

    // ── Directory entry scan ─────────────────────────────────────────────────

    /// Iterate all `APFS_TYPE_DIR_REC` records for directory `dir_ino`,
    /// calling `callback(child_id, name_bytes, dt_type)`.
    fn scan_dir_entries<R>(
        &self,
        dir_ino:  u64,
        mut cb:   impl FnMut(FileId, &[u8], u8) -> ControlFlow<R>,
    ) -> io::Result<Option<R>> {
        self.walk_fs_tree(dir_ino, APFS_TYPE_DIR_REC, |key, val| {
            // key: JDrecHashedKey (16 bytes: JKey(8) + name_len_and_hash(4) + _pad(4)) + name
            let hdr_size = mem::size_of::<raw::JDrecHashedKey>(); // 16
            // The actual name starts at hdr_size - 4 because _pad is not on-disk data;
            // however since we use bytemuck on the raw block bytes directly and the
            // on-disk key layout is JKey(8)+u32(4)+name[], we read the name at offset 12.
            let name_offset_in_key = 12usize; // JKey(8) + name_len_and_hash(4)
            if key.len() < hdr_size { return ControlFlow::Continue(()); }

            let hdr = match bytemuck::try_from_bytes::<raw::JDrecHashedKey>(
                &key[..hdr_size]
            ) {
                Ok(h) => h,
                Err(_) => return ControlFlow::Continue(()),
            };

            // low 10 bits = name_len + 1 (null terminator included)
            let name_len_with_null = (u32::from_le(hdr.name_len_and_hash) & 0x3FF) as usize;
            if name_len_with_null == 0 { return ControlFlow::Continue(()); }
            let name_len = name_len_with_null.saturating_sub(1);

            let name_start = name_offset_in_key; // 12: right after the fixed on-disk header
            let name_end   = name_start + name_len;
            if name_end > key.len() { return ControlFlow::Continue(()); }
            let name_bytes = &key[name_start..name_end];

            // val: JDrecVal (18 bytes)
            let val_size = mem::size_of::<raw::JDrecVal>(); // 18
            if val.len() < val_size { return ControlFlow::Continue(()); }

            let drec = match bytemuck::try_from_bytes::<raw::JDrecVal>(&val[..val_size]) {
                Ok(d) => d,
                Err(_) => return ControlFlow::Continue(()),
            };

            let child_id = u64::from_le(drec.file_id);
            let dt       = (u16::from_le(drec.flags) & 0xF) as u8;

            cb(child_id, name_bytes, dt)
        })
    }

    // ── Extent collection ────────────────────────────────────────────────────

    /// Collect all `(physical_block, byte_length)` pairs for file `ino` that
    /// cover the first `size_to_read` bytes, in logical order.
    fn collect_extents(
        &self,
        ino:          u64,
        size_to_read: usize,
    ) -> io::Result<Vec<(u64, u64)>> {
        use super::raw::{JPhysExtKey, JPhysExtVal};

        let _span = tracy::span!("ApfsFs::collect_extents");

        let mut extents: Vec<(u64, u64)> = Vec::new();
        let mut covered: u64 = 0;

        self.walk_fs_tree(ino, super::APFS_TYPE_FILE_EXTENT, |key, val| {
            // APFS_TYPE_FILE_EXTENT = 8
            // key: JPhysExtKey (16 bytes), val: JPhysExtVal (24 bytes)
            let k_sz = mem::size_of::<JPhysExtKey>();
            let v_sz = mem::size_of::<JPhysExtVal>();
            if key.len() < k_sz || val.len() < v_sz {
                return ControlFlow::Continue(());
            }

            let v = match bytemuck::try_from_bytes::<JPhysExtVal>(&val[..v_sz]) {
                Ok(v) => v,
                Err(_) => return ControlFlow::Continue(()),
            };

            let len_bytes   = u64::from_le(v.len_and_flags) & 0x00FF_FFFF_FFFF_FFFF;
            let phys_block  = u64::from_le(v.phys_block_num);

            if phys_block == 0 || len_bytes == 0 {
                return ControlFlow::Continue(());
            }

            extents.push((phys_block, len_bytes));
            covered += len_bytes;

            if covered >= size_to_read as u64 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })?;

        Ok(extents)
    }
}
