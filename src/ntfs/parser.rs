//! NTFS filesystem implementation of RawFs trait

use smallvec::SmallVec;

use crate::tracy;
use crate::util::{is_dot_entry, read_at_offset, read_u16_le, read_u32_le};
use crate::parser::{BufKind, FileId, FileNode, FileType, Parser, RawFs, check_first_block_binary};

use super::*;

use std::io;
use std::fs::File;
use std::ops::ControlFlow;

// "$I30" in UTF-16LE - the name of the $FILE_NAME index on every directory
const I30: [u16; 4] = [0x0024, 0x0049, 0x0033, 0x0030];

pub struct NtfsFs {
    pub file: File,
    pub sb: NtfsSuperBlock,
    pub device_id: u64,
    pub mft_runs: SmallVec<[NtfsExtent; 8]>,
}

impl FileNode for NtfsNode {
    #[inline(always)]
    fn file_id(&self) -> FileId { self.record_num }

    #[inline(always)]
    fn size(&self) -> u64 { self.size }

    #[inline(always)]
    fn mtime(&self) -> i64 { self.mtime_sec }

    #[inline(always)]
    fn is_dir(&self) -> bool { self.flags & NTFS_MFT_RECORD_FLAG_IS_DIR != 0 }
}

impl RawFs for NtfsFs {
    type Node = NtfsNode;
    type Context<'b> = &'b Self where Self: 'b;

    #[inline(always)]
    fn device_id(&self) -> u64 { self.device_id }

    #[inline(always)]
    fn block_size(&self) -> u32 { self.sb.cluster_size }

    #[inline(always)]
    fn root_id(&self) -> FileId { NTFS_ROOT_DIR_RECORD }

    #[inline]
    fn parse_node(&self, file_id: FileId) -> io::Result<Self::Node> {
        let _span = tracy::span!("NtfsFs::parse_node");

        let mut record = vec![0u8; self.sb.mft_record_size as usize]; // @Heap
        self.read_mft_record(file_id, &mut record)?;

        parse_mft_record(&record, file_id)
    }

    fn read_file_content(
        &self,
        parser: &mut Parser,
        node: &Self::Node,
        max_size: usize,
        kind: BufKind,
        check_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("NtfsFs::read_file_content");

        if node.is_dir() && matches!(kind, BufKind::Dir) {
            return self.read_dir_linearised(node, parser, kind).map(|_| true);
        }

        let buf = parser.get_buf_mut(kind);
        buf.clear();

        let file_size = node.size as usize;
        let size_to_read = file_size.min(max_size);

        //
        // @Cutnpaste from Ext4Fs::read_file_content
        //
        // If previous file left a huge buffer, release it before reserving for this file
        // @Constant @Tune - 4MB threshold, files larger than this won't bloat next iteration
        //
        if buf.capacity() > 4 * 1024 * 1024 && size_to_read < buf.capacity() / 4 {
            *buf = Vec::with_capacity(size_to_read);
        } else {
            buf.reserve(size_to_read);
        }

        let mut record = vec![0u8; self.sb.mft_record_size as usize]; // @Heap
        self.read_mft_record(node.record_num, &mut record)?;

        let Some((is_resident, attr_slice)) = find_attribute(&record, NTFS_ATTR_DATA, None) else {
            return Ok(true); // no $DATA, metadata-only or empty
        };

        if is_resident {
            self.read_resident_data(parser, attr_slice, size_to_read, file_size, kind, check_binary)
        } else {
            self.read_nonresident_data(parser, attr_slice, size_to_read, file_size, kind, check_binary)
        }
    }

    #[inline]
    fn with_directory_entries<R>(
        &self,
        buf: &[u8],
        mut callback: impl FnMut(FileId, usize, usize, FileType) -> ControlFlow<R>
    ) -> Option<R> {
        let _span = tracy::span!("NtfsFs::with_directory_entries");

        //
        //
        // Linearised format: [u64 record_num][u8 is_dir][u8 name_len][name_utf8...]
        //
        //

        let mut pos = 0usize;
        while pos + 10 <= buf.len() { // @Cleanup
            let record_num = u64::from_le_bytes(buf[pos..pos+8].try_into().unwrap());
            let is_dir     = buf[pos+8] != 0;
            let name_len   = buf[pos+9] as usize;
            pos += 10;

            if pos + name_len > buf.len() { break; }
            if name_len == 0 { pos += name_len; continue; }

            let name_bytes = &buf[pos..pos + name_len];
            let file_type = if is_dir { FileType::Dir } else { FileType::File };
            pos += name_len;

            if is_dot_entry(name_bytes) { continue; }

            match callback(record_num, pos - name_len, name_len, file_type) {
                ControlFlow::Break(b) => return Some(b),
                ControlFlow::Continue(_) => {}
            }
        }

        None
    }
}

impl NtfsFs {
    #[inline]
    pub fn new(file: File, device_id: u64) -> io::Result<Self> {
        let mut boot = [0u8; 512];
        read_at_offset(&file, &mut boot, 0)?;
        let sb = parse_boot_sector(&boot)?;

        let mft_start = sb.mft_offset();
        let mut mft_record = vec![0u8; sb.mft_record_size as usize];
        read_at_offset(&file, &mut mft_record, mft_start)?;

        apply_fixups(&mut mft_record)?;
        validate_file_magic(&mft_record)?;

        let mft_runs = match find_attribute(&mft_record, NTFS_ATTR_DATA, None) {
            Some((false, attr_slice)) => decode_runlist(attr_slice, &sb)?,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Could not find $MFT $DATA attribute")),
        };

        Ok(NtfsFs { file, sb, device_id, mft_runs })
    }

    #[inline]
    fn read_mft_record(&self, record_num: u64, buf: &mut [u8]) -> io::Result<()> {
        let offset = mft_record_offset(&self.mft_runs, record_num, &self.sb)?;
        self.read_at_offset(buf, offset)?;
        apply_fixups(buf)
    }

    #[inline]
    fn read_at_offset(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        read_at_offset(&self.file, buf, offset)
    }

    #[inline]
    fn read_resident_data(
        &self,
        parser: &mut Parser,
        attr_slice: &[u8],
        size_to_read: usize, file_size: usize,
        kind: BufKind,
        check_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("NtfsFs::read_resident_data");

        let value_len = read_u32_le(attr_slice, NTFS_ATTR_RES_VALUE_LEN_OFFSET) as usize;
        let value_off = read_u16_le(attr_slice, NTFS_ATTR_RES_VALUE_OFF_OFFSET) as usize;
        let end = (value_off + value_len).min(attr_slice.len());
        if value_off >= end { return Ok(true); }

        let data = &attr_slice[value_off..end];
        let actual = data.len().min(size_to_read);

        if check_binary && check_first_block_binary(&data[..actual], file_size) {
            return Ok(false);
        }

        parser.get_buf_mut(kind).extend_from_slice(&data[..actual]);
        Ok(true)
    }

    fn read_nonresident_data(
        &self,
        parser: &mut Parser,
        attr_slice: &[u8],
        size_to_read: usize, file_size: usize,
        kind: BufKind,
        check_binary: bool,
    ) -> io::Result<bool> {
        let _span = tracy::span!("NtfsFs::read_nonresident_data");

        let runs = decode_runlist(attr_slice, &self.sb)?;
        let cluster_size = self.sb.cluster_size as u64;

        if check_binary && let Some(first_run) = runs.iter().find(|r| r.lcn != u64::MAX) {
            let mut first_cluster = vec![0u8; self.sb.cluster_size as usize]; // @Heap
            _ = self.read_at_offset(&mut first_cluster, first_run.lcn * cluster_size);

            if check_first_block_binary(&first_cluster, file_size) {
                return Ok(false);
            }
        }

        let mut copied = 0usize;
        for run in &runs {
            if copied >= size_to_read { break; }

            if run.lcn == u64::MAX {
                let to_fill = ((run.len * cluster_size) as usize).min(size_to_read - copied);
                let buf = parser.get_buf_mut(kind);
                buf.resize(buf.len() + to_fill, 0);
                copied += to_fill;
                continue;
            }

            let to_read = ((run.len * cluster_size) as usize).min(size_to_read - copied);
            let buf = parser.get_buf_mut(kind);
            let old_len = buf.len();
            buf.resize(old_len + to_read, 0);

            match self.read_at_offset(&mut buf[old_len..], run.lcn * cluster_size) {
                Ok(n) => { buf.truncate(old_len + n); copied += n; }
                Err(_) => { buf.truncate(old_len); break; }
            }
        }

        parser.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    #[inline]
    fn read_dir_linearised(&self, node: &NtfsNode, parser: &mut Parser, kind: BufKind) -> io::Result<()> {
        let _span = tracy::span!("NtfsFs::read_dir_linearised");

        let buf = parser.get_buf_mut(kind);
        buf.clear();

        let mut record = vec![0u8; self.sb.mft_record_size as usize]; // @Heap
        self.read_mft_record(node.record_num, &mut record)?;

        // $INDEX_ROOT: resident, always present, holds entries for small dirs or the B-tree root
        self.collect_index_root_entries(&record, buf);

        // $INDEX_ALLOCATION: non-resident INDX blocks on disk, holds entries for larger dirs
        // Both are collected into the same linearised buf so caller doesn't need to care which had what
        _ = self.collect_index_alloc_entries(&record, buf);

        Ok(())
    }

    #[inline]
    fn collect_index_root_entries(&self, record: &[u8], out: &mut Vec<u8>) {
        let Some((true, attr_slice)) = find_attribute(
            record,
            NTFS_ATTR_INDEX_ROOT,
            Some(&I30)
        ) else { return; };

        let val_off = read_u16_le(attr_slice, NTFS_ATTR_RES_VALUE_OFF_OFFSET) as usize;
        let val_len = read_u32_le(attr_slice, NTFS_ATTR_RES_VALUE_LEN_OFFSET) as usize;
        if val_off + 0x20 > attr_slice.len() { return; }

        let value = &attr_slice[val_off..(val_off + val_len).min(attr_slice.len())];
        if value.len() < 0x20 { return; }

        let node_hdr = &value[0x10..];

        let first_entry_off = read_u32_le(node_hdr, 0) as usize;
        let used_size       = read_u32_le(node_hdr, 4) as usize;
        let end = used_size.min(node_hdr.len());
        if first_entry_off >= end { return; }

        linearise_index_entries_into(&node_hdr[first_entry_off..end], out);
    }

    fn collect_index_alloc_entries(&self, record: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let Some((false, attr_slice)) = find_attribute(
            record,
            NTFS_ATTR_INDEX_ALLOCATION,
            Some(&I30)
        ) else {
            return Ok(());
        };

        //
        // Index block size comes from $INDEX_ROOT value+0x08; fall back to cluster size
        //
        let index_block_size = find_attribute(record, NTFS_ATTR_INDEX_ROOT, Some(&I30)).and_then(|(resident, ir)| {
            if !resident { return None; }

            let val_off = read_u16_le(ir, NTFS_ATTR_RES_VALUE_OFF_OFFSET) as usize;
            if val_off + 12 > ir.len() { return None; }

            Some(read_u32_le(ir, val_off + 8) as u64)
        }).unwrap_or(self.sb.cluster_size as u64).max(512);

        let runs = decode_runlist(attr_slice, &self.sb)?;
        let cluster_size = self.sb.cluster_size as u64;
        let clusters_per_block = (index_block_size / cluster_size).max(1);
        let total_clusters: u64 = runs.iter().map(|r| r.len).sum();
        let total_blocks = total_clusters / clusters_per_block;

        for block_idx in 0..total_blocks {
            let vcn = block_idx * clusters_per_block;

            //
            // Walk runlist to find LCN for this block's VCN
            //

            let mut lcn_start = None;
            let mut remaining = vcn;
            for run in &runs {
                if run.lcn == u64::MAX {
                    if remaining < run.len { break; }
                    remaining -= run.len;
                    continue;
                }
                if remaining < run.len {
                    lcn_start = Some(run.lcn + remaining);
                    break;
                }
                remaining -= run.len;
            }

            let Some(lcn) = lcn_start else { continue; };

            let mut indx = vec![0u8; index_block_size as usize];
            if self.read_at_offset(&mut indx, lcn * cluster_size).is_err() { continue; }

            //
            // Skip corrupt blocks
            //
            if apply_fixups(&mut indx).is_err() { continue; }

            if indx.len() < 4 { continue; }
            if u32::from_le_bytes(indx[0..4].try_into().unwrap()) != NTFS_INDX_MAGIC { continue; }
            if indx.len() < 0x28 { continue; }

            let node_hdr = &indx[0x18..];

            let first_entry_off = read_u32_le(node_hdr, 0) as usize;
            let used_size       = read_u32_le(node_hdr, 4) as usize;
            let end = used_size.min(node_hdr.len());
            if first_entry_off >= end { continue; }

            linearise_index_entries_into(&node_hdr[first_entry_off..end], out);
        }

        Ok(())
    }
}

#[inline]
fn parse_boot_sector(boot: &[u8]) -> io::Result<NtfsSuperBlock> {
    if boot.len() < 80 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Boot sector too short"));
    }

    if &boot[3..11] != b"NTFS    " {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Not an NTFS volume"));
    }

    let bytes_per_sector    = u16::from_le_bytes(boot[11..13].try_into().unwrap());
    let sectors_per_cluster = boot[13];
    let cluster_size = bytes_per_sector as u32 * sectors_per_cluster as u32;
    let mft_lcn = u64::from_le_bytes(boot[48..56].try_into().unwrap());
    let mft_record_size = {
        let raw = boot[64] as i8;
        if raw > 0 { (raw as u32) * cluster_size } else { 1u32 << (-raw as u32) }
    };

    Ok(NtfsSuperBlock { bytes_per_sector, sectors_per_cluster, cluster_size, mft_lcn, mft_record_size })
}

#[inline]
fn validate_file_magic(record: &[u8]) -> io::Result<()> {
    if record.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "MFT record too short"));
    }

    if u32::from_le_bytes(record[0..4].try_into().unwrap()) != NTFS_FILE_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Bad MFT record magic"));
    }

    Ok(())
}

/// Apply NTFS update sequence array fixups.
/// Returns Err on USN mismatch so callers can skip corrupt records/blocks.
#[inline]
fn apply_fixups(buf: &mut [u8]) -> io::Result<()> {
    if buf.len() < 8 { return Ok(()); }

    let usa_offset = u16::from_le_bytes(buf[4..6].try_into().unwrap()) as usize;
    let usa_count  = u16::from_le_bytes(buf[6..8].try_into().unwrap()) as usize;

    if usa_count < 2 || usa_offset + usa_count * 2 > buf.len() { return Ok(()); }

    let usn_lo = buf[usa_offset + 0];
    let usn_hi = buf[usa_offset + 1];

    for i in 1..usa_count {
        let sector_end = i * 512 - 2;
        if sector_end + 1 >= buf.len() { break; }

        if buf[sector_end] != usn_lo || buf[sector_end + 1] != usn_hi {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "USN mismatch"));
        }

        let saved = usa_offset + i * 2;
        buf[sector_end + 0] = buf[saved + 0];
        buf[sector_end + 1] = buf[saved + 1];
    }

    Ok(())
}

#[inline]
fn parse_mft_record(record: &[u8], record_num: u64) -> io::Result<NtfsNode> {
    if record.len() < 48 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "MFT record too short"));
    }

    validate_file_magic(record)?;

    let flags = &record[NTFS_MFT_RECORD_FLAGS_OFFSET..NTFS_MFT_RECORD_FLAGS_OFFSET+2];
    let flags = u16::from_le_bytes(flags.try_into().unwrap());
    if flags & NTFS_MFT_RECORD_FLAG_IN_USE == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "MFT record not in use"));
    }

    let mut mtime_sec = 0i64;
    if let Some((true, si)) = find_attribute(record, NTFS_ATTR_STANDARD_INFORMATION, None) {
        let val_off = read_u16_le(si, NTFS_ATTR_RES_VALUE_OFF_OFFSET) as usize;
        if val_off + NTFS_SI_MTIME_OFFSET + 8 <= si.len() {
            let ft = &si[val_off + NTFS_SI_MTIME_OFFSET..val_off + NTFS_SI_MTIME_OFFSET + 8];
            let ft = u64::from_le_bytes(ft.try_into().unwrap());
            mtime_sec = filetime_to_unix(ft);
        }
    }

    let size = find_data_size(record);
    Ok(NtfsNode { record_num, flags, size, mtime_sec })
}

#[inline]
fn find_data_size(record: &[u8]) -> u64 {
    match find_attribute(record, NTFS_ATTR_DATA, None) {
        Some((true,  attr)) => read_u32_le(attr, NTFS_ATTR_RES_VALUE_LEN_OFFSET) as u64,
        Some((false, attr)) if attr.len() >= 56 => u64::from_le_bytes(attr[48..56].try_into().unwrap()), // data_size at +0x30
        _ => 0,
    }
}

fn find_attribute<'a>(
    record: &'a [u8],
    attr_type: u32,
    name_utf16: Option<&[u16]>,
) -> Option<(bool, &'a [u8])> {
    let first_attr_off = record.get(NTFS_MFT_RECORD_ATTRS_OFFSET..NTFS_MFT_RECORD_ATTRS_OFFSET+2)?;
    let first_attr_off = first_attr_off.try_into().ok()?;
    let first_attr_off = u16::from_le_bytes(first_attr_off) as usize;

    let mut offset = first_attr_off;
    loop {
        if offset + 8 > record.len() { return None; }

        let a_type = read_u32_le(record, offset);
        if a_type == NTFS_ATTR_END || a_type == 0 { return None; }

        let a_len = read_u32_le(record, offset + 4) as usize;
        if a_len < 8 || offset + a_len > record.len() { return None; }

        if a_type == attr_type {
            let attr = &record[offset..offset + a_len];
            let name_len = attr[NTFS_ATTR_NAME_LEN_OFFSET] as usize;
            let matches = match name_utf16 {
                None => name_len == 0,

                Some(wanted) => name_len == wanted.len() && {
                    let name_off = read_u16_le(attr, NTFS_ATTR_NAME_OFF_OFFSET) as usize;
                    let nbytes = name_len * 2;
                    let name_bytes = &attr[name_off..name_off+nbytes];
                    name_off + nbytes <= attr.len() && name_bytes == bytemuck::cast_slice(wanted)
                }
            };

            if matches {
                return Some((attr[NTFS_ATTR_NON_RESIDENT_OFFSET] == 0, attr));
            }
        }

        offset += a_len;
    }
}

/// Decode NTFS runlist from a non-resident attribute slice into absolute LCNs.
fn decode_runlist(attr_slice: &[u8], _sb: &NtfsSuperBlock) -> io::Result<SmallVec<[NtfsExtent; 8]>> {
    if attr_slice.len() < 34 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Attr slice too short"));
    }

    let runlist_off = u16::from_le_bytes(attr_slice[32..34].try_into().unwrap()) as usize;
    if runlist_off >= attr_slice.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Runlist offset out of range"));
    }

    let runlist = &attr_slice[runlist_off..];
    let mut runs = SmallVec::new();
    let mut pos = 0usize;
    let mut current_lcn = 0i64;
    let mut current_vcn = 0u64;

    while pos < runlist.len() {
        let header = runlist[pos];
        if header == 0 { break; }

        let len_len = (header & 0x0F) as usize;
        let off_len = ((header >> 4) & 0x0F) as usize;
        pos += 1;
        if pos + len_len + off_len > runlist.len() { break; }

        let mut run_len = 0u64;
        for i in 0..len_len { run_len |= (runlist[pos + i] as u64) << (i * 8) }
        pos += len_len;

        let lcn = if off_len == 0 {
            u64::MAX // sparse
        } else {
            let mut raw = 0i64;
            for i in 0..off_len { raw |= (runlist[pos + i] as i64) << (i * 8) }

            let sign_bit = 1i64 << (off_len * 8 - 1);
            if raw & sign_bit != 0 { raw |= !((1i64 << (off_len * 8)) - 1); }

            current_lcn += raw;
            current_lcn as u64
        };
        pos += off_len;

        runs.push(NtfsExtent { lcn, vcn: current_vcn, len: run_len });
        current_vcn += run_len;
    }

    Ok(runs)
}

#[inline]
fn mft_record_offset(mft_runs: &[NtfsExtent], record_num: u64, sb: &NtfsSuperBlock) -> io::Result<u64> {
    let mft_record_size     = sb.mft_record_size as u64;
    let cluster_size        = sb.cluster_size as u64;
    let records_per_cluster = cluster_size / mft_record_size; // e.g. 4096/1024 = 4
    let vcn                 = record_num / records_per_cluster;
    let byte_within_cluster = (record_num % records_per_cluster) * mft_record_size;

    for run in mft_runs {
        if run.lcn == u64::MAX { continue; }
        if vcn >= run.vcn && vcn < run.vcn + run.len {
            return Ok((run.lcn + (vcn - run.vcn)) * cluster_size + byte_within_cluster);
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, format!("MFT record {record_num} not found in MFT runlist")))
}

#[inline]
fn filetime_to_unix(ft: u64) -> i64 {
    if ft < FILETIME_EPOCH_OFFSET { return 0; }
    ((ft - FILETIME_EPOCH_OFFSET) / 10_000_000) as i64
}

fn linearise_index_entries_into(entries_buf: &[u8], out: &mut Vec<u8>) {
    let mut pos = 0;
    while pos + 0x10 <= entries_buf.len() { // @Cleanup
        let entry_len = u16::from_le_bytes(entries_buf[pos+8..pos+10].try_into().unwrap()) as usize;
        let key_len   = u16::from_le_bytes(entries_buf[pos+10..pos+12].try_into().unwrap()) as usize;
        let flags     = u16::from_le_bytes(entries_buf[pos+12..pos+14].try_into().unwrap());

        if entry_len < 0x10 || flags & NTFS_INDEX_ENTRY_LAST != 0 { break; }

        let record_num = u64::from_le_bytes(entries_buf[pos..pos+8].try_into().unwrap()) & 0x0000_FFFF_FFFF_FFFF;

        'entry: {
            let key_end = pos + 0x10 + key_len;
            if record_num == 0 || key_end > entries_buf.len() { break 'entry; }

            let key = &entries_buf[pos+0x10..key_end];
            if key.len() < NTFS_FN_NAME_OFFSET + 2 { break 'entry; }

            let namespace   = key[NTFS_FN_NAMESPACE_OFFSET];
            let fn_name_len = key[NTFS_FN_NAME_LEN_OFFSET] as usize;
            let file_attrs  = key[NTFS_FN_FLAGS_OFFSET..NTFS_FN_FLAGS_OFFSET+4].try_into().unwrap();
            let file_attrs  = u32::from_le_bytes(file_attrs);

            if namespace == 2 || fn_name_len == 0 { break 'entry; }

            let name_end = NTFS_FN_NAME_OFFSET + fn_name_len * 2;
            if name_end > key.len() { break 'entry; }

            let mut utf16: SmallVec<[u16; 64]> = SmallVec::new();
            utf16.extend(key[NTFS_FN_NAME_OFFSET..name_end].chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])));

            let name = String::from_utf16_lossy(&utf16);
            let name = name.as_bytes();
            if name.len() > 255 { break 'entry; }

            //
            //
            // Linearised format: [u64 record_num][u8 is_dir][u8 name_len][name_utf8...]
            //
            //

            let is_dir = (file_attrs & NTFS_FILE_ATTR_DIRECTORY) != 0;
            out.extend_from_slice(&record_num.to_le_bytes());
            out.push(is_dir as u8);
            out.push(name.len() as u8);
            out.extend_from_slice(name);
        }

        pos += entry_len;
    }
}
