//! NTFS filesystem implementation of RawFs trait

use smallvec::SmallVec;

use crate::tracy;
use crate::util::{is_dot_entry, read_at_offset, read_u16_le, read_u32_le};
use crate::parser::{BufKind, FileId, FileNode, FileType, Parser, RawFs, binary_probe};
use crate::worker::STREAMING_CHUNK_SIZE;

use super::*;

use std::cell::UnsafeCell;
use std::fs::File;
use std::io;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::{Condvar, Mutex};

const DATA_NONE: u8 = 0;
const DATA_RESIDENT: u8 = 1;
const DATA_NONRESIDENT: u8 = 2;

pub struct NtfsFs {
    pub file: File,
    pub sb: NtfsSuperBlock,
    pub device_path: Arc<str>,
    pub device_id: u64,
    pub mft_runs: SmallVec<[NtfsExtent; 8]>,
    tree: UnsafeCell<NtfsTree>,
    scan: MftScan,
}

// Disjoint per-record writes during the parallel `$MFT` scan; after `ready`
// the tree is read-only. `File`/`Vec` fields are otherwise `Sync`.
unsafe impl Sync for NtfsFs {}

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

    #[inline(always)] fn device_id(&self) -> u64 { self.device_id }
    #[inline(always)] fn block_size(&self) -> u32 { self.sb.cluster_size }
    #[inline(always)] fn device_file(&self) -> &File { &self.file }
    #[inline(always)] fn root_id(&self) -> FileId { NTFS_ROOT_DIR_RECORD }

    #[inline]
    fn parse_node(&self, file_id: FileId) -> io::Result<Self::Node> {
        let _span = tracy::span!("NtfsFs::parse_node");

        if !self.tree().is_in_use(file_id) {
            return Err(io::Error::new(io::ErrorKind::NotFound, "MFT record not in use"));
        }
        let m = self.tree().meta(file_id);
        Ok(NtfsNode {
            record_num: file_id,
            flags: m.flags,
            size: m.size,
            mtime_sec: m.mtime_sec,
        })
    }

    #[inline]
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

        let file_size   = node.size as usize;
        let size_to_read = file_size.min(max_size);

        match self.tree().data_kind(node.record_num) {
            DATA_NONE => {
                parser.get_buf_mut(kind).clear();
                return Ok(true);
            }
            DATA_RESIDENT => {
                let data = self.tree().raw_runlist(node.record_num);
                let actual = data.len().min(size_to_read);
                if check_binary && binary_probe(&data[..actual], file_size) {
                    return Ok(false);
                }
                let buf = parser.get_buf_mut(kind);
                buf.clear();
                buf.extend_from_slice(&data[..actual]);
                return Ok(true);
            }
            _ => {}
        }

        let buf = Parser::get_buf_mut_impl(&mut parser.file, &mut parser.dir, &mut parser.gitignore, kind);
        buf.clear();

        let Some(chunks) = self.collect_file_chunks(
            &mut parser.scratch,
            &mut parser.scratch2,
            node,
            size_to_read,
            check_binary,
            buf
        )? else {
            parser.get_buf_mut(kind).clear();
            return Ok(false); // binary
        };

        for (disk_offset, len) in &chunks {
            let buf = parser.get_buf_mut(kind);

            let old_len = buf.len();
            buf.resize(old_len + len, 0);
            match self.read_at_offset(&mut buf[old_len..], *disk_offset) {
                Ok(n)  => buf.truncate(old_len + n),
                Err(_) => { buf.truncate(old_len); break; }
            }
        }

        parser.get_buf_mut(kind).truncate(size_to_read);
        Ok(true)
    }

    fn collect_file_chunks(
        &self,
        _scratch: &mut Vec<u8>,    // unused for NTFS cuz runlists are decoded inline
        _scratch2: &mut Vec<u8>,   // unused for NTFS cuz runlists are decoded inline
        node: &NtfsNode,
        max_size: usize,
        check_binary: bool,
        buf: &mut Vec<u8>
    ) -> io::Result<Option<SmallVec<[(u64, usize); 32]>>> {
        let _span = tracy::span!("NtfsFs::collect_file_chunks");

        let file_size = node.size as usize;
        let cluster_size = self.sb.cluster_size as u64;

        if node.is_dir() {
            return Ok(Some(SmallVec::new()));
        }

        let raw = self.tree().raw_runlist(node.record_num);
        if raw.is_empty() {
            return Ok(Some(SmallVec::new()));
        }

        let runs = decode_runlist_bytes(raw)?;

        let mut skip_first = 0usize;

        if check_binary && let Some(first) = runs.iter().find(|r| r.lcn != u64::MAX) {
            let probe_len = (self.sb.cluster_size as usize).min(max_size);
            let mut probe = vec![0u8; probe_len]; // @Heap

            let n = self.read_at_offset(&mut probe, first.lcn * cluster_size).unwrap_or(0);
            if binary_probe(&probe[..n], file_size) {
                return Ok(None);
            }
            buf.extend_from_slice(&probe[..n]);
            skip_first = n;
        }

        let mut chunks = SmallVec::<[_; 32]>::new();
        let mut total = 0usize;

        for run in &runs {
            if total >= max_size { break; }

            if run.lcn == u64::MAX {
                // Sparse run, skip it for now?...
                let to_skip = ((run.len * cluster_size) as usize).min(max_size - total);
                total += to_skip;
                continue;
            }

            let run_bytes = (run.len * cluster_size) as usize;
            let mut run_offset = 0usize;

            while run_offset < run_bytes {
                if total >= max_size { break; }

                let remaining  = max_size - total;
                let mut to_read = STREAMING_CHUNK_SIZE.min(remaining).min(run_bytes - run_offset);
                let mut disk_offset = run.lcn * cluster_size + run_offset as u64;

                if skip_first > 0 {
                    let skip = skip_first.min(to_read);
                    disk_offset += skip as u64;
                    to_read     -= skip;
                    run_offset  += skip;
                    total       += skip;
                    skip_first  -= skip;
                    if to_read == 0 { continue; }
                }

                chunks.push((disk_offset, to_read));
                run_offset += to_read;
                total      += to_read;
            }
        }

        Ok(Some(chunks))
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
    pub fn new(file: File, device_id: u64, device_path: &str) -> io::Result<Self> {
        let mut boot = [0u8; 512];
        read_at_offset(&file, &mut boot, 0)?;
        let sb = parse_boot_sector(&boot)?;

        let mft_start = sb.mft_offset();
        let mut mft_record = vec![0u8; sb.mft_record_size as usize]; // @Heap
        read_at_offset(&file, &mut mft_record, mft_start)?;

        apply_fixups(&mut mft_record)?;
        validate_file_magic(&mft_record)?;

        let mft_runs = match find_attribute(&mft_record, NTFS_ATTR_DATA, None) {
            Some((false, attr_slice)) => decode_runlist(attr_slice, &sb)?,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Could not find $MFT $DATA attribute")),
        };

        let mft_data_size = find_data_size(&mft_record);
        let num_records = (mft_data_size / sb.mft_record_size as u64) as usize;
        let tree = NtfsTree::with_capacity(num_records);
        let scan = MftScan::new(num_records);

        Ok(NtfsFs {
            file,
            sb,
            device_id,
            mft_runs,
            device_path: device_path.into(),
            tree: UnsafeCell::new(tree),
            scan,
        })
    }

    #[inline]
    fn tree(&self) -> &NtfsTree {
        // SAFETY: slots are written disjointly during scan; after `ready` the
        // tree is treated as read-only shared state.
        unsafe { &*self.tree.get() }
    }

    /// Arm the parallel `$MFT` scan. Call once on the search thread before
    /// workers wake; each worker then runs [`scan_mft_worker`].
    pub fn init_parallel_scan(&self, num_workers: usize) {
        let n = num_workers.max(1);
        *self.scan.parts.lock() = (0..n).map(|_| None).collect();
        self.scan.remaining.store(n, Ordering::Release);
        *self.scan.ready.0.lock() = false;
        *self.scan.work_gate.0.lock() = false;
        *self.scan.error.lock() = None;
    }

    /// One worker's disjoint record-number slice. Last arriver merges arenas
    /// and builds the CSR. Every worker then waits on the work gate so the
    /// search thread can resolve the root path and push the first `WorkItem`
    /// before anyone enters the steal loop.
    pub fn scan_mft_worker(&self, worker_id: usize, num_workers: usize) {
        let _span = tracy::span!("NtfsFs::scan_mft_worker");

        let n = self.tree().capacity();
        let nw = num_workers.max(1);
        let start = n * worker_id / nw;
        let end = n * (worker_id + 1) / nw;

        let mut part = ScanPart {
            rec_start: start,
            rec_end: end,
            names: Vec::with_capacity((end - start).saturating_mul(16)),
            runlists: Vec::new(),
        };

        if let Err(e) = self.scan_mft_range(start, end, &mut part) {
            *self.scan.error.lock() = Some(e);
        }

        self.scan.parts.lock()[worker_id] = Some(part);

        if self.scan.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.finish_scan();
            let (lock, cvar) = &self.scan.ready;
            *lock.lock() = true;
            cvar.notify_all();
        } else {
            let (lock, cvar) = &self.scan.ready;
            let mut ready = lock.lock();
            while !*ready {
                cvar.wait(&mut ready);
            }
        }

        let (lock, cvar) = &self.scan.work_gate;
        let mut gate = lock.lock();
        while !*gate {
            cvar.wait(&mut gate);
        }
    }

    pub fn wait_mft_ready(&self) -> io::Result<()> {
        let (lock, cvar) = &self.scan.ready;
        let mut ready = lock.lock();
        while !*ready {
            cvar.wait(&mut ready);
        }
        drop(ready);
        match self.scan.error.lock().take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    pub fn release_work_gate(&self) {
        let (lock, cvar) = &self.scan.work_gate;
        *lock.lock() = true;
        cvar.notify_all();
    }

    #[inline]
    fn read_at_offset(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        crate::util::with_thread_device_file(&self.device_path, |file| {
            crate::util::read_at_offset(file, buf, offset)
        })?
    }

    #[inline]
    fn read_dir_linearised(&self, node: &NtfsNode, parser: &mut Parser, kind: BufKind) -> io::Result<()> {
        let _span = tracy::span!("NtfsFs::read_dir_linearised");

        let buf = parser.get_buf_mut(kind);
        buf.clear();

        for &child in self.tree().dir_children(node.record_num) {
            let child = child as u64;
            if child == node.record_num { continue; }
            if !self.tree().is_in_use(child) { continue; }

            let name = self.tree().name(child);
            if name.is_empty() || name.len() > 255 { continue; }

            buf.extend_from_slice(&child.to_le_bytes());
            buf.push(self.tree().is_dir(child) as u8);
            buf.push(name.len() as u8);
            buf.extend_from_slice(name);
        }
        Ok(())
    }

    fn scan_mft_range(&self, rec_start: usize, rec_end: usize, part: &mut ScanPart) -> io::Result<()> {
        if rec_start >= rec_end {
            return Ok(());
        }

        const CHUNK_RECORDS: usize = 4096;
        let record_size = self.sb.mft_record_size as usize;
        let chunk_cap = record_size * CHUNK_RECORDS;

        #[cfg(windows)]
        let mut chunk = crate::util::AlignedBuf::new(chunk_cap);
        #[cfg(not(windows))]
        let mut chunk = vec![0u8; chunk_cap];

        let file = {
            #[cfg(windows)]
            { crate::grep::open_device_impl(&self.device_path, true)? }
            #[cfg(not(windows))]
            { crate::grep::open_device(&self.device_path)? }
        };

        for run in &self.mft_runs {
            if run.lcn == u64::MAX { continue; }

            let (run_first, run_end) = run_record_span(run, &self.sb);
            let start = rec_start.max(run_first as usize);
            let end = rec_end.min(run_end as usize);
            if start >= end { continue; }

            let Ok(mut disk_offset) = mft_record_offset(&self.mft_runs, start as u64, &self.sb) else {
                continue;
            };

            let mut rec = start;
            while rec < end {
                let batch = (end - rec).min(CHUNK_RECORDS);
                let to_read = batch * record_size;

                let (prefix, n) = scan_read_chunk(&file, &mut chunk, to_read, disk_offset)?;
                if n < record_size { break; }

                let mut pos = prefix;
                let data_end = prefix + n;
                while pos + record_size <= data_end {
                    let record_num = rec + (pos - prefix) / record_size;
                    if record_num >= end { break; }

                    #[cfg(windows)]
                    let record = &mut chunk.as_mut_slice()[pos..pos + record_size];
                    #[cfg(not(windows))]
                    let record = &mut chunk[pos..pos + record_size];

                    if apply_fixups(record).is_ok() && validate_file_magic(record).is_ok() {
                        let _ = parse_mft_record_full(
                            record,
                            record_num as u64,
                            self.tree(),
                            unsafe { &mut *self.scan.parent.0.get() },
                            part,
                        );
                    }
                    pos += record_size;
                }

                let consumed = (n / record_size) * record_size;
                rec += consumed / record_size;
                disk_offset += consumed as u64;
            }
        }

        Ok(())
    }

    fn finish_scan(&self) {
        let mut parts = self.scan.parts.lock();
        let mut names = Vec::new();
        let mut runlists = Vec::new();

        for part in parts.iter_mut().flatten() {
            let name_base = names.len() as u32;
            let run_base = runlists.len() as u32;
            for idx in part.rec_start..part.rec_end {
                if self.tree().name_len_at(idx) > 0 {
                    self.tree().add_name_off(idx, name_base);
                }
                if self.tree().runlist_len_at(idx) > 0 {
                    self.tree().add_runlist_off(idx, run_base);
                }
            }
            names.append(&mut part.names);
            runlists.append(&mut part.runlists);
        }

        let tree = unsafe { &mut *self.tree.get() };
        tree.set_arenas(names, runlists);
        let parent = unsafe { &*self.scan.parent.0.get() };
        tree.build_csr(parent);
    }
}

struct ScanPart {
    rec_start: usize,
    rec_end: usize,
    names: Vec<u8>,
    runlists: Vec<u8>,
}

struct ScanParent(UnsafeCell<Vec<u64>>);
unsafe impl Sync for ScanParent {}

struct MftScan {
    remaining: AtomicUsize,
    error: Mutex<Option<io::Error>>,
    ready: (Mutex<bool>, Condvar),
    work_gate: (Mutex<bool>, Condvar),
    parts: Mutex<Vec<Option<ScanPart>>>,
    parent: ScanParent,
}

impl MftScan {
    fn new(num_records: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(0),
            error: Mutex::new(None),
            ready: (Mutex::new(false), Condvar::new()),
            work_gate: (Mutex::new(false), Condvar::new()),
            parts: Mutex::new(Vec::new()),
            parent: ScanParent(UnsafeCell::new(vec![0u64; num_records])),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecordMeta {
    pub flags: u16,
    pub size: u64,
    pub mtime_sec: i64,
}

pub struct NtfsTree {
    meta: Vec<RecordMeta>,
    name_off: Vec<u32>,
    name_len: Vec<u16>,
    names: Vec<u8>,
    runlist_off: Vec<u32>,
    runlist_len: Vec<u32>,
    runlists: Vec<u8>,
    data_kind: Vec<u8>,
    child_offsets: Vec<u32>,
    child_ids: Vec<u32>,
}

impl NtfsTree {
    pub fn with_capacity(num_records: usize) -> Self {
        Self {
            meta: vec![RecordMeta { flags: 0, size: 0, mtime_sec: 0 }; num_records],
            name_off: vec![0; num_records],
            name_len: vec![0; num_records],
            names: Vec::new(),
            runlist_off: vec![0; num_records],
            runlist_len: vec![0; num_records],
            runlists: Vec::new(),
            data_kind: vec![0; num_records],
            child_offsets: Vec::new(),
            child_ids: Vec::new(),
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize { self.meta.len() }

    #[inline]
    pub fn is_in_use(&self, id: u64) -> bool {
        self.meta.get(id as usize).is_some_and(|m| m.flags & NTFS_MFT_RECORD_FLAG_IN_USE != 0)
    }

    #[inline]
    pub fn meta(&self, id: u64) -> RecordMeta {
        self.meta[id as usize]
    }

    #[inline]
    pub fn is_dir(&self, id: u64) -> bool {
        self.meta[id as usize].flags & NTFS_MFT_RECORD_FLAG_IS_DIR != 0
    }

    #[inline]
    pub fn name(&self, id: u64) -> &[u8] {
        let idx = id as usize;
        let off = self.name_off[idx] as usize;
        let len = self.name_len[idx] as usize;
        &self.names[off..off + len]
    }

    #[inline]
    pub fn raw_runlist(&self, id: u64) -> &[u8] {
        let idx = id as usize;
        let off = self.runlist_off[idx] as usize;
        let len = self.runlist_len[idx] as usize;
        &self.runlists[off..off + len]
    }

    #[inline]
    pub fn data_kind(&self, id: u64) -> u8 {
        self.data_kind.get(id as usize).copied().unwrap_or(0)
    }

    #[inline]
    fn name_len_at(&self, idx: usize) -> u16 { self.name_len[idx] }

    #[inline]
    fn runlist_len_at(&self, idx: usize) -> u32 { self.runlist_len[idx] }

    #[inline]
    fn add_name_off(&self, idx: usize, base: u32) {
        unsafe {
            let p = self.name_off.as_ptr() as *mut u32;
            *p.add(idx) += base;
        }
    }

    #[inline]
    fn add_runlist_off(&self, idx: usize, base: u32) {
        unsafe {
            let p = self.runlist_off.as_ptr() as *mut u32;
            *p.add(idx) += base;
        }
    }

    fn set_arenas(&mut self, names: Vec<u8>, runlists: Vec<u8>) {
        self.names = names;
        self.runlists = runlists;
    }

    pub fn build_csr(&mut self, parent: &[u64]) {
        let n = parent.len();
        let mut offsets = vec![0u32; n + 1];

        for i in 0..n {
            if !self.is_in_use(i as u64) { continue; }
            let p = parent[i] as usize;
            if p < n { offsets[p + 1] += 1; }
        }
        for i in 0..n { offsets[i + 1] += offsets[i]; }

        let mut cursor = offsets.clone();
        let mut child_ids = vec![0u32; offsets[n] as usize];

        for i in 0..n {
            if !self.is_in_use(i as u64) { continue; }
            let p = parent[i] as usize;
            if p < n {
                let slot = &mut cursor[p];
                child_ids[*slot as usize] = i as u32;
                *slot += 1;
            }
        }

        self.child_offsets = offsets;
        self.child_ids = child_ids;
    }

    #[inline]
    pub fn dir_children(&self, dir_id: FileId) -> &[u32] {
        let r = dir_id as usize;
        if r + 1 >= self.child_offsets.len() {
            return &[];
        }
        let start = self.child_offsets[r] as usize;
        let end = self.child_offsets[r + 1] as usize;
        &self.child_ids[start..end]
    }

    fn write_slot(&self, idx: usize, meta: RecordMeta, parent_ref: u64, parent: &mut [u64], part: &mut ScanPart, name: &[u8], data: &[u8], kind: u8) {
        unsafe {
            *self.meta.as_ptr().cast_mut().add(idx) = meta;
            *self.data_kind.as_ptr().cast_mut().add(idx) = kind;
            *self.name_off.as_ptr().cast_mut().add(idx) = part.names.len() as u32;
            *self.name_len.as_ptr().cast_mut().add(idx) = name.len() as u16;
            *self.runlist_off.as_ptr().cast_mut().add(idx) = part.runlists.len() as u32;
            *self.runlist_len.as_ptr().cast_mut().add(idx) = data.len() as u32;
        }
        parent[idx] = parent_ref;
        part.names.extend_from_slice(name);
        part.runlists.extend_from_slice(data);
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
fn find_data_size(record: &[u8]) -> u64 {
    match find_attribute(record, NTFS_ATTR_DATA, None) {
        Some((true,  attr)) => read_u32_le(attr, NTFS_ATTR_RES_VALUE_LEN_OFFSET) as u64,
        Some((false, attr)) if attr.len() >= 56 => u64::from_le_bytes(attr[48..56].try_into().unwrap()),
        _ => 0,
    }
}

fn find_best_file_name(record: &[u8]) -> Option<(u64, &[u8])> {
    let raw = record.get(NTFS_MFT_RECORD_ATTRS_OFFSET..NTFS_MFT_RECORD_ATTRS_OFFSET + 2)?;
    let mut offset = u16::from_le_bytes(raw.try_into().ok()?) as usize;
    let mut best: Option<(u8, u64, &[u8])> = None;

    loop {
        if offset + 8 > record.len() { break; }
        let a_type = read_u32_le(record, offset);
        if a_type == NTFS_ATTR_END || a_type == 0 { break; }

        let a_len = read_u32_le(record, offset + 4) as usize;
        if a_len < 8 || offset + a_len > record.len() { break; }

        if a_type == NTFS_ATTR_FILE_NAME {
            let attr = &record[offset..offset + a_len];
            if attr.get(NTFS_ATTR_NON_RESIDENT_OFFSET) == Some(&0) {
                let val_off = read_u16_le(attr, NTFS_ATTR_RES_VALUE_OFF_OFFSET) as usize;
                let val_len = read_u32_le(attr, NTFS_ATTR_RES_VALUE_LEN_OFFSET) as usize;
                let end = (val_off + val_len).min(attr.len());

                if val_off + NTFS_FN_NAME_OFFSET + 2 <= end {
                    let value = &attr[val_off..end];
                    let parent_ref = u64::from_le_bytes(value[0..8].try_into().unwrap());
                    let namespace = value[NTFS_FN_NAMESPACE_OFFSET];
                    let name_len_chars = value[NTFS_FN_NAME_LEN_OFFSET] as usize;
                    let name_end = NTFS_FN_NAME_OFFSET + name_len_chars * 2;

                    if name_len_chars > 0 && name_end <= value.len() {
                        let rank = if namespace == 2 { 0 } else { 1 };
                        if best.map_or(true, |(r, _, _)| rank > r) {
                            best = Some((rank, parent_ref, &value[NTFS_FN_NAME_OFFSET..name_end]));
                        }
                    }
                }
            }
        }

        offset += a_len;
    }

    best.map(|(_, parent_ref, name)| (parent_ref, name))
}

fn parse_mft_record_full(
    record: &[u8],
    record_num: u64,
    tree: &NtfsTree,
    parent: &mut [u64],
    part: &mut ScanPart,
) -> io::Result<()> {
    if record.len() < 48 {
        return Ok(());
    }

    let flags = u16::from_le_bytes(
        record[NTFS_MFT_RECORD_FLAGS_OFFSET..NTFS_MFT_RECORD_FLAGS_OFFSET + 2].try_into().unwrap()
    );
    if flags & NTFS_MFT_RECORD_FLAG_IN_USE == 0 {
        return Ok(());
    }

    const BASE_RECORD_REF_OFFSET: usize = 0x20;
    if record.len() >= BASE_RECORD_REF_OFFSET + 8 {
        let base_ref = u64::from_le_bytes(
            record[BASE_RECORD_REF_OFFSET..BASE_RECORD_REF_OFFSET + 8].try_into().unwrap()
        );
        if base_ref & 0x0000_FFFF_FFFF_FFFF != 0 {
            return Ok(());
        }
    }

    let mut mtime_sec = 0i64;
    if let Some((true, si)) = find_attribute(record, NTFS_ATTR_STANDARD_INFORMATION, None) {
        let val_off = read_u16_le(si, NTFS_ATTR_RES_VALUE_OFF_OFFSET) as usize;
        if val_off + NTFS_SI_MTIME_OFFSET + 8 <= si.len() {
            let ft = u64::from_le_bytes(
                si[val_off + NTFS_SI_MTIME_OFFSET..val_off + NTFS_SI_MTIME_OFFSET + 8].try_into().unwrap()
            );
            mtime_sec = filetime_to_unix(ft);
        }
    }

    let size = find_data_size(record);
    let idx = record_num as usize;
    if idx >= tree.capacity() {
        return Ok(());
    }

    let (parent_ref, name_utf16) = find_best_file_name(record).unwrap_or((0, &[][..]));
    let parent_ref = parent_ref & 0x0000_FFFF_FFFF_FFFF;

    let mut utf16: SmallVec<[u16; 64]> = SmallVec::new();
    utf16.extend(name_utf16.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])));
    let name = String::from_utf16_lossy(&utf16);
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(255);
    let name = &name_bytes[..name_len];

    let (kind, data): (u8, &[u8]) = match find_attribute(record, NTFS_ATTR_DATA, None) {
        Some((true, attr)) => {
            let value_len = read_u32_le(attr, NTFS_ATTR_RES_VALUE_LEN_OFFSET) as usize;
            let value_off = read_u16_le(attr, NTFS_ATTR_RES_VALUE_OFF_OFFSET) as usize;
            let end = (value_off + value_len).min(attr.len());
            if value_off < end {
                (DATA_RESIDENT, &attr[value_off..end])
            } else {
                (DATA_NONE, &[][..])
            }
        }
        Some((false, attr)) if attr.len() >= 34 => {
            let runlist_off = read_u16_le(attr, 32) as usize;
            if runlist_off < attr.len() {
                (DATA_NONRESIDENT, &attr[runlist_off..])
            } else {
                (DATA_NONE, &[][..])
            }
        }
        _ => (DATA_NONE, &[][..]),
    };

    tree.write_slot(
        idx,
        RecordMeta { flags, size, mtime_sec },
        parent_ref,
        parent,
        part,
        name,
        data,
        kind,
    );
    Ok(())
}

#[inline]
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

fn decode_runlist(attr_slice: &[u8], _sb: &NtfsSuperBlock) -> io::Result<SmallVec<[NtfsExtent; 8]>> {
    if attr_slice.len() < 34 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Attr slice too short"));
    }

    let runlist_off = u16::from_le_bytes(attr_slice[32..34].try_into().unwrap()) as usize;
    if runlist_off >= attr_slice.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Runlist offset out of range"));
    }

    decode_runlist_bytes(&attr_slice[runlist_off..])
}

fn decode_runlist_bytes(runlist: &[u8]) -> io::Result<SmallVec<[NtfsExtent; 8]>> {
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
            u64::MAX
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
    let records_per_cluster = cluster_size / mft_record_size;
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

#[inline]
fn run_record_span(run: &NtfsExtent, sb: &NtfsSuperBlock) -> (u64, u64) {
    let rec_size = sb.mft_record_size as u64;
    let cluster_size = sb.cluster_size as u64;
    let rpc = (cluster_size / rec_size).max(1);
    let first = run.vcn * rpc;
    let recs = (run.len * cluster_size) / rec_size;
    (first, first + recs)
}

#[cfg(windows)]
fn scan_read_chunk(
    file: &File,
    chunk: &mut crate::util::AlignedBuf,
    to_read: usize,
    offset: u64,
) -> io::Result<(usize, usize)> {
    use std::os::windows::fs::FileExt;

    let sector = crate::util::sector_size();
    let aligned_offset = offset & !(sector - 1);
    let prefix = (offset - aligned_offset) as usize;
    let aligned_len = (prefix + to_read + sector as usize - 1) & !(sector as usize - 1);
    chunk.ensure_len(aligned_len);

    let n = match file.seek_read(&mut chunk.as_mut_slice()[..aligned_len], aligned_offset) {
        Ok(n) => n,
        Err(e) if e.raw_os_error() == Some(87) => {
            let shrunk = (prefix + to_read + sector as usize - 1) & !(sector as usize - 1);
            if shrunk == 0 {
                return Ok((prefix, 0));
            }
            chunk.ensure_len(shrunk);
            file.seek_read(&mut chunk.as_mut_slice()[..shrunk], aligned_offset)?
        }
        Err(e) => return Err(e),
    };
    Ok((prefix, n.saturating_sub(prefix).min(to_read)))
}

#[cfg(not(windows))]
fn scan_read_chunk(
    file: &File,
    chunk: &mut Vec<u8>,
    to_read: usize,
    offset: u64,
) -> io::Result<(usize, usize)> {
    if chunk.len() < to_read {
        chunk.resize(to_read, 0);
    }
    let n = crate::util::read_at_offset(file, &mut chunk[..to_read], offset)?;
    Ok((0, n))
}
