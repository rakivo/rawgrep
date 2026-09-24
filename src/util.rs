#[cfg(windows)]
use std::sync::OnceLock;
use std::{fs::File, io};

#[cfg(feature = "enable-bytemuck-checks")]
#[inline(always)]
pub fn try_from_bytes<T: bytemuck::AnyBitPattern>(
    s: &[u8],
) -> Result<&T, bytemuck::PodCastError> {
    bytemuck::try_from_bytes(s)
}

#[cfg(not(feature = "enable-bytemuck-checks"))]
#[inline(always)]
#[allow(clippy::result_unit_err)]
pub fn try_from_bytes<T>(s: &[u8]) -> Result<&T, ()> {
    unsafe {
        Ok(&*(s.as_ptr() as *const T))
    }
}

#[cfg(feature = "enable-bytemuck-checks")]
#[inline(always)]
pub fn cast_slice<A: bytemuck::NoUninit, B: bytemuck::AnyBitPattern>(
    a: &[A],
) -> &[B] {
    bytemuck::cast_slice(a)
}

#[cfg(not(feature = "enable-bytemuck-checks"))]
#[inline(always)]
pub fn cast_slice<A, B>(a: &[A]) -> &[B] {
    if size_of::<B>() == size_of::<A>() {
        unsafe { core::slice::from_raw_parts(a.as_ptr() as *const B, a.len()) }
    } else {
        let new_len = if size_of::<B>() != 0 {
            size_of_val::<[A]>(a) / size_of::<B>()
        } else {
            0
        };

        unsafe { core::slice::from_raw_parts(a.as_ptr() as *const B, new_len) }
    }
}

#[inline(always)]
pub fn read_u8_unaligned(data: &[u8], offset: usize) -> u8 {
    unsafe { data.as_ptr().add(offset).read_unaligned() }
}

#[inline(always)]
pub fn read_u16_unaligned_le(data: &[u8], offset: usize) -> u16 {
    unsafe { (data.as_ptr().add(offset) as *const u16).read_unaligned().to_le() }
}

#[inline(always)]
pub fn read_u32_unaligned_le(data: &[u8], offset: usize) -> u32 {
    unsafe { (data.as_ptr().add(offset) as *const u32).read_unaligned().to_le() }
}

#[inline(always)]
pub fn read_u64_as_u32_and_u16_unaligned_le(data: &[u8], offset: usize) -> (u32, u16) {
    let value = unsafe {
        (data.as_ptr().add(offset) as *const u64)
            .read_unaligned()
            .to_le()
    };

    (value as u32, (value >> 32) as u16)
}

#[inline(always)]
pub fn read_u64_unaligned_le(data: &[u8], offset: usize) -> u64 {
    unsafe { (data.as_ptr().add(offset) as *const u64).read_unaligned().to_le() }
}

#[inline(always)]
pub fn read_u16_unaligned_be(data: &[u8], offset: usize) -> u16 {
    unsafe { (data.as_ptr().add(offset) as *const u16).read_unaligned().to_be() }
}

#[inline(always)]
pub fn read_u32_unaligned_be(data: &[u8], offset: usize) -> u32 {
    unsafe { (data.as_ptr().add(offset) as *const u32).read_unaligned().to_be() }
}

#[inline(always)]
pub fn read_u64_unaligned_be(data: &[u8], offset: usize) -> u64 {
    unsafe { (data.as_ptr().add(offset) as *const u64).read_unaligned().to_be() }
}

#[inline]
pub fn extend_le(out: &mut Vec<u8>, v: &[impl Copy]) {
    #[cfg(target_endian = "little")]
    out.extend_from_slice(unsafe {
        std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v))
    });

    #[cfg(not(target_endian = "little"))]
    for x in v { out.extend_from_slice(&x.to_le_bytes()); }
}

#[inline]
pub fn read_le(bytes: &[u8]) -> Vec<u64> {          // bytes.len() % 8 == 0
    let n = bytes.len() / 8;

    #[cfg(target_endian = "little")] {
        let mut v = Vec::<u64>::with_capacity(n);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), v.as_mut_ptr() as *mut u8, n * 8);
            v.set_len(n);
        }
        v
    }

    #[cfg(not(target_endian = "little"))]
    { bytes.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect() }
}

#[cfg(windows)]
pub static SECTOR_SIZE: OnceLock<u64> = OnceLock::new();

#[cfg(windows)]
const DEFAULT_SECTOR_SIZE: u64 = 512;

#[inline]
pub fn read_at_offset(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)] {
        use std::os::fd::AsRawFd;

        let fd = file.as_raw_fd();
        let ret = unsafe {
            libc::syscall(
                libc::SYS_pread64,
                fd,
                buf.as_mut_ptr(),
                buf.len(),
                offset as i64,
            )
        };

        if likely(ret >= 0) {
            Ok(ret as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(windows)] {
        use std::os::windows::fs::FileExt;

        let sector_size = SECTOR_SIZE.get().copied().unwrap_or(DEFAULT_SECTOR_SIZE);

        let aligned_offset = offset & !(sector_size - 1);
        let prefix = (offset - aligned_offset) as usize;
        if prefix == 0 && buf.len() % sector_size as usize == 0 {
            // Already aligned, read directly
            return file.seek_read(buf, offset);
        }

        // Unaligned, probably never would happen but for @Robustness,
        // read into a sector-aligned temp buffer and copy out.
        let aligned_len = ((prefix + buf.len()) + sector_size as usize - 1) & !(sector_size as usize - 1);
        let mut tmp = vec![0u8; aligned_len];  // @Heap @Heap @Heap
        let n = file.seek_read(&mut tmp, aligned_offset)?;

        let available = n.saturating_sub(prefix);
        let to_copy = available.min(buf.len());
        buf[..to_copy].copy_from_slice(&tmp[prefix..prefix + to_copy]);

        Ok(to_copy)
    }
}

#[inline(always)]
pub fn prefetch_read<T>(ptr: *const T) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::x86_64::_mm_prefetch(ptr as *const i8, std::arch::x86_64::_MM_HINT_T0);
    }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        std::arch::asm!("prfm pldl1keep, [{0}]", in(reg) ptr, options(readonly, nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn truncate_utf8(s: &[u8], max: usize) -> &[u8] {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && (s[end] & 0b1100_0000) == 0b1000_0000 {
        end -= 1;
    }
    &s[..end]
}

#[inline]
pub fn format_bytes(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;

    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.2} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

/// `std::vec::Vec::into_boxed_slice` takes CPU cycles to shrink
/// itself to the `.len`, this function does not shrink and saves
/// us some CPU cycles
#[inline]
#[must_use]
pub fn vec_into_boxed_slice_noshrink<T>(mut v: Vec<T>) -> Box<[T]> {
    let len = v.len();
    let ptr = v.as_mut_ptr();

    core::mem::forget(v);

    unsafe {
        Box::from_raw(core::ptr::slice_from_raw_parts_mut(ptr, len))
    }
}

#[cfg(target_os = "macos")]
pub fn resolve_apfs_physical_store(virtual_device: &str) -> Result<String, Error> {
    let disk_id = virtual_device.trim_start_matches("/dev/");

    let output = std::process::Command::new("diskutil")
        .args(["info", "-plist", disk_id])
        .output()
        .map_err(Error::Io)?;

    if !output.status.success() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "diskutil info failed",
        )));
    }

    let stdout    = String::from_utf8_lossy(&output.stdout);
    let key       = "<key>APFSPhysicalStore</key>";
    let val_open  = "<string>";
    let val_close = "</string>";

    if let Some(kp) = stdout.find(key) {
        let after_key = &stdout[kp + key.len()..];
        if let Some(op) = after_key.find(val_open) {
            let after_open = &after_key[op + val_open.len()..];
            if let Some(cp) = after_open.find(val_close) {
                return Ok(format!("/dev/{}", &after_open[..cp]));
            }
        }
    }

    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "APFSPhysicalStore not found in diskutil output",
    )))
}

//
// CPU affinity helpers - gdt-cpus has bugs on macOS, so we provide fallbacks
//

/// Get number of physical cores, falling back to provided default
#[inline]
pub fn num_physical_cores_or(fallback: usize) -> usize {
    #[cfg(not(target_os = "macos"))]
    {
        gdt_cpus::num_physical_cores().unwrap_or(fallback)
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: use sysctl to get physical core count
        macos_num_physical_cores().unwrap_or(fallback)
    }
}

/// Pin current thread to a specific core (best-effort, ignores failures)
#[inline]
pub fn pin_thread_to_core(core_id: usize) {
    #[cfg(not(target_os = "macos"))]
    {
        _ = gdt_cpus::pin_thread_to_core(core_id);
    }
    #[cfg(target_os = "macos")]
    {
        // macOS doesn't support thread-to-core pinning via public APIs
        // Thread affinity hints are handled by the kernel
        _ = core_id;
    }
}

#[cfg(target_os = "macos")]
pub fn macos_num_physical_cores() -> Option<usize> {
    // sysctl hw.physicalcpu
    let mut count: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();

    let ret = unsafe {
        libc::sysctlbyname(
            c"hw.physicalcpu".as_ptr(),
            &mut count as *mut _ as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };

    if ret == 0 && count > 0 {
        Some(count as usize)
    } else {
        None
    }
}

// ---------------
// Nightly implementation
// ----------------------
#[cfg(all(feature = "use_nightly", nightly))]
mod imp {
    use core::intrinsics;

    #[inline(always)]
    pub const fn likely(b: bool) -> bool {
        intrinsics::likely(b)
    }

    #[inline(always)]
    pub const fn unlikely(b: bool) -> bool {
        intrinsics::unlikely(b)
    }
}

// ---------------
// Stable fallback
// ---------------
#[cfg(not(all(feature = "use_nightly", nightly)))]
mod imp {
    #[inline(always)]
    pub const fn likely(b: bool) -> bool { b }

    #[inline(always)]
    pub const fn unlikely(b: bool) -> bool { b }
}

pub use imp::*;

/// Appends POD data to a Vec as raw bytes without bounds checks
#[macro_export]
macro_rules! batch_extend_pod {
    ($buf:expr, [$($slice:expr),+ $(,)?]) => {{
        let buf   = &mut $buf;
        let start = buf.len();
        let extra = 0 $(+ std::mem::size_of_val($slice))+;

        buf.reserve(extra);

        // SAFETY: 'buf' was just reserved for exactly 'extra' more bytes, each slice's
        // raw bytes are memcpy'd in turn into that region with 'p' advanced by exactly
        // that slice's length, so by 'set_len', all of 'start..start+extra' is written
        // and nothing past it is touched.
        #[allow(unused_assignments)]
        unsafe {
            let mut p = buf.as_mut_ptr().add(start);
            $(
                let n = std::mem::size_of_val($slice);
                std::ptr::copy_nonoverlapping($slice.as_ptr() as *const u8, p, n);
                p = p.add(n);
            )+
            buf.set_len(start + extra);
        }
    }};
}

/// A 'Vec<u8>' append cursor for hand written loops that write a variable, runtime known
/// number of pieces.
///
/// Caller reserves an exact-or-upper-bound number of bytes once up front ('Vec::reserve'),
/// wraps the vec in 'RawAppend::new', calls 'push'/'extend' any number of times, each one
/// an unchecked pointer write, no per-call capacity check, then calls 'finish()' exactly
/// once, which is the only place 'set_len' happens.
pub(crate) struct RawAppend<'a> {
    buf:     &'a mut Vec<u8>,
    ptr:     *mut u8,
    written: usize,
}

#[allow(unsafe_op_in_unsafe_fn)]
impl<'a> RawAppend<'a> {
    #[inline(always)]
    pub(crate) fn new(buf: &'a mut Vec<u8>) -> Self {
        // SAFETY: offsetting to exactly buf.len() from as_mut_ptr() always lands within
        // the allocation.
        let ptr = unsafe { buf.as_mut_ptr().add(buf.len()) };
        RawAppend { buf, ptr, written: 0 }
    }

    #[inline(always)]
    pub(crate) unsafe fn push(&mut self, byte: u8) {
        self.ptr.write(byte);
        self.ptr = self.ptr.add(1);
        self.written += 1;
    }

    #[inline(always)]
    pub(crate) unsafe fn extend(&mut self, bytes: &[u8]) {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr, bytes.len());
        self.ptr = self.ptr.add(bytes.len());
        self.written += bytes.len();
    }

    #[inline(always)]
    pub(crate) fn finish(self) {
        let new_len = self.buf.len() + self.written;
        // SAFETY: caller's contract (see struct docs) guarantees 'written' bytes were
        // actually written into the reserved region starting at the old length.
        unsafe { self.buf.set_len(new_len); }
    }
}

#[inline]
pub fn mmap_populate(path: &std::path::Path) -> Option<memmap2::Mmap> {
    let file = File::open(path).ok()?;

    let mut opts = memmap2::MmapOptions::new();
    opts.populate();

    unsafe { opts.map(&file).ok() }
}
