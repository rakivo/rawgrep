use std::{fs::File, io, sync::Arc};

use smallvec::SmallVec;

#[inline]
pub fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset+4].try_into().unwrap())
}

#[inline]
pub fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset+2].try_into().unwrap())
}

#[inline]
pub fn read_at_offset(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    #[cfg(unix)] {
        use std::os::unix::fs::FileExt;
        file.read_at(buf, offset)
    }

    #[cfg(windows)] {
        use std::os::windows::fs::FileExt;

        const SECTOR: u64 = 512;

        let aligned_offset = offset & !(SECTOR - 1);
        let prefix = (offset - aligned_offset) as usize;
        if prefix == 0 && buf.len() % SECTOR as usize == 0 {
            // Already aligned, read directly
            return file.seek_read(buf, offset);
        }

        // Unaligned, probably never would happen but for @Robustness,
        // read into a sector-aligned temp buffer and copy out.
        let aligned_len = ((prefix + buf.len()) + SECTOR as usize - 1) & !(SECTOR as usize - 1);
        let mut tmp = vec![0u8; aligned_len];
        let n = file.seek_read(&mut tmp, aligned_offset)?;

        let available = n.saturating_sub(prefix);
        let to_copy = available.min(buf.len());
        buf[..to_copy].copy_from_slice(&tmp[prefix..prefix + to_copy]);

        Ok(to_copy)
    }
}

#[inline(always)]
pub const fn is_dot_entry(name: &[u8]) -> bool {
    name.len() == 1 && name[0] == b'.' ||
    name.len() == 2 && name[0] == b'.' && name[1] == b'.'
}

#[inline(always)]
pub const fn is_common_skip_dir(dir: &[u8]) -> bool {
    matches!{
        dir,
        b"node_modules" | b"target" | b".git" | b".hg" | b".svn" |
        b"dist" | b"build" | b"out" | b"bin" | b"tmp" | b".cache"
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

/// `std::vec::Vec::into_boxed_slice` takes CPU cycles to shrink
/// itself to the `.len`, this function does not shrink and saves
/// us some time
#[inline]
#[must_use]
pub fn vec_into_arc_slice_noshrink<T>(mut v: Vec<T>) -> Arc<[T]> {
    let len = v.len();
    let ptr = v.as_mut_ptr();

    let boxed_slice = unsafe {
        // SAFETY: We use the raw parts from Vec to reconstruct a Box<[T]>.
        // This transfers ownership of the heap memory from Vec to Box.
        // This is safe ONLY because we are immediately calling core::mem::forget(v) below,
        // preventing the original Vec from attempting to free the memory.
        let slice_ptr = core::slice::from_raw_parts_mut(ptr, len);
        Box::from_raw(slice_ptr)
    };

    core::mem::forget(v);

    Arc::from(boxed_slice)
}

#[inline]
#[must_use]
pub fn smallvec_into_arc_slice_noshrink<A, T>(mut v: SmallVec<A>) -> Arc<[T]>
where
    A: smallvec::Array<Item = T>,
{
    if v.spilled() {
        // SAFETY: we are taking ownership of the allocated buffer.
        let boxed = unsafe {
            Box::from_raw(v.as_mut_slice())
        };
        core::mem::forget(v);
        Arc::from(boxed)
    } else {
        vec_into_arc_slice_noshrink(v.into_vec())
    }
}

#[inline]
#[must_use]
pub fn smallvec_into_boxed_slice_noshrink<A, T>(mut v: SmallVec<A>) -> Box<[T]>
where
    A: smallvec::Array<Item = T>,
{
    if v.spilled() {
        // SAFETY: we are taking ownership of the allocated buffer.
        let boxed = unsafe {
            Box::from_raw(v.as_mut_slice())
        };
        core::mem::forget(v);
        boxed
    } else {
        vec_into_boxed_slice_noshrink(v.into_vec())
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

#[macro_export]
macro_rules! ceprintln {
    ($color:expr, $($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            eprintln!(concat!("\x1b[", "{}", "{}", "\x1b[0m"), $color, format_args!($($arg)*));
        } else {
            eprintln!($($arg)*);
        }
    }};
}

#[macro_export]
macro_rules! ceprint {
    ($color:expr, $($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            eprint!(concat!("\x1b[", "{}", "{}", "\x1b[0m"), $color, format_args!($($arg)*));
        } else {
            eprint!($($arg)*);
        }
    }};
}

#[macro_export]
macro_rules! eprintln_red {
    ($($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            eprintln!(concat!("\x1b[1;31m", "{}", "\x1b[0m"), format_args!($($arg)*));
        } else {
            eprintln!($($arg)*);
        }
    }};
}

#[macro_export]
macro_rules! eprintln_green {
    ($($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            eprintln!(concat!("\x1b[1;32m", "{}", "\x1b[0m"), format_args!($($arg)*));
        } else {
            eprintln!($($arg)*);
        }
    }};
}

#[macro_export]
macro_rules! eprintln_blue {
    ($($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            eprintln!(concat!("\x1b[1;34m", "{}", "\x1b[0m"), format_args!($($arg)*));
        } else {
            eprintln!($($arg)*);
        }
    }};
}

#[macro_export]
macro_rules! eprintln_cyan {
    ($($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            eprintln!(concat!("\x1b[1;36m", "{}", "\x1b[0m"), format_args!($($arg)*));
        } else {
            eprintln!($($arg)*);
        }
    }};
}

// eprint! versions (no newline)
#[macro_export]
macro_rules! eprint_red {
    ($($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            eprint!(concat!("\x1b[1;31m", "{}", "\x1b[0m"), format_args!($($arg)*));
        } else {
            eprint!($($arg)*);
        }
    }};
}

#[macro_export]
macro_rules! eprint_green {
    ($($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            eprint!(concat!("\x1b[1;32m", "{}", "\x1b[0m"), format_args!($($arg)*));
        } else {
            eprint!($($arg)*);
        }
    }};
}

#[macro_export]
macro_rules! eprint_blue {
    ($($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            eprint!(concat!("\x1b[1;34m", "{}", "\x1b[0m"), format_args!($($arg)*));
        } else {
            eprint!($($arg)*);
        }
    }};
}

#[macro_export]
macro_rules! eprint_cyan {
    ($($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            eprint!(concat!("\x1b[1;36m", "{}", "\x1b[0m"), format_args!($($arg)*));
        } else {
            eprint!($($arg)*);
        }
    }};
}

// writeln! versions
#[macro_export]
macro_rules! cwriteln {
    ($writer:expr, $color:expr, $($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            writeln!($writer, concat!("\x1b[", "{}", "{}", "\x1b[0m"), $color, format_args!($($arg)*))
        } else {
            writeln!($writer, $($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! cwrite {
    ($writer:expr, $color:expr, $($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            write!($writer, concat!("\x1b[", "{}", "{}", "\x1b[0m"), $color, format_args!($($arg)*))
        } else {
            write!($writer, $($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! writeln_red {
    ($writer:expr, $($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            writeln!($writer, concat!("\x1b[1;31m", "{}", "\x1b[0m"), format_args!($($arg)*))
        } else {
            writeln!($writer, $($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! writeln_green {
    ($writer:expr, $($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            writeln!($writer, concat!("\x1b[1;32m", "{}", "\x1b[0m"), format_args!($($arg)*))
        } else {
            writeln!($writer, $($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! writeln_blue {
    ($writer:expr, $($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            writeln!($writer, concat!("\x1b[1;34m", "{}", "\x1b[0m"), format_args!($($arg)*))
        } else {
            writeln!($writer, $($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! writeln_cyan {
    ($writer:expr, $($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            writeln!($writer, concat!("\x1b[1;36m", "{}", "\x1b[0m"), format_args!($($arg)*))
        } else {
            writeln!($writer, $($arg)*)
        }
    }};
}

// write! versions (no newline)
#[macro_export]
macro_rules! write_red {
    ($writer:expr, $($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            write!($writer, concat!("\x1b[1;31m", "{}", "\x1b[0m"), format_args!($($arg)*))
        } else {
            write!($writer, $($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! write_green {
    ($writer:expr, $($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            write!($writer, concat!("\x1b[1;32m", "{}", "\x1b[0m"), format_args!($($arg)*))
        } else {
            write!($writer, $($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! write_blue {
    ($writer:expr, $($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            write!($writer, concat!("\x1b[1;34m", "{}", "\x1b[0m"), format_args!($($arg)*))
        } else {
            write!($writer, $($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! write_cyan {
    ($writer:expr, $($arg:tt)*) => {{
        if $crate::cli::should_enable_ansi_coloring() {
            write!($writer, concat!("\x1b[1;36m", "{}", "\x1b[0m"), format_args!($($arg)*))
        } else {
            write!($writer, $($arg)*)
        }
    }};
}
