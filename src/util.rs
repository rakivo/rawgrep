use std::sync::Arc;
use std::{fs, io};
use std::path::{Path, PathBuf};

use ignore::gitignore::{Gitignore, GitignoreBuilder};

#[inline(always)]
pub const fn is_dot_entry(name: &[u8]) -> bool {
    name.len() == 1 && name[0] == b'.' ||
    name.len() == 2 && name[0] == b'.' && name[1] == b'.'
}

#[inline(always)]
pub const fn is_common_skip_dir(dir: &[u8]) -> bool {
    matches!(dir, b"node_modules" | b"target" | b".git" | b".hg" | b".svn")
}


#[inline(always)]
pub fn is_gitignored(gi: &Gitignore, path: &Path, is_dir: bool) -> bool {
    if gi.matched(path, is_dir).is_ignore() {
        return true;
    }
    false
}

#[inline(always)]
pub fn build_gitignore(root: &Path) -> Option<Gitignore> {
    let mut builder = GitignoreBuilder::new(root);
    builder.add(root.join(".gitignore"));
    builder.build().ok()
}

#[inline(always)]
pub fn build_gitignore_from_bytes(parent_path: &Path, bytes: &[u8]) -> Gitignore {
    let mut builder = GitignoreBuilder::new(parent_path);
    for line in bytes.split(|&b| b == b'\n') {
        if let Ok(s) = std::str::from_utf8(line) {
            builder.add_line(None, s).ok();
        }
    }
    builder.build().unwrap_or_else(|_| Gitignore::empty())
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

/// Detect which partition/device a given path is mounted on
pub fn detect_partition_for_path(canonicalized_path: &Path) -> io::Result<String> {
    let mounts = fs::read_to_string("/proc/mounts")
        .or_else(|_| fs::read_to_string("/etc/mtab"))?;

    let mut best_match = None;
    let mut best_match_len = 0;

    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let device = parts[0];
        let mountpoint_escaped = parts[1];
        let fstype = parts[2];

        // Skip non-ext4 filesystems
        if fstype != "ext4" {
            continue;
        }

        // Skip virtual/pseudo filesystems (not starting with /dev/)
        if !device.starts_with("/dev/") {
            continue;
        }

        // Resolve device symlinks (e.g., /dev/disk/by-uuid/...)
        let device = fs::canonicalize(device).unwrap_or_else(|_| PathBuf::from(device));
        let device = device.to_string_lossy();

        let mountpoint = unescape_mountpoint(mountpoint_escaped);

        match fs::canonicalize(&mountpoint) {
            Ok(mount_path) => {
                // Check if our path is under this mountpoint
                if canonicalized_path.starts_with(&mount_path) {
                    let mount_len = mount_path.as_os_str().len();
                    // Find the longest matching mountpoint (most specific)
                    if mount_len > best_match_len {
                        best_match_len = mount_len;
                        best_match = Some(device.to_string());
                    }
                }
            }
            Err(_) => {
                // If canonicalize fails, try direct string comparison as fallback
                let mount_path = PathBuf::from(&mountpoint);
                if canonicalized_path.starts_with(&mount_path) {
                    let mount_len = mount_path.as_os_str().len();
                    if mount_len > best_match_len {
                        best_match_len = mount_len;
                        best_match = Some(device.to_string());
                    }
                }
            }
        }
    }

    best_match.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!{
                "could not find ext4 partition for path: {}",
                canonicalized_path.display()
            }
        )
    })
}

/// Unescape mountpoint from /proc/mounts format
/// Spaces are encoded as \040, tabs as \011, newlines as \012, backslashes as \134
fn unescape_mountpoint(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            // Read next 3 characters as octal
            let octal: String = chars.by_ref().take(3).collect();
            if let Ok(byte) = u8::from_str_radix(&octal, 8) {
                result.push(byte as char);
            } else {
                // If parsing fails, just keep the backslash
                result.push('\\');
                result.push_str(&octal);
            }
        } else {
            result.push(ch);
        }
    }

    result
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
        Box::from_raw(core::slice::from_raw_parts_mut(ptr, len))
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
#[cfg(feature = "use_nightly")]
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
#[cfg(not(feature = "use_nightly"))]
mod imp {
    #[inline(always)]
    pub const fn likely(b: bool) -> bool { b }

    #[inline(always)]
    pub const fn unlikely(b: bool) -> bool { b }
}

pub use imp::*;
use smallvec::SmallVec;

