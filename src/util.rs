use crate::GitignoreFrame;

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
pub fn is_gitignored(frames: &[GitignoreFrame], path: &Path, is_dir: bool) -> bool {
    for frame in frames.iter().rev() {
        if frame.matcher.matched(path, is_dir).is_ignore() {
            return true;
        }
    }
    false
}

#[inline(always)]
pub fn build_gitignore(root: &Path) -> Gitignore {
    let mut builder = GitignoreBuilder::new(root);
    builder.add(root.join(".gitignore"));
    builder.build().unwrap()
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

        let mountpoint = unescape_mountpoint(mountpoint_escaped);

        match fs::canonicalize(&mountpoint) {
            Ok(mount_path) => {
                // Check if our path is under this mountpoint
                if canonicalized_path.starts_with(&mount_path) {
                    let mount_len = mount_path.as_os_str().len();
                    // Find the longest matching mountpoint (most specific)
                    if mount_len > best_match_len {
                        best_match_len = mount_len;
                        best_match = Some(device.to_owned());
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
                        best_match = Some(device.to_owned());
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
