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

use std::path::Path;

use ignore::gitignore::{Gitignore, GitignoreBuilder};
pub use imp::*;

use crate::GitignoreFrame;


