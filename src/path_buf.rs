use std::{ops::{Deref, DerefMut}, path::{MAIN_SEPARATOR, MAIN_SEPARATOR_STR}};

use smallvec::SmallVec;

pub struct SmallPathBuf<const N: usize = 0x400> {
    buf: SmallVec<[u8; N]>,
}

impl<const N: usize> Default for SmallPathBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for SmallPathBuf<N> {
    type Target = SmallVec<[u8; N]>;
    #[inline(always)]
    fn deref(&self) -> &Self::Target { &self.buf }
}

impl<const N: usize> DerefMut for SmallPathBuf<N> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.buf }
}

#[allow(dead_code)]
impl<const N: usize> SmallPathBuf<N> {
    #[inline(always)]
    pub fn new() -> Self {
        Self { buf: SmallVec::with_capacity(N) }
    }

    #[inline(always)]
    pub fn from_bytes(s: &[u8]) -> Self {
        let mut pb = Self::new();
        pb.extend_from_slice(s);
        pb
    }

    /// Returns a new FixedPathBuf with the parent directory path.
    /// If path is "/" or empty, returns empty path.
    /// Examples:
    ///   "/usr/bin" -> "/usr"
    ///   "/usr" -> "/"
    ///   "/" -> ""
    ///   "foo/bar" -> "foo"
    #[inline]
    pub fn parent(&self) -> Self {
        if self.is_empty() {
            return Self::new();
        }

        // Find last '/'
        let bytes = self.as_slice();

        // Handle trailing slash: "/usr/bin/" -> find slash before the trailing one
        let search_end = if bytes[self.len() - 1] == MAIN_SEPARATOR as _ {
            self.len().saturating_sub(1)
        } else {
            self.len()
        };

        if search_end == 0 {
            return Self::new();
        }

        // Search backwards for '/'
        for i in (0..search_end).rev() {
            if bytes[i] == MAIN_SEPARATOR as _ {
                // Found a slash
                if i == 0 {
                    // Path was "/something", parent is "/"
                    return Self::from_bytes(MAIN_SEPARATOR_STR.as_bytes())
                } else {
                    // Path was "/foo/bar", parent is "/foo"
                    return Self::from_bytes(&bytes[..i]);
                }
            }
        }

        // No slash found, it's a relative path like "foo" or "foo/bar"
        // Parent of relative path with no slashes is empty
        Self::new()
    }

    /// Returns the last component of the path (filename or last directory)
    #[inline]
    pub fn file_name(&self) -> &[u8] {
        if self.is_empty() {
            return &[];
        }

        let bytes = self.as_slice();

        // Skip trailing slashes
        let mut end = self.len();
        while end > 0 && bytes[end - 1] == MAIN_SEPARATOR as _ {
            end -= 1;
        }

        if end == 0 {
            return MAIN_SEPARATOR_STR.as_bytes();
        }

        // Find last slash before the name
        for i in (0..end).rev() {
            if bytes[i] == MAIN_SEPARATOR as _ {
                return &bytes[i + 1..end];
            }
        }

        // No slash found, entire path is the filename
        &bytes[..end]
    }
}
