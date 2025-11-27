#[derive(Clone)]
pub struct FixedPathBuf<const N: usize = 0x1000> {
    buf: [u8; N],
    len: usize,
}

#[allow(dead_code)]
impl<const N: usize> FixedPathBuf<N> {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    #[inline(always)]
    pub fn from_bytes(s: &[u8]) -> Self {
        let mut pb = Self::new();
        pb.extend_from_slice(s);
        pb
    }

    #[inline(always)]
    pub fn push(&mut self, byte: u8) {
        debug_assert!(self.len < N);
        self.buf[self.len] = byte;
        self.len += 1;
    }

    #[inline(always)]
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        let copy_len = slice.len();
        debug_assert!(copy_len + self.len < N);
        self.buf[self.len..self.len + copy_len].copy_from_slice(&slice[..copy_len]);
        self.len += copy_len;
    }

    #[inline(always)]
    pub fn truncate(&mut self, len: usize) {
        self.len = len;
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        N
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
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
        if self.len == 0 {
            return Self::new();
        }

        // Find last '/'
        let bytes = self.as_bytes();

        // Handle trailing slash: "/usr/bin/" -> find slash before the trailing one
        let search_end = if bytes[self.len - 1] == b'/' {
            self.len.saturating_sub(1)
        } else {
            self.len
        };

        if search_end == 0 {
            return Self::new();
        }

        // Search backwards for '/'
        for i in (0..search_end).rev() {
            if bytes[i] == b'/' {
                // Found a slash
                if i == 0 {
                    // Path was "/something", parent is "/"
                    return Self::from_bytes(b"/");
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
        if self.len == 0 {
            return &[];
        }

        let bytes = self.as_bytes();

        // Skip trailing slashes
        let mut end = self.len;
        while end > 0 && bytes[end - 1] == b'/' {
            end -= 1;
        }

        if end == 0 {
            return b"/";
        }

        // Find last slash before the name
        for i in (0..end).rev() {
            if bytes[i] == b'/' {
                return &bytes[i + 1..end];
            }
        }

        // No slash found, entire path is the filename
        &bytes[..end]
    }
}

