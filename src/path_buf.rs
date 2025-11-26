use crate::util::likely;

pub struct FixedPathBuf<const N: usize = 0x1000> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> FixedPathBuf<N> {
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    #[inline]
    pub fn from_bytes(s: &[u8]) -> Self {
        let mut pb = Self::new();
        pb.extend_from_slice(s);
        pb
    }

    #[inline(always)]
    pub fn push(&mut self, byte: u8) {
        if likely(self.len < N) {
            self.buf[self.len] = byte;
            self.len += 1;
        }
    }

    #[inline(always)]
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        let copy_len = slice.len().min(N - self.len);
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
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

