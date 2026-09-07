#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Encoding { Utf32LE, Utf32BE, Utf8, Utf16LE, Utf16BE }

impl Encoding {
    /// Byte length of this encoding's BOM.
    #[inline(always)]
    pub fn bom_len(self) -> usize {
        match self {
            Encoding::Utf8                        => 3,
            Encoding::Utf16LE | Encoding::Utf16BE => 2,
            Encoding::Utf32LE | Encoding::Utf32BE => 4,
        }
    }
}

/// Encoding-specific behavior for walking a byte buffer line by line and
/// handing back valid UTF-8 to the matcher/printer.
///
/// Every codec below is a zero-sized type, so dispatching
/// through `C: LineCodec` monomorphizes down to fully specialized code
/// per encoding -- for `RawCodec` (plain bytes / UTF-8).
pub trait LineCodec {
    /// Byte width of one code unit -- also the width of a raw "\n"
    /// sequence, since a line break is always exactly one code unit.
    /// 1 for raw/UTF-8, 2 for UTF-16, 4 for UTF-32.
    const UNIT_WIDTH: usize;

    /// True when the raw bytes are already valid UTF-8 (plain bytes, or
    /// UTF-8-with-BOM once the BOM's been skipped), so lines can be
    /// matched against directly with zero copies.
    const RAW_PASSTHROUGH: bool;

    /// Exact bytes a trailing "\r" takes in this encoding. Checked
    /// against the end of every line and stripped before match/decode,
    /// so Windows CRLF sources don't leave a ^M glyph in the output.
    /// This applies to RawCodec too -- CRLF has nothing to do with
    /// which encoding the file is in.
    const CR_SUFFIX: &'static [u8];

    /// Offset of the start of the next raw "\n" sequence, scanning
    /// forward at valid code-unit boundaries.
    fn find_newline(data: &[u8]) -> Option<usize>;

    /// Offset of the start of the *last* raw "\n" sequence, scanning
    /// backward. Mirrors find_newline; used to know how much of a chunk
    /// is safe to process now vs. carry to the next call.
    fn rfind_newline(data: &[u8]) -> Option<usize>;

    /// Decode one complete raw line (no trailing newline bytes) into
    /// `dst` as UTF-8, appending. Never called when RAW_PASSTHROUGH.
    fn decode_line(raw: &[u8], dst: &mut Vec<u8>);

    #[inline(always)]
    fn strip_trailing_cr(line: &[u8]) -> &[u8] {
        let cr = Self::CR_SUFFIX;
        if line.len() >= cr.len() && &line[line.len() - cr.len()..] == cr {
            &line[..line.len() - cr.len()]
        } else {
            line
        }
    }
}

pub struct RawCodec;

impl LineCodec for RawCodec {
    const UNIT_WIDTH:      usize = 1;
    const RAW_PASSTHROUGH: bool  = true;
    const CR_SUFFIX: &'static [u8] = &[0x0D];

    #[inline(always)]
    fn find_newline(data: &[u8]) -> Option<usize> {
        memchr::memchr(b'\n', data)
    }

    #[inline(always)]
    fn rfind_newline(data: &[u8]) -> Option<usize> {
        memchr::memrchr(b'\n', data)
    }

    #[inline(always)]
    fn decode_line(_raw: &[u8], _dst: &mut Vec<u8>) {
        unsafe { std::hint::unreachable_unchecked() }
    }
}

pub struct Utf16LeCodec;

impl LineCodec for Utf16LeCodec {
    const UNIT_WIDTH:      usize = 2;
    const RAW_PASSTHROUGH: bool  = false;
    const CR_SUFFIX: &'static [u8] = &[0x0D, 0x00];

    #[inline(always)]
    fn find_newline(data: &[u8]) -> Option<usize> {
        let mut start = 0;
        loop {
            let pos = start + memchr::memmem::find(&data[start..], &[0x0A, 0x00])?;
            if pos % 2 == 0 { return Some(pos); }
            start = pos + 1;
        }
    }

    #[inline(always)]
    fn rfind_newline(data: &[u8]) -> Option<usize> {
        let mut end = data.len();
        loop {
            let pos = memchr::memmem::rfind(&data[..end], &[0x0A, 0x00])?;
            if pos % 2 == 0 { return Some(pos); }
            end = pos;
        }
    }

    #[inline(always)]
    fn decode_line(raw: &[u8], dst: &mut Vec<u8>) {
        // Single pass: copy ASCII code units directly as low bytes,
        // stop at the first non-ASCII unit, hand the remainder to the
        // slow path. Most "UTF-16" files in the wild are ASCII text
        // wearing a BOM, so the common case never touches decode_utf16.
        dst.reserve(raw.len() / 2);

        let mut i = 0;
        while i + 1 < raw.len() {
            let lo = raw[i];
            let hi = raw[i + 1];
            if hi != 0 || lo & 0x80 != 0 { break; }
            dst.push(lo);
            i += 2;
        }

        if i >= raw.len() { return; }

        let units = raw[i..].chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]]));
        let mut buf = [0u8; 4];
        for ch in std::char::decode_utf16(units) {
            let ch = ch.unwrap_or(char::REPLACEMENT_CHARACTER);
            dst.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    }
}

pub struct Utf16BeCodec;

impl LineCodec for Utf16BeCodec {
    const UNIT_WIDTH:      usize = 2;
    const RAW_PASSTHROUGH: bool  = false;
    const CR_SUFFIX: &'static [u8] = &[0x00, 0x0D];

    #[inline(always)]
    fn find_newline(data: &[u8]) -> Option<usize> {
        let mut start = 0;
        loop {
            let pos = start + memchr::memmem::find(&data[start..], &[0x00, 0x0A])?;
            if pos % 2 == 0 { return Some(pos); }
            start = pos + 1;
        }
    }

    #[inline(always)]
    fn rfind_newline(data: &[u8]) -> Option<usize> {
        let mut end = data.len();
        loop {
            let pos = memchr::memmem::rfind(&data[..end], &[0x00, 0x0A])?;
            if pos % 2 == 0 { return Some(pos); }
            end = pos;
        }
    }

    #[inline(always)]
    fn decode_line(raw: &[u8], dst: &mut Vec<u8>) {
        dst.reserve(raw.len() / 2);

        let mut i = 0;
        while i + 1 < raw.len() {
            let hi = raw[i];
            let lo = raw[i + 1];
            if hi != 0 || lo & 0x80 != 0 { break; }
            dst.push(lo);
            i += 2;
        }

        if i >= raw.len() { return; }

        let units = raw[i..].chunks_exact(2).map(|b| u16::from_be_bytes([b[0], b[1]]));
        let mut buf = [0u8; 4];
        for ch in std::char::decode_utf16(units) {
            let ch = ch.unwrap_or(char::REPLACEMENT_CHARACTER);
            dst.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    }
}

pub struct Utf32LeCodec;

impl LineCodec for Utf32LeCodec {
    const UNIT_WIDTH:      usize = 4;
    const RAW_PASSTHROUGH: bool  = false;
    const CR_SUFFIX: &'static [u8] = &[0x0D, 0x00, 0x00, 0x00];

    #[inline(always)]
    fn find_newline(data: &[u8]) -> Option<usize> {
        let mut start = 0;
        loop {
            let pos = start + memchr::memmem::find(&data[start..], &[0x0A, 0, 0, 0])?;
            if pos % 4 == 0 { return Some(pos); }
            start = pos + 1;
        }
    }

    #[inline(always)]
    fn rfind_newline(data: &[u8]) -> Option<usize> {
        let mut end = data.len();
        loop {
            let pos = memchr::memmem::rfind(&data[..end], &[0x0A, 0, 0, 0])?;
            if pos % 4 == 0 { return Some(pos); }
            end = pos;
        }
    }

    #[inline(always)]
    fn decode_line(raw: &[u8], dst: &mut Vec<u8>) {
        dst.reserve(raw.len() / 4);

        let mut i = 0;
        while i + 3 < raw.len() {
            let ascii = raw[i];
            if ascii & 0x80 != 0 || raw[i + 1] != 0 || raw[i + 2] != 0 || raw[i + 3] != 0 { break; }
            dst.push(ascii);
            i += 4;
        }

        if i >= raw.len() { return; }

        let mut buf = [0u8; 4];
        for chunk in raw[i..].chunks_exact(4) {
            let cp = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let ch = char::from_u32(cp).unwrap_or(char::REPLACEMENT_CHARACTER);
            dst.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    }
}

pub struct Utf32BeCodec;

impl LineCodec for Utf32BeCodec {
    const UNIT_WIDTH:      usize = 4;
    const RAW_PASSTHROUGH: bool  = false;
    const CR_SUFFIX: &'static [u8] = &[0x00, 0x00, 0x00, 0x0D];

    #[inline(always)]
    fn find_newline(data: &[u8]) -> Option<usize> {
        let mut start = 0;
        loop {
            let pos = start + memchr::memmem::find(&data[start..], &[0, 0, 0, 0x0A])?;
            if pos % 4 == 0 { return Some(pos); }
            start = pos + 1;
        }
    }

    #[inline(always)]
    fn rfind_newline(data: &[u8]) -> Option<usize> {
        let mut end = data.len();
        loop {
            let pos = memchr::memmem::rfind(&data[..end], &[0, 0, 0, 0x0A])?;
            if pos % 4 == 0 { return Some(pos); }
            end = pos;
        }
    }

    #[inline(always)]
    fn decode_line(raw: &[u8], dst: &mut Vec<u8>) {
        dst.reserve(raw.len() / 4);

        let mut i = 0;
        while i + 3 < raw.len() {
            let ascii = raw[i + 3];
            if ascii & 0x80 != 0 || raw[i] != 0 || raw[i + 1] != 0 || raw[i + 2] != 0 { break; }
            dst.push(ascii);
            i += 4;
        }

        if i >= raw.len() { return; }

        let mut buf = [0u8; 4];
        for chunk in raw[i..].chunks_exact(4) {
            let cp = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let ch = char::from_u32(cp).unwrap_or(char::REPLACEMENT_CHARACTER);
            dst.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    }
}
