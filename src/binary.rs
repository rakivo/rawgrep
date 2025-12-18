use crate::grep::BINARY_CONTROL_COUNT;

#[inline(always)]
pub fn is_binary_ext(ext: &[u8]) -> bool {
    const BINARY_EXTS: &[&[u8]] = &[
        b"png",b"jpg",b"jpeg",b"gif",b"class",b"so",b"o",b"a",
        b"pdf",b"zip",b"tar",b"gz",b"7z",b"exe",b"dll",b"bin",
    ];

    BINARY_EXTS.contains(&ext)
}

const BYTE_CLASS: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = matches!(
            i as u8,
            0x09 | 0x0A | 0x0D | 0x20..=0x7E | 0x80..=0xFF
        );
        i += 1;
    }
    table
};

#[inline]
pub fn is_binary_chunk(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    if memchr::memchr(0, data).is_some() {
        return true;
    }

    if cfg!(target_arch = "x86_64") && is_x86_feature_detected!("sse2") {
        unsafe { is_binary_chunk_simd_sse2(data) }
    } else {
        is_binary_chunk_(data)
    }
}

/// # Safety
/// Caller's machine supports SSE2
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
pub unsafe fn is_binary_chunk_simd_sse2(data: &[u8]) -> bool {
    use std::arch::x86_64::*;

    let check_len = data.len().min(512);
    let mut control_count = 0;

    let chunks = check_len / 16;
    let ptr = data.as_ptr();

    // Create masks for allowed control chars: \t (0x09), \n (0x0A), \r (0x0D)
    let tab = _mm_set1_epi8(0x09);
    let lf = _mm_set1_epi8(0x0A);
    let cr = _mm_set1_epi8(0x0D);
    let space = _mm_set1_epi8(0x20);

    for i in 0..chunks {
        use crate::grep::BINARY_CONTROL_COUNT;

        let chunk = unsafe { _mm_loadu_si128(ptr.add(i * 16) as *const __m128i) };

        // Find bytes < 0x20 (potential control characters)
        let below_space = _mm_cmplt_epi8(chunk, space);

        // Exclude allowed control chars: tab, LF, CR
        let is_tab = _mm_cmpeq_epi8(chunk, tab);
        let is_lf  = _mm_cmpeq_epi8(chunk, lf);
        let is_cr  = _mm_cmpeq_epi8(chunk, cr);

        // Combine: allowed = tab | lf | cr
        let allowed = _mm_or_si128(_mm_or_si128(is_tab, is_lf), is_cr);

        // Bad control chars = below_space AND NOT allowed
        let bad_controls = _mm_andnot_si128(allowed, below_space);

        let mask = _mm_movemask_epi8(bad_controls) as u32;
        control_count += mask.count_ones() as usize;

        if control_count > BINARY_CONTROL_COUNT {
            return true;
        }
    }

    // Handle remaining bytes
    for &byte in &data[chunks * 16..check_len] {
        if !BYTE_CLASS[byte as usize] {
            control_count += 1;
            if control_count > BINARY_CONTROL_COUNT {
                return true;
            }
        }
    }

    false
}

#[inline]
fn is_binary_chunk_(data: &[u8]) -> bool {
    let check_len = data.len().min(512);
    let mut control_count = 0;

    let mut i = 0;
    while i + 4 <= check_len {
        control_count += !BYTE_CLASS[data[i] as usize] as usize;
        control_count += !BYTE_CLASS[data[i+1] as usize] as usize;
        control_count += !BYTE_CLASS[data[i+2] as usize] as usize;
        control_count += !BYTE_CLASS[data[i+3] as usize] as usize;

        if control_count > BINARY_CONTROL_COUNT {
            return true;
        }
        i += 4;
    }

    // Handle remaining bytes
    while i < check_len {
        control_count += !BYTE_CLASS[data[i] as usize] as usize;
        if control_count > BINARY_CONTROL_COUNT {
            return true;
        }
        i += 1;
    }

    false
}
