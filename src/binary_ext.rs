#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(target_endian = "big")]
compile_error!("pack8/pack16 assume little-endian; audit before enabling on this target");

/// Pack 1..=8 bytes into a zero-extended u64.
///
/// SAFETY: caller guarantees `1 <= len <= 8` and that `ptr` points to at
/// least `len` valid, initialized, readable bytes.
///
/// Every load below reads only within `[ptr, ptr+len)`.
#[inline(always)]
unsafe fn pack8(ptr: *const u8, len: usize) -> u64 {
    match len {
        8 => ptr.cast::<u64>().read_unaligned(),

        4..=7 => {
            let lo = ptr.cast::<u32>().read_unaligned() as u64;
            if len == 4 {
                lo
            } else {
                let hi = ptr.add(len - 4).cast::<u32>().read_unaligned() as u64;
                lo | (hi << ((len - 4) * 8))
            }
        }

        3 => {
            let lo = ptr.cast::<u16>().read_unaligned() as u64;
            let hi = *ptr.add(2) as u64;
            lo | (hi << 16)
        }

        2 => ptr.cast::<u16>().read_unaligned() as u64,

        1 => *ptr as u64,

        _ => core::hint::unreachable_unchecked(),
    }
}

/// Same idea as `pack8`, for 9..=16 bytes into a u128.
///
/// SAFETY: caller guarantees `9 <= len <= 16` and that `ptr` points to at
/// least `len` valid, initialized, readable bytes.
#[inline(always)]
unsafe fn pack16(ptr: *const u8, len: usize) -> u128 {
    let lo = ptr.cast::<u64>().read_unaligned() as u128;
    let hi = ptr.add(len - 8).cast::<u64>().read_unaligned() as u128;
    lo | (hi << ((len - 8) * 8))
}

#[cfg(test)]
mod pack_self_consistency_tests {
    use super::*;

    #[test]
    fn pack8_matches_reference_for_all_lengths_1_to_8() {
        let data: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        for len in 1..=8usize {
            let got = unsafe { pack8(data.as_ptr(), len) };
            let want = const_pack64(&data[..len]);
            assert_eq!(got, want, "pack8 mismatch at len={}", len);
        }
    }

    #[test]
    fn pack16_matches_reference_for_all_lengths_9_to_16() {
        let data: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];
        for len in 9..=16usize {
            let got = unsafe { pack16(data.as_ptr(), len) };
            let want = const_pack128(&data[..len]);
            assert_eq!(got, want, "pack16 mismatch at len={}", len);
        }
    }
}

#[inline(always)]
fn binary_search<T: Ord + Copy>(sorted: &[T], target: T) -> bool {
    use crate::index_::Index_;

    if sorted.is_empty() {
        return false;
    }

    let mut base = 0usize;
    let mut len = sorted.len();

    while len > 1 {
        let half = len / 2;
        let mid = *sorted.get_(base + half);
        if mid <= target {
            base += half;
        }

        len -= half;
    }

    *sorted.get_(base) == target
}

//
// Compile-time table construction.
//
//       pack8/pack16 above are the fast runtime path (SWAR, unsafe, overlapping loads).
// const_pack64/128   below are the slow, obviously-correct version of the same bit layout,
// used only while building the sorted tables at compile time.
//
// If the two ever disagree, the generated 'every listed string matches' test catches it,
// since the table would be sorted/searched using one packing and queried at runtime using the other.
//

const fn const_pack64(bytes: &[u8]) -> u64 {
    let mut key = 0u64;
    let mut i = 0usize;
    while i < bytes.len() {
        key |= (bytes[i] as u64) << (i * 8);
        i += 1;
    }
    key
}

const fn const_pack128(bytes: &[u8]) -> u128 {
    let mut key = 0u128;
    let mut i = 0usize;
    while i < bytes.len() {
        key |= (bytes[i] as u128) << (i * 8);
        i += 1;
    }
    key
}

const fn count_short(strs: &[&str]) -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    while i < strs.len() {
        let l = strs[i].len();
        if l >= 1 && l <= 8 {
            n += 1;
        }
        i += 1;
    }
    n
}

const fn count_mid(strs: &[&str]) -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    while i < strs.len() {
        let l = strs[i].len();
        if l >= 9 && l <= 16 {
            n += 1;
        }
        i += 1;
    }
    n
}

const fn count_long(strs: &[&str]) -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    while i < strs.len() {
        if strs[i].len() > 16 {
            n += 1;
        }
        i += 1;
    }
    n
}

#[allow(clippy::len_zero)]
const fn build_keys8<const N: usize>(strs: &[&str]) -> [u64; N] {
    let mut out   = [0u64; N];
    let mut index = 0usize;

    let mut i = 0usize;
    while i < strs.len() {
        let s = strs[i];
        if s.len() >= 1 && s.len() <= 8 {
            out[index] = const_pack64(s.as_bytes());
            index += 1;
        }

        i += 1;
    }

    // Insertion sort. N is small (dozens of entries at most) and this runs
    // once at compile time, so O(N^2) is fine...
    let mut a = 1usize;
    while a < N {
        let key = out[a];
        let mut b = a;
        while b > 0 && out[b - 1] > key {
            out[b] = out[b - 1];
            b -= 1;
        }

        out[b] = key;
        a += 1;
    }

    //
    // Two distinct strings of the same byte length can never pack to the
    // same key, since packing not hashing.
    //
    // Two different lengths could only collide if one string were a prefix of
    // the other padded with NUL bytes, which none of these inputs are.
    //
    // So any equal neighbor here means the input list itself has a literal
    // duplicate entry.
    //

    let mut c = 1usize;
    while c < N {
        assert!(out[c - 1] != out[c], "duplicate entry in lookup table");
        c += 1;
    }

    out
}

const fn build_keys16<const N: usize>(strs: &[&str]) -> [u128; N] {
    let mut out    = [0u128; N];
    let mut index = 0usize;

    let mut i = 0usize;
    while i < strs.len() {
        let s = strs[i];
        if s.len() >= 9 && s.len() <= 16 {
            out[index] = const_pack128(s.as_bytes());
            index += 1;
        }
        i += 1;
    }

    let mut a = 1usize;
    while a < N {
        let key = out[a];
        let mut b = a;
        while b > 0 && out[b - 1] > key {
            out[b] = out[b - 1];
            b -= 1;
        }
        out[b] = key;
        a += 1;
    }

    let mut c = 1usize;
    while c < N {
        assert!(out[c - 1] != out[c], "duplicate entry in lookup table");
        c += 1;
    }

    out
}

const fn build_long<'a, const N: usize>(strs: &[&'a str]) -> [&'a str; N] {
    let mut out: [&str; N] = [""; N];
    let mut index = 0usize;
    let mut i = 0usize;
    while i < strs.len() {
        if strs[i].len() > 16 {
            out[index] = strs[i];
            index += 1;
        }
        i += 1;
    }
    out
}

macro_rules! sorted_lookup_table {
    (
        $vis:vis fn $name:ident;
        test_mod: $test_mod:ident;
        strings: [ $($s:literal),+ $(,)? ];
    ) => {
        $vis fn $name(input: &[u8]) -> bool {
            const RAW:   &[&str]       = &[$($s), +];
            const N8:     usize        = count_short(RAW);
            const N16:    usize        = count_mid(RAW);
            const NBIG:   usize        = count_long(RAW);
            const KEYS8:  [u64; N8]    = build_keys8::<N8>(RAW);
            const KEYS16: [u128; N16]  = build_keys16::<N16>(RAW);
            const LONG:   [&str; NBIG] = build_long::<NBIG>(RAW);

            match input.len() {
                0 => false,

                len @ 1..=8 => {
                    // SAFETY: len checked 1..=8, input[0..len] fully valid.
                    let key = unsafe { pack8(input.as_ptr(), len) };
                    binary_search(&KEYS8, key)
                }

                len @ 9..=16 => {
                    // SAFETY: len checked 9..=16, input[0..len] fully valid.
                    let key = unsafe { pack16(input.as_ptr(), len) };
                    binary_search(&KEYS16, key)
                }

                _ => LONG.iter().any(|s| s.as_bytes() == input),
            }
        }

        #[cfg(test)]
        mod $test_mod {
            use super::$name;

            const ALL: &[&str] = &[ $($s),+ ];

            #[test]
            fn every_listed_string_matches() {
                for s in ALL {
                    assert!(
                        $name(s.as_bytes()),
                        "{}({:?}) returned false, expected true",
                        stringify!($name),
                        s,
                    );
                }
            }

            #[test]
            fn empty_input_does_not_match() {
                assert!(!$name(b""));
            }

            #[test]
            fn unrelated_input_does_not_match() {
                for junk in [".definitely_not_in_the_table", "xyzzy", "q", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] {
                    assert!(
                        !ALL.contains(&junk),
                        "test bug: junk value {:?} is actually in the table",
                        junk,
                    );
                    assert!(!$name(junk.as_bytes()));
                }
            }
        }
    };
}

sorted_lookup_table! {
    pub fn is_binary_ext;
    test_mod: is_binary_ext_tests;
    strings: [
        // Images
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp",
        "tiff", "tif", "heic", "heif", "avif", "psd", "xcf",
        "raw", "cr2", "nef", "orf", "sr2", "dng",

        // Audio
        "mp3", "wav", "flac", "ogg", "oga", "m4a", "aac",
        "wma", "opus", "aiff", "mid", "midi", "amr",

        // Video
        "mp4", "mkv", "avi", "mov", "webm", "flv", "wmv",
        "m4v", "mpg", "mpeg", "3gp", "mts",

        // Archives / compressed
        "zip", "tar", "gz", "tgz", "bz2", "tbz2", "7z",
        "rar", "xz", "zst", "lz4", "lzma", "z", "cab", "br",

        // Executables / compiled objects
        "exe", "dll", "so", "a", "o", "obj", "lib",
        "class", "pyc", "pyo", "pyd", "wasm", "bin",
        "dylib", "msi", "deb", "rpm", "apk", "elf", "com",

        // Documents (binary formats)
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "odt", "ods", "odp", "rtf",

        // Fonts
        "ttf", "otf", "woff", "woff2", "eot",

        // Databases / data blobs
        "db", "sqlite", "sqlite3", "mdb", "accdb", "dat",
        "parquet", "avro", "orc",

        // Disk images / packages
        "iso", "dmg", "img", "jar", "war", "ear", "pak",
        "vhd", "vmdk", "qcow2", "appimage", "flatpak",
    ];
}

sorted_lookup_table! {
    pub fn is_reserved_tool_dir;
    test_mod: is_reserved_tool_dir_tests;
    strings: [
        // Version control
        ".git", ".hg", ".svn", ".jj", ".bzr", "_darcs",
        "CVS", "RCS", "SCCS",

        // Language / package manager caches & deps
        "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache",
        ".tox", ".nox", ".venv", "venv", "env", ".env",
        ".eggs", ".ipynb_checkpoints",
        "vendor", "Pods", ".dart_tool", ".pub-cache",
        ".cargo", ".rustup", "target",
        ".gradle", ".m2", ".ivy2",
        ".bundle", ".stack-work", "_build", "deps",
        ".yarn", ".pnpm-store", ".npm",
        ".cabal-sandbox", "dist-newstyle",

        // Build / output dirs
        "obj", ".next", ".nuxt", ".output", ".svelte-kit", ".angular",
        ".parcel-cache", ".turbo", ".cache", ".webpack",

        // IDE / editor
        ".idea", ".vscode", ".vs", ".fleet", ".settings",

        // Infra / IaC
        ".terraform", ".serverless", ".aws-sam",

        // Coverage / test artifacts
        ".nyc_output", "coverage", ".sass-cache",

        // OS junk directories
        "$RECYCLE.BIN", "System Volume Information",
    ];
}
