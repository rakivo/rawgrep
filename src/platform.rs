//! Platform-specific abstractions for device operations
//!
//! This module provides cross-platform abstractions for:
//! - Getting block device size
//! - Getting device ID (for cache keys)
//! - Detecting which partition a path is on

use std::io;
use std::fs::File;
use std::path::Path;

pub trait Platform {
    /// Get the size of a block device in bytes
    fn device_size(fd: &File) -> io::Result<u64>;

    /// Get a unique device identifier (used for cache keys)
    fn device_id(fd: &File) -> io::Result<u64>;

    /// Detect which partition/device a given path is mounted on
    /// Returns the device path (e.g., "/dev/sda1" on Linux)
    fn detect_partition_for_path(path: &Path) -> io::Result<String>;
}

// ============================================================================
// Linux implementation
// ============================================================================

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;

    use std::fs;
    use std::path::PathBuf;
    use std::os::fd::AsRawFd;

    const BLKGETSIZE64: libc::c_ulong = 0x80081272;

    pub struct LinuxPlatform;

    impl Platform for LinuxPlatform {
        #[inline]
        fn device_size(fd: &File) -> io::Result<u64> {
            let mut size = 0u64;
            let res = unsafe {
                libc::ioctl(fd.as_raw_fd(), BLKGETSIZE64, &mut size)
            };

            if res < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(size)
        }

        #[inline]
        fn device_id(fd: &File) -> io::Result<u64> {
            unsafe {
                let mut stat: libc::stat = std::mem::zeroed();
                if libc::fstat(fd.as_raw_fd(), &mut stat) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(stat.st_dev)
            }
        }

        fn detect_partition_for_path(canonicalized_path: &Path) -> io::Result<String> {
            let mounts = fs::read_to_string("/proc/mounts")
                .or_else(|_| fs::read_to_string("/etc/mtab"))?;

            let mut best_match: Option<String> = None;
            let mut best_match_len = 0;

            for line in mounts.lines() {
                let parts = line.split_whitespace().collect::<Vec<_>>();
                if parts.len() < 3 {
                    continue;
                }

                let device = parts[0];
                let mountpoint_escaped = parts[1];
                let fstype = parts[2];

                //
                // Skip non-ext4 filesystems
                //
                if fstype != "ext4" {
                    continue;
                }

                //
                // Skip virtual/pseudo filesystems
                //
                if !device.starts_with("/dev/") {
                    continue;
                }

                //
                // Resolve device symlinks
                //
                let device = fs::canonicalize(device)
                    .unwrap_or_else(|_| PathBuf::from(device));
                let device = device.to_string_lossy();

                let mountpoint = unescape_mountpoint(mountpoint_escaped);

                match fs::canonicalize(&mountpoint) {
                    Ok(mount_path) => {
                        if canonicalized_path.starts_with(&mount_path) {
                            let mount_len = mount_path.as_os_str().len();
                            if mount_len > best_match_len {
                                best_match_len = mount_len;
                                best_match = Some(device.to_string());
                            }
                        }
                    }
                    Err(_) => {
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
                    format!(
                        "No ext4 partition found for path: {}",
                        canonicalized_path.display()
                    ),
                )
            })
        }
    }

    /// Unescape octal sequences in mountpoint paths (e.g., \040 -> space)
    fn unescape_mountpoint(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '\\' {
                let mut octal = String::with_capacity(3);
                for _ in 0..3 {
                    if let Some(&next) = chars.peek() {
                        if next.is_ascii_digit() {
                            octal.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    }
                }
                if octal.len() == 3 {
                    if let Ok(code) = u8::from_str_radix(&octal, 8) {
                        result.push(code as char);
                        continue;
                    }
                }
                result.push('\\');
                result.push_str(&octal);
            } else {
                result.push(c);
            }
        }

        result
    }
}

// ============================================================================
// macOS implementation
// ============================================================================

#[cfg(target_os = "macos")]
pub mod macos {
    use super::*;
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;

    // ioctl constants from <sys/disk.h>
    // DKIOCGETBLOCKSIZE = _IOR('d', 24, uint32_t) = 0x40046418
    // DKIOCGETBLOCKCOUNT = _IOR('d', 25, uint64_t) = 0x40086419
    const DKIOCGETBLOCKSIZE: libc::c_ulong = 0x40046418;
    const DKIOCGETBLOCKCOUNT: libc::c_ulong = 0x40086419;

    pub struct MacOSPlatform;

    impl Platform for MacOSPlatform {
        fn device_size(fd: &File) -> io::Result<u64> {
            let raw_fd = fd.as_raw_fd();

            let mut block_size: u32 = 0;
            let mut block_count: u64 = 0;

            //
            // Get block size
            //
            let res = unsafe {
                libc::ioctl(raw_fd, DKIOCGETBLOCKSIZE, &mut block_size)
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }

            //
            // Get block count
            //
            let res = unsafe {
                libc::ioctl(raw_fd, DKIOCGETBLOCKCOUNT, &mut block_count)
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(block_count * block_size as u64)
        }

        #[inline]
        fn device_id(fd: &File) -> io::Result<u64> {
            unsafe {
                let mut stat: libc::stat = std::mem::zeroed();
                if libc::fstat(fd.as_raw_fd(), &mut stat) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(stat.st_dev as u64)
            }
        }

        fn detect_partition_for_path(path: &Path) -> io::Result<String> {
            use std::os::unix::ffi::OsStrExt;

            //
            // Convert path to C string
            //
            let path_bytes = path.as_os_str().as_bytes();
            let mut path_buf = Vec::with_capacity(path_bytes.len() + 1);
            path_buf.extend_from_slice(path_bytes);
            path_buf.push(0);

            let mut statfs_buf: libc::statfs = unsafe { std::mem::zeroed() };

            let res = unsafe {
                libc::statfs(path_buf.as_ptr() as *const libc::c_char, &mut statfs_buf)
            };

            if res < 0 {
                return Err(io::Error::last_os_error());
            }

            //
            // f_mntfromname contains the device path (e.g., "/dev/disk1s1")
            //
            let device = unsafe {
                CStr::from_ptr(statfs_buf.f_mntfromname.as_ptr())
            };

            device.to_str()
                .map(|s| s.to_string())
                .map_err(|_| io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Device path contains invalid UTF-8"
                ))
        }
    }
}

// ============================================================================
// Windows implementation
// ============================================================================

#[cfg(target_os = "windows")]
pub mod windows {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, GetVolumePathNameW,
        BY_HANDLE_FILE_INFORMATION,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::IOCTL_DISK_GET_LENGTH_INFO;

    /// GET_LENGTH_INFORMATION structure for IOCTL_DISK_GET_LENGTH_INFO
    #[repr(C)]
    struct GetLengthInformation {
        length: i64,
    }

    pub struct WindowsPlatform;

    impl Platform for WindowsPlatform {
        fn device_size(fd: &File) -> io::Result<u64> {
            let handle = fd.as_raw_handle();
            if std::ptr::eq(handle, INVALID_HANDLE_VALUE) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid file handle"
                ));
            }

            let mut length_info = GetLengthInformation { length: 0 };
            let mut bytes_returned: u32 = 0;

            let result = unsafe {
                DeviceIoControl(
                    handle as _,
                    IOCTL_DISK_GET_LENGTH_INFO,
                    std::ptr::null(),
                    0,
                    &mut length_info as *mut _ as *mut _,
                    std::mem::size_of::<GetLengthInformation>() as u32,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };

            if result == 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(length_info.length as u64)
        }

        fn device_id(fd: &File) -> io::Result<u64> {
            let handle = fd.as_raw_handle();
            if std::ptr::eq(handle, INVALID_HANDLE_VALUE) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid file handle"
                ));
            }

            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };

            let result = unsafe {
                GetFileInformationByHandle(handle as _, &mut info)
            };

            if result == 0 {
                return Err(io::Error::last_os_error());
            }

            //
            // Combine volume serial number and file index for unique ID
            //
            let file_index = ((info.nFileIndexHigh as u64) << 32) | (info.nFileIndexLow as u64);
            let volume_serial = info.dwVolumeSerialNumber as u64;
            Ok(volume_serial ^ file_index)
        }

        fn detect_partition_for_path(path: &Path) -> io::Result<String> {
            //
            // Convert path to wide string
            //
            let path_wide: Vec<u16> = path.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();

            //
            // Buffer for volume path (e.g., "C:\")
            //
            let mut volume_path = vec![0u16; 260]; // MAX_PATH @Constant

            let result = unsafe {
                GetVolumePathNameW(
                    path_wide.as_ptr(),
                    volume_path.as_mut_ptr(),
                    volume_path.len() as u32,
                )
            };

            if result == 0 {
                return Err(io::Error::last_os_error());
            }

            //
            // Find null terminator and convert to String
            //
            let len = volume_path.iter().position(|&c| c == 0).unwrap_or(volume_path.len());
            let volume_str = String::from_utf16_lossy(&volume_path[..len]);

            //
            // Windows returns mount points like "C:\", convert to device path "\\.\C:"
            //
            let trimmed = volume_str.trim_end_matches('\\');
            Ok(format!("\\\\.\\{trimmed}"))
        }
    }
}

// ============================================================================
// Platform type alias for current OS
// ============================================================================

#[cfg(target_os = "linux")]
pub type CurrentPlatform = linux::LinuxPlatform;

#[cfg(target_os = "macos")]
pub type CurrentPlatform = macos::MacOSPlatform;

#[cfg(target_os = "windows")]
pub type CurrentPlatform = windows::WindowsPlatform;

// ===============================================
// Convenience functions using CurrentPlatform
// ===============================================

#[inline]
pub fn device_size(fd: &File) -> io::Result<u64> {
    CurrentPlatform::device_size(fd)
}

#[inline]
pub fn device_id(fd: &File) -> io::Result<u64> {
    CurrentPlatform::device_id(fd)
}

#[inline]
pub fn detect_partition_for_path(path: &Path) -> io::Result<String> {
    CurrentPlatform::detect_partition_for_path(path)
}
