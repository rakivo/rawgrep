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

    /// Set process priority (-20 to 19, lower = higher priority)
    /// Returns Ok(()) on success, Err on failure
    fn set_process_priority(priority: i32) -> io::Result<()>;

    /// Given a device path and an absolute filesystem path, return the portion
    /// of the path that is relative to the device's mount point.
    ///
    /// e.g. device = "ntfs_test.img", path = "/mnt/ntfs_test/Odin"
    ///      mount point of that device = "/mnt/ntfs_test"
    ///      returns Some("Odin")
    ///
    /// Returns None if the device isn't mounted or the path isn't under its mount.
    fn strip_mountpoint_prefix(device: &str, path: &Path) -> Option<String>;
}

//
// Linux implementation
//

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;

    use std::fs;
    use std::path::{PathBuf, MAIN_SEPARATOR_STR};
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

        fn set_process_priority(priority: i32) -> io::Result<()> {
            let result = unsafe {
                libc::setpriority(libc::PRIO_PROCESS, 0, priority)
            };

            if result == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        fn strip_mountpoint_prefix(device: &str, path: &Path) -> Option<String> {
            let mounts = fs::read_to_string("/proc/mounts")
                .or_else(|_| fs::read_to_string("/etc/mtab"))
                .ok()?;

            // Canonicalize the requested device path
            let canonical_device = fs::canonicalize(device)
                .unwrap_or_else(|_| PathBuf::from(device));

            let mut best_mountpoint: Option<PathBuf> = None;
            let mut best_len = 0usize;

            for line in mounts.lines() {
                let mut parts = line.split_whitespace();
                let dev = parts.next()?;
                let mountpoint_escaped = parts.next()?;

                // Canonicalize the mounted device
                let canonical_mounted = fs::canonicalize(dev)
                    .unwrap_or_else(|_| PathBuf::from(dev));

                // Direct match (e.g. /dev/sda1 == /dev/sda1)
                let matches = canonical_mounted == canonical_device
                // Loop device: check /sys/block/loopN/loop/backing_file
                    || loop_device_backing_file(&canonical_mounted)
                    .as_deref()
                    .and_then(|b| fs::canonicalize(b).ok())
                    .map(|b| b == canonical_device)
                    .unwrap_or(false);

                if !matches {
                    continue;
                }

                let mountpoint = unescape_mountpoint(mountpoint_escaped);
                let mount_path = fs::canonicalize(&mountpoint)
                    .unwrap_or_else(|_| PathBuf::from(&mountpoint));

                if path.starts_with(&mount_path) {
                    let len = mount_path.as_os_str().len();
                    if len >= best_len {
                        best_len = len;
                        best_mountpoint = Some(mount_path);
                    }
                }
            }

            let mountpoint = best_mountpoint?;
            let relative = path.strip_prefix(&mountpoint).ok()?;
            let s = relative.to_string_lossy();
            Some(if s.is_empty() { MAIN_SEPARATOR_STR.to_string() } else { s.into_owned() })
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

    /// Read /sys/block/loopN/loop/backing_file to find what image a loop device backs.
    fn loop_device_backing_file(dev: &Path) -> Option<String> {
        // dev is e.g. /dev/loop3 — extract "loop3"
        let name = dev.file_name()?.to_str()?;
        if !name.starts_with("loop") { return None; }
        let backing = fs::read_to_string(format!("/sys/block/{name}/loop/backing_file")).ok()?;
        Some(backing.trim().to_string())
    }
}

//
// macOS implementation
//

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

        fn set_process_priority(priority: i32) -> io::Result<()> {
            let result = unsafe {
                libc::setpriority(libc::PRIO_PROCESS, 0, priority)
            };

            if result == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        fn strip_mountpoint_prefix(device: &str, path: &Path) -> Option<String> {
            use std::ffi::CStr;

            // statfs on the path gives us the mount point directly
            let path_bytes = path.as_os_str().as_bytes();
            let mut path_cstr = Vec::with_capacity(path_bytes.len() + 1);
            path_cstr.extend_from_slice(path_bytes);
            path_cstr.push(0);

            let mut statfs_buf: libc::statfs = unsafe { std::mem::zeroed() };
            let res = unsafe {
                libc::statfs(path_cstr.as_ptr() as *const libc::c_char, &mut statfs_buf)
            };
            if res < 0 { return None; }

            // Check the device matches
            let mounted_from = unsafe {
                CStr::from_ptr(statfs_buf.f_mntfromname.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            };
            let canonical_device = std::fs::canonicalize(device)
                .unwrap_or_else(|_| std::path::PathBuf::from(device));
            let canonical_mounted = std::fs::canonicalize(&mounted_from)
                .unwrap_or_else(|_| std::path::PathBuf::from(&mounted_from));
            if canonical_device != canonical_mounted { return None; }

            let mountpoint = unsafe {
                CStr::from_ptr(statfs_buf.f_mntonname.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            };
            let mount_path = std::path::Path::new(&mountpoint);
            let relative = path.strip_prefix(mount_path).ok()?;
            let s = relative.to_string_lossy();
            Some(if s.is_empty() { MAIN_SEPARATOR_STR.to_string() } else { s.into_owned() })
        }
    }
}

//
// Windows implementation
//

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
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, SetPriorityClass,
        ABOVE_NORMAL_PRIORITY_CLASS, HIGH_PRIORITY_CLASS,
        NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS,
    };

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

        fn set_process_priority(priority: i32) -> io::Result<()> {
            // Windows uses different priority classes, map Unix nice values to them
            let priority_class = match priority {
                i32::MIN..=-10 => HIGH_PRIORITY_CLASS,           // High priority
                -9..=0 => ABOVE_NORMAL_PRIORITY_CLASS,           // Above normal
                1..=10 => NORMAL_PRIORITY_CLASS,                 // Normal
                11..=i32::MAX => BELOW_NORMAL_PRIORITY_CLASS,    // Below normal
            };

            let result = unsafe {
                SetPriorityClass(GetCurrentProcess(), priority_class)
            };

            if result == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }

        fn strip_mountpoint_prefix(device: &str, path: &Path) -> Option<String> {
            use std::os::windows::ffi::OsStrExt;

            let path_wide: Vec<u16> = path.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let mut volume_path = vec![0u16; 260];
            let result = unsafe {
                GetVolumePathNameW(
                    path_wide.as_ptr(),
                    volume_path.as_mut_ptr(),
                    volume_path.len() as u32,
                )
            };
            if result == 0 { return None; }

            let len = volume_path.iter().position(|&c| c == 0).unwrap_or(volume_path.len());
            let mountpoint = String::from_utf16_lossy(&volume_path[..len]);
            // mountpoint is e.g. "C:\" — check it matches device
            let trimmed = mountpoint.trim_end_matches('\\');
            let device_path = format!("\\\\.\\{trimmed}");
            if !device.eq_ignore_ascii_case(&device_path) { return None; }

            let mount_path = std::path::Path::new(&mountpoint);
            let relative = path.strip_prefix(mount_path).ok()?;
            let s = relative.to_string_lossy();
            Some(if s.is_empty() { MAIN_SEPARATOR_STR.to_string() } else { s.into_owned() })
        }
    }
}

//
// Platform type alias for current OS
//

#[cfg(target_os = "linux")]
pub type CurrentPlatform = linux::LinuxPlatform;

#[cfg(target_os = "macos")]
pub type CurrentPlatform = macos::MacOSPlatform;

#[cfg(target_os = "windows")]
pub type CurrentPlatform = windows::WindowsPlatform;

//
// Convenience functions using CurrentPlatform
//

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

#[inline]
pub fn set_process_priority(priority: i32) -> io::Result<()> {
    CurrentPlatform::set_process_priority(priority)
}

#[inline]
pub fn strip_mountpoint_prefix(device: &str, path: &Path) -> Option<String> {
    CurrentPlatform::strip_mountpoint_prefix(device, path)
}
