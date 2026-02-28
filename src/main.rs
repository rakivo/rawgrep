use rawgrep::cli::Cli;
use rawgrep::grep::{open_device_and_detect_fs, FsType, RawGrepper};
use rawgrep::{eprint_blue, eprint_green, eprintln_red, CURSOR_HIDE, CURSOR_UNHIDE};

use std::fs;
use std::sync::Arc;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

#[inline]
fn setup_signal_handler() -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
        {
            let mut handle = io::stdout().lock();
            _ = handle.write_all(CURSOR_UNHIDE.as_bytes());
        }
        _ = io::stdout().flush();
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    running
}

pub struct CursorHide;

impl CursorHide {
    #[inline]
    pub fn new() -> io::Result<Self> {
        io::stdout().lock().write_all(CURSOR_HIDE.as_bytes())?;
        io::stdout().flush()?;
        Ok(CursorHide)
    }
}

impl Drop for CursorHide {
    #[inline]
    fn drop(&mut self) {
        _ = io::stdout().lock().write_all(CURSOR_UNHIDE.as_bytes());
        _ = io::stdout().flush();
    }
}

fn main() -> io::Result<()> {
    #[cfg(feature = "dhat")]
    let _profiler = dhat::Profiler::new_heap();

    _ = rawgrep::platform::set_process_priority(-10);

    let cli = Cli::parse();

    let search_root_path_buf = match fs::canonicalize(&cli.search_root_path) {
        Ok(path) => path,
        Err(e) => {
            let search_root_path = &cli.search_root_path;
            eprintln_red!("error: couldn't canonicalize '{search_root_path}': {e}");
            std::process::exit(1);
        }
    };

    let device = cli.device.as_ref().cloned().unwrap_or_else(|| {
        match rawgrep::platform::detect_partition_for_path(search_root_path_buf.as_ref()) {
            Ok(ok) => ok,
            Err(e) => {
                eprintln_red!("error: couldn't find auto-detect partition: {e}");
                std::process::exit(1);
            }
        }
    });

    #[cfg(target_os = "macos")]
    let device = resolve_apfs_physical_store(&device)?;

    let (file, fs) = match open_device_and_detect_fs(&device) {
        Ok(ok) => ok,
        Err(e) => {
            match e.kind() {
                io::ErrorKind::NotFound => {
                    eprintln_red!("error: device or partition not found: '{device}'");
                }
                io::ErrorKind::PermissionDenied => {
                    eprintln_red!("error: permission denied. Try running with sudo/root to read raw devices.");
                }
                _ => {
                    eprintln_red!("error: failed to open device: {e}");
                }
            }
            std::process::exit(1);
        }
    };

    let grep = match fs {
        FsType::Apfs => RawGrepper::new_apfs(&cli, &device, file),
        FsType::Ext4 => RawGrepper::new_ext4(&cli, &device, file),
        FsType::Ntfs => RawGrepper::new_ntfs(&cli, &device, file),
    };

    let grep = match grep {
        Ok(ok) => ok,
        Err(e) => {
            match e.kind() {
                io::ErrorKind::InvalidData if fs == FsType::Ext4 => {
                    eprintln_red!("error: invalid ext4 filesystem on this path: {e}");
                    eprintln_red!("help: make sure the path points to a partition (e.g., /dev/sda1) and not a whole disk (e.g., /dev/sda)");
                    eprintln_red!("tip: try running `df -Th /` to find your root partition");
                }
                _ => {
                    eprintln_red!("error: failed to initialize {fs:?} reader: {e}");
                }
            }

            std::process::exit(1);
        }
    };

    let search_root_path_for_fs = if cli.device.is_some() {
        //
        // Try to find where this device is mounted and strip that prefix
        //
        rawgrep::platform::strip_mountpoint_prefix(&device, &search_root_path_buf)
            .unwrap_or_else(|| search_root_path_buf.to_string_lossy().into_owned())
    } else {
        search_root_path_buf.to_string_lossy().into_owned()
    };

    let search_root_path = search_root_path_for_fs.as_ref();

    let start_inode = match grep.try_resolve_path_to_file_id(search_root_path) {
        Ok(ok) => ok,
        Err(e) => {
            eprintln_red!("error: couldn't find {search_root_path} in {device}: {e}");
            std::process::exit(1);
        }
    };

    eprint_blue!("Searching ");
    eprint_green!("'{search_root_path}' ");
    eprint_blue!("on device ");
    eprint_green!("'{device}' ");
    eprint_blue!("with fs ");
    eprint_green!("'{fs:?}' ");
    eprint_blue!("for pattern: ");
    eprintln_red!("'{pattern}'", pattern = cli.pattern);

    let _cur = CursorHide::new();

    let potential_root_gitignore_path_buf = search_root_path_buf.join(".gitignore");
    let potential_root_gitignore_path = potential_root_gitignore_path_buf.to_string_lossy();
    let potential_root_gitignore_path = potential_root_gitignore_path.as_ref();

    let stats = grep.search(
        start_inode,
        &setup_signal_handler(),
        rawgrep::ignore::build_gitignore_from_file(potential_root_gitignore_path)
    )?;

    if cli.stats {
        eprintln!("{stats}");
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn resolve_apfs_physical_store(virtual_device: &str) -> io::Result<String> {
    // virtual_device is e.g. "/dev/disk3s5"
    // We need to find "disk0s2" via diskutil info -plist
    let disk_id = virtual_device.trim_start_matches("/dev/");

    let output = std::process::Command::new("diskutil")
        .args(["info", "-plist", disk_id])
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "diskutil failed"));
    }

    // Parse the plist to find APFSPhysicalStores[0].APFSPhysicalStore
    // Simple string search avoids a plist dependency
    let stdout = String::from_utf8_lossy(&output.stdout);
    let key = "<key>APFSPhysicalStore</key>";
    let val_open  = "<string>";
    let val_close = "</string>";

    if let Some(key_pos) = stdout.find(key) {
        let after_key = &stdout[key_pos + key.len()..];
        if let Some(open_pos) = after_key.find(val_open) {
            let after_open = &after_key[open_pos + val_open.len()..];
            if let Some(close_pos) = after_open.find(val_close) {
                let store = &after_open[..close_pos]; // e.g. "disk0s2"
                return Ok(format!("/dev/{store}"));
            }
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "APFSPhysicalStore not found in diskutil output"))
}
