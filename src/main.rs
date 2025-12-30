use std::fs;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rawgrep::cli::Cli;
use rawgrep::fs::FsType;
use rawgrep::grep::{open_device, RawGrepper};
use rawgrep::{eprint_blue, eprint_green, eprintln_red, exit_err, CURSOR_HIDE, CURSOR_UNHIDE};

fn setup_signal_handler() -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
        _ = io::stdout().lock().write_all(CURSOR_UNHIDE.as_bytes());
        _ = io::stdout().flush();
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    running
}

struct CursorHide;

impl CursorHide {
    fn new() -> io::Result<Self> {
        io::stdout().lock().write_all(CURSOR_HIDE.as_bytes())?;
        io::stdout().flush()?;
        Ok(Self)
    }
}

impl Drop for CursorHide {
    fn drop(&mut self) {
        _ = io::stdout().lock().write_all(CURSOR_UNHIDE.as_bytes());
        _ = io::stdout().flush();
    }
}

fn main() -> io::Result<()> {
    #[cfg(feature = "dhat")]
    let _profiler = dhat::Profiler::new_heap();

    let cli = Cli::parse();

    let search_root_path_buf = fs::canonicalize(&cli.search_root_path).unwrap_or_else(|e| {
        exit_err!("error: couldn't canonicalize '{}': {e}", cli.search_root_path);
    });

    let device = cli.device.clone().unwrap_or_else(|| {
        rawgrep::platform::detect_partition_for_path(&search_root_path_buf).unwrap_or_else(|e| {
            exit_err!("error: couldn't auto-detect partition: {e}");
        })
    });

    let search_root_path = search_root_path_buf.to_string_lossy();

    let (_file, mmap) = open_device(&device).unwrap_or_else(|e| {
        match e.kind() {
            io::ErrorKind::NotFound => exit_err!("error: device not found: '{device}'"),
            io::ErrorKind::PermissionDenied => exit_err!("error: permission denied (try sudo)"),
            _ => exit_err!("error: failed to open device: {e}"),
        }
    });

    let fs_type = FsType::detect(&mmap);

    eprint_blue!("Searching ");
    eprint_green!("'{device}' ");
    eprint_blue!("({fs_type}) for pattern: ");
    eprintln_red!("'{}'", cli.pattern);

    let _cursor = CursorHide::new();
    let running = setup_signal_handler();

    let gitignore_path = search_root_path_buf.join(".gitignore");
    let root_gitignore = rawgrep::ignore::build_gitignore_from_file(
        gitignore_path.to_string_lossy().as_ref()
    );

    let stats = match fs_type {
        FsType::Ext4 => {
            let grep = RawGrepper::new_ext4(&device, &cli, &mmap).unwrap_or_else(|e| {
                exit_err!("error: failed to initialize ext4 reader: {e}");
            });

            let start = grep.try_resolve_path_to_file_id(&search_root_path).unwrap_or_else(|e| {
                exit_err!("error: path not found in {device}: {e}");
            });

            grep.search(start, &running, root_gitignore)?
        }

        FsType::Apfs => {
            let grep = RawGrepper::new_apfs(&device, &cli, &mmap).unwrap_or_else(|e| {
                exit_err!("error: failed to initialize APFS reader: {e}");
            });

            let start = grep.try_resolve_path_to_file_id(&search_root_path).unwrap_or_else(|e| {
                exit_err!("error: path not found in {device}: {e}");
            });

            grep.search(start, &running, root_gitignore)?
        }

        FsType::Unknown => {
            exit_err!("error: unsupported filesystem on {device} (supports: ext4, apfs)");
        }
    };

    if cli.stats {
        eprintln!("{stats}");
    }

    Ok(())
}
