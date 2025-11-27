#![cfg_attr(feature = "use_nightly", allow(internal_features))]
#![cfg_attr(feature = "use_nightly", feature(core_intrinsics))]

#![allow(
    clippy::identity_op,
    clippy::only_used_in_recursion
)]

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod cli;
mod grep;
mod util;
mod stats;
mod binary;
mod writer;
mod matcher;
mod path_buf;

use crate::cli::Cli;
use crate::grep::RawGrepper;
use crate::util::build_gitignore;

use std::fs;
use std::sync::Arc;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Parser;
use smallvec::SmallVec;

pub const COLOR_RED: &str = "\x1b[1;31m";
pub const COLOR_GREEN: &str = "\x1b[1;32m";
pub const COLOR_BLUE: &str = "\x1b[1;34m";
pub const COLOR_CYAN: &str = "\x1b[1;36m";
pub const COLOR_RESET: &str = "\x1b[0m";

pub const CURSOR_HIDE: &str = "\x1b[?25l";
pub const CURSOR_UNHIDE: &str = "\x1b[?25h";

/// Helper used to indicate that we copy some amount of copiable data (bytes) into a newly allocated memory
#[inline(always)]
pub fn copy_data<A, T>(bytes: &[T]) -> SmallVec<A>
where
    A: smallvec::Array<Item = T>,
    T: Copy
{
    SmallVec::from_slice(bytes)
}

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
    pub fn new() -> io::Result<Self> {
        io::stdout().lock().write_all(CURSOR_HIDE.as_bytes())?;
        io::stdout().flush()?;
        Ok(CursorHide)
    }
}

impl Drop for CursorHide {
    fn drop(&mut self) {
        _ = io::stdout().lock().write_all(CURSOR_UNHIDE.as_bytes());
        _ = io::stdout().flush();
    }
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let search_root_path = match fs::canonicalize(&cli.search_root_path) {
        Ok(path) => path,
        Err(e) => {
            let search_root_path = &cli.search_root_path;
            eprintln!("error: couldn't canonicalize '{search_root_path}': {e}");
            std::process::exit(1);
        }
    };

    let device = cli.device.as_ref().cloned().unwrap_or_else(|| {
        match crate::util::detect_partition_for_path(search_root_path.as_ref()) {
            Ok(ok) => ok,
            Err(e) => {
                eprintln!("error: couldn't find auto-detect partition: {e}");
                std::process::exit(1);
            }
        }
    });

    let dir_path = search_root_path.to_string_lossy();
    let dir_path = dir_path.as_ref();

    let mut grep = match RawGrepper::new(&device, dir_path, cli) {
        Ok(ok) => ok,
        Err(e) => {
            eprint!("{COLOR_RED}");
            match e.kind() {
                io::ErrorKind::NotFound => {
                    eprintln!("error: device or partition not found: '{device}'");
                }
                io::ErrorKind::PermissionDenied => {
                    eprintln!("error: permission denied. Try running with sudo/root to read raw devices.");
                }
                io::ErrorKind::InvalidData => {
                    eprintln!("error: invalid ext4 filesystem on this path: {e}");
                    eprintln!("help: make sure the path points to a partition (e.g., /dev/sda1) and not a whole disk (e.g., /dev/sda)");
                    eprintln!("tip: try running `df -Th /` to find your root partition");
                }
                _ => {
                    eprintln!("error: failed to initialize ext4 reader: {e}");
                }
            }
            eprint!("{COLOR_RESET}");

            std::process::exit(1);
        }
    };

    let start_inode = match grep.try_resolve_path_to_inode(dir_path) {
        Ok(ok) => ok,
        Err(e) => {
            eprintln!("{COLOR_RED}error: couldn't find {dir_path} in {device}: {e}{COLOR_RESET}");
            std::process::exit(1);
        }
    };

    eprintln!{
        "{COLOR_CYAN}Searching{COLOR_RESET} '{device}' for pattern: {COLOR_RED}'{pattern}'{COLOR_RESET}\n",
        pattern = grep.cli.pattern
    };

    let _cur = CursorHide::new();

    let (cli, stats) = grep.search(
        start_inode,
        &mut dir_path.to_owned(),
        &setup_signal_handler(),
        build_gitignore(dir_path.as_ref())
    )?;

    if cli.stats {
        eprintln!("{stats}");
    }

    Ok(())
}
