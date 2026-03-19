#![cfg_attr(all(nightly, feature = "use_nightly"), allow(internal_features))]
#![cfg_attr(all(nightly, feature = "use_nightly"), feature(core_intrinsics))]

#![allow(
    clippy::identity_op,
    clippy::collapsible_if,
    clippy::module_inception,
    clippy::new_without_default,
    clippy::only_used_in_recursion,
    clippy::doc_overindented_list_items,
)]

#[cfg(all(feature = "small", feature = "full"))]
compile_error!("Cannot enable both `small` and `full` features - choose one!");

#[cfg(not(any(feature = "small", feature = "full")))]
compile_error!("Must enable either `small` or `full` feature!");

pub mod ctx;
pub mod cli;
pub mod grep;
pub mod ext4;
pub mod apfs;
pub mod ntfs;
pub mod util;
pub mod stats;
pub mod tracy;
pub mod ignore;
pub mod parser;
pub mod error;
pub mod worker;
pub mod binary;
pub mod matcher;
pub mod path_buf;
pub mod cache;
pub mod fragments;
pub mod platform;

#[cfg(feature = "small")]
pub(crate) extern crate regex_tiny as regex;
#[cfg(feature = "small")]
pub(crate) extern crate clap_tiny as clap;

pub use tracing;
pub use crossbeam_channel;

#[cfg(not(feature = "small"))]
pub(crate) extern crate regex_full as regex;
#[cfg(not(feature = "small"))]
pub(crate) extern crate clap_full as clap;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
pub use stats::Stats;
pub use grep::RawGrepper;
pub use ctx::RawGrepCtx;

use grep::FsType;
use worker::MatchSink;

pub const COLOR_RED: &str = "\x1b[1;31m";
pub const COLOR_GREEN: &str = "\x1b[1;32m";
pub const COLOR_BLUE: &str = "\x1b[1;34m";
pub const COLOR_CYAN: &str = "\x1b[1;36m";
pub const COLOR_RESET: &str = "\x1b[0m";

pub const CURSOR_HIDE: &str = "\x1b[?25l";
pub const CURSOR_UNHIDE: &str = "\x1b[?25h";

use smallvec::SmallVec;

/// Helper used to indicate that we copy some amount of copiable data (bytes) into a newly allocated memory
#[inline(always)]
pub fn copy_data<A, T>(bytes: &[T]) -> SmallVec<A>
where
    A: smallvec::Array<Item = T>,
    T: Copy
{
    SmallVec::from_slice(bytes)
}

use std::sync::Arc;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Configuration for a single rawgrep search.
#[derive(Debug, Clone)]
pub struct RawGrepConfig {
    // ---- required -------------------------------------------------------
    pub pattern:          Box<str>,
    pub search_root_path: Box<str>,

    // ---- optional device override ---------------------------------------
    /// `None` -> auto-detect from `search_root_path`.
    pub device: Option<Box<str>>,

    // ---- filtering ------------------------------------------------------
    pub no_ignore:    bool,
    pub binary:       bool,
    pub large:        bool,
    pub all:          bool,
    pub unrestricted: u8,

    // ---- output ---------------------------------------------------------
    pub no_color:       bool,
    pub jump:           bool,
    pub stats:          bool,

    // ---- matcher --------------------------------------------------------
    pub force_literal: bool,

    // ---- parallelism ----------------------------------------------------
    pub threads: NonZeroUsize,

    // ---- cache ----------------------------------------------------------
    pub no_cache:      bool,
    pub cache_size_mb: usize,
    pub cache_dir:     Option<Box<Path>>,
    pub rebuild_cache: bool,
}

impl RawGrepConfig {
    /// Minimal constructor, all optional fields use sensible defaults.
    pub fn new(pattern: impl Into<Box<str>>, search_root_path: impl Into<Box<str>>) -> Self {
        RawGrepConfig {
            pattern:          pattern.into(),
            search_root_path: search_root_path.into(),
            device:           None,
            no_ignore:        false,
            binary:           false,
            large:            false,
            all:              false,
            unrestricted:     0,
            no_color:         false,
            jump:             false,
            stats:            false,
            force_literal:    false,
            threads:          std::thread::available_parallelism()
                                  .unwrap_or(unsafe { NonZeroUsize::new_unchecked(1) }),
            no_cache:         false,
            cache_size_mb:    100,
            cache_dir:        Some(PathBuf::from("~/.cache/rawgrep").into()),  // @Cleanup
            rebuild_cache:    false,
        }
    }

    pub fn device(mut self, d: impl Into<Box<str>>)     -> Self { self.device = Some(d.into());    self }
    pub fn no_color(mut self)                           -> Self { self.no_color      = true;       self }
    pub fn jump(mut self)                               -> Self { self.jump          = true;       self }
    pub fn stats(mut self)                              -> Self { self.stats         = true;       self }
    pub fn all(mut self)                                -> Self { self.all           = true;       self }
    pub fn binary(mut self)                             -> Self { self.binary        = true;       self }
    pub fn no_ignore(mut self)                          -> Self { self.no_ignore     = true;       self }
    pub fn large(mut self)                              -> Self { self.large         = true;       self }
    pub fn force_literal(mut self)                      -> Self { self.force_literal = true;       self }
    pub fn no_cache(mut self)                           -> Self { self.no_cache      = true;       self }
    pub fn rebuild_cache(mut self)                      -> Self { self.rebuild_cache = true;       self }
    pub fn unrestricted(mut self, n: u8)                -> Self { self.unrestricted  = n;          self }
    pub fn threads(mut self, n: NonZeroUsize)           -> Self { self.threads    = n;             self }
    pub fn cache_size_mb(mut self, mb: usize)           -> Self { self.cache_size_mb = mb        ; self }
    pub fn cache_dir(mut self, d: impl Into<Box<Path>>) -> Self { self.cache_dir = Some(d.into()); self }

    #[inline]
    pub fn from_cli(c: cli::Cli) -> Self {
        RawGrepConfig {
            pattern:          c.pattern,
            search_root_path: c.search_root_path,
            device:           c.device,
            no_ignore:        c.no_ignore,
            binary:           c.binary,
            large:            c.large,
            all:              c.all,
            unrestricted:     c.unrestricted,
            no_color:         c.no_color,
            jump:             c.jump,
            stats:            c.stats,
            force_literal:    c.force_literal,
            threads:          c.threads,
            no_cache:         c.no_cache,
            cache_size_mb:    c.cache_size_mb,
            cache_dir:        c.cache_dir,
            rebuild_cache:    c.rebuild_cache,
        }
    }

    #[inline]
    pub fn to_cli(&self) -> cli::Cli {
        cli::Cli {
            pattern:          self.pattern.clone(),
            search_root_path: self.search_root_path.clone(),
            device:           self.device.clone(),
            no_ignore:        self.no_ignore,
            binary:           self.binary,
            large:            self.large,
            all:              self.all,
            unrestricted:     self.unrestricted,
            no_color:         self.no_color,
            jump:             self.jump,
            stats:            self.stats,
            force_literal:    self.force_literal,
            threads:          self.threads,
            no_cache:         self.no_cache,
            cache_size_mb:    self.cache_size_mb,
            cache_dir:        self.cache_dir.clone(),
            rebuild_cache:    self.rebuild_cache,
        }
    }
}

/// Run a search with the given configuration and sink.
///
/// # Arguments
///
/// * `config`  - what to search and how (see [`RawGrepConfig`])
/// * `running` - cancellation flag; store `false` to abort mid-search
/// * `sink`    - receives formatted match output; pass [`worker::NoSink`]
///               for the default stdout-printing behavior
#[inline]
pub fn run<S: MatchSink + 'static>(
    config: RawGrepConfig,
    running: Arc<AtomicBool>,
    sink: S,
) -> Result<Stats> {
    run_with_inspect(config, running, sink, |_, _, _, _| {})
}

#[inline]
pub fn run_with_inspect<S: MatchSink + 'static>(
    config: RawGrepConfig,
    running: Arc<AtomicBool>,
    sink: S,
    inspect_before_search: impl FnOnce(&Path, &str, FsType, &str) // (search root, device, fs, pattern)
) -> Result<Stats> {
    let threads = config.threads.get();
    let mut ctx = RawGrepCtx::new(threads, running);
    ctx.search(config, sink, inspect_before_search)?;
    Ok(ctx.wait_and_save_cache())
}

#[inline]
pub fn setup_signal_handler() -> Arc<AtomicBool> {
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
