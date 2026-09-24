#![cfg_attr(all(nightly, feature = "use_nightly"), allow(internal_features))]
#![cfg_attr(all(nightly, feature = "use_nightly"), feature(core_intrinsics, portable_simd))]

#![allow(
    clippy::identity_op,
    clippy::collapsible_if,
    clippy::module_inception,
    clippy::new_without_default,
    clippy::explicit_counter_loop,
    clippy::only_used_in_recursion,
    clippy::doc_overindented_list_items,
)]

#[cfg(all(feature = "dont_vendor", feature = "generic-simd"))]
compile_error!(
    "'dont_vendor' + 'generic-simd' pulls in upstream 'bytecount's SIMD code, which \
     still calls portable_simd APIs (e.g. 'Mask::to_int') removed on recent nightlies. \
     The vendored fork in 'src/bytecount_vendor' has already been patched for this, drop \
     'dont_vendor' to use it, or wait for upstream bytecount to catch up to current nightly."
);

pub mod ctx;
pub mod cli;
pub mod stale;
pub mod binary_verdicts;
pub mod grep;
pub mod ext4;
pub mod ctrl_c;
pub mod apfs;
pub mod ntfs;
pub mod util;
pub mod stats;
pub mod tracy;
pub mod stdout;
pub mod ignore;
pub mod color;
pub mod parser;
pub mod error;
pub mod worker;
pub mod binary;
pub mod matcher;
pub mod path_buf;
pub mod cache;
pub mod pacer;
pub mod fragments;
pub mod platform;
pub mod output;
pub mod topology;
pub mod thin_path_arc;
pub mod binary_ext;
pub mod extractor;
pub mod liner;
pub mod unwrap_;
pub mod index_;
pub mod logger;
#[cfg(unix)] pub mod run_temperature;
#[cfg(unix)] pub mod holder;

#[cfg(not(feature = "dont_vendor"))]
pub mod smallvec_vendor;
#[cfg(not(feature = "dont_vendor"))]
pub use smallvec_vendor as smallvec;

#[cfg(not(feature = "dont_vendor"))]
pub mod bytecount_vendor;
#[cfg(not(feature = "dont_vendor"))]
pub use bytecount_vendor as bytecount;

#[cfg(feature = "dont_vendor")]
pub use bytecount;
#[cfg(feature = "dont_vendor")]
pub use smallvec;

pub use crossbeam_channel;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
pub use stats::Stats;
pub use cache::CacheStats;
pub use grep::RawGrepper;
pub use ctx::RawGrepCtx;

use grep::FsType;
use worker::MatchSink;

pub const CURSOR_HIDE:   &str = "\x1b[?25l";
pub const CURSOR_UNHIDE: &str = "\x1b[?25h";

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
    pub should_ignore_reserved_tool_dir_filter: bool,
    pub all:          bool,
    pub unrestricted: u8,
    pub hidden:       bool,
    pub word_regexp:  bool,
    pub no_require_git:bool,

    // ---- output ---------------------------------------------------------
    pub line_numbers:   bool,
    pub no_line_numbers:bool,
    pub color:          cli::ColorMode,
    pub jump:           bool,
    pub stats:          bool,

    // ---- matcher --------------------------------------------------------
    pub force_literal: bool,
    pub ignore_case: bool,
    // ---- parallelism ----------------------------------------------------
    pub threads: NonZeroUsize,

    // ---- cache ----------------------------------------------------------
    pub no_cache:      bool,
    pub no_binary_cache:bool,
    pub no_cache_write:bool,
    pub cache_size_mb: usize,
    pub cache_dir:     Option<Box<Path>>,
    pub rebuild_cache: bool,

    pub force_stdout_redirect_to_dev_null: bool,
}

impl RawGrepConfig {
    /// Minimal constructor, all optional fields use sensible defaults.
    pub fn new(pattern: impl Into<Box<str>>, search_root_path: impl Into<Box<str>>) -> Self {
        RawGrepConfig {
            no_binary_cache:  false,
            pattern:          pattern.into(),
            search_root_path: search_root_path.into(),
            device:           None,
            hidden:           false,
            no_ignore:        false,
            force_stdout_redirect_to_dev_null: false,
            binary:           false,
            large:            false,
            no_cache_write:   false,
            all:              false,
            unrestricted:     0,
            color:            cli::ColorMode::Auto,
            jump:             false,
            stats:            false,
            no_require_git:   false,
            word_regexp:      false,
            force_literal:    false,
            ignore_case:      false,
            no_line_numbers:  false,
            line_numbers:     true,
            should_ignore_reserved_tool_dir_filter: false,
            threads: crate::topology::default_worker_count(),
            no_cache:         false,
            cache_size_mb:    100,
            cache_dir:        Some(resolve_cache_dir().into_boxed_path()),  // @Cleanup
            rebuild_cache:    false,
        }
    }

    pub fn device(mut self, d: impl Into<Box<str>>)     -> Self { self.device = Some(d.into());    self }
    pub fn color(mut self, mode: cli::ColorMode)        -> Self { self.color      = mode;       self }
    pub fn no_require_git(mut self)                     -> Self { self.no_require_git          = true;       self }
    pub fn word_regexp(mut self)                        -> Self { self.word_regexp          = true;       self }
    pub fn jump(mut self)                               -> Self { self.jump          = true;       self }
    pub fn stats(mut self)                              -> Self { self.stats         = true;       self }
    pub fn line_numbers(mut self)                       -> Self { self.line_numbers         = true;       self }
    pub fn no_line_numbers(mut self)                    -> Self { self.no_line_numbers         = true;       self }
    pub fn all(mut self)                                -> Self { self.all           = true;       self }
    pub fn binary(mut self)                             -> Self { self.binary        = true;       self }
    pub fn no_ignore(mut self)                          -> Self { self.no_ignore     = true;       self }
    pub fn large(mut self)                              -> Self { self.large         = true;       self }
    pub fn should_ignore_reserved_tool_dir_filter(mut self)->Self{ self.should_ignore_reserved_tool_dir_filter = true; self }
    pub fn force_literal(mut self)                      -> Self { self.force_literal = true;       self }
    pub fn ignore_case(mut self)                        -> Self { self.ignore_case = true;         self }
    pub fn no_cache(mut self)                           -> Self { self.no_cache      = true;       self }
    pub fn no_cache_write(mut self)                     -> Self { self.no_cache_write= true;       self }
    pub fn rebuild_cache(mut self)                      -> Self { self.rebuild_cache = true;       self }
    pub fn unrestricted(mut self, n: u8)                -> Self { self.unrestricted  = n;          self }
    pub fn threads(mut self, n: NonZeroUsize)           -> Self { self.threads    = n;             self }
    pub fn cache_size_mb(mut self, mb: usize)           -> Self { self.cache_size_mb = mb        ; self }
    pub fn cache_dir(mut self, d: impl Into<Box<Path>>) -> Self { self.cache_dir = Some(d.into()); self }

    #[inline]
    pub fn from_cli(c: cli::Cli) -> Self {
        RawGrepConfig {
            no_binary_cache:  c.no_binary_cache,
            should_ignore_reserved_tool_dir_filter: c.should_ignore_reserved_tool_dir_filter(),
            pattern:          c.pattern.into_boxed_str(),
            search_root_path: c.search_root_path.into_boxed_str(),
            device:           c.device.map(Into::into),
            no_ignore:        c.no_ignore,
            no_require_git:   c.no_require_git,
            binary:           c.binary,
            large:            c.large,
            hidden:           c.hidden,
            all:              c.all,
            no_line_numbers:  c.no_line_numbers,
            line_numbers:     c.line_numbers,
            word_regexp:      c.word_regexp,
            no_cache_write:   c.no_cache_write,
            unrestricted:     c.unrestricted,
            color:            c.color,
            jump:             c.jump,
            stats:            c.stats,
            force_literal:    c.force_literal,
            ignore_case:      c.ignore_case,
            force_stdout_redirect_to_dev_null: c.force_stdout_redirect_to_dev_null,
            threads:          c.threads,
            no_cache:         c.no_cache,
            cache_size_mb:    c.cache_size_mb,
            cache_dir:        c.cache_dir.map(Into::into),
            rebuild_cache:    c.rebuild_cache,
        }
    }

    #[inline]
    pub fn to_cli(&self) -> cli::Cli {
        cli::Cli {
            no_binary_cache:  self.no_binary_cache,
            hidden:           self.hidden,
            no_cache_write:   self.no_cache_write,
            force_stdout_redirect_to_dev_null: self.force_stdout_redirect_to_dev_null,
            reserved_tool_dirs: self.should_ignore_reserved_tool_dir_filter,
            pattern:          self.pattern.clone().into_string(),
            search_root_path: self.search_root_path.clone().into_string(),
            device:           self.device.clone().map(String::from),
            no_ignore:        self.no_ignore,
            binary:           self.binary,
            line_numbers:     self.line_numbers,
            no_line_numbers:  self.no_line_numbers,
            no_require_git:   self.no_require_git,
            large:            self.large,
            all:              self.all,
            unrestricted:     self.unrestricted,
            word_regexp:      self.word_regexp,
            color:            self.color,
            jump:             self.jump,
            stats:            self.stats,
            force_literal:    self.force_literal,
            ignore_case:      self.ignore_case,
            threads:          self.threads,
            no_cache:         self.no_cache,
            cache_size_mb:    self.cache_size_mb,
            cache_dir:        self.cache_dir.clone().map(std::path::PathBuf::from),
            rebuild_cache:    self.rebuild_cache,
        }
    }

    #[inline(always)]
    pub fn enable_color(&self, is_tty: bool) -> bool {
        match self.color {
            cli::ColorMode::Always => true,
            cli::ColorMode::Never  => false,
            cli::ColorMode::Auto   => is_tty
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
) -> Result<(Stats, Option<CacheStats>)> {
    run_with_inspect(config, running, sink, |_, _, _, _| {})
}

#[inline]
pub fn run_with_inspect<S: MatchSink + 'static>(
    config: RawGrepConfig,
    running: Arc<AtomicBool>,
    sink: S,
    inspect_before_search: impl FnOnce(&Path, &str, FsType, &str) // (search root, device, fs, pattern)
) -> Result<(Stats, Option<CacheStats>)> {
    let mut ctx = RawGrepCtx::new(config.threads.get(), running);
    ctx.search(&config, sink, inspect_before_search)?;
    Ok(ctx.wait_and_save_cache(&config))
}

#[inline]
pub fn run_with_inspect_for_single_search<S: MatchSink + 'static>(
    config: RawGrepConfig,
    running: Arc<AtomicBool>,
    sink: S,
    inspect_before_search: impl FnOnce(&Path, &str, FsType, &str) // (search root, device, fs, pattern)
) -> Result<(Stats, Option<CacheStats>)> {
    let mut ctx = RawGrepCtx::new_for_single_search(
        config.threads.get(), running, &config,
        sink, inspect_before_search
    )?;
    let (stats, cstats) = ctx.wait_and_save_cache(&config);
    Ok((stats, cstats))
}

pub use ctrl_c::setup_signal_handler;

use std::sync::atomic::AtomicUsize;

static CURSOR_HIDDEN_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
pub struct CursorHide;

impl CursorHide {
    #[inline]
    pub fn new() -> io::Result<Self> {
        // fetch_add returns the PREVIOUS value; if it was 0, we're the
        // first handle in, so we're the one that actually hides the cursor.
        if CURSOR_HIDDEN_COUNT.fetch_add(1, Ordering::AcqRel) == 0 {
            let mut out = io::stdout().lock();
            out.write_all(CURSOR_HIDE.as_bytes())?;
            out.flush()?;
        }

        Ok(CursorHide)
    }
}

impl Drop for CursorHide {
    #[inline]
    fn drop(&mut self) {
        // fetch_sub returns the PREVIOUS value; if it was 1, we just brought
        // it to 0, so we're the last handle out and should restore the cursor.
        if CURSOR_HIDDEN_COUNT.fetch_sub(1, Ordering::AcqRel) == 1 {
            let mut out = io::stdout().lock();
            _ = out.write_all(CURSOR_UNHIDE.as_bytes());
            _ = out.flush();
        }
    }
}

pub fn find_git_boundary(start: &Path) -> bool {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    let Ok(start_meta) = std::fs::symlink_metadata(start) else {
        return false;
    };

    #[cfg(unix)]
    let start_dev = start_meta.dev();

    let mut current = start;

    loop {
        if std::fs::symlink_metadata(current.join(".git")).is_ok() {
            return true;
        }

        let Some(parent) = current.parent() else {
            return false;
        };

        let Ok(parent_meta) = std::fs::symlink_metadata(parent) else {
            return false;
        };

        #[cfg(unix)]
        if parent_meta.dev() != start_dev {
            // Crossed a mount boundary, stop here same as rg does
            return false;
        }

        current = parent;
    }
}

#[cfg(target_os = "linux")]
pub fn resolve_cache_dir() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("rawgrep");
    }
    let uid = unsafe { libc::getuid() };

    PathBuf::from(format!("/dev/shm/rawgrep-{uid}"))
}

#[cfg(not(target_os = "linux"))]
pub fn resolve_cache_dir() -> PathBuf {
    get_default_disk_cache_dir() // whatever get_cache_path falls back to today
}
