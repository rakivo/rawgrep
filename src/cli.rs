use std::sync::OnceLock;
use std::num::NonZeroUsize;

use bpaf::Bpaf;

pub static SHOULD_ENABLE_ANSI_COLORING: OnceLock<bool> = OnceLock::new();

#[inline(always)]
pub fn should_enable_ansi_coloring() -> bool {
    SHOULD_ENABLE_ANSI_COLORING.get().copied().unwrap_or(false)
}

/// When to emit ANSI color codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorMode {
    Never,
    Always,
    #[default]
    Auto,
}

impl core::str::FromStr for ColorMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "never"  => Ok(ColorMode::Never),
            "always" => Ok(ColorMode::Always),
            "auto"   => Ok(ColorMode::Auto),
            other    => Err(format!(
                "invalid value '{other}' for --color (expected: never, always, auto)"
            )),
        }
    }
}

pub struct BufferConfig {
    pub output_buf: usize,
    pub dir_buf: usize,
    pub file_buf: usize,
    pub extent_buf: usize,
}

// TODO(#7): add -v / --invert-match (print non-matching lines)
// TODO(#5): add -w / --word-regexp
// TODO(#8): add -x / --line-regexp (match whole line)
// TODO(#9): add -s / --case-sensitive override if auto-detect ever added
// TODO(#11): add -n / --line-number
// TODO(#10): add -H / --with-filename
// TODO(#12): add -h / --no-filename
// TODO(#15): add -o / --only-matching
// TODO(#14): add -q / --quiet (stop after first match)
// TODO(#13): add --glob / --glob-case-insensitive / --type / --type-not
// TODO(#19): add --count (only count matches)
// TODO(#20): add --max-count N
// TODO(#21): add --files-with-matches / --files-without-match
// TODO(#22): add --json output mode for integration tools later
// TODO(#23): add --stats-extended (per-file timings, cache hit/miss)
#[derive(Bpaf, Clone)]
#[bpaf(options, version("0.2.0"))]
/// Grep at the speed of raw disk
pub struct Cli {
    /// Block device to read from (auto-detected if not specified)
    #[bpaf(short, long, argument("DEVICE"))]
    pub device: Option<String>,

    /// Print statistics at the end
    #[bpaf(short, long)]
    pub stats: bool,

    /// Reduce filtering (can be repeated)
    ///
    /// -u: disable size filtering
    /// -uu: also disable .gitignore filtering
    /// -uuu: disable all filtering, including  binary file filtering (by extension, probe)
    #[bpaf(short('u'), long("unrestricted"), req_flag(()), many, map(|v| v.len() as u8))]
    pub unrestricted: u8,

    /// The equivalent to surrounding every pattern with \b{start-half} and \b{end-half}.
    #[bpaf(short, long)]
    pub word_regexp: bool,

    /// Don't respect .gitignore files
    #[bpaf(long("no-ignore"))]
    pub no_ignore: bool,

    /// Don't ignore .gitignore files even if the current directory is not a git repository
    #[bpaf(long("no-require-git"))]
    pub no_require_git: bool,

    /// Search binary files (don't skip them)
    #[bpaf(long)]
    pub binary: bool,

    /// Search files and directories that start with "." (dont's skip them)
    #[bpaf(long)]
    pub hidden: bool,

    /// Search large files and large directories (don't skip them)
    /// Default FILE_MAX_SIZE is 8 MB and DIRECTORY_MAX_SIZE is 16 MB
    #[bpaf(long)]
    pub large: bool,

    /// Search directories usually reserved by tools, i.e. /node_modules, /__py_cache__, etc (Don't skip them)
    #[bpaf(long)]
    pub reserved_tool_dirs: bool,

    /// Disable all filtering (search everything)
    ///
    /// Equivalent to -uuu or --no-ignore --binary --hidden
    #[bpaf(short('a'), long("all"))]
    pub all: bool,

    /// Control when to emit colored output
    ///
    /// never: plain text always
    /// always: colored output even when piped
    /// auto: colored output only when stdout is a terminal (default)
    #[bpaf(long("color"), argument("WHEN"), fallback(ColorMode::Auto))]
    pub color: ColorMode,

    /// Print matches in conventional jumpable format (for VIM, EMACS, etc)
    #[bpaf(short, long)]
    pub jump: bool,

    /// Force `Matcher` to use literal search even if there's regex stuff in the pattern
    #[bpaf(short, long("force-literal"))]
    pub force_literal: bool,

    #[bpaf(short('i'), long("ignore-case"))]
    pub ignore_case: bool,

    /// Show line numbers (default when printing to a terminal)
    #[bpaf(short('n'), long("line-number"))]
    pub line_numbers: bool,

    /// Never show line numbers (overrides --line-number and any terminal auto-detection)
    #[bpaf(short('N'), long("no-line-number"))]
    pub no_line_numbers: bool,

    /// Number of worker threads to use
    ///
    /// Defaults to number of logical CPUs. Use fewer to reduce load,
    /// or increase to oversubscribe the machine.
    #[bpaf(
        short('t'),
        long("threads"),
        argument("THREADS"),
        fallback(crate::topology::default_worker_count())
    )]
    pub threads: NonZeroUsize,

    /// Disable fragment cache
    #[bpaf(long("no-cache"))]
    pub no_cache: bool,

    /// Disable binary verdicts cache
    #[bpaf(long("no-binary-cache"))]
    pub no_binary_cache: bool,

    /// Don't write/update cache
    #[bpaf(long("no-cache-write"))]
    pub no_cache_write: bool,

    /// Fragment cache memory budget in MB (default: 100)
    #[bpaf(long("cache-size"), argument("MB"), fallback(100))]
    pub cache_size_mb: usize,

    /// Cache directory // nocheckin (default: ~/.cache/rawgrep/)
    #[bpaf(long("cache-dir"), argument("DIR"), fallback(Some(crate::resolve_cache_dir())))]
    pub cache_dir: Option<std::path::PathBuf>,

    /// Ignore existing cache and rebuild from scratch
    #[bpaf(long("rebuild-cache"))]
    pub rebuild_cache: bool,

    /// Pattern to search for (supports regex syntax)
    #[bpaf(positional("PATTERN"))]
    pub pattern: String,

    /// Directory path to search in
    #[bpaf(positional("PATH"), fallback(".".into()))]
    pub search_root_path: String,

    #[bpaf(long("force-stdout-null"), fallback(false))]
    pub force_stdout_redirect_to_dev_null: bool,
}

impl Cli {
    #[inline(always)]
    pub fn parse() -> Self {
        cli().run()
    }

    #[inline(always)]
    pub fn enable_color(&self, is_tty: bool) -> bool {
        match self.color {
            ColorMode::Always => true,
            ColorMode::Never  => false,
            ColorMode::Auto   => is_tty
        }
    }

    /// Returns true if should search large files
    #[inline(always)]
    pub const fn should_ignore_size_filter(&self) -> bool {
        self.unrestricted >= 1 || self.large || self.all
    }

    /// Returns true if should search directories reserved by tools (See is_reserved_tool_dir)
    #[inline(always)]
    pub const fn should_ignore_reserved_tool_dir_filter(&self) -> bool {
        self.unrestricted >= 1 || self.reserved_tool_dirs
    }

    /// Returns true if .gitignore files should be ignored
    #[inline(always)]
    pub const fn should_ignore_gitignore(&self) -> bool {
        self.unrestricted >= 1 || self.no_ignore || self.all
    }

    /// Returns true if binary files should be searched
    #[inline(always)]
    pub const fn should_search_binary(&self) -> bool {
        self.unrestricted >= 3 || self.binary || self.all
    }

    /// Returns true if all filters should be disabled
    #[inline(always)]
    pub const fn should_ignore_all_filters(&self) -> bool {
        self.unrestricted >= 3 || self.all
    }

    /// Get optimized buffer sizes based on filtering settings
    #[inline]
    pub const fn get_buffer_config(&self) -> BufferConfig {
        if self.should_ignore_all_filters() || self.should_search_binary() {
            // Unfiltered search: processing MANY more LARGE files
            BufferConfig {
                dir_buf:  1 * 1024 * 1024,    // 1 MB
                file_buf: 2 * 1024 * 1024,    // 2 MB
                output_buf: 1 * 1024 * 1024,  // 1 MB
                extent_buf: 1024,             // Large files have more extents
            }
        } else {
            // Default filtered search: optimal for text files
            BufferConfig {
                dir_buf: 256 * 1024,          // 256 KB
                file_buf: 1 * 1024 * 1024,    // 1 MB
                output_buf: 256 * 1024,       // 256 KB
                extent_buf: 256,              // Most text files fit in few extents
            }
        }
    }
}
