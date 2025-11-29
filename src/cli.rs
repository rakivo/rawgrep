use crate::grep::BufferConfig;

use std::sync::OnceLock;
use std::num::NonZeroUsize;

use clap::Parser;

pub static SHOULD_ENABLE_ANSI_COLORING: OnceLock<bool> = OnceLock::new();

#[inline(always)]
pub fn should_enable_ansi_coloring() -> bool {
    SHOULD_ENABLE_ANSI_COLORING.get().copied().unwrap_or(false)
}

// TODO(#7): add -v / --invert-match (print non-matching lines)
// TODO(#6): add -i / --ignore-case
// TODO(#5): add -w / --word-regexp
// TODO(#8): add -x / --line-regexp (match whole line)
// TODO(#9): add -s / --case-sensitive override if auto-detect ever added
// TODO(#11): add -n / --line-number
// TODO(#10): add -H / --with-filename
// TODO(#12): add -h / --no-filename
// TODO(#15): add -o / --only-matching
// TODO(#14): add -q / --quiet (stop after first match)
// TODO(#13): add --glob / --glob-case-insensitive / --type / --type-not
// TODO(#16): add color modes: auto|never|always
// TODO(#17): detect TTY for default color behavior
// TODO(#18): add --threads N to override thread count
// TODO(#19): add --count (only count matches)
// TODO(#20): add --max-count N
// TODO(#21): add --files-with-matches / --files-without-match
// TODO(#22): add --json output mode for integration tools later
// TODO(#23): add --stats-extended (per-file timings, cache hit/miss)
#[derive(Parser)]
#[command(
    name = "rawgrep",
    about = "The fastest grep in the world",
    long_about = None,
    version = "1.0",
    arg_required_else_help = true,
    override_usage = "<PATTERN> [PATH ...]"
)]
pub struct Cli {
    /// Pattern to search for (supports regex syntax)
    #[arg(value_name = "PATTERN")]
    pub pattern: String,

    /// Directory path to search in
    #[arg(value_name = "PATH", default_value = ".")]
    pub search_root_path: String,

    /// Block device to read from (auto-detected if not specified)
    #[arg(short, long, value_name = "DEVICE")]
    pub device: Option<String>,

    /// Print statistics at the end
    #[arg(short, long)]
    pub stats: bool,

    /// Reduce filtering (can be repeated)
    ///
    /// -u: disable size filtering
    /// -uu: also disable .gitignore filtering
    /// -uuu: disable all filtering, including  binary file filtering (by extension, probe)
    #[arg(short = 'u', long = "unrestricted", action = clap::ArgAction::Count)]
    pub unrestricted: u8,

    /// Don't respect .gitignore files
    #[arg(long = "no-ignore", conflicts_with = "unrestricted")]
    pub no_ignore: bool,

    /// Search binary files (don't skip them)
    #[arg(long = "binary", conflicts_with = "unrestricted")]
    pub binary: bool,

    /// Search large files and large directories (don't skip them)
    /// Default FILE_MAX_SIZE is 8 MB and DIRECTORY_MAX_SIZE is 16 MB
    #[arg(long, conflicts_with = "unrestricted")]
    pub large: bool,

    /// Disable all filtering (search everything)
    ///
    /// Equivalent to -uuu or --no-ignore --binary --hidden
    #[arg(short = 'a', long = "all", conflicts_with = "unrestricted")]
    pub all: bool,

    /// Disable colored output (force plain text)
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Print matches in conventional jumpable format (for VIM, EMACS, etc)
    #[arg(short, long)]
    pub jump: bool,

    /// Force `Matcher` to use literal search even if there's regex stuff in the pattern
    #[arg(short, long = "force-literal")]
    pub force_literal: bool,

    /// Number of worker threads to use
    ///
    /// Defaults to number of logical CPUs. Use fewer to reduce load,
    /// or increase to oversubscribe the machine.
    #[arg(
        short = 't',
        long = "threads",
        default_value_t = std::thread::available_parallelism()
            .unwrap_or(unsafe { NonZeroUsize::new_unchecked(1) })
    )]
    pub threads: NonZeroUsize,
}

impl Cli {
    #[inline(always)]
    pub fn parse() -> Self {
        let cli = <Self as Parser>::parse();

        _ = SHOULD_ENABLE_ANSI_COLORING.set(!cli.no_color);

        cli
    }

    /// Returns true if should search large files
    #[inline(always)]
    pub const fn should_ignore_size_filter(&self) -> bool {
        self.unrestricted >= 1 || self.large || self.all
    }

    /// Returns true if .gitignore files should be ignored
    #[inline(always)]
    pub const fn should_ignore_gitignore(&self) -> bool {
        self.unrestricted >= 2 || self.no_ignore || self.all
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
                dir_buf: 1 * 1024 * 1024,     // 1 MB
                file_buf: 4 * 1024 * 1024,    // 4 MB
                output_buf: 2 * 1024 * 1024,  // 2 MB
                gitignore_buf: 0,             // 0 KB - not using .gitignore
                extent_buf: 1024,             // Large files have more extents
            }
        } else {
            // Default filtered search: optimal for text files
            BufferConfig {
                dir_buf: 256 * 1024,          // 256 KB
                file_buf: 1 * 1024 * 1024,    // 1 MB
                output_buf: 1 * 1024 * 1024,  // 1 MB
                gitignore_buf: if self.should_ignore_gitignore() { 0 } else { 16 * 1024 },
                extent_buf: 256,              // Most text files fit in few extents
            }
        }
    }
}
