use crate::grep::BufferConfig;

use std::sync::OnceLock;

use clap::Parser;

pub static SHOULD_ENABLE_ANSI_COLORING: OnceLock<bool> = OnceLock::new();

#[inline(always)]
pub fn should_enable_ansi_coloring() -> bool {
    SHOULD_ENABLE_ANSI_COLORING.get().copied().unwrap_or(false)
}

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
