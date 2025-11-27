use clap::Parser;

use crate::grep::BufferConfig;

// TODO: Flag to disable ANSI coloring
#[derive(Parser)]
#[command(
    name = "rawgrep",
    about = "The fastest grep in the world",
    long_about = None,
    version = "1.0",
    arg_required_else_help = true,
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
    /// -u: disable .gitignore filtering
    /// -uu: also disable binary file filtering
    /// -uuu: disable all filtering
    #[arg(short = 'u', long = "unrestricted", action = clap::ArgAction::Count)]
    pub unrestricted: u8,

    /// Don't respect .gitignore files
    #[arg(long = "no-ignore", conflicts_with = "unrestricted")]
    pub no_ignore: bool,

    /// Search binary files (don't skip them)
    #[arg(long = "binary", conflicts_with = "unrestricted")]
    pub binary: bool,

    /// Disable all filtering (search everything)
    ///
    /// Equivalent to -uuu or --no-ignore --binary --hidden
    #[arg(short = 'a', long = "all", conflicts_with = "unrestricted")]
    pub all: bool,
}

impl Cli {
    /// Returns true if .gitignore files should be ignored
    #[inline(always)]
    pub const fn should_ignore_gitignore(&self) -> bool {
        self.unrestricted >= 1 || self.no_ignore || self.all
    }

    /// Returns true if binary files should be searched
    #[inline(always)]
    pub const fn should_search_binary(&self) -> bool {
        self.unrestricted >= 2 || self.binary || self.all
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
                dir_name_buf: 16 * 1024,      // 16 KB - more directories to track
                dir_buf: 1024 * 1024,         // 1 MB - larger directory listings
                content_buf: 4 * 1024 * 1024, // 4 MB - reading more larger files
                gitignore_buf: 0,             // 0 KB - not using .gitignore
                extent_buf: 1024,             // Large files have more extents
            }
        } else {
            // Default filtered search: optimal for text files
            BufferConfig {
                dir_name_buf: 8 * 1024,      // 8 KB
                dir_buf: 256 * 1024,         // 256 KB
                content_buf: 1024 * 1024,    // 1 MB
                gitignore_buf: if self.should_ignore_gitignore() { 0 } else { 16 * 1024 },
                extent_buf: 256,             // Most text files fit in few extents
            }
        }
    }
}
