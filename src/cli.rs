use clap::Parser;

// TODO: Flag to disable ANSI coloring
// TODO: Three-level filtering flags
//   1: .gitignore filtering
//   2: binary ext filtering
//   3: binary probe filtering
#[derive(Parser)]
#[command(
    name = "rawgrep",
    about = "The fastest grep in the world",
    long_about = None,
    version = "1.0",
    arg_required_else_help = true,
    override_usage = "rawgrep <PATTERN> [PATH ...]"
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

    /// Print the stats at the end
    #[arg(short, long)]
    pub stats: bool,
}
