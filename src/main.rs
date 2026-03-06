#[cfg(all(feature = "mimalloc", feature = "dhat"))]
compile_error!("Cannot enable both `mimalloc` and `dhat` allocators - choose one!");

#[cfg(all(feature = "mimalloc", not(feature = "dhat")))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(feature = "dhat", not(feature = "mimalloc")))]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use rawgrep::cli::Cli;
use rawgrep::worker::NoSink;
use rawgrep::{CursorHide, Error, RawGrepConfig, eprint_blue, eprint_green, eprintln_red};

use std::io;

fn main() -> io::Result<()> {
    #[cfg(feature = "dhat")]
    let _profiler = dhat::Profiler::new_heap();

    rawgrep::util::init_logging();

    _ = rawgrep::platform::set_process_priority(-10);

    let cli = Cli::parse();
    let show_stats = cli.stats;

    let _cur = CursorHide::new();

    match rawgrep::run_with_inspect(
        RawGrepConfig::from_cli(cli),
        rawgrep::setup_signal_handler(),
        NoSink,
        |search_root, device, fs, pattern| {
            eprint_blue!("Searching ");
            eprint_green!("'{search_root}' ", search_root = search_root.display());
            eprint_blue!("on device ");
            eprint_green!("'{device}' ");
            eprint_blue!("with fs ");
            eprint_green!("'{fs:?}' ");
            eprint_blue!("for pattern: ");
            eprintln_red!("'{pattern}'");
        }
    ) {
        Ok(stats) => {
            if show_stats {
                eprintln!("{stats}");
            }

            Ok(())
        }

        Err(e) => {
            eprintln_red!("error: {e}");
            std::process::exit(exit_code(&e));
        }
    }
}

#[inline]
const fn exit_code(e: &Error) -> i32 {
    match e {
        Error::PermissionDenied(_)  => 77, // EX_NOPERM

        Error::DeviceNotFound(_)
        | Error::PathNotFound { .. }
        | Error::RootNotFound { .. } => 66, // EX_NOINPUT

        Error::InvalidPattern(_)    => 2,  // misuse of shell builtins (grep convention)

        _                           => 1,
    }
}
