#[cfg(all(feature = "mimalloc", feature = "dhat"))]
compile_error!("Cannot enable both `mimalloc` and `dhat` allocators - choose one!");

#[cfg(all(feature = "mimalloc", not(feature = "dhat")))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(feature = "dhat", not(feature = "mimalloc")))]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use rawgrep::cli::Cli;
use rawgrep::sink::NoSink;
use rawgrep::{Error, RawGrepConfig, eprint_blue, eprint_green, eprintln_red};

fn main() {
    #[cfg(unix)]
    rawgrep::holder::run_if_holder();

    _ = rawgrep::platform::set_process_priority(-10);

    #[cfg(feature = "dhat")]
    let _profiler = dhat::Profiler::new_heap();

    #[cfg(feature = "mimalloc")]
    mi_tuning::apply();

    let cli = Cli::parse();
    let show_stats = cli.stats;

    match rawgrep::run_with_inspect_for_single_search(
        RawGrepConfig::from_cli(cli),
        rawgrep::setup_signal_handler(),
        NoSink,
        |search_root, device, fs, pattern| {
            eprint_blue!("Searching ");
            eprint_green!("'{search_root}' ", search_root = search_root.display());
            eprint_blue!("on device ");
            eprint_green!("'{device}' ");
            eprint_blue!("with fs ");
            eprint_green!("{fs:?} ");
            eprint_blue!("for pattern ");
            eprintln_red!("{b}{pattern}", b = rawgrep::color::BOLD);
        }
    ) {
        Ok((stats, cache_stats)) => {
            if show_stats {
                eprintln!("{stats}");
                if let Some(cache_stats) = cache_stats {
                    eprintln!("{cache_stats}");
                }
            }
        }

        Err(e) => {
            eprintln_red!("error: {e}");
            std::process::exit(exit_code(&e))
        }
    }
}

#[inline]
const fn exit_code(e: &Error) -> i32 {
    match e {
        Error::PermissionDenied(_)   => 77, // EX_NOPERM

        Error::DeviceNotFound(_)
        | Error::PathNotFound { .. }
        | Error::RootNotFound { .. } => 66, // EX_NOINPUT

        Error::InvalidPattern(_)     => 2,  // misuse of shell builtins (grep convention)

        _                            => 1,
    }
}

#[cfg(feature = "mimalloc")]
#[allow(non_camel_case_types)]
mod mi_tuning {
    use libmimalloc_sys as mi;
    use std::os::raw::c_long;

    // Not exported by libmimalloc-sys v0.1.44...
    const MI_OPTION_PURGE_DELAY: mi::mi_option_t = 15;

    struct Option_Setting {
        id: mi::mi_option_t,
        value: c_long,
    }

    const SETTINGS: &[Option_Setting] = &[
        Option_Setting { id: MI_OPTION_PURGE_DELAY, value: -1 },
    ];

    pub fn apply() {
        for s in SETTINGS {
            unsafe { mi::mi_option_set(s.id, s.value); }
        }
    }

    extern "C" fn init() { apply(); }

    #[used]
    #[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
    static INIT: extern "C" fn() = init;
}
