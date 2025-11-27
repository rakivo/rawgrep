#![allow(unused, unused_imports, dead_code, clippy::inline_always)]

pub use tracy_client::{span, plot, Client};

/// # Safety
/// The string must be static or otherwise live for the entire program,
/// as Tracy stores the pointer internally.
///
/// # Panics
/// If no Tracy client is currently running.
#[inline(always)]
pub unsafe fn set_thread_name(s: &str) {
    #[cfg(feature = "tracy")] {
        let c = Client::running().expect("set_thread_name without a running Client");
        c.set_thread_name(s);
    }
}

/// # Panics
/// If no Tracy client is currently running.
#[inline(always)]
pub fn message(s: &str) {
    #[cfg(feature = "tracy")] {
        let c = Client::running().expect("message without a running Client");
        c.message(s, 0);
    }
}

/// # Panics
/// If no Tracy client is currently running.
#[inline(always)]
pub fn message_color(s: &str, rgba: u32) {
    #[cfg(feature = "tracy")] {
        let c = Client::running().expect("message_collor without a running Client");
        c.color_message(s, rgba, 0);
    }
}

/// NOTE: This function leaks memory,
/// @Incomplete:
///   Fork `tracy_client` and expose internal module so we can stop leaking memory
///   each `create_plot` call.
///
/// # Safety
/// The string must be static or otherwise live for the entire program,
/// as Tracy stores the pointer internally.
#[inline(always)]
pub fn create_plot(name: &str) -> tracy_client::PlotName {
    tracy_client::PlotName::new_leak(name.into())
}

/// Record a plot sample for the given plot name.
///
/// # Panics
/// If no Tracy client is currently running.
#[inline(always)]
pub fn plot_value(plot: tracy_client::PlotName, value: f64) {
    #[cfg(feature = "tracy")] {
        Client::running()
            .expect("plot_value called without a running Client")
            .plot(plot, value);
    }
}

/// Record a one-off plot value for a string name (creates plot if needed).
///
/// # Panics
/// If no Tracy client is currently running.
#[inline(always)]
pub fn plot_named(name: &str, value: f64) {
    #[cfg(feature = "tracy")] {
        let client = Client::running().expect("plot_named called without a running Client");
        let plot_name = tracy_client::PlotName::new_leak(name.into());
        client.plot(plot_name, value);
    }
}
