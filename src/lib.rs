#![cfg_attr(all(nightly, feature = "use_nightly"), allow(internal_features))]
#![cfg_attr(all(nightly, feature = "use_nightly"), feature(core_intrinsics))]

#![allow(
    clippy::identity_op,
    clippy::collapsible_if,
    clippy::module_inception,
    clippy::only_used_in_recursion
)]

#[cfg(all(feature = "small", feature = "full"))]
compile_error!("Cannot enable both `small` and `full` features - choose one!");

#[cfg(not(any(feature = "small", feature = "full")))]
compile_error!("Must enable either `small` or `full` feature!");

#[cfg(all(feature = "mimalloc", feature = "dhat"))]
compile_error!("Cannot enable both `mimalloc` and `dhat` allocators - choose one!");

#[cfg(all(feature = "mimalloc", not(feature = "dhat")))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(feature = "dhat", not(feature = "mimalloc")))]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

pub mod cli;
pub mod grep;
pub mod ext4;
pub mod util;
pub mod stats;
pub mod tracy;
pub mod ignore;
pub mod parser;
pub mod worker;
pub mod binary;
pub mod matcher;
pub mod path_buf;
pub mod cache;
pub mod fragments;
pub mod platform;

#[cfg(feature = "small")]
pub extern crate regex_tiny as regex;
#[cfg(feature = "small")]
pub extern crate clap_tiny as clap;

#[cfg(not(feature = "small"))]
pub(crate) extern crate regex_full as regex;
#[cfg(not(feature = "small"))]
pub(crate) extern crate clap_full as clap;

use smallvec::SmallVec;

pub const COLOR_RED: &str = "\x1b[1;31m";
pub const COLOR_GREEN: &str = "\x1b[1;32m";
pub const COLOR_BLUE: &str = "\x1b[1;34m";
pub const COLOR_CYAN: &str = "\x1b[1;36m";
pub const COLOR_RESET: &str = "\x1b[0m";

pub const CURSOR_HIDE: &str = "\x1b[?25l";
pub const CURSOR_UNHIDE: &str = "\x1b[?25h";

/// Helper used to indicate that we copy some amount of copiable data (bytes) into a newly allocated memory
#[inline(always)]
pub fn copy_data<A, T>(bytes: &[T]) -> SmallVec<A>
where
    A: smallvec::Array<Item = T>,
    T: Copy
{
    SmallVec::from_slice(bytes)
}

