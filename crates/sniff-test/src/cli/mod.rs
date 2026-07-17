//! Executable plumbing for the sniff-test Cargo/rustc integration.

mod args;
mod cache_encode;
mod cargo;
mod diagnostics;
mod driver;
mod findings;
mod plugin;
mod report;
mod rustc_invocation;

fn display_error(error: &anyhow::Error) {
    eprintln!("error: {error:?}");
}

pub use self::args::SniffTestArgs;
pub use self::plugin::driver_main;

pub use self::cargo::cargo_frontend;
