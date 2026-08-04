//! Executable plumbing for the sniff-test Cargo/rustc integration.

mod args;
mod cargo;
mod diagnostics;
mod driver;
mod findings;
mod plugin;
mod report;

pub use self::plugin::driver_main;

pub use self::cargo::cargo_frontend;
