//! Executable plumbing for the sniff-test Cargo/rustc integration.

mod args;
mod cargo;
mod driver;
mod plugin;

pub use self::plugin::driver_main;

pub use self::cargo::cargo_frontend;
