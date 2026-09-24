//! Cargo subcommand and rustc driver for sniff-test.
//!
//! The executable selects built-in effects, connects rustc to the analysis
//! crates, and passes structured findings to the report crate.

#![feature(rustc_private)]
#![deny(warnings)]
#![warn(clippy::pedantic)]

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_metadata;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

mod cli;

pub use cli::{cargo_frontend, driver_main};
