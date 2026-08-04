//! High-level sniff-test policy and checking behavior.
//!
//! This crate owns sniff-test's panic policy, rustc/Cargo integration,
//! reporting, and versioned on-disk analysis IR.
//!
//! Artifact IR stores policy-neutral semantic facts, such as compiler asserts
//! and panic invocations, rather than findings or rendered diagnostics. This
//! keeps cached dependency evidence reusable under different lint policies.

#![feature(rustc_private)]
#![deny(warnings)]
#![warn(clippy::pedantic)]

extern crate rustc_abi;
extern crate rustc_ast;
extern crate rustc_data_structures;
extern crate rustc_driver;
extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_metadata;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

mod analysis;
mod cli;
mod config;
mod contracts;
mod namespace;
mod panics;
mod path_patterns;
mod report_roots;
mod safety;
mod source_markers;

pub use cli::{cargo_frontend, driver_main};
