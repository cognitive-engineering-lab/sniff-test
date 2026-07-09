//! High-level sniff-test policy and checking behavior.
//!
//! This crate owns sniff-test's panic policy, rustc/Cargo integration,
//! reporting, and on-disk analysis cache.
//!
//! The cache stores semantic facts, such as "compiler assert" or "panic
//! invocation", rather than pre-rendered text with ANSI styling. That keeps
//! cached dependency evidence reusable under different reporting and color
//! policies.

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
extern crate rustc_middle;
extern crate rustc_span;

pub mod cache;
mod cli;
pub mod config;
mod contracts;
pub mod dependency_cache;
pub mod namespace;
pub mod panics;
pub mod report_roots;
pub mod safety;
pub mod source_markers;

pub use cli::{SniffTestArgs, cargo_frontend, driver_main};
