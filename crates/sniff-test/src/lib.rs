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
extern crate rustc_session;
extern crate rustc_span;

mod cache;
mod cli;
mod config;
mod contracts;
mod dependency_cache;
mod effect_tracker;
mod namespace;
mod panics;
mod report_roots;
mod safety;
mod source_markers;

pub use cli::{cargo_frontend, driver_main};
pub(crate) use contracts::EffectKind;
pub(crate) use effect_tracker::EffectSite;
