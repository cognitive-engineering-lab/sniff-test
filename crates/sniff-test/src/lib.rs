//! High-level sniff-test policy and checking behavior.
//!
//! This crate owns the reusable parts of sniff-test: configuration, panic
//! evidence classification, report-root selection, and the on-disk analysis
//! cache. The `sniff-test-cli` crate is expected to provide rustc/Cargo
//! plumbing and terminal rendering.
//!
//! The cache stores semantic facts, such as "compiler assert" or "panic
//! invocation", rather than pre-rendered text with ANSI styling. That keeps
//! cached dependency evidence reusable under different reporting and color
//! policies.

#![feature(rustc_private)]
#![deny(warnings)]
#![warn(clippy::pedantic)]

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

pub mod cache;
pub mod config;
pub mod dependency_cache;
pub mod namespace;
pub mod panics;
pub mod report_roots;
