//! Rust compiler probing and reporting for first-class panic and safety
//! effects.
//!
//! This crate owns sniff-test's panic and safety policies, rustc/Cargo
//! integration, reporting, and versioned on-disk artifact facts. Shared graph
//! traversal lives in the compiler-independent `effect-tracing` crate.
//!
//! HIR, THIR, and MIR passes discover concrete seeds. Shared obligation
//! tracking then parses contracts and justifications, replaces concrete
//! carriers with contract carriers at documented boundaries, and traces both
//! through incoming source-level invocations.
//!
//! Artifact facts store policy-neutral semantic facts, such as call edges,
//! compiler-assert kinds, unsafe operations, contracts, and source markers,
//! rather than findings or rendered diagnostics. This keeps dependency
//! facts reusable under different lint policies.

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

mod annotations;
mod artifact;
mod artifact_cache;
mod cli;
mod compiler;
mod config;
mod contracts;
mod effects;
mod namespace;
mod path_patterns;
mod report;
mod report_model;
mod report_roots;
mod source_markers;
mod workspace;

pub use cli::{cargo_frontend, driver_main};
