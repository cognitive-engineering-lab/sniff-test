//! Shared extraction and effect analysis for sniff-test.
//!
//! The core extracts versioned facts from rustc, tracks obligations through
//! invocations, and returns structured findings. Effect definitions are
//! supplied by callers. Graph propagation remains in `effect-tracing`, and
//! output rendering remains in `sniff-test-diagnostics`.
//!
//! Artifact facts store policy-neutral semantic facts, such as call edges,
//! compiler-assert kinds, unsafe operations, contracts, and source markers,
//! rather than findings or rendered diagnostics. This keeps dependency
//! facts reusable under different lint policies.

#![feature(rustc_private)]
#![deny(warnings)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "workspace-facing analysis APIs retain their existing error and panic contracts"
)]

extern crate rustc_abi;
extern crate rustc_ast;
extern crate rustc_data_structures;
extern crate rustc_hir;
extern crate rustc_metadata;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

pub mod analysis;
pub mod annotations;
pub mod artifact;
pub mod artifact_cache;
pub mod compiler;
pub mod config;
pub mod contracts;
pub mod effects;
pub mod namespace;
pub mod path_patterns;
pub mod report;
pub mod report_model;
pub mod report_roots;
pub mod source_markers;
pub mod workspace;
