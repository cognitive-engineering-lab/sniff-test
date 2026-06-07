//! Reachability analysis over concrete Rust function instances.
//!
//! This crate builds a graph from a root function to the functions and compiler
//! artifacts that are reachable in MIR/HIR. It records normal calls, tail calls,
//! function-pointer reification, closure definitions, dynamic object unsizing,
//! vtable entries, const bodies, compiler assertions, and indirect calls.
//!
//! The analysis is structural. It does not evaluate branch conditions or prove
//! that an edge is taken at runtime. A reported edge means the target is present
//! in the compiled body and should be considered possible by downstream policy
//! code.
//!
//! Generic roots require a concrete [`rustc_middle::ty::Instance`]. Use
//! [`ReachabilityRoot::Instance`] when the caller already has a monomorphized
//! instance, or [`ReachabilityRoot::LocalBody`] for non-generic local items.
//! [`ReachabilityHooks`] can observe nodes/edges, stop traversal, or prevent
//! descending into selected callees.

#![feature(rustc_private)]
#![deny(warnings)]
#![warn(clippy::pedantic)]

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

mod analysis;
mod body;
mod graph;
mod hooks;

pub use analysis::{
    ReachabilityOptions, ReachabilityRoot, analyze_local_reachability, analyze_reachability,
};
pub use graph::{
    ReachabilityEdge, ReachabilityEdgeKind, ReachabilityGraph, ReachabilityNode,
    ReachabilityNodeId, ReachabilityNodeKind,
};
pub use hooks::{
    NoopReachabilityHooks, ReachabilityContext, ReachabilityControl, ReachabilityHalt,
    ReachabilityHooks,
};
