//! Reachability analysis over Rust function instances.
//!
//! This crate builds shared graph facts for functions and compiler artifacts
//! that are reachable in MIR/HIR. It records normal calls, tail calls,
//! function-pointer reification, dynamic object unsizing, vtable entries, const
//! bodies, compiler assertions, and indirect calls.
//!
//! The analysis is structural. It does not evaluate branch conditions or prove
//! that an edge is taken at runtime. A reported edge means the target is present
//! in the compiled body and should be considered possible by downstream policy
//! code.
//!
//! Create a [`ReachabilityIndex`] for a compiler context, then call
//! [`ReachabilityIndex::query`] for each root. The index stores root-independent
//! graph facts and caches expanded outgoing edges per instance. A
//! [`ReachabilitySnapshot`] is the per-root BFS result: it records reached nodes,
//! reached edges, depths, predecessor edges, per-instance expansion outcomes,
//! and the halt reason for one query.
//!
//! Use [`ReachabilityRoot::Instance`] when the caller already has a
//! monomorphized instance, or [`ReachabilityRoot::LocalBody`] to walk a local
//! body structurally. Generic local bodies are walked with identity generic
//! arguments; unresolved trait-dispatched calls are recorded as indirect
//! boundaries instead of guessed implementations. [`ReachabilityHooks`] can
//! observe nodes/edges, stop traversal, or prevent descending into selected
//! callees. [`ReachabilityOptions::artifact_scope`] can limit body expansion to
//! the crate containing the query root while retaining cross-artifact calls as
//! explicit frontier nodes.
//!
//! # Provenance
//!
//! This crate's reachability methodology was informed by
//! [Ferrocene](https://github.com/ferrocene/ferrocene). Its implementation
//! evolved from the original sniff-test reachability modules and has since
//! been substantially rewritten as a standalone crate. See the repository's
//! `ACKNOWLEDGMENTS.md` for details.

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
    ArtifactScope, DynDispatchVTableEdges, FnPointerEdges, IntoInstance, ReachabilityIndex,
    ReachabilityOptions, ReachabilityRoot,
};
pub use graph::{
    CallableEdgeInfo, CompilerAssertLocal, CompilerAssertLocalRole, ReachabilityEdge,
    ReachabilityEdgeId, ReachabilityEdgeKind, ReachabilityGraph, ReachabilityNode,
    ReachabilityNodeExpansion, ReachabilityNodeId, ReachabilityNodeKind, ReachabilitySnapshot,
    ReachabilityView, ReachedEdge, ReachedNode,
};
pub use hooks::{
    NoopReachabilityHooks, ReachabilityContext, ReachabilityControl, ReachabilityHalt,
    ReachabilityHooks, ReachabilityQueryStats,
};
