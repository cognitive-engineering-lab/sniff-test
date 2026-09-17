//! Shared, compiler-independent effect tracing.
//!
//! A [`TracePolicy`] defines where an effect starts, how carriers hand off at
//! function boundaries, how state changes across propagation edges, and where
//! a path terminates. [`EffectEngine`] supplies reverse-invocation traversal,
//! transparent-body traversal, path splitting and convergence, state-aware
//! cycle detection, resource limits, and trace recording. Panic and safety
//! seed semantics deliberately live outside this crate.

mod effect;
mod engine;
mod graph;
mod trace;

pub use effect::{EffectSeed, Propagation, PropagationEdge, TraceCx, TracePolicy, TraceSite};
pub use engine::{EffectEngine, TraceOptions};
pub use graph::{
    EffectGraph, FunctionId, InvocationId, TransparentBodyEdgeId, UnknownBoundary,
    UnknownBoundaryKind,
};
pub use trace::{
    EffectTrace, HandledTrace, TerminationSite, TraceEdge, TraceEdgeId, TraceNode, TraceNodeId,
    TraceOutcome, UnknownTrace,
};

#[cfg(test)]
mod tests;
