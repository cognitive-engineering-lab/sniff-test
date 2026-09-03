//! Shared, compiler-independent effect tracing.
//!
//! An [`Effect`] defines only three pieces of domain behavior: where the
//! effect starts, how its state changes across a propagation edge, and where a
//! path terminates. [`EffectEngine`] supplies reverse-invocation traversal,
//! transparent-body traversal, path splitting and convergence, state-aware
//! cycle detection, resource limits, and trace recording. Panic, safety, and
//! documentation semantics deliberately live outside this crate.

mod effect;
mod engine;
mod graph;
mod trace;

pub use effect::{Effect, EffectSeed, Propagation, PropagationEdge, TraceCx, TraceSite};
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
