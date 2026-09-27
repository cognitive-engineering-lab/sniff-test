//! Concrete and documentation-obligation propagation over the invocation graph.
//!
//! Each pass owns a worklist of path nodes. Handoffs retain depth and trust
//! context, and both passes share one state budget per effect.

mod effect;
mod graph;
mod model;
mod worklist;

pub use effect::{EffectSeed, Propagation, PropagationEdge, TraceSite};
pub use graph::{
    FunctionId, InvocationId, TransparentBodyEdgeId, UnknownBoundary, UnknownBoundaryKind,
};
pub use model::{
    EffectTrace, HandledTrace, TerminationSite, TraceEdge, TraceEdgeId, TraceNode, TraceNodeId,
    TraceOutcome, UnknownTrace,
};
pub use worklist::{DomainTrace, TraceOptions, trace_effect};
