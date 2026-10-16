//! Concrete and documentation-obligation propagation over the invocation graph.
//!
//! A forward walk from the report roots ([`RootRoutes`]) bounds the search.
//! Tracing then runs a concrete pass and a documentation pass over those
//! routes. Handoffs retain depth and trust context, including the originating
//! seed's state budget. Independently documented contracts start new budgets.

mod effect;
mod graph;
mod model;
mod routes;
mod worklist;

pub use effect::{EffectSeed, Propagation, PropagationEdge, TraceSite};
pub use graph::{
    FunctionId, InvocationId, TransparentBodyEdgeId, UnknownBoundary, UnknownBoundaryKind,
};
pub use model::{
    EffectTrace, HandledTrace, TerminationSite, TraceEdge, TraceEdgeId, TraceNode, TraceNodeId,
    TraceOutcome, UnknownTrace,
};
pub use routes::{EdgeScope, RootRoutes};
pub use worklist::{DomainTrace, TraceOptions, trace_effect};
