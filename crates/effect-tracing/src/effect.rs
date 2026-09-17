use std::hash::Hash;

use crate::{EffectGraph, FunctionId, InvocationId, TransparentBodyEdgeId, UnknownBoundary};

/// Domain semantics consumed by the generic tracing engine.
pub trait TracePolicy {
    type Origin: Clone + Eq + Hash;
    type State: Clone + Eq + Hash;
    type Termination: Clone;

    fn sources(&self) -> impl Iterator<Item = EffectSeed<Self::Origin, Self::State>> + '_;

    /// Replaces one carrier at a function boundary while retaining its causal
    /// trace. Concrete effects use this to become documentation-derived
    /// contract obligations before propagation continues to callers.
    fn handoff(
        &self,
        _cx: &TraceCx<'_>,
        _state: &Self::State,
        _function: FunctionId,
    ) -> Option<Self::State> {
        None
    }

    fn propagate(
        &self,
        cx: &TraceCx<'_>,
        state: &Self::State,
        edge: PropagationEdge,
    ) -> Propagation<Self::State>;

    fn terminate(
        &self,
        cx: &TraceCx<'_>,
        state: &Self::State,
        site: TraceSite<'_, Self::Origin>,
    ) -> Option<Self::Termination>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectSeed<O, S> {
    pub origin: O,
    pub owner: FunctionId,
    pub state: S,
}

impl<O, S> EffectSeed<O, S> {
    #[must_use]
    pub const fn new(origin: O, owner: FunctionId, state: S) -> Self {
        Self {
            origin,
            owner,
            state,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TraceSite<'a, O> {
    Source(&'a O),
    Function(FunctionId),
    Invocation(InvocationId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PropagationEdge {
    Invocation(InvocationId),
    TransparentBody(TransparentBodyEdgeId),
    ContractHandoff,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Propagation<S> {
    Follow(S),
    Ignore,
    Unknown(UnknownBoundary),
}

#[derive(Clone, Copy)]
pub struct TraceCx<'graph> {
    graph: &'graph dyn EffectGraph,
}

impl<'graph> TraceCx<'graph> {
    pub(crate) const fn new(graph: &'graph dyn EffectGraph) -> Self {
        Self { graph }
    }

    #[must_use]
    pub const fn graph(self) -> &'graph dyn EffectGraph {
        self.graph
    }
}
