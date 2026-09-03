use crate::{FunctionId, PropagationEdge, UnknownBoundary};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TraceNodeId(pub(crate) usize);

impl TraceNodeId {
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TraceEdgeId(pub(crate) usize);

impl TraceEdgeId {
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceNode<O, S> {
    pub(crate) origin: O,
    pub(crate) function: FunctionId,
    pub(crate) state: S,
    pub(crate) predecessors: Vec<TraceEdgeId>,
}

impl<O, S> TraceNode<O, S> {
    #[must_use]
    pub const fn origin(&self) -> &O {
        &self.origin
    }

    #[must_use]
    pub const fn function(&self) -> FunctionId {
        self.function
    }

    #[must_use]
    pub const fn state(&self) -> &S {
        &self.state
    }

    pub fn predecessors(&self) -> impl ExactSizeIterator<Item = TraceEdgeId> + '_ {
        self.predecessors.iter().copied()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceEdge {
    pub(crate) from: TraceNodeId,
    pub(crate) to: TraceNodeId,
    pub(crate) propagation: PropagationEdge,
}

impl TraceEdge {
    #[must_use]
    pub const fn from(self) -> TraceNodeId {
        self.from
    }

    #[must_use]
    pub const fn to(self) -> TraceNodeId {
        self.to
    }

    #[must_use]
    pub const fn propagation(self) -> PropagationEdge {
        self.propagation
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminationSite<O> {
    Source(O),
    Function(FunctionId),
    Invocation(crate::InvocationId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandledTrace<O, T> {
    pub(crate) origin: O,
    pub(crate) node: Option<TraceNodeId>,
    pub(crate) site: TerminationSite<O>,
    pub(crate) termination: T,
}

impl<O, T> HandledTrace<O, T> {
    #[must_use]
    pub const fn origin(&self) -> &O {
        &self.origin
    }

    #[must_use]
    pub const fn node(&self) -> Option<TraceNodeId> {
        self.node
    }

    #[must_use]
    pub const fn site(&self) -> &TerminationSite<O> {
        &self.site
    }

    #[must_use]
    pub const fn termination(&self) -> &T {
        &self.termination
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownTrace<O, S> {
    pub(crate) origin: O,
    pub(crate) node: Option<TraceNodeId>,
    pub(crate) function: FunctionId,
    pub(crate) state: S,
    pub(crate) boundary: UnknownBoundary,
}

impl<O, S> UnknownTrace<O, S> {
    #[must_use]
    pub const fn origin(&self) -> &O {
        &self.origin
    }

    #[must_use]
    pub const fn node(&self) -> Option<TraceNodeId> {
        self.node
    }

    #[must_use]
    pub const fn function(&self) -> FunctionId {
        self.function
    }

    #[must_use]
    pub const fn state(&self) -> &S {
        &self.state
    }

    #[must_use]
    pub const fn boundary(&self) -> &UnknownBoundary {
        &self.boundary
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceOutcome<O> {
    Handled(O),
    Escaped(O),
    Unknown {
        origin: O,
        boundary: UnknownBoundary,
    },
}

#[derive(Clone, Debug)]
pub struct EffectTrace<O, S, T> {
    pub(crate) nodes: Vec<TraceNode<O, S>>,
    pub(crate) edges: Vec<TraceEdge>,
    pub(crate) handled: Vec<HandledTrace<O, T>>,
    pub(crate) escaped: Vec<(O, TraceNodeId)>,
    pub(crate) unknown: Vec<UnknownTrace<O, S>>,
    pub(crate) outcomes: Vec<TraceOutcome<O>>,
}

impl<O, S, T> Default for EffectTrace<O, S, T> {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            handled: Vec::new(),
            escaped: Vec::new(),
            unknown: Vec::new(),
            outcomes: Vec::new(),
        }
    }
}

impl<O: Clone, S, T> EffectTrace<O, S, T> {
    #[must_use]
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = &TraceNode<O, S>> {
        self.nodes.iter()
    }

    #[must_use]
    pub fn edges(&self) -> impl ExactSizeIterator<Item = TraceEdge> + '_ {
        self.edges.iter().copied()
    }

    #[must_use]
    pub fn handled(&self) -> impl ExactSizeIterator<Item = &HandledTrace<O, T>> {
        self.handled.iter()
    }

    #[must_use]
    pub fn escaped(&self) -> impl ExactSizeIterator<Item = (&O, TraceNodeId)> {
        self.escaped.iter().map(|(origin, node)| (origin, *node))
    }

    #[must_use]
    pub fn unknown(&self) -> impl ExactSizeIterator<Item = &UnknownTrace<O, S>> {
        self.unknown.iter()
    }

    #[must_use]
    pub fn outcomes(&self) -> impl ExactSizeIterator<Item = TraceOutcome<O>> + '_ {
        self.outcomes.iter().cloned()
    }
}
