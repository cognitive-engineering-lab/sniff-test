use crate::trace::{FunctionId, InvocationId, TransparentBodyEdgeId, UnknownBoundary};

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
    Handoff,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Propagation<S> {
    Follow(S),
    Ignore,
    Unknown(UnknownBoundary),
}

impl<S> Propagation<S> {
    #[must_use]
    pub fn map<T>(self, f: impl FnOnce(S) -> T) -> Propagation<T> {
        match self {
            Self::Follow(state) => Propagation::Follow(f(state)),
            Self::Ignore => Propagation::Ignore,
            Self::Unknown(boundary) => Propagation::Unknown(boundary),
        }
    }
}
