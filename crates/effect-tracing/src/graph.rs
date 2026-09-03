use std::fmt;

macro_rules! index_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(usize);

        impl $name {
            #[must_use]
            pub const fn from_index(index: usize) -> Self {
                Self(index)
            }

            #[must_use]
            pub const fn index(self) -> usize {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

index_id!(FunctionId);
index_id!(InvocationId);
index_id!(TransparentBodyEdgeId);

/// The compiler-independent graph surface needed by effect tracing.
///
/// Ordinary calls are indexed in reverse: `incoming_invocations(callee)`
/// returns source-level invocations whose caller may observe an effect from the
/// callee. Multiple concrete targets of one source call must share one
/// [`InvocationId`].
pub trait EffectGraph {
    fn incoming_invocations(&self, function: FunctionId) -> &[InvocationId];

    fn caller(&self, invocation: InvocationId) -> FunctionId;

    fn transparent_parents(&self, function: FunctionId) -> &[TransparentBodyEdgeId];

    fn transparent_parent(&self, edge: TransparentBodyEdgeId) -> FunctionId;

    /// Returns unresolved boundaries reached from this tracing position.
    ///
    /// These are outcomes, not guessed invocation targets. Implementations may
    /// return an empty slice when all relevant boundaries are represented by
    /// effect-specific [`crate::Propagation::Unknown`] results.
    fn unknown_boundaries(&self, _function: FunctionId) -> &[UnknownBoundary] {
        &[]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnknownBoundary {
    kind: UnknownBoundaryKind,
}

impl UnknownBoundary {
    #[must_use]
    pub const fn new(kind: UnknownBoundaryKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(&self) -> UnknownBoundaryKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnknownBoundaryKind {
    IndirectCall,
    MissingDefinition,
    Cycle,
    TraceDepth,
    TraceStateBudget,
}
