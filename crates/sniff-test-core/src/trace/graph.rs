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
