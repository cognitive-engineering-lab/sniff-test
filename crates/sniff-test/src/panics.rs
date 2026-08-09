//! Stable policy-neutral classifications for compiler-generated panic facts.

use rustc_middle::mir::AssertKind;
use serde::{Deserialize, Serialize};

/// Stable semantic subtype for a compiler-generated MIR assertion.
///
/// The variant set mirrors [`AssertKind`] without retaining MIR operands or
/// applying lint policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CompilerAssertKind {
    BoundsCheck,
    Overflow,
    OverflowNegation,
    DivisionByZero,
    RemainderByZero,
    ResumedAfterReturn,
    ResumedAfterPanic,
    ResumedAfterDrop,
    MisalignedPointerDereference,
    NullPointerDereference,
    InvalidEnumConstruction,
}

impl CompilerAssertKind {
    /// Stable human-facing description of this compiler assertion.
    #[must_use]
    pub(crate) const fn human_description(self) -> &'static str {
        match self {
            Self::BoundsCheck => "index out of bounds",
            Self::Overflow => "arithmetic overflow",
            Self::OverflowNegation => "negation overflow",
            Self::DivisionByZero => "division by zero",
            Self::RemainderByZero => "remainder with a zero divisor",
            Self::ResumedAfterReturn => "coroutine resumed after returning",
            Self::ResumedAfterPanic => "coroutine resumed after panicking",
            Self::ResumedAfterDrop => "coroutine resumed after being dropped",
            Self::MisalignedPointerDereference => "misaligned pointer dereference",
            Self::NullPointerDereference => "null pointer dereference",
            Self::InvalidEnumConstruction => "invalid enum construction",
        }
    }
}

impl<O> From<&AssertKind<O>> for CompilerAssertKind {
    fn from(kind: &AssertKind<O>) -> Self {
        match kind {
            AssertKind::BoundsCheck { .. } => Self::BoundsCheck,
            AssertKind::Overflow(..) => Self::Overflow,
            AssertKind::OverflowNeg(..) => Self::OverflowNegation,
            AssertKind::DivisionByZero(..) => Self::DivisionByZero,
            AssertKind::RemainderByZero(..) => Self::RemainderByZero,
            AssertKind::ResumedAfterReturn(..) => Self::ResumedAfterReturn,
            AssertKind::ResumedAfterPanic(..) => Self::ResumedAfterPanic,
            AssertKind::ResumedAfterDrop(..) => Self::ResumedAfterDrop,
            AssertKind::MisalignedPointerDereference { .. } => Self::MisalignedPointerDereference,
            AssertKind::NullPointerDereference => Self::NullPointerDereference,
            AssertKind::InvalidEnumConstruction(..) => Self::InvalidEnumConstruction,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CompilerAssertKind;

    #[test]
    fn compiler_assert_kinds_have_stable_human_descriptions() {
        for (kind, description) in [
            (CompilerAssertKind::BoundsCheck, "index out of bounds"),
            (CompilerAssertKind::Overflow, "arithmetic overflow"),
            (CompilerAssertKind::OverflowNegation, "negation overflow"),
            (CompilerAssertKind::DivisionByZero, "division by zero"),
            (
                CompilerAssertKind::RemainderByZero,
                "remainder with a zero divisor",
            ),
            (
                CompilerAssertKind::ResumedAfterReturn,
                "coroutine resumed after returning",
            ),
            (
                CompilerAssertKind::ResumedAfterPanic,
                "coroutine resumed after panicking",
            ),
            (
                CompilerAssertKind::ResumedAfterDrop,
                "coroutine resumed after being dropped",
            ),
            (
                CompilerAssertKind::MisalignedPointerDereference,
                "misaligned pointer dereference",
            ),
            (
                CompilerAssertKind::NullPointerDereference,
                "null pointer dereference",
            ),
            (
                CompilerAssertKind::InvalidEnumConstruction,
                "invalid enum construction",
            ),
        ] {
            assert_eq!(kind.human_description(), description);
        }
    }
}
