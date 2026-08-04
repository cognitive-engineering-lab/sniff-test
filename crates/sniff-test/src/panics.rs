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
