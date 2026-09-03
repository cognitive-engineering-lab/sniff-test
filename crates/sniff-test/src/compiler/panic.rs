//! Converts rustc MIR assertions into stable artifact classifications.

use crate::artifact::CompilerAssertKind;
use rustc_middle::mir::AssertKind;

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
