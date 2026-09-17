//! Converts rustc MIR assertions into stable artifact classifications.

use crate::artifact::CompilerAssertKind;
use crate::compiler::effect_passes::MirEffectPass;
use reachability::{ReachabilityEdge, ReachabilityGraph, ReachabilityNodeKind};
use rustc_middle::mir::AssertKind;

pub(crate) struct CompilerAssertPass;

impl MirEffectPass for CompilerAssertPass {
    fn check_reachability_edge(
        &mut self,
        graph: &ReachabilityGraph<'_>,
        edge: &ReachabilityEdge,
    ) -> Option<CompilerAssertKind> {
        let ReachabilityNodeKind::CompilerAssert { message, .. } = &graph.node(edge.target).kind
        else {
            return None;
        };
        Some(CompilerAssertKind::from(message.as_ref()))
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
