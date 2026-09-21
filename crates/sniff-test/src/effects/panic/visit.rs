//! Converts rustc MIR assertions into stable artifact classifications.

use crate::artifact::CallTargetFact;
use crate::artifact::{CompilerAssertKind, EffectKind};
use crate::effects::visit::{MirEffectPass, PreliminaryMirEffectSeed, PreliminaryMirEffectSource};
use reachability::{ReachabilityGraph, ReachabilityNodeKind, ReachedEdge};
use rustc_middle::mir::AssertKind;
use rustc_middle::ty::TyCtxt;

pub(crate) struct CompilerAssertPass;

impl MirEffectPass for CompilerAssertPass {
    fn check_reachability_edge<'view, 'tcx>(
        &mut self,
        _tcx: TyCtxt<'tcx>,
        graph: &'view ReachabilityGraph<'tcx>,
        reached: ReachedEdge<'view, 'tcx>,
        _target: &CallTargetFact,
        _suppressed_by_compiler_context: bool,
    ) -> Option<PreliminaryMirEffectSeed> {
        let edge = reached.edge();
        let ReachabilityNodeKind::CompilerAssert { message, .. } = &graph.node(edge.target).kind
        else {
            return None;
        };
        let kind = CompilerAssertKind::from(message.as_ref());
        Some(PreliminaryMirEffectSeed {
            kind: EffectKind::new(kind.effect_kind_name()),
            source: PreliminaryMirEffectSource::Operation,
        })
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
