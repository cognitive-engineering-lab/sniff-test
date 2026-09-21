//! Converts rustc MIR assertions into stable artifact classifications.

use crate::artifact::{CompilerAssertKind, EffectKind};
use crate::effects::visit::{
    MirEffectCx, MirEffectPass, PreliminaryMirEffectSeed, PreliminaryMirEffectSource,
};
use rustc_middle::mir::{AssertKind, Location, TerminatorKind};

pub(crate) struct CompilerAssertPass;

impl MirEffectPass for CompilerAssertPass {
    fn check_body(&mut self, cx: MirEffectCx<'_>) -> Vec<PreliminaryMirEffectSeed> {
        cx.body()
            .basic_blocks
            .iter_enumerated()
            .filter_map(|(block, data)| {
                let terminator = data.terminator();
                let TerminatorKind::Assert { msg, .. } = &terminator.kind else {
                    return None;
                };
                let kind = CompilerAssertKind::from(msg.as_ref());
                Some(PreliminaryMirEffectSeed {
                    location: Location {
                        block,
                        statement_index: data.statements.len(),
                    },
                    kind: EffectKind::new(kind.effect_kind_name()),
                    source: PreliminaryMirEffectSource::Operation,
                    suppress_in_compiler_context: false,
                })
            })
            .collect()
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
