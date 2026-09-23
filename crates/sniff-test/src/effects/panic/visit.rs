//! Converts rustc MIR assertions into stable artifact classifications.

use crate::artifact::EffectKind;
use crate::effects::visit::{
    MirEffectCx, MirEffectPass, PreliminaryMirEffectSeed, PreliminaryMirEffectSource,
};
use crate::namespace::canonical_namespace;
use rustc_middle::mir::{AssertKind, Location, TerminatorKind};
use rustc_middle::ty::TyKind;

pub(crate) struct CompilerAssertPass;

/// Turns calls into rustc's built-in panic runtime into invocation sources.
///
/// Panic source recognition belongs to the panic effect writer. Persisting it
/// during extraction lets shared concrete probing consume the same invocation
/// facts as every other effect instead of knowing about panic sink policy.
pub(crate) struct BuiltinPanicInvocationPass;

impl MirEffectPass for BuiltinPanicInvocationPass {
    fn check_body(&mut self, cx: MirEffectCx<'_>) -> Vec<PreliminaryMirEffectSeed> {
        cx.body()
            .basic_blocks
            .iter_enumerated()
            .filter_map(|(block, data)| {
                let terminator = data.terminator();
                let (TerminatorKind::Call { func, .. } | TerminatorKind::TailCall { func, .. }) =
                    &terminator.kind
                else {
                    return None;
                };
                builtin_panic_callee(cx, func).map(|_| PreliminaryMirEffectSeed {
                    location: Location {
                        block,
                        statement_index: data.statements.len(),
                    },
                    // Preserve the existing report kind while source discovery
                    // moves from configured probing into compiler extraction.
                    kind: EffectKind::new("configured-invocation"),
                    source: PreliminaryMirEffectSource::Invocation {
                        requires_documented_obligation: false,
                    },
                    suppress_in_compiler_context: false,
                })
            })
            .collect()
    }
}

fn builtin_panic_callee<'tcx>(
    cx: MirEffectCx<'tcx>,
    func: &rustc_middle::mir::Operand<'tcx>,
) -> Option<rustc_hir::def_id::DefId> {
    let TyKind::FnDef(def_id, args) = *cx.operand_ty(func).kind() else {
        return None;
    };
    let callee = cx
        .resolve_callable_instance(def_id, args)
        .map_or(def_id, |instance| instance.def_id());
    is_builtin_panic_sink(cx, callee).then_some(callee)
}

fn is_builtin_panic_sink(cx: MirEffectCx<'_>, callee: rustc_hir::def_id::DefId) -> bool {
    let path = canonical_namespace(cx.tcx(), callee);
    path.starts_with("core::panicking::")
        || path.starts_with("std::panicking::")
        || matches!(
            path.as_str(),
            "core::std::rt::panic_fmt" | "std::rt::panic_fmt"
        )
}

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
                Some(PreliminaryMirEffectSeed {
                    location: Location {
                        block,
                        statement_index: data.statements.len(),
                    },
                    kind: EffectKind::new(compiler_assert_kind_name(msg.as_ref())),
                    source: PreliminaryMirEffectSource::Operation,
                    suppress_in_compiler_context: false,
                })
            })
            .collect()
    }
}

fn compiler_assert_kind_name<O>(kind: &AssertKind<O>) -> &'static str {
    match kind {
        AssertKind::BoundsCheck { .. } => "bounds-check",
        AssertKind::Overflow(..) => "overflow",
        AssertKind::OverflowNeg(..) => "overflow-negation",
        AssertKind::DivisionByZero(..) => "division-by-zero",
        AssertKind::RemainderByZero(..) => "remainder-by-zero",
        AssertKind::ResumedAfterReturn(..) => "resumed-after-return",
        AssertKind::ResumedAfterPanic(..) => "resumed-after-panic",
        AssertKind::ResumedAfterDrop(..) => "resumed-after-drop",
        AssertKind::MisalignedPointerDereference { .. } => "misaligned-pointer-dereference",
        AssertKind::NullPointerDereference => "null-pointer-dereference",
        AssertKind::InvalidEnumConstruction(..) => "invalid-enum-construction",
    }
}
