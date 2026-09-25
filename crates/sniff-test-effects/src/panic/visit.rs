//! Converts rustc MIR assertions into stable artifact classifications.

use rustc_middle::mir::{AssertKind, Location, TerminatorKind};
use rustc_middle::ty::TyKind;
use sniff_test_core::effects::visit::{
    MirEffectCx, MirEffectPass, PreliminaryMirEffectSeed, PreliminaryMirEffectSource,
};
use sniff_test_core::namespace::canonical_namespace;

use super::PanicOperation;

pub struct CompilerAssertPass;

/// Turns calls into rustc's built-in panic runtime into invocation sources.
///
/// Panic source recognition belongs to the panic effect writer. Persisting it
/// during extraction lets shared concrete probing consume the same invocation
/// facts as every other effect instead of knowing about panic sink policy.
pub struct BuiltinPanicInvocationPass;

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
                    // Preserve the existing report kind for panic invocations.
                    kind: PanicOperation::ConfiguredInvocation.into(),
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
    is_builtin_panic_sink_path(&path)
}

fn is_builtin_panic_sink_path(path: &str) -> bool {
    path.starts_with("core::panicking::")
        || path.starts_with("std::panicking::")
        || matches!(
            path,
            "core::std::rt::panic_fmt"
                | "std::rt::panic_fmt"
                | "core::option::unwrap_failed"
                | "core::result::unwrap_failed"
                | "std::option::unwrap_failed"
                | "std::result::unwrap_failed"
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
                    kind: compiler_assert_kind(msg.as_ref()).into(),
                    source: PreliminaryMirEffectSource::Operation,
                    suppress_in_compiler_context: false,
                })
            })
            .collect()
    }
}

fn compiler_assert_kind<O>(kind: &AssertKind<O>) -> PanicOperation {
    match kind {
        AssertKind::BoundsCheck { .. } => PanicOperation::BoundsCheck,
        AssertKind::Overflow(..) => PanicOperation::Overflow,
        AssertKind::OverflowNeg(..) => PanicOperation::OverflowNegation,
        AssertKind::DivisionByZero(..) => PanicOperation::DivisionByZero,
        AssertKind::RemainderByZero(..) => PanicOperation::RemainderByZero,
        AssertKind::ResumedAfterReturn(..) => PanicOperation::ResumedAfterReturn,
        AssertKind::ResumedAfterPanic(..) => PanicOperation::ResumedAfterPanic,
        AssertKind::ResumedAfterDrop(..) => PanicOperation::ResumedAfterDrop,
        AssertKind::MisalignedPointerDereference { .. } => {
            PanicOperation::MisalignedPointerDereference
        }
        AssertKind::NullPointerDereference => PanicOperation::NullPointerDereference,
        AssertKind::InvalidEnumConstruction(..) => PanicOperation::InvalidEnumConstruction,
    }
}

#[cfg(test)]
mod tests {
    use super::is_builtin_panic_sink_path;

    #[test]
    fn recognizes_every_former_builtin_panic_sink() {
        for path in [
            "core::panicking::panic_fmt",
            "std::panicking::panic_fmt",
            "core::std::rt::panic_fmt",
            "std::rt::panic_fmt",
            "core::option::unwrap_failed",
            "core::result::unwrap_failed",
            "std::option::unwrap_failed",
            "std::result::unwrap_failed",
        ] {
            assert!(is_builtin_panic_sink_path(path), "{path}");
        }
        assert!(!is_builtin_panic_sink_path(
            "ambiguous_markers::configured_sink"
        ));
        assert!(!is_builtin_panic_sink_path("core::option::unwrap"));
    }
}
