//! Converts rustc MIR assertions into stable artifact classifications.

use rustc_hir::def_id::DefId;
use rustc_middle::mir::{AssertKind, Location, TerminatorKind};
use rustc_middle::ty::Ty;
use sniff_test_core::effects::visit::{MirEffectCx, MirEffectPass, MirEffectSeed, MirEffectSource};
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
    fn check_call<'tcx>(
        &mut self,
        cx: MirEffectCx<'tcx>,
        callee: Option<DefId>,
        _callable_ty: Ty<'tcx>,
        location: Location,
    ) -> Option<MirEffectSeed> {
        if !callee.is_some_and(|callee| is_builtin_panic_sink(cx, callee)) {
            return None;
        }
        Some(MirEffectSeed {
            location,
            // Preserve the existing report kind for panic invocations.
            kind: PanicOperation::ConfiguredInvocation.into(),
            source: MirEffectSource::Invocation {
                requires_documented_obligation: false,
            },
            suppress_in_compiler_context: false,
        })
    }
}

fn is_builtin_panic_sink(cx: MirEffectCx<'_>, callee: DefId) -> bool {
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
    fn check_body(&mut self, cx: MirEffectCx<'_>) -> Vec<MirEffectSeed> {
        cx.body()
            .basic_blocks
            .iter_enumerated()
            .filter_map(|(block, data)| {
                let terminator = data.terminator();
                let TerminatorKind::Assert { msg, .. } = &terminator.kind else {
                    return None;
                };
                Some(MirEffectSeed {
                    location: Location {
                        block,
                        statement_index: data.statements.len(),
                    },
                    kind: compiler_assert_kind(msg.as_ref()).into(),
                    source: MirEffectSource::Operation,
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
