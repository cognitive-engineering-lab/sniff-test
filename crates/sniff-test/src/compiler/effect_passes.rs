//! Compiler-pass registration and orchestration for concrete effect seeds.

use reachability::{ReachabilityEdge, ReachabilityGraph};
use rustc_hir::def_id::LocalDefId;
use rustc_middle::thir::{ExprId, Thir};
use rustc_middle::ty::TyCtxt;

use super::safety::RawSafetyFacts;
use crate::artifact::CompilerAssertKind;
use crate::effects::Effect;

/// HIR seed pass. The framework owns body enumeration and invokes every
/// registered pass for each analyzable function body.
pub(crate) trait HirEffectPass {
    fn check_body(&mut self, _tcx: TyCtxt<'_>, _owner: LocalDefId) {}
}

/// THIR seed pass. Typed expression visitors can retain state across callback
/// invocations and publish their collected facts through `take_output`.
pub(crate) trait ThirEffectPass {
    fn check_body<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        owner: LocalDefId,
        thir: &Thir<'tcx>,
        root: ExprId,
    );

    fn take_output(&mut self, _output: &mut EffectPassOutput) {}
}

/// MIR-derived seed pass. Reachability exposes compiler assertions as graph
/// nodes, so the callback receives the normalized edge rather than repeating a
/// second MIR traversal.
pub(crate) trait MirEffectPass {
    fn check_reachability_edge(
        &mut self,
        _graph: &ReachabilityGraph<'_>,
        _edge: &ReachabilityEdge,
    ) -> Option<CompilerAssertKind> {
        None
    }
}

#[derive(Default)]
pub(crate) struct EffectPassOutput {
    pub(crate) safety: RawSafetyFacts,
}

#[derive(Default)]
pub(crate) struct EffectPassRegistry {
    hir_passes: Vec<Box<dyn HirEffectPass>>,
    thir_passes: Vec<Box<dyn ThirEffectPass>>,
    mir_passes: Vec<Box<dyn MirEffectPass>>,
}

impl EffectPassRegistry {
    pub(crate) fn register_effect<E: Effect>(&mut self) {
        assert!(!E::EFFECT_NAME.is_empty(), "effect name must not be empty");
        assert!(
            !E::OBLIGATION.is_empty(),
            "obligation heading must not be empty"
        );
        assert!(
            !E::JUSTIFICATION.is_empty(),
            "justification marker must not be empty"
        );
        E::register_passes(self);
    }

    #[allow(
        dead_code,
        reason = "no built-in effect currently requires a HIR seed pass"
    )]
    pub(crate) fn register_hir_pass(&mut self, pass: Box<dyn HirEffectPass>) {
        self.hir_passes.push(pass);
    }

    pub(crate) fn register_thir_pass(&mut self, pass: Box<dyn ThirEffectPass>) {
        self.thir_passes.push(pass);
    }

    pub(crate) fn register_mir_pass(&mut self, pass: Box<dyn MirEffectPass>) {
        self.mir_passes.push(pass);
    }

    pub(crate) fn collect_bodies(
        &mut self,
        tcx: TyCtxt<'_>,
        owners: &[LocalDefId],
    ) -> EffectPassOutput {
        for &owner in owners {
            for pass in &mut self.hir_passes {
                pass.check_body(tcx, owner);
            }
            if self.thir_passes.is_empty() {
                continue;
            }
            let Ok((thir, root)) = tcx.thir_body(owner) else {
                continue;
            };
            let thir = thir.borrow();
            for pass in &mut self.thir_passes {
                pass.check_body(tcx, owner, &thir, root);
            }
        }
        let mut output = EffectPassOutput::default();
        for pass in &mut self.thir_passes {
            pass.take_output(&mut output);
        }
        output
    }

    pub(crate) fn compiler_assert_kind(
        &mut self,
        graph: &ReachabilityGraph<'_>,
        edge: &ReachabilityEdge,
    ) -> Option<CompilerAssertKind> {
        self.mir_passes
            .iter_mut()
            .find_map(|pass| pass.check_reachability_edge(graph, edge))
    }
}
