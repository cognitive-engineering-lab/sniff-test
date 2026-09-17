//! Compiler-pass registration and orchestration for concrete effect seeds.

use reachability::{ReachabilityEdge, ReachabilityGraph};
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::thir::{ExprId, Thir};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use super::safety::SafetyEffectGroup;
use crate::artifact::{CompilerAssertKind, SafetyOpKind};
use crate::effects::Effect;

/// A compiler-local effect source reported by an effect pass.
///
/// Extraction resolves these candidates into stable artifact facts. A later
/// effect-specific qualification step may still reject a candidate (for
/// example, a safety call whose resolved target does not require unsafe).
#[derive(Debug, Clone)]
pub(crate) enum PreliminaryEffectSeed {
    SafetyOperation(PreliminarySafetyOperationSeed),
    SafetyCall(PreliminarySafetyCallSeed),
}

/// One runtime operation that rustc requires to occur in an unsafe context.
#[derive(Debug, Clone)]
pub(crate) struct PreliminarySafetyOperationSeed {
    pub(crate) owner: DefId,
    pub(crate) op: SafetyOpKind,
    pub(crate) span: Span,
    pub(crate) marker_anchor_spans: Vec<Span>,
    pub(crate) effect_group: SafetyEffectGroup,
}

/// One THIR call site that may become a concrete safety source after it is
/// joined with the resolved reachability edge.
#[derive(Debug, Clone)]
pub(crate) struct PreliminarySafetyCallSeed {
    pub(crate) owner: DefId,
    pub(crate) callee: Option<DefId>,
    pub(crate) declaration_callee: Option<DefId>,
    pub(crate) inside_builtin_unsafe: bool,
    pub(crate) call_site: usize,
    pub(crate) span: Span,
    pub(crate) effect_group: SafetyEffectGroup,
}

/// Facts required to resolve preliminary seeds but which are not themselves
/// potential effect sources.
#[derive(Debug, Default)]
pub(crate) struct EffectPassAuxiliary {
    pub(crate) safety_groups: Vec<PreliminarySafetyGroup>,
}

#[derive(Debug, Clone)]
pub(crate) struct PreliminarySafetyGroup {
    pub(crate) owner: DefId,
    pub(crate) effect_group: SafetyEffectGroup,
}

/// A source classification emitted while visiting an already-normalized MIR
/// reachability edge. Extraction supplies the edge's owner and source site.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PreliminaryMirEffectSeed {
    CompilerAssert(CompilerAssertKind),
}

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
    ) -> Option<PreliminaryMirEffectSeed> {
        None
    }
}

#[derive(Default)]
pub(crate) struct EffectPassOutput {
    pub(crate) seeds: Vec<PreliminaryEffectSeed>,
    pub(crate) auxiliary: EffectPassAuxiliary,
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

    pub(crate) fn preliminary_mir_seed(
        &mut self,
        graph: &ReachabilityGraph<'_>,
        edge: &ReachabilityEdge,
    ) -> Option<PreliminaryMirEffectSeed> {
        self.mir_passes
            .iter_mut()
            .find_map(|pass| pass.check_reachability_edge(graph, edge))
    }
}
