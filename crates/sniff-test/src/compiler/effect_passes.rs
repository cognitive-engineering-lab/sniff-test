//! Compiler-pass registration and orchestration for concrete effect seeds.

use reachability::{ReachabilityEdge, ReachabilityGraph};
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::thir::{ExprId, Thir};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use super::safety::SafetyEffectGroup;
use crate::artifact::{EffectKey, EffectKind};
use crate::effects::Effect;

/// One compiler-local operation reported by an effect pass.
#[derive(Debug, Clone)]
pub(crate) struct PreliminaryEffectSeed {
    pub(crate) owner: DefId,
    pub(crate) kind: EffectKind,
    pub(crate) span: Span,
    pub(crate) marker_anchor_spans: Vec<Span>,
    pub(crate) effect_group: Option<SafetyEffectGroup>,
}

/// A detected operation stamped with the effect that registered its pass.
#[derive(Debug, Clone)]
pub(crate) struct RegisteredEffectSeed {
    pub(crate) effect: EffectKey,
    pub(crate) seed: PreliminaryEffectSeed,
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
    pub(crate) safety_calls: Vec<PreliminarySafetyCallSeed>,
}

#[derive(Debug, Clone)]
pub(crate) struct PreliminarySafetyGroup {
    pub(crate) owner: DefId,
    pub(crate) effect_group: SafetyEffectGroup,
}

/// A source classification emitted while visiting an already-normalized MIR
/// reachability edge. Extraction supplies the edge's owner and source site.
#[derive(Debug, Clone)]
pub(crate) struct PreliminaryMirEffectSeed {
    pub(crate) kind: EffectKind,
}

#[derive(Debug, Clone)]
pub(crate) struct RegisteredMirEffectSeed {
    pub(crate) effect: EffectKey,
    pub(crate) kind: EffectKind,
}

/// HIR seed pass. The framework owns body enumeration and invokes every
/// registered pass for each analyzable function body.
pub(crate) trait HirEffectPass {
    fn check_body(&mut self, _tcx: TyCtxt<'_>, _owner: LocalDefId) {}

    fn take_output(&mut self, _output: &mut EffectPassOutput) {}
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

struct RegisteredThirPass {
    effect: EffectKey,
    pass: Box<dyn ThirEffectPass>,
}

struct RegisteredHirPass {
    effect: EffectKey,
    pass: Box<dyn HirEffectPass>,
}

struct RegisteredMirPass {
    effect: EffectKey,
    pass: Box<dyn MirEffectPass>,
}

#[derive(Default)]
pub(crate) struct RegisteredEffectPassOutput {
    pub(crate) seeds: Vec<RegisteredEffectSeed>,
    pub(crate) auxiliary: EffectPassAuxiliary,
}

#[derive(Default)]
pub(crate) struct EffectPassRegistry {
    hir_passes: Vec<RegisteredHirPass>,
    thir_passes: Vec<RegisteredThirPass>,
    mir_passes: Vec<RegisteredMirPass>,
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
    pub(crate) fn register_hir_pass<E: Effect>(&mut self, pass: Box<dyn HirEffectPass>) {
        self.hir_passes.push(RegisteredHirPass {
            effect: EffectKey::new(E::EFFECT_KEY),
            pass,
        });
    }

    pub(crate) fn register_thir_pass<E: Effect>(&mut self, pass: Box<dyn ThirEffectPass>) {
        self.thir_passes.push(RegisteredThirPass {
            effect: EffectKey::new(E::EFFECT_KEY),
            pass,
        });
    }

    pub(crate) fn register_mir_pass<E: Effect>(&mut self, pass: Box<dyn MirEffectPass>) {
        self.mir_passes.push(RegisteredMirPass {
            effect: EffectKey::new(E::EFFECT_KEY),
            pass,
        });
    }

    pub(crate) fn collect_bodies(
        &mut self,
        tcx: TyCtxt<'_>,
        owners: &[LocalDefId],
    ) -> RegisteredEffectPassOutput {
        for &owner in owners {
            for pass in &mut self.hir_passes {
                pass.pass.check_body(tcx, owner);
            }
            if self.thir_passes.is_empty() {
                continue;
            }
            let Ok((thir, root)) = tcx.thir_body(owner) else {
                continue;
            };
            let thir = thir.borrow();
            for pass in &mut self.thir_passes {
                pass.pass.check_body(tcx, owner, &thir, root);
            }
        }
        let mut output = RegisteredEffectPassOutput::default();
        for pass in &mut self.hir_passes {
            let mut local = EffectPassOutput::default();
            pass.pass.take_output(&mut local);
            append_registered_output(&pass.effect, local, &mut output);
        }
        for pass in &mut self.thir_passes {
            let mut local = EffectPassOutput::default();
            pass.pass.take_output(&mut local);
            append_registered_output(&pass.effect, local, &mut output);
        }
        output
    }

    pub(crate) fn preliminary_mir_seed(
        &mut self,
        graph: &ReachabilityGraph<'_>,
        edge: &ReachabilityEdge,
    ) -> Option<RegisteredMirEffectSeed> {
        self.mir_passes.iter_mut().find_map(|pass| {
            pass.pass
                .check_reachability_edge(graph, edge)
                .map(|seed| RegisteredMirEffectSeed {
                    effect: pass.effect.clone(),
                    kind: seed.kind,
                })
        })
    }
}

fn append_registered_output(
    effect: &EffectKey,
    local: EffectPassOutput,
    output: &mut RegisteredEffectPassOutput,
) {
    output
        .seeds
        .extend(local.seeds.into_iter().map(|seed| RegisteredEffectSeed {
            effect: effect.clone(),
            seed,
        }));
    output
        .auxiliary
        .safety_groups
        .extend(local.auxiliary.safety_groups);
    output
        .auxiliary
        .safety_calls
        .extend(local.auxiliary.safety_calls);
}
