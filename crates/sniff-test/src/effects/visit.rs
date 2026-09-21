//! Compiler-pass registration and orchestration for concrete effect seeds.

use reachability::{ReachabilityGraph, ReachedEdge};
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::thir::{ExprId, Thir};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use crate::artifact::{CallTargetFact, EffectKey, EffectKind};

use super::{Effect, EffectMetadata};

/// Pass-local identity shared by concrete sources that use one justification.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PreliminaryEffectGroup {
    pub(crate) id: usize,
    pub(crate) span: Span,
}

/// One compiler-local operation reported by an effect pass.
#[derive(Debug, Clone)]
pub(crate) struct PreliminaryEffectSeed {
    pub(crate) owner: DefId,
    pub(crate) kind: EffectKind,
    pub(crate) span: Span,
    pub(crate) marker_anchor_spans: Vec<Span>,
    pub(crate) effect_group: Option<PreliminaryEffectGroup>,
}

/// A detected operation stamped with the effect that registered its pass.
#[derive(Debug, Clone)]
pub(crate) struct RegisteredEffectSeed {
    pub(crate) effect: EffectKey,
    pub(crate) seed: PreliminaryEffectSeed,
}

/// One source call reported by an effect pass, before it is joined with the
/// corresponding normalized reachability edge.
#[derive(Debug, Clone)]
pub(crate) struct PreliminaryCallSeed {
    pub(crate) owner: DefId,
    pub(crate) callee: Option<DefId>,
    pub(crate) declaration_callee: Option<DefId>,
    /// The compiler owns this context, so user-authored evidence must not be
    /// required for the call itself.
    pub(crate) suppressed_by_compiler_context: bool,
    pub(crate) call_site: usize,
    pub(crate) span: Span,
    pub(crate) effect_group: PreliminaryEffectGroup,
}

/// Facts required to resolve preliminary seeds but which are not themselves
/// potential effect sources.
#[derive(Debug, Default)]
pub(crate) struct EffectPassAuxiliary {
    pub(crate) groups: Vec<PreliminaryEffectGroupSeed>,
    pub(crate) calls: Vec<PreliminaryCallSeed>,
}

#[derive(Debug, Clone)]
pub(crate) struct PreliminaryEffectGroupSeed {
    pub(crate) owner: DefId,
    pub(crate) effect_group: PreliminaryEffectGroup,
}

/// A source classification emitted while visiting an already-normalized MIR
/// reachability edge. Extraction supplies the edge's owner and source site.
#[derive(Debug, Clone)]
pub(crate) struct PreliminaryMirEffectSeed {
    pub(crate) kind: EffectKind,
    pub(crate) source: PreliminaryMirEffectSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreliminaryMirEffectSource {
    Operation,
    Invocation,
}

#[derive(Debug, Clone)]
pub(crate) struct RegisteredMirEffectSeed {
    pub(crate) effect: EffectKey,
    pub(crate) kind: EffectKind,
    pub(crate) source: PreliminaryMirEffectSource,
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
    fn check_reachability_edge<'view, 'tcx>(
        &mut self,
        _tcx: TyCtxt<'tcx>,
        _graph: &'view ReachabilityGraph<'tcx>,
        _reached: ReachedEdge<'view, 'tcx>,
        _target: &CallTargetFact,
        _suppressed_by_compiler_context: bool,
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
    effects: Vec<EffectMetadata>,
    hir_passes: Vec<RegisteredHirPass>,
    thir_passes: Vec<RegisteredThirPass>,
    mir_passes: Vec<RegisteredMirPass>,
}

impl EffectPassRegistry {
    /// Whether a registered pass requires complete THIR for every analyzable
    /// body. The requirement follows from the pass shape rather than an
    /// effect name.
    #[must_use]
    pub(crate) fn requires_complete_thir(&self) -> bool {
        !self.thir_passes.is_empty()
    }

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
        let effect = EffectMetadata::of::<E>();
        assert!(
            self.effects
                .iter()
                .all(|registered| registered.key != effect.key),
            "effect names must be unique"
        );
        self.effects.push(effect);
        E::register_passes(self);
    }

    #[allow(
        dead_code,
        reason = "no built-in effect currently requires a HIR seed pass"
    )]
    pub(crate) fn register_hir_pass<E: Effect>(&mut self, pass: Box<dyn HirEffectPass>) {
        self.hir_passes.push(RegisteredHirPass {
            effect: EffectKey::new(E::EFFECT_NAME),
            pass,
        });
    }

    pub(crate) fn register_thir_pass<E: Effect>(&mut self, pass: Box<dyn ThirEffectPass>) {
        self.thir_passes.push(RegisteredThirPass {
            effect: EffectKey::new(E::EFFECT_NAME),
            pass,
        });
    }

    pub(crate) fn register_mir_pass<E: Effect>(&mut self, pass: Box<dyn MirEffectPass>) {
        self.mir_passes.push(RegisteredMirPass {
            effect: EffectKey::new(E::EFFECT_NAME),
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

    pub(crate) fn preliminary_mir_seeds<'view, 'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &'view ReachabilityGraph<'tcx>,
        reached: ReachedEdge<'view, 'tcx>,
        target: &CallTargetFact,
        suppressed_by_compiler_context: bool,
    ) -> Vec<RegisteredMirEffectSeed> {
        self.mir_passes
            .iter_mut()
            .filter_map(|pass| {
                pass.pass
                    .check_reachability_edge(
                        tcx,
                        graph,
                        reached,
                        target,
                        suppressed_by_compiler_context,
                    )
                    .map(|seed| RegisteredMirEffectSeed {
                        effect: pass.effect.clone(),
                        kind: seed.kind,
                        source: seed.source,
                    })
            })
            .collect()
    }
}

fn append_registered_output(
    effect: &EffectKey,
    mut local: EffectPassOutput,
    output: &mut RegisteredEffectPassOutput,
) {
    // Pass-local group and call identities commonly start at zero. Remap them
    // into one artifact-wide namespace before combining independently written
    // effects, so plugin passes cannot alias a built-in pass by accident.
    let group_offset = output
        .auxiliary
        .groups
        .iter()
        .map(|seed| seed.effect_group.id)
        .chain(
            output
                .auxiliary
                .calls
                .iter()
                .map(|seed| seed.effect_group.id),
        )
        .chain(
            output
                .seeds
                .iter()
                .filter_map(|seed| seed.seed.effect_group.map(|group| group.id)),
        )
        .max()
        .map_or(0, |group| {
            group
                .checked_add(1)
                .expect("too many preliminary effect groups")
        });
    let call_offset = output
        .auxiliary
        .calls
        .iter()
        .map(|seed| seed.call_site)
        .max()
        .map_or(0, |call| {
            call.checked_add(1)
                .expect("too many preliminary call sites")
        });
    for seed in &mut local.auxiliary.groups {
        seed.effect_group.id = seed
            .effect_group
            .id
            .checked_add(group_offset)
            .expect("too many preliminary effect groups");
    }
    for seed in &mut local.auxiliary.calls {
        seed.effect_group.id = seed
            .effect_group
            .id
            .checked_add(group_offset)
            .expect("too many preliminary effect groups");
        seed.call_site = seed
            .call_site
            .checked_add(call_offset)
            .expect("too many preliminary call sites");
    }
    for seed in &mut local.seeds {
        if let Some(group) = &mut seed.effect_group {
            group.id = group
                .id
                .checked_add(group_offset)
                .expect("too many preliminary effect groups");
        }
    }
    output
        .seeds
        .extend(local.seeds.into_iter().map(|seed| RegisteredEffectSeed {
            effect: effect.clone(),
            seed,
        }));
    output.auxiliary.groups.extend(local.auxiliary.groups);
    output.auxiliary.calls.extend(local.auxiliary.calls);
}

#[cfg(test)]
mod tests {
    use rustc_hir::def_id::{CRATE_DEF_ID, DefId};
    use rustc_span::DUMMY_SP;

    use super::{
        EffectPassAuxiliary, EffectPassOutput, PreliminaryCallSeed, PreliminaryEffectGroup,
        PreliminaryEffectGroupSeed, RegisteredEffectPassOutput, append_registered_output,
    };
    use crate::artifact::EffectKey;

    fn output(owner: DefId) -> EffectPassOutput {
        let effect_group = PreliminaryEffectGroup {
            id: 0,
            span: DUMMY_SP,
        };
        EffectPassOutput {
            seeds: Vec::new(),
            auxiliary: EffectPassAuxiliary {
                groups: vec![PreliminaryEffectGroupSeed {
                    owner,
                    effect_group,
                }],
                calls: vec![PreliminaryCallSeed {
                    owner,
                    callee: None,
                    declaration_callee: None,
                    suppressed_by_compiler_context: false,
                    call_site: 0,
                    span: DUMMY_SP,
                    effect_group,
                }],
            },
        }
    }

    #[test]
    fn registered_pass_outputs_receive_disjoint_local_id_namespaces() {
        let owner = CRATE_DEF_ID.to_def_id();
        let mut combined = RegisteredEffectPassOutput::default();
        append_registered_output(&EffectKey::new("first"), output(owner), &mut combined);
        append_registered_output(&EffectKey::new("second"), output(owner), &mut combined);

        assert_eq!(combined.auxiliary.groups[0].effect_group.id, 0);
        assert_eq!(combined.auxiliary.groups[1].effect_group.id, 1);
        assert_eq!(combined.auxiliary.calls[0].call_site, 0);
        assert_eq!(combined.auxiliary.calls[1].call_site, 1);
        assert_eq!(combined.auxiliary.calls[1].effect_group.id, 1);
    }
}
