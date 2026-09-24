//! Compiler-pass registration and orchestration for concrete effect seeds.

use std::collections::{HashMap, HashSet};

use reachability::MirBodyLocation;
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::mir::{Body, Location, Operand};
use rustc_middle::thir::{ExprId, Thir};
use rustc_middle::ty::{
    self, EarlyBinder, GenericArgsRef, Instance, Ty, TyCtxt, TypeFoldable, TypeVisitableExt,
};
use rustc_span::Span;

use crate::artifact::{EffectKey, EffectKind};

use super::EffectSpec;

/// Pass-local identity shared by concrete sources that use one justification.
#[derive(Debug, Clone, Copy)]
pub struct PreliminaryEffectGroup {
    pub id: usize,
    pub span: Span,
}

impl PartialEq for PreliminaryEffectGroup {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for PreliminaryEffectGroup {}

impl std::hash::Hash for PreliminaryEffectGroup {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// One compiler-local operation reported by an effect pass.
#[derive(Debug, Clone)]
pub struct PreliminaryEffectSeed {
    pub owner: DefId,
    pub kind: EffectKind,
    pub span: Span,
    pub marker_anchor_spans: Vec<Span>,
    pub effect_group: Option<PreliminaryEffectGroup>,
}

/// A detected operation stamped with the effect that registered its pass.
#[derive(Debug, Clone)]
pub struct RegisteredEffectSeed {
    pub effect: EffectKey,
    pub seed: PreliminaryEffectSeed,
}

/// One source call reported by an effect pass, before it is joined with the
/// corresponding normalized reachability edge.
#[derive(Debug, Clone)]
pub struct PreliminaryCallSeed {
    pub owner: DefId,
    pub callee: Option<DefId>,
    pub declaration_callee: Option<DefId>,
    /// The compiler owns this context, so user-authored evidence must not be
    /// required for the call itself.
    pub suppressed_by_compiler_context: bool,
    pub call_site: usize,
    pub span: Span,
    pub effect_group: PreliminaryEffectGroup,
}

/// Facts required to resolve preliminary seeds but which are not themselves
/// potential effect sources.
#[derive(Debug, Default)]
pub struct EffectPassAuxiliary {
    pub groups: Vec<PreliminaryEffectGroupSeed>,
    pub calls: Vec<PreliminaryCallSeed>,
}

#[derive(Debug, Clone)]
pub struct PreliminaryEffectGroupSeed {
    pub owner: DefId,
    pub effect_group: PreliminaryEffectGroup,
}

/// A source classification emitted while visiting a MIR body.
#[derive(Debug, Clone)]
pub struct PreliminaryMirEffectSeed {
    pub location: Location,
    pub kind: EffectKind,
    pub source: PreliminaryMirEffectSource,
    pub suppress_in_compiler_context: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreliminaryMirEffectSource {
    Operation,
    Invocation {
        requires_documented_obligation: bool,
    },
}

#[derive(Debug, Clone)]
pub struct RegisteredMirEffectSeed {
    pub effect: EffectKey,
    pub kind: EffectKind,
    pub source: PreliminaryMirEffectSource,
    pub suppress_in_compiler_context: bool,
}

#[derive(Default)]
pub struct RegisteredMirEffectPassOutput<'tcx> {
    seeds: HashMap<(Instance<'tcx>, MirBodyLocation), Vec<RegisteredMirEffectSeed>>,
}

impl<'tcx> RegisteredMirEffectPassOutput<'tcx> {
    pub fn take(
        &mut self,
        instance: Instance<'tcx>,
        location: Option<MirBodyLocation>,
    ) -> Vec<RegisteredMirEffectSeed> {
        location
            .and_then(|location| self.seeds.remove(&(instance, location)))
            .unwrap_or_default()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seeds.is_empty()
    }
}

/// HIR seed pass. The framework owns body enumeration and invokes every
/// registered pass for each analyzable function body.
pub trait HirEffectPass {
    fn check_body(&mut self, _tcx: TyCtxt<'_>, _owner: LocalDefId) {}

    fn take_output(&mut self, _output: &mut EffectPassOutput) {}
}

/// THIR seed pass. Typed expression visitors can retain state across callback
/// invocations and publish their collected facts through `take_output`.
pub trait ThirEffectPass {
    fn check_body<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        owner: LocalDefId,
        thir: &Thir<'tcx>,
        root: ExprId,
    );

    fn take_output(&mut self, _output: &mut EffectPassOutput) {}
}

/// Context for inspecting one exact MIR instance without exposing extraction's
/// reachability graph to the effect implementation.
#[derive(Clone, Copy)]
pub struct MirEffectCx<'tcx> {
    tcx: TyCtxt<'tcx>,
    instance: Instance<'tcx>,
    body: &'tcx Body<'tcx>,
}

impl<'tcx> MirEffectCx<'tcx> {
    #[must_use]
    pub const fn tcx(self) -> TyCtxt<'tcx> {
        self.tcx
    }

    #[must_use]
    pub const fn instance(self) -> Instance<'tcx> {
        self.instance
    }

    #[must_use]
    pub const fn body(self) -> &'tcx Body<'tcx> {
        self.body
    }

    #[must_use]
    pub fn monomorphize<T>(self, value: T) -> T
    where
        T: TypeFoldable<TyCtxt<'tcx>>,
    {
        let value = EarlyBinder::bind(value);
        if self.instance.args.has_param() {
            value
                .instantiate(self.tcx, self.instance.args)
                .skip_norm_wip()
        } else {
            self.instance.instantiate_mir_and_normalize_erasing_regions(
                self.tcx,
                ty::TypingEnv::fully_monomorphized(),
                value,
            )
        }
    }

    #[must_use]
    pub fn operand_ty(self, operand: &Operand<'tcx>) -> Ty<'tcx> {
        self.monomorphize(operand.ty(&self.body.local_decls, self.tcx))
    }

    #[must_use]
    pub fn resolve_callable_instance(
        self,
        def_id: DefId,
        args: GenericArgsRef<'tcx>,
    ) -> Option<Instance<'tcx>> {
        if args.has_param() {
            if self.tcx.trait_of_assoc(def_id).is_some() {
                None
            } else {
                Some(Instance::new_raw(def_id, args))
            }
        } else {
            Instance::try_resolve(self.tcx, ty::TypingEnv::fully_monomorphized(), def_id, args)
                .ok()
                .flatten()
        }
    }
}

/// MIR-derived seed pass. The framework enumerates every exact function
/// instance expanded by reachability and invokes the pass directly on its MIR.
pub trait MirEffectPass {
    fn check_body(&mut self, _cx: MirEffectCx<'_>) -> Vec<PreliminaryMirEffectSeed> {
        Vec::new()
    }
}

#[derive(Default)]
pub struct EffectPassOutput {
    pub seeds: Vec<PreliminaryEffectSeed>,
    pub auxiliary: EffectPassAuxiliary,
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
pub struct RegisteredEffectPassOutput {
    pub seeds: Vec<RegisteredEffectSeed>,
    pub auxiliary: EffectPassAuxiliary,
}

#[derive(Default)]
pub struct EffectPassRegistry {
    hir: Vec<RegisteredHirPass>,
    thir: Vec<RegisteredThirPass>,
    mir: Vec<RegisteredMirPass>,
}

impl EffectPassRegistry {
    /// Whether a registered pass requires complete THIR for every analyzable
    /// body. The requirement follows from the pass shape rather than an
    /// effect name.
    #[must_use]
    pub fn requires_complete_thir(&self) -> bool {
        !self.thir.is_empty()
    }

    /// Source-level HIR and THIR passes only visit bodies in their defining
    /// artifact. MIR passes can also inspect consumer instantiations.
    #[must_use]
    pub fn requires_defining_body(&self, effect: &EffectKey) -> bool {
        self.hir.iter().any(|pass| &pass.effect == effect)
            || self.thir.iter().any(|pass| &pass.effect == effect)
    }

    #[allow(
        dead_code,
        reason = "no built-in effect currently requires a HIR seed pass"
    )]
    pub fn register_hir_pass<E: EffectSpec>(&mut self, pass: Box<dyn HirEffectPass>) {
        self.hir.push(RegisteredHirPass {
            effect: EffectKey::new(E::EFFECT_NAME),
            pass,
        });
    }

    pub fn register_thir_pass<E: EffectSpec>(&mut self, pass: Box<dyn ThirEffectPass>) {
        self.thir.push(RegisteredThirPass {
            effect: EffectKey::new(E::EFFECT_NAME),
            pass,
        });
    }

    pub fn register_mir_pass<E: EffectSpec>(&mut self, pass: Box<dyn MirEffectPass>) {
        self.mir.push(RegisteredMirPass {
            effect: EffectKey::new(E::EFFECT_NAME),
            pass,
        });
    }

    pub fn collect_bodies(
        &mut self,
        tcx: TyCtxt<'_>,
        owners: &[LocalDefId],
    ) -> RegisteredEffectPassOutput {
        for &owner in owners {
            for pass in &mut self.hir {
                pass.pass.check_body(tcx, owner);
            }
            if self.thir.is_empty() {
                continue;
            }
            let Ok((thir, root)) = tcx.thir_body(owner) else {
                continue;
            };
            let thir = thir.borrow();
            for pass in &mut self.thir {
                pass.pass.check_body(tcx, owner, &thir, root);
            }
        }
        let mut output = RegisteredEffectPassOutput::default();
        for pass in &mut self.hir {
            let mut local = EffectPassOutput::default();
            pass.pass.take_output(&mut local);
            append_registered_output(&pass.effect, local, &mut output);
        }
        for pass in &mut self.thir {
            let mut local = EffectPassOutput::default();
            pass.pass.take_output(&mut local);
            append_registered_output(&pass.effect, local, &mut output);
        }
        output
    }

    pub fn collect_mir_bodies<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        instances: impl IntoIterator<Item = Instance<'tcx>>,
    ) -> RegisteredMirEffectPassOutput<'tcx> {
        let mut output = RegisteredMirEffectPassOutput::default();
        let mut visited = HashSet::new();
        for instance in instances {
            if !visited.insert(instance) {
                continue;
            }
            let body = tcx.instance_mir(instance.def);
            let cx = MirEffectCx {
                tcx,
                instance,
                body,
            };
            for pass in &mut self.mir {
                for seed in pass.pass.check_body(cx) {
                    output
                        .seeds
                        .entry((instance, seed.location.into()))
                        .or_default()
                        .push(RegisteredMirEffectSeed {
                            effect: pass.effect.clone(),
                            kind: seed.kind,
                            source: seed.source,
                            suppress_in_compiler_context: seed.suppress_in_compiler_context,
                        });
                }
            }
        }
        output
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
