//! Query-local receiver evidence for rapid type analysis of trait objects.
//!
//! A cast supplies types, not object identities. No value-flow claim is made.
use rustc_hir::def_id::DefId;
use rustc_middle::ty::{
    self, GenericArgsRef, Instance, InstanceKind, Ty, TyCtxt, TypeVisitableExt,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DynCast<'tcx> {
    pub trait_ref: ty::TraitRef<'tcx>,
    object_ty: Ty<'tcx>,
}

pub(crate) fn casts<'tcx>(
    tcx: TyCtxt<'tcx>,
    source: Ty<'tcx>,
    target: Ty<'tcx>,
) -> Vec<DynCast<'tcx>> {
    let mut result = Vec::new();
    for (concrete, object_ty) in crate::body::dyn_trait_tails(source, target) {
        if concrete.has_param() || concrete.has_escaping_bound_vars() {
            continue;
        }
        let ty::Dynamic(predicates, _) = object_ty.kind() else {
            continue;
        };
        let Some(principal) = predicates.principal() else {
            continue;
        };
        for trait_ref in ty::elaborate::supertraits(tcx, principal.with_self_ty(tcx, concrete)) {
            let trait_ref = tcx.instantiate_bound_regions_with_erased(trait_ref);
            result.push(DynCast {
                trait_ref,
                object_ty,
            });
        }
    }
    result
}

pub(crate) fn resolve<'tcx>(
    tcx: TyCtxt<'tcx>,
    cast: DynCast<'tcx>,
    method: DefId,
    args: GenericArgsRef<'tcx>,
) -> Result<Option<Instance<'tcx>>, ()> {
    let ty::Dynamic(required, _) = *args.type_at(0).kind() else {
        return Ok(None);
    };
    let ty::Dynamic(observed, _) = *cast.object_ty.kind() else {
        return Ok(None);
    };
    let concrete = cast.trait_ref.self_ty();
    let env = ty::TypingEnv::fully_monomorphized();
    let normalize = |value| {
        tcx.try_normalize_erasing_regions(env, ty::Unnormalized::new(value))
            .map_err(|_| ())
    };
    let principal = required.principal().ok_or(())?;
    let required_ref =
        tcx.instantiate_bound_regions_with_erased(principal.with_self_ty(tcx, concrete));
    let required_ref = normalize(required_ref)?;
    let mut compatible = false;
    for reference in ty::elaborate::supertraits(
        tcx,
        observed.principal().ok_or(())?.with_self_ty(tcx, concrete),
    ) {
        if normalize(tcx.instantiate_bound_regions_with_erased(reference))? == required_ref {
            compatible = true;
            break;
        }
    }
    if !compatible
        || required
            .auto_traits()
            .any(|id| !observed.auto_traits().any(|other| other == id))
    {
        return Ok(None);
    }
    // Associated-type bindings are part of the erased receiver's identity.
    for projection in required.projection_bounds() {
        let projection =
            tcx.instantiate_bound_regions_with_erased(projection.with_self_ty(tcx, concrete));
        let actual = tcx
            .try_normalize_erasing_regions(
                env,
                ty::Unnormalized::new(projection.projection_term.to_term(tcx)),
            )
            .map_err(|_| ())?;
        let expected = tcx
            .try_normalize_erasing_regions(env, ty::Unnormalized::new(projection.term))
            .map_err(|_| ())?;
        if actual != expected {
            return Ok(None);
        }
    }
    let args = tcx.mk_args_from_iter(std::iter::once(concrete.into()).chain(args.iter().skip(1)));
    if args.has_param() || args.has_escaping_bound_vars() {
        return Err(());
    }
    let args = tcx
        .try_normalize_erasing_regions(env, ty::Unnormalized::new(args))
        .map_err(|_| ())?;
    let target = Instance::try_resolve(tcx, env, method, args)
        .map_err(|_| ())?
        .ok_or(())?;
    if matches!(target.def, InstanceKind::Virtual(..)) {
        Err(())
    } else {
        Ok(Some(target))
    }
}
