//! Built-in summaries of APIs that submit one future for later execution.
//! Matching uses defining crates and inherent self types, never import spelling.
use reachability::{ModeledInvocation, ReachabilityHooks};
use rustc_hir::def::DefKind;
use rustc_middle::ty::{Instance, TyCtxt, TyKind};

pub(super) struct RuntimeModels;

impl<'tcx> ReachabilityHooks<'tcx> for RuntimeModels {
    fn model_call(
        &self,
        tcx: TyCtxt<'tcx>,
        target: Instance<'tcx>,
    ) -> Option<ModeledInvocation<'tcx>> {
        let def = target.def_id();
        let krate = tcx.crate_name(def.krate);
        if !matches!(krate.as_str(), "tokio" | "smol" | "async_executor") {
            return None;
        }
        if !matches!(tcx.def_kind(def), DefKind::Fn | DefKind::AssocFn) {
            return None;
        }
        let name = tcx.item_name(def);
        let argument = if let Some(impl_id) = tcx.impl_of_assoc(def) {
            if tcx.trait_item_of(def).is_some() {
                return None;
            }
            let self_ty = tcx
                .type_of(impl_id)
                .instantiate_identity()
                .skip_normalization();
            let TyKind::Adt(adt, _) = self_ty.kind() else {
                return None;
            };
            let owner = crate::namespace::canonical_namespace(tcx, adt.did());
            let valid = match krate.as_str() {
                "tokio" => match owner.as_str() {
                    "tokio::runtime::runtime::Runtime" | "tokio::runtime::handle::Handle" => {
                        name.as_str() == "spawn"
                    }
                    "tokio::task::local::LocalSet"
                    | "tokio::runtime::local_runtime::runtime::LocalRuntime" => {
                        name.as_str() == "spawn_local"
                    }
                    "tokio::task::join_set::JoinSet"
                    | "tokio::task::join_set::Builder"
                    | "tokio::task::builder::Builder" => matches!(
                        name.as_str(),
                        "spawn" | "spawn_on" | "spawn_local" | "spawn_local_on"
                    ),
                    _ => false,
                },
                "async_executor" => {
                    matches!(
                        owner.as_str(),
                        "async_executor::Executor"
                            | "async_executor::LocalExecutor"
                            | "async_executor::static_executors::StaticExecutor"
                            | "async_executor::static_executors::StaticLocalExecutor"
                    ) && name.as_str() == "spawn"
                }
                _ => false,
            };
            if !valid {
                return None;
            }
            1
        } else {
            if !matches!(
                crate::namespace::canonical_namespace(tcx, def).as_str(),
                "tokio::task::spawn::spawn"
                    | "tokio::task::local::spawn_local"
                    | "smol::spawn::spawn"
            ) {
                return None;
            }
            0
        };
        let declaration = tcx.fn_sig(def).instantiate_identity().skip_binder();
        let expected_inputs = argument + 1 + usize::from(name.as_str().ends_with("_on"));
        if declaration.inputs().len() != expected_inputs {
            return None;
        }
        let parameter = *declaration.inputs().get(argument)?;
        let future_trait = tcx.lang_items().future_trait()?;
        let has_future_bound = tcx.predicates_of(def).predicates.iter().any(|(clause, _)| {
            clause.as_trait_clause().is_some_and(|bound| {
                let bound = bound.skip_binder();
                bound.trait_ref.def_id == future_trait && bound.self_ty() == parameter
            })
        });
        if !has_future_bound {
            return None;
        }
        let signature = tcx.fn_sig(def).instantiate(tcx, target.args).skip_binder();
        let future = *signature.inputs().get(argument)?;
        let method = tcx.lang_items().future_poll_fn()?;
        let receiver_ty = future;
        Some(ModeledInvocation {
            argument,
            method,
            receiver_ty,
        })
    }
}
