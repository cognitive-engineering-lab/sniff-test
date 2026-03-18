use std::{collections::HashMap, marker::PhantomData};

use crate::{
    annotations::{self, DefAnnotation, Obligation, parse_expr, toml::TomlAnnotation},
    properties::{self, FoundAxiom, Property, UnjustifiedAxiom},
    reachability::{self, CallsWObligations, GenericCallsWObligations},
};
use rustc_hir::def_id::{DefId, DefPathHash, LOCAL_CRATE, LocalDefId};
use rustc_macros::{Decodable, Encodable};
use rustc_middle::ty::TyCtxt;
use rustc_session::StableCrateId;
use rustc_span::Span;

pub mod err;
mod expr;

#[derive(Debug, Clone)]
pub struct CheckStats {
    #[allow(dead_code)]
    pub property: &'static str,
    pub entrypoints: usize,
    pub total_fns_checked: usize,
    pub w_obligation: usize,
    pub w_no_obligation: usize,
    pub calls_checked: usize,
}

impl CheckStats {
    pub fn new<P: Property>() -> Self {
        CheckStats {
            property: P::property_name(),
            entrypoints: 0,
            total_fns_checked: 0,
            w_obligation: 0,
            w_no_obligation: 0,
            calls_checked: 0,
        }
    }
}

use crate::reachability::CallGraph;

// struct CheckResult<P: Property> {
//     callgraph: CallGraph,
//     result: Result<CheckStats, Vec<LocalError<'_, P>>>,
// }

/// Checks that all local functions in the crate are properly annotated.
pub fn check_crate_for_property<P: Property>(
    tcx: TyCtxt<'_>,
    property: P,
    is_dependency: bool,
) -> Result<CheckStats, (CallGraph, Vec<LocalError<P>>)> {
    // Parse TOML annotations from file
    let toml_path = "sniff-test.toml";
    let toml_annotations = match TomlAnnotation::from_file(toml_path) {
        Ok(annotations) => annotations,
        Err(e) => {
            tcx.dcx()
                .struct_warn(format!(
                    "Failed to parse TOML annotations from {toml_path}: {e:?}"
                ))
                .emit();
            TomlAnnotation::default()
        }
    };

    let mut stats = CheckStats::new::<P>();
    let entry = reachability::analysis_entry_points::<P>(tcx, is_dependency);

    // Debug print all our entries and where they are in the src
    // (this isn't actually needed for analysis)
    {
        let entries = entry
            .iter()
            .map(|local| {
                let span = tcx.optimized_mir(local.to_def_id()).span;
                (local, span)
            })
            .collect::<Vec<_>>();
        log::info!(
            "the {} entry functions for {} in {} are {entries:#?}",
            entry.len(),
            P::property_name(),
            tcx.crate_name(LOCAL_CRATE)
        );
    }

    stats.entrypoints = entry.len();
    let callgraph = reachability::build_callgraph(tcx, entry);
    let reachable = callgraph.local_reachable(tcx);
    let mut local_errors = Vec::new();

    log::info!(
        "the {} reachable functions for {} in {} are {reachable:#?}",
        reachable.len(),
        P::property_name(),
        tcx.crate_name(LOCAL_CRATE)
    );

    // Filter for functions that aren't annotated as having obligations
    let mut reachable_no_obligations = Vec::new();

    // TODO: this could be a filter i think...
    for func in reachable {
        stats.total_fns_checked += 1;
        match annotations::parse_fn_def(tcx, &toml_annotations, func, property) {
            Some(annotation) if annotation.creates_obligation().is_some() => {
                stats.w_obligation += 1;
                if let Some(trait_def) = is_impl_of_trait(tcx, func)
                    && let Err(e) = check_consistent_w_trait_requirements(
                        tcx,
                        func,
                        &annotation,
                        trait_def,
                        property,
                        &toml_annotations,
                    )
                {
                    local_errors.push(e);
                }
                if let Err(e) = property.additional_check(tcx, func) {
                    local_errors.push(e);
                }
                // TODO: in the future, could check to make sure this annotation doesn't create unneeded obligations.
                log::debug!("fn {func:?} has obligations {annotation:?}, we'll trust it...");
            }
            _ => {
                stats.w_no_obligation += 1;
                reachable_no_obligations.push(func);
            }
        }
    }

    log::info!(
        "the {} reachable, unannotated functions we need to check for {} in {} are {reachable_no_obligations:#?}",
        reachable_no_obligations.len(),
        P::property_name(),
        tcx.crate_name(LOCAL_CRATE)
    );

    local_errors.extend(reachable_no_obligations.into_iter().filter_map(|func| {
        let func_calls_to = callgraph.calls_from(func);
        check_function_for_property(
            tcx,
            &toml_annotations,
            func,
            &func_calls_to,
            property,
            &mut stats,
        )
        .err()
    }));

    if !local_errors.is_empty() {
        return Err((callgraph, local_errors));
    }

    Ok(stats)
}

#[derive(Encodable, Decodable, Debug)]
pub struct SerializableDefId(DefPathHash, StableCrateId);

impl SerializableDefId {
    pub fn from_def_id(def_id: DefId, tcx: TyCtxt) -> Self {
        SerializableDefId(tcx.def_path_hash(def_id), tcx.stable_crate_id(def_id.krate))
    }

    pub fn to_def_id(&self, tcx: TyCtxt) -> DefId {
        tcx.def_path_hash_to_def_id_extern(self.0, self.1)
    }
}

type SerializableError<P> = GenericError<SerializableDefId, P>;

#[derive(Encodable, Decodable)]
pub enum GenericError<DefIdRepr, P: Property> {
    Basic {
        func: DefIdRepr,
        unjustified_axioms: Vec<UnjustifiedAxiom>,
        unjustified_calls: Vec<GenericCallsWObligations<DefIdRepr>>,
        property: PhantomData<P>,
    },
    Trait {
        func_has_obligations: DefIdRepr,
        inconsistent_w_trait: DefIdRepr,
    },
    CallMissedObligations {
        func: DefIdRepr,
        callsite_comment: String,
        callsite_span: Span,
        obligations: Vec<String>,
    },
    FnDefShouldHaveKeyword {
        fn_def: DefIdRepr,
        needed_keyword: String,
    },
}

#[derive(Debug, Decodable, Encodable)]
#[allow(dead_code)]
pub struct SerializableCallsWObligations {
    pub call_to: SerializableDefId,
    pub obligation: Obligation,
    pub from_spans: Vec<Span>,
}

impl<P: Property> SerializableError<P> {
    pub fn into_local(self, tcx: TyCtxt) -> LocalError<P> {
        match self {
            Self::Basic {
                func,
                unjustified_axioms,
                unjustified_calls,
                property,
            } => LocalError::Basic {
                func: func.to_def_id(tcx),
                unjustified_axioms,
                unjustified_calls: to_local_calls(unjustified_calls, tcx),
                property,
            },
            Self::Trait {
                func_has_obligations,
                inconsistent_w_trait,
            } => LocalError::Trait {
                func_has_obligations: func_has_obligations.to_def_id(tcx),
                inconsistent_w_trait: inconsistent_w_trait.to_def_id(tcx),
            },
            Self::CallMissedObligations {
                func,
                callsite_comment,
                callsite_span,
                obligations,
            } => LocalError::CallMissedObligations {
                func: func.to_def_id(tcx),
                callsite_comment,
                callsite_span,
                obligations,
            },
            Self::FnDefShouldHaveKeyword {
                fn_def,
                needed_keyword,
            } => LocalError::FnDefShouldHaveKeyword {
                fn_def: fn_def.to_def_id(tcx),
                needed_keyword,
            },
        }
    }
}

impl<P: Property> LocalError<P> {
    pub fn into_serializable(self, tcx: TyCtxt) -> SerializableError<P> {
        match self {
            Self::Basic {
                func,
                unjustified_axioms,
                unjustified_calls,
                property,
            } => SerializableError::Basic {
                func: SerializableDefId::from_def_id(func, tcx),
                unjustified_axioms,
                unjustified_calls: from_local_calls(unjustified_calls, tcx),
                property,
            },
            Self::Trait {
                func_has_obligations,
                inconsistent_w_trait,
            } => SerializableError::Trait {
                func_has_obligations: SerializableDefId::from_def_id(func_has_obligations, tcx),
                inconsistent_w_trait: SerializableDefId::from_def_id(inconsistent_w_trait, tcx),
            },
            Self::CallMissedObligations {
                func,
                callsite_comment,
                callsite_span,
                obligations,
            } => SerializableError::CallMissedObligations {
                func: SerializableDefId::from_def_id(func, tcx),
                callsite_comment,
                callsite_span,
                obligations,
            },
            Self::FnDefShouldHaveKeyword {
                fn_def,
                needed_keyword,
            } => SerializableError::FnDefShouldHaveKeyword {
                fn_def: SerializableDefId::from_def_id(fn_def, tcx),
                needed_keyword,
            },
        }
    }
}

pub fn to_local_calls(
    serializable: Vec<GenericCallsWObligations<SerializableDefId>>,
    tcx: TyCtxt,
) -> Vec<CallsWObligations> {
    serializable
        .into_iter()
        .map(|serializable| CallsWObligations {
            call_to: serializable.call_to.to_def_id(tcx),
            obligation: serializable.obligation,
            from_spans: serializable.from_spans,
        })
        .collect()
}

pub fn from_local_calls(
    local: Vec<CallsWObligations>,
    tcx: TyCtxt,
) -> Vec<GenericCallsWObligations<SerializableDefId>> {
    local
        .into_iter()
        .map(|local| GenericCallsWObligations {
            call_to: SerializableDefId::from_def_id(local.call_to, tcx),
            obligation: local.obligation,
            from_spans: local.from_spans,
        })
        .collect()
}

pub type LocalError<P> = GenericError<DefId, P>;

impl<DefIdRepr, P: Property> GenericError<DefIdRepr, P> {
    pub fn func(&self) -> &DefIdRepr {
        match self {
            Self::Basic { func, .. }
            | Self::CallMissedObligations { func, .. }
            | Self::FnDefShouldHaveKeyword { fn_def: func, .. }
            | Self::Trait {
                func_has_obligations: func,
                ..
            } => func,
        }
    }
}

fn check_function_for_property<P: Property>(
    tcx: TyCtxt,
    toml_annotations: &TomlAnnotation,
    func: LocalDefId,
    func_calls_to: &HashMap<DefId, Vec<Span>>,
    property: P,
    stats: &mut CheckStats,
) -> Result<(), LocalError<P>> {
    // Look for all axioms within this function
    let axioms = properties::find_axioms(tcx, &func, property).collect::<Vec<_>>();
    log::debug!("fn {func:?} has raw axioms {axioms:#?}");
    let unjustified_axioms = axioms
        .into_iter()
        .filter_map(only_unjustified_axioms(tcx, property))
        .collect::<Vec<_>>();

    // Find all calls that have obligations.
    let calls =
        reachability::find_calls_w_obligations(tcx, toml_annotations, func_calls_to, property)
            .collect::<Vec<_>>();
    let call_ct = calls
        .iter()
        .map(|calls| calls.from_spans.len())
        .sum::<usize>();

    stats.calls_checked += call_ct;
    log::debug!("fn {func:?} has raw calls {calls:#?}");
    let mut unjustified_calls = Vec::new();
    let only_unjustified = only_unjustified_callsites(tcx, func, property);
    for c in calls {
        match only_unjustified(c) {
            JustificationStatus::AllCallsJustified => (),
            JustificationStatus::ImproperJustification(err) => return Err(err),
            JustificationStatus::SomeNotJustified(remaining) => unjustified_calls.push(remaining),
        }
    }

    log::info!("fn {func:?} has unjustified axioms {unjustified_axioms:#?}");
    log::info!("fn {func:?} has unjustified calls {unjustified_calls:#?}",);

    // If we have obligations, we've dismissed them
    if unjustified_calls.is_empty() && unjustified_axioms.is_empty() {
        // Nothing to report, all good!
        Ok(())
    } else {
        // Unjustified issues, report them!!
        Err(LocalError::Basic {
            func: func.to_def_id(),
            unjustified_axioms,
            unjustified_calls,
            property: PhantomData,
        })
    }
}

fn check_consistent_w_trait_requirements<P: Property>(
    tcx: TyCtxt,
    func: LocalDefId,
    annotation: &DefAnnotation,
    t: DefId,
    property: P,
    toml_annotations: &TomlAnnotation,
) -> Result<(), LocalError<P>> {
    let name = tcx.item_ident(func);

    let trait_fn = tcx
        .associated_items(t)
        .find_by_ident_and_kind(tcx, name, rustc_middle::ty::AssocTag::Fn, t)
        .expect("can't resolve trait fn to original def");

    let def_obligation =
        annotations::parse_fn_def(tcx, toml_annotations, trait_fn.def_id, property)
            .and_then(|def_annot| def_annot.creates_obligation());

    if annotation.creates_obligation() == def_obligation {
        Ok(())
    } else {
        Err(LocalError::Trait {
            func_has_obligations: func.to_def_id(),
            inconsistent_w_trait: t,
        })
    }
}

fn is_impl_of_trait(tcx: TyCtxt, owner: LocalDefId) -> Option<DefId> {
    let is = tcx
        .impl_subject(tcx.trait_impl_of_assoc(owner.to_def_id())?)
        .skip_binder();

    match is {
        rustc_middle::ty::ImplSubject::Inherent(_) => todo!("what's an inherent?"),
        rustc_middle::ty::ImplSubject::Trait(t) => {
            let t = t.def_id;
            assert_eq!(tcx.def_kind(t), rustc_hir::def::DefKind::Trait);
            Some(t)
        }
    }
}

fn only_unjustified_axioms<'tcx, P: Property>(
    tcx: TyCtxt<'tcx>,
    property: P,
) -> impl Fn(FoundAxiom<'tcx, P::Axiom>) -> Option<UnjustifiedAxiom> {
    move |axiom| {
        log::debug!("getting seeing if axiom {axiom:?} has justification");
        if parse_expr(tcx, axiom.found_in, property).is_none() {
            Some(UnjustifiedAxiom {
                name: axiom.axiom.to_string(),
                span: axiom.span,
            })
        } else {
            None
        }
    }
}

enum JustificationStatus<P: Property> {
    AllCallsJustified,
    SomeNotJustified(CallsWObligations),
    ImproperJustification(LocalError<P>),
}

/// Filter a set of calls to a function for only those which are not property justified.
fn only_unjustified_callsites<P: Property>(
    tcx: TyCtxt,
    in_fn: LocalDefId,
    property: P,
) -> impl Fn(CallsWObligations) -> JustificationStatus<P> {
    move |mut calls| {
        let mut new_spans = Vec::new();

        for call_span in calls.from_spans {
            let call_expr = expr::find_expr_for_call(tcx, calls.call_to, in_fn, call_span);
            let callsite_annotation = parse_expr(tcx, call_expr, property);

            match callsite_annotation {
                Some(annotation) => {
                    if let Err(e) = annotation.satisfies_obligation(
                        &calls.obligation,
                        calls.call_to,
                        call_span,
                        &in_fn,
                        // tcx,
                    ) {
                        return JustificationStatus::ImproperJustification(e);
                    }
                }
                None => {
                    // Callsite not annotated, add to list of unjustified calls
                    new_spans.push(call_span);
                }
            }
        }

        // If we have no new callsites, just remove this one from the list...
        if new_spans.is_empty() {
            JustificationStatus::AllCallsJustified
        } else {
            calls.from_spans = new_spans;
            JustificationStatus::SomeNotJustified(calls)
        }
    }
}
