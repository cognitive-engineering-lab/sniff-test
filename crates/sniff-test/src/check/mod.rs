use std::collections::HashMap;

use crate::{
    annotations::{self, DefAnnotation, parse_expr, toml::TomlAnnotation},
    properties::{self, FoundAxiom, Property},
    reachability::{self, CallsWObligations},
};
use rustc_hir::def_id::{DefId, LOCAL_CRATE, LocalDefId};
use rustc_middle::ty::TyCtxt;
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

/// Checks that all local functions in the crate are properly annotated.
pub fn check_crate_for_property<P: Property>(
    tcx: TyCtxt<'_>,
    property: P,
    is_dependency: bool,
) -> Result<CheckStats, Vec<LocalError<'_, P>>> {
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
    let reachable = callgraph.local_reachable();
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
        return Err(local_errors);
    }

    Ok(stats)
}

pub enum LocalError<'tcx, P: Property> {
    Basic {
        tcx: TyCtxt<'tcx>,
        func: LocalDefId,
        _property: P,
        unjustified_axioms: Vec<FoundAxiom<'tcx, P::Axiom>>,
        unjustified_calls: Vec<CallsWObligations>,
    },
    Trait {
        func_has_obligations: LocalDefId,
        inconsistent_w_trait: DefId,
    },
    CallMissedObligations {
        func: LocalDefId,
        callsite_comment: String,
        callsite_span: Span,
        obligations: Vec<String>,
    },
    FnDefShouldHaveKeyword {
        fn_def: LocalDefId,
        needed_keyword: &'static str,
    },
}

impl<P: Property> LocalError<'_, P> {
    pub fn func(&self) -> &LocalDefId {
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

fn check_function_for_property<'tcx, P: Property>(
    tcx: TyCtxt<'tcx>,
    toml_annotations: &TomlAnnotation,
    func: LocalDefId,
    func_calls_to: &HashMap<DefId, Vec<Span>>,
    property: P,
    stats: &mut CheckStats,
) -> Result<(), LocalError<'tcx, P>> {
    // Look for all axioms within this function
    let axioms = properties::find_axioms(tcx, &func, property).collect::<Vec<_>>();
    log::debug!("fn {func:?} has raw axioms {axioms:#?}");
    let unjustified_axioms = axioms
        .into_iter()
        .filter(only_unjustified_axioms(tcx, property))
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
            tcx,
            func,
            _property: property,
            unjustified_axioms,
            unjustified_calls,
        })
    }
}

fn check_consistent_w_trait_requirements<'tcx, P: Property>(
    tcx: TyCtxt<'tcx>,
    func: LocalDefId,
    annotation: &DefAnnotation,
    t: DefId,
    property: P,
    toml_annotations: &TomlAnnotation,
) -> Result<(), LocalError<'tcx, P>> {
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
            func_has_obligations: func,
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
) -> impl Fn(&FoundAxiom<'tcx, P::Axiom>) -> bool {
    move |axiom| {
        log::debug!("getting seeing if axiom {axiom:?} has justification");
        parse_expr(tcx, axiom.found_in, property).is_none()
    }
}

enum JustificationStatus<'tcx, P: Property> {
    AllCallsJustified,
    SomeNotJustified(CallsWObligations),
    ImproperJustification(LocalError<'tcx, P>),
}

/// Filter a set of calls to a function for only those which are not property justified.
fn only_unjustified_callsites<'tcx, P: Property>(
    tcx: TyCtxt<'tcx>,
    in_fn: LocalDefId,
    property: P,
) -> impl Fn(CallsWObligations) -> JustificationStatus<'tcx, P> {
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
