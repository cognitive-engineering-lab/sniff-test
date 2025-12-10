use crate::{
    annotations::{self, DefAnnotation, parse_expr, toml::TomlAnnotation},
    properties::{self, FoundAxiom, Property},
    reachability::{self, CallsWObligations, LocallyReachable},
};
use rustc_hir::def_id::{DefId, LOCAL_CRATE, LocalDefId};
use rustc_middle::ty::TyCtxt;
use rustc_span::ErrorGuaranteed;

mod err;
mod expr;

#[derive(Debug, Default, Clone, Copy)]
pub struct CheckStats {
    pub entrypoints: usize,
    pub total_fns_checked: usize,
    pub w_obligation: usize,
    pub w_no_obligation: usize,
}

/// Checks that all local functions in the crate are properly annotated.
pub fn check_crate_for_property<P: Property>(
    tcx: TyCtxt,
    property: P,
) -> Result<CheckStats, ErrorGuaranteed> {
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

    let mut stats = CheckStats::default();
    let entry = reachability::analysis_entry_points::<P>(tcx);

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
    let reachable = reachability::locally_reachable_from(tcx, entry);

    log::info!(
        "the {} reachable functions for {} in {} are {reachable:#?}",
        reachable.len(),
        P::property_name(),
        tcx.crate_name(LOCAL_CRATE)
    );

    // Filter for functions that aren't annotated as having obligations
    let mut reachable_no_obligations = Vec::new();

    for func in reachable {
        stats.total_fns_checked += 1;
        match annotations::parse_fn_def(tcx, &toml_annotations, func.reach, property) {
            Some(annotation) if annotation.creates_obligation() => {
                stats.w_obligation += 1;
                if let Some(trait_def) = is_impl_of_trait(tcx, func.reach) {
                    check_consistent_w_trait_requirements(
                        tcx,
                        &func,
                        &annotation,
                        trait_def,
                        property,
                        &toml_annotations,
                    )?;
                }
                property.additional_check(tcx, func.reach.to_def_id())?;
                // TODO: in the future, could check to make sure this annotation doesn't create unneeded obligations.
                log::debug!(
                    "fn {:?} has obligations {:?}, we'll trust it...",
                    func.reach,
                    annotation
                );
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

    let mut res = Ok(stats);

    // For all reachable local function definitions, ensure their axioms align with their annotations.
    for func in reachable_no_obligations {
        // Continue checking functions, even if one fails to ensure we report as many errors as possible.
        // TODO: is this actually bad? one could imagine properly documenting one function could also
        // fix errors for where it is called.
        if let Err(e) = check_function_for_property(tcx, &toml_annotations, func, property) {
            res = Err(e);
        }
    }

    res
}

fn check_function_for_property<P: Property>(
    tcx: TyCtxt,
    toml_annotations: &TomlAnnotation,
    func: LocallyReachable,
    property: P,
) -> Result<(), ErrorGuaranteed> {
    // Look for all axioms within this function
    let axioms = properties::find_axioms(tcx, &func, property).collect::<Vec<_>>();
    log::debug!("fn {:?} has raw axioms {:#?}", func.reach, axioms);
    let unjustified_axioms = axioms
        .into_iter()
        .filter(only_unjustified_axioms(tcx, property))
        .collect::<Vec<_>>();

    // Find all calls that have obligations.
    let calls = reachability::find_calls_w_obligations(tcx, toml_annotations, &func, property)
        .collect::<Vec<_>>();
    log::debug!("fn {:?} has raw calls {:#?}", func.reach, calls);
    let unjustified_calls = calls
        .into_iter()
        // Filter those with only callsites that haven't been justified.
        .filter_map(only_unjustified_callsites(tcx, func.reach, property))
        .collect::<Vec<_>>();

    log::info!(
        "fn {:?} has unjustified axioms {:#?}",
        func.reach,
        unjustified_axioms
    );
    log::info!(
        "fn {:?} has unjustified calls {:#?}",
        func.reach,
        unjustified_calls
    );

    // If we have obligations, we've dismissed them

    if unjustified_calls.is_empty() && unjustified_axioms.is_empty() {
        // Nothing to report, all good!
        Ok(())
    } else {
        // Unjustified issues, report them!!
        Err(err::report_errors(
            tcx,
            func,
            property,
            unjustified_axioms,
            unjustified_calls,
        ))
    }
}

fn check_consistent_w_trait_requirements<P: Property>(
    tcx: TyCtxt,
    func: &LocallyReachable,
    annotation: &DefAnnotation,
    t: DefId,
    property: P,
    toml_annotations: &TomlAnnotation,
) -> Result<(), ErrorGuaranteed> {
    let name = tcx.item_ident(func.reach);

    let trait_fn = tcx
        .associated_items(t)
        .find_by_ident_and_kind(tcx, name, rustc_middle::ty::AssocTag::Fn, t)
        .expect("can't resolve trait fn to original def");

    let def_obligation =
        annotations::parse_fn_def(tcx, toml_annotations, trait_fn.def_id, property)
            .is_some_and(|def_annot| def_annot.creates_obligation());

    if annotation.creates_obligation() && !def_obligation {
        let a = tcx.dcx().struct_err(format!("function {:?} has obligations, which is inconsistent with the definition of that associated function for trait {:?}!", func.reach, t)).emit();
        Err(a)
    } else {
        Ok(())
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

/// Filter a set of calls to a function for only those which are not property justified.
fn only_unjustified_callsites<P: Property>(
    tcx: TyCtxt,
    in_fn: LocalDefId,
    property: P,
) -> impl Fn(CallsWObligations) -> Option<CallsWObligations> {
    move |mut calls| {
        let mut new_spans = Vec::new();

        for call_span in calls.from_spans {
            let call_expr = expr::find_expr_for_call(tcx, calls.call_to, in_fn, call_span);
            let callsite_annotation = parse_expr(tcx, call_expr, property);

            if callsite_annotation.is_none() {
                new_spans.push(call_span);
            }
        }

        // If we have no new callsites, just remove this one from the list...
        if new_spans.is_empty() {
            None
        } else {
            calls.from_spans = new_spans;
            Some(calls)
        }
    }
}
