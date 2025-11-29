use crate::{
    annotations::{self, parse_expr, toml::TomlAnnotation},
    properties::{self, FoundAxiom, Property},
    reachability::{self, CallsWObligations, LocallyReachable},
};
use rustc_hir::def_id::{LOCAL_CRATE, LocalDefId};
use rustc_middle::ty::TyCtxt;
use rustc_span::ErrorGuaranteed;

mod err;
mod expr;

/// Checks that all local functions in the crate are properly annotated.
pub fn check_crate_for_property<P: Property>(
    tcx: TyCtxt,
    property: P,
) -> Result<(), ErrorGuaranteed> {
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

    let reachable = reachability::locally_reachable_from(tcx, entry).collect::<Vec<_>>();

    log::info!(
        "the {} reachable functions for {} in {} are {reachable:#?}",
        reachable.len(),
        P::property_name(),
        tcx.crate_name(LOCAL_CRATE)
    );

    // Filter for functions that aren't annotated as having obligations
    let reachable_no_obligations = reachable
        .into_iter()
        .filter(|func| {
            match annotations::parse_fn_def(tcx, &toml_annotations, func.reach, property) {
                Some(annotation) => {
                    // TODO: in the future, could check to make sure this annotation doesn't create unneeded obligations.
                    log::debug!(
                        "fn {:?} has obligations {:?}, we'll trust it...",
                        func.reach,
                        annotation
                    );
                    false
                }
                None => true,
            }
        })
        .collect::<Vec<_>>();

    log::info!(
        "the {} reachable, unannotated functions we need to check for {} in {} are {reachable_no_obligations:#?}",
        reachable_no_obligations.len(),
        P::property_name(),
        tcx.crate_name(LOCAL_CRATE)
    );

    // For all reachable local function definitions, ensure their axioms align with their annotations.
    for func in reachable_no_obligations {
        check_function_for_property(tcx, &toml_annotations, func, property)?;
    }

    Ok(())
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
