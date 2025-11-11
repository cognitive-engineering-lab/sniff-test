use itertools::Itertools;
use rustc_errors::{Diag, DiagCtxtHandle};
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::ty::TyCtxt;
use rustc_span::{ErrorGuaranteed, source_map::Spanned, sym::todo_macro};

use crate::{
    annotations::{self, parse_expr},
    properties::{self, Axiom, Property},
    reachability::{self, CallsWObligations, LocallyReachable},
    utils::SniffTestDiagnostic,
};

mod err;
mod expr;

/// Checks that all local functions in the crate are properly annotated.
pub fn check_properly_annotated<P: Property>(
    tcx: TyCtxt,
    property: P,
) -> Result<(), ErrorGuaranteed> {
    let entry = reachability::local_entry_points::<P>(tcx);

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
        log::debug!("entry is {entries:#?}");
    }

    let reachable = reachability::locally_reachable_from(tcx, entry).collect::<Vec<_>>();

    log::debug!("reachable is {reachable:#?}");

    // For all reachable local function definitions, ensure their axioms align with their annotations.
    for func in reachable {
        check_function_properties(tcx, func, property)?;
    }

    Ok(())
}

fn check_function_properties<P: Property>(
    tcx: TyCtxt,
    func: LocallyReachable,
    property: P,
) -> Result<(), ErrorGuaranteed> {
    // Look for the local annotation
    let annotation = annotations::parse_fn_def(tcx, func.reach, property);

    // If the function we're analyzing is directly annotated, we trust the user's annotation
    // and don't need to analyze its body locally. Vitally, we'll still explore functions it calls
    // due to collecting reachability earlier.
    if let Some(annotation) = annotation {
        // TODO: in the future, could check to make sure this annotation doesn't create unneeded obligations.
        return Ok(());
    }

    // Look for all axioms within this function
    let axioms = properties::find_axioms(tcx, &func, property);

    log::debug!("fn {:?} has axioms {:?}", func.reach, axioms);
    log::debug!("fn {:?} has obligations {:?}", func.reach, annotation);

    // Find all calls that have obligations.
    let unjustified_calls = reachability::find_calls_w_obligations(tcx, &func, property)
        // Filter those with only callsites that haven't been justified.
        .filter_map(only_unjustified_callsites(tcx, func.reach, property))
        .collect::<Vec<_>>();

    // If we have obligations, we've dismissed them

    if unjustified_calls.is_empty() && axioms.is_empty() {
        // Nothing to report, all good!
        Ok(())
    } else {
        // Unjustified issues, report them!!
        Err(err::report_errors(
            tcx,
            func,
            property,
            axioms,
            unjustified_calls,
        ))
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
        let obligations = &calls.w_annotation;

        for call_span in calls.from_spans {
            let call_expr = expr::find_expr_for_call(tcx, calls.call_to, in_fn, call_span);
            let callsite_annotation = parse_expr(tcx, *call_expr, property);

            println!("found justification {callsite_annotation:?}");

            if callsite_annotation.is_none() {
                new_spans.push(call_span);
            }
        }

        println!("found spans {new_spans:?}");

        // If we have no new callsites, just remove this one from the list...
        if new_spans.is_empty() {
            None
        } else {
            calls.from_spans = new_spans;
            Some(calls)
        }
    }
}

fn reachability_str(fn_name: &str, tcx: TyCtxt, reachable: &LocallyReachable) -> String {
    let reachability_str = reachable
        .through
        .iter()
        .map(|def| {
            let name = tcx.def_path_str(def.0);
            let s = tcx
                .sess
                .source_map()
                .span_to_string(def.1, rustc_span::FileNameDisplayPreference::Local);
            let colon = s.find(": ").expect("should have a colon");
            format!("{name} ({})", &s[..colon])
        })
        .chain(std::iter::once(format!("*{fn_name}*")))
        .join(" -> ");

    format!("reachable from [{reachability_str}]")
}
