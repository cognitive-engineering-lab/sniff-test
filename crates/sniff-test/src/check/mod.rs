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

mod expr;

/// Checks that all local functions in the crate are properly annotated.
pub fn check_properly_annotated(tcx: TyCtxt) -> Result<(), ErrorGuaranteed> {
    let entry = reachability::local_entry_points(tcx).collect::<Vec<_>>();

    // Debug print all our entries and where they are in the src
    // (this isn't actually needed for analysis)
    let entries = entry
        .iter()
        .map(|local| {
            let span = tcx.optimized_mir(local.to_def_id()).span;
            (local, span)
        })
        .collect::<Vec<_>>();
    log::debug!("entry is {entries:#?}");

    let reachable = reachability::locally_reachable_from(tcx, entry).collect::<Vec<_>>();

    log::debug!("reachable is {reachable:#?}");

    // For all reachable local function definitions, ensure their axioms align with their annotations.
    for func in reachable {
        check_function_properties(tcx, func, properties::SafetyProperty)?;
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
    let bad_calls = reachability::find_calls_w_obligations(tcx, &func, property)
        // Filter those with only callsites that haven't been justified.
        .filter_map(only_unjustified_callsites(tcx, func.reach, property))
        .collect::<Vec<_>>();

    // If we have obligations, we've dismissed them

    // todo!()
    if bad_calls.is_empty() {
        Ok(())
    } else {
        Err(tcx.dcx().struct_err("sniff test failed!").emit())
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

// struct FunctionIssues<A: Axiom>(Vec<Spanned<A>>, Vec<CallsToBad>);

// pub fn check_function<F: AxiomFinder>(
//     tcx: TyCtxt,
//     fn_def: LocallyReachable,
// ) -> Result<(), FunctionIssues<F::Axiom>> {
//     // Check that this function:
//     //   a) contains no axiomatic bad things.
//     //   b) contains no calls to bad functions.

//     todo!()
// }

// fn needs_annotation<A: Axiom>(
//     dcx: DiagCtxtHandle,
//     tcx: TyCtxt,
//     reachable: &LocallyReachable,
//     bc_of_isses: FunctionIssues<A>,
// ) -> ErrorGuaranteed {
//     let def_span = tcx.def_span(reachable.reach);
//     let fn_name = tcx.def_path_str(reachable.reach.to_def_id());

//     let mut diag = dcx.struct_span_err(def_span, summary::summary_string(&fn_name, &bc_of_isses));

//     diag = diag.with_note(reachability_str(&fn_name, tcx, reachable));

//     for axiom in bc_of_isses.0 {
//         diag = diag_handle_axiom(diag, axiom);
//     }

//     for bad_call in bc_of_isses.1 {
//         diag = diag_handle_bad_call(diag, tcx, bad_call);
//     }

//     diag.emit()
// }

// fn diag_handle_bad_call<'d>(mut diag: Diag<'d>, tcx: TyCtxt, bad_call: CallsToBad) -> Diag<'d> {
//     // let times = if bad_call.from_spans.len() > 1 {
//     //     format!("{} times ", bad_call.from_spans.len())
//     // } else {
//     //     String::new()
//     // };
//     let call_to = tcx.def_path_str(bad_call.def_id);
//     diag = diag.with_span_note(bad_call.from_spans, format!("{call_to} is called here"));

//     diag
// }

// #[allow(clippy::needless_pass_by_value)]
// fn diag_handle_axiom<A: Axiom>(mut diag: Diag<'_>, axiom: Spanned<A>) -> Diag<'_> {
//     diag = diag.with_span_note(axiom.span, format!("{} here", axiom.node));
//     match axiom.node.known_requirements() {
//         None => (),
//         Some(AxiomaticBadness::Conditional(known_reqs)) => {
//             // We know the conditional requirements, so display them
//             let intro_string = "this axiom has known requirements:".to_string();

//             let known_req_strs = known_reqs
//                 .into_iter()
//                 .enumerate()
//                 .map(|(i, req)| format!("\t{}. {}", i + 1, req.description()));

//             diag = diag.with_help(
//                 std::iter::once(intro_string)
//                     .chain(known_req_strs)
//                     .join("\n"),
//             );
//         }
//         Some(AxiomaticBadness::Unconditional) => todo!(),
//     }

//     diag
// }

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

// mod summary {
//     use itertools::Itertools;
//     use rustc_span::source_map::Spanned;

//     use crate::check::FunctionIssues;
//     use crate::properties::Axiom;
//     use crate::reachability::CallsToBad;

//     pub fn summary_string<A: Axiom>(fn_name: &str, issues: &FunctionIssues<A>) -> String {
//         let axiom_summary = axiom_summary(&issues.0);
//         let call_summary = call_summary::<A>(&issues.1);
//         let issue_summary = [axiom_summary, call_summary]
//             .into_iter()
//             .flatten()
//             .join(" and ");

//         let kind = A::axiom_kind_name();
//         format!("function {fn_name} directly contains {issue_summary}, but is not annotated {kind}")
//     }

//     fn call_summary<A: Axiom>(calls: &[CallsToBad]) -> Option<String> {
//         let count: usize = calls.iter().map(|call| call.from_spans.len()).sum();
//         let kind = A::axiom_kind_name();
//         let s = match count {
//             1 => "",
//             x if x > 1 => "s",
//             _ => return None,
//         };
//         Some(format!("{count} unjustified call{s} to {kind} functions"))
//     }

//     fn axiom_summary<A: Axiom>(axioms: &[Spanned<A>]) -> Option<String> {
//         let count = axioms.len();
//         let kind = A::axiom_kind_name();
//         let s = match count {
//             1 => "",
//             x if x > 1 => "s",
//             _ => return None,
//         };
//         Some(format!("{count} unjustified {kind} axiom{s}"))
//     }
// }
