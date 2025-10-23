use itertools::Itertools;
use rustc_errors::{Diag, DiagCtxtHandle};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::{ErrorGuaranteed, source_map::Spanned};

use crate::{
    annotations::{self, Annotation},
    axioms::{self, Axiom, AxiomFinder, AxiomaticBadness},
    reachability::{self, CallsToBad, LocallyReachable},
    utils::SniffTestDiagnostic,
};

/// Checks that all local functions in the crate are properly annotated.
pub fn check_properly_annotated(tcx: TyCtxt) -> Result<(), ErrorGuaranteed> {
    let mut res = Ok(());

    let entry = reachability::annotated_local_entry_points(tcx).collect::<Vec<_>>();

    println!("entry is {entry:?}");

    let reachable = reachability::locally_reachable_from(tcx, entry).collect::<Vec<_>>();

    println!("reachable is {:?}", reachable);

    // For all reachable local function definitions, ensure their axioms align with their annotations.
    for reachable in reachable.iter().cloned() {
        let axioms = axioms::find_axioms(axioms::SafetyFinder, tcx, &reachable);

        let bad_calls = reachability::find_bad_calls(tcx, &reachable)
            .map_err(|parsing_error| parsing_error.diag(tcx.dcx()).emit())?;

        let annotations = annotations::Requirement::try_parse(tcx, reachable.reach.to_def_id());

        // For now, just check that all functions with axioms have some annotations.
        if annotations.is_none() && (!axioms.is_empty() || !bad_calls.is_empty()) {
            res = Err(needs_annotation(
                tcx.dcx(),
                tcx,
                reachable,
                FunctionIssues(axioms, bad_calls),
            ));
        }
    }

    res
}

struct FunctionIssues<A: Axiom>(Vec<Spanned<A>>, Vec<CallsToBad>);

pub fn check_function<F: AxiomFinder>(
    tcx: TyCtxt,
    fn_def: LocallyReachable,
) -> Result<(), FunctionIssues<F::Axiom>> {
    // Check that this function:
    //   a) contains no axiomatic bad things.
    //   b) contains no calls to bad functions.

    todo!()
}

fn needs_annotation<A: Axiom>(
    dcx: DiagCtxtHandle,
    tcx: TyCtxt,
    reachable: LocallyReachable,
    bc_of_isses: FunctionIssues<A>,
) -> ErrorGuaranteed {
    let def_span = tcx.def_span(reachable.reach);
    let fn_name = tcx.def_path_str(reachable.reach.to_def_id());

    let mut diag = dcx.struct_span_err(def_span, summary::summary_string(&fn_name, &bc_of_isses));

    diag = diag.with_note(reachability_str(&fn_name, tcx, reachable));

    for axiom in bc_of_isses.0 {
        diag = diag_handle_axiom(diag, axiom);
    }

    for bad_call in bc_of_isses.1 {
        diag = diag_handle_bad_call(diag, tcx, bad_call);
    }

    diag.emit()
}

fn diag_handle_bad_call<'d>(mut diag: Diag<'d>, tcx: TyCtxt, bad_call: CallsToBad) -> Diag<'d> {
    let (num, s) = if bad_call.from_spans.len() > 1 {
        (format!("{} ", bad_call.from_spans.len()), "s")
    } else {
        ("".to_string(), "")
    };
    let call_to = tcx.def_path_str(bad_call.def_id);
    diag = diag.with_span_note(
        bad_call.from_spans,
        format!("{num}call{s} to {call_to} here"),
    );

    diag
}

fn diag_handle_axiom<A: Axiom>(mut diag: Diag<'_>, axiom: Spanned<A>) -> Diag<'_> {
    diag = diag.with_span_note(axiom.span, format!("{} here", axiom.node));
    match axiom.node.known_requirements() {
        None => (),
        Some(AxiomaticBadness::Conditional(known_reqs)) => {
            // We know the conditional requirements, so display them
            let intro_string = "this axiom has known requirements:".to_string();

            let known_req_strs = known_reqs
                .into_iter()
                .enumerate()
                .map(|(i, req)| format!("\t{}. {}", i + 1, req.description()));

            diag = diag.with_help(
                std::iter::once(intro_string)
                    .chain(known_req_strs)
                    .join("\n"),
            );
        }
        Some(AxiomaticBadness::Unconditional) => todo!(),
    }

    diag
}

fn reachability_str(fn_name: &str, tcx: TyCtxt, reachable: LocallyReachable) -> String {
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

mod summary {
    use itertools::Itertools;
    use rustc_span::source_map::Spanned;

    use crate::axioms::Axiom;
    use crate::check::FunctionIssues;
    use crate::reachability::CallsToBad;

    pub fn summary_string<A: Axiom>(fn_name: &str, issues: &FunctionIssues<A>) -> String {
        let axiom_summary = axiom_summary(&issues.0);
        let call_summary = call_summary::<A>(&issues.1);
        let issue_summary = [axiom_summary, call_summary]
            .into_iter()
            .flatten()
            .join(" and ");

        let kind = A::axiom_kind_name();
        format!("function {fn_name} directly contains {issue_summary}, but is not annotated {kind}")
    }

    fn call_summary<A: Axiom>(calls: &[CallsToBad]) -> Option<String> {
        let count: usize = calls.iter().map(|call| call.from_spans.len()).sum();
        let kind = A::axiom_kind_name();
        let s = match count {
            1 => "",
            x if x > 1 => "s",
            _ => return None,
        };
        Some(format!("{count} call{s} to {kind} functions"))
    }

    fn axiom_summary<A: Axiom>(axioms: &[Spanned<A>]) -> Option<String> {
        let count = axioms.len();
        let kind = A::axiom_kind_name();
        let s = match count {
            1 => "",
            x if x > 1 => "s",
            _ => return None,
        };
        Some(format!("{count} {kind} axiom{s}"))
    }
}
