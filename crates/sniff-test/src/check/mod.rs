use itertools::Itertools;
use rustc_errors::DiagCtxtHandle;
use rustc_middle::ty::TyCtxt;
use rustc_span::{ErrorGuaranteed, Span, SpanData, source_map::Spanned};

use crate::{
    annotations::{self, Annotation},
    axioms::{self, Axiom},
    reachability::{self, LocalReachable},
};

/// Checks that all local functions in the crate are properly annotated.
pub fn check_properly_annotated(tcx: TyCtxt) -> Result<(), ErrorGuaranteed> {
    let mut res = Ok(());

    let entry = reachability::annotated_local_entry_points(tcx);

    let entry = entry.collect::<Vec<_>>();

    println!("entry is {entry:?}");

    let reachable = reachability::local_reachable_from(tcx, entry).collect::<Vec<_>>();

    println!("reachable is {:?}", reachable);

    for reachable in reachable.iter().cloned() {
        let name = &tcx.def_path_debug_str(reachable.reach.to_def_id());
        let axioms = axioms::find_axioms(
            axioms::SafetyFinder,
            tcx,
            tcx.hir_body_owned_by(reachable.reach).id(),
        );

        let annotations = annotations::Requirement::try_parse(tcx, reachable.reach.to_def_id());

        if !axioms.is_empty() && annotations.is_none() {
            res = Err(needs_annotation(tcx.dcx(), tcx, reachable, axioms));
            // println!("err from {name}");
        }
    }

    res
}

fn needs_annotation<A: Axiom>(
    dcx: DiagCtxtHandle,
    tcx: TyCtxt,
    reachable: LocalReachable,
    bc_of_axioms: Vec<Spanned<A>>,
) -> ErrorGuaranteed {
    let def_span = tcx.def_span(reachable.reach);
    let fn_name = tcx.def_path_str(reachable.reach.to_def_id());
    let mut diag = dcx.struct_span_err(
        def_span,
        format!("function {fn_name} has unsafe axioms, but is not annotated unsafe"),
    );

    let reachability_str = reachable
        .from
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

    diag = diag.with_help(format!("(reachable from [{reachability_str}])"));

    for axiom in bc_of_axioms {
        diag = diag.with_span_note(axiom.span, format!("{} here", axiom.node));
        if let Some(known_reqs) = axiom.node.known_requirements() {
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
    }

    diag.emit()
}
