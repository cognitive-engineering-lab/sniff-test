use itertools::Itertools;
use rustc_errors::{DiagCtxt, DiagCtxtHandle};
use rustc_middle::ty::TyCtxt;
use rustc_span::{ErrorGuaranteed, Span, source_map::Spanned};

use crate::{
    annotations::{self, Annotation},
    axioms::{self, Axiom},
};

/// Checks that all local functions in the crate are properly annotated.
pub fn check_properly_annotated(tcx: TyCtxt) -> Result<(), ErrorGuaranteed> {
    for local_def_id in tcx.hir_body_owners() {
        let name = &tcx.def_path_debug_str(local_def_id.to_def_id());
        let axioms = axioms::find_axioms(
            axioms::SafetyFinder,
            tcx,
            tcx.hir_body_owned_by(local_def_id).id(),
        );
        println!("{name}: axioms are {axioms:?}");

        let annotations = annotations::Requirement::try_parse(tcx, local_def_id.to_def_id());
        println!("{name}: annotations are {annotations:?}");

        if !axioms.is_empty() && annotations.is_none() {
            return Err(needs_annotation(
                tcx.dcx(),
                name,
                tcx.def_span(local_def_id.to_def_id()),
                axioms,
            ));
        }
    }

    todo!()
}

fn needs_annotation<A: Axiom>(
    dcx: DiagCtxtHandle,
    fn_name: &str,
    def_span: Span,
    bc_of_axioms: Vec<Spanned<A>>,
) -> ErrorGuaranteed {
    let mut diag = dcx.struct_span_err(
        def_span,
        format!("function {fn_name} has unsafe axioms, but is not annotated unsafe"),
    );

    for axiom in bc_of_axioms {
        diag = diag.with_span_note(axiom.span, format!("{} here", axiom.node));
        if let Some(known_reqs) = axiom.node.known_requirements() {
            let intro_string = format!("this axiom has known requirements:");

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
