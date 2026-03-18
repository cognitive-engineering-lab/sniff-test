use crate::{
    check::LocalError,
    properties::UnjustifiedAxiom,
    reachability::{Reachability, WithReachability},
};
use itertools::Itertools;
use rustc_errors::Diag;
use rustc_middle::ty::TyCtxt;
use rustc_span::ErrorGuaranteed;

use crate::{properties::Property, reachability::CallsWObligations};

pub fn report_errors<P: Property>(
    tcx: TyCtxt,
    _property: P,
    errors: impl IntoIterator<Item = WithReachability<LocalError<P>>>,
) -> ErrorGuaranteed {
    errors
        .into_iter()
        .map(|error| report_error(tcx, error))
        .last()
        .expect("don't call this on empty errors")
}

fn report_error<P: Property>(
    tcx: TyCtxt,
    WithReachability(error, reachabilty): WithReachability<LocalError<P>>,
) -> ErrorGuaranteed {
    let dcx = tcx.dcx();
    let def_span = tcx.def_span(*error.func());
    let fn_name = tcx.def_path_str(*error.func());

    match error {
        LocalError::Basic { func: _, _property, unjustified_axioms, unjustified_calls } => {
            let mut diag = dcx.struct_span_err(
                def_span,
                summary::summary_string::<P>(&fn_name, &unjustified_axioms, &unjustified_calls),
            );

            // TODO: fix reachability here soon...
            diag = diag.with_note(reachability_str(&fn_name, tcx, &reachabilty));

            for axiom in unjustified_axioms {
                diag = extend_diag_axiom::<P>(diag, axiom);
            }

            for calls in unjustified_calls {
                diag = extend_diag_calls(diag, tcx, calls);
            }

            diag.emit()
        },
        LocalError::CallMissedObligations { callsite_comment: _, callsite_span, obligations, .. } => {
            dcx.struct_span_err(
                callsite_span,
                format!("call to {fn_name} here fails to consider its named obligations {obligations:?}"),
            ).emit()
        },
        LocalError::FnDefShouldHaveKeyword { needed_keyword, .. } => {
            dcx.struct_span_err(
                def_span,
                format!("function definition of {fn_name} here should have the {needed_keyword} keyword because of the {} property", P::property_name()),
            ).emit()
        },
        LocalError::Trait { inconsistent_w_trait, .. } => {
            dcx.struct_span_err(
                def_span,
                format!("implementation {fn_name} here has {} obligations that are inconsistent with those on the definition of the {} trait", tcx.def_path_debug_str(inconsistent_w_trait), P::property_name()),
            ).with_span_note(tcx.def_span(inconsistent_w_trait), "which is defined here").emit()
        }
    }
}

fn extend_diag_axiom<P: Property>(diag: Diag, axiom: UnjustifiedAxiom<P::Axiom>) -> Diag {
    // TODO: add notes about the known requirements
    diag.with_span_note(axiom.span, format!("{} here", axiom.axiom))
}

fn extend_diag_calls<'tcx>(
    diag: Diag<'tcx>,
    tcx: TyCtxt<'tcx>,
    calls: CallsWObligations,
) -> Diag<'tcx> {
    let call_to = tcx.def_path_str(calls.call_to);
    diag.with_span_note(calls.from_spans, format!("{call_to} is called here"))
}

fn reachability_str(fn_name: &str, tcx: TyCtxt, reachable: &Reachability) -> String {
    let reachability_str = reachable
        .through()
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

    use crate::properties::{Property, UnjustifiedAxiom};
    use crate::reachability::CallsWObligations;

    pub fn summary_string<P: Property>(
        fn_name: &str,
        axioms: &[UnjustifiedAxiom<P::Axiom>],
        calls: &[CallsWObligations],
    ) -> String {
        let axiom_summary = axiom_summary::<P>(axioms);
        let call_summary = call_summary::<P>(calls);
        let issue_summary = [axiom_summary, call_summary]
            .into_iter()
            .flatten()
            .join(" and ");

        let kind = P::property_name();
        format!("function {fn_name} directly contains {issue_summary}, but is not annotated {kind}")
    }

    fn call_summary<P: Property>(calls: &[CallsWObligations]) -> Option<String> {
        let count: usize = calls.iter().map(|call| call.from_spans.len()).sum();
        let kind = P::property_name();
        let s = match count {
            1 => "",
            x if x > 1 => "s",
            _ => return None,
        };
        Some(format!(
            "{count} unjustified call{s} to annotated {kind} functions"
        ))
    }

    fn axiom_summary<P: Property>(axioms: &[UnjustifiedAxiom<P::Axiom>]) -> Option<String> {
        let count = axioms.len();
        let kind = P::property_name();
        let s = match count {
            1 => "",
            x if x > 1 => "s",
            _ => return None,
        };
        Some(format!("{count} unjustified {kind} axiom{s}"))
    }
}
