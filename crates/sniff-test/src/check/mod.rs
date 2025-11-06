use itertools::Itertools;
use rustc_errors::{Diag, DiagCtxtHandle};
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::ty::TyCtxt;
use rustc_span::{
    DUMMY_SP, ErrorGuaranteed,
    source_map::{Spanned, respan},
    sym::todo_macro,
};

use crate::{
    annotations::{self, Annotation, ParsingError, Requirement, parsing::ParseBulletsFromString},
    axioms::{self, Axiom, AxiomFinder, AxiomaticBadness},
    reachability::{self, CallsToBad, LocallyReachable},
    utils::SniffTestDiagnostic,
};

mod expr;

fn load_external_requirements(
    path: &str,
) -> Result<std::collections::HashMap<String, String>, std::io::Error> {
    let text = std::fs::read_to_string(path)?;
    let value: toml::Value = toml::from_str(&text).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse TOML: {}", e),
        )
    })?;

    // Each val should be a table with exactly one key, "requirements"
    // Requirement's value should be a string
    if let Some(table) = value.as_table() {
        let mut reqs = std::collections::HashMap::new();
        for (key, val) in table {
            if let Some(inner_table) = val.as_table() {
                if inner_table.len() == 1 && inner_table.contains_key("requirements") {
                    if let Some(req_str) = inner_table["requirements"].as_str() {
                        reqs.insert(key.clone(), req_str.to_string());
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("Expected a string for 'requirements' in key '{}'", key),
                        ));
                    }
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Expected a single key 'requirements' for key '{}'", key),
                    ));
                }
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Expected a table for key '{}'", key),
                ));
            }
        }
        Ok(reqs)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Expected a TOML table at the top level",
        ))
    }
}

// Note, I don't really get and didn't fully implement the correct error handling for toml fallback.
fn get_requirements<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
    external_doc_strings: &std::collections::HashMap<String, String>,
) -> Option<Result<Vec<Spanned<Requirement>>, ParsingError<'tcx>>> {
    // First, try to parse from in-code annotations
    if let Some(in_code) = annotations::Requirement::try_parse(tcx, def_id) {
        return Some(in_code);
    }

    // Next, try to parse from external doc strings
    let fn_name = tcx.def_path_str(def_id);
    if let Some(doc_str) = external_doc_strings.get(&fn_name) {
        let parsed = match annotations::Requirement::parse_bullets_from_string(doc_str) {
            Ok(reqs) => Ok(reqs
                .into_iter()
                .map(|(req, range)| respan(DUMMY_SP, req))
                .collect()),
            Err(e) => {
                tcx.dcx()
                    .struct_warn(format!(
                        "Invalid external requirements for `{fn_name}`: {e:?}"
                    ))
                    .emit();
                return None;
            }
        };
        return Some(parsed);
    }

    // If neither source yielded requirements, return None
    None
}

/// Checks that all local functions in the crate are properly annotated.
pub fn check_properly_annotated(tcx: TyCtxt) -> Result<(), ErrorGuaranteed> {
    let mut res = Ok(());

    // Parse TOML file into map from fully qualified name to docstring (not yet implemented)
    let external_doc_strings = match load_external_requirements("sniff_test_requirements.toml") {
        Ok(map) => {
            println!("Loaded external requirements: {:?}", map);
            map
        }
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    // File not found, proceed without external requirements
                    println!("No external requirements file found, proceeding without it.");
                    std::collections::HashMap::new()
                }
                _ => {
                    // Other errors should be reported
                    tcx.dcx()
                        .struct_warn(format!("Failed to load external requirements: {}", e));
                    std::collections::HashMap::new()
                }
            }
        }
    };

    let entry = reachability::annotated_local_entry_points(tcx).collect::<Vec<_>>();

    // println!("entry is {entry:?}");

    let reachable = reachability::locally_reachable_from(tcx, entry).collect::<Vec<_>>();

    // println!("reachable is {reachable:?}");

    // For all reachable local function definitions, ensure their axioms align with their annotations.
    for reachable in reachable.iter().cloned() {
        let axioms = axioms::find_axioms(axioms::SafetyFinder, tcx, &reachable);

        // Try to parse requirements in code, if not found, try to parse from external doc strings
        let my_requirements =
            get_requirements(tcx, reachable.reach.to_def_id(), &external_doc_strings);

        // let find_requirements = |def_id| annotations::Requirement::parse(tcx, def_id);
        // let find_justifications = |def_id| annotations::Justification::parse(tcx, def_id);

        let bad_calls = reachability::find_bad_calls(tcx, &reachable)
            .map_err(|parsing_error| parsing_error.diag(tcx.dcx()).emit())?
            // Take only the unjustified call sites
            .map(only_unjustified_callsites(tcx, reachable.reach))
            // Filter out everything that no longer has call sites
            .filter(|calls| {
                !calls
                    .as_ref()
                    .is_ok_and(|calls| calls.from_spans.is_empty())
            })
            .collect::<Result<Vec<_>, ErrorGuaranteed>>()?;

        // let justifications = annotations::Justification::try_parse(tcx, todo!());

        // For now, just check that all functions with axioms have some annotations.
        if my_requirements.is_none() && (!axioms.is_empty() || !bad_calls.is_empty()) {
            res = Err(needs_annotation(
                tcx.dcx(),
                tcx,
                &reachable,
                FunctionIssues(axioms, bad_calls),
            ));
        }
    }

    res
}

fn only_unjustified_callsites(
    tcx: TyCtxt,
    in_fn: LocalDefId,
) -> impl Fn(CallsToBad) -> Result<CallsToBad, ErrorGuaranteed> {
    move |mut calls| {
        let mut new_spans = Vec::new();
        let requirements =
            annotations::Requirement::parse(tcx, calls.def_id).map_err(|e| e.emit(tcx.dcx()))?;

        for call_span in calls.from_spans {
            let expr = expr::find_expr_for_call(tcx, calls.def_id, in_fn, call_span);
            let justs = annotations::Justification::try_parse(tcx, expr);
            // println!("justs are {justs:?}");
            match justs {
                Some(Err(e)) => return Err(e.emit(tcx.dcx())),
                Some(Ok(justs)) => annotations::check::check_consistency(&justs, &requirements)
                    .map_err(|e| e.diag(tcx.dcx()).emit())?,
                None => new_spans.push(call_span),
            }
        }
        calls.from_spans = new_spans;
        Ok(calls)
    }
}

struct FunctionIssues<A: Axiom>(Vec<Spanned<A>>, Vec<CallsToBad>);

// pub fn check_function<F: AxiomFinder>(
//     tcx: TyCtxt,
//     fn_def: LocallyReachable,
// ) -> Result<(), FunctionIssues<F::Axiom>> {
//     // Check that this function:
//     //   a) contains no axiomatic bad things.
//     //   b) contains no calls to bad functions.

//     todo!()
// }

fn needs_annotation<A: Axiom>(
    dcx: DiagCtxtHandle,
    tcx: TyCtxt,
    reachable: &LocallyReachable,
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
    // let times = if bad_call.from_spans.len() > 1 {
    //     format!("{} times ", bad_call.from_spans.len())
    // } else {
    //     String::new()
    // };
    let call_to = tcx.def_path_str(bad_call.def_id);
    diag = diag.with_span_note(bad_call.from_spans, format!("{call_to} is called here"));

    diag
}

#[allow(clippy::needless_pass_by_value)]
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
        Some(format!("{count} unjustified call{s} to {kind} functions"))
    }

    fn axiom_summary<A: Axiom>(axioms: &[Spanned<A>]) -> Option<String> {
        let count = axioms.len();
        let kind = A::axiom_kind_name();
        let s = match count {
            1 => "",
            x if x > 1 => "s",
            _ => return None,
        };
        Some(format!("{count} unjustified {kind} axiom{s}"))
    }
}
