//! Finds the 'bad' functions that should be annotated

use crate::annotations::{self, Annotation, ParsingError, Requirement};
use crate::reachability::LocallyReachable;
use std::collections::HashMap;

use crate::utils::MultiEmittable;
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_public::mir::Safety;
use rustc_public::ty::FnDef;
use rustc_span::{ErrorGuaranteed, Span};

pub struct CallsToBad {
    pub def_id: DefId,
    pub requirements: Vec<annotations::Requirement>,
    pub from_spans: Vec<Span>,
}

fn is_call_bad<'tcx>(
    tcx: TyCtxt<'tcx>,
) -> impl Fn((&DefId, &Vec<Span>)) -> Option<Result<CallsToBad, ParsingError<'tcx>>> {
    move |(to_def_id, from_spans)| {
        let requirements = match Requirement::try_parse(tcx, to_def_id)? {
            Err(e) => return Some(Err(e)),
            Ok(req) => req,
        };

        // match
        Some(Ok(CallsToBad {
            def_id: *to_def_id,
            requirements,
            from_spans: from_spans.clone(),
        }))
    }
}

pub fn find_bad_calls<'tcx>(
    tcx: TyCtxt<'tcx>,
    locally_reachable: &LocallyReachable,
) -> Result<Vec<CallsToBad>, ParsingError<'tcx>> {
    locally_reachable
        .calls_to
        .iter()
        .filter_map(is_call_bad(tcx))
        .collect::<Result<Vec<_>, ParsingError>>()
}

pub fn filter_bad_functions(
    tcx: TyCtxt,
    items: &[FnDef],
) -> Result<HashMap<FnDef, Vec<Requirement>>, ErrorGuaranteed> {
    let annotated_bad = items
        .iter()
        .filter_map(|item| {
            Some((
                *item,
                Requirement::try_parse(tcx, rustc_public::rustc_internal::internal(tcx, item.0))?,
            ))
        })
        .collect::<HashMap<_, _>>()
        .emit_all_errors(tcx)?;

    let should_be_bad = items
        .iter()
        .filter_map(|fn_def| Some((fn_def, should_be_bad(tcx, *fn_def)?)));

    let bad_but_missed = should_be_bad
        .filter(|(fn_def, _reason)| !annotated_bad.contains_key(fn_def))
        .collect::<Box<[_]>>();

    assert!(
        bad_but_missed.is_empty(),
        "some functions should be annotated for the following reasons, but are not {bad_but_missed:?}"
    );

    Ok(annotated_bad)
}

#[derive(Debug)]
pub enum ShouldBeBadReason {
    MarkedUnsafe,
    // SpecifiedInToml?
}

// TODO: add config from .toml file.
fn should_be_bad(_tcx: TyCtxt, fn_def: FnDef) -> Option<ShouldBeBadReason> {
    if fn_def.fn_sig().value.safety == Safety::Unsafe {
        return Some(ShouldBeBadReason::MarkedUnsafe);
    }

    None
}
