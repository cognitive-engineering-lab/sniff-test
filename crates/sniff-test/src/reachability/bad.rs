//! Finds the 'bad' functions that should be annotated

use crate::annotations::{Annotation, Requirement};
use std::collections::HashMap;

use crate::utils::MultiEmittable;

use rustc_middle::ty::TyCtxt;
use rustc_public::mir::Safety;
use rustc_public::{CrateItem, ty::FnDef};
use rustc_span::ErrorGuaranteed;

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

    if !bad_but_missed.is_empty() {
        panic!(
            "some functions should be annotated for the following reasons, but are not {:?}",
            bad_but_missed
        );
    }

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

    return None;
}
