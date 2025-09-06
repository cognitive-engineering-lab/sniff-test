//! The utilities needed to find and parse code annotations.
#![allow(dead_code)]

use crate::parsing::{
    err::{ParsingError, ParsingIssue},
    str::requirements_from_string,
};
use rustc_middle::ty::TyCtxt;
use rustc_public::DefId;
use rustc_span::Span;

mod err;
mod str;
mod types;

pub use types::Requirement;

/// Tries to parse the requirments for a given [`DefId`].
pub fn parse_requirements(
    tcx: TyCtxt<'_>,
    def_id: DefId,
) -> Result<Vec<Requirement>, ParsingError> {
    let (doc_str_val, doc_str_span) =
        get_doc_str(tcx, def_id).ok_or(ParsingIssue::NoDocString.into_error_at(
            def_id,
            tcx.def_span(rustc_public::rustc_internal::internal(tcx, def_id)),
        ))?;

    requirements_from_string(&doc_str_val)
        .map_err(|issue| issue.into_error_at(def_id, doc_str_span))
}

/// Finds the doc attribute of a given [`DefId`], returning it's value and the span where
/// it was found if present.
fn get_doc_str(tcx: TyCtxt<'_>, def_id: DefId) -> Option<(String, Span)> {
    tcx.get_attr(
        rustc_public::rustc_internal::internal(tcx, def_id),
        rustc_span::symbol::Symbol::intern("doc"),
    )
    .map(|attr| {
        (
            attr.doc_str()
                .expect("FIXME: honestly don't know when this can fail")
                .to_string(),
            attr.value_span().expect("also dont know why this can fail"),
        )
    })
}
