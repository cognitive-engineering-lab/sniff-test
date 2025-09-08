//! The utilities needed to find and parse code annotations.
#![allow(dead_code)]

use err::{ParsingError, ParsingIssue};
use rustc_middle::ty::TyCtxt;
use rustc_public::DefId;
use rustc_span::Span;

mod err;
mod parsing;
mod types;

pub use types::{Justification, Requirement};
use parsing::ParseBulletsFromString;

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

    Requirement::parse_bullets_from_string(&doc_str_val)
        .map_err(|issue| issue.into_error_at(def_id, doc_str_span))
}

/// Finds the doc attribute of a given [`DefId`], returning it's value and the span where
/// it was found if present.
fn get_doc_str(tcx: TyCtxt<'_>, def_id: DefId) -> Option<(String, Span)> {
    let internal = rustc_public::rustc_internal::internal(tcx, def_id);
    println!("internal is {internal:?}");
    let all = tcx.get_all_attrs(internal);
    println!("all is {all:?}");
    if let Some(first) = all.first() {
        let joined_str = all.iter().filter_map(|attr|{
            if let rustc_hir::Attribute::Parsed(kind) = attr && let rustc_hir::attrs::AttributeKind::DocComment { style, kind, span, comment } = kind {
                Some(comment.as_str())
            } else {
                None
            }
        }).collect::<Vec<&str>>().join("\n");

        let span = first.span();
        Some((joined_str, span))
    } else { None }
}
