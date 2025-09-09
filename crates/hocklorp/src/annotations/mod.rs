//! The utilities needed to find and parse code annotations.
#![allow(dead_code)]

use err::ParsingError;
use rustc_middle::ty::TyCtxt;
use rustc_public::DefId;

mod err;
mod parsing;
mod types;

use parsing::ParseBulletsFromString;
pub use types::{Justification, Requirement};

/// Tries to parse the requirments for a given [`DefId`].
pub fn parse_requirements(
    tcx: TyCtxt<'_>,
    def_id: DefId,
) -> Result<Vec<Requirement>, ParsingError> {
    let doc_str = get_doc_str(tcx, def_id).ok_or(ParsingError::NoDocString)?;

    Requirement::parse_bullets_from_string(&doc_str)
}

/// Finds the doc attribute of a given [`DefId`], returning it's value and the span where
/// it was found if present.
fn get_doc_str(tcx: TyCtxt<'_>, def_id: DefId) -> Option<String> {
    let internal = rustc_public::rustc_internal::internal(tcx, def_id);

    let all_attrs = tcx.get_all_attrs(internal);

    let doc_strs = all_attrs
        .iter()
        .filter_map(|attr| {
            if let rustc_hir::Attribute::Parsed(kind) = attr
                && let rustc_hir::attrs::AttributeKind::DocComment {
                    style: _,
                    kind: _,
                    span: _,
                    comment,
                } = kind
            {
                Some(comment.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if doc_strs.is_empty() {
        None
    } else {
        Some(doc_strs.join("\n"))
    }
}
