//! Utilities for getting attributes from relevant pieces of a program.

use crate::annotations::{ParsingError, err::ParsingIssue};
use rustc_middle::ty::TyCtxt;

impl Attributeable for rustc_span::def_id::DefId {
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute] {
        tcx.get_all_attrs(*self)
    }

    fn convert_err<'tcx>(&self, tcx: TyCtxt<'tcx>) -> impl Fn(ParsingIssue) -> ParsingError<'tcx> {
        move |issue| issue.at_fn_def(*self, tcx)
    }
}

impl Attributeable for rustc_hir::Expr<'_> {
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute] {
        tcx.hir_attrs(self.hir_id)
    }

    fn convert_err<'tcx>(&self, tcx: TyCtxt<'tcx>) -> impl Fn(ParsingIssue) -> ParsingError<'tcx> {
        move |issue| issue.at_callsite(self, self.hir_id.owner.to_def_id(), tcx)
    }
}

/// A trait for items from which you can get a list of HIR attributes from the typing context.
pub trait Attributeable {
    /// Get the HIR attributes for this item.
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute];

    /// Returns a function that can be used to add additional context to [`ParsingIssue`]s,
    /// turning them into full [`ParsingError`]s that can be rendered to the user.
    fn convert_err<'tcx>(&self, tcx: TyCtxt<'tcx>) -> impl Fn(ParsingIssue) -> ParsingError<'tcx>;

    /// Get the full string of all doc attributes on n item concatenated together.
    fn get_doc_str(&self, tcx: TyCtxt<'_>) -> Option<String> {
        let all_attrs = self.get_attrs(tcx);

        // Filter for doc comments.
        let doc_comments = all_attrs
            .iter()
            .filter_map(|attr| attr.doc_str().map(|a| a.as_str().to_owned()))
            .collect::<Vec<_>>();

        // Return none if no doc comments were found
        if doc_comments.is_empty() {
            None
        } else {
            Some(doc_comments.join("\n"))
        }
    }
}
