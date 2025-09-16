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
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute];

    fn convert_err<'tcx>(&self, tcx: TyCtxt<'tcx>) -> impl Fn(ParsingIssue) -> ParsingError<'tcx>;

    fn get_doc_str(&self, tcx: TyCtxt<'_>) -> Option<String> {
        let all_attrs = self.get_attrs(tcx);

        let doc_strs = all_attrs
            .iter()
            .filter_map(|attr| {
                if let rustc_hir::Attribute::Parsed(kind) = attr
                    && let rustc_hir::attrs::AttributeKind::DocComment { comment, .. } = kind
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
}
