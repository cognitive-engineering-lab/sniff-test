//! Utilities for getting attributes & doc strings from relevant pieces of a program.

use crate::annotations::DocStrSource;
use rustc_middle::ty::TyCtxt;

/// Get the full string of all doc attributes on n item concatenated together.
pub fn get_comment_doc_str<T: Attributeable>(
    item: T,
    tcx: TyCtxt,
) -> Option<(String, DocStrSource)> {
    let all_attrs = item.get_attrs(tcx);

    let (doc_attrs, doc_comments) = all_attrs
        .iter()
        .filter_map(|attr| {
            attr.doc_str()
                .map(|a| (attr.clone(), a.as_str().to_owned()))
        })
        .collect::<(Vec<_>, Vec<_>)>();

    // Return none if no doc comments were found
    if doc_comments.is_empty() {
        None
    } else {
        Some((doc_comments.join("\n"), DocStrSource::DocComment(doc_attrs)))
    }
}

/// A trait for items from which you can get a list of HIR attributes from the typing context.
pub trait Attributeable {
    /// Get the HIR attributes for this item.
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute];
}

impl Attributeable for rustc_span::def_id::DefId {
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute] {
        tcx.get_all_attrs(*self)
    }
}

impl Attributeable for rustc_hir::Expr<'_> {
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute] {
        tcx.hir_attrs(self.hir_id)
    }
}

impl Attributeable for rustc_hir::HirId {
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute] {
        tcx.hir_attrs(*self)
    }
}

impl Attributeable for rustc_hir::Block<'_> {
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute] {
        tcx.hir_attrs(tcx.parent_hir_id(self.hir_id))
    }
}
