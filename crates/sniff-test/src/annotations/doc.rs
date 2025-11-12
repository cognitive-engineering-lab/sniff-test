//! Utilities for getting attributes & doc strings from relevant pieces of a program.

use std::ops::Range;

use super::span::Mergeable;
use rustc_hir::Attribute;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

#[derive(Debug)]
pub struct DocStr<'tcx>(String, &'tcx [Attribute]);

impl DocStr<'_> {
    pub fn str(&self) -> &str {
        &self.0
    }

    pub fn span_of_chars(&self, chars: Range<usize>) -> Span {
        super::span::span_some_comments(self.1, chars)
            .merge_adjacent()
            .into_iter()
            .next()
            .expect("should have a span")
    }
}

/// Get the full string of all doc attributes on n item concatenated together.
pub fn get_doc_str<T: Attributeable>(item: T, tcx: TyCtxt) -> Option<DocStr> {
    let all_attrs = item.get_attrs(tcx);

    // Filter for doc comments.
    let doc_comments = all_attrs
        .iter()
        .filter_map(|attr| attr.doc_str().map(|a| a.as_str().to_owned()))
        .collect::<Vec<_>>();

    // Return none if no doc comments were found
    if doc_comments.is_empty() {
        None
    } else {
        Some(DocStr(doc_comments.join("\n"), all_attrs))
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

impl Attributeable for rustc_hir::Block<'_> {
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute] {
        tcx.hir_attrs(tcx.parent_hir_id(self.hir_id))
    }
}
