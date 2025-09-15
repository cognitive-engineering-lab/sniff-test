//! The utilities needed to find and parse code annotations.
#![allow(dead_code)]

use std::borrow::Borrow;

use rustc_hir::HirId;
use rustc_middle::ty::TyCtxt;

mod err;
mod parsing;
mod types;

pub use err::{ParsingError, ParsingErrorLoc};
use parsing::ParseBulletsFromString;
pub use types::{Justification, Requirement};

impl Annotation for Requirement {
    type Input = rustc_span::def_id::DefId;
}

impl Annotation for Justification {
    type Input = HirId;
}

pub trait Annotation: ParseBulletsFromString {
    type Input: Attributeable;

    fn parse(tcx: TyCtxt<'_>, input: impl Borrow<Self::Input>) -> Result<Vec<Self>, ParsingError> {
        let doc_str = input
            .borrow()
            .get_doc_str(tcx)
            .ok_or(ParsingError::NoDocString)?;

        Self::parse_bullets_from_string(&doc_str)
    }

    fn try_parse(
        tcx: TyCtxt<'_>,
        input: impl Borrow<Self::Input>,
    ) -> Option<Result<Vec<Self>, ParsingError>> {
        match Self::parse(tcx, input) {
            Err(ParsingError::NoDocString | ParsingError::NoMarkerPattern) => None,
            unrecoverable => Some(unrecoverable),
        }
    }
}

impl Attributeable for rustc_span::def_id::DefId {
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute] {
        tcx.get_all_attrs(*self)
    }
}

impl Attributeable for HirId {
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute] {
        tcx.hir_attrs(*self)
    }
}

pub trait Attributeable {
    fn get_attrs<'tcx>(&self, tcx: TyCtxt<'tcx>) -> &'tcx [rustc_hir::Attribute];

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
