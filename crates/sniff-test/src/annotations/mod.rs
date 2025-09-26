//! The utilities needed to find and parse code annotations.

use crate::annotations::{attr::Attributeable, err::ParsingIssue};
use parsing::ParseBulletsFromString;
use rustc_middle::ty::TyCtxt;
use std::borrow::Borrow;


mod attr;
mod err;
mod parsing;
mod types;

pub use err::ParsingError;
pub use types::{Justification, Requirement};

impl Annotation<'static> for Requirement {
    type Input = rustc_span::def_id::DefId;
}

impl<'a> Annotation<'a> for Justification {
    type Input = rustc_hir::Expr<'a>;
}

/// A type that can be parsed from a given [`Input`](Annotation::Input) within the [`TyCtxt`].
pub trait Annotation<'a>: ParseBulletsFromString {
    type Input: Attributeable;

    /// Parse the given [`Input`](Annotation::Input).
    fn parse(tcx: TyCtxt, input: impl Borrow<Self::Input>) -> Result<Vec<Self>, ParsingError> {
        let input: &Self::Input = input.borrow();
        let doc_str: Result<String, ParsingIssue> =
            input.get_doc_str(tcx).ok_or(ParsingIssue::NoDocString);

        doc_str
            .and_then(|doc_str| Self::parse_bullets_from_string(&doc_str))
            .map_err(input.convert_err(tcx))
    }

    /// Try to parse the given [`Input`](Annotation::Input), returning `None` if
    /// there was an error, but the error was recoverable.
    fn try_parse(
        tcx: TyCtxt,
        input: impl Borrow<Self::Input>,
    ) -> Option<Result<Vec<Self>, ParsingError>> {
        let res = Self::parse(tcx, input);

        // If the error is recoverable, just return none instead.
        match res.as_ref().map_err(ParsingError::issue) {
            Err(ParsingIssue::NoDocString | ParsingIssue::NoMarkerPattern) => None,
            _unrecoverable => Some(res),
        }
    }
}
