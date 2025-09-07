use rustc_errors::{Diag, DiagCtxtHandle};
use rustc_public::DefId;
use rustc_span::{ErrorGuaranteed, Span};

use crate::annotations::types::InvalidConditionNameReason;

pub struct ParsingError {
    /// The issue that caused us to fail.
    issue: ParsingIssue,
    /// The function we were analyzing when the error happened.
    def_id: DefId,
    /// The span where we should report the error.
    span: Span,
}

impl ParsingError {
    /// Emit this as a readable compiler error for the end user.
    pub fn emit(&self, dcx: DiagCtxtHandle<'_>) -> ErrorGuaranteed {
        self.issue
            .diag(dcx, self.def_id)
            .with_span(self.span)
            .emit()
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum ParsingIssue {
    /// The `FnDef` in question doesn't have a `#[doc(..)]` attribute.
    NoDocString,
    /// No marker patterns were found.
    NoMarkerPattern,
    /// Multiple marker patters were found.
    MultipleMarkerPatterns,
    /// No colon delimiter was found after the condition name.
    ///
    /// This probably should just default in an empty description but, for now, is an error.
    NoColon,
    /// A marker was found, but it had no requirements.
    EmptyMarker,
    /// The name of a condition was invalid.
    InvalidConditionName(InvalidConditionNameReason),
    /// The bullet types found were non-matching.
    NonMatchingBullets,
}

impl ParsingIssue {
    pub(crate) fn diag<'s, 'a: 's>(&'s self, dcx: DiagCtxtHandle<'a>, def_id: DefId) -> Diag<'a> {
        dcx.struct_err(format!(
            "had an issue {self:?} when parsing FnDef {def_id:?}"
        ))
    }

    pub(crate) fn into_error_at(self, def_id: DefId, span: Span) -> ParsingError {
        ParsingError {
            issue: self,
            def_id,
            span,
        }
    }
}
