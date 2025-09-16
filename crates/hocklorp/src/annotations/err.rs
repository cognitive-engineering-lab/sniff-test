//! Error handling and pretty printing using rustc's diagnostics.

use crate::annotations::err::span::{span_all_comments, span_some_comments};
use crate::annotations::{Attributeable, types::InvalidConditionNameReason};
use rustc_errors::{Diag, DiagCtxtHandle};
use rustc_hir::Attribute;
use rustc_middle::ty::TyCtxt;
use rustc_span::def_id::DefId;
use rustc_span::{ErrorGuaranteed, Span};
use std::ops::Range;

#[derive(PartialEq, Eq, Debug)]
pub enum ParsingIssue {
    /// The `FnDef` in question doesn't have a `#[doc(..)]` attribute.
    NoDocString,
    /// No marker patterns were found.
    NoMarkerPattern,
    /// Multiple marker patters were found.
    MultipleMarkerPatterns(Vec<Range<usize>>),
    /// No colon delimiter was found after the condition name.
    ///
    /// This probably should just default in an empty description but, for now, is an error.
    NoColon(Range<usize>, usize),
    /// A marker was found, but it had no requirements.
    EmptyMarker,
    /// The name of a condition was invalid.
    InvalidConditionName {
        reason: InvalidConditionNameReason,
        chars: Range<usize>,
        name: String,
    },
    /// The bullet types found were non-matching.
    NonMatchingBullets(Vec<(Range<usize>, String)>),
}

pub struct ParsingError<'a> {
    issue: ParsingIssue,
    loc_name: String,
    span: Span,
    doc_comments: &'a [Attribute],
}

impl ParsingError<'_> {
    pub fn issue(&self) -> &ParsingIssue {
        &self.issue
    }

    pub fn update_span(&mut self, span: Span) {
        self.span = span;
    }
}

impl ParsingIssue {
    pub fn at_fn_def(self, def_id: rustc_span::def_id::DefId, tcx: TyCtxt<'_>) -> ParsingError<'_> {
        ParsingError {
            issue: self,
            loc_name: format!("function definition {}", tcx.def_path_debug_str(def_id)),
            span: tcx.hir_span(tcx.local_def_id_to_hir_id(def_id.expect_local())),
            doc_comments: def_id.get_attrs(tcx),
        }
    }

    pub fn at_callsite<'a>(
        self,
        calling_expr: &rustc_hir::Expr<'_>,
        callee_def_id: DefId,
        tcx: TyCtxt<'a>,
    ) -> ParsingError<'a> {
        ParsingError {
            issue: self,
            loc_name: format!("function call of {}", tcx.def_path_debug_str(callee_def_id)),
            span: calling_expr.span,
            doc_comments: calling_expr.get_attrs(tcx),
        }
    }
}

impl ParsingError<'_> {
    pub(crate) fn emit<'s, 'a: 's>(&'s self, dcx: DiagCtxtHandle<'a>) -> ErrorGuaranteed {
        self.diag(dcx).emit()
    }

    pub(crate) fn diag<'s, 'a: 's>(&'s self, dcx: DiagCtxtHandle<'a>) -> Diag<'a> {
        let base_diag = match &self.issue {
            ParsingIssue::InvalidConditionName { reason, .. } => {
                self.build_invalid_condition_diag(dcx, reason)
            }
            ParsingIssue::EmptyMarker => self.build_empty_marker_diag(dcx),
            ParsingIssue::NoDocString => self.build_no_doc_string_diag(dcx),
            ParsingIssue::MultipleMarkerPatterns(marker_ranges) => {
                self.build_multiple_markers_diag(dcx, marker_ranges)
            }
            ParsingIssue::NoColon(bullet_range, first_word_len) => {
                self.build_no_colon_diag(dcx, bullet_range, *first_word_len)
            }
            ParsingIssue::NoMarkerPattern => self.build_no_marker_diag(dcx),
            ParsingIssue::NonMatchingBullets(bullet_ranges) => {
                self.build_non_matching_bullets_diag(dcx, bullet_ranges)
            }
        };

        base_diag.with_span_label(self.span, "here")
    }

    fn build_invalid_condition_diag<'a>(
        &self,
        dcx: DiagCtxtHandle<'a>,
        reason: &InvalidConditionNameReason,
    ) -> Diag<'a> {
        match reason {
            InvalidConditionNameReason::TrailingWhitespace => {
                self.build_trailing_whitespace_diag(dcx)
            }
            InvalidConditionNameReason::MultipleWords => self.build_multiple_words_diag(dcx),
        }
    }

    fn build_trailing_whitespace_diag<'a>(&self, dcx: DiagCtxtHandle<'a>) -> Diag<'a> {
        if let ParsingIssue::InvalidConditionName { chars, name, .. } = &self.issue {
            let invalid_index = name
                .find(super::types::INVALID_WHITESPACE)
                .expect("we found there to be invalid whitespace here...");

            let span =
                span_some_comments(self.doc_comments, (chars.start + invalid_index)..chars.end);
            let first = *span.first().expect("should have a first span");

            dcx.struct_err(format!(
                "trailing white space found on condition name {name:?} for {}",
                self.loc_name
            ))
            .with_span(span)
            .with_span_suggestion_verbose(
                first,
                "try removing it",
                "",
                rustc_errors::Applicability::MaybeIncorrect,
            )
        } else {
            unreachable!("build_trailing_whitespace_diag called with wrong issue type")
        }
    }

    fn build_multiple_words_diag<'a>(&self, dcx: DiagCtxtHandle<'a>) -> Diag<'a> {
        if let ParsingIssue::InvalidConditionName { chars, name, .. } = &self.issue {
            let span = span_some_comments(self.doc_comments, chars);
            let first = *span.first().unwrap();

            dcx.struct_err(format!(
                "multi-word condition name found for {}",
                self.loc_name
            ))
            .with_span(span)
            .with_span_suggestion_verbose(
                first,
                "try using a kebab case name instead",
                name.replace(super::types::INVALID_WHITESPACE, "-"),
                rustc_errors::Applicability::MaybeIncorrect,
            )
        } else {
            unreachable!("build_multiple_words_diag called with wrong issue type")
        }
    }

    fn build_empty_marker_diag<'a>(&self, dcx: DiagCtxtHandle<'a>) -> Diag<'a> {
        let span = span_all_comments(self.doc_comments);
        let first = *span.first().unwrap();

        dcx.struct_err(format!(
            "safety section for {} exists but is empty",
            self.loc_name
        ))
        .with_span(span)
        .with_span_suggestion_verbose(
            first.shrink_to_hi(),
            "try adding preconditions",
            "\n/// - cond1: /* condition that must hold for UB-freedom */",
            rustc_errors::Applicability::HasPlaceholders,
        )
    }

    fn build_no_doc_string_diag<'a>(&self, dcx: DiagCtxtHandle<'a>) -> Diag<'a> {
        dcx.struct_err(format!("no doc comments found for {}", self.loc_name))
            .with_span(self.span)
    }

    fn build_multiple_markers_diag<'a>(
        &self,
        dcx: DiagCtxtHandle<'a>,
        marker_char_ranges: &[Range<usize>],
    ) -> Diag<'a> {
        let spans = marker_char_ranges
            .iter()
            .flat_map(|range| span_some_comments(self.doc_comments, range))
            .collect::<Vec<_>>();

        dcx.struct_err(format!(
            "multiple marker patterns found in doc comments on {}",
            self.loc_name
        ))
        .with_span(spans)
    }

    fn build_no_colon_diag<'a>(
        &self,
        dcx: DiagCtxtHandle<'a>,
        bullet_range: &Range<usize>,
        first_word_len: usize,
    ) -> Diag<'a> {
        let bullet_span = span_some_comments(self.doc_comments, bullet_range);
        let name_span = span_some_comments(
            self.doc_comments,
            (bullet_range.start + first_word_len)..(bullet_range.start + first_word_len + 1),
        );

        dcx.struct_err(
            "bullet has no colon delimiter to separate out the condition name and description",
        )
        .with_span(bullet_span)
        .with_span_suggestion_verbose(
            name_span[0],
            "try adding a colon after the condition name",
            ": ",
            rustc_errors::Applicability::MaybeIncorrect,
        )
    }

    fn build_no_marker_diag<'a>(&self, dcx: DiagCtxtHandle<'a>) -> Diag<'a> {
        dcx.struct_err(format!(
            "no unsafe markers found in doc comments for {}",
            self.loc_name
        ))
        .with_span(span_all_comments(self.doc_comments))
    }

    fn build_non_matching_bullets_diag<'a>(
        &self,
        dcx: DiagCtxtHandle<'a>,
        bullet_ranges: &[(Range<usize>, String)],
    ) -> Diag<'a> {
        let mut diag = dcx.struct_err(format!(
            "non-matching bullet types found in doc comments on {}",
            self.loc_name
        ));
        let mut err_spans = Vec::new();

        let suggested = bullet_ranges.first().unwrap().1.clone();
        for (i, (range, _string)) in bullet_ranges.iter().enumerate() {
            let this_span = span_some_comments(self.doc_comments, range);

            if i != 0 {
                diag = diag.with_span_suggestion_verbose(
                    *this_span.first().unwrap(),
                    "try replacing them for consistency",
                    &suggested[(suggested.len() - 1)..],
                    rustc_errors::Applicability::MachineApplicable,
                );
            }

            err_spans.extend(this_span);
        }
        err_spans.reverse();
        diag.with_span(err_spans)
    }
}

// Utilities for converting character ranges of a doc string into spans that can be
// used to reference specific source code when displaying error messages.
mod span {
    use rustc_hir::Attribute;
    use rustc_span::BytePos;
    use rustc_span::Span;
    use std::borrow::Borrow;
    use std::ops::Range;

    /// The length of each doc comment line before you reach the start of the actual doc comment.
    /// Currently 3 because of the three backslashes before each line, telling us to factor those in
    /// when converting from a doc string to a span which will have those extra characters each line.
    const DOC_COMMENT_PREFIX_LEN: u32 = 3;

    /// Returns the set of spans relevant for a certain range of characters distributed throughout a
    /// set of doc comments.
    ///
    /// For example, if the `chars` array goes from halfway through the first comment to halfway
    /// through the second, this will return the second half of the first doc comment's span and
    /// the first half of the second doc comment's span.
    pub fn span_some_comments(
        doc_comments: &[Attribute],
        chars: impl Borrow<Range<usize>>,
    ) -> Vec<Span> {
        let chars: &Range<usize> = chars.borrow();

        let doc_comments = doc_comments
            .iter()
            .filter_map(|attr| {
                if let rustc_hir::Attribute::Parsed(kind) = attr
                    && let rustc_hir::attrs::AttributeKind::DocComment { span, comment, .. } = kind
                {
                    Some((*span, comment.as_str()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let mut final_spans = vec![];
        let mut line_start_char_no = 0;
        for (mut span, comment) in doc_comments {
            let wanted_char_start = u32::try_from((chars.start).saturating_sub(line_start_char_no)).expect("it would be crazy if the doc string length was greater than the max val for a u32 i would be very impressed");
            let wanted_char_end = u32::try_from(usize::min(
                (chars.end).saturating_sub(line_start_char_no),
                comment.len(),
            ))
            .expect("same here...");

            let wanted_span_start: BytePos = if wanted_char_start == 0 {
                span.lo()
            } else {
                span.lo() + BytePos(wanted_char_start + DOC_COMMENT_PREFIX_LEN)
            };
            let wanted_span_end = if wanted_char_end == 0 {
                span.lo()
            } else {
                span.lo() + BytePos(wanted_char_end + DOC_COMMENT_PREFIX_LEN)
            };

            line_start_char_no += comment.len() + 1;

            if wanted_span_start > span.lo() {
                span = span.with_lo(wanted_span_start);
            }
            if wanted_span_end < span.hi() {
                span = span.with_hi(wanted_span_end);
            }

            // trim all the spans we don't want to include
            if span.hi() != span.lo() {
                final_spans.push(span);
            }
        }

        final_spans.merge_adjacent()
    }

    /// Returns the span for all `doc_comments`.
    pub fn span_all_comments(doc_comments: &[Attribute]) -> Vec<Span> {
        doc_comments
            .iter()
            .enumerate()
            .filter_map(|attr| {
                if let rustc_hir::Attribute::Parsed(kind) = attr.1
                    && let rustc_hir::attrs::AttributeKind::DocComment { span, .. } = kind
                {
                    Some(span)
                } else {
                    None
                }
            })
            .merge_adjacent()
    }

    trait Mergeable {
        fn merge_adjacent(self) -> Vec<Span>;
    }

    impl<'a, T> Mergeable for T
    where
        T: IntoIterator<Item = &'a Span>,
    {
        /// Merges spans that are adjacent in the iterator and correspond to adjacent regions of code.
        fn merge_adjacent(self) -> Vec<Span> {
            self.into_iter()
                .fold(Vec::new(), |mut base: Vec<Span>, span: &Span| {
                    if let Some(last) = base.last_mut()
                        && last.hi() + BytePos(1) == span.lo()
                    {
                        // Merge the line spans if theyre adjacent
                        *last = last.to(*span);
                    } else {
                        base.push(*span);
                    }

                    base
                })
        }
    }
}
