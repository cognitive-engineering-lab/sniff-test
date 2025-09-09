use std::{borrow::Borrow, ops::Range};

use rustc_errors::{Diag, DiagCtxtHandle};
use rustc_hir::Attribute;
use rustc_span::{BytePos, Span};

use crate::annotations::types::InvalidConditionNameReason;

fn span_some_comments(doc_comments: &[Attribute], chars: impl Borrow<Range<usize>>) -> Vec<Span> {
    let chars: &Range<usize> = chars.borrow();

    let doc_comments = doc_comments
        .iter()
        .filter_map(|attr| {
            if let rustc_hir::Attribute::Parsed(kind) = attr
                && let rustc_hir::attrs::AttributeKind::DocComment {
                    style: _,
                    kind: _,
                    span,
                    comment,
                } = kind
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
            span.lo() + BytePos(wanted_char_start + 3)
        };
        let wanted_span_end = if wanted_char_end == 0 {
            span.lo()
        } else {
            span.lo() + BytePos(wanted_char_end + 3)
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

    final_spans
        .into_iter()
        .fold(Vec::new(), |mut base: Vec<Span>, span: Span| {
            if let Some(last) = base.last_mut()
                && last.hi() + BytePos(1) == span.lo()
            {
                // Merge the line spans if theyre adjacent
                *last = last.to(span);
            } else {
                base.push(span);
            }

            base
        })
}

fn span_all_comments(doc_comments: &[Attribute]) -> Vec<Span> {
    doc_comments
        .iter()
        .enumerate()
        .filter_map(|attr| {
            if let rustc_hir::Attribute::Parsed(kind) = attr.1
                && let rustc_hir::attrs::AttributeKind::DocComment {
                    style: _,
                    kind: _,
                    span,
                    comment: _,
                } = kind
            {
                Some(span)
            } else {
                None
            }
        })
        .fold(Vec::new(), |mut base, span: &Span| {
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

#[derive(PartialEq, Eq, Debug)]
pub enum ParsingError {
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

impl ParsingError {
    // TODO: should clean this to shorten up later, there's a lot of shared logic and behavior
    #[allow(clippy::too_many_lines)]
    pub(crate) fn diag<'s, 'a: 's>(
        &'s self,
        dcx: DiagCtxtHandle<'a>,
        def_name: &str,
        doc_comments: &[Attribute],
    ) -> Diag<'a> {
        match self {
            Self::InvalidConditionName {
                reason: InvalidConditionNameReason::TrailingWhitespace,
                chars,
                name,
            } => {
                let invalid_index = name
                    .find(super::types::INVALID_WHITESPACE)
                    .expect("we found there to be invalid whitespace here...");

                let span =
                    span_some_comments(doc_comments, (chars.start + invalid_index)..chars.end);
                let first = *span.first().unwrap();
                dcx.struct_err(format!(
                    "trailing white space found on condition name {name:?} for `{def_name}`"
                ))
                .with_span(span)
                .with_span_suggestion_verbose(
                    first,
                    "try removing it",
                    "",
                    rustc_errors::Applicability::MaybeIncorrect,
                )
            }
            Self::InvalidConditionName {
                reason: InvalidConditionNameReason::MultipleWords,
                chars,
                name,
            } => {
                let span = span_some_comments(doc_comments, chars);
                let first = *span.first().unwrap();
                dcx.struct_err(format!(
                    "multi-word condition name found for function `{def_name}`"
                ))
                .with_span(span)
                .with_span_suggestion_verbose(
                    first,
                    "try using a kebab case name instead",
                    name.replace(super::types::INVALID_WHITESPACE, "-"),
                    rustc_errors::Applicability::MaybeIncorrect,
                )
            }
            Self::EmptyMarker => {
                let span = span_all_comments(doc_comments);
                let first = *span.first().unwrap();
                dcx.struct_err(format!(
                    "safety section for function definition `{def_name}` exists but is empty"
                ))
                .with_span(span)
                .with_span_suggestion_verbose(
                    first.shrink_to_hi(),
                    "try adding preconditions",
                    "\n/// - cond1: /* condition that must hold for UB-freedom */",
                    rustc_errors::Applicability::HasPlaceholders,
                )
            }
            Self::NoDocString => dcx.struct_err(format!(
                "no doc comments found for function definition `{def_name}`"
            )),
            Self::MultipleMarkerPatterns(marker_char_ranges) => {
                let spans = marker_char_ranges
                    .iter()
                    .flat_map(|range| span_some_comments(doc_comments, range))
                    .collect::<Vec<_>>();

                dcx.struct_err(format!(
                    "multiple marker patterns found in doc comments on function `{def_name}`"
                ))
                .with_span(spans)
            }
            Self::NoColon(bullet_range, first_word_len) => {
                let bullet_span = span_some_comments(doc_comments, bullet_range);
                let name_span = span_some_comments(
                    doc_comments,
                    (bullet_range.start + first_word_len)
                        ..(bullet_range.start + first_word_len + 1),
                );
                dcx.struct_err("bullet has no colon delimiter to separate out the condition name and description").with_span(bullet_span).with_span_suggestion_verbose(name_span[0], "try adding a colon after the condition name", ": ", rustc_errors::Applicability::MaybeIncorrect).with_arg("test", "hello")
            }
            Self::NoMarkerPattern => {
                let span = span_all_comments(doc_comments);
                dcx.struct_err(format!(
                    "no unsafe markers found in doc comments for `{def_name}`"
                ))
                .with_span(span)
            }
            Self::NonMatchingBullets(bullet_ranges) => {
                let mut diag = dcx.struct_err(format!(
                    "non-matching bullet types found in doc comments on function `{def_name}`"
                ));
                let mut err_spans = Vec::new();

                let suggested = bullet_ranges.first().unwrap().1.clone();
                for (i, (range, _string)) in bullet_ranges.iter().enumerate() {
                    let this_span = span_some_comments(doc_comments, range);

                    // TODO: clean this yuckiness up
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
                diag = diag.with_span(err_spans);
                diag
            }
        }
    }
}
