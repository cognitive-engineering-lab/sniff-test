//! Utilities for converting characters from a doc comment back into the span that created them.

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
        .filter_map(|attr| Some((attr.span(), attr.doc_str().map(|a| a.as_str().to_owned())?)))
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
#[allow(unused)]
pub fn span_all_comments(doc_comments: &[Attribute]) -> Vec<Span> {
    doc_comments
        .iter()
        .enumerate()
        .filter_map(|attr| {
            if let rustc_hir::Attribute::Parsed(kind) = attr.1
                && let rustc_hir::attrs::AttributeKind::DocComment { span, .. } = kind
            {
                Some(*span)
            } else {
                None
            }
        })
        .merge_adjacent()
}

/// Adaptor trait to call this function as a method.
pub trait Mergeable {
    fn merge_adjacent(self) -> Vec<Span>;
}

impl<T> Mergeable for T
where
    T: IntoIterator<Item = Span>,
{
    /// Merges spans that are adjacent in the iterator and correspond to adjacent regions of code.
    fn merge_adjacent(self) -> Vec<Span> {
        self.into_iter()
            .fold(Vec::new(), |mut base: Vec<Span>, span: Span| {
                if let Some(last) = base.last_mut()
                    && last.hi() + BytePos(1) == span.lo()
                {
                    // Merge the line spans if they're adjacent
                    *last = last.to(span);
                } else {
                    base.push(span);
                }

                base
            })
    }
}
