use rustc_span::Span;

use crate::annotations::Justification;

#[derive(Debug)]
pub enum ConsistencyIssue {
    UnsatisfiedJustification(Justification),
}

#[derive(Debug)]
pub struct ConsistencyError {
    call_at: Span,
    issue: ConsistencyIssue,
}
