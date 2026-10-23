//! Complete expansion ancestry for analysis rather than diagnostic display.

use rustc_span::{ExpnData, Span};

/// Walks every expansion ancestor from innermost to outermost.
///
/// Unlike `Span::macro_backtrace`, this preserves recursive frames. The rustc
/// diagnostic iterator suppresses some of those frames based on the starting
/// span, so it cannot provide consistent provenance for shared ancestors.
/// Callers can filter by `macro_def_id` to select definition-backed macros.
pub fn expansion_ancestry(mut span: Span) -> impl Iterator<Item = ExpnData> {
    std::iter::from_fn(move || {
        let context = span.ctxt();
        if context.is_root() {
            return None;
        }
        let expansion = context.outer_expn_data();
        span = expansion.call_site;
        Some(expansion)
    })
}
