//! Source-local analysis markers.

use reachability::{ReachabilityEdge, ReachabilityGraph, ReachabilityNodeKind};
use rustc_hir::def_id::LocalDefId;
use rustc_middle::thir::visit::{self, Visitor};
use rustc_middle::thir::{Block, Thir};
use rustc_middle::ty::TyCtxt;
use rustc_span::{SourceFile, Span};

use crate::config::MarkerProbing;
use crate::contracts::MarkerSatisfaction;

#[derive(Debug, Clone, Copy)]
enum MarkerSyntax {
    Panic,
    Safety,
}

impl MarkerSyntax {
    fn prefix(self) -> &'static str {
        match self {
            Self::Panic => "PANIC:",
            Self::Safety => "SAFETY:",
        }
    }

    fn other_prefix(self) -> &'static str {
        match self {
            Self::Panic => Self::Safety.prefix(),
            Self::Safety => Self::Panic.prefix(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct MarkerBlockKey {
    pub file_start: u32,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectMarkerBlock {
    pub key: MarkerBlockKey,
    pub span: Span,
    pub satisfactions: Vec<MarkerSatisfaction>,
}

#[must_use]
pub(crate) fn panic_span_marker_block(
    tcx: TyCtxt<'_>,
    span: Span,
    probing: MarkerProbing,
) -> Option<EffectMarkerBlock> {
    span_marker_block_with(tcx, span, MarkerSyntax::Panic, probing)
}

#[must_use]
pub(crate) fn safety_span_marker_block(
    tcx: TyCtxt<'_>,
    span: Span,
    probing: MarkerProbing,
) -> Option<EffectMarkerBlock> {
    span_marker_block_with(tcx, span, MarkerSyntax::Safety, probing)
}

fn span_marker_block_with(
    tcx: TyCtxt<'_>,
    span: Span,
    syntax: MarkerSyntax,
    probing: MarkerProbing,
) -> Option<EffectMarkerBlock> {
    marker_probe_spans(span, probing)
        .into_iter()
        .find_map(|span| span_marker_block_at(tcx, span, syntax))
}

/// Marker block that justifies one effect-bearing reachability edge.
///
/// A marker directly above a callee segment wins, so a marker between links of
/// a multi-line method chain applies only to that link. An unnamed marker above
/// the whole multi-line statement cannot select one link, although named
/// requirement bullets still apply. Enclosing block markers are the fallback.
#[must_use]
pub(crate) fn panic_effect_edge_marker_block(
    tcx: TyCtxt<'_>,
    graph: &ReachabilityGraph<'_>,
    edge: &ReachabilityEdge,
    probing: MarkerProbing,
) -> Option<EffectMarkerBlock> {
    effect_edge_marker_block_with(tcx, graph, edge, MarkerSyntax::Panic, probing)
}

/// Marker block that justifies one safety-bearing reachability edge.
#[must_use]
pub(crate) fn safety_effect_edge_marker_block(
    tcx: TyCtxt<'_>,
    graph: &ReachabilityGraph<'_>,
    edge: &ReachabilityEdge,
    probing: MarkerProbing,
) -> Option<EffectMarkerBlock> {
    effect_edge_marker_block_with(tcx, graph, edge, MarkerSyntax::Safety, probing)
}

fn effect_edge_marker_block_with(
    tcx: TyCtxt<'_>,
    graph: &ReachabilityGraph<'_>,
    edge: &ReachabilityEdge,
    syntax: MarkerSyntax,
    probing: MarkerProbing,
) -> Option<EffectMarkerBlock> {
    let statement = span_marker_block_with(tcx, edge.span, syntax, probing);
    if let Some(callee_span) = edge.callee_span
        && !spans_start_on_same_line(tcx, edge.span, callee_span)
    {
        if let Some(callee) = span_marker_block_with(tcx, callee_span, syntax, probing) {
            return Some(callee);
        }
        if let Some(statement) = statement {
            let satisfactions = statement
                .satisfactions
                .into_iter()
                .filter(|satisfaction| satisfaction.requirement.is_some())
                .collect::<Vec<_>>();
            return (!satisfactions.is_empty()).then_some(EffectMarkerBlock {
                key: statement.key,
                span: statement.span,
                satisfactions,
            });
        }

        return enclosing_block_marker_block(tcx, graph, edge, syntax, probing);
    }

    statement.or_else(|| enclosing_block_marker_block(tcx, graph, edge, syntax, probing))
}

fn enclosing_block_marker_block(
    tcx: TyCtxt<'_>,
    graph: &ReachabilityGraph<'_>,
    edge: &ReachabilityEdge,
    syntax: MarkerSyntax,
    probing: MarkerProbing,
) -> Option<EffectMarkerBlock> {
    let owner = match &graph.node(edge.origin).kind {
        ReachabilityNodeKind::Instance(instance) => instance.def_id().as_local()?,
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::MacroExpansion { .. }
        | ReachabilityNodeKind::IndirectCall { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => return None,
    };

    enclosing_block_spans(tcx, owner, edge.span)
        .into_iter()
        .find_map(|span| span_marker_block_with(tcx, span, syntax, probing))
}

fn enclosing_block_spans(tcx: TyCtxt<'_>, owner: LocalDefId, target: Span) -> Vec<Span> {
    let Ok((thir, root)) = tcx.thir_body(owner) else {
        return Vec::new();
    };
    let thir = thir.borrow();
    let mut visitor = EnclosingBlockVisitor {
        thir: &thir,
        target,
        block_depth: 0,
        spans: Vec::new(),
    };
    visitor.visit_expr(&thir[root]);
    visitor.spans.sort_by_key(|span| {
        let span = span.source_callsite();
        (span.hi().0.saturating_sub(span.lo().0), span.lo().0)
    });
    visitor.spans.dedup_by_key(|span| {
        let span = span.source_callsite();
        (span.lo(), span.hi())
    });
    visitor.spans
}

struct EnclosingBlockVisitor<'a, 'tcx> {
    thir: &'a Thir<'tcx>,
    target: Span,
    block_depth: usize,
    spans: Vec<Span>,
}

impl<'a, 'tcx> Visitor<'a, 'tcx> for EnclosingBlockVisitor<'a, 'tcx> {
    fn thir(&self) -> &'a Thir<'tcx> {
        self.thir
    }

    fn visit_block(&mut self, block: &'a Block) {
        if self.block_depth > 0 && span_contains(block.span, self.target) {
            self.spans.push(block.span);
        }
        self.block_depth += 1;
        visit::walk_block(self, block);
        self.block_depth -= 1;
    }
}

fn span_contains(outer: Span, inner: Span) -> bool {
    let outer = outer.source_callsite();
    let inner = inner.source_callsite();
    !outer.is_dummy() && !inner.is_dummy() && outer.lo() <= inner.lo() && inner.hi() <= outer.hi()
}

fn spans_start_on_same_line(tcx: TyCtxt<'_>, left: Span, right: Span) -> bool {
    let left = left.source_callsite();
    let right = right.source_callsite();
    if left.is_dummy() || right.is_dummy() {
        return true;
    }
    let source_map = tcx.sess.source_map();
    source_map.lookup_char_pos(left.lo()).line == source_map.lookup_char_pos(right.lo()).line
}

// One rustc session per process and single-threaded analysis; source files
// keep disjoint start offsets within a session's source map, so the file
// start plus line index identifies a marker lookup. Every edge of every
// per-root traversal re-scans its lines without this.
thread_local! {
    static PANIC_MARKER_BLOCK_CACHE: std::cell::RefCell<
        std::collections::HashMap<(u32, usize), Option<EffectMarkerBlock>>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
    static SAFETY_MARKER_BLOCK_CACHE: std::cell::RefCell<
        std::collections::HashMap<(u32, usize), Option<EffectMarkerBlock>>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

fn marker_probe_spans(span: Span, probing: MarkerProbing) -> Vec<Span> {
    let mut spans = Vec::new();
    match probing {
        MarkerProbing::SourceCallsite => {
            push_unique_probe_span(&mut spans, span.source_callsite());
        }
        MarkerProbing::MacroDefinitionFirst => {
            // For macro-expanded code, prefer markers in the macro body that
            // produced the operation, then walk callsites outward before the
            // usual fallback.
            push_unique_probe_span(&mut spans, span);
            for expansion in span.macro_backtrace() {
                push_unique_probe_span(&mut spans, expansion.call_site);
            }
            push_unique_probe_span(&mut spans, span.source_callsite());
        }
    }
    spans
}

fn push_unique_probe_span(spans: &mut Vec<Span>, span: Span) {
    // A dummy span would resolve to byte 0 — line 1 of an arbitrary file —
    // where a stray marker could suppress every dummy-span edge crate-wide.
    if span.is_dummy() || spans.iter().any(|existing| existing.source_equal(span)) {
        return;
    }
    spans.push(span);
}

fn span_marker_block_at(
    tcx: TyCtxt<'_>,
    span: Span,
    syntax: MarkerSyntax,
) -> Option<EffectMarkerBlock> {
    let location = tcx.sess.source_map().lookup_char_pos(span.lo());
    let line_index = location.line.saturating_sub(1);
    let key = (location.file.start_pos.0, line_index);
    match syntax {
        MarkerSyntax::Panic => PANIC_MARKER_BLOCK_CACHE.with_borrow_mut(|cache| {
            cache
                .entry(key)
                .or_insert_with(|| marker_block_at(&location.file, line_index, syntax))
                .clone()
        }),
        MarkerSyntax::Safety => SAFETY_MARKER_BLOCK_CACHE.with_borrow_mut(|cache| {
            cache
                .entry(key)
                .or_insert_with(|| marker_block_at(&location.file, line_index, syntax))
                .clone()
        }),
    }
}

#[must_use]
fn line_satisfaction(line: &str, syntax: MarkerSyntax) -> Option<MarkerSatisfaction> {
    comment_body(line)
        .and_then(|body| body.strip_prefix(syntax.prefix()))
        .map(parse_marker)
        .filter(MarkerSatisfaction::has_justification)
}

#[must_use]
fn normalize_requirement_name(name: &str) -> String {
    crate::contracts::normalize_requirement_name(name)
}

fn parse_marker_body(body: &str) -> (Option<String>, &str) {
    let Some((name, reason)) = body.split_once(':') else {
        return (None, body);
    };
    let name = name.trim();
    if looks_like_requirement_name(name) {
        (Some(name.to_owned()), reason.trim())
    } else {
        (None, body)
    }
}

fn parse_marker(body: &str) -> MarkerSatisfaction {
    let body = body.trim();
    let (requirement, reason) = parse_marker_body(body);
    MarkerSatisfaction {
        requirement,
        reason: reason.to_owned(),
    }
}

fn looks_like_requirement_name(name: &str) -> bool {
    !normalize_requirement_name(name).is_empty()
}

fn marker_block_at(
    file: &SourceFile,
    line_index: usize,
    syntax: MarkerSyntax,
) -> Option<EffectMarkerBlock> {
    let mut block = preceding_marker_block(file, line_index, syntax);
    let line_satisfactions = source_line_satisfactions(file, line_index, syntax);
    if line_satisfactions.is_empty() {
        return block;
    }

    if let Some(block) = &mut block {
        block.satisfactions.extend(line_satisfactions);
        return Some(block.clone());
    }

    Some(EffectMarkerBlock {
        key: MarkerBlockKey {
            file_start: file.start_pos.0,
            start_line: line_index,
            end_line: line_index,
        },
        span: comment_block_span(file, line_index, line_index),
        satisfactions: line_satisfactions,
    })
}

fn preceding_marker_block(
    file: &SourceFile,
    line_index: usize,
    syntax: MarkerSyntax,
) -> Option<EffectMarkerBlock> {
    let block = preceding_comment_block(file, line_index)?;
    let satisfactions = comment_block_satisfactions(&block.lines, syntax);
    if satisfactions.is_empty() {
        return None;
    }

    Some(EffectMarkerBlock {
        key: MarkerBlockKey {
            file_start: file.start_pos.0,
            start_line: block.start_line,
            end_line: block.end_line,
        },
        span: comment_block_span(file, block.start_line, block.end_line),
        satisfactions,
    })
}

struct CommentBlock {
    start_line: usize,
    end_line: usize,
    lines: Vec<String>,
}

fn preceding_comment_block(file: &SourceFile, line_index: usize) -> Option<CommentBlock> {
    let mut block = Vec::new();
    let mut current = line_index;
    while let Some(previous) = current.checked_sub(1) {
        let Some(line) = file.get_line(previous) else {
            break;
        };
        let line = line.as_ref();
        if !line_is_standalone_comment(line) {
            break;
        }
        block.push(line.to_owned());
        current = previous;
    }

    if block.is_empty() {
        return None;
    }

    block.reverse();
    Some(CommentBlock {
        start_line: current,
        end_line: line_index - 1,
        lines: block,
    })
}

fn comment_block_span(file: &SourceFile, start_line: usize, end_line: usize) -> Span {
    let lo = file.line_bounds(start_line).start;
    let hi = file.line_bounds(end_line).end;
    Span::with_root_ctxt(lo, hi)
}

fn source_line_satisfactions(
    file: &SourceFile,
    line_index: usize,
    syntax: MarkerSyntax,
) -> Vec<MarkerSatisfaction> {
    file.get_line(line_index)
        .and_then(|line| line_satisfaction(line.as_ref(), syntax))
        .into_iter()
        .collect()
}

fn line_is_standalone_comment(line: &str) -> bool {
    comment_body(line).is_some()
}

fn comment_body(line: &str) -> Option<&str> {
    let comment = line.trim_start().strip_prefix("//")?;
    (!comment.starts_with('/') && !comment.starts_with('!')).then(|| comment.trim_start())
}

fn comment_block_satisfactions(lines: &[String], syntax: MarkerSyntax) -> Vec<MarkerSatisfaction> {
    let mut satisfactions: Vec<MarkerSatisfaction> = Vec::new();
    let mut pending_header_reason: Option<String> = None;
    let mut in_marker_block = false;

    for line in lines {
        let Some(body) = comment_body(line) else {
            continue;
        };
        if let Some(marker_body) = body.strip_prefix(syntax.prefix()) {
            flush_pending_header(&mut satisfactions, &mut pending_header_reason);
            in_marker_block = true;
            let parsed = parse_marker(marker_body);
            if parsed.requirement.is_none() && parsed.reason.is_empty() {
                pending_header_reason = Some(String::new());
            } else {
                satisfactions.push(parsed);
            }
        } else if body.starts_with(syntax.other_prefix()) {
            flush_pending_header(&mut satisfactions, &mut pending_header_reason);
            in_marker_block = false;
        } else if in_marker_block {
            if let Some(satisfaction) = parse_satisfaction_bullet(body) {
                pending_header_reason = None;
                satisfactions.push(satisfaction);
            } else if let Some(reason) = pending_header_reason.as_mut() {
                append_reason_line(reason, body.trim());
            } else if let Some(satisfaction) = satisfactions.last_mut() {
                let continuation = body.trim();
                append_reason_line(&mut satisfaction.reason, continuation);
            }
        }
    }
    flush_pending_header(&mut satisfactions, &mut pending_header_reason);
    satisfactions.retain(MarkerSatisfaction::has_justification);

    satisfactions
}

fn flush_pending_header(
    satisfactions: &mut Vec<MarkerSatisfaction>,
    pending_header_reason: &mut Option<String>,
) {
    if let Some(reason) = pending_header_reason.take() {
        satisfactions.push(MarkerSatisfaction {
            requirement: None,
            reason,
        });
    }
}

fn append_reason_line(reason: &mut String, line: &str) {
    if line.is_empty() {
        return;
    }
    if !reason.is_empty() {
        reason.push('\n');
    }
    reason.push_str(line);
}

fn parse_satisfaction_bullet(line: &str) -> Option<MarkerSatisfaction> {
    let line = line.trim_start();
    let body = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .or_else(|| line.strip_prefix("+ "))?;
    let (name, reason) = parse_marker_body(body);
    name.map(|requirement| MarkerSatisfaction {
        requirement: Some(requirement),
        reason: reason.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{MarkerSatisfaction, MarkerSyntax, normalize_requirement_name};

    fn line_has_panic_marker(line: &str) -> bool {
        super::line_satisfaction(line, MarkerSyntax::Panic).is_some()
    }

    fn line_has_safety_marker(line: &str) -> bool {
        super::line_satisfaction(line, MarkerSyntax::Safety).is_some()
    }

    #[test]
    fn panic_marker_matches_plain_comments() {
        assert!(line_has_panic_marker(
            "// PANIC: caller checked denominator"
        ));
        assert!(line_has_panic_marker("    // PANIC: inspected"));
    }

    #[test]
    fn panic_marker_parses_named_satisfactions() {
        assert_eq!(
            super::line_satisfaction(
                "// PANIC: index in bounds: checked by caller",
                MarkerSyntax::Panic,
            ),
            Some(MarkerSatisfaction {
                requirement: Some(String::from("index in bounds")),
                reason: String::from("checked by caller"),
            })
        );
    }

    #[test]
    fn panic_marker_keeps_following_comment_lines_as_reason_context() {
        let lines = [
            String::from("    // PANIC: nonzero: caller checked denominator."),
            String::from("    // The constructor rejects zero."),
            String::from("    // PANIC: index in bounds: caller checked the index."),
        ];

        assert_eq!(
            comment_block_satisfactions_for_panic(&lines),
            [
                MarkerSatisfaction {
                    requirement: Some(String::from("nonzero")),
                    reason: String::from(
                        "caller checked denominator.\nThe constructor rejects zero."
                    ),
                },
                MarkerSatisfaction {
                    requirement: Some(String::from("index in bounds")),
                    reason: String::from("caller checked the index."),
                },
            ]
        );
    }

    #[test]
    fn panic_marker_parses_requirement_bullets_after_header() {
        let lines = [
            String::from("    // PANIC:"),
            String::from("    //"),
            String::from("    // The call site validates the callee contract."),
            String::from("    // Requirements:"),
            String::from("    // - something[var_1]: checked the first precondition."),
            String::from("    //   Additional evidence for the first precondition."),
            String::from("    // - something2[var_1]: checked the second precondition."),
            String::from("    // - something3:"),
            String::from("    //   checked the third precondition."),
        ];

        assert_eq!(
            comment_block_satisfactions_for_panic(&lines),
            [
                MarkerSatisfaction {
                    requirement: Some(String::from("something[var_1]")),
                    reason: String::from(
                        "checked the first precondition.\nAdditional evidence for the first precondition."
                    ),
                },
                MarkerSatisfaction {
                    requirement: Some(String::from("something2[var_1]")),
                    reason: String::from("checked the second precondition."),
                },
                MarkerSatisfaction {
                    requirement: Some(String::from("something3")),
                    reason: String::from("checked the third precondition."),
                },
            ]
        );
    }

    #[test]
    fn empty_panic_marker_without_bullets_remains_an_unnamed_marker() {
        let lines = [
            String::from("    // PANIC:"),
            String::from("    // caller checked the local invariant."),
        ];

        assert_eq!(
            comment_block_satisfactions_for_panic(&lines),
            [MarkerSatisfaction {
                requirement: None,
                reason: String::from("caller checked the local invariant."),
            }]
        );
    }

    #[test]
    fn empty_panic_marker_alone_does_not_suppress() {
        let lines = [String::from("    // PANIC:")];

        assert_eq!(comment_block_satisfactions_for_panic(&lines), []);
    }

    #[test]
    fn requirement_bullets_without_panic_marker_are_ignored() {
        let lines = [
            String::from("    // Requirements:"),
            String::from("    // - nonzero: checked above."),
        ];

        assert_eq!(comment_block_satisfactions_for_panic(&lines), []);
    }

    #[test]
    fn empty_requirement_bullets_do_not_satisfy_requirements() {
        let lines = [
            String::from("    // PANIC:"),
            String::from("    // - nonzero:"),
        ];

        assert_eq!(comment_block_satisfactions_for_panic(&lines), []);
    }

    #[test]
    fn panic_marker_rejects_non_plain_comment_text() {
        for line in [
            "let label = \"PANIC:\";",
            "let _ = f(); // PANIC: inspected",
            "/// PANIC: doc comments are not call-site markers",
            "// SAFETY: not the sniff-test marker",
            "// panic: no",
            "// PANIC:",
            "// PANIC: nonzero:",
        ] {
            assert!(!line_has_panic_marker(line));
        }
    }

    #[test]
    fn safety_marker_uses_same_comment_syntax() {
        assert!(line_has_safety_marker(
            "// SAFETY: pointer came from NonNull"
        ));
        assert_eq!(
            super::line_satisfaction(
                "// SAFETY: initialized: written above",
                MarkerSyntax::Safety,
            ),
            Some(MarkerSatisfaction {
                requirement: Some(String::from("initialized")),
                reason: String::from("written above"),
            })
        );
        assert!(!line_has_safety_marker("// PANIC: not safety"));
        assert!(!line_has_safety_marker("// SAFETY:"));
        assert!(!line_has_safety_marker(
            "/// SAFETY: doc comments are not call-site markers"
        ));
    }

    #[test]
    fn different_marker_header_stops_current_marker_block() {
        let lines = [
            String::from("    // PANIC:"),
            String::from("    // SAFETY: pointer came from NonNull."),
            String::from("    // This should not become panic evidence."),
        ];

        assert_eq!(comment_block_satisfactions_for_panic(&lines), []);
        assert_eq!(
            super::comment_block_satisfactions(&lines, MarkerSyntax::Safety),
            [super::MarkerSatisfaction {
                requirement: None,
                reason: String::from(
                    "pointer came from NonNull.\nThis should not become panic evidence."
                ),
            }]
        );
    }

    #[test]
    fn requirement_names_are_normalized_for_matching() {
        assert_eq!(
            normalize_requirement_name(" Index_In-Bounds  "),
            "index in bounds"
        );
        assert_eq!(
            normalize_requirement_name("something[var_1]"),
            "something var 1"
        );
    }

    #[test]
    fn leading_comment_block_can_contain_panic_marker_above_explanation() {
        let lines = [
            "pub fn ratio(total: usize, denominator: usize) -> usize {",
            "    // PANIC: caller guarantees denominator is nonzero.",
            "    // This is enforced by the public constructor.",
            "    total / denominator",
            "}",
        ];

        assert!(lines_have_panic_marker_before(&lines, 3));
    }

    #[test]
    fn leading_comment_block_stops_at_non_comment_lines() {
        let lines = [
            "pub fn ratio(total: usize, denominator: usize) -> usize {",
            "    // PANIC: this belongs to the checked branch.",
            "    let checked = denominator.max(1);",
            "    total / denominator",
            "}",
        ];

        assert!(!lines_have_panic_marker_before(&lines, 3));
    }

    fn lines_have_panic_marker_before(lines: &[&str], line_index: usize) -> bool {
        let mut current = line_index;
        while let Some(previous) = current.checked_sub(1) {
            let Some(line) = lines.get(previous) else {
                break;
            };
            if line_has_panic_marker(line) {
                return true;
            }
            if !super::line_is_standalone_comment(line) {
                break;
            }
            current = previous;
        }

        false
    }

    fn comment_block_satisfactions_for_panic(lines: &[String]) -> Vec<MarkerSatisfaction> {
        super::comment_block_satisfactions(lines, MarkerSyntax::Panic)
    }
}
