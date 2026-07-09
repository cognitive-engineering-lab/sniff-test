//! Source-local analysis markers.

use rustc_middle::ty::TyCtxt;
use rustc_span::{SourceFile, Span};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MarkerKind {
    Panic,
    Safety,
}

impl MarkerKind {
    const ALL: [Self; 2] = [Self::Panic, Self::Safety];

    fn prefix(self) -> &'static str {
        match self {
            Self::Panic => "PANIC:",
            Self::Safety => "SAFETY:",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MarkerSatisfaction {
    pub requirement: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanicSatisfaction {
    pub requirement: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetySatisfaction {
    pub requirement: Option<String>,
    pub reason: String,
}

impl From<MarkerSatisfaction> for PanicSatisfaction {
    fn from(satisfaction: MarkerSatisfaction) -> Self {
        Self {
            requirement: satisfaction.requirement,
            reason: satisfaction.reason,
        }
    }
}

impl From<MarkerSatisfaction> for SafetySatisfaction {
    fn from(satisfaction: MarkerSatisfaction) -> Self {
        Self {
            requirement: satisfaction.requirement,
            reason: satisfaction.reason,
        }
    }
}

#[must_use]
pub fn span_has_panic_marker(tcx: TyCtxt<'_>, span: Span) -> bool {
    !span_panic_satisfactions(tcx, span).is_empty()
}

#[must_use]
pub fn span_panic_satisfactions(tcx: TyCtxt<'_>, span: Span) -> Vec<PanicSatisfaction> {
    span_satisfactions(tcx, span, MarkerKind::Panic)
        .into_iter()
        .map(Into::into)
        .collect()
}

#[must_use]
pub fn span_has_safety_marker(tcx: TyCtxt<'_>, span: Span) -> bool {
    !span_safety_satisfactions(tcx, span).is_empty()
}

#[must_use]
pub fn span_safety_satisfactions(tcx: TyCtxt<'_>, span: Span) -> Vec<SafetySatisfaction> {
    span_satisfactions(tcx, span, MarkerKind::Safety)
        .into_iter()
        .map(Into::into)
        .collect()
}

// One rustc session per process and single-threaded analysis; source files
// keep disjoint start offsets within a session's source map, so the file
// start plus line index identifies a marker lookup. Every edge of every
// per-root traversal re-scans its lines without this.
thread_local! {
    static LINE_CACHE: std::cell::RefCell<
        std::collections::HashMap<(u32, usize, MarkerKind), Vec<MarkerSatisfaction>>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

fn span_satisfactions(tcx: TyCtxt<'_>, span: Span, kind: MarkerKind) -> Vec<MarkerSatisfaction> {
    let span = span.source_callsite();
    // A dummy span would resolve to byte 0 — line 1 of an arbitrary file —
    // where a stray marker could suppress every dummy-span edge crate-wide.
    if span.is_dummy() {
        return Vec::new();
    }
    let location = tcx.sess.source_map().lookup_char_pos(span.lo());
    let line_index = location.line.saturating_sub(1);

    LINE_CACHE.with_borrow_mut(|cache| {
        cache
            .entry((location.file.start_pos.0, line_index, kind))
            .or_insert_with(|| {
                let mut satisfactions = source_line_satisfactions(&location.file, line_index, kind);
                satisfactions.extend(preceding_comment_block_satisfactions(
                    &location.file,
                    line_index,
                    kind,
                ));
                satisfactions
            })
            .clone()
    })
}

#[must_use]
pub fn line_has_panic_marker(line: &str) -> bool {
    line_panic_satisfaction(line).is_some()
}

#[must_use]
pub fn line_panic_satisfaction(line: &str) -> Option<PanicSatisfaction> {
    line_satisfaction(line, MarkerKind::Panic).map(Into::into)
}

#[must_use]
pub fn line_has_safety_marker(line: &str) -> bool {
    line_safety_satisfaction(line).is_some()
}

#[must_use]
pub fn line_safety_satisfaction(line: &str) -> Option<SafetySatisfaction> {
    line_satisfaction(line, MarkerKind::Safety).map(Into::into)
}

fn line_satisfaction(line: &str, kind: MarkerKind) -> Option<MarkerSatisfaction> {
    comment_body(line)
        .and_then(|body| body.strip_prefix(kind.prefix()))
        .map(parse_marker)
        .filter(has_justification)
}

#[must_use]
pub fn normalize_requirement_name(name: &str) -> String {
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

fn preceding_comment_block_satisfactions(
    file: &SourceFile,
    line_index: usize,
    kind: MarkerKind,
) -> Vec<MarkerSatisfaction> {
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

    block.reverse();
    comment_block_satisfactions(&block, kind)
}

fn source_line_satisfactions(
    file: &SourceFile,
    line_index: usize,
    kind: MarkerKind,
) -> Vec<MarkerSatisfaction> {
    file.get_line(line_index)
        .and_then(|line| line_satisfaction(line.as_ref(), kind))
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

fn comment_block_satisfactions(lines: &[String], kind: MarkerKind) -> Vec<MarkerSatisfaction> {
    let mut satisfactions: Vec<MarkerSatisfaction> = Vec::new();
    let mut pending_header_reason: Option<String> = None;
    let mut in_marker_block = false;

    for line in lines {
        let Some(body) = comment_body(line) else {
            continue;
        };
        if let Some(marker_body) = body.strip_prefix(kind.prefix()) {
            flush_pending_header(&mut satisfactions, &mut pending_header_reason);
            in_marker_block = true;
            let parsed = parse_marker(marker_body);
            if parsed.requirement.is_none() && parsed.reason.is_empty() {
                pending_header_reason = Some(String::new());
            } else {
                satisfactions.push(parsed);
            }
        } else if body_starts_with_different_marker(body, kind) {
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
    satisfactions.retain(has_justification);

    satisfactions
}

fn body_starts_with_different_marker(body: &str, kind: MarkerKind) -> bool {
    MarkerKind::ALL
        .iter()
        .any(|known_kind| *known_kind != kind && body.starts_with(known_kind.prefix()))
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

fn has_justification(satisfaction: &MarkerSatisfaction) -> bool {
    !satisfaction.reason.trim().is_empty()
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
    use super::{MarkerKind, SafetySatisfaction};
    use super::{
        PanicSatisfaction, line_has_panic_marker, line_has_safety_marker, line_panic_satisfaction,
        line_safety_satisfaction, normalize_requirement_name,
    };

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
            line_panic_satisfaction("// PANIC: index in bounds: checked by caller"),
            Some(PanicSatisfaction {
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
                PanicSatisfaction {
                    requirement: Some(String::from("nonzero")),
                    reason: String::from(
                        "caller checked denominator.\nThe constructor rejects zero."
                    ),
                },
                PanicSatisfaction {
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
                PanicSatisfaction {
                    requirement: Some(String::from("something[var_1]")),
                    reason: String::from(
                        "checked the first precondition.\nAdditional evidence for the first precondition."
                    ),
                },
                PanicSatisfaction {
                    requirement: Some(String::from("something2[var_1]")),
                    reason: String::from("checked the second precondition."),
                },
                PanicSatisfaction {
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
            [PanicSatisfaction {
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
        assert!(!line_has_panic_marker("let label = \"PANIC:\";"));
        assert!(!line_has_panic_marker("let _ = f(); // PANIC: inspected"));
        assert!(!line_has_panic_marker(
            "/// PANIC: doc comments are not call-site markers"
        ));
        assert!(!line_has_panic_marker(
            "// SAFETY: not the sniff-test marker"
        ));
        assert!(!line_has_panic_marker("// panic: no"));
        assert!(!line_has_panic_marker("// SAFE: old marker spelling"));
        assert!(!line_has_panic_marker("// PANIC:"));
        assert!(!line_has_panic_marker("// PANIC: nonzero:"));
    }

    #[test]
    fn safety_marker_uses_same_comment_syntax() {
        assert!(line_has_safety_marker(
            "// SAFETY: pointer came from NonNull"
        ));
        assert_eq!(
            line_safety_satisfaction("// SAFETY: initialized: written above"),
            Some(SafetySatisfaction {
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
            super::comment_block_satisfactions(&lines, MarkerKind::Safety),
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

    fn comment_block_satisfactions_for_panic(lines: &[String]) -> Vec<PanicSatisfaction> {
        super::comment_block_satisfactions(lines, MarkerKind::Panic)
            .into_iter()
            .map(Into::into)
            .collect()
    }
}
