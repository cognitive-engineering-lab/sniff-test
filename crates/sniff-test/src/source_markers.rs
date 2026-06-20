//! Source-local analysis markers.

use rustc_middle::ty::TyCtxt;
use rustc_span::{SourceFile, Span};

const PANIC_MARKER: &str = "PANIC:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanicSatisfaction {
    pub requirement: Option<String>,
    pub reason: String,
}

#[must_use]
pub fn span_has_panic_marker(tcx: TyCtxt<'_>, span: Span) -> bool {
    !span_panic_satisfactions(tcx, span).is_empty()
}

#[must_use]
pub fn span_panic_satisfactions(tcx: TyCtxt<'_>, span: Span) -> Vec<PanicSatisfaction> {
    let span = span.source_callsite();
    let location = tcx.sess.source_map().lookup_char_pos(span.lo());
    let line_index = location.line.saturating_sub(1);

    let mut satisfactions = source_line_panic_satisfactions(&location.file, line_index);
    satisfactions.extend(preceding_comment_block_panic_satisfactions(
        &location.file,
        line_index,
    ));
    satisfactions
}

#[must_use]
pub fn line_has_panic_marker(line: &str) -> bool {
    line_panic_satisfaction(line).is_some()
}

#[must_use]
pub fn line_panic_satisfaction(line: &str) -> Option<PanicSatisfaction> {
    comment_body(line)
        .and_then(|body| body.strip_prefix(PANIC_MARKER))
        .map(parse_panic_marker)
        .filter(has_justification)
}

#[must_use]
pub fn normalize_requirement_name(name: &str) -> String {
    let mut normalized = String::new();
    let mut pending_space = false;

    for character in name.trim().chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            if pending_space && !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.push(character);
            pending_space = false;
        } else {
            pending_space = true;
        }
    }

    normalized
}

fn parse_panic_marker_body(body: &str) -> (Option<String>, &str) {
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

fn parse_panic_marker(body: &str) -> PanicSatisfaction {
    let body = body.trim();
    let (requirement, reason) = parse_panic_marker_body(body);
    PanicSatisfaction {
        requirement,
        reason: reason.to_owned(),
    }
}

fn looks_like_requirement_name(name: &str) -> bool {
    !normalize_requirement_name(name).is_empty()
}

fn preceding_comment_block_panic_satisfactions(
    file: &SourceFile,
    line_index: usize,
) -> Vec<PanicSatisfaction> {
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
    comment_block_panic_satisfactions(&block)
}

fn source_line_panic_satisfactions(file: &SourceFile, line_index: usize) -> Vec<PanicSatisfaction> {
    file.get_line(line_index)
        .and_then(|line| line_panic_satisfaction(line.as_ref()))
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

fn comment_block_panic_satisfactions(lines: &[String]) -> Vec<PanicSatisfaction> {
    let mut satisfactions: Vec<PanicSatisfaction> = Vec::new();
    let mut pending_header_reason: Option<String> = None;
    let mut in_panic_block = false;

    for line in lines {
        let Some(body) = comment_body(line) else {
            continue;
        };
        if let Some(marker_body) = body.strip_prefix(PANIC_MARKER) {
            flush_pending_header(&mut satisfactions, &mut pending_header_reason);
            in_panic_block = true;
            let marker = parse_panic_marker(marker_body);
            if marker.requirement.is_none() && marker.reason.is_empty() {
                pending_header_reason = Some(String::new());
            } else {
                satisfactions.push(marker);
            }
        } else if in_panic_block {
            if let Some(satisfaction) = parse_panic_satisfaction_bullet(body) {
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

fn flush_pending_header(
    satisfactions: &mut Vec<PanicSatisfaction>,
    pending_header_reason: &mut Option<String>,
) {
    if let Some(reason) = pending_header_reason.take() {
        satisfactions.push(PanicSatisfaction {
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

fn has_justification(satisfaction: &PanicSatisfaction) -> bool {
    !satisfaction.reason.trim().is_empty()
}

fn parse_panic_satisfaction_bullet(line: &str) -> Option<PanicSatisfaction> {
    let line = line.trim_start();
    let body = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .or_else(|| line.strip_prefix("+ "))?;
    let (name, reason) = parse_panic_marker_body(body);
    name.map(|requirement| PanicSatisfaction {
        requirement: Some(requirement),
        reason: reason.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        PanicSatisfaction, line_has_panic_marker, line_panic_satisfaction,
        normalize_requirement_name,
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
            super::comment_block_panic_satisfactions(&lines),
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
            super::comment_block_panic_satisfactions(&lines),
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
            super::comment_block_panic_satisfactions(&lines),
            [PanicSatisfaction {
                requirement: None,
                reason: String::from("caller checked the local invariant."),
            }]
        );
    }

    #[test]
    fn empty_panic_marker_alone_does_not_suppress() {
        let lines = [String::from("    // PANIC:")];

        assert_eq!(super::comment_block_panic_satisfactions(&lines), []);
    }

    #[test]
    fn requirement_bullets_without_panic_marker_are_ignored() {
        let lines = [
            String::from("    // Requirements:"),
            String::from("    // - nonzero: checked above."),
        ];

        assert_eq!(super::comment_block_panic_satisfactions(&lines), []);
    }

    #[test]
    fn empty_requirement_bullets_do_not_satisfy_requirements() {
        let lines = [
            String::from("    // PANIC:"),
            String::from("    // - nonzero:"),
        ];

        assert_eq!(super::comment_block_panic_satisfactions(&lines), []);
    }

    #[test]
    fn panic_marker_rejects_non_plain_comment_text() {
        assert!(!line_has_panic_marker("let label = \"PANIC:\";"));
        assert!(!line_has_panic_marker("let _ = f(); // PANIC: inspected"));
        assert!(!line_has_panic_marker(
            "/// PANIC: doc comments are for `# Panics` API docs"
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
}
