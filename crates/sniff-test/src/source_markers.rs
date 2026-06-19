//! Source-local analysis markers.

use rustc_middle::ty::TyCtxt;
use rustc_span::{SourceFile, Span};

const SAFE_MARKER: &str = "SAFE:";

#[must_use]
pub fn span_has_safe_marker(tcx: TyCtxt<'_>, span: Span) -> bool {
    let span = span.source_callsite();
    let location = tcx.sess.source_map().lookup_char_pos(span.lo());
    let line_index = location.line.saturating_sub(1);

    source_line_has_safe_marker(&location.file, line_index)
        || preceding_comment_block_has_safe_marker(&location.file, line_index)
}

#[must_use]
pub fn line_has_safe_marker(line: &str) -> bool {
    let line = line.trim_start();
    let Some(comment) = line.strip_prefix("//") else {
        return false;
    };
    comment
        .trim_start_matches('/')
        .trim_start_matches('!')
        .trim_start()
        .starts_with(SAFE_MARKER)
}

fn preceding_comment_block_has_safe_marker(file: &SourceFile, line_index: usize) -> bool {
    let mut current = line_index;
    while let Some(previous) = current.checked_sub(1) {
        let Some(line) = file.get_line(previous) else {
            break;
        };
        let line = line.as_ref();
        if line_has_safe_marker(line) {
            return true;
        }
        if !line_is_standalone_comment(line) {
            break;
        }
        current = previous;
    }

    false
}

fn source_line_has_safe_marker(file: &SourceFile, line_index: usize) -> bool {
    file.get_line(line_index)
        .is_some_and(|line| line_has_safe_marker(line.as_ref()))
}

fn line_is_standalone_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

#[cfg(test)]
mod tests {
    use super::line_has_safe_marker;

    #[test]
    fn safe_marker_matches_line_and_doc_comments() {
        assert!(line_has_safe_marker("// SAFE: caller checked denominator"));
        assert!(line_has_safe_marker("/// SAFE: caller checked denominator"));
        assert!(line_has_safe_marker("    // SAFE: inspected"));
    }

    #[test]
    fn safe_marker_rejects_non_comment_text() {
        assert!(!line_has_safe_marker("let label = \"SAFE:\";"));
        assert!(!line_has_safe_marker("let _ = f(); // SAFE: inspected"));
        assert!(!line_has_safe_marker(
            "// SAFETY: not the sniff-test marker"
        ));
        assert!(!line_has_safe_marker("// unsafe: no"));
    }

    #[test]
    fn leading_comment_block_can_contain_safe_marker_above_explanation() {
        let lines = [
            "pub fn ratio(total: usize, denominator: usize) -> usize {",
            "    // SAFE: caller guarantees denominator is nonzero.",
            "    // This is enforced by the public constructor.",
            "    total / denominator",
            "}",
        ];

        assert!(lines_have_safe_marker_before(&lines, 3));
    }

    #[test]
    fn leading_comment_block_stops_at_non_comment_lines() {
        let lines = [
            "pub fn ratio(total: usize, denominator: usize) -> usize {",
            "    // SAFE: this belongs to the checked branch.",
            "    let checked = denominator.max(1);",
            "    total / denominator",
            "}",
        ];

        assert!(!lines_have_safe_marker_before(&lines, 3));
    }

    fn lines_have_safe_marker_before(lines: &[&str], line_index: usize) -> bool {
        let mut current = line_index;
        while let Some(previous) = current.checked_sub(1) {
            let Some(line) = lines.get(previous) else {
                break;
            };
            if line_has_safe_marker(line) {
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
