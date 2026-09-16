//! Rustc diagnostic emission for interpreted workspace findings.

use std::path::Path;

use crate::config::{LintLevel, ReportRootSet};
use crate::report_roots::MissingReportRoot;
use rustc_errors::{Diag, DiagInner, EmissionGuarantee, Level, MultiSpan, Style};
use rustc_middle::ty::TyCtxt;
use rustc_span::{BytePos, Span};
use toml::Spanned;

use super::findings::{DiagnosticMessage, FindingDiagnostic};

pub(super) fn emit_finding_diagnostic(
    tcx: TyCtxt<'_>,
    level: LintLevel,
    lint_code: &str,
    diagnostic: &FindingDiagnostic,
) {
    let message = lint_coded_message(lint_code, &diagnostic.message);
    let spans = diagnostic.span.map(|primary| {
        let mut spans = MultiSpan::from_span(primary);
        if let Some(second) = diagnostic.second_primary_span {
            spans.push_primary_span(second);
        }
        spans
    });
    match (level, spans) {
        (LintLevel::Allow, _) => {}
        (LintLevel::Warn, Some(span)) => {
            let mut emitted = tcx.dcx().struct_span_warn(span, message.clone());
            decorate(&mut emitted, lint_code, &diagnostic.messages);
            emitted.emit();
        }
        (LintLevel::Warn, None) => {
            let mut emitted = tcx.dcx().struct_warn(message.clone());
            decorate(&mut emitted, lint_code, &diagnostic.messages);
            emitted.emit();
        }
        (LintLevel::Deny, Some(span)) => {
            let mut emitted = tcx.dcx().struct_span_err(span, message.clone());
            decorate(&mut emitted, lint_code, &diagnostic.messages);
            let _ = emitted.emit();
        }
        (LintLevel::Deny, None) => {
            let mut emitted = tcx.dcx().struct_err(message);
            decorate(&mut emitted, lint_code, &diagnostic.messages);
            let _ = emitted.emit();
        }
    }
}

/// `FailureNote` is the one rustc diagnostic level that omits the trailing
/// blank separator. Supply the ordinary note label and style explicitly so a
/// footer keeps rustc's green `note:` presentation without an empty line.
pub(super) fn emit_footer_note(tcx: TyCtxt<'_>, message: &str) {
    tcx.dcx().emit_diagnostic(DiagInner::new_with_messages(
        Level::FailureNote,
        vec![
            ("note".into(), Style::Level(Level::Note)),
            ((": ".to_owned() + message).into(), Style::NoStyle),
        ],
    ));
}

fn lint_coded_message(lint_code: &str, message: &str) -> String {
    format!("[{lint_code}] {message}")
}

fn decorate<G: EmissionGuarantee>(
    diagnostic: &mut Diag<'_, G>,
    lint_code: &str,
    messages: &[DiagnosticMessage],
) {
    diagnostic.is_lint(lint_code.to_owned(), false);
    let alternative_count = messages
        .iter()
        .filter(|message| {
            matches!(
                message,
                DiagnosticMessage::AlternativeHelp(_)
                    | DiagnosticMessage::SpanAlternativeHelp(_, _)
            )
        })
        .count();
    let mut alternative_index = 0;
    for message in messages {
        match message {
            DiagnosticMessage::Note(note) => {
                diagnostic.note(note.clone());
            }
            DiagnosticMessage::SpanNote(span, note) => {
                diagnostic.span_note(*span, note.clone());
            }
            DiagnosticMessage::SpanLabel(span, label) => {
                diagnostic.span_label(*span, label.clone());
            }
            DiagnosticMessage::Help(help) => {
                diagnostic.help(help.clone());
            }
            DiagnosticMessage::AlternativeHelp(help) => {
                alternative_index += 1;
                diagnostic.help(alternative_help(help, alternative_count, alternative_index));
            }
            DiagnosticMessage::SpanAlternativeHelp(span, help) => {
                alternative_index += 1;
                diagnostic.span_help(
                    *span,
                    alternative_help(help, alternative_count, alternative_index),
                );
            }
        }
    }
}

fn alternative_help(help: &str, alternative_count: usize, alternative_index: usize) -> String {
    if alternative_count > 1 {
        format!("[option {alternative_index}] {help}")
    } else {
        help.to_owned()
    }
}

pub(super) fn empty_report_roots_diagnostic(
    tcx: TyCtxt<'_>,
    manifest_path: &Path,
    report_roots: &Spanned<ReportRootSet>,
    crate_name: &str,
) -> FindingDiagnostic {
    let message = format!(
        "`[analysis].report-roots = {}` selected no functions in `{crate_name}`; no effects were analyzed",
        report_roots.get_ref().description()
    );
    let source_file = tcx.sess.source_map().load_file(manifest_path).ok();
    let source_span = report_roots.span();
    let span = (!source_span.is_empty())
        .then_some(source_span)
        .and_then(|source_span| {
            source_file
                .as_ref()
                .and_then(|file| config_span(file, source_span))
        });
    FindingDiagnostic {
        span,
        second_primary_span: None,
        message,
        messages: vec![DiagnosticMessage::Help(String::from(
            "update `[analysis].report-roots` to include functions in the current crate",
        ))],
    }
}

pub(super) fn missing_report_root_diagnostic(
    tcx: TyCtxt<'_>,
    manifest_path: &Path,
    root: &MissingReportRoot,
) -> FindingDiagnostic {
    let source_file = tcx.sess.source_map().load_file(manifest_path).ok();
    let span = source_file
        .as_ref()
        .and_then(|file| config_span(file, root.source_span.clone()));
    let message = span.map_or_else(
        || format!("configured report root was not found: `{}`", root.path),
        |_| String::from("configured report root was not found"),
    );
    FindingDiagnostic {
        span,
        second_primary_span: None,
        message,
        messages: vec![
            DiagnosticMessage::Note(String::from("configured under `[analysis].report-roots`")),
            DiagnosticMessage::Help(String::from(
                "remove it or update it to a function in the current crate",
            )),
        ],
    }
}

fn config_span(file: &rustc_span::SourceFile, source_span: std::ops::Range<usize>) -> Option<Span> {
    let start = normalized_offset(file, source_span.start)?;
    let end = normalized_offset(file, source_span.end)?;
    Some(Span::with_root_ctxt(
        file.start_pos + BytePos(start),
        file.start_pos + BytePos(end),
    ))
}

fn normalized_offset(file: &rustc_span::SourceFile, original: usize) -> Option<u32> {
    let original = u32::try_from(original).ok()?;
    let diff = file
        .normalized_pos
        .iter()
        .take_while(|entry| entry.pos.0 + entry.diff <= original)
        .last()
        .map_or(0, |entry| entry.diff);
    Some(original - diff)
}

#[cfg(test)]
mod tests {
    use rustc_span::source_map::{FilePathMapping, SourceMap};
    use rustc_span::{BytePos, FileName};

    use super::{alternative_help, config_span, lint_coded_message};

    fn with_source_file(source: &str, check: impl FnOnce(&rustc_span::SourceFile)) {
        rustc_span::create_default_session_globals_then(|| {
            let source_map = SourceMap::new(FilePathMapping::empty());
            let file = source_map.new_source_file(
                FileName::Custom(String::from("sniff-test.toml")),
                source.to_owned(),
            );
            check(&file);
        });
    }

    #[test]
    fn converts_config_byte_range_to_source_span() {
        with_source_file("key = \"value\"\n", |file| {
            let span = config_span(file, 6..13).expect("span should fit");
            assert_eq!(span.lo(), file.start_pos + BytePos(6));
            assert_eq!(span.hi(), file.start_pos + BytePos(13));
        });
    }

    #[test]
    fn crlf_manifest_offsets_account_for_normalization() {
        with_source_file("a = 1\r\nkey = \"value\"\r\n", |file| {
            let span = config_span(file, 13..20).expect("span should fit");
            assert_eq!(span.lo(), file.start_pos + BytePos(12));
            assert_eq!(span.hi(), file.start_pos + BytePos(19));
        });
    }

    #[test]
    fn bom_manifest_offsets_account_for_normalization() {
        with_source_file("\u{feff}key = \"value\"\n", |file| {
            let span = config_span(file, 9..16).expect("span should fit");
            assert_eq!(span.lo(), file.start_pos + BytePos(6));
            assert_eq!(span.hi(), file.start_pos + BytePos(13));
        });
    }

    #[test]
    fn lint_codes_are_visible_in_the_diagnostic_headline() {
        assert_eq!(
            lint_coded_message(
                "sniff-test::safety::raw-pointer-dereference-missing-justification",
                "unsafe operation lacks a justification",
            ),
            "[sniff-test::safety::raw-pointer-dereference-missing-justification] unsafe operation lacks a justification"
        );
    }

    #[test]
    fn multiple_alternative_fixes_receive_bracketed_option_labels() {
        assert_eq!(
            alternative_help("add a local justification", 3, 1),
            "[option 1] add a local justification"
        );
        assert_eq!(
            alternative_help("audit the dependency", 3, 3),
            "[option 3] audit the dependency"
        );
        assert_eq!(
            alternative_help("add the only available justification", 1, 1),
            "add the only available justification"
        );
    }
}
