//! Rustc diagnostic emission for interpreted workspace findings.

use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::config::{LintLevel, ReportRootSet};
use crate::report_roots::MissingReportRoot;
use rustc_errors::annotate_snippet_emitter_writer::AnnotateSnippetEmitter;
use rustc_errors::emitter::Emitter;
use rustc_errors::{
    AutoStream, ColorChoice, Diag, DiagInner, EmissionGuarantee, Level, MultiSpan, Style,
};
use rustc_middle::ty::TyCtxt;
use rustc_span::source_map::SourceMap;
use rustc_span::{BytePos, Span};
use toml::Spanned;

use super::explanations::DiagnosticGroupHandle;
use super::findings::{DiagnosticMessage, FindingDiagnostic};

pub(super) fn emit_finding_diagnostic(
    tcx: TyCtxt<'_>,
    level: LintLevel,
    lint_code: &str,
    diagnostic: &FindingDiagnostic,
    group: Option<&DiagnosticGroupHandle>,
    cache_dir: &Path,
    frontend_executable: Option<&Path>,
) {
    let message = lint_coded_message(lint_code, &diagnostic.message);
    let messages = messages_for_emission(diagnostic, group);
    let explanation_help = group.map(|group| explain_help(group, cache_dir, frontend_executable));
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
            decorate(&mut emitted, lint_code, messages, explanation_help);
            emitted.emit();
        }
        (LintLevel::Warn, None) => {
            let mut emitted = tcx.dcx().struct_warn(message.clone());
            decorate(&mut emitted, lint_code, messages, explanation_help);
            emitted.emit();
        }
        (LintLevel::Deny, Some(span)) => {
            let mut emitted = tcx.dcx().struct_span_err(span, message.clone());
            decorate(&mut emitted, lint_code, messages, explanation_help);
            let _ = emitted.emit();
        }
        (LintLevel::Deny, None) => {
            let mut emitted = tcx.dcx().struct_err(message);
            decorate(&mut emitted, lint_code, messages, explanation_help);
            let _ = emitted.emit();
        }
    }
}

pub(super) fn render_finding_diagnostic(
    tcx: TyCtxt<'_>,
    level: LintLevel,
    lint_code: &str,
    diagnostic: &FindingDiagnostic,
    group: &DiagnosticGroupHandle,
) -> String {
    let level = match level {
        LintLevel::Allow => return String::new(),
        LintLevel::Warn => Level::Warning,
        LintLevel::Deny => Level::Error,
    };
    let message = format!(
        "{} ({group})",
        lint_coded_message(lint_code, &diagnostic.message)
    );
    let mut rendered = Diag::<()>::new(tcx.dcx(), level, message);
    if let Some(primary) = diagnostic.span {
        let mut spans = MultiSpan::from_span(primary);
        if let Some(second) = diagnostic.second_primary_span {
            spans.push_primary_span(second);
        }
        rendered.span(spans);
    }
    let mut messages = diagnostic.messages.clone();
    messages.sort_by_key(|message| {
        matches!(
            message,
            DiagnosticMessage::Help(_) | DiagnosticMessage::SpanHelp(..)
        )
    });
    decorate(&mut rendered, lint_code, &messages, None);
    render_diagnostic(
        rendered,
        tcx.sess.psess.clone_source_map(),
        tcx.sess.opts.diagnostic_width,
    )
}

fn render_diagnostic<G: EmissionGuarantee>(
    diagnostic: Diag<'_, G>,
    source_map: Arc<SourceMap>,
    diagnostic_width: Option<usize>,
) -> String {
    let inner = (*diagnostic).clone();
    // Rendering must not emit to the session or increment its error count.
    diagnostic.cancel();
    let buffer = DiagnosticBuffer::default();
    AnnotateSnippetEmitter::new(AutoStream::new(
        Box::new(buffer.clone()),
        ColorChoice::AlwaysAnsi,
    ))
    .sm(Some(source_map))
    .diagnostic_width(diagnostic_width)
    .emit_diagnostic(inner);
    let bytes = std::mem::take(&mut *buffer.0.lock().expect("diagnostic buffer lock"));
    String::from_utf8(bytes).expect("rustc diagnostics are UTF-8")
}

#[derive(Clone, Default)]
struct DiagnosticBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for DiagnosticBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("diagnostic buffer lock").write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn messages_for_emission<'a>(
    diagnostic: &'a FindingDiagnostic,
    group: Option<&DiagnosticGroupHandle>,
) -> &'a [DiagnosticMessage] {
    if group.is_some() {
        diagnostic.messages_for_default_output()
    } else {
        &diagnostic.messages
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
    explanation_help: Option<String>,
) {
    diagnostic.is_lint(lint_code.to_owned(), false);
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
            DiagnosticMessage::SpanHelp(span, help) => {
                diagnostic.span_help(*span, help.clone());
            }
            DiagnosticMessage::Help(help) => {
                diagnostic.help(help.clone());
            }
            DiagnosticMessage::TraceStep {
                span,
                index,
                total,
                description,
            } => {
                let note = format!(
                    "effect trace step {index}/{total} (report root -> effect source): {description}"
                );
                if let Some(span) = span {
                    diagnostic.span_note(*span, note);
                } else {
                    diagnostic.note(note);
                }
            }
        }
    }
    if let Some(help) = explanation_help {
        diagnostic.help(help);
    }
}

fn explain_help(
    group: &DiagnosticGroupHandle,
    cache_dir: &Path,
    frontend_executable: Option<&Path>,
) -> String {
    let Some(frontend_executable) = frontend_executable else {
        return format!("run `cargo sniff-test explain {}`", group.as_str());
    };
    let command = explain_command(group, cache_dir, frontend_executable);
    let shell = if cfg!(windows) { " in PowerShell" } else { "" };
    format!("for the full explanation, run{shell} `{command}`")
}

#[cfg(unix)]
fn explain_command(
    group: &DiagnosticGroupHandle,
    cache_dir: &Path,
    frontend_executable: &Path,
) -> String {
    format!(
        "{} explain {} --cache-dir {}",
        shell_quote(&frontend_executable.to_string_lossy()),
        group.as_str(),
        shell_quote(&cache_dir.to_string_lossy()),
    )
}

#[cfg(windows)]
fn explain_command(
    group: &DiagnosticGroupHandle,
    cache_dir: &Path,
    frontend_executable: &Path,
) -> String {
    format!(
        "& {} explain {} --cache-dir {}",
        powershell_quote(&frontend_executable.to_string_lossy()),
        group.as_str(),
        powershell_quote(&cache_dir.to_string_lossy()),
    )
}

#[cfg(unix)]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(windows)]
fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
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
        compact_messages: None,
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
        compact_messages: None,
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
    use rustc_errors::emitter::SilentEmitter;
    use rustc_errors::{Diag, DiagCtxt, Level};
    use rustc_span::source_map::{FilePathMapping, SourceMap};
    use rustc_span::{BytePos, FileName, Span};
    use std::path::Path;
    use std::sync::Arc;

    use crate::cli::explanations::{DiagnosticGroupHandle, DiagnosticGroupKey};
    use crate::cli::findings::{DiagnosticMessage, FindingDiagnostic};

    use super::{
        config_span, decorate, explain_help, lint_coded_message, messages_for_emission,
        render_diagnostic,
    };

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

    fn group_handle() -> DiagnosticGroupHandle {
        DiagnosticGroupKey::new(
            "sniff-test::panics::panic-invocation",
            "sample::operation",
            "",
        )
        .handle()
    }

    #[test]
    fn compact_messages_require_a_persisted_diagnostic_group() {
        let full = DiagnosticMessage::Note(String::from("full trace"));
        let compact = DiagnosticMessage::Help(String::from("compact action"));
        let diagnostic = FindingDiagnostic {
            span: None,
            second_primary_span: None,
            message: String::from("finding"),
            messages: vec![full.clone()],
            compact_messages: Some(vec![compact.clone()]),
        };
        let group = group_handle();

        assert_eq!(messages_for_emission(&diagnostic, None), &[full]);
        assert_eq!(messages_for_emission(&diagnostic, Some(&group)), &[compact]);
    }

    #[test]
    fn native_rendering_preserves_color_source_and_details_without_emitting_errors() {
        rustc_span::create_default_session_globals_then(|| {
            #[expect(
                clippy::arc_with_non_send_sync,
                reason = "rustc's emitter requires Arc<SourceMap>, including in single-threaded tests"
            )]
            let source_map = Arc::new(SourceMap::new(FilePathMapping::empty()));
            let source = "fn main() {\n    danger();\n}\n";
            let file = source_map.new_source_file(
                FileName::Custom(String::from("example.rs")),
                source.to_owned(),
            );
            let start = u32::try_from(source.find("danger").expect("source call"))
                .expect("source fits in a span");
            let span = Span::with_root_ctxt(
                file.start_pos + BytePos(start),
                file.start_pos + BytePos(start + 8),
            );
            let dcx = DiagCtxt::new(Box::new(SilentEmitter));
            for level in [Level::Warning, Level::Error] {
                let mut diagnostic = Diag::<()>::new(dcx.handle(), level, "finding (abcd)");
                diagnostic.span(span);
                decorate(
                    &mut diagnostic,
                    "sniff-test::safety::unsafe-call",
                    &[
                        DiagnosticMessage::SpanLabel(span, String::from("audit this call")),
                        DiagnosticMessage::TraceStep {
                            span: Some(span),
                            index: 1,
                            total: 1,
                            description: String::from("main calls danger"),
                        },
                        DiagnosticMessage::Help(String::from("justify the safety contract")),
                    ],
                    None,
                );
                let rendered = render_diagnostic(diagnostic, Arc::clone(&source_map), Some(100));

                assert!(rendered.contains("\u{1b}["), "native ANSI styling");
                assert!(rendered.contains("finding (abcd)"));
                assert!(rendered.contains("example.rs"));
                assert!(rendered.contains(":2:5"), "{rendered:?}");
                assert!(rendered.contains("danger();"));
                assert!(rendered.contains("audit this call"));
                assert!(rendered.contains("effect trace step 1/1"));
                assert!(rendered.contains("main calls danger"));
                assert!(rendered.contains("justify the safety contract"));
                assert!(!rendered.contains("run `cargo sniff-test explain"));
                assert_eq!(dcx.handle().err_count(), 0);
                assert!(dcx.handle().has_errors().is_none());
            }
        });
    }

    #[test]
    fn explain_metadata_is_one_help_without_a_separate_handle_line() {
        let group = group_handle();
        let messages = [DiagnosticMessage::Help(String::from(
            "remediate this finding",
        ))];
        let dcx = DiagCtxt::new(Box::new(SilentEmitter));
        let mut diagnostic = dcx.handle().struct_warn("finding");

        decorate(
            &mut diagnostic,
            "sniff-test::panics::panic-invocation",
            &messages,
            Some(explain_help(
                &group,
                Path::new("/tmp/sniff-test-cache"),
                Some(Path::new("/opt/sniff-test")),
            )),
        );

        let children = diagnostic
            .children
            .iter()
            .map(|child| {
                let message = child
                    .messages
                    .iter()
                    .filter_map(|(message, _)| message.as_str())
                    .collect::<String>();
                (child.level, message)
            })
            .collect::<Vec<_>>();
        diagnostic.cancel();

        assert!(children.contains(&(Level::Help, String::from("remediate this finding"))));
        assert!(
            !children
                .iter()
                .any(|(_, message)| message.starts_with("issue:"))
        );
        assert_eq!(
            children
                .iter()
                .filter(|(_, message)| message.starts_with("for the full explanation, run"))
                .map(|(level, _)| *level)
                .collect::<Vec<_>>(),
            [Level::Help]
        );
    }

    #[cfg(unix)]
    #[test]
    fn default_explain_help_is_a_short_cargo_command() {
        let group = group_handle();

        assert_eq!(
            explain_help(&group, Path::new("/unused/default/cache"), None),
            format!("run `cargo sniff-test explain {}`", group.as_str())
        );
    }

    #[cfg(unix)]
    #[test]
    fn fallback_explain_help_names_the_exact_frontend_and_cache() {
        let group = group_handle();

        assert_eq!(
            explain_help(
                &group,
                Path::new("/tmp/cache with 'quote"),
                Some(Path::new("/opt/sniff test/cargo-sniff-test")),
            ),
            format!(
                "for the full explanation, run `'/opt/sniff test/cargo-sniff-test' explain {} --cache-dir '/tmp/cache with '\\''quote'`",
                group.as_str()
            )
        );
    }

    #[cfg(windows)]
    #[test]
    fn fallback_explain_help_names_the_exact_frontend_and_cache() {
        let group = group_handle();

        assert_eq!(
            explain_help(
                &group,
                Path::new(r"C:\cache with 'quote"),
                Some(Path::new(r"C:\Program Files\cargo-sniff-test.exe")),
            ),
            format!(
                "for the full explanation, run in PowerShell `& 'C:\\Program Files\\cargo-sniff-test.exe' explain {} --cache-dir 'C:\\cache with ''quote'`",
                group.as_str()
            )
        );
    }
}
