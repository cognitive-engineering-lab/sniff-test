//! Rustc diagnostic emission for interpreted workspace findings.

use std::path::Path;

use crate::config::{LintLevel, ReportRootSet};
use crate::report_roots::MissingReportRoot;
use rustc_errors::{Diag, EmissionGuarantee};
use rustc_middle::ty::TyCtxt;
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
    let explainable_group = group.map(|group| (group, frontend_executable));
    match (level, diagnostic.span) {
        (LintLevel::Allow, _) => {}
        (LintLevel::Warn, Some(span)) => {
            let mut emitted = tcx.dcx().struct_span_warn(span, message.clone());
            decorate(
                &mut emitted,
                lint_code,
                messages,
                explainable_group,
                cache_dir,
            );
            emitted.emit();
        }
        (LintLevel::Warn, None) => {
            let mut emitted = tcx.dcx().struct_warn(message.clone());
            decorate(
                &mut emitted,
                lint_code,
                messages,
                explainable_group,
                cache_dir,
            );
            emitted.emit();
        }
        (LintLevel::Deny, Some(span)) => {
            let mut emitted = tcx.dcx().struct_span_err(span, message.clone());
            decorate(
                &mut emitted,
                lint_code,
                messages,
                explainable_group,
                cache_dir,
            );
            let _ = emitted.emit();
        }
        (LintLevel::Deny, None) => {
            let mut emitted = tcx.dcx().struct_err(message);
            decorate(
                &mut emitted,
                lint_code,
                messages,
                explainable_group,
                cache_dir,
            );
            let _ = emitted.emit();
        }
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

fn lint_coded_message(lint_code: &str, message: &str) -> String {
    format!("[{lint_code}] {message}")
}

fn decorate<G: EmissionGuarantee>(
    diagnostic: &mut Diag<'_, G>,
    lint_code: &str,
    messages: &[DiagnosticMessage],
    group: Option<(&DiagnosticGroupHandle, Option<&Path>)>,
    cache_dir: &Path,
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
    if let Some((group, frontend_executable)) = group {
        diagnostic.help(explain_help(group, cache_dir, frontend_executable));
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
    use rustc_errors::{DiagCtxt, Level};
    use rustc_span::source_map::{FilePathMapping, SourceMap};
    use rustc_span::{BytePos, FileName};
    use std::path::Path;

    use crate::cli::explanations::{DiagnosticGroupHandle, DiagnosticGroupKey};
    use crate::cli::findings::{DiagnosticMessage, FindingDiagnostic};

    use super::{config_span, decorate, explain_help, lint_coded_message, messages_for_emission};

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
            message: String::from("finding"),
            messages: vec![full.clone()],
            compact_messages: Some(vec![compact.clone()]),
        };
        let group = group_handle();

        assert_eq!(messages_for_emission(&diagnostic, None), &[full]);
        assert_eq!(messages_for_emission(&diagnostic, Some(&group)), &[compact]);
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
            Some((&group, Some(Path::new("/opt/sniff-test")))),
            Path::new("/tmp/sniff-test-cache"),
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
