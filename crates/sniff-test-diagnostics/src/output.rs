//! Render and emit one analyzed artifact's results.

use rustc_middle::ty::TyCtxt;
use sniff_test_core::config::SniffTestConfig;
use sniff_test_core::effects::Effect;

use crate::diagnostics::{emit_finding_diagnostic, emit_footer_note};
use crate::findings::{
    FULL_STACK_TRACE_HINT, Finding, aggregate_human_findings, is_effect_source_finding,
    resolve_findings, take_full_stack_trace_hint,
};
use crate::report::{AnalysisArtifactReport, REPORT_FORMAT_VERSION, ReportArtifact};

pub fn emit_tool_error(tcx: TyCtxt<'_>, message: impl Into<String>) {
    let diagnostic = tcx.dcx().struct_err(message.into());
    let _ = diagnostic.emit();
}

#[must_use]
pub fn build_report(
    crate_name: String,
    rustc_version: String,
    config: &SniffTestConfig,
    effects: &[Box<dyn Effect + '_>],
    findings: Vec<Finding>,
) -> AnalysisArtifactReport {
    AnalysisArtifactReport {
        reason: String::from("sniff-test-artifact"),
        format_version: REPORT_FORMAT_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        rustc_version,
        artifact: ReportArtifact { crate_name },
        findings: resolve_findings(findings, config, effects),
    }
}

pub fn emit_human_diagnostics(
    tcx: TyCtxt<'_>,
    report: &AnalysisArtifactReport,
    effect_flags: &[String],
) {
    let mut human_findings = aggregate_human_findings(&report.findings);
    let has_trace_id = human_findings
        .iter()
        .any(|finding| finding.finding.trace_id.is_some());
    let show_full_stack_trace_hint = take_full_stack_trace_hint(&mut human_findings);
    for finding in human_findings {
        emit_finding_diagnostic(
            tcx,
            finding.level,
            &finding.finding.kind.lint_code(),
            &finding.finding.diagnostic,
            !is_effect_source_finding(&finding.finding.kind),
            finding.finding.trace_id.as_deref(),
            false,
        );
    }
    if has_trace_id {
        let flags = effect_flags
            .iter()
            .map(|effect| format!(" -e {effect}"))
            .collect::<String>();
        emit_footer_note(
            tcx,
            &format!("run `cargo sniff-test{flags} --explain <trace-id>` to see more details"),
        );
    }
    if show_full_stack_trace_hint {
        emit_footer_note(tcx, FULL_STACK_TRACE_HINT);
    }
}

#[must_use]
pub fn emit_explanation(tcx: TyCtxt<'_>, report: &AnalysisArtifactReport, trace_id: &str) -> bool {
    let selected = report
        .findings
        .iter()
        .filter(|finding| finding.finding.trace_id.as_deref() == Some(trace_id))
        .cloned()
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return false;
    }
    for finding in aggregate_human_findings(&selected) {
        emit_finding_diagnostic(
            tcx,
            finding.level,
            &finding.finding.kind.lint_code(),
            &finding.finding.diagnostic,
            !is_effect_source_finding(&finding.finding.kind),
            finding.finding.trace_id.as_deref(),
            true,
        );
    }
    true
}

pub fn emit_json_report(report: &AnalysisArtifactReport) {
    match serde_json::to_string(report) {
        Ok(report) => println!("{report}"),
        Err(error) => eprintln!("sniff-test: failed to encode JSON report: {error}"),
    }
}
