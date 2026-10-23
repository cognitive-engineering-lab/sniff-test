//! Render and emit one analyzed artifact's results.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use rustc_middle::ty::TyCtxt;
use sniff_test_core::artifact::EffectKey;
use sniff_test_core::config::{LintLevel, SniffTestConfig};
use sniff_test_core::effects::Effect;
use sniff_test_core::report_model::EffectFindingClass;

use crate::diagnostics::{emit_finding_diagnostic, emit_footer_note};
use crate::findings::{
    FULL_STACK_TRACE_HINT, Finding, FindingKind, ResolvedFinding, aggregate_human_findings,
    aggregate_human_findings_owned, is_effect_source_finding, resolve_findings_with_root_codes,
    take_full_stack_trace_hint,
};
use crate::report::{AnalysisArtifactReport, REPORT_FORMAT_VERSION, ReportArtifact};

pub fn emit_tool_error(tcx: TyCtxt<'_>, message: impl Into<String>) {
    let diagnostic = tcx.dcx().struct_err(message.into());
    let _ = diagnostic.emit();
}

#[must_use]
pub fn build_report_with_item_lints(
    crate_name: String,
    rustc_version: String,
    config: &SniffTestConfig,
    effects: &[Box<dyn Effect + '_>],
    findings: Vec<Finding>,
    item_lints: &BTreeMap<(String, String), LintLevel>,
    root_codes: &BTreeMap<String, String>,
) -> AnalysisArtifactReport {
    AnalysisArtifactReport {
        reason: String::from("sniff-test-artifact"),
        format_version: REPORT_FORMAT_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        rustc_version,
        artifact: ReportArtifact { crate_name },
        findings: resolve_findings_with_root_codes(
            findings, config, effects, item_lints, root_codes,
        ),
    }
}

pub fn emit_human_diagnostics(
    tcx: TyCtxt<'_>,
    report: &AnalysisArtifactReport,
    explicit_effects: &[EffectKey],
) {
    emit_human_findings(
        tcx,
        aggregate_human_findings(&report.findings),
        explicit_effects,
    );
}

pub fn emit_human_diagnostics_owned(
    tcx: TyCtxt<'_>,
    report: AnalysisArtifactReport,
    explicit_effects: &[EffectKey],
) {
    emit_human_findings(
        tcx,
        aggregate_human_findings_owned(report.findings),
        explicit_effects,
    );
}

fn emit_human_findings(
    tcx: TyCtxt<'_>,
    mut human_findings: Vec<ResolvedFinding>,
    explicit_effects: &[EffectKey],
) {
    let has_trace_id = human_findings
        .iter()
        .any(|finding| finding.finding.trace_id.is_some());
    let incomplete_notice = incomplete_notice(&human_findings);
    let show_full_stack_trace_hint = take_full_stack_trace_hint(&mut human_findings);
    for finding in human_findings {
        emit_finding_diagnostic(
            tcx,
            finding.level,
            &finding.finding.kind.lint_code(),
            finding.finding.diagnostic,
            !is_effect_source_finding(&finding.finding.kind),
            finding.finding.trace_id.as_deref(),
        );
    }
    if let Some(notice) = incomplete_notice {
        emit_footer_note(tcx, &notice);
    }
    if has_trace_id {
        emit_footer_note(tcx, &explain_hint(explicit_effects));
    }
    if show_full_stack_trace_hint {
        emit_footer_note(tcx, FULL_STACK_TRACE_HINT);
    }
}

fn incomplete_notice(findings: &[ResolvedFinding]) -> Option<String> {
    let incomplete = findings
        .iter()
        .filter_map(|resolved| match &resolved.finding.kind {
            FindingKind::Effect {
                effect,
                finding: EffectFindingClass::AnalysisIncomplete,
                ..
            } => Some((
                resolved.finding.root.as_deref().unwrap_or("unknown root"),
                effect.as_str(),
                resolved.finding.reason.as_str(),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [(root, effect, reason)] = incomplete.as_slice() else {
        let affected = incomplete
            .iter()
            .map(|(root, effect, _)| (*root, *effect))
            .collect::<BTreeSet<_>>();
        if affected.is_empty() {
            return None;
        }
        return Some(format!(
            "sniff-test analysis is incomplete for {} root/effect pairs; findings may be partial (see analysis-incomplete diagnostics above)",
            affected.len()
        ));
    };
    Some(format!(
        "sniff-test analysis is incomplete for `{root}` ({effect}): {reason}; findings may be partial"
    ))
}

fn explain_hint(explicit_effects: &[EffectKey]) -> String {
    let mut flags = String::new();
    for effect in explicit_effects {
        write!(flags, " -e {}", effect.as_str()).expect("writing to a String cannot fail");
    }
    format!("run `cargo sniff-test{flags} --explain <trace-id>` to see more details")
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
    for finding in aggregate_human_findings_owned(selected) {
        emit_finding_diagnostic(
            tcx,
            finding.level,
            &finding.finding.kind.lint_code(),
            finding.finding.diagnostic,
            !is_effect_source_finding(&finding.finding.kind),
            finding.finding.trace_id.as_deref(),
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

#[cfg(test)]
mod tests {
    use sniff_test_core::artifact::EffectKey;

    use super::explain_hint;

    #[test]
    fn explain_hint_preserves_explicit_effect_flags() {
        assert_eq!(
            explain_hint(&[]),
            "run `cargo sniff-test --explain <trace-id>` to see more details"
        );
        assert_eq!(
            explain_hint(&[EffectKey::new("panic")]),
            "run `cargo sniff-test -e panic --explain <trace-id>` to see more details"
        );
        assert_eq!(
            explain_hint(&[EffectKey::new("safety"), EffectKey::new("panic")]),
            "run `cargo sniff-test -e safety -e panic --explain <trace-id>` to see more details"
        );
    }
}
