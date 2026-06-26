use crate::config::{LintLevel, SafetyLintConfig};
use crate::namespace::canonical_namespace;
use crate::safety::{
    SafetyAnalysis, SafetyCallKind, SafetyFinding, SafetyFindingKind, render_safety_requirement,
    safety_call_label, safety_callee_name,
};
use rustc_middle::ty::TyCtxt;
use serde::Serialize;

use super::report::render_span;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) struct SafetyArtifactReport {
    counts: SafetyFindingCounts,
    findings: Vec<SafetyFindingReport>,
}

impl SafetyArtifactReport {
    pub(super) fn from_analysis(
        tcx: TyCtxt<'_>,
        analysis: SafetyAnalysis,
        lints: SafetyLintConfig,
    ) -> Option<Self> {
        let mut report = Self {
            counts: SafetyFindingCounts::default(),
            findings: Vec::new(),
        };

        for finding in analysis.findings {
            let level = finding.kind().lint_level(lints);
            if level == LintLevel::Allow {
                continue;
            }
            report.counts.increment(finding.kind());
            report
                .findings
                .push(SafetyFindingReport::from_finding(tcx, finding, level));
        }

        (!report.findings.is_empty()).then_some(report)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
struct SafetyFindingCounts {
    missing_safety_docs: usize,
    unsafe_calls_missing_justification: usize,
    unsafe_calls_missing_requirements: usize,
    safety_obligations_missing_justification: usize,
    safety_obligations_missing_requirements: usize,
}

impl SafetyFindingCounts {
    fn increment(&mut self, kind: SafetyFindingKind) {
        match kind {
            SafetyFindingKind::MissingSafetyDocs => self.missing_safety_docs += 1,
            SafetyFindingKind::UnsafeCallMissingJustification => {
                self.unsafe_calls_missing_justification += 1;
            }
            SafetyFindingKind::UnsafeCallMissingRequirements => {
                self.unsafe_calls_missing_requirements += 1;
            }
            SafetyFindingKind::SafetyObligationMissingJustification => {
                self.safety_obligations_missing_justification += 1;
            }
            SafetyFindingKind::SafetyObligationMissingRequirements => {
                self.safety_obligations_missing_requirements += 1;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
struct SafetyFindingReport {
    kind: SafetyFindingKindReport,
    level: LintLevel,
    span: String,
    function: String,
    target: Option<String>,
    reason: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    missing_requirements: Vec<String>,
}

impl SafetyFindingReport {
    fn from_finding(tcx: TyCtxt<'_>, finding: SafetyFinding, level: LintLevel) -> Self {
        match finding {
            SafetyFinding::MissingSafetyDocs { def_id, span } => {
                let function = canonical_namespace(tcx, def_id);
                Self {
                    kind: SafetyFindingKindReport::MissingSafetyDocs,
                    level,
                    span: render_span(tcx, span),
                    function: function.clone(),
                    target: None,
                    reason: format!("public unsafe function `{function}` is missing # Safety docs"),
                    missing_requirements: Vec::new(),
                }
            }
            SafetyFinding::CallMissingJustification {
                caller,
                callee,
                call_kind,
                span,
            } => {
                let target = safety_callee_name(tcx, callee);
                let kind = safety_finding_report_kind(call_kind, false);
                let call = safety_call_label(call_kind);
                Self {
                    kind,
                    level,
                    span: render_span(tcx, span),
                    function: canonical_namespace(tcx, caller),
                    target: Some(target.clone()),
                    reason: format!("{call} to `{target}` has no `// SAFETY:` justification"),
                    missing_requirements: Vec::new(),
                }
            }
            SafetyFinding::CallMissingRequirements {
                caller,
                callee,
                call_kind,
                span,
                missing_requirements,
            } => {
                let target = safety_callee_name(tcx, callee);
                let kind = safety_finding_report_kind(call_kind, true);
                let call = safety_call_label(call_kind);
                let missing_requirements = missing_requirements
                    .iter()
                    .map(render_safety_requirement)
                    .collect();
                Self {
                    kind,
                    level,
                    span: render_span(tcx, span),
                    function: canonical_namespace(tcx, caller),
                    target: Some(target.clone()),
                    reason: format!(
                        "{call} to `{target}` does not satisfy all # Safety requirements"
                    ),
                    missing_requirements,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SafetyFindingKindReport {
    MissingSafetyDocs,
    UnsafeCallMissingJustification,
    UnsafeCallMissingRequirements,
    SafetyObligationMissingJustification,
    SafetyObligationMissingRequirements,
}

fn safety_finding_report_kind(
    call_kind: SafetyCallKind,
    missing_requirements: bool,
) -> SafetyFindingKindReport {
    match (call_kind, missing_requirements) {
        (SafetyCallKind::Unsafe, false) => SafetyFindingKindReport::UnsafeCallMissingJustification,
        (SafetyCallKind::Unsafe, true) => SafetyFindingKindReport::UnsafeCallMissingRequirements,
        (SafetyCallKind::ConfiguredObligation, false) => {
            SafetyFindingKindReport::SafetyObligationMissingJustification
        }
        (SafetyCallKind::ConfiguredObligation, true) => {
            SafetyFindingKindReport::SafetyObligationMissingRequirements
        }
    }
}
