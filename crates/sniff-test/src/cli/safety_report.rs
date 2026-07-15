use crate::config::{LintLevel, SafetyLintConfig};
use crate::namespace::canonical_namespace;
use crate::safety::{
    SafetyAnalysis, SafetyFinding, SafetyFindingKind, render_safety_requirement, safety_call_label,
    safety_callee_name, safety_op_label,
};
use rustc_middle::ty::TyCtxt;
use serde::Serialize;

use super::{report::render_span, usize_is_zero};

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
        ambiguous_obligations: LintLevel,
    ) -> Option<Self> {
        let mut report = Self {
            counts: SafetyFindingCounts::default(),
            findings: Vec::new(),
        };

        for finding in analysis.findings {
            let level = finding.kind().lint_level(lints, ambiguous_obligations);
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
    unsafe_call_missing_justification: usize,
    unsafe_call_missing_requirements: usize,
    unsafe_op_missing_justification: usize,
    safety_obligation_missing_justification: usize,
    safety_obligation_missing_requirements: usize,
    #[serde(skip_serializing_if = "usize_is_zero")]
    ambiguous_safety_requirements: usize,
}

impl SafetyFindingCounts {
    fn increment(&mut self, kind: SafetyFindingKind) {
        match kind {
            SafetyFindingKind::MissingSafetyDocs => self.missing_safety_docs += 1,
            SafetyFindingKind::UnsafeCallMissingJustification => {
                self.unsafe_call_missing_justification += 1;
            }
            SafetyFindingKind::UnsafeCallMissingRequirements => {
                self.unsafe_call_missing_requirements += 1;
            }
            SafetyFindingKind::UnsafeOpMissingJustification => {
                self.unsafe_op_missing_justification += 1;
            }
            SafetyFindingKind::SafetyObligationMissingJustification => {
                self.safety_obligation_missing_justification += 1;
            }
            SafetyFindingKind::SafetyObligationMissingRequirements => {
                self.safety_obligation_missing_requirements += 1;
            }
            SafetyFindingKind::AmbiguousSafetyRequirement => {
                self.ambiguous_safety_requirements += 1;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
struct SafetyFindingReport {
    kind: SafetyFindingKind,
    level: LintLevel,
    span: String,
    function: String,
    target: Option<String>,
    reason: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    missing_requirements: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    requirements: Vec<String>,
}

impl SafetyFindingReport {
    fn from_finding(tcx: TyCtxt<'_>, finding: SafetyFinding, level: LintLevel) -> Self {
        let kind = finding.kind();
        match finding {
            SafetyFinding::MissingSafetyDocs { def_id, span } => {
                let function = canonical_namespace(tcx, def_id);
                Self {
                    kind,
                    level,
                    span: render_span(tcx, span),
                    function: function.clone(),
                    target: None,
                    reason: format!("public unsafe function `{function}` is missing # Safety docs"),
                    missing_requirements: Vec::new(),
                    requirements: Vec::new(),
                }
            }
            SafetyFinding::CallMissingJustification {
                caller,
                callee,
                call_kind,
                span,
            } => {
                let target = safety_callee_name(tcx, callee);
                let call = safety_call_label(call_kind);
                Self {
                    kind,
                    level,
                    span: render_span(tcx, span),
                    function: canonical_namespace(tcx, caller),
                    target: Some(target.clone()),
                    reason: format!("{call} to `{target}` has no `// SAFETY:` justification"),
                    missing_requirements: Vec::new(),
                    requirements: Vec::new(),
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
                    requirements: Vec::new(),
                }
            }
            SafetyFinding::OpMissingJustification { caller, op, span } => {
                let operation = safety_op_label(op);
                Self {
                    kind,
                    level,
                    span: render_span(tcx, span),
                    function: canonical_namespace(tcx, caller),
                    target: None,
                    reason: format!(
                        "unsafe operation ({operation}) has no `// SAFETY:` justification"
                    ),
                    missing_requirements: Vec::new(),
                    requirements: Vec::new(),
                }
            }
            SafetyFinding::AmbiguousObligationName {
                def_id,
                normalized_name,
                requirements,
            } => {
                let function = canonical_namespace(tcx, def_id);
                let span = requirements
                    .first()
                    .map_or_else(|| tcx.def_span(def_id), |requirement| requirement.span);
                let requirements = requirements.iter().map(render_safety_requirement).collect();
                Self {
                    kind,
                    level,
                    span: render_span(tcx, span),
                    function: function.clone(),
                    target: None,
                    reason: format!(
                        "`{function}` has multiple # Safety requirements named `{normalized_name}`"
                    ),
                    missing_requirements: Vec::new(),
                    requirements,
                }
            }
        }
    }
}
