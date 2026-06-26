use crate::namespace::canonical_namespace;
use crate::safety::{SafetyAnalysis, SafetyFinding, render_safety_requirement, unsafe_callee_name};
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
    pub(super) fn from_analysis(tcx: TyCtxt<'_>, analysis: SafetyAnalysis) -> Option<Self> {
        let mut report = Self {
            counts: SafetyFindingCounts::default(),
            findings: Vec::new(),
        };

        for finding in analysis.findings {
            report.counts.increment(&finding);
            report
                .findings
                .push(SafetyFindingReport::from_finding(tcx, finding));
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
}

impl SafetyFindingCounts {
    fn increment(&mut self, finding: &SafetyFinding) {
        match finding {
            SafetyFinding::MissingSafetyDocs { .. } => self.missing_safety_docs += 1,
            SafetyFinding::UnsafeCallMissingJustification { .. } => {
                self.unsafe_calls_missing_justification += 1;
            }
            SafetyFinding::UnsafeCallMissingRequirements { .. } => {
                self.unsafe_calls_missing_requirements += 1;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
struct SafetyFindingReport {
    kind: SafetyFindingKindReport,
    span: String,
    function: String,
    target: Option<String>,
    reason: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    missing_requirements: Vec<String>,
}

impl SafetyFindingReport {
    fn from_finding(tcx: TyCtxt<'_>, finding: SafetyFinding) -> Self {
        match finding {
            SafetyFinding::MissingSafetyDocs { def_id, span } => {
                let function = canonical_namespace(tcx, def_id);
                Self {
                    kind: SafetyFindingKindReport::MissingSafetyDocs,
                    span: render_span(tcx, span),
                    function: function.clone(),
                    target: None,
                    reason: format!("public unsafe function `{function}` is missing # Safety docs"),
                    missing_requirements: Vec::new(),
                }
            }
            SafetyFinding::UnsafeCallMissingJustification {
                caller,
                callee,
                span,
            } => {
                let target = unsafe_callee_name(tcx, callee);
                Self {
                    kind: SafetyFindingKindReport::UnsafeCallMissingJustification,
                    span: render_span(tcx, span),
                    function: canonical_namespace(tcx, caller),
                    target: Some(target.clone()),
                    reason: format!("unsafe call to `{target}` has no `// SAFETY:` justification"),
                    missing_requirements: Vec::new(),
                }
            }
            SafetyFinding::UnsafeCallMissingRequirements {
                caller,
                callee,
                span,
                missing_requirements,
            } => {
                let target = unsafe_callee_name(tcx, callee);
                let missing_requirements = missing_requirements
                    .iter()
                    .map(render_safety_requirement)
                    .collect();
                Self {
                    kind: SafetyFindingKindReport::UnsafeCallMissingRequirements,
                    span: render_span(tcx, span),
                    function: canonical_namespace(tcx, caller),
                    target: Some(target.clone()),
                    reason: format!(
                        "unsafe call to `{target}` does not satisfy all # Safety requirements"
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
}
