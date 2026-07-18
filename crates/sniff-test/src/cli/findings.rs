//! Canonical findings and the single configuration-policy boundary.

use std::path::Path;

use crate::config::{ContractDocOverrides, LintLevel, ReportRootSet, SniffTestConfig};
use crate::namespace::canonical_namespace;
use crate::panics::PanicEvidenceKind;
use crate::report_roots::{MissingReportRoot, MissingRootReason, ReportRootKind};
use crate::safety::{SafetyAnalysis, SafetyCallKind, SafetyFinding, SafetyRequirement};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;
use serde::Serialize;

use super::diagnostics::{
    empty_report_roots_diagnostic, missing_report_root_diagnostic, safety_finding_diagnostic,
};
use super::report::render_span;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Finding {
    pub(crate) kind: FindingKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) root_kind: Option<ReportRootKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) span: Option<String>,
    pub(crate) reason: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) trace: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) missing_requirements: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) requirements: Vec<String>,
    #[serde(skip)]
    pub(crate) diagnostic: FindingDiagnostic,
}

impl Finding {
    pub(crate) fn new(kind: FindingKind, reason: String, diagnostic: FindingDiagnostic) -> Self {
        Self {
            kind,
            root: None,
            root_kind: None,
            function: None,
            target: None,
            span: None,
            reason,
            trace: Vec::new(),
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
            diagnostic,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct ResolvedFinding {
    pub(crate) level: LintLevel,
    #[serde(flatten)]
    pub(crate) finding: Finding,
}

pub(crate) fn resolve_findings(
    findings: Vec<Finding>,
    config: &SniffTestConfig,
) -> Vec<ResolvedFinding> {
    findings
        .into_iter()
        .filter_map(|finding| {
            let level = finding.kind.lint_level(config);
            (!level.is_allow()).then_some(ResolvedFinding { level, finding })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingDiagnostic {
    pub(crate) span: Option<Span>,
    pub(crate) message: String,
    pub(crate) messages: Vec<DiagnosticMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DiagnosticMessage {
    Note(String),
    SpanNote(Span, String),
    SpanLabel(Span, String),
    SpanHelp(Span, &'static str),
    Help(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FindingKind {
    CompilerAssert,
    PanicInvocation,
    CachedDependencyPanic,
    DocumentedPanic,
    TrustedPanic,
    IndirectCallBoundary,
    AmbiguousPanicMarker,
    AmbiguousPanicRequirement,
    AnalysisIncomplete,
    EmptyReportRoots,
    MissingReportRoot,
    IgnoredReportRoot,
    MissingSafetyDocs,
    UnsafeCallMissingJustification,
    UnsafeCallMissingRequirements,
    UnsafeOpMissingJustification,
    SafetyObligationMissingJustification,
    SafetyObligationMissingRequirements,
    AmbiguousSafetyRequirement,
}

impl FindingKind {
    pub(crate) fn from_evidence(kind: &PanicEvidenceKind) -> Self {
        match kind {
            PanicEvidenceKind::CompilerAssert => Self::CompilerAssert,
            PanicEvidenceKind::PanicObligation { .. } => Self::DocumentedPanic,
            PanicEvidenceKind::PanicSink { .. } => Self::PanicInvocation,
            PanicEvidenceKind::IndirectBoundary { .. } => Self::IndirectCallBoundary,
        }
    }

    fn lint_level(self, config: &SniffTestConfig) -> LintLevel {
        match self {
            Self::CompilerAssert => config.panics.lints.compiler_assert,
            Self::PanicInvocation => config.panics.lints.panic_invocation,
            Self::CachedDependencyPanic => config.panics.lints.cached_dependency_panic,
            Self::DocumentedPanic => config.panics.lints.documented_panic,
            Self::TrustedPanic => config.panics.lints.trusted_panic,
            Self::IndirectCallBoundary => config.panics.lints.indirect_call_boundary,
            Self::AmbiguousPanicMarker => config.analysis.lints.ambiguous_panic_marker,
            Self::AmbiguousPanicRequirement => config.analysis.lints.ambiguous_panic_requirement,
            Self::AnalysisIncomplete => config.analysis.lints.analysis_incomplete,
            Self::EmptyReportRoots => config.analysis.lints.empty_report_roots,
            Self::MissingReportRoot => config.analysis.lints.missing_report_root,
            Self::IgnoredReportRoot => config.analysis.lints.ignored_report_root,
            Self::MissingSafetyDocs => config.safety.lints.missing_safety_docs,
            Self::UnsafeCallMissingJustification => {
                config.safety.lints.unsafe_call_missing_justification
            }
            Self::UnsafeCallMissingRequirements => {
                config.safety.lints.unsafe_call_missing_requirements
            }
            Self::UnsafeOpMissingJustification => {
                config.safety.lints.unsafe_op_missing_justification
            }
            Self::SafetyObligationMissingJustification => {
                config.safety.lints.safety_obligation_missing_justification
            }
            Self::SafetyObligationMissingRequirements => {
                config.safety.lints.safety_obligation_missing_requirements
            }
            Self::AmbiguousSafetyRequirement => config.analysis.lints.ambiguous_safety_requirement,
        }
    }
}

pub(crate) fn collect_report_root_findings(
    tcx: TyCtxt<'_>,
    manifest_path: &Path,
    empty_report_roots: bool,
    missing_roots: &[MissingReportRoot],
    report_roots: &ReportRootSet,
    crate_name: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if empty_report_roots {
        let diagnostic =
            empty_report_roots_diagnostic(tcx, manifest_path, report_roots, crate_name);
        findings.push(Finding::new(
            FindingKind::EmptyReportRoots,
            format!(
                "`[analysis].report-roots = {}` selected no functions in `{crate_name}`",
                report_roots.description()
            ),
            diagnostic,
        ));
    }
    findings.extend(missing_roots.iter().map(|root| {
        let kind = match root.reason {
            MissingRootReason::NotFound => FindingKind::MissingReportRoot,
            MissingRootReason::Ignored => FindingKind::IgnoredReportRoot,
        };
        let reason = match root.reason {
            MissingRootReason::NotFound => String::from("configured report root was not found"),
            MissingRootReason::Ignored => {
                String::from("configured report root is excluded by `[panics].ignored-namespaces`")
            }
        };
        Finding {
            target: Some(root.path.clone()),
            ..Finding::new(
                kind,
                reason,
                missing_report_root_diagnostic(tcx, manifest_path, root),
            )
        }
    }));
    findings
}

pub(crate) fn collect_safety_findings(
    tcx: TyCtxt<'_>,
    analysis: SafetyAnalysis,
    overrides: &ContractDocOverrides,
) -> Vec<Finding> {
    analysis
        .findings
        .into_iter()
        .map(|finding| safety_finding_report(tcx, finding, overrides))
        .collect()
}

#[allow(
    clippy::too_many_lines,
    reason = "keeping all finding variants together makes their output mapping easier to compare"
)]
fn safety_finding_report(
    tcx: TyCtxt<'_>,
    finding: SafetyFinding,
    overrides: &ContractDocOverrides,
) -> Finding {
    let diagnostic = safety_finding_diagnostic(tcx, &finding, overrides);
    match finding {
        SafetyFinding::MissingSafetyDocs { def_id, span } => {
            let function = canonical_namespace(tcx, def_id);
            Finding {
                function: Some(function.clone()),
                span: Some(render_span(tcx, span)),
                ..Finding::new(
                    FindingKind::MissingSafetyDocs,
                    format!("public unsafe function `{function}` is missing # Safety docs"),
                    diagnostic,
                )
            }
        }
        SafetyFinding::CallMissingJustification {
            caller,
            callee,
            call_kind,
            span,
        } => {
            let target = callee.name(tcx);
            let call = call_kind.label();
            let kind = match call_kind {
                SafetyCallKind::Unsafe => FindingKind::UnsafeCallMissingJustification,
                SafetyCallKind::ConfiguredObligation => {
                    FindingKind::SafetyObligationMissingJustification
                }
            };
            Finding {
                function: Some(canonical_namespace(tcx, caller)),
                target: Some(target.clone()),
                span: Some(render_span(tcx, span)),
                ..Finding::new(
                    kind,
                    format!("{call} to `{target}` has no `// SAFETY:` justification"),
                    diagnostic,
                )
            }
        }
        SafetyFinding::CallMissingRequirements {
            caller,
            callee,
            call_kind,
            span,
            missing_requirements,
        } => {
            let target = callee.name(tcx);
            let call = call_kind.label();
            let missing_requirements = missing_requirements
                .iter()
                .map(SafetyRequirement::render)
                .collect();
            let kind = match call_kind {
                SafetyCallKind::Unsafe => FindingKind::UnsafeCallMissingRequirements,
                SafetyCallKind::ConfiguredObligation => {
                    FindingKind::SafetyObligationMissingRequirements
                }
            };
            Finding {
                function: Some(canonical_namespace(tcx, caller)),
                target: Some(target.clone()),
                span: Some(render_span(tcx, span)),
                missing_requirements,
                ..Finding::new(
                    kind,
                    format!("{call} to `{target}` does not satisfy all # Safety requirements"),
                    diagnostic,
                )
            }
        }
        SafetyFinding::OpMissingJustification { caller, op, span } => {
            let operation = op.label();
            Finding {
                function: Some(canonical_namespace(tcx, caller)),
                span: Some(render_span(tcx, span)),
                ..Finding::new(
                    FindingKind::UnsafeOpMissingJustification,
                    format!("unsafe operation ({operation}) has no `// SAFETY:` justification"),
                    diagnostic,
                )
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
            let requirements = requirements.iter().map(SafetyRequirement::render).collect();
            Finding {
                function: Some(function.clone()),
                span: Some(render_span(tcx, span)),
                requirements,
                ..Finding::new(
                    FindingKind::AmbiguousSafetyRequirement,
                    format!(
                        "`{function}` has multiple # Safety requirements named `{normalized_name}`"
                    ),
                    diagnostic,
                )
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::{Finding, FindingDiagnostic, FindingKind, resolve_findings};
    use crate::config::{LintLevel, SniffTestConfig};

    fn finding(kind: FindingKind) -> Finding {
        Finding::new(
            kind,
            String::from("test finding"),
            FindingDiagnostic {
                span: None,
                message: String::from("test finding"),
                messages: Vec::new(),
            },
        )
    }

    #[test]
    fn resolves_policy_and_filters_allowed_findings_once() {
        let mut config = SniffTestConfig::default();
        config.panics.lints.panic_invocation = LintLevel::Allow;
        config.safety.lints.missing_safety_docs = LintLevel::Warn;
        config.analysis.lints.empty_report_roots = LintLevel::Deny;

        let resolved = resolve_findings(
            vec![
                finding(FindingKind::PanicInvocation),
                finding(FindingKind::MissingSafetyDocs),
                finding(FindingKind::EmptyReportRoots),
            ],
            &config,
        );

        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].finding.kind, FindingKind::MissingSafetyDocs);
        assert_eq!(resolved[0].level, LintLevel::Warn);
        assert_eq!(resolved[1].finding.kind, FindingKind::EmptyReportRoots);
        assert_eq!(resolved[1].level, LintLevel::Deny);
    }
}
