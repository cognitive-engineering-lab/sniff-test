//! Canonical findings and the single lint-policy resolution boundary.

use std::path::Path;

use crate::analysis::ir::{SourceFileIr, SourceRangeIr};
use crate::config::{LintLevel, ReportRootSet, SniffTestConfig};
use crate::panics::CompilerAssertKind;
use crate::report_roots::{MissingReportRoot, ReportRootKind};
use crate::safety::SafetyOpKind;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;
use serde::Serialize;
use toml::Spanned;

use super::diagnostics::{empty_report_roots_diagnostic, missing_report_root_diagnostic};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum LintSelector {
    #[default]
    FindingKind,
    DependencyAnalysisIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Finding {
    #[serde(flatten)]
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
    pub(crate) lint_selector: LintSelector,
    #[serde(skip)]
    pub(crate) diagnostic: FindingDiagnostic,
    #[serde(skip)]
    pub(crate) source_order: Option<FindingSourceOrder>,
    #[serde(skip)]
    pub(crate) trace_order: Vec<FindingTraceStepOrder>,
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
            lint_selector: LintSelector::FindingKind,
            diagnostic,
            source_order: None,
            trace_order: Vec::new(),
        }
    }

    pub(crate) fn with_source_order(
        mut self,
        source: Option<&SourceFileIr>,
        range: Option<&SourceRangeIr>,
    ) -> Self {
        self.source_order = FindingSourceOrder::new(source, range);
        self
    }

    pub(crate) fn with_trace_order(mut self, trace_order: Vec<FindingTraceStepOrder>) -> Self {
        self.trace_order = trace_order;
        self
    }

    pub(crate) fn with_dependency_analysis_lint(mut self) -> Self {
        debug_assert!(matches!(
            self.kind,
            FindingKind::PanicAnalysisIncomplete | FindingKind::SafetyAnalysisIncomplete
        ));
        self.lint_selector = LintSelector::DependencyAnalysisIncomplete;
        self
    }

    fn lint_level(&self, config: &SniffTestConfig) -> LintLevel {
        let fallback = self.kind.lint_level(config);
        match (self.lint_selector, self.kind) {
            (LintSelector::DependencyAnalysisIncomplete, FindingKind::PanicAnalysisIncomplete) => {
                config
                    .analysis
                    .lints
                    .dependency_panic_analysis_incomplete
                    .unwrap_or(fallback)
            }
            (LintSelector::DependencyAnalysisIncomplete, FindingKind::SafetyAnalysisIncomplete) => {
                config
                    .analysis
                    .lints
                    .dependency_safety_analysis_incomplete
                    .unwrap_or(fallback)
            }
            _ => fallback,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FindingSourceOrder {
    filename: String,
    source_file: String,
    byte_start: u64,
    byte_end: u64,
}

impl FindingSourceOrder {
    fn new(source: Option<&SourceFileIr>, range: Option<&SourceRangeIr>) -> Option<Self> {
        range.map(|range| Self {
            filename: source.map_or_else(
                || range.file.as_str().to_owned(),
                |source| source.filename.clone(),
            ),
            source_file: range.file.as_str().to_owned(),
            byte_start: range.byte_start,
            byte_end: range.byte_end,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FindingTraceStepOrder {
    source: Option<FindingSourceOrder>,
    kind: (u8, u8),
    caller: String,
}

impl FindingTraceStepOrder {
    pub(crate) fn new(
        source: Option<&SourceFileIr>,
        range: Option<&SourceRangeIr>,
        kind: (u8, u8),
        caller: &str,
    ) -> Self {
        Self {
            source: FindingSourceOrder::new(source, range),
            kind,
            caller: caller.to_owned(),
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
    let mut resolved = findings
        .into_iter()
        .filter_map(|finding| {
            let level = finding.lint_level(config);
            (!level.is_allow()).then_some(ResolvedFinding { level, finding })
        })
        .collect::<Vec<_>>();
    resolved.sort_by(|left, right| compare_findings(&left.finding, &right.finding));
    resolved
}

fn compare_findings(left: &Finding, right: &Finding) -> std::cmp::Ordering {
    left.root
        .cmp(&right.root)
        .then_with(|| {
            report_root_kind_order(left.root_kind).cmp(&report_root_kind_order(right.root_kind))
        })
        .then_with(|| finding_domain_order(left.kind).cmp(&finding_domain_order(right.kind)))
        .then_with(|| left.trace_order.cmp(&right.trace_order))
        .then_with(|| left.source_order.cmp(&right.source_order))
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.function.cmp(&right.function))
        .then_with(|| left.target.cmp(&right.target))
        .then_with(|| left.span.cmp(&right.span))
        .then_with(|| left.reason.cmp(&right.reason))
        .then_with(|| left.trace.cmp(&right.trace))
        .then_with(|| left.missing_requirements.cmp(&right.missing_requirements))
        .then_with(|| left.requirements.cmp(&right.requirements))
}

const fn finding_domain_order(kind: FindingKind) -> u8 {
    match kind {
        FindingKind::CompilerAssert { .. }
        | FindingKind::PanicInvocation
        | FindingKind::DocumentedPanic
        | FindingKind::TrustedPanic
        | FindingKind::IndirectCallBoundary
        | FindingKind::AmbiguousPanicMarker
        | FindingKind::AmbiguousPanicRequirement
        | FindingKind::PanicAnalysisIncomplete => 0,
        FindingKind::AmbiguousSafetyMarker
        | FindingKind::AmbiguousSafetyRequirement
        | FindingKind::SafetyAnalysisIncomplete
        | FindingKind::MissingSafetyDocs
        | FindingKind::UnsafeCallMissingJustification
        | FindingKind::UnsafeCallMissingRequirements
        | FindingKind::UnsafeOpMissingJustification { .. }
        | FindingKind::SafetyObligationMissingJustification
        | FindingKind::SafetyObligationMissingRequirements => 1,
        FindingKind::EmptyReportRoots | FindingKind::MissingReportRoot => 2,
    }
}

const fn report_root_kind_order(kind: Option<ReportRootKind>) -> u8 {
    match kind {
        None => 0,
        Some(ReportRootKind::Concrete) => 1,
        Some(ReportRootKind::Generic) => 2,
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    tag = "kind"
)]
pub(crate) enum FindingKind {
    CompilerAssert {
        compiler_assert_kind: CompilerAssertKind,
    },
    PanicInvocation,
    DocumentedPanic,
    TrustedPanic,
    IndirectCallBoundary,
    AmbiguousPanicMarker,
    AmbiguousSafetyMarker,
    AmbiguousPanicRequirement,
    AmbiguousSafetyRequirement,
    PanicAnalysisIncomplete,
    SafetyAnalysisIncomplete,
    EmptyReportRoots,
    MissingReportRoot,
    MissingSafetyDocs,
    UnsafeCallMissingJustification,
    UnsafeCallMissingRequirements,
    UnsafeOpMissingJustification {
        safety_op_kind: SafetyOpKind,
    },
    SafetyObligationMissingJustification,
    SafetyObligationMissingRequirements,
}

impl FindingKind {
    fn lint_level(self, config: &SniffTestConfig) -> LintLevel {
        match self {
            Self::CompilerAssert {
                compiler_assert_kind,
            } => compiler_assert_lint_override(compiler_assert_kind, config)
                .unwrap_or(config.panics.lints.compiler_assert),
            Self::PanicInvocation => config.panics.lints.panic_invocation,
            Self::DocumentedPanic => config.panics.lints.documented_panic,
            Self::TrustedPanic => config.panics.lints.trusted_panic,
            Self::IndirectCallBoundary => config.panics.lints.indirect_call_boundary,
            Self::AmbiguousPanicMarker => config.analysis.lints.ambiguous_panic_marker,
            Self::AmbiguousSafetyMarker => config.analysis.lints.ambiguous_safety_marker,
            Self::AmbiguousPanicRequirement => config.analysis.lints.ambiguous_panic_requirement,
            Self::AmbiguousSafetyRequirement => config.analysis.lints.ambiguous_safety_requirement,
            Self::PanicAnalysisIncomplete => config.analysis.lints.panic_analysis_incomplete,
            Self::SafetyAnalysisIncomplete => config.analysis.lints.safety_analysis_incomplete,
            Self::EmptyReportRoots => config.analysis.lints.empty_report_roots,
            Self::MissingReportRoot => config.analysis.lints.missing_report_root,
            Self::MissingSafetyDocs => config.safety.lints.missing_safety_docs,
            Self::UnsafeCallMissingJustification => {
                config.safety.lints.unsafe_call_missing_justification
            }
            Self::UnsafeCallMissingRequirements => {
                config.safety.lints.unsafe_call_missing_requirements
            }
            Self::UnsafeOpMissingJustification { safety_op_kind } => {
                safety_op_lint_override(safety_op_kind, config)
                    .unwrap_or(config.safety.lints.unsafe_op_missing_justification)
            }
            Self::SafetyObligationMissingJustification => {
                config.safety.lints.safety_obligation_missing_justification
            }
            Self::SafetyObligationMissingRequirements => {
                config.safety.lints.safety_obligation_missing_requirements
            }
        }
    }
}

fn compiler_assert_lint_override(
    kind: CompilerAssertKind,
    config: &SniffTestConfig,
) -> Option<LintLevel> {
    let lints = &config.panics.lints;
    match kind {
        CompilerAssertKind::BoundsCheck => lints.compiler_assert_bounds_check,
        CompilerAssertKind::Overflow => lints.compiler_assert_overflow,
        CompilerAssertKind::OverflowNegation => lints.compiler_assert_overflow_negation,
        CompilerAssertKind::DivisionByZero => lints.compiler_assert_division_by_zero,
        CompilerAssertKind::RemainderByZero => lints.compiler_assert_remainder_by_zero,
        CompilerAssertKind::ResumedAfterReturn => lints.compiler_assert_resumed_after_return,
        CompilerAssertKind::ResumedAfterPanic => lints.compiler_assert_resumed_after_panic,
        CompilerAssertKind::ResumedAfterDrop => lints.compiler_assert_resumed_after_drop,
        CompilerAssertKind::MisalignedPointerDereference => {
            lints.compiler_assert_misaligned_pointer_dereference
        }
        CompilerAssertKind::NullPointerDereference => {
            lints.compiler_assert_null_pointer_dereference
        }
        CompilerAssertKind::InvalidEnumConstruction => {
            lints.compiler_assert_invalid_enum_construction
        }
    }
}

fn safety_op_lint_override(kind: SafetyOpKind, config: &SniffTestConfig) -> Option<LintLevel> {
    let lints = &config.safety.lints;
    match kind {
        SafetyOpKind::DerefRawPointer => lints.raw_pointer_dereference_missing_justification,
        SafetyOpKind::UseOfMutableStatic => lints.mutable_static_access_missing_justification,
        SafetyOpKind::UseOfExternStatic => lints.extern_static_access_missing_justification,
        SafetyOpKind::AccessToUnionField => lints.union_field_access_missing_justification,
        SafetyOpKind::UseOfUnsafeField => lints.unsafe_field_access_missing_justification,
        SafetyOpKind::InitializingLayoutConstrainedType => {
            lints.layout_constrained_type_initialization_missing_justification
        }
        SafetyOpKind::InitializingTypeWithUnsafeField => {
            lints.unsafe_field_initialization_missing_justification
        }
        SafetyOpKind::MutationOfLayoutConstrainedField => {
            lints.layout_constrained_field_mutation_missing_justification
        }
        SafetyOpKind::BorrowOfLayoutConstrainedField => {
            lints.layout_constrained_field_borrow_missing_justification
        }
        SafetyOpKind::InlineAssembly => lints.inline_assembly_missing_justification,
        SafetyOpKind::UnsafeBinderCast => lints.unsafe_binder_cast_missing_justification,
    }
}

pub(crate) fn collect_report_root_findings(
    tcx: TyCtxt<'_>,
    manifest_path: &Path,
    empty_report_roots: bool,
    missing_roots: &[MissingReportRoot],
    report_roots: &Spanned<ReportRootSet>,
    crate_name: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if empty_report_roots {
        findings.push(Finding::new(
            FindingKind::EmptyReportRoots,
            format!(
                "`[analysis].report-roots = {}` selected no functions in `{crate_name}`",
                report_roots.get_ref().description()
            ),
            empty_report_roots_diagnostic(tcx, manifest_path, report_roots, crate_name),
        ));
    }
    findings.extend(missing_roots.iter().map(|root| Finding {
        target: Some(root.path.clone()),
        ..Finding::new(
            FindingKind::MissingReportRoot,
            String::from("configured report root was not found"),
            missing_report_root_diagnostic(tcx, manifest_path, root),
        )
    }));
    findings
}

#[cfg(test)]
mod tests {
    use super::{Finding, FindingDiagnostic, FindingKind, resolve_findings};
    use crate::analysis::ir::{SourceFileId, SourceFileIr, SourceRangeIr};
    use crate::config::{LintLevel, SniffTestConfig};
    use crate::panics::CompilerAssertKind;
    use crate::safety::SafetyOpKind;

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

    fn dependency_incomplete_finding(kind: FindingKind) -> Finding {
        finding(kind).with_dependency_analysis_lint()
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
        assert_eq!(resolved[0].level, LintLevel::Warn);
        assert_eq!(resolved[1].level, LintLevel::Deny);
    }

    #[test]
    fn dependency_lint_selector_is_not_serialized() {
        let json = serde_json::to_value(dependency_incomplete_finding(
            FindingKind::PanicAnalysisIncomplete,
        ))
        .expect("serialize dependency incomplete finding");
        let object = json.as_object().expect("finding object");

        assert_eq!(object["kind"], "panic-analysis-incomplete");
        assert!(!object.contains_key("lint-selector"));
    }

    #[test]
    fn dependency_incomplete_findings_use_only_their_exact_overrides() {
        let mut config = SniffTestConfig::default();
        config.analysis.lints.panic_analysis_incomplete = LintLevel::Deny;
        config.analysis.lints.safety_analysis_incomplete = LintLevel::Warn;
        config.analysis.lints.dependency_panic_analysis_incomplete = Some(LintLevel::Warn);
        config.analysis.lints.dependency_safety_analysis_incomplete = Some(LintLevel::Allow);

        assert_eq!(
            dependency_incomplete_finding(FindingKind::PanicAnalysisIncomplete).lint_level(&config),
            LintLevel::Warn
        );
        assert_eq!(
            dependency_incomplete_finding(FindingKind::SafetyAnalysisIncomplete)
                .lint_level(&config),
            LintLevel::Allow
        );
        assert_eq!(
            finding(FindingKind::PanicAnalysisIncomplete).lint_level(&config),
            LintLevel::Deny
        );
        assert_eq!(
            finding(FindingKind::SafetyAnalysisIncomplete).lint_level(&config),
            LintLevel::Warn
        );
    }

    #[test]
    fn dependency_incomplete_findings_fall_back_to_their_effect_policy() {
        let mut config = SniffTestConfig::default();
        config.analysis.lints.panic_analysis_incomplete = LintLevel::Warn;
        config.analysis.lints.safety_analysis_incomplete = LintLevel::Allow;

        assert_eq!(
            dependency_incomplete_finding(FindingKind::PanicAnalysisIncomplete).lint_level(&config),
            LintLevel::Warn
        );
        assert_eq!(
            dependency_incomplete_finding(FindingKind::SafetyAnalysisIncomplete)
                .lint_level(&config),
            LintLevel::Allow
        );
    }

    #[test]
    fn findings_serialize_typed_subtypes_without_effect_or_dependency_origin() {
        let assert = serde_json::to_value(finding(FindingKind::CompilerAssert {
            compiler_assert_kind: CompilerAssertKind::DivisionByZero,
        }))
        .expect("serialize compiler assert");
        assert_eq!(assert["kind"], "compiler-assert");
        assert_eq!(assert["compiler-assert-kind"], "division-by-zero");
        assert!(assert.get("effect").is_none());

        let safety = serde_json::to_value(finding(FindingKind::UnsafeOpMissingJustification {
            safety_op_kind: SafetyOpKind::DerefRawPointer,
        }))
        .expect("serialize safety operation");
        assert_eq!(safety["safety-op-kind"], "raw-pointer-dereference");
    }

    #[test]
    fn exact_compiler_assert_override_wins_for_every_artifact() {
        let mut config = SniffTestConfig::default();
        config.panics.lints.compiler_assert = LintLevel::Allow;
        config.panics.lints.compiler_assert_overflow = Some(LintLevel::Warn);

        let resolved = resolve_findings(
            vec![finding(FindingKind::CompilerAssert {
                compiler_assert_kind: CompilerAssertKind::Overflow,
            })],
            &config,
        );

        assert_eq!(resolved[0].level, LintLevel::Warn);
    }

    #[test]
    fn resolved_findings_have_stable_order_regardless_of_discovery_order() {
        let config = SniffTestConfig::default();
        let source = SourceFileIr {
            id: SourceFileId::new("source-id"),
            filename: String::from("dependency/src/lib.rs"),
            content_hash: String::from("content"),
            byte_len: 200,
        };
        let trusted_range = SourceRangeIr {
            file: source.id.clone(),
            byte_start: 90,
            byte_end: 99,
        };
        let invocation_range = SourceRangeIr {
            file: source.id.clone(),
            byte_start: 100,
            byte_end: 110,
        };
        let trusted = finding(FindingKind::TrustedPanic)
            .with_source_order(Some(&source), Some(&trusted_range));
        let invocation = finding(FindingKind::PanicInvocation)
            .with_source_order(Some(&source), Some(&invocation_range));

        let forward = serde_json::to_value(resolve_findings(
            vec![trusted.clone(), invocation.clone()],
            &config,
        ))
        .expect("serialize findings");
        let reverse = serde_json::to_value(resolve_findings(vec![invocation, trusted], &config))
            .expect("serialize findings");

        assert_eq!(forward, reverse);
        assert_eq!(forward[0]["kind"], "trusted-panic");
        assert_eq!(forward[1]["kind"], "panic-invocation");
    }
}
