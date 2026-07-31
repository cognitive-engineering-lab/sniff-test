//! Canonical findings and the single configuration-policy boundary.

use std::path::Path;

use crate::cache::{CachedFinding, CachedFindingKind};
use crate::config::{LintLevel, ReportRootSet, SniffTestConfig};
use crate::contracts::ContractDocOverrides;
use crate::namespace::canonical_namespace;
use crate::panics::{CompilerAssertKind, PanicEvidenceKind};
use crate::report_roots::{MissingReportRoot, ReportRootKind};
use crate::safety::{SafetyCallKind, SafetyFinding, SafetyOpKind, SafetyRequirement};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;
use serde::Serialize;
use toml::Spanned;

use super::diagnostics::{
    empty_report_roots_diagnostic, missing_report_root_diagnostic, safety_finding_diagnostic,
};
use super::report::render_span;

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
    /// Originating effect site when it differs from the local diagnostic span.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) effect_span: Option<String>,
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
            effect_span: None,
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
#[serde(rename_all = "kebab-case", tag = "kind")]
pub(crate) enum FindingKind {
    CompilerAssert {
        #[serde(rename = "compiler-assert-kind")]
        compiler_assert_kind: CompilerAssertKind,
    },
    PanicInvocation,
    CachedDependencyPanic {
        #[serde(
            rename = "compiler-assert-kind",
            skip_serializing_if = "Option::is_none"
        )]
        compiler_assert_kind: Option<CompilerAssertKind>,
    },
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
        #[serde(rename = "safety-op-kind")]
        safety_op_kind: SafetyOpKind,
    },
    SafetyObligationMissingJustification,
    SafetyObligationMissingRequirements,
}

impl FindingKind {
    pub(crate) fn from_evidence(kind: &PanicEvidenceKind) -> Self {
        match kind {
            PanicEvidenceKind::CompilerAssert { kind } => Self::CompilerAssert {
                compiler_assert_kind: *kind,
            },
            PanicEvidenceKind::PanicObligation { .. } => Self::DocumentedPanic,
            PanicEvidenceKind::PanicSink { .. } => Self::PanicInvocation,
            PanicEvidenceKind::IndirectBoundary { .. } => Self::IndirectCallBoundary,
        }
    }

    pub(crate) fn from_cached_safety(finding: &CachedFinding) -> Option<Self> {
        match finding.kind {
            CachedFindingKind::UnsafeCallMissingJustification => {
                Some(Self::UnsafeCallMissingJustification)
            }
            CachedFindingKind::UnsafeCallMissingRequirements => {
                Some(Self::UnsafeCallMissingRequirements)
            }
            CachedFindingKind::UnsafeOpMissingJustification => {
                Some(Self::UnsafeOpMissingJustification {
                    safety_op_kind: finding
                        .safety_op_kind
                        .expect("validated cached unsafe operation must have its subtype"),
                })
            }
            CachedFindingKind::SafetyObligationMissingJustification => {
                Some(Self::SafetyObligationMissingJustification)
            }
            CachedFindingKind::SafetyObligationMissingRequirements => {
                Some(Self::SafetyObligationMissingRequirements)
            }
            CachedFindingKind::CompilerAssert
            | CachedFindingKind::PanicInvocation
            | CachedFindingKind::PanicObligation
            | CachedFindingKind::TrustedPanicObligation
            | CachedFindingKind::IndirectCallBoundary => None,
        }
    }

    fn lint_level(self, config: &SniffTestConfig) -> LintLevel {
        match self {
            Self::CompilerAssert {
                compiler_assert_kind,
            } => compiler_assert_lint_override(compiler_assert_kind, config)
                .unwrap_or(config.panics.lints.compiler_assert),
            Self::PanicInvocation => config.panics.lints.panic_invocation,
            Self::CachedDependencyPanic {
                compiler_assert_kind,
            } => compiler_assert_kind
                .and_then(|kind| compiler_assert_lint_override(kind, config))
                .unwrap_or(config.panics.lints.cached_dependency_panic),
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
        let diagnostic =
            empty_report_roots_diagnostic(tcx, manifest_path, report_roots, crate_name);
        findings.push(Finding::new(
            FindingKind::EmptyReportRoots,
            format!(
                "`[analysis].report-roots = {}` selected no functions in `{crate_name}`",
                report_roots.get_ref().description()
            ),
            diagnostic,
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

#[allow(
    clippy::too_many_lines,
    reason = "keeping all finding variants together makes their output mapping easier to compare"
)]
pub(crate) fn safety_finding_report(
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
            site,
            callee,
            call_kind,
        } => {
            let target = callee.name(tcx);
            let call = call_kind.label();
            let kind = match call_kind {
                SafetyCallKind::Unsafe => FindingKind::UnsafeCallMissingJustification,
                SafetyCallKind::Obligation => FindingKind::SafetyObligationMissingJustification,
            };
            Finding {
                function: Some(canonical_namespace(tcx, site.owner)),
                target: Some(target.clone()),
                span: Some(render_span(tcx, site.span)),
                ..Finding::new(
                    kind,
                    format!("{call} to `{target}` has no `// SAFETY:` justification"),
                    diagnostic,
                )
            }
        }
        SafetyFinding::CallMissingRequirements {
            site,
            callee,
            call_kind,
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
                SafetyCallKind::Obligation => FindingKind::SafetyObligationMissingRequirements,
            };
            Finding {
                function: Some(canonical_namespace(tcx, site.owner)),
                target: Some(target.clone()),
                span: Some(render_span(tcx, site.span)),
                missing_requirements,
                ..Finding::new(
                    kind,
                    format!("{call} to `{target}` does not satisfy all # Safety requirements"),
                    diagnostic,
                )
            }
        }
        SafetyFinding::OpMissingJustification { site, op } => {
            let operation = op.label();
            Finding {
                function: Some(canonical_namespace(tcx, site.owner)),
                span: Some(render_span(tcx, site.span)),
                ..Finding::new(
                    FindingKind::UnsafeOpMissingJustification { safety_op_kind: op },
                    format!("unsafe operation ({operation}) has no `// SAFETY:` justification"),
                    diagnostic,
                )
            }
        }
        SafetyFinding::AmbiguousObligationName {
            caller: _,
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
        SafetyFinding::AmbiguousMarker {
            caller,
            marker_span,
            effect_spans,
        } => Finding {
            function: Some(canonical_namespace(tcx, caller)),
            span: Some(render_span(tcx, marker_span)),
            ..Finding::new(
                FindingKind::AmbiguousSafetyMarker,
                format!(
                    "one `// SAFETY:` marker applies to {} safety effect groups",
                    effect_spans.len()
                ),
                diagnostic,
            )
        },
    }
}
#[cfg(test)]
mod tests {
    use super::{Finding, FindingDiagnostic, FindingKind, resolve_findings};
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

    #[test]
    fn serialized_finding_does_not_repeat_its_effect() {
        let json =
            serde_json::to_value(finding(FindingKind::PanicInvocation)).expect("serialize finding");
        let object = json.as_object().expect("finding object");

        assert_eq!(object["kind"], "panic-invocation");
        assert!(!object.contains_key("effect"));
    }

    #[test]
    fn contextual_kinds_encode_the_effect_in_the_discriminator() {
        for (kind, expected) in [
            (FindingKind::AmbiguousPanicMarker, "ambiguous-panic-marker"),
            (
                FindingKind::AmbiguousSafetyMarker,
                "ambiguous-safety-marker",
            ),
            (
                FindingKind::AmbiguousPanicRequirement,
                "ambiguous-panic-requirement",
            ),
            (
                FindingKind::AmbiguousSafetyRequirement,
                "ambiguous-safety-requirement",
            ),
            (
                FindingKind::PanicAnalysisIncomplete,
                "panic-analysis-incomplete",
            ),
            (
                FindingKind::SafetyAnalysisIncomplete,
                "safety-analysis-incomplete",
            ),
        ] {
            let json = serde_json::to_value(finding(kind)).expect("serialize finding");
            assert_eq!(json["kind"], expected);
            assert!(
                !json
                    .as_object()
                    .expect("finding object")
                    .contains_key("effect")
            );
        }
    }

    #[test]
    fn contextual_kinds_use_their_granular_analysis_lint_policy() {
        const CONTEXTUAL_KINDS: [FindingKind; 6] = [
            FindingKind::AmbiguousPanicMarker,
            FindingKind::AmbiguousSafetyMarker,
            FindingKind::AmbiguousPanicRequirement,
            FindingKind::AmbiguousSafetyRequirement,
            FindingKind::PanicAnalysisIncomplete,
            FindingKind::SafetyAnalysisIncomplete,
        ];

        type ConfigureLint = fn(&mut SniffTestConfig);
        let cases: [(FindingKind, ConfigureLint); 6] = [
            (FindingKind::AmbiguousPanicMarker, |config| {
                config.analysis.lints.ambiguous_panic_marker = LintLevel::Allow;
            }),
            (FindingKind::AmbiguousSafetyMarker, |config| {
                config.analysis.lints.ambiguous_safety_marker = LintLevel::Allow;
            }),
            (FindingKind::AmbiguousPanicRequirement, |config| {
                config.analysis.lints.ambiguous_panic_requirement = LintLevel::Allow;
            }),
            (FindingKind::AmbiguousSafetyRequirement, |config| {
                config.analysis.lints.ambiguous_safety_requirement = LintLevel::Allow;
            }),
            (FindingKind::PanicAnalysisIncomplete, |config| {
                config.analysis.lints.panic_analysis_incomplete = LintLevel::Allow;
            }),
            (FindingKind::SafetyAnalysisIncomplete, |config| {
                config.analysis.lints.safety_analysis_incomplete = LintLevel::Allow;
            }),
        ];

        for (allowed_kind, allow) in cases {
            let mut config = SniffTestConfig::default();
            allow(&mut config);

            for kind in CONTEXTUAL_KINDS {
                let expected = if kind == allowed_kind {
                    LintLevel::Allow
                } else {
                    LintLevel::Deny
                };
                assert_eq!(
                    kind.lint_level(&config),
                    expected,
                    "{kind:?} must resolve only its own granular analysis lint"
                );
            }
        }
    }

    #[test]
    fn compiler_assert_subtypes_use_only_their_exact_override() {
        type ConfigureLint = fn(&mut SniffTestConfig);
        let cases: [(CompilerAssertKind, ConfigureLint); 11] = [
            (CompilerAssertKind::BoundsCheck, |config| {
                config.panics.lints.compiler_assert_bounds_check = Some(LintLevel::Warn);
            }),
            (CompilerAssertKind::Overflow, |config| {
                config.panics.lints.compiler_assert_overflow = Some(LintLevel::Warn);
            }),
            (CompilerAssertKind::OverflowNegation, |config| {
                config.panics.lints.compiler_assert_overflow_negation = Some(LintLevel::Warn);
            }),
            (CompilerAssertKind::DivisionByZero, |config| {
                config.panics.lints.compiler_assert_division_by_zero = Some(LintLevel::Warn);
            }),
            (CompilerAssertKind::RemainderByZero, |config| {
                config.panics.lints.compiler_assert_remainder_by_zero = Some(LintLevel::Warn);
            }),
            (CompilerAssertKind::ResumedAfterReturn, |config| {
                config.panics.lints.compiler_assert_resumed_after_return = Some(LintLevel::Warn);
            }),
            (CompilerAssertKind::ResumedAfterPanic, |config| {
                config.panics.lints.compiler_assert_resumed_after_panic = Some(LintLevel::Warn);
            }),
            (CompilerAssertKind::ResumedAfterDrop, |config| {
                config.panics.lints.compiler_assert_resumed_after_drop = Some(LintLevel::Warn);
            }),
            (CompilerAssertKind::MisalignedPointerDereference, |config| {
                config
                    .panics
                    .lints
                    .compiler_assert_misaligned_pointer_dereference = Some(LintLevel::Warn);
            }),
            (CompilerAssertKind::NullPointerDereference, |config| {
                config.panics.lints.compiler_assert_null_pointer_dereference =
                    Some(LintLevel::Warn);
            }),
            (CompilerAssertKind::InvalidEnumConstruction, |config| {
                config
                    .panics
                    .lints
                    .compiler_assert_invalid_enum_construction = Some(LintLevel::Warn);
            }),
        ];

        for (kind, configure) in cases {
            let mut config = SniffTestConfig::default();
            config.panics.lints.compiler_assert = LintLevel::Allow;
            configure(&mut config);
            let finding = finding(FindingKind::CompilerAssert {
                compiler_assert_kind: kind,
            });

            assert_eq!(
                finding.kind.lint_level(&config),
                LintLevel::Warn,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn cached_compiler_assert_without_exact_override_uses_dependency_fallback() {
        let mut config = SniffTestConfig::default();
        config.panics.lints.compiler_assert = LintLevel::Deny;
        config.panics.lints.cached_dependency_panic = LintLevel::Allow;
        let finding = finding(FindingKind::CachedDependencyPanic {
            compiler_assert_kind: Some(CompilerAssertKind::DivisionByZero),
        });

        assert_eq!(finding.kind.lint_level(&config), LintLevel::Allow);
    }

    #[test]
    fn safety_op_subtypes_use_only_their_exact_override() {
        type ConfigureLint = fn(&mut SniffTestConfig);
        let cases: [(SafetyOpKind, ConfigureLint); 11] = [
            (SafetyOpKind::DerefRawPointer, |config| {
                config
                    .safety
                    .lints
                    .raw_pointer_dereference_missing_justification = Some(LintLevel::Deny);
            }),
            (SafetyOpKind::UseOfMutableStatic, |config| {
                config
                    .safety
                    .lints
                    .mutable_static_access_missing_justification = Some(LintLevel::Deny);
            }),
            (SafetyOpKind::UseOfExternStatic, |config| {
                config
                    .safety
                    .lints
                    .extern_static_access_missing_justification = Some(LintLevel::Deny);
            }),
            (SafetyOpKind::AccessToUnionField, |config| {
                config.safety.lints.union_field_access_missing_justification =
                    Some(LintLevel::Deny);
            }),
            (SafetyOpKind::UseOfUnsafeField, |config| {
                config
                    .safety
                    .lints
                    .unsafe_field_access_missing_justification = Some(LintLevel::Deny);
            }),
            (SafetyOpKind::InitializingLayoutConstrainedType, |config| {
                config
                    .safety
                    .lints
                    .layout_constrained_type_initialization_missing_justification =
                    Some(LintLevel::Deny);
            }),
            (SafetyOpKind::InitializingTypeWithUnsafeField, |config| {
                config
                    .safety
                    .lints
                    .unsafe_field_initialization_missing_justification = Some(LintLevel::Deny);
            }),
            (SafetyOpKind::MutationOfLayoutConstrainedField, |config| {
                config
                    .safety
                    .lints
                    .layout_constrained_field_mutation_missing_justification =
                    Some(LintLevel::Deny);
            }),
            (SafetyOpKind::BorrowOfLayoutConstrainedField, |config| {
                config
                    .safety
                    .lints
                    .layout_constrained_field_borrow_missing_justification = Some(LintLevel::Deny);
            }),
            (SafetyOpKind::InlineAssembly, |config| {
                config.safety.lints.inline_assembly_missing_justification = Some(LintLevel::Deny);
            }),
            (SafetyOpKind::UnsafeBinderCast, |config| {
                config.safety.lints.unsafe_binder_cast_missing_justification =
                    Some(LintLevel::Deny);
            }),
        ];

        for (kind, configure) in cases {
            let mut config = SniffTestConfig::default();
            config.safety.lints.unsafe_op_missing_justification = LintLevel::Allow;
            configure(&mut config);
            let finding = finding(FindingKind::UnsafeOpMissingJustification {
                safety_op_kind: kind,
            });

            assert_eq!(
                finding.kind.lint_level(&config),
                LintLevel::Deny,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn serialized_findings_include_flat_typed_subtypes() {
        let compiler_assert = finding(FindingKind::CompilerAssert {
            compiler_assert_kind: CompilerAssertKind::DivisionByZero,
        });
        let compiler_assert =
            serde_json::to_value(compiler_assert).expect("serialize compiler assert");
        assert_eq!(compiler_assert["compiler-assert-kind"], "division-by-zero");
        assert!(compiler_assert.get("safety-op-kind").is_none());

        let cached_compiler_assert = finding(FindingKind::CachedDependencyPanic {
            compiler_assert_kind: Some(CompilerAssertKind::BoundsCheck),
        });
        let cached_compiler_assert =
            serde_json::to_value(cached_compiler_assert).expect("serialize cached compiler assert");
        assert_eq!(cached_compiler_assert["kind"], "cached-dependency-panic");
        assert_eq!(
            cached_compiler_assert["compiler-assert-kind"],
            "bounds-check"
        );

        let safety_op = finding(FindingKind::UnsafeOpMissingJustification {
            safety_op_kind: SafetyOpKind::DerefRawPointer,
        });
        let safety_op = serde_json::to_value(safety_op).expect("serialize safety op");
        assert_eq!(safety_op["safety-op-kind"], "raw-pointer-dereference");
        assert!(safety_op.get("compiler-assert-kind").is_none());
    }
}
