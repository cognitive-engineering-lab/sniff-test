//! Canonical findings and the single lint-policy resolution boundary.

use std::collections::BTreeSet;
use std::path::Path;

use crate::artifact::{
    CompilerAssertKind, MarkerEvidenceState, SafetyOpKind, SourceFileFact, SourceRangeFact,
    UnverifiedMarkerProbeReason,
};
use crate::config::{LintLevel, ReportRootSet, SniffTestConfig};
use crate::report_model::UnresolvedCallSite;
use crate::report_roots::{MissingReportRoot, ReportRootKind};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;
use serde::Serialize;
use toml::Spanned;

use super::diagnostics::{empty_report_roots_diagnostic, missing_report_root_diagnostic};

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
    pub(crate) root_span: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) span: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) owner: Option<FindingOwner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source_evidence: Option<SourceEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) unresolved_call: Option<UnresolvedCallSite>,
    pub(crate) reason: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) trace: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) missing_requirements: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) requirements: Vec<String>,
    #[serde(skip)]
    pub(crate) diagnostic: FindingDiagnostic,
    #[serde(skip)]
    pub(crate) source_order: Option<FindingSourceOrder>,
    #[serde(skip)]
    pub(crate) trace_order: Vec<FindingTraceStepOrder>,
    #[serde(skip)]
    pub(crate) effect_span: Option<Span>,
}

impl Finding {
    pub(crate) fn new(kind: FindingKind, reason: String, diagnostic: FindingDiagnostic) -> Self {
        Self {
            kind,
            root: None,
            root_kind: None,
            root_span: None,
            function: None,
            target: None,
            span: None,
            owner: None,
            source_evidence: None,
            unresolved_call: None,
            reason,
            trace: Vec::new(),
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
            diagnostic,
            source_order: None,
            trace_order: Vec::new(),
            effect_span: None,
        }
    }

    pub(crate) fn with_source_order(
        mut self,
        source: Option<&SourceFileFact>,
        range: Option<&SourceRangeFact>,
    ) -> Self {
        self.source_order = FindingSourceOrder::new(source, range);
        self
    }

    pub(crate) fn with_trace_order(mut self, trace_order: Vec<FindingTraceStepOrder>) -> Self {
        self.trace_order = trace_order;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FindingOwner {
    pub(crate) scope: OwnerScope,
    #[serde(rename = "crate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) crate_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OwnerScope {
    Workspace,
    Dependency,
    Toolchain,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub(crate) enum SourceEvidence {
    Present,
    VerifiedAbsent,
    Unverified { reason: UnverifiedMarkerProbeReason },
}

impl From<MarkerEvidenceState> for SourceEvidence {
    fn from(evidence: MarkerEvidenceState) -> Self {
        match evidence {
            MarkerEvidenceState::Present => Self::Present,
            MarkerEvidenceState::VerifiedAbsent => Self::VerifiedAbsent,
            MarkerEvidenceState::Unverified(reason) => Self::Unverified { reason },
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
    fn new(source: Option<&SourceFileFact>, range: Option<&SourceRangeFact>) -> Option<Self> {
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
    call: u32,
    kind: (u8, u8),
    caller: String,
}

impl FindingTraceStepOrder {
    pub(crate) fn new(
        source: Option<&SourceFileFact>,
        range: Option<&SourceRangeFact>,
        call: u32,
        kind: (u8, u8),
        caller: &str,
    ) -> Self {
        Self {
            source: FindingSourceOrder::new(source, range),
            call,
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
            let level = finding.kind.lint_level(config);
            (!level.is_allow()).then_some(ResolvedFinding { level, finding })
        })
        .collect::<Vec<_>>();
    resolved.sort_by(|left, right| compare_findings(&left.finding, &right.finding));
    resolved
}

/// Normalizes source findings and collapses root-specific projections only for
/// human diagnostic emission.
///
/// The serialized report retains every root and path. Human findings always
/// use their semantic effect source as the primary location, even when only
/// one report root reaches it. Findings without a stable source identity,
/// completeness reports, and report-root diagnostics remain separate because
/// merging them could hide distinct analysis gaps.
pub(crate) fn aggregate_human_findings(findings: &[ResolvedFinding]) -> Vec<ResolvedFinding> {
    let mut groups = Vec::<(ResolvedFinding, BTreeSet<String>)>::new();
    for finding in findings {
        let matching = groups
            .iter_mut()
            .find(|(representative, _)| same_human_source(representative, finding));
        let roots = finding.finding.root.iter().cloned().collect();
        if let Some((representative, group_roots)) = matching {
            group_roots.extend(roots);
            let candidate_trace_length = finding.finding.trace.len();
            let representative_trace_length = representative.finding.trace.len();
            if candidate_trace_length < representative_trace_length
                || candidate_trace_length == representative_trace_length
                    && compare_findings(&finding.finding, &representative.finding).is_lt()
            {
                *representative = finding.clone();
            }
        } else {
            groups.push((finding.clone(), roots));
        }
    }

    groups
        .into_iter()
        .map(|(mut finding, roots)| {
            if is_source_finding(finding.finding.kind) {
                make_source_centric(&mut finding.finding);
                if roots.len() > 1 {
                    finding
                        .finding
                        .diagnostic
                        .messages
                        .retain(|message| !is_compact_reachable_note(message));
                }
                let needs_root_note = match roots.len() {
                    0 => false,
                    1 => finding.finding.trace.is_empty(),
                    _ => true,
                };
                if needs_root_note {
                    let note = DiagnosticMessage::Note(reachable_roots_note(&roots));
                    if !finding.finding.diagnostic.messages.contains(&note) {
                        finding.finding.diagnostic.messages.push(note);
                    }
                }
            }
            finding
        })
        .collect()
}

fn same_human_source(left: &ResolvedFinding, right: &ResolvedFinding) -> bool {
    is_source_finding(left.finding.kind)
        && is_source_finding(right.finding.kind)
        && left.finding.source_order.is_some()
        && left.level == right.level
        && left.finding.kind == right.finding.kind
        && left.finding.source_order == right.finding.source_order
        && left.finding.function == right.finding.function
        && left.finding.target == right.finding.target
        && left.finding.span == right.finding.span
        && left.finding.owner == right.finding.owner
        && left.finding.source_evidence == right.finding.source_evidence
        && left.finding.reason == right.finding.reason
        && left.finding.missing_requirements == right.finding.missing_requirements
        && left.finding.requirements == right.finding.requirements
}

fn make_source_centric(finding: &mut Finding) {
    finding.diagnostic.message.clone_from(&finding.reason);
    finding.diagnostic.span = finding.effect_span;
}

fn is_compact_reachable_note(message: &DiagnosticMessage) -> bool {
    matches!(message, DiagnosticMessage::Note(note) if note.starts_with("reachable from `"))
}

const fn is_source_finding(kind: FindingKind) -> bool {
    !matches!(
        kind,
        FindingKind::PanicAnalysisIncomplete
            | FindingKind::SafetyAnalysisIncomplete
            | FindingKind::UnresolvedPanicCallTarget
            | FindingKind::UnresolvedSafetyCallTarget
            | FindingKind::EmptyReportRoots
            | FindingKind::MissingReportRoot
    )
}

fn reachable_roots_note(roots: &BTreeSet<String>) -> String {
    let shown = roots
        .iter()
        .take(3)
        .map(|root| format!("`{root}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let remaining = roots.len().saturating_sub(3);
    if roots.len() == 1 {
        format!("reachable from local report root: {shown}")
    } else if remaining == 0 {
        format!("reachable from {} local report roots: {shown}", roots.len())
    } else {
        format!(
            "reachable from {} local report roots: {shown}, and {remaining} more",
            roots.len()
        )
    }
}

fn compare_findings(left: &Finding, right: &Finding) -> std::cmp::Ordering {
    left.root
        .cmp(&right.root)
        .then_with(|| {
            report_root_kind_order(left.root_kind).cmp(&report_root_kind_order(right.root_kind))
        })
        .then_with(|| left.root_span.cmp(&right.root_span))
        .then_with(|| finding_domain_order(left.kind).cmp(&finding_domain_order(right.kind)))
        .then_with(|| left.trace_order.cmp(&right.trace_order))
        .then_with(|| left.source_order.cmp(&right.source_order))
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| left.function.cmp(&right.function))
        .then_with(|| left.target.cmp(&right.target))
        .then_with(|| left.span.cmp(&right.span))
        .then_with(|| left.owner.cmp(&right.owner))
        .then_with(|| left.source_evidence.cmp(&right.source_evidence))
        .then_with(|| left.unresolved_call.cmp(&right.unresolved_call))
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
        | FindingKind::UnresolvedPanicCallTarget
        | FindingKind::AmbiguousPanicMarker
        | FindingKind::AmbiguousPanicRequirement
        | FindingKind::PanicAnalysisIncomplete => 0,
        FindingKind::AmbiguousSafetyMarker
        | FindingKind::AmbiguousSafetyRequirement
        | FindingKind::SafetyAnalysisIncomplete
        | FindingKind::MissingSafetyDocs
        | FindingKind::UnresolvedSafetyCallTarget
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
    SpanHelp(Span, String),
    Help(String),
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
    UnresolvedPanicCallTarget,
    AmbiguousPanicMarker,
    AmbiguousSafetyMarker,
    AmbiguousPanicRequirement,
    AmbiguousSafetyRequirement,
    PanicAnalysisIncomplete,
    SafetyAnalysisIncomplete,
    EmptyReportRoots,
    MissingReportRoot,
    MissingSafetyDocs,
    UnresolvedSafetyCallTarget,
    UnsafeCallMissingJustification,
    UnsafeCallMissingRequirements,
    UnsafeOpMissingJustification {
        safety_op_kind: SafetyOpKind,
    },
    SafetyObligationMissingJustification,
    SafetyObligationMissingRequirements,
}

impl FindingKind {
    pub(crate) fn lint_code(self) -> String {
        let (domain, lint) = match self {
            Self::CompilerAssert {
                compiler_assert_kind,
            } => (
                "panics",
                format!(
                    "compiler-assert-{}",
                    compiler_assert_lint_suffix(compiler_assert_kind)
                ),
            ),
            Self::PanicInvocation => ("panics", String::from("panic-invocation")),
            Self::DocumentedPanic => ("panics", String::from("documented-panic")),
            Self::UnresolvedPanicCallTarget => ("panics", String::from("unresolved-call-target")),
            Self::AmbiguousPanicMarker => ("analysis", String::from("ambiguous-panic-marker")),
            Self::AmbiguousSafetyMarker => ("analysis", String::from("ambiguous-safety-marker")),
            Self::AmbiguousPanicRequirement => {
                ("analysis", String::from("ambiguous-panic-requirement"))
            }
            Self::AmbiguousSafetyRequirement => {
                ("analysis", String::from("ambiguous-safety-requirement"))
            }
            Self::PanicAnalysisIncomplete => {
                ("analysis", String::from("panic-analysis-incomplete"))
            }
            Self::SafetyAnalysisIncomplete => {
                ("analysis", String::from("safety-analysis-incomplete"))
            }
            Self::EmptyReportRoots => ("analysis", String::from("empty-report-roots")),
            Self::MissingReportRoot => ("analysis", String::from("missing-report-root")),
            Self::MissingSafetyDocs => ("safety", String::from("missing-safety-docs")),
            Self::UnresolvedSafetyCallTarget => ("safety", String::from("unresolved-call-target")),
            Self::UnsafeCallMissingJustification => {
                ("safety", String::from("unsafe-call-missing-justification"))
            }
            Self::UnsafeCallMissingRequirements => {
                ("safety", String::from("unsafe-call-missing-requirements"))
            }
            Self::UnsafeOpMissingJustification { safety_op_kind } => (
                "safety",
                format!(
                    "{}-missing-justification",
                    safety_op_lint_suffix(safety_op_kind)
                ),
            ),
            Self::SafetyObligationMissingJustification => (
                "safety",
                String::from("safety-obligation-missing-justification"),
            ),
            Self::SafetyObligationMissingRequirements => (
                "safety",
                String::from("safety-obligation-missing-requirements"),
            ),
        };
        format!("sniff-test::{domain}::{lint}")
    }

    fn lint_level(self, config: &SniffTestConfig) -> LintLevel {
        match self {
            Self::CompilerAssert {
                compiler_assert_kind,
            } => compiler_assert_lint_override(compiler_assert_kind, config)
                .unwrap_or(config.panics.lints.compiler_assert),
            Self::PanicInvocation => config.panics.lints.panic_invocation,
            Self::DocumentedPanic => config.panics.lints.documented_panic,
            Self::UnresolvedPanicCallTarget => config.panics.lints.unresolved_call_target,
            Self::AmbiguousPanicMarker => config.analysis.lints.ambiguous_panic_marker,
            Self::AmbiguousSafetyMarker => config.analysis.lints.ambiguous_safety_marker,
            Self::AmbiguousPanicRequirement => config.analysis.lints.ambiguous_panic_requirement,
            Self::AmbiguousSafetyRequirement => config.analysis.lints.ambiguous_safety_requirement,
            Self::PanicAnalysisIncomplete => config.analysis.lints.panic_analysis_incomplete,
            Self::SafetyAnalysisIncomplete => config.analysis.lints.safety_analysis_incomplete,
            Self::EmptyReportRoots => config.analysis.lints.empty_report_roots,
            Self::MissingReportRoot => config.analysis.lints.missing_report_root,
            Self::MissingSafetyDocs => config.safety.lints.missing_safety_docs,
            Self::UnresolvedSafetyCallTarget => config.safety.lints.unresolved_call_target,
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

const fn compiler_assert_lint_suffix(kind: CompilerAssertKind) -> &'static str {
    match kind {
        CompilerAssertKind::BoundsCheck => "bounds-check",
        CompilerAssertKind::Overflow => "overflow",
        CompilerAssertKind::OverflowNegation => "overflow-negation",
        CompilerAssertKind::DivisionByZero => "division-by-zero",
        CompilerAssertKind::RemainderByZero => "remainder-by-zero",
        CompilerAssertKind::ResumedAfterReturn => "resumed-after-return",
        CompilerAssertKind::ResumedAfterPanic => "resumed-after-panic",
        CompilerAssertKind::ResumedAfterDrop => "resumed-after-drop",
        CompilerAssertKind::MisalignedPointerDereference => "misaligned-pointer-dereference",
        CompilerAssertKind::NullPointerDereference => "null-pointer-dereference",
        CompilerAssertKind::InvalidEnumConstruction => "invalid-enum-construction",
    }
}

const fn safety_op_lint_suffix(kind: SafetyOpKind) -> &'static str {
    match kind {
        SafetyOpKind::DerefRawPointer => "raw-pointer-dereference",
        SafetyOpKind::UseOfMutableStatic => "mutable-static-access",
        SafetyOpKind::UseOfExternStatic => "extern-static-access",
        SafetyOpKind::AccessToUnionField => "union-field-access",
        SafetyOpKind::UseOfUnsafeField => "unsafe-field-access",
        SafetyOpKind::InitializingLayoutConstrainedType => "layout-constrained-type-initialization",
        SafetyOpKind::InitializingTypeWithUnsafeField => "unsafe-field-initialization",
        SafetyOpKind::MutationOfLayoutConstrainedField => "layout-constrained-field-mutation",
        SafetyOpKind::BorrowOfLayoutConstrainedField => "layout-constrained-field-borrow",
        SafetyOpKind::InlineAssembly => "inline-assembly",
        SafetyOpKind::UnsafeBinderCast => "unsafe-binder-cast",
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
    use super::{
        DiagnosticMessage, Finding, FindingDiagnostic, FindingKind, FindingOwner, OwnerScope,
        ResolvedFinding, SourceEvidence, aggregate_human_findings, is_compact_reachable_note,
        resolve_findings,
    };
    use crate::artifact::{
        CompilerAssertKind, SafetyOpKind, SourceFileFact, SourceFileId, SourceRangeFact,
        UnverifiedMarkerProbeReason,
    };
    use crate::config::{LintLevel, SniffTestConfig};
    use crate::report_model::{
        UnresolvedCallCoverage, UnresolvedCallMechanism, UnresolvedCallSite,
    };
    use rustc_span::{BytePos, Span};

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
                finding(FindingKind::UnresolvedPanicCallTarget),
                finding(FindingKind::UnresolvedSafetyCallTarget),
            ],
            &config,
        );

        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].level, LintLevel::Warn);
        assert_eq!(resolved[1].level, LintLevel::Deny);
    }

    #[test]
    fn safety_contracts_use_ordinary_obligation_policy() {
        let mut config = SniffTestConfig::default();
        config.safety.lints.safety_obligation_missing_requirements = LintLevel::Deny;
        let obligation = finding(FindingKind::SafetyObligationMissingRequirements);

        let resolved = resolve_findings(vec![obligation], &config);
        let [remaining] = resolved.as_slice() else {
            panic!("the safety obligation should use its ordinary lint policy");
        };
        assert_eq!(
            remaining.finding.kind,
            FindingKind::SafetyObligationMissingRequirements
        );
        assert_eq!(remaining.level, LintLevel::Deny);
    }

    #[test]
    fn incomplete_findings_use_their_effect_policy() {
        let mut config = SniffTestConfig::default();
        config.analysis.lints.panic_analysis_incomplete = LintLevel::Warn;
        config.analysis.lints.safety_analysis_incomplete = LintLevel::Allow;

        let resolved = resolve_findings(
            vec![
                finding(FindingKind::PanicAnalysisIncomplete),
                finding(FindingKind::SafetyAnalysisIncomplete),
            ],
            &config,
        );

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].level, LintLevel::Warn);
        assert_eq!(
            resolved[0].finding.kind,
            FindingKind::PanicAnalysisIncomplete
        );
    }

    #[test]
    fn findings_serialize_their_public_semantic_fields() {
        let mut compiler_assert = finding(FindingKind::CompilerAssert {
            compiler_assert_kind: CompilerAssertKind::DivisionByZero,
        });
        compiler_assert.owner = Some(FindingOwner {
            scope: OwnerScope::Dependency,
            crate_name: Some(String::from("example-dependency")),
        });
        compiler_assert.source_evidence = Some(SourceEvidence::Unverified {
            reason: UnverifiedMarkerProbeReason::SourceUnavailable,
        });
        let assert = serde_json::to_value(compiler_assert).expect("serialize compiler assert");
        assert_eq!(
            assert,
            serde_json::json!({
                "kind": "compiler-assert",
                "compiler-assert-kind": "division-by-zero",
                "owner": {
                    "scope": "dependency",
                    "crate": "example-dependency",
                },
                "source-evidence": {
                    "status": "unverified",
                    "reason": "source-unavailable",
                },
                "reason": "test finding",
            })
        );

        let mut unknown_owner = finding(FindingKind::PanicInvocation);
        unknown_owner.owner = Some(FindingOwner {
            scope: OwnerScope::Unknown,
            crate_name: None,
        });
        let unknown_owner =
            serde_json::to_value(unknown_owner).expect("serialize unknown source owner");
        assert_eq!(
            unknown_owner["owner"],
            serde_json::json!({ "scope": "unknown" })
        );

        let safety = serde_json::to_value(finding(FindingKind::UnsafeOpMissingJustification {
            safety_op_kind: SafetyOpKind::DerefRawPointer,
        }))
        .expect("serialize safety operation");
        assert_eq!(
            safety,
            serde_json::json!({
                "kind": "unsafe-op-missing-justification",
                "safety-op-kind": "raw-pointer-dereference",
                "reason": "test finding",
            })
        );

        for (kind, expected) in [
            (
                FindingKind::UnresolvedPanicCallTarget,
                "unresolved-panic-call-target",
            ),
            (
                FindingKind::UnresolvedSafetyCallTarget,
                "unresolved-safety-call-target",
            ),
        ] {
            let serialized = serde_json::to_value(finding(kind)).expect("serialize target finding");
            assert_eq!(serialized["kind"], expected);
        }

        let mut unresolved = finding(FindingKind::UnresolvedPanicCallTarget);
        unresolved.unresolved_call = Some(UnresolvedCallSite {
            coverage: UnresolvedCallCoverage::Partial,
            mechanism: UnresolvedCallMechanism::DynamicDispatch,
        });
        assert_eq!(
            serde_json::to_value(unresolved).expect("serialize unresolved call")["unresolved-call"],
            serde_json::json!({
                "coverage": "partial",
                "mechanism": "dynamic-dispatch",
            })
        );
    }

    #[test]
    fn finding_kinds_expose_exact_domain_qualified_lint_codes() {
        assert_eq!(
            FindingKind::CompilerAssert {
                compiler_assert_kind: CompilerAssertKind::DivisionByZero,
            }
            .lint_code(),
            "sniff-test::panics::compiler-assert-division-by-zero"
        );
        assert_eq!(
            FindingKind::UnsafeOpMissingJustification {
                safety_op_kind: SafetyOpKind::DerefRawPointer,
            }
            .lint_code(),
            "sniff-test::safety::raw-pointer-dereference-missing-justification"
        );
        assert_eq!(
            FindingKind::UnresolvedSafetyCallTarget.lint_code(),
            "sniff-test::safety::unresolved-call-target"
        );
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
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("dependency/src/lib.rs"),
            content_hash: String::from("content"),
            byte_len: 200,
        };
        let documented_range = SourceRangeFact {
            file: source.id.clone(),
            byte_start: 90,
            byte_end: 99,
        };
        let invocation_range = SourceRangeFact {
            file: source.id.clone(),
            byte_start: 100,
            byte_end: 110,
        };
        let documented = finding(FindingKind::DocumentedPanic)
            .with_source_order(Some(&source), Some(&documented_range));
        let invocation = finding(FindingKind::PanicInvocation)
            .with_source_order(Some(&source), Some(&invocation_range));

        let forward = serde_json::to_value(resolve_findings(
            vec![documented.clone(), invocation.clone()],
            &config,
        ))
        .expect("serialize findings");
        let reverse = serde_json::to_value(resolve_findings(vec![invocation, documented], &config))
            .expect("serialize findings");

        assert_eq!(forward, reverse);
        assert_eq!(forward[0]["kind"], "documented-panic");
        assert_eq!(forward[1]["kind"], "panic-invocation");
    }

    #[test]
    fn human_findings_aggregate_root_paths_at_one_effect_source() {
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("dependency/src/lib.rs"),
            content_hash: String::from("content"),
            byte_len: 200,
        };
        let range = SourceRangeFact {
            file: source.id.clone(),
            byte_start: 40,
            byte_end: 50,
        };
        let effect_span = Span::with_root_ctxt(BytePos(40), BytePos(50));
        let root_span = Span::with_root_ctxt(BytePos(100), BytePos(120));
        let at_root = |root: &str, trace: &[&str]| {
            let mut finding = finding(FindingKind::PanicInvocation)
                .with_source_order(Some(&source), Some(&range));
            finding.root = Some(root.to_owned());
            finding.trace = trace.iter().map(|step| (*step).to_owned()).collect();
            finding.diagnostic.message = format!("representative for {root}");
            finding.diagnostic.span = Some(root_span);
            finding
                .diagnostic
                .messages
                .push(DiagnosticMessage::Note(format!(
                    "reachable from `{root}` to `core::panicking::panic_fmt`"
                )));
            finding.effect_span = Some(effect_span);
            finding.target = Some(String::from("core::panicking::panic_fmt"));
            finding.reason = String::from(
                "panic invocation to `core::panicking::panic_fmt` is reachable through undocumented panic paths",
            );
            ResolvedFinding {
                level: LintLevel::Deny,
                finding,
            }
        };
        let long = at_root("sample::first", &["one", "two"]);
        let short = at_root("sample::second", &["one"]);

        let aggregated = aggregate_human_findings(&[long, short]);

        assert_eq!(aggregated.len(), 1);
        assert_eq!(
            aggregated[0].finding.diagnostic.message,
            "panic invocation to `core::panicking::panic_fmt` is reachable through undocumented panic paths"
        );
        assert_eq!(aggregated[0].finding.diagnostic.span, Some(effect_span));
        assert!(aggregated[0].finding.diagnostic.messages.iter().any(
            |message| matches!(message, DiagnosticMessage::Note(note) if note ==
                "reachable from 2 local report roots: `sample::first`, `sample::second`")
        ));
        assert!(
            !aggregated[0]
                .finding
                .diagnostic
                .messages
                .iter()
                .any(is_compact_reachable_note)
        );
    }

    #[test]
    fn human_single_root_source_finding_is_source_centric_without_changing_json() {
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("content"),
            byte_len: 200,
        };
        let range = SourceRangeFact {
            file: source.id.clone(),
            byte_start: 40,
            byte_end: 50,
        };
        let effect_span = Span::with_root_ctxt(BytePos(40), BytePos(50));
        let root_span = Span::with_root_ctxt(BytePos(100), BytePos(120));
        let mut finding =
            finding(FindingKind::PanicInvocation).with_source_order(Some(&source), Some(&range));
        finding.root = Some(String::from("sample::api"));
        finding.diagnostic.message =
            String::from("function `sample::api` has an undocumented panic path");
        finding.diagnostic.span = Some(root_span);
        finding.trace = vec![String::from(
            "sample::api --direct-call-> core::panicking::panic_fmt",
        )];
        finding
            .diagnostic
            .messages
            .push(DiagnosticMessage::Note(String::from(
                "reachable from `sample::api` to `core::panicking::panic_fmt`",
            )));
        finding.effect_span = Some(effect_span);
        finding.target = Some(String::from("core::panicking::panic_fmt"));
        finding.reason = String::from(
            "panic invocation to `core::panicking::panic_fmt` is reachable through undocumented panic paths",
        );
        let resolved = ResolvedFinding {
            level: LintLevel::Deny,
            finding,
        };
        let serialized = serde_json::to_value(&resolved).expect("serialize source finding");

        let aggregated = aggregate_human_findings(std::slice::from_ref(&resolved));

        assert_eq!(aggregated.len(), 1);
        assert_eq!(
            aggregated[0].finding.diagnostic.message,
            "panic invocation to `core::panicking::panic_fmt` is reachable through undocumented panic paths"
        );
        assert_eq!(aggregated[0].finding.diagnostic.span, Some(effect_span));
        assert_eq!(
            aggregated[0]
                .finding
                .diagnostic
                .messages
                .iter()
                .filter(|message| matches!(message, DiagnosticMessage::Note(note) if
                    note.contains("`sample::api`")))
                .count(),
            1
        );
        assert_eq!(
            serde_json::to_value(&aggregated[0]).expect("serialize human finding"),
            serialized
        );
    }

    #[test]
    fn human_source_finding_without_displayable_source_has_no_primary_span() {
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("dependency/src/lib.rs"),
            content_hash: String::from("content"),
            byte_len: 200,
        };
        let range = SourceRangeFact {
            file: source.id.clone(),
            byte_start: 40,
            byte_end: 50,
        };
        let root_span = Span::with_root_ctxt(BytePos(100), BytePos(120));
        let mut finding =
            finding(FindingKind::PanicInvocation).with_source_order(Some(&source), Some(&range));
        finding.root = Some(String::from("sample::api"));
        finding.diagnostic.span = Some(root_span);
        finding.effect_span = None;
        let resolved = ResolvedFinding {
            level: LintLevel::Deny,
            finding,
        };

        let aggregated = aggregate_human_findings(&[resolved]);

        assert_eq!(aggregated[0].finding.diagnostic.span, None);
        assert_eq!(
            aggregated[0].finding.diagnostic.messages,
            [DiagnosticMessage::Note(String::from(
                "reachable from local report root: `sample::api`"
            ))]
        );
    }

    #[test]
    fn human_findings_leave_non_source_diagnostics_unchanged() {
        let root_span = Span::with_root_ctxt(BytePos(100), BytePos(120));
        let at_root = |kind| {
            let mut finding = finding(kind);
            finding.root = Some(String::from("sample::api"));
            finding.diagnostic.message = String::from("original diagnostic");
            finding.diagnostic.span = Some(root_span);
            ResolvedFinding {
                level: LintLevel::Warn,
                finding,
            }
        };
        let resolved = [
            at_root(FindingKind::PanicAnalysisIncomplete),
            at_root(FindingKind::EmptyReportRoots),
            at_root(FindingKind::MissingReportRoot),
        ];

        let aggregated = aggregate_human_findings(&resolved);

        assert_eq!(aggregated, resolved);
    }

    #[test]
    fn human_findings_keep_distinct_unresolved_target_coverage() {
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("content"),
            byte_len: 200,
        };
        let range = SourceRangeFact {
            file: source.id.clone(),
            byte_start: 40,
            byte_end: 50,
        };
        let effect_span = Span::with_root_ctxt(BytePos(40), BytePos(50));
        let at_root = |root: &str, root_span: Span| {
            let mut finding = finding(FindingKind::UnresolvedSafetyCallTarget)
                .with_source_order(Some(&source), Some(&range));
            finding.root = Some(root.to_owned());
            finding.diagnostic.message = format!("coverage gap from `{root}`");
            finding.diagnostic.span = Some(root_span);
            finding.effect_span = Some(effect_span);
            ResolvedFinding {
                level: LintLevel::Warn,
                finding,
            }
        };
        let resolved = [
            at_root(
                "sample::first_root",
                Span::with_root_ctxt(BytePos(100), BytePos(110)),
            ),
            at_root(
                "sample::second_root",
                Span::with_root_ctxt(BytePos(120), BytePos(130)),
            ),
        ];

        let aggregated = aggregate_human_findings(&resolved);

        assert_eq!(aggregated, resolved);
    }

    #[test]
    fn human_findings_do_not_merge_distinct_obligation_states_or_limit_reports() {
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("src/lib.rs"),
            content_hash: String::from("content"),
            byte_len: 200,
        };
        let range = SourceRangeFact {
            file: source.id.clone(),
            byte_start: 40,
            byte_end: 50,
        };
        let mut missing_first = finding(FindingKind::SafetyObligationMissingRequirements)
            .with_source_order(Some(&source), Some(&range));
        missing_first.missing_requirements = vec![String::from("initialized")];
        let mut missing_second = finding(FindingKind::SafetyObligationMissingRequirements)
            .with_source_order(Some(&source), Some(&range));
        missing_second.missing_requirements = vec![String::from("exclusive")];
        let incomplete = finding(FindingKind::SafetyAnalysisIncomplete);
        let resolved = [
            missing_first,
            missing_second,
            incomplete.clone(),
            incomplete,
        ]
        .into_iter()
        .map(|finding| ResolvedFinding {
            level: LintLevel::Warn,
            finding,
        })
        .collect::<Vec<_>>();

        assert_eq!(aggregate_human_findings(&resolved).len(), 4);
    }

    #[test]
    fn human_findings_do_not_merge_distinct_owner_or_source_evidence() {
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("dependency/src/lib.rs"),
            content_hash: String::from("content"),
            byte_len: 200,
        };
        let range = SourceRangeFact {
            file: source.id.clone(),
            byte_start: 40,
            byte_end: 50,
        };
        let base =
            finding(FindingKind::PanicInvocation).with_source_order(Some(&source), Some(&range));
        let with = |scope, evidence| {
            let mut finding = base.clone();
            finding.owner = Some(FindingOwner {
                scope,
                crate_name: Some(String::from("shared")),
            });
            finding.source_evidence = Some(evidence);
            ResolvedFinding {
                level: LintLevel::Warn,
                finding,
            }
        };
        let resolved = [
            with(OwnerScope::Workspace, SourceEvidence::VerifiedAbsent),
            with(OwnerScope::Dependency, SourceEvidence::VerifiedAbsent),
            with(OwnerScope::Workspace, SourceEvidence::Present),
        ];

        assert_eq!(aggregate_human_findings(&resolved).len(), 3);
    }
}
