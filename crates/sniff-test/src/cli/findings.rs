//! Canonical findings and the single lint-policy resolution boundary.

use std::collections::BTreeSet;
use std::path::Path;

use crate::artifact::{
    EffectKey, MarkerEvidenceState, SourceFileFact, SourceRangeFact, UnverifiedMarkerProbeReason,
};
use crate::config::{LintLevel, ReportRootSet, SniffTestConfig};
use crate::report_model::{EffectFindingClass, UnresolvedCallSite};
use crate::report_roots::{MissingReportRoot, ReportRootKind};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;
use serde::Serialize;
use toml::Spanned;

use super::diagnostics::{empty_report_roots_diagnostic, missing_report_root_diagnostic};

pub(super) const FULL_STACK_TRACE_HINT: &str = "set `show-full-stack-trace = true` under `[analysis]` in sniff-test.toml to show every reachability step";

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
    #[serde(skip)]
    pub(crate) local_boundary_span: Option<Span>,
    #[serde(skip)]
    pub(crate) justification_marker: Option<String>,
    #[serde(skip)]
    pub(crate) effect_display: Option<String>,
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
            local_boundary_span: None,
            justification_marker: None,
            effect_display: None,
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

/// Normalizes source findings for human diagnostic emission. Repeated paths
/// from one report root are collapsed only when their canonical traces match,
/// while distinct paths and workspace- or dependency-owned report roots retain
/// separate diagnostics.
///
/// The serialized report retains every root and path. Human findings always
/// use their semantic effect source as the primary location for local effects.
/// Dependency findings with a reachable local call use that call as the
/// primary location. Findings without a stable source identity,
/// completeness reports, and report-root diagnostics remain separate because
/// merging them could hide distinct analysis gaps.
pub(crate) fn aggregate_human_findings(findings: &[ResolvedFinding]) -> Vec<ResolvedFinding> {
    let mut groups = Vec::<(ResolvedFinding, BTreeSet<String>, BTreeSet<String>)>::new();
    for finding in findings {
        let matching = groups
            .iter_mut()
            .find(|(representative, _, _)| same_human_source(representative, finding));
        let roots = finding.finding.root.iter().cloned().collect();
        let roots_without_trace = finding
            .finding
            .root
            .iter()
            .filter(|_| finding.finding.trace.is_empty())
            .cloned()
            .collect();
        if let Some((representative, group_roots, group_roots_without_trace)) = matching {
            group_roots.extend(roots);
            group_roots_without_trace.extend(roots_without_trace);
            let mut messages = representative.finding.diagnostic.messages.clone();
            extend_unique_messages(&mut messages, &finding.finding.diagnostic.messages);
            let candidate_trace_length = finding.finding.trace.len();
            let representative_trace_length = representative.finding.trace.len();
            if candidate_trace_length < representative_trace_length
                || candidate_trace_length == representative_trace_length
                    && compare_findings(&finding.finding, &representative.finding).is_lt()
            {
                *representative = finding.clone();
            }
            representative.finding.diagnostic.messages = messages;
        } else {
            groups.push((finding.clone(), roots, roots_without_trace));
        }
    }

    groups
        .into_iter()
        .map(|(mut finding, roots, roots_without_trace)| {
            if is_source_finding(&finding.finding.kind) {
                let has_local_primary = place_source_diagnostic(&mut finding.finding);
                let has_reachability_note =
                    combine_root_reachability_note(&mut finding.finding, &roots);
                compact_human_diagnostic_paths(&mut finding.finding, &roots);
                let root_labels = shortest_distinguishing_root_labels(&roots);
                for (_, root) in roots.iter().zip(root_labels).filter(|(root, _)| {
                    !has_local_primary
                        && !has_reachability_note
                        && roots_without_trace.contains(*root)
                }) {
                    let note = DiagnosticMessage::Note(format!(
                        "reachable from local report root: `{root}`"
                    ));
                    if !finding.finding.diagnostic.messages.contains(&note) {
                        finding.finding.diagnostic.messages.push(note);
                    }
                }
                if finding.finding.owner.as_ref().is_some_and(|owner| {
                    matches!(owner.scope, OwnerScope::Workspace | OwnerScope::Dependency)
                }) {
                    // Preserve the order within each group while presenting local
                    // actions before contract and reachability context.
                    finding.finding.diagnostic.messages.sort_by_key(|message| {
                        !matches!(
                            message,
                            DiagnosticMessage::Help(_)
                                | DiagnosticMessage::AlternativeHelp(_)
                                | DiagnosticMessage::SpanAlternativeHelp(_, _)
                        )
                    });
                }
            }
            finding
        })
        .collect()
}

fn extend_unique_messages(messages: &mut Vec<DiagnosticMessage>, additional: &[DiagnosticMessage]) {
    for message in additional {
        if !messages.contains(message) {
            messages.push(message.clone());
        }
    }
}

fn combine_root_reachability_note(finding: &mut Finding, roots: &BTreeSet<String>) -> bool {
    if roots.len() < 2 {
        return finding
            .diagnostic
            .messages
            .iter()
            .any(is_compact_reachability_note);
    }
    let mut insertion = None;
    let mut destination = None;
    let mut retained = Vec::with_capacity(finding.diagnostic.messages.len());
    for message in finding.diagnostic.messages.drain(..) {
        if is_compact_reachability_note(&message) {
            insertion.get_or_insert(retained.len());
            if let DiagnosticMessage::Note(note) = &message {
                destination = destination.or_else(|| {
                    note.split_once(" to ")
                        .map(|(_, destination)| destination.to_owned())
                });
            }
        } else {
            retained.push(message);
        }
    }
    let Some(insertion) = insertion else {
        finding.diagnostic.messages = retained;
        return false;
    };
    let roots = shortest_distinguishing_root_labels(roots)
        .into_iter()
        .map(|root| format!("`{root}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let destination = destination.unwrap_or_else(|| String::from("the effect source"));
    retained.insert(
        insertion,
        DiagnosticMessage::Note(format!("reachable from {roots} to {destination}")),
    );
    finding.diagnostic.messages = retained;
    true
}

fn is_compact_reachability_note(message: &DiagnosticMessage) -> bool {
    matches!(message, DiagnosticMessage::Note(note) if note.starts_with("reachable from `"))
}

/// Removes per-finding stack trace hints so the caller can emit one footer after
/// all human diagnostics.
pub(crate) fn take_full_stack_trace_hint(findings: &mut [ResolvedFinding]) -> bool {
    let mut removed = false;
    for finding in findings {
        finding.finding.diagnostic.messages.retain(|message| {
            let is_hint =
                matches!(message, DiagnosticMessage::Note(note) if note == FULL_STACK_TRACE_HINT);
            removed |= is_hint;
            !is_hint
        });
    }
    removed
}

fn same_human_source(left: &ResolvedFinding, right: &ResolvedFinding) -> bool {
    is_source_finding(&left.finding.kind)
        && is_source_finding(&right.finding.kind)
        && left.finding.source_order.is_some()
        && left.level == right.level
        && left.finding.kind == right.finding.kind
        && left.finding.source_order == right.finding.source_order
        && left.finding.function == right.finding.function
        && left.finding.target == right.finding.target
        && left.finding.span == right.finding.span
        && left.finding.owner == right.finding.owner
        && (left.finding.owner.as_ref().is_none_or(|owner| {
            !matches!(owner.scope, OwnerScope::Workspace | OwnerScope::Dependency)
        }) || left.finding.root == right.finding.root)
        && left.finding.source_evidence == right.finding.source_evidence
        && left.finding.reason == right.finding.reason
        && left.finding.trace_order == right.finding.trace_order
        && left.finding.missing_requirements == right.finding.missing_requirements
        && left.finding.requirements == right.finding.requirements
}

fn place_source_diagnostic(finding: &mut Finding) -> bool {
    let destination = finding
        .target
        .as_deref()
        .map(|target| format!("`{target}`"))
        .or_else(|| finding.effect_display.clone());
    if let (
        Some(FindingOwner {
            scope: OwnerScope::Dependency,
            crate_name: Some(crate_name),
        }),
        Some(root),
        Some(destination),
        Some(local_span),
    ) = (
        finding.owner.as_ref(),
        finding.root.as_deref(),
        destination,
        finding.local_boundary_span,
    ) {
        let missing_marker = (finding.source_evidence == Some(SourceEvidence::VerifiedAbsent))
            .then(|| finding.justification_marker.as_deref())
            .flatten();
        finding.diagnostic.message = format!(
            "`{root}` can reach {destination} with effect obligation in dependency crate `{crate_name}`."
        );
        finding.diagnostic.span = Some(local_span);
        finding.diagnostic.second_primary_span =
            finding.effect_span.filter(|span| *span != local_span);
        finding
            .diagnostic
            .messages
            .retain(|message| !is_compact_reachability_note(message));
        let source_note = missing_marker.map_or_else(
            || finding.reason.clone(),
            |marker| format!("no recorded `// {marker}:` justification"),
        );
        let source_note = match finding.effect_span {
            Some(span) => DiagnosticMessage::SpanLabel(span, source_note),
            None => DiagnosticMessage::Note(source_note),
        };
        finding.diagnostic.messages.insert(0, source_note);
        return true;
    }
    finding.diagnostic.message.clone_from(&finding.reason);
    finding.diagnostic.span = finding.effect_span;
    false
}

fn compact_human_diagnostic_paths(finding: &mut Finding, roots: &BTreeSet<String>) {
    let root_labels = shortest_distinguishing_root_labels(roots);
    let mut paths = roots
        .iter()
        .zip(root_labels)
        .filter(|(path, compact)| path.as_str() != compact)
        .map(|(path, compact)| (path.clone(), compact))
        .collect::<Vec<_>>();
    paths.extend(
        finding
            .target
            .iter()
            .chain(finding.function.iter())
            .filter(|path| !roots.contains(*path))
            .map(|path| (path.clone(), compact_function_name(path).to_owned()))
            .filter(|(path, compact)| path != compact),
    );

    compact_quoted_paths(&mut finding.diagnostic.message, &paths);
    for message in &mut finding.diagnostic.messages {
        let text = match message {
            DiagnosticMessage::Note(text)
            | DiagnosticMessage::SpanNote(_, text)
            | DiagnosticMessage::SpanLabel(_, text)
            | DiagnosticMessage::Help(text)
            | DiagnosticMessage::AlternativeHelp(text)
            | DiagnosticMessage::SpanAlternativeHelp(_, text) => text,
        };
        if text.starts_with("effect trace step ") {
            continue;
        }
        compact_quoted_paths(text, &paths);
    }
}

fn compact_quoted_paths(text: &mut String, paths: &[(String, String)]) {
    for (path, compact) in paths {
        *text = text.replace(&format!("`{path}`"), &format!("`{compact}`"));
    }
}

pub(super) fn compact_function_name(path: &str) -> &str {
    top_level_path_segments(path)
        .last()
        .copied()
        .unwrap_or(path)
}

fn top_level_path_segments(path: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut angle_depth = 0_u32;
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'<' => angle_depth += 1,
            b'>' => angle_depth = angle_depth.saturating_sub(1),
            b':' if angle_depth == 0 && bytes.get(index + 1) == Some(&b':') => {
                segments.push(&path[start..index]);
                index += 1;
                start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    segments.push(&path[start..]);
    segments
}

fn is_source_finding(kind: &FindingKind) -> bool {
    !matches!(
        kind,
        FindingKind::Effect {
            finding: EffectFindingClass::AnalysisIncomplete
                | EffectFindingClass::UnresolvedCallTarget,
            ..
        } | FindingKind::EmptyReportRoots
            | FindingKind::MissingReportRoot
    )
}

fn shortest_distinguishing_root_labels(roots: &BTreeSet<String>) -> Vec<String> {
    let split = roots
        .iter()
        .map(|root| top_level_path_segments(root))
        .collect::<Vec<_>>();
    split
        .iter()
        .enumerate()
        .map(|(index, segments)| {
            for suffix_len in 1..=segments.len() {
                let start = segments.len() - suffix_len;
                let candidate = segments[start..].join("::");
                let unique = split.iter().enumerate().all(|(other_index, other)| {
                    other_index == index
                        || other.len() < suffix_len
                        || other[other.len() - suffix_len..].join("::") != candidate
                });
                if unique {
                    return candidate;
                }
            }
            segments.join("::")
        })
        .collect()
}

fn compare_findings(left: &Finding, right: &Finding) -> std::cmp::Ordering {
    left.root
        .cmp(&right.root)
        .then_with(|| {
            report_root_kind_order(left.root_kind).cmp(&report_root_kind_order(right.root_kind))
        })
        .then_with(|| left.root_span.cmp(&right.root_span))
        .then_with(|| finding_domain_order(&left.kind).cmp(&finding_domain_order(&right.kind)))
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

fn finding_domain_order(kind: &FindingKind) -> u8 {
    match kind {
        FindingKind::Effect { .. } => 2,
        FindingKind::EmptyReportRoots | FindingKind::MissingReportRoot => 3,
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
    pub(crate) second_primary_span: Option<Span>,
    pub(crate) message: String,
    pub(crate) messages: Vec<DiagnosticMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DiagnosticMessage {
    Note(String),
    SpanNote(Span, String),
    SpanLabel(Span, String),
    Help(String),
    AlternativeHelp(String),
    SpanAlternativeHelp(Span, String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    tag = "kind"
)]
pub(crate) enum FindingKind {
    Effect {
        effect: String,
        finding: EffectFindingClass,
        #[serde(skip_serializing_if = "Option::is_none")]
        operation: Option<String>,
        #[serde(skip)]
        missing_requirements: bool,
    },
    EmptyReportRoots,
    MissingReportRoot,
}

impl FindingKind {
    pub(crate) fn lint_code(&self) -> String {
        let (domain, lint) = match self {
            Self::Effect {
                effect,
                finding,
                operation,
                ..
            } => {
                let lint = operation.clone().unwrap_or_else(|| match finding {
                    EffectFindingClass::ConcreteOperation => String::from("operation"),
                    EffectFindingClass::ConcreteInvocation => String::from("invocation"),
                    EffectFindingClass::UndocumentedInvocation => {
                        String::from("undocumented-invocation")
                    }
                    EffectFindingClass::DocumentedObligation => {
                        String::from("documented-obligation")
                    }
                    EffectFindingClass::UnresolvedCallTarget => {
                        String::from("unresolved-call-target")
                    }
                    EffectFindingClass::AmbiguousMarker => String::from("ambiguous-marker"),
                    EffectFindingClass::AmbiguousRequirement => {
                        String::from("ambiguous-requirement")
                    }
                    EffectFindingClass::AnalysisIncomplete => String::from("analysis-incomplete"),
                });
                (effect.as_str(), lint)
            }
            Self::EmptyReportRoots => ("analysis", String::from("empty-report-roots")),
            Self::MissingReportRoot => ("analysis", String::from("missing-report-root")),
        };
        format!("sniff-test::{domain}::{lint}")
    }

    fn lint_level(&self, config: &SniffTestConfig) -> LintLevel {
        match self {
            Self::Effect {
                finding: EffectFindingClass::UndocumentedInvocation,
                ..
            } => config.analysis.lints.undocumented_effect_invocation,
            Self::Effect {
                effect,
                finding: EffectFindingClass::UnresolvedCallTarget,
                ..
            } => config
                .effect_coverage(&EffectKey::new(effect))
                .map_or(LintLevel::Warn, |coverage| coverage.unresolved_call_target),
            Self::Effect {
                effect,
                finding: EffectFindingClass::AnalysisIncomplete,
                ..
            } => config
                .effect_coverage(&EffectKey::new(effect))
                .map_or(LintLevel::Warn, |coverage| coverage.analysis_incomplete),
            Self::Effect {
                effect,
                finding,
                missing_requirements,
                operation,
                ..
            } => config
                .effect_config(&EffectKey::new(effect))
                .map_or(LintLevel::Warn, |effect| {
                    let lints = effect.finding_lints(&config.analysis.lints);
                    match finding {
                        EffectFindingClass::ConcreteOperation => {
                            effect.operation_lint(operation.as_deref())
                        }
                        EffectFindingClass::ConcreteInvocation => lints.concrete_invocation,
                        EffectFindingClass::DocumentedObligation if *missing_requirements => {
                            lints.documented_obligation_missing_requirements
                        }
                        EffectFindingClass::DocumentedObligation => lints.documented_obligation,
                        EffectFindingClass::AmbiguousMarker => lints.ambiguous_marker,
                        EffectFindingClass::AmbiguousRequirement => lints.ambiguous_requirement,
                        EffectFindingClass::UndocumentedInvocation
                        | EffectFindingClass::UnresolvedCallTarget
                        | EffectFindingClass::AnalysisIncomplete => {
                            unreachable!("shared analysis policy is resolved first")
                        }
                    }
                }),
            Self::EmptyReportRoots => config.analysis.lints.empty_report_roots,
            Self::MissingReportRoot => config.analysis.lints.missing_report_root,
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
        DiagnosticMessage, FULL_STACK_TRACE_HINT, Finding, FindingDiagnostic, FindingKind,
        FindingOwner, FindingTraceStepOrder, OwnerScope, ResolvedFinding, SourceEvidence,
        aggregate_human_findings, compact_human_diagnostic_paths, resolve_findings,
        shortest_distinguishing_root_labels, take_full_stack_trace_hint,
    };
    use crate::artifact::{SourceFileFact, SourceFileId, SourceRangeFact};
    use crate::config::{LintLevel, SniffTestConfig};
    use crate::report_model::{
        EffectFindingClass, UnresolvedCallCoverage, UnresolvedCallMechanism, UnresolvedCallSite,
    };
    use rustc_span::{BytePos, Span};
    use std::collections::BTreeSet;

    fn finding(kind: FindingKind) -> Finding {
        Finding::new(
            kind,
            String::from("test finding"),
            FindingDiagnostic {
                span: None,
                second_primary_span: None,
                message: String::from("test finding"),
                messages: Vec::new(),
            },
        )
    }

    fn effect(
        effect: &str,
        finding: EffectFindingClass,
        missing_requirements: bool,
    ) -> FindingKind {
        FindingKind::Effect {
            effect: effect.to_owned(),
            finding,
            operation: None,
            missing_requirements,
        }
    }

    #[test]
    fn resolves_policy_and_filters_allowed_findings_once() {
        let mut config = SniffTestConfig::default();
        config.panics.lints.panic_invocation = LintLevel::Allow;
        config.panics.lints.unresolved_call_target = Some(LintLevel::Allow);
        config.safety.lints.unresolved_call_target = Some(LintLevel::Allow);
        config.analysis.lints.undocumented_effect_invocation = LintLevel::Warn;
        config.analysis.lints.empty_report_roots = LintLevel::Deny;

        let resolved = resolve_findings(
            vec![
                finding(effect(
                    "panic",
                    EffectFindingClass::ConcreteInvocation,
                    false,
                )),
                finding(effect(
                    "safety",
                    EffectFindingClass::DocumentedObligation,
                    false,
                )),
                finding(FindingKind::EmptyReportRoots),
                finding(effect(
                    "panic",
                    EffectFindingClass::UnresolvedCallTarget,
                    false,
                )),
                finding(effect(
                    "safety",
                    EffectFindingClass::UnresolvedCallTarget,
                    false,
                )),
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
        let obligation = finding(effect(
            "safety",
            EffectFindingClass::DocumentedObligation,
            true,
        ));

        let resolved = resolve_findings(vec![obligation], &config);
        let [remaining] = resolved.as_slice() else {
            panic!("the safety obligation should use its ordinary lint policy");
        };
        assert_eq!(
            remaining.finding.kind,
            effect("safety", EffectFindingClass::DocumentedObligation, true)
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
                finding(effect(
                    "panic",
                    EffectFindingClass::AnalysisIncomplete,
                    false,
                )),
                finding(effect(
                    "safety",
                    EffectFindingClass::AnalysisIncomplete,
                    false,
                )),
            ],
            &config,
        );

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].level, LintLevel::Warn);
        assert_eq!(
            resolved[0].finding.kind,
            effect("panic", EffectFindingClass::AnalysisIncomplete, false)
        );
    }

    #[test]
    fn findings_serialize_generic_effect_fields() {
        let mut unresolved = finding(effect(
            "panic",
            EffectFindingClass::UnresolvedCallTarget,
            false,
        ));
        unresolved.unresolved_call = Some(UnresolvedCallSite {
            coverage: UnresolvedCallCoverage::Partial,
            mechanism: UnresolvedCallMechanism::DynamicDispatch,
        });
        let serialized = serde_json::to_value(unresolved).expect("serialize unresolved call");
        assert_eq!(serialized["kind"], "effect");
        assert_eq!(serialized["effect"], "panic");
        assert_eq!(serialized["finding"], "unresolved-call-target");
        assert_eq!(
            serialized["unresolved-call"],
            serde_json::json!({
                "coverage": "partial",
                "mechanism": "dynamic-dispatch",
            })
        );
    }

    #[test]
    fn finding_kinds_expose_generic_effect_lint_codes() {
        assert_eq!(
            effect("panic", EffectFindingClass::ConcreteInvocation, false).lint_code(),
            "sniff-test::panic::invocation"
        );
        assert_eq!(
            effect(
                "allocation",
                EffectFindingClass::UndocumentedInvocation,
                false
            )
            .lint_code(),
            "sniff-test::allocation::undocumented-invocation"
        );
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
        let documented = finding(effect(
            "panic",
            EffectFindingClass::DocumentedObligation,
            false,
        ))
        .with_source_order(Some(&source), Some(&documented_range));
        let invocation = finding(effect(
            "panic",
            EffectFindingClass::ConcreteInvocation,
            false,
        ))
        .with_source_order(Some(&source), Some(&invocation_range));

        let forward = serde_json::to_value(resolve_findings(
            vec![documented.clone(), invocation.clone()],
            &config,
        ))
        .expect("serialize findings");
        let reverse = serde_json::to_value(resolve_findings(vec![invocation, documented], &config))
            .expect("serialize findings");

        assert_eq!(forward, reverse);
        assert_eq!(forward[0]["kind"], "effect");
        assert_eq!(forward[0]["finding"], "documented-obligation");
        assert_eq!(forward[1]["kind"], "effect");
        assert_eq!(forward[1]["finding"], "concrete-invocation");
    }

    #[test]
    fn human_findings_aggregate_one_effect_source_and_retain_every_root_message() {
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
        let first_root_span = Span::with_root_ctxt(BytePos(100), BytePos(120));
        let second_root_span = Span::with_root_ctxt(BytePos(130), BytePos(150));
        let at_root = |root: &str, root_span: Span, trace: &[&str]| {
            let mut finding = finding(effect(
                "panic",
                EffectFindingClass::ConcreteInvocation,
                false,
            ))
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
            finding
                .diagnostic
                .messages
                .push(DiagnosticMessage::SpanAlternativeHelp(
                    root_span,
                    format!("document `{root}`"),
                ));
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
        let long = at_root("sample::first", first_root_span, &["one", "two"]);
        let short = at_root("sample::second", second_root_span, &["one"]);

        let aggregated = aggregate_human_findings(&[long, short]);

        assert_eq!(aggregated.len(), 1);
        assert_eq!(
            aggregated[0].finding.diagnostic.message,
            "panic invocation to `panic_fmt` is reachable through undocumented panic paths"
        );
        assert_eq!(aggregated[0].finding.diagnostic.span, Some(effect_span));
        assert_eq!(
            aggregated[0].finding.diagnostic.messages,
            [
                DiagnosticMessage::Note(String::from(
                    "reachable from `first`, `second` to `panic_fmt`"
                )),
                DiagnosticMessage::SpanAlternativeHelp(
                    first_root_span,
                    String::from("document `first`"),
                ),
                DiagnosticMessage::SpanAlternativeHelp(
                    second_root_span,
                    String::from("document `second`"),
                ),
            ]
        );
    }

    #[test]
    fn workspace_effect_emits_one_diagnostic_per_report_root() {
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
            let mut finding = finding(effect(
                "panic",
                EffectFindingClass::DocumentedObligation,
                false,
            ))
            .with_source_order(Some(&source), Some(&range));
            finding.owner = Some(FindingOwner {
                scope: OwnerScope::Workspace,
                crate_name: Some(String::from("sample")),
            });
            finding.root = Some(root.to_owned());
            finding.target = Some(String::from("core::result::Result::unwrap"));
            finding.reason = String::from("call to `core::result::Result::unwrap` may panic");
            finding.effect_span = Some(effect_span);
            finding.diagnostic.messages = vec![
                DiagnosticMessage::Note(format!("reachable from `{root}` to `unwrap`")),
                DiagnosticMessage::SpanAlternativeHelp(root_span, format!("document `{root}`")),
            ];
            ResolvedFinding {
                level: LintLevel::Warn,
                finding,
            }
        };
        let first_span = Span::with_root_ctxt(BytePos(100), BytePos(120));
        let second_span = Span::with_root_ctxt(BytePos(130), BytePos(150));

        let diagnostics = aggregate_human_findings(&[
            at_root("sample::read_bytes_to_end", first_span),
            at_root("sample::skip_to_end", second_span),
        ]);

        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].finding.diagnostic.span, Some(effect_span));
        assert_eq!(diagnostics[1].finding.diagnostic.span, Some(effect_span));
        assert_eq!(
            diagnostics[0].finding.diagnostic.messages,
            [
                DiagnosticMessage::SpanAlternativeHelp(
                    first_span,
                    String::from("document `read_bytes_to_end`")
                ),
                DiagnosticMessage::Note(String::from(
                    "reachable from `read_bytes_to_end` to `unwrap`"
                )),
            ]
        );
        assert_eq!(
            diagnostics[1].finding.diagnostic.messages,
            [
                DiagnosticMessage::SpanAlternativeHelp(
                    second_span,
                    String::from("document `skip_to_end`"),
                ),
                DiagnosticMessage::Note(String::from("reachable from `skip_to_end` to `unwrap`")),
            ]
        );
    }

    #[test]
    fn dependency_effect_keeps_each_root_and_collapses_repeated_paths() {
        let source = SourceFileFact {
            id: SourceFileId::new("dependency-source"),
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
        let at_root = |root: &str, local_span: Span, trace: &[&str]| {
            let mut finding = finding(effect(
                "panic",
                EffectFindingClass::DocumentedObligation,
                false,
            ))
            .with_source_order(Some(&source), Some(&range));
            finding.owner = Some(FindingOwner {
                scope: OwnerScope::Dependency,
                crate_name: Some(String::from("dependency")),
            });
            finding.root = Some(root.to_owned());
            finding.target = Some(String::from("alloc::vec::Vec::push"));
            finding.reason = String::from("dependency call to `alloc::vec::Vec::push` may panic");
            finding.effect_span = Some(effect_span);
            finding.local_boundary_span = Some(local_span);
            finding.source_evidence = Some(SourceEvidence::VerifiedAbsent);
            finding.justification_marker = Some(String::from("PANIC"));
            finding.trace = trace.iter().map(|step| (*step).to_owned()).collect();
            finding.diagnostic.messages = vec![
                DiagnosticMessage::Note(format!("reachable from `{root}` to `push`")),
                DiagnosticMessage::SpanAlternativeHelp(local_span, format!("guard `{root}`")),
            ];
            ResolvedFinding {
                level: LintLevel::Warn,
                finding,
            }
        };
        let first_span = Span::with_root_ctxt(BytePos(100), BytePos(120));
        let second_span = Span::with_root_ctxt(BytePos(130), BytePos(150));
        let diagnostics = aggregate_human_findings(&[
            at_root("sample::ensure", first_span, &["long", "path"]),
            at_root("sample::insert", second_span, &["short"]),
            at_root("sample::ensure", first_span, &["short"]),
        ]);

        assert_eq!(diagnostics.len(), 2);
        assert_eq!(
            diagnostics[0].finding.root.as_deref(),
            Some("sample::ensure")
        );
        assert_eq!(
            diagnostics[1].finding.root.as_deref(),
            Some("sample::insert")
        );
        assert_eq!(diagnostics[0].finding.diagnostic.span, Some(first_span));
        assert_eq!(diagnostics[1].finding.diagnostic.span, Some(second_span));
        assert_eq!(
            diagnostics[0].finding.diagnostic.second_primary_span,
            Some(effect_span)
        );
        assert_eq!(
            diagnostics[1].finding.diagnostic.second_primary_span,
            Some(effect_span)
        );
        assert_eq!(
            diagnostics[0].finding.diagnostic.message,
            "`ensure` can reach `push` with effect obligation in dependency crate `dependency`."
        );
        assert_eq!(
            diagnostics[1].finding.diagnostic.message,
            "`insert` can reach `push` with effect obligation in dependency crate `dependency`."
        );
        assert_eq!(
            diagnostics[0].finding.diagnostic.messages,
            [
                DiagnosticMessage::SpanAlternativeHelp(first_span, String::from("guard `ensure`"),),
                DiagnosticMessage::SpanLabel(
                    effect_span,
                    String::from("no recorded `// PANIC:` justification")
                ),
            ]
        );
        assert_eq!(
            diagnostics[1].finding.diagnostic.messages,
            [
                DiagnosticMessage::SpanAlternativeHelp(second_span, String::from("guard `insert`"),),
                DiagnosticMessage::SpanLabel(
                    effect_span,
                    String::from("no recorded `// PANIC:` justification")
                ),
            ]
        );
    }

    #[test]
    fn dependency_effect_keeps_distinct_paths_from_the_same_root() {
        let source = SourceFileFact {
            id: SourceFileId::new("dependency-source"),
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
        let at_call = |call: u32, local_span: Span, label: &str| {
            let mut finding = finding(effect(
                "panic",
                EffectFindingClass::DocumentedObligation,
                false,
            ))
            .with_source_order(Some(&source), Some(&range))
            .with_trace_order(vec![FindingTraceStepOrder::new(
                None,
                None,
                call,
                (0, 0),
                "sample::root",
            )]);
            finding.owner = Some(FindingOwner {
                scope: OwnerScope::Dependency,
                crate_name: Some(String::from("dependency")),
            });
            finding.root = Some(String::from("sample::root"));
            finding.target = Some(String::from("dependency::effect"));
            finding.reason = String::from("dependency effect is reachable");
            finding.effect_span = Some(effect_span);
            finding.local_boundary_span = Some(local_span);
            finding.source_evidence = Some(SourceEvidence::VerifiedAbsent);
            finding.justification_marker = Some(String::from("PANIC"));
            finding.diagnostic.messages = vec![DiagnosticMessage::SpanAlternativeHelp(
                local_span,
                format!("guard {label}"),
            )];
            ResolvedFinding {
                level: LintLevel::Warn,
                finding,
            }
        };
        let first_span = Span::with_root_ctxt(BytePos(100), BytePos(110));
        let second_span = Span::with_root_ctxt(BytePos(120), BytePos(130));

        let diagnostics = aggregate_human_findings(&[
            at_call(1, first_span, "first call"),
            at_call(2, second_span, "second call"),
        ]);

        assert_eq!(diagnostics.len(), 2);
        assert_eq!(diagnostics[0].finding.diagnostic.span, Some(first_span));
        assert_eq!(diagnostics[1].finding.diagnostic.span, Some(second_span));
        assert!(diagnostics[0].finding.diagnostic.messages.contains(
            &DiagnosticMessage::SpanAlternativeHelp(first_span, String::from("guard first call"),)
        ));
        assert!(diagnostics[1].finding.diagnostic.messages.contains(
            &DiagnosticMessage::SpanAlternativeHelp(second_span, String::from("guard second call"),)
        ));
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
        let mut finding = finding(effect(
            "panic",
            EffectFindingClass::ConcreteInvocation,
            false,
        ))
        .with_source_order(Some(&source), Some(&range));
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
            "panic invocation to `panic_fmt` is reachable through undocumented panic paths"
        );
        assert_eq!(aggregated[0].finding.diagnostic.span, Some(effect_span));
        assert_eq!(
            aggregated[0]
                .finding
                .diagnostic
                .messages
                .iter()
                .filter(|message| matches!(message, DiagnosticMessage::Note(note) if
                    note.contains("`api`")))
                .count(),
            1
        );
        assert_eq!(
            serde_json::to_value(&aggregated[0]).expect("serialize human finding"),
            serialized
        );
    }

    #[test]
    fn local_source_diagnostic_puts_all_help_before_notes() {
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
        let root_span = Span::with_root_ctxt(BytePos(100), BytePos(120));
        let mut finding = finding(effect(
            "panic",
            EffectFindingClass::DocumentedObligation,
            false,
        ))
        .with_source_order(Some(&source), Some(&range));
        finding.owner = Some(FindingOwner {
            scope: OwnerScope::Workspace,
            crate_name: Some(String::from("sample")),
        });
        finding.root = Some(String::from("sample::api"));
        finding.target = Some(String::from("core::result::Result::unwrap"));
        finding.effect_span = Some(Span::with_root_ctxt(BytePos(40), BytePos(50)));
        finding.diagnostic.messages = vec![
            DiagnosticMessage::Help(String::from("justify this call")),
            DiagnosticMessage::SpanNote(root_span, String::from("callee contract")),
            DiagnosticMessage::Note(String::from("reachable from `sample::api` to `unwrap`")),
            DiagnosticMessage::SpanAlternativeHelp(root_span, String::from("document this root")),
        ];

        let aggregated = aggregate_human_findings(&[ResolvedFinding {
            level: LintLevel::Warn,
            finding,
        }]);

        assert_eq!(
            aggregated[0].finding.diagnostic.messages,
            [
                DiagnosticMessage::Help(String::from("justify this call")),
                DiagnosticMessage::SpanAlternativeHelp(
                    root_span,
                    String::from("document this root"),
                ),
                DiagnosticMessage::SpanNote(root_span, String::from("callee contract")),
                DiagnosticMessage::Note(String::from("reachable from `api` to `unwrap`")),
            ]
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
        let mut finding = finding(effect(
            "panic",
            EffectFindingClass::ConcreteInvocation,
            false,
        ))
        .with_source_order(Some(&source), Some(&range));
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
                "reachable from local report root: `api`"
            ))]
        );
    }

    #[test]
    fn human_paths_use_callable_names_without_changing_serialized_paths() {
        let mut finding = finding(effect(
            "panic",
            EffectFindingClass::DocumentedObligation,
            false,
        ));
        let target = String::from(
            "<bitvec::slice::BitSlice<T, bitvec::order::Msb0> as bitvec::field::BitField>::load_be",
        );
        finding.root = Some(String::from(
            "indexical::bitset::bitvec::<impl indexical::bitset::BitSet for bitvec::vec::BitVec>::intersect",
        ));
        finding.target = Some(target.clone());
        finding.trace = vec![String::from("canonical trace")];
        finding.reason = format!(
            "dependency crate `bitvec` has no recorded `// PANIC:` justification for call to `{target}` with a `# Panics` obligation"
        );
        finding
            .diagnostic
            .messages
            .push(DiagnosticMessage::Note(format!(
                "`{target}` documents `# Panics` here"
            )));
        finding
            .diagnostic
            .messages
            .push(DiagnosticMessage::Note(format!(
                "reachable from `{}` to `{target}`",
                finding.root.as_deref().expect("root")
            )));
        let resolved = ResolvedFinding {
            level: LintLevel::Warn,
            finding,
        };
        let serialized = serde_json::to_value(&resolved).expect("serialize source finding");

        let aggregated = aggregate_human_findings(std::slice::from_ref(&resolved));

        assert_eq!(
            aggregated[0].finding.diagnostic.message,
            "dependency crate `bitvec` has no recorded `// PANIC:` justification for call to `load_be` with a `# Panics` obligation"
        );
        assert_eq!(
            aggregated[0].finding.diagnostic.messages,
            [
                DiagnosticMessage::Note(String::from("`load_be` documents `# Panics` here")),
                DiagnosticMessage::Note(String::from("reachable from `intersect` to `load_be`")),
            ]
        );
        assert_eq!(
            serde_json::to_value(&aggregated[0]).expect("serialize human finding"),
            serialized
        );
    }

    #[test]
    fn colliding_root_names_use_the_shortest_distinguishing_suffix() {
        let roots = BTreeSet::from([
            String::from("sample::left::run"),
            String::from("sample::right::run"),
            String::from("sample::right::stop"),
        ]);

        assert_eq!(
            shortest_distinguishing_root_labels(&roots),
            ["left::run", "right::run", "stop"]
        );

        let mut finding = finding(effect(
            "panic",
            EffectFindingClass::ConcreteInvocation,
            false,
        ));
        finding.diagnostic.messages = vec![
            DiagnosticMessage::Note(String::from(
                "reachable from `sample::left::run` to `panic_fmt`",
            )),
            DiagnosticMessage::Note(String::from(
                "reachable from `sample::right::run` to `panic_fmt`",
            )),
        ];
        compact_human_diagnostic_paths(&mut finding, &roots);
        assert_eq!(
            finding.diagnostic.messages,
            [
                DiagnosticMessage::Note(String::from("reachable from `left::run` to `panic_fmt`")),
                DiagnosticMessage::Note(String::from("reachable from `right::run` to `panic_fmt`")),
            ]
        );
    }

    #[test]
    fn full_trace_steps_keep_canonical_paths() {
        let mut finding = finding(effect(
            "panic",
            EffectFindingClass::ConcreteInvocation,
            false,
        ));
        finding.root = Some(String::from("sample::api"));
        finding.target = Some(String::from("core::panicking::panic_fmt"));
        finding.trace = vec![String::from("canonical trace")];
        finding.reason = String::from(
            "panic invocation to `core::panicking::panic_fmt` has no recorded evidence",
        );
        let trace_span = Span::with_root_ctxt(BytePos(20), BytePos(30));
        finding
            .diagnostic
            .messages
            .push(DiagnosticMessage::SpanNote(
                trace_span,
                String::from(
                    "effect trace step 1/1 (public root -> effect source): sample::api --direct-call-> core::panicking::panic_fmt",
                ),
            ));
        let resolved = ResolvedFinding {
            level: LintLevel::Deny,
            finding,
        };

        let aggregated = aggregate_human_findings(&[resolved]);

        assert_eq!(
            aggregated[0].finding.diagnostic.messages,
            [DiagnosticMessage::SpanNote(
                trace_span,
                String::from(
                    "effect trace step 1/1 (public root -> effect source): sample::api --direct-call-> core::panicking::panic_fmt"
                )
            )]
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
            at_root(effect(
                "panic",
                EffectFindingClass::AnalysisIncomplete,
                false,
            )),
            at_root(FindingKind::EmptyReportRoots),
            at_root(FindingKind::MissingReportRoot),
        ];

        let aggregated = aggregate_human_findings(&resolved);

        assert_eq!(aggregated, resolved);
    }

    #[test]
    fn full_stack_trace_hint_is_removed_from_every_human_finding() {
        let hint = DiagnosticMessage::Note(String::from(FULL_STACK_TRACE_HINT));
        let other = DiagnosticMessage::Note(String::from("other note"));
        let resolved = |messages| ResolvedFinding {
            level: LintLevel::Warn,
            finding: Finding {
                diagnostic: FindingDiagnostic {
                    span: None,
                    second_primary_span: None,
                    message: String::from("test finding"),
                    messages,
                },
                ..finding(effect(
                    "panic",
                    EffectFindingClass::ConcreteInvocation,
                    false,
                ))
            },
        };
        let mut findings = [
            resolved(vec![hint.clone(), other.clone()]),
            resolved(vec![hint]),
        ];

        assert!(take_full_stack_trace_hint(&mut findings));
        assert_eq!(findings[0].finding.diagnostic.messages, [other]);
        assert!(findings[1].finding.diagnostic.messages.is_empty());
        assert!(!take_full_stack_trace_hint(&mut findings));
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
            let mut finding = finding(effect(
                "safety",
                EffectFindingClass::UnresolvedCallTarget,
                false,
            ))
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
        let mut missing_first = finding(effect(
            "safety",
            EffectFindingClass::DocumentedObligation,
            true,
        ))
        .with_source_order(Some(&source), Some(&range));
        missing_first.missing_requirements = vec![String::from("initialized")];
        let mut missing_second = finding(effect(
            "safety",
            EffectFindingClass::DocumentedObligation,
            true,
        ))
        .with_source_order(Some(&source), Some(&range));
        missing_second.missing_requirements = vec![String::from("exclusive")];
        let incomplete = finding(effect(
            "safety",
            EffectFindingClass::AnalysisIncomplete,
            false,
        ));
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
        let base = finding(effect(
            "panic",
            EffectFindingClass::ConcreteInvocation,
            false,
        ))
        .with_source_order(Some(&source), Some(&range));
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
