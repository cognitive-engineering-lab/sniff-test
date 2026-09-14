//! Canonical findings and the single lint-policy resolution boundary.

use std::collections::BTreeSet;
use std::path::Path;

use crate::artifact::{
    CompilerAssertKind, MarkerEvidenceState, SafetyOpKind, SourceFileFact, SourceRangeFact,
    UnverifiedMarkerProbeReason,
};
use crate::config::{LintLevel, ReportRootSet, SniffTestConfig};
use crate::report_model::{IncompleteTraceKind, UnresolvedCallMechanism, UnresolvedCallSite};
use crate::report_roots::{MissingReportRoot, ReportRootKind};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;
use serde::Serialize;
use toml::Spanned;

use super::args::SourcePackage;
use super::diagnostics::{empty_report_roots_diagnostic, missing_report_root_diagnostic};
use super::explanations::DiagnosticGroupKey;

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
    pub(crate) ambiguous_marker_effect_count: Option<usize>,
    #[serde(skip)]
    pub(crate) diagnostic_group_subtype: Option<FindingGroupSubtype>,
    #[serde(skip)]
    pub(crate) diagnostic_function_path: Option<String>,
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
            ambiguous_marker_effect_count: None,
            diagnostic_group_subtype: None,
            diagnostic_function_path: None,
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

    pub(crate) fn with_diagnostic_group_subtype(mut self, subtype: FindingGroupSubtype) -> Self {
        self.diagnostic_group_subtype = Some(subtype);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_diagnostic_function_path(mut self, function: impl Into<String>) -> Self {
        self.diagnostic_function_path = Some(function.into());
        self
    }

    /// Selects the small semantic group expanded by `cargo sniff-test explain`.
    ///
    /// This deliberately ignores the source site,
    /// report root, trace, requirements, and current analysis-run details.
    pub(crate) fn diagnostic_group_key(&self) -> DiagnosticGroupKey {
        DiagnosticGroupKey::new(
            self.kind.lint_code(),
            stable_named_scope(self.diagnostic_group_scope()),
            self.diagnostic_group_subtype_label(),
        )
    }

    fn diagnostic_group_scope(&self) -> &str {
        match self.kind {
            FindingKind::EmptyReportRoots | FindingKind::MissingReportRoot => "<configuration>",
            _ => self
                .diagnostic_function_path
                .as_deref()
                .or(self.function.as_deref())
                .unwrap_or("<unknown-function>"),
        }
    }

    fn diagnostic_group_subtype_label(&self) -> String {
        match self.kind {
            FindingKind::UnresolvedPanicCallTarget | FindingKind::UnresolvedSafetyCallTarget => {
                self.unresolved_call
                    .map(|site| unresolved_call_mechanism_label(site.mechanism))
                    .unwrap_or_default()
                    .to_owned()
            }
            FindingKind::PanicAnalysisIncomplete | FindingKind::SafetyAnalysisIncomplete => self
                .diagnostic_group_subtype
                .as_ref()
                .map(incomplete_group_subtype)
                .unwrap_or_default(),
            _ => String::new(),
        }
    }
}

fn stable_named_scope(path: &str) -> String {
    let named = path
        .split("::")
        .filter(|segment| !is_anonymous_scope_segment(segment))
        .map(normalize_embedded_anonymous_scopes)
        .collect::<Vec<_>>()
        .join("::");
    if named.is_empty() {
        String::from("<unknown-function>")
    } else {
        named
    }
}

fn is_anonymous_scope_segment(segment: &str) -> bool {
    segment
        .strip_prefix('{')
        .and_then(|segment| segment.strip_suffix('}'))
        .and_then(anonymous_scope_kind)
        .is_some()
}

fn normalize_embedded_anonymous_scopes(segment: &str) -> String {
    let mut normalized = String::with_capacity(segment.len());
    let mut remaining = segment;
    while let Some(open) = remaining.find('{') {
        normalized.push_str(&remaining[..open]);
        let after_open = &remaining[open + 1..];
        let Some(close) = after_open.find('}') else {
            normalized.push_str(&remaining[open..]);
            return normalized;
        };
        let body = &after_open[..close];
        if let Some(kind) = anonymous_scope_kind(body) {
            normalized.push('{');
            normalized.push_str(kind);
            normalized.push('}');
        } else {
            normalized.push_str(&remaining[open..=open + close + 1]);
        }
        remaining = &after_open[close + 1..];
    }
    normalized.push_str(remaining);
    normalized
}

fn anonymous_scope_kind(segment: &str) -> Option<&'static str> {
    if segment.starts_with("closure#") {
        Some("closure")
    } else if segment.starts_with("coroutine#") {
        Some("coroutine")
    } else if segment.starts_with("async") {
        Some("async")
    } else if segment.starts_with("constant#") {
        Some("constant")
    } else if segment.starts_with("impl#") {
        Some("impl")
    } else {
        None
    }
}

const fn unresolved_call_mechanism_label(mechanism: UnresolvedCallMechanism) -> &'static str {
    match mechanism {
        UnresolvedCallMechanism::FunctionPointer => "function-pointer",
        UnresolvedCallMechanism::DynamicDispatch => "dynamic-dispatch",
        UnresolvedCallMechanism::GenericDispatch => "generic-dispatch",
        UnresolvedCallMechanism::Opaque => "opaque",
    }
}

fn incomplete_group_subtype(subtype: &FindingGroupSubtype) -> String {
    match subtype {
        FindingGroupSubtype::TraceDepth { trace_kind } => {
            format!("trace-depth:{}", incomplete_trace_kind_label(*trace_kind))
        }
        FindingGroupSubtype::TraceStateBudget { trace_kind } => format!(
            "trace-state-budget:{}",
            incomplete_trace_kind_label(*trace_kind)
        ),
        FindingGroupSubtype::MissingBody => String::from("missing-body"),
    }
}

const fn incomplete_trace_kind_label(kind: IncompleteTraceKind) -> &'static str {
    match kind {
        IncompleteTraceKind::PanicEffect => "panic-effect",
        IncompleteTraceKind::SafetyEffect => "safety-effect",
        IncompleteTraceKind::PanicComment => "panic-comment",
        IncompleteTraceKind::SafetyComment => "safety-comment",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct FindingOwner {
    pub(crate) scope: OwnerScope,
    #[serde(rename = "crate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) crate_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) package_version: Option<String>,
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

/// Low-cardinality cause used only to group incomplete-analysis diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FindingGroupSubtype {
    TraceDepth { trace_kind: IncompleteTraceKind },
    TraceStateBudget { trace_kind: IncompleteTraceKind },
    MissingBody,
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
    content_hash: Option<String>,
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
            content_hash: source.map(|source| source.content_hash.clone()),
            byte_start: range.byte_start,
            byte_end: range.byte_end,
        })
    }

    fn location_identity(
        &self,
        package_root: Option<&Path>,
        cargo_target_dir: Option<&Path>,
        source_packages: &[SourcePackage],
    ) -> (Option<String>, String, Option<&str>, u64, u64) {
        let (package_identity, filename) =
            self.portable_source_identity(package_root, cargo_target_dir, source_packages);
        (
            package_identity,
            filename,
            self.content_hash.as_deref(),
            self.byte_start,
            self.byte_end,
        )
    }

    fn portable_source_identity(
        &self,
        package_root: Option<&Path>,
        cargo_target_dir: Option<&Path>,
        source_packages: &[SourcePackage],
    ) -> (Option<String>, String) {
        let filename = Path::new(&self.filename);
        let generated = cargo_target_dir.and_then(|target_dir| {
            filename
                .strip_prefix(target_dir)
                .ok()
                .map(portable_out_dir_path)
        });
        let package = source_packages
            .iter()
            .filter_map(|package| {
                filename
                    .strip_prefix(&package.root)
                    .ok()
                    .map(|relative| (package.root.components().count(), package, relative))
            })
            .max_by_key(|(depth, _, _)| *depth);
        let package_identity = package.map(|(_, package, _)| package.identity.clone());
        let filename = generated.unwrap_or_else(|| {
            package.map_or_else(
                || portable_source_filename(&self.filename, package_root),
                |(_, _, relative)| portable_relative_path(relative),
            )
        });
        (package_identity, filename)
    }
}

fn portable_relative_path(path: &Path) -> String {
    let components = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(component) => component.to_str(),
            std::path::Component::ParentDir => Some(".."),
            _ => None,
        })
        .collect::<Vec<_>>();
    let portable = components.join("/");
    if portable.is_empty() {
        path.to_string_lossy().into_owned()
    } else {
        portable
    }
}

fn portable_out_dir_path(path: &Path) -> String {
    let components = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(component) => component.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    let out_index = components
        .windows(3)
        .rposition(|window| window[0] == "build" && window[2] == "out")
        .map_or(0, |index| index + 2);
    components[out_index..].join("/")
}

fn portable_source_filename(filename: &str, package_root: Option<&Path>) -> String {
    // Cargo and snapshot tests may relocate an otherwise identical workspace.
    // Keep the crate-relative suffix in the human-aggregation location; the
    // caller combines it with the recorded content hash and byte range.
    let filename = Path::new(filename);
    let rooted_relative = package_root
        .and_then(|root| filename.strip_prefix(root).ok())
        .or_else(|| filename.is_relative().then_some(filename));
    if let Some(relative) = rooted_relative {
        return portable_relative_path(relative);
    }
    let components = filename
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(component) => component.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    let stable_root = components
        .iter()
        .rposition(|component| matches!(*component, "src" | "tests" | "examples" | "benches"));
    let portable = stable_root
        .map_or_else(
            || {
                components
                    .iter()
                    .rev()
                    .take(3)
                    .rev()
                    .copied()
                    .collect::<Vec<_>>()
            },
            // External dependency paths are outside the current package root.
            // Retain the package-directory component before the conventional
            // source root so same-named files from two dependency packages do
            // not collapse, while discarding the relocated workspace prefix.
            |index| components[index.saturating_sub(1)..].to_vec(),
        )
        .join("/");
    if portable.is_empty() {
        // Virtual filenames have no normal path component. Preserve their
        // compiler-provided spelling rather than collapsing all of them.
        filename.to_string_lossy().into_owned()
    } else {
        portable
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
/// from one report root are collapsed, while workspace- and dependency-owned
/// effects retain a separate diagnostic for each reaching report root.
///
/// The serialized report retains every root and path. Human findings always
/// use their semantic effect source as the primary location for local effects.
/// Dependency findings with a reachable local call use that call as the
/// primary location. Findings without a stable source identity,
/// completeness reports, and report-root diagnostics remain separate because
/// merging them could hide distinct analysis gaps.
#[cfg(test)]
pub(crate) fn aggregate_human_findings(findings: &[ResolvedFinding]) -> Vec<ResolvedFinding> {
    aggregate_human_findings_with_source_packages(findings, None, None, &[])
}

pub(crate) fn aggregate_human_findings_with_source_packages(
    findings: &[ResolvedFinding],
    package_root: Option<&Path>,
    cargo_target_dir: Option<&Path>,
    source_packages: &[SourcePackage],
) -> Vec<ResolvedFinding> {
    let mut groups = Vec::<(
        ResolvedFinding,
        BTreeSet<String>,
        BTreeSet<String>,
        Vec<FindingDiagnostic>,
    )>::new();
    for finding in findings {
        let matching = groups.iter_mut().find(|(representative, _, _, _)| {
            same_human_source(
                representative,
                finding,
                package_root,
                cargo_target_dir,
                source_packages,
            )
        });
        let roots = finding.finding.root.iter().cloned().collect();
        let roots_without_trace = finding
            .finding
            .root
            .iter()
            .filter(|_| finding.finding.trace.is_empty())
            .cloned()
            .collect();
        if let Some((representative, group_roots, group_roots_without_trace, diagnostics)) =
            matching
        {
            group_roots.extend(roots);
            diagnostics.push(finding.finding.diagnostic.clone());
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
            groups.push((
                finding.clone(),
                roots,
                roots_without_trace,
                vec![finding.finding.diagnostic.clone()],
            ));
        }
    }

    let mut findings = groups
        .into_iter()
        .map(|(mut finding, roots, roots_without_trace, diagnostics)| {
            if is_source_finding(finding.finding.kind) {
                merge_group_diagnostics(&mut finding.finding.diagnostic, &diagnostics);
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
                            DiagnosticMessage::Help(_) | DiagnosticMessage::SpanHelp(_, _)
                        )
                    });
                }
            }
            finding
        })
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        left.finding
            .source_order
            .cmp(&right.finding.source_order)
            .then_with(|| compare_findings(&left.finding, &right.finding))
    });
    findings
}

fn merge_group_diagnostics(
    representative: &mut FindingDiagnostic,
    projections: &[FindingDiagnostic],
) {
    for projection in projections {
        for message in &projection.messages {
            if !representative.messages.contains(message) {
                representative.messages.push(message.clone());
            }
        }
    }

    let Some(compact) = &mut representative.compact_messages else {
        return;
    };
    for projection in projections {
        let Some(messages) = &projection.compact_messages else {
            continue;
        };
        for message in messages {
            if !matches!(message, DiagnosticMessage::SpanLabel(_, _)) && !compact.contains(message)
            {
                compact.push(message.clone());
            }
        }
    }
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
        removed |= finding.finding.diagnostic.compact_messages.is_some()
            && !finding.finding.trace.is_empty()
            && (finding.finding.trace.len() > 1 || is_source_finding(finding.finding.kind));
        finding.finding.diagnostic.messages.retain(|message| {
            let is_hint =
                matches!(message, DiagnosticMessage::Note(note) if note == FULL_STACK_TRACE_HINT);
            removed |= is_hint;
            !is_hint
        });
    }
    removed
}

fn same_human_source(
    left: &ResolvedFinding,
    right: &ResolvedFinding,
    package_root: Option<&Path>,
    cargo_target_dir: Option<&Path>,
    source_packages: &[SourcePackage],
) -> bool {
    let same_source = match (&left.finding.source_order, &right.finding.source_order) {
        (Some(left), Some(right)) => {
            left.location_identity(package_root, cargo_target_dir, source_packages)
                == right.location_identity(package_root, cargo_target_dir, source_packages)
        }
        _ => false,
    };
    is_source_finding(left.finding.kind)
        && is_source_finding(right.finding.kind)
        && left.level == right.level
        && left.finding.kind == right.finding.kind
        && same_source
        && left.finding.function == right.finding.function
        && left.finding.target == right.finding.target
        && left.finding.owner == right.finding.owner
        && (left.finding.owner.as_ref().is_none_or(|owner| {
            !matches!(owner.scope, OwnerScope::Workspace | OwnerScope::Dependency)
        }) || left.finding.root == right.finding.root)
        && left.finding.source_evidence == right.finding.source_evidence
        && left.finding.ambiguous_marker_effect_count == right.finding.ambiguous_marker_effect_count
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
            ..
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
            .then_some(finding.justification_marker.as_deref())
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
    for message in finding
        .diagnostic
        .messages
        .iter_mut()
        .chain(finding.diagnostic.compact_messages.iter_mut().flatten())
    {
        let text = match message {
            DiagnosticMessage::Note(text)
            | DiagnosticMessage::SpanNote(_, text)
            | DiagnosticMessage::SpanLabel(_, text)
            | DiagnosticMessage::SpanHelp(_, text)
            | DiagnosticMessage::Help(text) => text,
            DiagnosticMessage::TraceStep { .. } => continue,
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
        .then_with(|| finding_domain_order(left.kind).cmp(&finding_domain_order(right.kind)))
        .then_with(|| left.trace_order.cmp(&right.trace_order))
        .then_with(|| left.source_order.cmp(&right.source_order))
        .then_with(|| left.kind.cmp(&right.kind))
        .then_with(|| {
            left.ambiguous_marker_effect_count
                .cmp(&right.ambiguous_marker_effect_count)
        })
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
    pub(crate) second_primary_span: Option<Span>,
    pub(crate) message: String,
    /// The complete explanation retained for `explain` and explicit verbose
    /// output.
    pub(crate) messages: Vec<DiagnosticMessage>,
    /// A deliberately small, independently constructed default presentation.
    /// `None` means the complete messages are already compact (for example,
    /// configuration diagnostics).
    pub(crate) compact_messages: Option<Vec<DiagnosticMessage>>,
}

impl FindingDiagnostic {
    pub(crate) fn messages_for_default_output(&self) -> &[DiagnosticMessage] {
        self.compact_messages.as_deref().unwrap_or(&self.messages)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DiagnosticMessage {
    Note(String),
    SpanNote(Span, String),
    SpanLabel(Span, String),
    SpanHelp(Span, String),
    Help(String),
    /// Keep path steps distinct so inline diagnostics and `explain` can render
    /// them independently without parsing each other's presentation strings.
    TraceStep {
        span: Option<Span>,
        index: usize,
        total: usize,
        description: String,
    },
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
    use super::compact_human_diagnostic_paths;
    use std::collections::BTreeSet;
    use std::path::Path;

    use super::{
        DiagnosticMessage, FULL_STACK_TRACE_HINT, Finding, FindingDiagnostic, FindingGroupSubtype,
        FindingKind, FindingOwner, OwnerScope, ResolvedFinding, SourceEvidence,
        aggregate_human_findings, aggregate_human_findings_with_source_packages, resolve_findings,
        shortest_distinguishing_root_labels, take_full_stack_trace_hint,
    };
    use crate::artifact::{
        CompilerAssertKind, SafetyOpKind, SourceFileFact, SourceFileId, SourceRangeFact,
        UnverifiedMarkerProbeReason,
    };
    use crate::cli::args::SourcePackage;
    use crate::config::{LintLevel, SniffTestConfig};
    use crate::report_model::{
        IncompleteTraceKind, UnresolvedCallCoverage, UnresolvedCallMechanism, UnresolvedCallSite,
    };
    use rustc_span::{BytePos, Span};

    fn finding(kind: FindingKind) -> Finding {
        Finding::new(
            kind,
            String::from("test finding"),
            FindingDiagnostic {
                second_primary_span: None,
                span: None,
                message: String::from("test finding"),
                messages: Vec::new(),
                compact_messages: None,
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
            package_name: Some(String::from("example-package")),
            package_version: Some(String::from("1.2.3")),
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
                    "package-name": "example-package",
                    "package-version": "1.2.3",
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
            package_name: None,
            package_version: None,
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
            logical_path: None,
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
    fn human_findings_are_ordered_by_their_primary_source_location() {
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("src/lib.rs"),
            logical_path: None,
            content_hash: String::from("content"),
            byte_len: 200,
        };
        let at_source = |root: &str, byte_start, reason: &str| {
            let range = SourceRangeFact {
                file: source.id.clone(),
                byte_start,
                byte_end: byte_start + 1,
            };
            let mut finding = finding(FindingKind::PanicInvocation)
                .with_source_order(Some(&source), Some(&range));
            finding.root = Some(root.to_owned());
            finding.reason = reason.to_owned();
            ResolvedFinding {
                level: LintLevel::Deny,
                finding,
            }
        };
        let later = at_source("sample::first_root", 100, "later source");
        let earlier = at_source("sample::second_root", 40, "earlier source");

        let aggregated = aggregate_human_findings(&[later, earlier]);

        assert_eq!(
            aggregated
                .iter()
                .map(|finding| finding.finding.reason.as_str())
                .collect::<Vec<_>>(),
            ["earlier source", "later source"]
        );
    }

    #[test]
    fn human_findings_do_not_merge_distinct_ambiguous_marker_counts() {
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("src/lib.rs"),
            logical_path: None,
            content_hash: String::from("content"),
            byte_len: 200,
        };
        let range = SourceRangeFact {
            file: source.id.clone(),
            byte_start: 40,
            byte_end: 50,
        };
        let at_count = |root: &str, count| {
            let mut finding = finding(FindingKind::AmbiguousPanicMarker)
                .with_source_order(Some(&source), Some(&range));
            finding.root = Some(root.to_owned());
            finding.ambiguous_marker_effect_count = Some(count);
            ResolvedFinding {
                level: LintLevel::Deny,
                finding,
            }
        };

        let aggregated = aggregate_human_findings(&[
            at_count("sample::first", 2),
            at_count("sample::second", 3),
        ]);

        assert_eq!(aggregated.len(), 2);
        assert_eq!(
            aggregated
                .iter()
                .map(|finding| finding.finding.ambiguous_marker_effect_count)
                .collect::<Vec<_>>(),
            [Some(2), Some(3)]
        );
    }

    fn projected_panic_source(root: &str, trace: &[&str], action_start: u32) -> ResolvedFinding {
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("dependency/src/lib.rs"),
            logical_path: None,
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
        let action_span = Span::with_root_ctxt(BytePos(action_start), BytePos(action_start + 10));
        let mut finding =
            finding(FindingKind::PanicInvocation).with_source_order(Some(&source), Some(&range));
        finding.root = Some(root.to_owned());
        finding.trace = trace.iter().map(|step| (*step).to_owned()).collect();
        finding.diagnostic.message = String::from("this panic path is not accounted for");
        finding.diagnostic.span = Some(root_span);
        finding.diagnostic.messages = vec![
            DiagnosticMessage::Note(format!(
                "reachable from `{root}` to `core::panicking::panic_fmt`"
            )),
            DiagnosticMessage::Help(String::from("remediate this finding")),
            DiagnosticMessage::SpanNote(action_span, format!("this is the path from `{root}`")),
        ];
        finding.diagnostic.compact_messages = Some(vec![
            DiagnosticMessage::SpanLabel(effect_span, String::from("the panic originates here")),
            DiagnosticMessage::SpanHelp(
                action_span,
                String::from("account for this path at this call"),
            ),
        ]);
        finding.effect_span = Some(effect_span);
        finding.target = Some(String::from("core::panicking::panic_fmt"));
        finding.reason = String::from(
            "panic invocation to `core::panicking::panic_fmt` is reachable through undocumented panic paths",
        );
        ResolvedFinding {
            level: LintLevel::Deny,
            finding,
        }
    }

    #[test]
    fn human_findings_aggregate_root_paths_at_one_effect_source() {
        let effect_span = Span::with_root_ctxt(BytePos(40), BytePos(50));
        let long = projected_panic_source("sample::first", &["one", "two"], 130);
        let short = projected_panic_source("sample::second", &["one"], 150);

        let aggregated = aggregate_human_findings(&[long, short]);

        assert_eq!(aggregated.len(), 1);
        assert_eq!(
            aggregated[0].finding.diagnostic.message,
            "this panic path is not accounted for"
        );
        assert_eq!(aggregated[0].finding.diagnostic.span, Some(effect_span));
        let diagnostic = &aggregated[0].finding.diagnostic;
        assert!(
            diagnostic
                .messages
                .contains(&DiagnosticMessage::Note(String::from(
                    "reachable from `first`, `second` to `panic_fmt`"
                )))
        );
        let mut full_path_spans = diagnostic
            .messages
            .iter()
            .filter_map(|message| match message {
                DiagnosticMessage::SpanNote(span, note) if note.starts_with("this is the path") => {
                    Some(*span)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        full_path_spans.sort();
        assert_eq!(
            full_path_spans,
            [
                Span::with_root_ctxt(BytePos(130), BytePos(140)),
                Span::with_root_ctxt(BytePos(150), BytePos(160)),
            ]
        );
        let mut compact_path_spans = diagnostic
            .compact_messages
            .as_deref()
            .expect("source finding has compact messages")
            .iter()
            .filter_map(|message| match message {
                DiagnosticMessage::SpanHelp(span, _) => Some(*span),
                _ => None,
            })
            .collect::<Vec<_>>();
        compact_path_spans.sort();
        assert_eq!(compact_path_spans, full_path_spans);
    }

    #[test]
    fn human_source_aggregation_keeps_source_and_invocation_actions() {
        let effect_span = Span::with_root_ctxt(BytePos(40), BytePos(50));
        let mut source_root = projected_panic_source("sample::source", &[], 130);
        source_root.finding.diagnostic.compact_messages = Some(vec![
            DiagnosticMessage::SpanLabel(effect_span, String::from("the panic originates here")),
            DiagnosticMessage::Help(String::from(
                "document the source function under `# Panics`",
            )),
        ]);
        let caller_root = projected_panic_source("sample::caller", &["one"], 150);

        let aggregated = aggregate_human_findings(&[source_root, caller_root]);

        let compact = aggregated[0]
            .finding
            .diagnostic
            .compact_messages
            .as_deref()
            .expect("source finding has compact messages");
        assert!(compact.contains(&DiagnosticMessage::Help(String::from(
            "document the source function under `# Panics`"
        ))));
        assert!(compact.contains(&DiagnosticMessage::SpanHelp(
            Span::with_root_ctxt(BytePos(150), BytePos(160)),
            String::from("account for this path at this call"),
        )));
    }

    #[test]
    fn human_single_root_source_finding_preserves_headline_without_changing_json() {
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("src/lib.rs"),
            logical_path: None,
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
        finding.diagnostic.message = String::from("this panic path is not accounted for");
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
            "this panic path is not accounted for"
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
    fn human_source_aggregation_identity_does_not_depend_on_reason_prose() {
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("src/lib.rs"),
            logical_path: None,
            content_hash: String::from("content"),
            byte_len: 200,
        };
        let range = SourceRangeFact {
            file: source.id.clone(),
            byte_start: 40,
            byte_end: 50,
        };
        let effect_span = Span::with_root_ctxt(BytePos(40), BytePos(50));
        let at_root = |root: &str, reason: &str| {
            let mut finding = finding(FindingKind::PanicInvocation)
                .with_source_order(Some(&source), Some(&range));
            finding.root = Some(root.to_owned());
            finding.target = Some(String::from("core::panicking::panic_fmt"));
            finding.effect_span = Some(effect_span);
            finding.reason = reason.to_owned();
            finding.diagnostic.message = String::from("this panic path is not accounted for");
            ResolvedFinding {
                level: LintLevel::Deny,
                finding,
            }
        };
        let first = at_root("sample::first", "legacy reason from the first projection");
        let second = at_root(
            "sample::second",
            "reworded reason from the second projection",
        );

        let aggregated = aggregate_human_findings(&[first, second]);

        assert_eq!(aggregated.len(), 1);
        assert_eq!(
            aggregated[0].finding.diagnostic.message,
            "this panic path is not accounted for"
        );
    }

    #[test]
    fn diagnostic_groups_ignore_distinct_sites_in_the_same_named_function() {
        let mut first =
            finding(FindingKind::PanicInvocation).with_diagnostic_function_path("sample::parse");
        first.span = Some(String::from("src/lib.rs:10:5"));
        let mut second =
            finding(FindingKind::PanicInvocation).with_diagnostic_function_path("sample::parse");
        second.span = Some(String::from("src/lib.rs:40:5"));

        assert_eq!(
            first.diagnostic_group_key(),
            second.diagnostic_group_key(),
            "a diagnostic group selects the lint category in a function, not one source site"
        );
    }

    #[test]
    fn diagnostic_groups_fold_anonymous_runtime_bodies_into_the_named_owner() {
        let at = |path| {
            finding(FindingKind::PanicInvocation)
                .with_diagnostic_function_path(path)
                .diagnostic_group_key()
        };

        assert_eq!(at("sample::parse"), at("sample::parse::{closure#7}"));
        assert_eq!(
            at("sample::parse"),
            at("sample::parse::{async_fn_body#3}::{coroutine#1}")
        );
        assert_eq!(
            at("sample::parse"),
            at("sample::{impl#2}::parse::{closure#4}"),
            "rustc's anonymous impl and runtime-body ordinals must not rename the group"
        );
        assert_eq!(
            at("sample::outer::inner"),
            at("sample::outer::{closure#7}::inner"),
            "a named item inside an anonymous body remains the nearest named scope"
        );
        assert_eq!(
            at("<sample::Array<{constant#1}> as sample::Trait>::run"),
            at("<sample::Array<{constant#9}> as sample::Trait>::run"),
            "anonymous ordinals embedded in a self type must not rename the group"
        );
    }

    #[test]
    fn diagnostic_groups_distinguish_unresolved_mechanisms_but_not_coverage() {
        let unresolved = |coverage, mechanism| {
            let mut finding = finding(FindingKind::UnresolvedPanicCallTarget)
                .with_diagnostic_function_path("sample::dispatch");
            finding.unresolved_call = Some(UnresolvedCallSite {
                coverage,
                mechanism,
            });
            finding.diagnostic_group_key()
        };

        assert_eq!(
            unresolved(
                UnresolvedCallCoverage::None,
                UnresolvedCallMechanism::DynamicDispatch,
            ),
            unresolved(
                UnresolvedCallCoverage::Partial,
                UnresolvedCallMechanism::DynamicDispatch,
            ),
            "resolution progress is not a diagnostic category"
        );
        assert_ne!(
            unresolved(
                UnresolvedCallCoverage::None,
                UnresolvedCallMechanism::DynamicDispatch,
            ),
            unresolved(
                UnresolvedCallCoverage::None,
                UnresolvedCallMechanism::FunctionPointer,
            ),
            "different dispatch mechanisms have different remedies"
        );
    }

    #[test]
    fn diagnostic_groups_distinguish_incomplete_causes() {
        let incomplete = |detail| {
            finding(FindingKind::PanicAnalysisIncomplete)
                .with_diagnostic_function_path("sample::frontier")
                .with_diagnostic_group_subtype(detail)
                .diagnostic_group_key()
        };

        assert_ne!(
            incomplete(FindingGroupSubtype::TraceDepth {
                trace_kind: IncompleteTraceKind::PanicEffect,
            }),
            incomplete(FindingGroupSubtype::TraceStateBudget {
                trace_kind: IncompleteTraceKind::PanicEffect,
            }),
        );
    }

    #[test]
    fn human_findings_merge_identical_sources_from_registry_mirrors() {
        let source = |filename: &str| SourceFileFact {
            id: SourceFileId::new(filename),
            filename: filename.to_owned(),
            logical_path: None,
            content_hash: String::from("same-content"),
            byte_len: 200,
        };
        let at = |source: &SourceFileFact, root: &str| {
            let range = SourceRangeFact {
                file: source.id.clone(),
                byte_start: 40,
                byte_end: 50,
            };
            let mut finding =
                finding(FindingKind::PanicInvocation).with_source_order(Some(source), Some(&range));
            finding.root = Some(root.to_owned());
            finding.function = Some(String::from("mirrored_dependency::panics"));
            finding.owner = Some(FindingOwner {
                scope: OwnerScope::Dependency,
                crate_name: Some(String::from("mirrored_dependency")),
                package_name: Some(String::from("mirrored-dependency")),
                package_version: Some(String::from("1.0.0")),
            });
            ResolvedFinding {
                level: LintLevel::Deny,
                finding,
            }
        };
        let first = source("/cargo/registry-a/mirrored-dependency/src/lib.rs");
        let second = source("/cargo/registry-b/mirrored-dependency/src/lib.rs");
        let packages = [
            SourcePackage {
                root: Path::new("/cargo/registry-a/mirrored-dependency").to_owned(),
                identity: String::from("mirrored-dependency@1.0.0:registry"),
            },
            SourcePackage {
                root: Path::new("/cargo/registry-b/mirrored-dependency").to_owned(),
                identity: String::from("mirrored-dependency@1.0.0:registry"),
            },
        ];

        let aggregated = aggregate_human_findings_with_source_packages(
            &[
                at(&first, "consumer::through_registry"),
                at(&second, "consumer::through_registry"),
            ],
            Some(Path::new("/workspace/consumer")),
            None,
            &packages,
        );

        assert_eq!(aggregated.len(), 1);
        assert!(
            aggregated[0]
                .finding
                .diagnostic
                .messages
                .contains(&DiagnosticMessage::Note(String::from(
                    "reachable from local report root: `through_registry`"
                )))
        );
    }

    #[test]
    fn human_source_finding_without_displayable_source_has_no_primary_span() {
        let source = SourceFileFact {
            id: SourceFileId::new("source-id"),
            filename: String::from("dependency/src/lib.rs"),
            logical_path: None,
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
                "reachable from local report root: `api`"
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
            logical_path: None,
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
            logical_path: None,
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
            logical_path: None,
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
                package_name: None,
                package_version: None,
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
    #[test]
    fn human_findings_aggregate_one_effect_source_and_retain_every_root_message() {
        let source = SourceFileFact {
            logical_path: None,
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
            finding
                .diagnostic
                .messages
                .push(DiagnosticMessage::SpanHelp(
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
            "representative for sample::second"
        );
        assert_eq!(aggregated[0].finding.diagnostic.span, Some(effect_span));
        assert_eq!(
            aggregated[0].finding.diagnostic.messages,
            [
                DiagnosticMessage::Note(String::from(
                    "reachable from `first`, `second` to `panic_fmt`"
                )),
                DiagnosticMessage::SpanHelp(first_root_span, String::from("document `first`")),
                DiagnosticMessage::SpanHelp(second_root_span, String::from("document `second`")),
            ]
        );
    }

    #[test]
    fn workspace_effect_emits_one_diagnostic_per_report_root() {
        let source = SourceFileFact {
            logical_path: None,
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
            let mut finding = finding(FindingKind::DocumentedPanic)
                .with_source_order(Some(&source), Some(&range));
            finding.owner = Some(FindingOwner {
                package_name: None,
                package_version: None,
                scope: OwnerScope::Workspace,
                crate_name: Some(String::from("sample")),
            });
            finding.root = Some(root.to_owned());
            finding.target = Some(String::from("core::result::Result::unwrap"));
            finding.reason = String::from("call to `core::result::Result::unwrap` may panic");
            finding.effect_span = Some(effect_span);
            finding.diagnostic.messages = vec![
                DiagnosticMessage::Note(format!("reachable from `{root}` to `unwrap`")),
                DiagnosticMessage::SpanHelp(root_span, format!("document `{root}`")),
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
                DiagnosticMessage::SpanHelp(
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
                DiagnosticMessage::SpanHelp(second_span, String::from("document `skip_to_end`")),
                DiagnosticMessage::Note(String::from("reachable from `skip_to_end` to `unwrap`")),
            ]
        );
    }

    #[test]
    fn dependency_effect_keeps_each_root_and_collapses_repeated_paths() {
        let source = SourceFileFact {
            logical_path: None,
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
            let mut finding = finding(FindingKind::DocumentedPanic)
                .with_source_order(Some(&source), Some(&range));
            finding.owner = Some(FindingOwner {
                package_name: None,
                package_version: None,
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
                DiagnosticMessage::SpanHelp(local_span, format!("guard `{root}`")),
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
                DiagnosticMessage::SpanHelp(first_span, String::from("guard `ensure`")),
                DiagnosticMessage::SpanLabel(
                    effect_span,
                    String::from("no recorded `// PANIC:` justification")
                ),
            ]
        );
        assert_eq!(
            diagnostics[1].finding.diagnostic.messages,
            [
                DiagnosticMessage::SpanHelp(second_span, String::from("guard `insert`")),
                DiagnosticMessage::SpanLabel(
                    effect_span,
                    String::from("no recorded `// PANIC:` justification")
                ),
            ]
        );
    }

    #[test]
    fn human_single_root_source_finding_is_source_centric_without_changing_json() {
        let source = SourceFileFact {
            logical_path: None,
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
            "function `api` has an undocumented panic path"
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
            logical_path: None,
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
        let mut finding =
            finding(FindingKind::DocumentedPanic).with_source_order(Some(&source), Some(&range));
        finding.owner = Some(FindingOwner {
            package_name: None,
            package_version: None,
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
            DiagnosticMessage::SpanHelp(root_span, String::from("document this root")),
        ];

        let aggregated = aggregate_human_findings(&[ResolvedFinding {
            level: LintLevel::Warn,
            finding,
        }]);

        assert_eq!(
            aggregated[0].finding.diagnostic.messages,
            [
                DiagnosticMessage::Help(String::from("justify this call")),
                DiagnosticMessage::SpanHelp(root_span, String::from("document this root")),
                DiagnosticMessage::SpanNote(root_span, String::from("callee contract")),
                DiagnosticMessage::Note(String::from("reachable from `api` to `unwrap`")),
            ]
        );
    }

    #[test]
    fn human_paths_use_callable_names_without_changing_serialized_paths() {
        let mut finding = finding(FindingKind::DocumentedPanic);
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
        finding.diagnostic.message =
            format!("call to `{target}` has undocumented panic conditions");
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
            "call to `load_be` has undocumented panic conditions"
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

        let mut finding = finding(FindingKind::PanicInvocation);
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
        let mut finding = finding(FindingKind::PanicInvocation);
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
    fn full_stack_trace_hint_is_removed_from_every_human_finding() {
        let hint = DiagnosticMessage::Note(String::from(FULL_STACK_TRACE_HINT));
        let other = DiagnosticMessage::Note(String::from("other note"));
        let resolved = |messages| ResolvedFinding {
            level: LintLevel::Warn,
            finding: Finding {
                diagnostic: FindingDiagnostic {
                    second_primary_span: None,
                    span: None,
                    message: String::from("test finding"),
                    messages,
                    compact_messages: None,
                },
                ..finding(FindingKind::PanicInvocation)
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
}
