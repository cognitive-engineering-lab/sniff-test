//! Canonical findings and the single lint-policy resolution boundary.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;
use std::hash::{BuildHasher, BuildHasherDefault, Hash, Hasher};
use std::path::Path;

use rustc_data_structures::fx::FxHasher;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;
use serde::Serialize;
use sniff_test_core::artifact::{
    MarkerEvidenceState, SourceFileFact, SourceRangeFact, UnverifiedMarkerProbeReason,
};
use sniff_test_core::config::{LintLevel, ReportRootSet, SniffTestConfig};
use sniff_test_core::effects::Effect;
use sniff_test_core::report_model::{EffectFindingClass, UnresolvedCallSite};
use sniff_test_core::report_roots::{MissingReportRoot, ReportRootKind};
use toml::Spanned;
use uuid::Uuid;

use super::diagnostics::{empty_report_roots_diagnostic, missing_report_root_diagnostic};

pub const FULL_STACK_TRACE_HINT: &str = "set `show-full-stack-trace = true` under `[analysis]` in sniff-test.toml to show every reachability step";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Finding {
    #[serde(flatten)]
    pub kind: FindingKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_kind: Option<ReportRootKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_span: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<FindingOwner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_evidence: Option<SourceEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unresolved_call: Option<UnresolvedCallSite>,
    pub reason: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    // A sized pointee keeps each entry one word instead of Arc<str>'s two;
    // large reports contain hundreds of millions of these shared references.
    pub trace: Vec<std::sync::Arc<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_requirements: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub requirements: Vec<String>,
    #[serde(skip)]
    pub diagnostic: FindingDiagnostic,
    #[serde(skip)]
    pub source_order: Option<FindingSourceOrder>,
    #[serde(skip)]
    pub trace_order: Vec<std::sync::Arc<FindingTraceStepOrder>>,
    #[serde(skip)]
    pub effect_span: Option<Span>,
    #[serde(skip)]
    pub local_boundary_span: Option<Span>,
    #[serde(skip)]
    pub justification_marker: Option<String>,
    #[serde(skip)]
    pub effect_display: Option<String>,
}

impl Finding {
    /// The obligation represented by a finding that item lint levels may control.
    #[must_use]
    pub fn unmet_item_effect(&self) -> Option<(&str, &str)> {
        match (&self.kind, self.root.as_deref()) {
            (
                FindingKind::Effect {
                    effect,
                    finding:
                        EffectFindingClass::ConcreteOperation
                        | EffectFindingClass::ConcreteInvocation
                        | EffectFindingClass::DocumentedObligation,
                    ..
                },
                Some(root),
            ) => Some((root, effect)),
            _ => None,
        }
    }

    #[must_use]
    pub fn new(kind: FindingKind, reason: String, diagnostic: FindingDiagnostic) -> Self {
        Self {
            kind,
            trace_id: None,
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

    #[must_use]
    pub fn with_source_order(
        mut self,
        source: Option<&SourceFileFact>,
        range: Option<&SourceRangeFact>,
    ) -> Self {
        self.source_order = FindingSourceOrder::new(source, range);
        self
    }

    #[must_use]
    pub fn with_trace_order(
        mut self,
        trace_order: Vec<std::sync::Arc<FindingTraceStepOrder>>,
    ) -> Self {
        self.trace_order = trace_order;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FindingOwner {
    pub scope: OwnerScope,
    #[serde(rename = "crate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crate_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwnerScope {
    Workspace,
    Dependency,
    Toolchain,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum SourceEvidence {
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FindingSourceOrder {
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FindingTraceStepOrder {
    source: Option<FindingSourceOrder>,
    call: u32,
    kind: (u8, u8),
    caller: String,
}

impl FindingTraceStepOrder {
    #[must_use]
    pub fn new(
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
pub struct ResolvedFinding {
    pub level: LintLevel,
    #[serde(flatten)]
    pub finding: Finding,
}

/// Assign distinct trace prefixes to report roots using their stable local hashes.
///
/// # Errors
///
/// Returns an error if the analysis unit contains more than 65,536 report roots.
pub fn trace_root_codes(
    roots: impl IntoIterator<Item = (String, u64)>,
) -> Result<BTreeMap<String, String>, String> {
    let hashes = roots
        .into_iter()
        .map(|(root, local_hash)| (root, format!("{local_hash:016x}")))
        .collect();
    assign_root_codes(hashes)
}

fn assign_root_codes(hashes: BTreeMap<String, String>) -> Result<BTreeMap<String, String>, String> {
    let mut codes = BTreeMap::new();
    let mut used = BTreeSet::new();
    for (root, hash) in hashes {
        let start = u16::from_str_radix(&hash[..4], 16).expect("stable root hash is hexadecimal");
        let Some(code) = (0..=u16::MAX)
            .map(|offset| start.wrapping_add(offset))
            .find(|candidate| used.insert(*candidate))
        else {
            return Err(String::from(
                "more than 65,536 report roots in one analysis unit; trace IDs cannot be assigned",
            ));
        };
        codes.insert(root, format!("{code:04x}"));
    }
    Ok(codes)
}

#[must_use]
pub fn resolve_findings_with_root_codes(
    findings: Vec<Finding>,
    config: &SniffTestConfig,
    effects: &[Box<dyn Effect + '_>],
    item_lints: &BTreeMap<(String, String), LintLevel>,
    root_codes: &BTreeMap<String, String>,
) -> Vec<ResolvedFinding> {
    let effect_index = effects
        .iter()
        .map(|effect| (effect.key().as_str(), effect.as_ref()))
        .collect::<BTreeMap<_, _>>();
    let mut resolved = findings
        .into_iter()
        .filter_map(|finding| {
            let level = match finding.unmet_item_effect() {
                Some((root, effect)) => item_lints
                    .get(&(root.to_owned(), effect.to_owned()))
                    .copied()
                    .unwrap_or_else(|| finding.lint_level(config, &effect_index)),
                _ => finding.lint_level(config, &effect_index),
            };
            (!level.is_allow()).then_some(ResolvedFinding { level, finding })
        })
        .collect::<Vec<_>>();
    resolved.sort_by(|left, right| compare_findings(&left.finding, &right.finding));
    assign_trace_ids(&mut resolved, root_codes);
    resolved
}

fn assign_trace_ids(findings: &mut [ResolvedFinding], root_codes: &BTreeMap<String, String>) {
    // Hash semantic report data, not the compact/full diagnostic presentation.
    let namespace = Uuid::new_v5(&Uuid::NAMESPACE_DNS, b"sniff-test.trace");
    let mut identity = String::new();
    let mut edges = Vec::new();
    let hashes = findings
        .iter()
        .map(|resolved| {
            let finding = &resolved.finding;
            if finding.trace_order.is_empty() {
                return None;
            }
            edges.clear();
            edges.extend(finding.trace.iter().map(|step| {
                step.as_bytes()
                    .windows(2)
                    .position(|pair| pair[0] == b':' && pair[1].is_ascii_digit())
                    .map_or(step.as_str(), |index| &step[index..])
            }));
            let source_bytes = finding
                .source_order
                .as_ref()
                .map(|source| (source.byte_start, source.byte_end));
            identity.clear();
            write!(
                identity,
                "{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
                finding.root.as_deref().unwrap_or_default(),
                finding.root_kind,
                finding.kind,
                finding.root_span,
                source_bytes,
                edges,
                finding.function,
                finding.target,
                finding.requirements,
                finding.missing_requirements,
                finding.unresolved_call,
                finding.source_evidence,
                finding.reason,
            )
            .expect("writing a trace identity to a string cannot fail");
            Some(
                Uuid::new_v5(&namespace, identity.as_bytes())
                    .simple()
                    .to_string(),
            )
        })
        .collect::<Vec<_>>();
    let mut suffixes = BTreeMap::<String, BTreeMap<String, String>>::new();
    for (index, finding) in findings.iter().enumerate() {
        if let (Some(root), Some(hash)) = (&finding.finding.root, &hashes[index]) {
            suffixes
                .entry(root.clone())
                .or_default()
                .entry(hash.clone())
                .or_default();
        }
    }
    for hashes in suffixes.values_mut() {
        assign_finding_suffixes(hashes);
    }
    for (index, finding) in findings.iter_mut().enumerate() {
        let (Some(root), Some(hash)) = (&finding.finding.root, &hashes[index]) else {
            continue;
        };
        if let (Some(prefix), Some(suffix)) = (
            root_codes.get(root.as_str()),
            suffixes
                .get(root.as_str())
                .and_then(|suffixes| suffixes.get(hash)),
        ) {
            finding.finding.trace_id = Some(format!("{prefix}{suffix}"));
        }
    }
}

fn assign_finding_suffixes(hashes: &mut BTreeMap<String, String>) {
    let mut used = BTreeSet::new();
    for (hash, suffix) in hashes {
        let start = u32::from_str_radix(&hash[..6], 16).expect("UUID hash is hexadecimal");
        let code = (0..=0x00ff_ffff)
            .map(|offset| (start + offset) & 0x00ff_ffff)
            .find(|candidate| used.insert(*candidate))
            .expect("more than 16,777,216 distinct findings for one report root");
        *suffix = format!("{code:06x}");
    }
}

/// Normalizes source findings for human diagnostic emission. Repeated paths
/// from one report root are collapsed only when their canonical traces match,
/// while distinct paths and workspace- or dependency-owned report roots retain
/// separate diagnostics.
///
/// The serialized report retains every root and path. Human source findings
/// use the report root as their primary location and show the effect source
/// in a note. Findings without a stable source identity,
/// completeness reports, and report-root diagnostics remain separate because
/// merging them could hide distinct analysis gaps.
#[must_use]
pub fn aggregate_human_findings(findings: &[ResolvedFinding]) -> Vec<ResolvedFinding> {
    let hashes = BuildHasherDefault::<FxHasher>::default();
    aggregate_human_findings_with(
        findings,
        |finding| hashes.hash_one(HumanSourceFingerprint(finding)),
        same_human_source,
    )
}

/// Consume canonical findings when human output is the only remaining use.
#[must_use]
pub fn aggregate_human_findings_owned(findings: Vec<ResolvedFinding>) -> Vec<ResolvedFinding> {
    let hashes = BuildHasherDefault::<FxHasher>::default();
    aggregate_human_findings_iter_with(
        findings.into_iter().map(Cow::Owned),
        |finding| hashes.hash_one(HumanSourceFingerprint(finding)),
        same_human_source,
    )
}

fn aggregate_human_findings_with(
    findings: &[ResolvedFinding],
    fingerprint: impl FnMut(&ResolvedFinding) -> u64,
    matches: impl FnMut(&ResolvedFinding, &ResolvedFinding) -> bool,
) -> Vec<ResolvedFinding> {
    aggregate_human_findings_iter_with(findings.iter().map(Cow::Borrowed), fingerprint, matches)
}

fn aggregate_human_findings_iter_with<'a>(
    findings: impl IntoIterator<Item = Cow<'a, ResolvedFinding>>,
    mut fingerprint: impl FnMut(&ResolvedFinding) -> u64,
    mut matches: impl FnMut(&ResolvedFinding, &ResolvedFinding) -> bool,
) -> Vec<ResolvedFinding> {
    let mut groups = Vec::<(ResolvedFinding, bool)>::new();
    let mut buckets: HashMap<u64, Vec<usize>> = HashMap::new();
    for finding in findings {
        let candidates = (is_source_finding(&finding.finding.kind)
            && finding.finding.source_order.is_some())
        .then(|| buckets.entry(fingerprint(&finding)).or_default());
        let matching = candidates.as_ref().and_then(|indices| {
            indices
                .iter()
                .copied()
                .find(|&index| matches(&groups[index].0, &finding))
        });
        // Equality keeps report roots separate, so every group has at most
        // its representative's root. Retain only the extra trace-absence bit.
        let root_without_trace = finding.finding.root.is_some() && finding.finding.trace.is_empty();
        if let Some(index) = matching {
            let (representative, group_root_without_trace) = &mut groups[index];
            *group_root_without_trace |= root_without_trace;
            let mut messages = representative.finding.diagnostic.messages.clone();
            extend_unique_messages(&mut messages, &finding.finding.diagnostic.messages);
            let candidate_trace_length = finding.finding.trace.len();
            let representative_trace_length = representative.finding.trace.len();
            if candidate_trace_length < representative_trace_length
                || candidate_trace_length == representative_trace_length
                    && compare_findings(&finding.finding, &representative.finding).is_lt()
            {
                *representative = finding.into_owned();
            }
            representative.finding.diagnostic.messages = messages;
        } else {
            if let Some(candidates) = candidates {
                candidates.push(groups.len());
            }
            groups.push((finding.into_owned(), root_without_trace));
        }
    }

    groups
        .into_iter()
        .map(|(mut finding, root_without_trace)| {
            if is_source_finding(&finding.finding.kind) {
                let has_local_primary = place_source_diagnostic(&mut finding.finding);
                let has_reachability_note = finding
                    .finding
                    .diagnostic
                    .messages
                    .iter()
                    .any(is_compact_reachability_note);
                compact_human_diagnostic_paths(&mut finding.finding);
                if !has_local_primary
                    && !has_reachability_note
                    && root_without_trace
                    && let Some(root) = &finding.finding.root
                {
                    let note = DiagnosticMessage::Note(format!(
                        "reachable from local report root: `{}`",
                        compact_function_name(root)
                    ));
                    if !finding.finding.diagnostic.messages.contains(&note) {
                        finding.finding.diagnostic.messages.push(note);
                    }
                }
            }
            // Keep the relative order of notes and of suggested actions, but
            // let readers follow the source trail before choosing a fix.
            finding.finding.diagnostic.messages.sort_by_key(|message| {
                matches!(
                    message,
                    DiagnosticMessage::Help(_)
                        | DiagnosticMessage::AlternativeHelp(_)
                        | DiagnosticMessage::SpanAlternativeHelp(_, _)
                )
            });
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

fn is_compact_reachability_note(message: &DiagnosticMessage) -> bool {
    matches!(message, DiagnosticMessage::Note(note) if note.starts_with("reachable from `"))
}

/// Removes per-finding stack trace hints so the caller can emit one footer after
/// all human diagnostics.
pub fn take_full_stack_trace_hint(findings: &mut [ResolvedFinding]) -> bool {
    let mut removed = false;
    for finding in findings {
        finding.finding.diagnostic.messages.retain(|message| {
            let is_hint =
                matches!(message, DiagnosticMessage::FullStackTraceHint)
                    || matches!(message, DiagnosticMessage::Note(note) if note == FULL_STACK_TRACE_HINT);
            removed |= is_hint;
            !is_hint
        });
    }
    removed
}

/// Fields compared by `same_human_source`, all invariant when a group's
/// representative is replaced. Collisions still undergo the full comparison.
struct HumanSourceFingerprint<'a>(&'a ResolvedFinding);

impl Hash for HumanSourceFingerprint<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.level.hash(state);
        let finding = &self.0.finding;
        finding.kind.hash(state);
        finding.source_order.hash(state);
        finding.root.hash(state);
        finding.function.hash(state);
        finding.target.hash(state);
        finding.span.hash(state);
        finding.owner.hash(state);
        finding.source_evidence.hash(state);
        finding.reason.hash(state);
        finding.trace_order.hash(state);
        finding.missing_requirements.hash(state);
        finding.requirements.hash(state);
    }
}

fn same_human_source(left: &ResolvedFinding, right: &ResolvedFinding) -> bool {
    is_source_finding(&left.finding.kind)
        && is_source_finding(&right.finding.kind)
        && left.finding.source_order.is_some()
        && left.level == right.level
        && left.finding.kind == right.finding.kind
        && left.finding.source_order == right.finding.source_order
        && left.finding.root == right.finding.root
        && left.finding.function == right.finding.function
        && left.finding.target == right.finding.target
        && left.finding.span == right.finding.span
        && left.finding.owner == right.finding.owner
        && left.finding.source_evidence == right.finding.source_evidence
        && left.finding.reason == right.finding.reason
        && left.finding.trace_order == right.finding.trace_order
        && left.finding.missing_requirements == right.finding.missing_requirements
        && left.finding.requirements == right.finding.requirements
}

fn place_source_diagnostic(finding: &mut Finding) -> bool {
    if let (Some(root), FindingKind::Effect { effect, .. }) =
        (finding.root.as_deref(), &finding.kind)
    {
        if !is_effect_source_finding(&finding.kind) {
            return false;
        }
        finding.diagnostic.message = format!("function `{root}` may have {effect} effect");
        finding.diagnostic.second_primary_span = None;
        return finding.diagnostic.span.is_some();
    }
    false
}

fn compact_human_diagnostic_paths(finding: &mut Finding) {
    let mut paths = finding
        .root
        .iter()
        .filter_map(|path| {
            let compact = compact_function_name(path);
            (path.as_str() != compact).then(|| (path.clone(), compact.to_owned()))
        })
        .collect::<Vec<_>>();
    paths.extend(
        finding
            .target
            .iter()
            .chain(finding.function.iter())
            .filter(|path| finding.root.as_ref() != Some(*path))
            .map(|path| (path.clone(), compact_function_name(path).to_owned()))
            .filter(|(path, compact)| path != compact),
    );

    for (path, compact) in &mut paths {
        *path = format!("`{path}`");
        *compact = format!("`{compact}`");
    }
    compact_quoted_paths(&mut finding.diagnostic.message, &paths);
    for message in &mut finding.diagnostic.messages {
        let text = match message {
            DiagnosticMessage::FullStackTraceHint => continue,
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
        if text.contains(path.as_str()) {
            *text = text.replace(path.as_str(), compact);
        }
    }
}

#[must_use]
pub fn compact_function_name(path: &str) -> &str {
    top_level_path_segments(path)
        .last()
        .copied()
        .unwrap_or(path)
}

pub(crate) fn top_level_path_segments(path: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut angle_depth = 0_u32;
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'<' => angle_depth += 1,
            b'>' => angle_depth = angle_depth.saturating_sub(1),
            b':' if angle_depth == 0
                && bytes.get(index + 1) == Some(&b':')
                && bytes.get(index + 2) != Some(&b'<') =>
            {
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

pub(crate) fn is_source_finding(kind: &FindingKind) -> bool {
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

pub(crate) fn is_effect_source_finding(kind: &FindingKind) -> bool {
    matches!(
        kind,
        FindingKind::Effect {
            finding: EffectFindingClass::ConcreteOperation
                | EffectFindingClass::ConcreteInvocation
                | EffectFindingClass::DocumentedObligation,
            ..
        }
    )
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
pub struct FindingDiagnostic {
    pub span: Option<Span>,
    pub second_primary_span: Option<Span>,
    pub message: String,
    pub messages: Vec<DiagnosticMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticMessage {
    /// Request one shared footer without copying its text into every finding.
    FullStackTraceHint,
    Note(String),
    SpanNote(Span, String),
    SpanLabel(Span, String),
    Help(String),
    AlternativeHelp(String),
    SpanAlternativeHelp(Span, String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    tag = "kind"
)]
pub enum FindingKind {
    Effect {
        effect: String,
        finding: EffectFindingClass,
        #[serde(skip_serializing_if = "Option::is_none")]
        operation: Option<String>,
    },
    EmptyReportRoots,
    MissingReportRoot,
}

impl FindingKind {
    #[must_use]
    pub fn lint_code(&self) -> String {
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
}

impl Finding {
    fn lint_level(
        &self,
        config: &SniffTestConfig,
        effects: &BTreeMap<&str, &dyn Effect>,
    ) -> LintLevel {
        match &self.kind {
            FindingKind::Effect {
                effect,
                finding,
                operation,
            } => {
                let domain = effects
                    .get(effect.as_str())
                    .unwrap_or_else(|| panic!("finding references unselected effect `{effect}`"));
                let policy = domain.config();
                match finding {
                    EffectFindingClass::ConcreteOperation => {
                        policy.operation_lint(operation.as_deref())
                    }
                    EffectFindingClass::UndocumentedInvocation => {
                        config.analysis.lints.undocumented_effect_invocation
                    }
                    EffectFindingClass::ConcreteInvocation
                    | EffectFindingClass::DocumentedObligation => {
                        policy.finding_lints().concrete_invocation
                    }
                    EffectFindingClass::UnresolvedCallTarget => {
                        policy.effective_coverage().unresolved_call_target
                    }
                    EffectFindingClass::AmbiguousMarker => policy.finding_lints().ambiguous_marker,
                    EffectFindingClass::AmbiguousRequirement => {
                        policy.finding_lints().ambiguous_requirement
                    }
                    EffectFindingClass::AnalysisIncomplete => {
                        policy.effective_coverage().analysis_incomplete
                    }
                }
            }
            FindingKind::EmptyReportRoots | FindingKind::MissingReportRoot => LintLevel::Warn,
        }
    }
}

#[must_use]
pub fn collect_report_root_findings(
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
        aggregate_human_findings, assign_finding_suffixes, assign_root_codes,
        take_full_stack_trace_hint, trace_root_codes,
    };
    use rustc_span::{BytePos, Span};
    use sniff_test_core::artifact::{SourceFileFact, SourceFileId, SourceRangeFact};
    use sniff_test_core::config::{EffectDocMatching, LintLevel, SniffTestConfig};
    use sniff_test_core::report_model::{
        EffectFindingClass, UnresolvedCallCoverage, UnresolvedCallMechanism, UnresolvedCallSite,
    };

    #[test]
    fn colliding_finding_codes_probe_the_next_free_code() {
        let mut hashes = ["123456aaaa", "123456bbbb", "876543cccc"]
            .into_iter()
            .map(|hash| (hash.to_owned(), String::new()))
            .collect();
        assign_finding_suffixes(&mut hashes);
        assert_eq!(hashes["123456aaaa"], "123456");
        assert_eq!(hashes["123456bbbb"], "123457");
        assert_eq!(hashes["876543cccc"], "876543");
    }

    #[test]
    fn colliding_root_codes_remain_unique() {
        let hashes = [
            ("example::first".to_owned(), "12340000".to_owned()),
            ("example::second".to_owned(), "1234ffff".to_owned()),
        ]
        .into_iter()
        .collect();
        let codes = assign_root_codes(hashes).unwrap();
        assert_eq!(codes["example::first"], "1234");
        assert_eq!(codes["example::second"], "1235");
    }

    #[test]
    fn root_code_uses_the_item_local_hash() {
        let codes = trace_root_codes([
            ("example::first".to_owned(), 0x1234_0000_0000_0001),
            ("example::second".to_owned(), 0x5678_0000_0000_0002),
        ])
        .unwrap();
        assert_eq!(codes["example::first"], "1234");
        assert_eq!(codes["example::second"], "5678");
    }

    fn test_config() -> SniffTestConfig {
        SniffTestConfig {
            effects: sniff_test_effects::registered_effect_configs(),
            ..SniffTestConfig::default()
        }
    }

    fn resolve_findings(findings: Vec<Finding>, config: &SniffTestConfig) -> Vec<ResolvedFinding> {
        let effects = sniff_test_effects::selected_effect_objects(
            &sniff_test_core::effects::EffectSelection::all(),
            config,
        );
        super::resolve_findings_with_root_codes(
            findings,
            config,
            &effects,
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
        )
    }

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

    fn effect(effect: &str, finding: EffectFindingClass) -> FindingKind {
        FindingKind::Effect {
            effect: effect.to_owned(),
            finding,
            operation: None,
        }
    }

    fn indexed_human_finding(index: u64) -> ResolvedFinding {
        let range = SourceRangeFact {
            file: SourceFileId::new("source"),
            byte_start: index,
            byte_end: index + 1,
        };
        ResolvedFinding {
            level: LintLevel::Warn,
            finding: finding(effect("panic", EffectFindingClass::ConcreteInvocation))
                .with_source_order(None, Some(&range)),
        }
    }

    #[test]
    fn owned_human_aggregation_moves_trace_storage() {
        let mut finding = indexed_human_finding(0);
        finding.finding.trace = vec!["first".to_owned().into(), "second".to_owned().into()];
        let storage = finding.finding.trace.as_ptr();
        let output = super::aggregate_human_findings_owned(vec![finding]);
        assert_eq!(output[0].finding.trace.as_ptr(), storage);
        assert_eq!(output[0].finding.trace.len(), 2);
    }

    #[test]
    fn indexed_human_groups_preserve_collisions_replacement_and_messages() {
        let mut long = indexed_human_finding(0);
        long.finding.trace = vec!["first".to_owned().into(), "second".to_owned().into()];
        long.finding.diagnostic.messages = vec![DiagnosticMessage::Note("long".into())];
        let mut short = long.clone();
        short.finding.trace.clear();
        short.finding.diagnostic.message = "short representative".into();
        short.finding.diagnostic.messages = vec![DiagnosticMessage::Note("short".into())];
        let distinct = indexed_human_finding(1);
        let input = [long.clone(), distinct.clone(), short, long];
        let normal = aggregate_human_findings(&input);
        assert_eq!(
            normal,
            super::aggregate_human_findings_owned(input.to_vec())
        );
        let collided =
            super::aggregate_human_findings_with(&input, |_| 0, super::same_human_source);
        assert_eq!(normal, collided);
        assert_eq!(normal.len(), 2);
        assert_eq!(normal[0].finding.diagnostic.message, "short representative");
        assert!(normal[0].finding.trace.is_empty());
        assert_eq!(
            normal[0].finding.diagnostic.messages,
            vec![
                DiagnosticMessage::Note("long".into()),
                DiagnosticMessage::Note("short".into()),
            ]
        );
        assert_eq!(normal[1], distinct);
    }

    #[test]
    fn indexed_human_groups_keep_excluded_findings_out_of_candidate_buckets() {
        let mut no_source = indexed_human_finding(0);
        no_source.finding.source_order = None;
        let mut incomplete = indexed_human_finding(0);
        incomplete.finding.kind = effect("panic", EffectFindingClass::AnalysisIncomplete);
        let mut root = indexed_human_finding(0);
        root.finding.kind = FindingKind::EmptyReportRoots;
        let input = [
            no_source.clone(),
            no_source,
            incomplete.clone(),
            incomplete,
            root.clone(),
            root,
        ];
        let output = super::aggregate_human_findings_with(
            &input,
            |_| panic!("excluded finding was indexed"),
            |_, _| panic!("excluded finding was compared"),
        );
        assert_eq!(output, input);
    }

    #[test]
    fn indexed_human_group_comparisons_scale_with_duplicates_not_all_findings() {
        use std::collections::hash_map::RandomState;
        use std::hash::BuildHasher;
        for count in [1000, 2000, 4000] {
            let input = (0..count)
                .flat_map(|index| {
                    let finding = indexed_human_finding(index as u64);
                    [finding.clone(), finding]
                })
                .collect::<Vec<_>>();
            let hashes = RandomState::new();
            let mut comparisons = 0;
            let output = super::aggregate_human_findings_with(
                &input,
                |finding| hashes.hash_one(super::HumanSourceFingerprint(finding)),
                |left, right| {
                    comparisons += 1;
                    super::same_human_source(left, right)
                },
            );
            assert_eq!(output.len(), count);
            assert!(
                comparisons <= count * 2,
                "{comparisons} comparisons for {count} distinct findings"
            );
        }
    }

    #[test]
    fn resolves_policy_and_filters_allowed_findings_once() {
        let mut config = test_config();
        config.effect_mut("panic").lints.invocation = LintLevel::Allow;
        config.effect_mut("panic").coverage.unresolved_call_target = LintLevel::Allow;
        config.effect_mut("safety").coverage.unresolved_call_target = LintLevel::Allow;
        config.analysis.lints.undocumented_effect_invocation = LintLevel::Warn;

        let resolved = resolve_findings(
            vec![
                finding(effect("panic", EffectFindingClass::ConcreteInvocation)),
                finding(effect("safety", EffectFindingClass::DocumentedObligation)),
                finding(FindingKind::EmptyReportRoots),
                finding(effect("panic", EffectFindingClass::UnresolvedCallTarget)),
                finding(effect("safety", EffectFindingClass::UnresolvedCallTarget)),
            ],
            &config,
        );

        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].level, LintLevel::Warn);
        assert_eq!(resolved[1].level, LintLevel::Warn);
    }

    #[test]
    fn documented_obligations_use_invocation_lint_with_or_without_requirements() {
        let mut config = test_config();
        config.analysis.effect_doc_matching = EffectDocMatching::Exact;
        config.effect_mut("safety").lints.invocation = LintLevel::Deny;
        config.effect_mut("panic").lints.invocation = LintLevel::Allow;
        let ordinary = finding(effect("safety", EffectFindingClass::DocumentedObligation));
        let mut obligation = finding(effect("safety", EffectFindingClass::DocumentedObligation));
        obligation.missing_requirements = vec![String::from("caller holds the lock")];
        obligation.source_evidence = Some(SourceEvidence::Present);
        let invocation = finding(effect("safety", EffectFindingClass::ConcreteInvocation));
        let panic_obligation = finding(effect("panic", EffectFindingClass::DocumentedObligation));

        let resolved = resolve_findings(
            vec![ordinary, obligation, invocation, panic_obligation],
            &config,
        );
        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved[0].level, LintLevel::Deny);
        assert_eq!(resolved[1].level, LintLevel::Deny);
        assert_eq!(resolved[2].level, LintLevel::Deny);
    }

    #[test]
    fn incomplete_findings_use_their_effect_policy() {
        let mut config = test_config();
        config.effect_mut("panic").coverage.analysis_incomplete = LintLevel::Warn;
        config.effect_mut("safety").coverage.analysis_incomplete = LintLevel::Allow;

        let resolved = resolve_findings(
            vec![
                finding(effect("panic", EffectFindingClass::AnalysisIncomplete)),
                finding(effect("safety", EffectFindingClass::AnalysisIncomplete)),
            ],
            &config,
        );

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].level, LintLevel::Warn);
        assert_eq!(
            resolved[0].finding.kind,
            effect("panic", EffectFindingClass::AnalysisIncomplete)
        );
    }

    #[test]
    fn findings_serialize_generic_effect_fields() {
        let mut unresolved = finding(effect("panic", EffectFindingClass::UnresolvedCallTarget));
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
            effect("panic", EffectFindingClass::ConcreteInvocation).lint_code(),
            "sniff-test::panic::invocation"
        );
        assert_eq!(
            effect("allocation", EffectFindingClass::UndocumentedInvocation).lint_code(),
            "sniff-test::allocation::undocumented-invocation"
        );
    }

    #[test]
    fn resolved_findings_have_stable_order_regardless_of_discovery_order() {
        let config = test_config();
        let source = SourceFileFact {
            logical_path: None,
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
        let documented = finding(effect("panic", EffectFindingClass::DocumentedObligation))
            .with_source_order(Some(&source), Some(&documented_range));
        let invocation = finding(effect("panic", EffectFindingClass::ConcreteInvocation))
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
    fn human_findings_keep_a_diagnostic_for_each_report_root() {
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
            let mut finding = finding(effect("panic", EffectFindingClass::ConcreteInvocation))
                .with_source_order(Some(&source), Some(&range));
            finding.root = Some(root.to_owned());
            finding.trace = trace
                .iter()
                .map(|step| std::sync::Arc::new((*step).to_owned()))
                .collect();
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

        assert_eq!(aggregated.len(), 2);
        assert_eq!(
            aggregated[0].finding.diagnostic.message,
            "function `first` may have panic effect"
        );
        assert_eq!(aggregated[0].finding.diagnostic.span, Some(first_root_span));
        assert_eq!(
            aggregated[0].finding.diagnostic.messages,
            [
                DiagnosticMessage::Note(String::from("reachable from `first` to `panic_fmt`")),
                DiagnosticMessage::SpanAlternativeHelp(
                    first_root_span,
                    String::from("document `first`"),
                ),
            ]
        );
        assert_eq!(
            aggregated[1].finding.diagnostic.message,
            "function `second` may have panic effect"
        );
        assert_eq!(
            aggregated[1].finding.diagnostic.span,
            Some(second_root_span)
        );
        assert_eq!(
            aggregated[1].finding.diagnostic.messages,
            [
                DiagnosticMessage::Note(String::from("reachable from `second` to `panic_fmt`")),
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
            let mut finding = finding(effect("panic", EffectFindingClass::DocumentedObligation))
                .with_source_order(Some(&source), Some(&range));
            finding.owner = Some(FindingOwner {
                scope: OwnerScope::Workspace,
                crate_name: Some(String::from("sample")),
            });
            finding.root = Some(root.to_owned());
            finding.target = Some(String::from("core::result::Result::unwrap"));
            finding.reason = String::from("call to `core::result::Result::unwrap` may panic");
            finding.effect_span = Some(effect_span);
            finding.diagnostic.span = Some(root_span);
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
        assert_eq!(diagnostics[0].finding.diagnostic.span, Some(first_span));
        assert_eq!(diagnostics[1].finding.diagnostic.span, Some(second_span));
        assert_eq!(
            diagnostics[0].finding.diagnostic.messages,
            [
                DiagnosticMessage::Note(String::from(
                    "reachable from `read_bytes_to_end` to `unwrap`"
                )),
                DiagnosticMessage::SpanAlternativeHelp(
                    first_span,
                    String::from("document `read_bytes_to_end`")
                ),
            ]
        );
        assert_eq!(
            diagnostics[1].finding.diagnostic.messages,
            [
                DiagnosticMessage::Note(String::from("reachable from `skip_to_end` to `unwrap`")),
                DiagnosticMessage::SpanAlternativeHelp(
                    second_span,
                    String::from("document `skip_to_end`"),
                ),
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
            let mut finding = finding(effect("panic", EffectFindingClass::DocumentedObligation))
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
            finding.diagnostic.span = Some(local_span);
            finding.source_evidence = Some(SourceEvidence::VerifiedAbsent);
            finding.justification_marker = Some(String::from("PANIC"));
            finding.trace = trace
                .iter()
                .map(|step| std::sync::Arc::new((*step).to_owned()))
                .collect();
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
        assert_eq!(diagnostics[0].finding.diagnostic.second_primary_span, None);
        assert_eq!(diagnostics[1].finding.diagnostic.second_primary_span, None);
        assert_eq!(
            diagnostics[0].finding.diagnostic.message,
            "function `ensure` may have panic effect"
        );
        assert_eq!(
            diagnostics[1].finding.diagnostic.message,
            "function `insert` may have panic effect"
        );
        assert_eq!(
            diagnostics[0].finding.diagnostic.messages,
            [
                DiagnosticMessage::Note(String::from("reachable from `ensure` to `push`")),
                DiagnosticMessage::SpanAlternativeHelp(first_span, String::from("guard `ensure`"),),
            ]
        );
        assert_eq!(
            diagnostics[1].finding.diagnostic.messages,
            [
                DiagnosticMessage::Note(String::from("reachable from `insert` to `push`")),
                DiagnosticMessage::SpanAlternativeHelp(second_span, String::from("guard `insert`"),),
            ]
        );
    }

    #[test]
    fn dependency_effect_keeps_distinct_paths_from_the_same_root() {
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
        let at_call = |call: u32, local_span: Span, label: &str| {
            let mut finding = finding(effect("panic", EffectFindingClass::DocumentedObligation))
                .with_source_order(Some(&source), Some(&range))
                .with_trace_order(vec![std::sync::Arc::new(FindingTraceStepOrder::new(
                    None,
                    None,
                    call,
                    (0, 0),
                    "sample::root",
                ))]);
            finding.owner = Some(FindingOwner {
                scope: OwnerScope::Dependency,
                crate_name: Some(String::from("dependency")),
            });
            finding.root = Some(String::from("sample::root"));
            finding.target = Some(String::from("dependency::effect"));
            finding.reason = String::from("dependency effect is reachable");
            finding.effect_span = Some(effect_span);
            finding.local_boundary_span = Some(local_span);
            finding.diagnostic.span = Some(local_span);
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
    fn human_single_root_source_finding_is_root_centric_without_changing_json() {
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
        let mut finding = finding(effect("panic", EffectFindingClass::ConcreteInvocation))
            .with_source_order(Some(&source), Some(&range));
        finding.root = Some(String::from("sample::api"));
        finding.diagnostic.message =
            String::from("function `sample::api` has an undocumented panic path");
        finding.diagnostic.span = Some(root_span);
        finding.trace = vec![
            "sample::api --direct-call-> core::panicking::panic_fmt"
                .to_owned()
                .into(),
        ];
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
            "function `api` may have panic effect"
        );
        assert_eq!(aggregated[0].finding.diagnostic.span, Some(root_span));
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
    fn local_source_diagnostic_puts_all_help_after_notes() {
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
        let mut finding = finding(effect("panic", EffectFindingClass::DocumentedObligation))
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
                DiagnosticMessage::SpanNote(root_span, String::from("callee contract")),
                DiagnosticMessage::Note(String::from("reachable from `api` to `unwrap`")),
                DiagnosticMessage::Help(String::from("justify this call")),
                DiagnosticMessage::SpanAlternativeHelp(
                    root_span,
                    String::from("document this root"),
                ),
            ]
        );
    }

    #[test]
    fn human_source_finding_without_displayable_source_keeps_root_span() {
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
        let root_span = Span::with_root_ctxt(BytePos(100), BytePos(120));
        let mut finding = finding(effect("panic", EffectFindingClass::ConcreteInvocation))
            .with_source_order(Some(&source), Some(&range));
        finding.root = Some(String::from("sample::api"));
        finding.diagnostic.span = Some(root_span);
        finding.effect_span = None;
        let resolved = ResolvedFinding {
            level: LintLevel::Deny,
            finding,
        };

        let aggregated = aggregate_human_findings(&[resolved]);

        assert_eq!(aggregated[0].finding.diagnostic.span, Some(root_span));
        assert_eq!(aggregated[0].finding.diagnostic.messages, []);
    }

    #[test]
    fn human_paths_use_callable_names_without_changing_serialized_paths() {
        let mut finding = finding(effect("panic", EffectFindingClass::DocumentedObligation));
        let target = String::from(
            "<bitvec::slice::BitSlice<T, bitvec::order::Msb0> as bitvec::field::BitField>::load_be",
        );
        finding.root = Some(String::from(
            "indexical::bitset::bitvec::<impl indexical::bitset::BitSet for bitvec::vec::BitVec>::intersect",
        ));
        finding.target = Some(target.clone());
        finding.trace = vec!["canonical trace".to_owned().into()];
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
            "function `intersect` may have panic effect"
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
    fn full_trace_steps_keep_canonical_paths() {
        let mut finding = finding(effect("panic", EffectFindingClass::ConcreteInvocation));
        finding.root = Some(String::from("sample::api"));
        finding.target = Some(String::from("core::panicking::panic_fmt"));
        finding.trace = vec!["canonical trace".to_owned().into()];
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
            at_root(effect("panic", EffectFindingClass::AnalysisIncomplete)),
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
                ..finding(effect("panic", EffectFindingClass::ConcreteInvocation))
            },
        };
        let mut findings = [
            resolved(vec![
                hint,
                DiagnosticMessage::FullStackTraceHint,
                other.clone(),
            ]),
            resolved(vec![DiagnosticMessage::FullStackTraceHint]),
        ];

        assert!(take_full_stack_trace_hint(&mut findings));
        assert_eq!(findings[0].finding.diagnostic.messages, [other]);
        assert!(findings[1].finding.diagnostic.messages.is_empty());
        assert!(!take_full_stack_trace_hint(&mut findings));
    }

    #[test]
    fn human_findings_keep_distinct_unresolved_target_coverage() {
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
            let mut finding = finding(effect("safety", EffectFindingClass::UnresolvedCallTarget))
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
        let mut missing_first = finding(effect("safety", EffectFindingClass::DocumentedObligation))
            .with_source_order(Some(&source), Some(&range));
        missing_first.missing_requirements = vec![String::from("initialized")];
        let mut missing_second =
            finding(effect("safety", EffectFindingClass::DocumentedObligation))
                .with_source_order(Some(&source), Some(&range));
        missing_second.missing_requirements = vec![String::from("exclusive")];
        let incomplete = finding(effect("safety", EffectFindingClass::AnalysisIncomplete));
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
        let base = finding(effect("panic", EffectFindingClass::ConcreteInvocation))
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
