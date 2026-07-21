//! Panic evidence classification over a reachability graph.
//!
//! The reachability crate records graph structure. This module interprets edges
//! and nodes as panic evidence:
//!
//! - compiler assert nodes are direct panic evidence;
//! - calls to configured panic sink namespaces are direct panic evidence;
//! - calls through functions documented with `# Panics` are panic obligations;
//! - calls into trusted panic-obligation namespaces are opaque boundaries that
//!   report obligations only when the reached function has panic docs.

use std::collections::{HashMap, HashSet};

use reachability::{
    CallableEdgeInfo, ReachabilityEdge, ReachabilityEdgeId, ReachabilityEdgeKind,
    ReachabilityGraph, ReachabilityNodeKind, ReachabilitySnapshot, ReachedEdge, ReachedNode,
};
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::mir::AssertKind;
use rustc_middle::thir::visit::{self, Visitor};
use rustc_middle::thir::{Block, Thir};
use rustc_middle::ty::{self, Ty, TyCtxt};
use rustc_span::Span;

use crate::config::{PanicBoundaryPolicy, PanicConfig};
use crate::contracts::{
    ContractDocSummary, ContractRequirement, EffectKind, check_contract, contract_doc_summary,
};
use crate::effect_tracker::{
    EffectPathDecision, EffectTrace, ambiguous_marker_uses, classify_effect_path, trace_to_edge,
};
use crate::namespace::canonical_namespace;
use crate::source_markers::{
    MarkerBlockKey, PanicMarkerBlock, PanicSatisfaction, span_panic_marker_block,
};

#[derive(Debug, Clone)]
pub struct PanicAnalysis {
    pub evidence: Vec<PanicEvidence>,
    pub ambiguous_markers: Vec<AmbiguousPanicMarker>,
    pub ambiguous_names: Vec<AmbiguousPanicRequirementName>,
}

#[derive(Debug, Clone)]
pub struct PanicEvidence {
    /// Edge that directly triggered this evidence before report-local adjustment.
    pub edge_id: ReachabilityEdgeId,
    /// Reachability path from the root to the triggering edge.
    pub trace: PanicTrace,
    /// Raw reason found in MIR/reachability data.
    pub kind: PanicEvidenceKind,
    /// Policy decision for whether this propagates as a raw panic path.
    pub decision: PanicPathDecision,
}

pub type PanicTrace = EffectTrace;

#[derive(Debug, Clone)]
pub struct AmbiguousPanicMarker {
    pub marker_span: Span,
    pub edge_ids: Vec<ReachabilityEdgeId>,
}

#[derive(Debug, Clone)]
pub struct AmbiguousPanicRequirementName {
    pub def_id: DefId,
    pub normalized_name: String,
    pub requirements: Vec<PanicRequirement>,
}

pub type PanicRequirement = ContractRequirement;

/// Raw panic evidence found in the graph.
#[derive(Debug, Clone, Copy)]
pub enum PanicEvidenceKind {
    /// Compiler-generated MIR assert, such as bounds, overflow, or invalid shift checks.
    CompilerAssert,
    /// Direct call to a function documented or configured as panicable.
    PanicObligation { def_id: DefId },
    /// Direct call to a configured panic sink.
    PanicSink { def_id: DefId },
    /// Call whose target cannot be resolved or verified: an undocumented
    /// trait method behind a generic bound (`def_id` is the trait method), or
    /// an opaque callable such as a function pointer (`def_id` is `None`).
    IndirectBoundary { def_id: Option<DefId> },
}

/// Propagation decision for one panic evidence path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicPathDecision {
    /// No documented/configured obligation stopped this path.
    RawPanic,
    /// The path reached a function boundary that documents or declares panic behavior.
    PanicObligation {
        edge_id: Option<ReachabilityEdgeId>,
        def_id: DefId,
    },
}

impl From<EffectPathDecision> for PanicPathDecision {
    fn from(decision: EffectPathDecision) -> Self {
        match decision {
            EffectPathDecision::RawEffect => Self::RawPanic,
            EffectPathDecision::Obligation { edge_id, def_id } => {
                Self::PanicObligation { edge_id, def_id }
            }
        }
    }
}

#[must_use]
pub fn analyze_panic_evidence<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    result: &ReachabilitySnapshot<'tcx>,
    config: &PanicConfig,
) -> PanicAnalysis {
    let view = graph.view(result);
    let root = view.root();
    let marker_resolution = resolve_panic_markers(tcx, graph, result, config);
    let ambiguous_names = collect_ambiguous_panic_requirement_names(tcx, graph, result, config);
    let mut seen_panic_obligations = HashSet::new();
    let mut evidence = view
        .edges()
        .filter_map(|edge| {
            let edge_id = edge.id();
            let kind = classify_edge(tcx, edge, config, &marker_resolution)?;
            let trace = PanicTrace {
                edge_ids: trace_to_edge_ids(edge),
            };
            if trace_crosses_satisfied_panic_marker(tcx, graph, &trace, config, &marker_resolution)
            {
                return None;
            }
            if trace_crosses_ignored_namespace(tcx, graph, &trace, config) {
                return None;
            }
            let decision = match kind {
                PanicEvidenceKind::PanicObligation { def_id } => {
                    let path_decision = classify_panic_path(tcx, graph, root, &trace, config);
                    if matches!(path_decision, PanicPathDecision::RawPanic) {
                        PanicPathDecision::PanicObligation {
                            edge_id: Some(edge_id),
                            def_id,
                        }
                    } else {
                        path_decision
                    }
                }
                PanicEvidenceKind::CompilerAssert
                | PanicEvidenceKind::PanicSink { .. }
                | PanicEvidenceKind::IndirectBoundary { .. } => {
                    classify_panic_path(tcx, graph, root, &trace, config)
                }
            };
            if let PanicPathDecision::PanicObligation { edge_id, def_id } = decision
                && !seen_panic_obligations.insert((edge_id, def_id))
            {
                return None;
            }

            Some(PanicEvidence {
                edge_id,
                trace,
                kind,
                decision,
            })
        })
        .collect::<Vec<_>>();
    suppress_resolved_callable_indirect_boundaries(graph, &mut evidence);

    PanicAnalysis {
        evidence,
        ambiguous_markers: marker_resolution.ambiguous_markers,
        ambiguous_names,
    }
}

fn suppress_resolved_callable_indirect_boundaries(
    graph: &ReachabilityGraph<'_>,
    evidence: &mut Vec<PanicEvidence>,
) {
    let resolved_callable_keys = evidence
        .iter()
        .filter(|evidence| !matches!(evidence.kind, PanicEvidenceKind::IndirectBoundary { .. }))
        .flat_map(|evidence| concrete_callable_keys_in_trace(graph, &evidence.trace))
        .collect::<HashSet<_>>();

    if resolved_callable_keys.is_empty() {
        return;
    }

    evidence.retain(|evidence| {
        !matches!(evidence.kind, PanicEvidenceKind::IndirectBoundary { .. })
            || graph
                .edge_callable(evidence.edge_id)
                .is_none_or(|key| !resolved_callable_keys.contains(&key))
    });
}

fn concrete_callable_keys_in_trace<'tcx>(
    graph: &ReachabilityGraph<'tcx>,
    trace: &PanicTrace,
) -> Vec<CallableEdgeInfo<'tcx>> {
    trace
        .edge_ids
        .iter()
        .filter_map(|edge_id| {
            let edge = graph.edge(*edge_id);
            if !matches!(
                edge.kind,
                ReachabilityEdgeKind::FnPointerReify
                    | ReachabilityEdgeKind::ClosureFnPointerReify
                    | ReachabilityEdgeKind::FnPointerCallTarget
                    | ReachabilityEdgeKind::VTableEntry
                    | ReachabilityEdgeKind::DynDispatchVTableEntry
            ) {
                return None;
            }

            graph.edge_callable(*edge_id)
        })
        .collect()
}

/// Returns the evidence trace up to and including `edge_id`.
#[must_use]
pub fn trace_edges_until(
    evidence: &PanicEvidence,
    edge_id: Option<ReachabilityEdgeId>,
) -> Vec<ReachabilityEdgeId> {
    let Some(edge_id) = edge_id else {
        return Vec::new();
    };
    let Some(position) = evidence
        .trace
        .edge_ids
        .iter()
        .position(|trace_edge_id| *trace_edge_id == edge_id)
    else {
        return evidence.trace.edge_ids.clone();
    };

    evidence.trace.edge_ids[..=position].to_vec()
}

/// Chooses the edge to show as the local trigger for an evidence path.
///
/// Reports prefer the last edge whose source is local, because dependency
/// internals can otherwise hide the current-crate call site that matters most.
#[must_use]
pub fn trigger_edge_id(
    graph: &ReachabilityGraph<'_>,
    evidence: &PanicEvidence,
) -> ReachabilityEdgeId {
    evidence
        .trace
        .edge_ids
        .iter()
        .copied()
        .rev()
        .find(|edge_id| {
            matches!(
                graph.node(graph.edge(*edge_id).source).kind,
                ReachabilityNodeKind::Instance(instance) if instance.def_id().is_local()
            )
        })
        .unwrap_or(evidence.edge_id)
}

/// Returns the graph trace up to and including `edge`.
#[must_use]
pub fn trace_to_edge_ids(edge: ReachedEdge<'_, '_>) -> Vec<ReachabilityEdgeId> {
    trace_to_edge(edge).edge_ids
}

/// Stable plain-text description for cached evidence reasons.
#[must_use]
pub fn describe_panic_evidence_kind(tcx: TyCtxt<'_>, kind: &PanicEvidenceKind) -> String {
    match kind {
        PanicEvidenceKind::CompilerAssert => String::from("compiler assert"),
        PanicEvidenceKind::PanicObligation { def_id } => {
            format!("panic obligation {}", canonical_namespace(tcx, *def_id))
        }
        PanicEvidenceKind::PanicSink { def_id } => {
            format!("panic sink {}", canonical_namespace(tcx, *def_id))
        }
        PanicEvidenceKind::IndirectBoundary {
            def_id: Some(def_id),
        } => {
            format!(
                "indirect call boundary {}",
                canonical_namespace(tcx, *def_id)
            )
        }
        PanicEvidenceKind::IndirectBoundary { def_id: None } => {
            String::from("indirect call boundary")
        }
    }
}

/// Contract definition embedded in an indirect-call target: the trait method
/// for unresolved trait-assoc calls; `None` for opaque callables such as
/// function pointers.
fn indirect_callee_def_id(callee_ty: Ty<'_>) -> Option<DefId> {
    match callee_ty.kind() {
        ty::FnDef(def_id, _) => Some(*def_id),
        _ => None,
    }
}

fn classify_panic_path<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    root: ReachedNode<'_, 'tcx>,
    trace: &PanicTrace,
    config: &PanicConfig,
) -> PanicPathDecision {
    classify_effect_path(graph, root, trace, |node| {
        panic_obligation_node_kind(tcx, node, config)
    })
    .into()
}

fn panic_obligation_node_kind<'tcx>(
    tcx: TyCtxt<'tcx>,
    node: &ReachabilityNodeKind<'tcx>,
    config: &PanicConfig,
) -> Option<DefId> {
    let def_id = match node {
        ReachabilityNodeKind::Instance(instance) => instance.def_id(),
        // The trait method's docs stand in for whichever impl runs.
        ReachabilityNodeKind::IndirectCall { callee_ty } => indirect_callee_def_id(*callee_ty)?,
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::MacroExpansion { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => return None,
    };
    (!config.ignores_def(tcx, def_id)
        && config.panic_boundary_policy(tcx, def_id) != PanicBoundaryPolicy::PanicSink
        && has_panic_docs(tcx, def_id, config))
    .then_some(def_id)
}

#[must_use]
pub fn has_panic_docs(tcx: TyCtxt<'_>, def_id: DefId, config: &PanicConfig) -> bool {
    panic_doc_summary(tcx, def_id, config).has_docs
}

#[must_use]
pub fn panic_requirements(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    config: &PanicConfig,
) -> Vec<PanicRequirement> {
    panic_doc_summary(tcx, def_id, config).requirements
}

type PanicDocSummary = ContractDocSummary;

fn panic_doc_summary(tcx: TyCtxt<'_>, def_id: DefId, config: &PanicConfig) -> PanicDocSummary {
    contract_doc_summary(
        tcx,
        def_id,
        EffectKind::Panic,
        &config.documentation_overrides,
    )
}

fn collect_ambiguous_panic_requirement_names<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    result: &ReachabilitySnapshot<'tcx>,
    config: &PanicConfig,
) -> Vec<AmbiguousPanicRequirementName> {
    let view = graph.view(result);
    let mut seen = HashSet::new();
    let mut ambiguous_names = Vec::new();
    if let Some(def_id) = panic_obligation_node_kind(tcx, view.root().kind(), config) {
        push_ambiguous_panic_requirement_names(
            tcx,
            def_id,
            config,
            &mut seen,
            &mut ambiguous_names,
        );
    }

    for edge in view.edges() {
        let trace = PanicTrace {
            edge_ids: trace_to_edge_ids(edge),
        };
        if trace_crosses_ignored_namespace(tcx, graph, &trace, config) {
            continue;
        }
        let target = &graph.node(edge.target().id()).kind;
        if let Some(def_id) = panic_obligation_node_kind(tcx, target, config) {
            push_ambiguous_panic_requirement_names(
                tcx,
                def_id,
                config,
                &mut seen,
                &mut ambiguous_names,
            );
        }
    }

    ambiguous_names.sort_by_key(|name| {
        let span = tcx.def_span(name.def_id).source_callsite();
        (span.lo().0, name.normalized_name.clone())
    });
    ambiguous_names
}

fn push_ambiguous_panic_requirement_names(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    config: &PanicConfig,
    seen: &mut HashSet<(DefId, String)>,
    ambiguous_names: &mut Vec<AmbiguousPanicRequirementName>,
) {
    for ambiguous in panic_doc_summary(tcx, def_id, config).ambiguous_requirements {
        if !seen.insert((def_id, ambiguous.normalized_name.clone())) {
            continue;
        }
        ambiguous_names.push(AmbiguousPanicRequirementName {
            def_id,
            normalized_name: ambiguous.normalized_name,
            requirements: ambiguous.requirements,
        });
    }
}

#[cfg(test)]
fn line_has_panic_heading(line: &str) -> bool {
    crate::contracts::line_has_contract_heading(line, EffectKind::Panic)
}

#[cfg(test)]
fn parse_panic_doc_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> PanicDocSummary {
    crate::contracts::parse_contract_doc_lines(lines, EffectKind::Panic)
}

fn trace_crosses_ignored_namespace<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    trace: &PanicTrace,
    config: &PanicConfig,
) -> bool {
    trace.edge_ids.iter().any(|edge_id| {
        let edge = graph.edge(*edge_id);
        let source = &graph.node(edge.source).kind;
        let target = &graph.node(edge.target).kind;
        node_kind_is_ignored_namespace(tcx, source, config)
            || node_kind_is_ignored_namespace(tcx, target, config)
    })
}

fn trace_crosses_satisfied_panic_marker<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    trace: &PanicTrace,
    config: &PanicConfig,
    marker_resolution: &PanicMarkerResolution,
) -> bool {
    trace.edge_ids.iter().any(|edge_id| {
        let edge = graph.edge(*edge_id);
        let target = &graph.node(edge.target).kind;
        edge_panic_marker_suppresses(tcx, *edge_id, target, config, marker_resolution)
    })
}

fn node_kind_is_ignored_namespace<'tcx>(
    tcx: TyCtxt<'tcx>,
    node: &ReachabilityNodeKind<'tcx>,
    config: &PanicConfig,
) -> bool {
    match node {
        ReachabilityNodeKind::Instance(instance) => {
            let def_id = instance.def_id();
            config.ignores_def(tcx, def_id)
        }
        ReachabilityNodeKind::MacroExpansion { def_id } => config.ignores_def(tcx, *def_id),
        ReachabilityNodeKind::IndirectCall { callee_ty } => {
            indirect_callee_def_id(*callee_ty).is_some_and(|def_id| config.ignores_def(tcx, def_id))
        }
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => false,
    }
}

fn classify_edge<'tcx>(
    tcx: TyCtxt<'tcx>,
    edge: ReachedEdge<'_, 'tcx>,
    config: &PanicConfig,
    marker_resolution: &PanicMarkerResolution,
) -> Option<PanicEvidenceKind> {
    let target = edge.target().kind();
    if edge_panic_marker_suppresses(tcx, edge.id(), target, config, marker_resolution) {
        return None;
    }

    classify_edge_without_marker(tcx, edge, config)
}

fn classify_edge_without_marker<'tcx>(
    tcx: TyCtxt<'tcx>,
    edge: ReachedEdge<'_, 'tcx>,
    config: &PanicConfig,
) -> Option<PanicEvidenceKind> {
    let target = edge.target().kind();
    match target {
        ReachabilityNodeKind::CompilerAssert { message, .. } => {
            if compiler_assert_is_safety_precondition(tcx, edge, message, config) {
                return None;
            }
            Some(PanicEvidenceKind::CompilerAssert)
        }
        // Every edge kind into an instance — direct and tail calls, vtable
        // entries, closure definitions, pointer reifications, const bodies —
        // carries the same obligation a direct call does; macro-expansion
        // edges never target instances.
        ReachabilityNodeKind::Instance(instance) => {
            let def_id = instance.def_id();
            if config.ignores_def(tcx, def_id) {
                return None;
            }

            match config.panic_boundary_policy(tcx, def_id) {
                PanicBoundaryPolicy::PanicSink => Some(PanicEvidenceKind::PanicSink { def_id }),
                PanicBoundaryPolicy::TrustedPanicObligation | PanicBoundaryPolicy::Normal => {
                    has_panic_docs(tcx, def_id, config)
                        .then_some(PanicEvidenceKind::PanicObligation { def_id })
                }
            }
        }
        ReachabilityNodeKind::IndirectCall { callee_ty } => {
            let Some(def_id) = indirect_callee_def_id(*callee_ty) else {
                // Opaque callable: nothing to descend into or consult.
                return Some(PanicEvidenceKind::IndirectBoundary { def_id: None });
            };
            if config.ignores_def(tcx, def_id) {
                return None;
            }

            match config.panic_boundary_policy(tcx, def_id) {
                PanicBoundaryPolicy::PanicSink => Some(PanicEvidenceKind::PanicSink { def_id }),
                PanicBoundaryPolicy::TrustedPanicObligation => has_panic_docs(tcx, def_id, config)
                    .then_some(PanicEvidenceKind::PanicObligation { def_id }),
                PanicBoundaryPolicy::Normal => Some(if has_panic_docs(tcx, def_id, config) {
                    PanicEvidenceKind::PanicObligation { def_id }
                } else {
                    // The trait method is undocumented and the running impl is
                    // unknowable: surface the boundary instead of staying silent.
                    PanicEvidenceKind::IndirectBoundary {
                        def_id: Some(def_id),
                    }
                }),
            }
        }
        ReachabilityNodeKind::MacroExpansion { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => None,
    }
}

fn compiler_assert_is_safety_precondition<'tcx>(
    tcx: TyCtxt<'tcx>,
    edge: ReachedEdge<'_, 'tcx>,
    message: &AssertKind<rustc_middle::mir::Operand<'tcx>>,
    config: &PanicConfig,
) -> bool {
    if !matches!(
        message,
        AssertKind::NullPointerDereference
            | AssertKind::MisalignedPointerDereference { .. }
            | AssertKind::InvalidEnumConstruction(_)
    ) {
        return false;
    }

    let ReachabilityNodeKind::Instance(instance) = edge.origin().kind() else {
        return false;
    };
    let def_id = instance.def_id();
    crate::safety::fn_def_is_unsafe(tcx, def_id)
        && crate::safety::has_safety_docs(tcx, def_id, &config.documentation_overrides)
}

fn edge_panic_marker_suppresses<'tcx>(
    tcx: TyCtxt<'tcx>,
    edge_id: ReachabilityEdgeId,
    target: &ReachabilityNodeKind<'tcx>,
    config: &PanicConfig,
    marker_resolution: &PanicMarkerResolution,
) -> bool {
    let Some(candidate) = marker_resolution.candidates.get(&edge_id) else {
        return false;
    };

    marker_satisfies_target(tcx, &candidate.satisfactions, target, config)
}

fn marker_satisfies_target<'tcx>(
    tcx: TyCtxt<'tcx>,
    satisfactions: &[PanicSatisfaction],
    target: &ReachabilityNodeKind<'tcx>,
    config: &PanicConfig,
) -> bool {
    let contract_def_id = match target {
        ReachabilityNodeKind::Instance(instance) => instance.def_id(),
        ReachabilityNodeKind::IndirectCall { callee_ty } => {
            match indirect_callee_def_id(*callee_ty) {
                Some(def_id) => def_id,
                None => return true,
            }
        }
        ReachabilityNodeKind::MacroExpansion { .. }
        | ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => return true,
    };
    let summary = panic_doc_summary(tcx, contract_def_id, config);
    summary.requirements.is_empty()
        || check_contract(&summary.requirements, satisfactions).is_satisfied()
}

#[derive(Debug)]
struct PanicMarkerResolution {
    candidates: HashMap<ReachabilityEdgeId, PanicMarkerCandidate>,
    ambiguous_markers: Vec<AmbiguousPanicMarker>,
}

#[derive(Debug, Clone)]
struct PanicMarkerCandidate {
    key: MarkerBlockKey,
    marker_span: Span,
    satisfactions: Vec<PanicSatisfaction>,
}

impl From<PanicMarkerBlock> for PanicMarkerCandidate {
    fn from(block: PanicMarkerBlock) -> Self {
        Self {
            key: block.key,
            marker_span: block.span,
            satisfactions: block.satisfactions,
        }
    }
}

fn resolve_panic_markers<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    result: &ReachabilitySnapshot<'tcx>,
    config: &PanicConfig,
) -> PanicMarkerResolution {
    let view = graph.view(result);
    let candidates = view
        .edges()
        .filter_map(|edge| {
            edge_marker_candidate(tcx, graph, edge.edge(), config)
                .map(|candidate| (edge.id(), candidate))
        })
        .collect::<HashMap<_, _>>();

    if panic_obligation_node_kind(tcx, view.root().kind(), config).is_some() {
        return PanicMarkerResolution {
            candidates,
            ambiguous_markers: Vec::new(),
        };
    }

    let mut marker_claims = Vec::new();
    for edge in view.edges() {
        if classify_edge_without_marker(tcx, edge, config).is_none() {
            continue;
        }
        let trace = PanicTrace {
            edge_ids: trace_to_edge_ids(edge),
        };
        if trace_crosses_ignored_namespace(tcx, graph, &trace, config) {
            continue;
        }

        if let Some((edge_id, candidate)) = trace.edge_ids.iter().find_map(|edge_id| {
            let candidate = candidates.get(edge_id)?;
            let edge = graph.edge(*edge_id);
            let target = &graph.node(edge.target).kind;
            if !marker_satisfies_target(tcx, &candidate.satisfactions, target, config) {
                return None;
            }
            Some((*edge_id, candidate))
        }) {
            marker_claims.push((candidate.key, candidate.marker_span, edge_id));
        }
    }

    let mut ambiguous_markers = ambiguous_marker_uses(marker_claims)
        .into_iter()
        .map(|marker_use| {
            let mut edge_ids = marker_use.groups;
            edge_ids.sort_by_key(|edge_id| edge_id.index());
            AmbiguousPanicMarker {
                marker_span: marker_use.marker_span,
                edge_ids,
            }
        })
        .collect::<Vec<_>>();
    ambiguous_markers.sort_by_key(|marker| {
        let span = marker.marker_span.source_callsite();
        (span.lo().0, span.hi().0)
    });

    PanicMarkerResolution {
        candidates,
        ambiguous_markers,
    }
}

/// Marker block that justifies an edge.
///
/// A marker directly above a callee segment wins, so a `// PANIC:` between
/// links of a multi-line method chain justifies only that link. The historical
/// chain rule is preserved: an unnamed marker above the whole multi-line
/// statement cannot select one link, although named requirement bullets still
/// apply. Only when no call-local marker is found do enclosing block markers
/// become candidates.
fn edge_marker_candidate(
    tcx: TyCtxt<'_>,
    graph: &ReachabilityGraph<'_>,
    edge: &ReachabilityEdge,
    config: &PanicConfig,
) -> Option<PanicMarkerCandidate> {
    let statement = span_panic_marker_block(tcx, edge.span, config.marker_probing);
    if let Some(callee_span) = edge.callee_span
        && !spans_start_on_same_line(tcx, edge.span, callee_span)
    {
        if let Some(callee) = span_panic_marker_block(tcx, callee_span, config.marker_probing) {
            return Some(callee.into());
        }
        if let Some(statement) = statement {
            let satisfactions = statement
                .satisfactions
                .into_iter()
                .filter(|satisfaction| satisfaction.requirement.is_some())
                .collect::<Vec<_>>();
            return (!satisfactions.is_empty()).then_some(PanicMarkerCandidate {
                key: statement.key,
                marker_span: statement.span,
                satisfactions,
            });
        }

        return enclosing_block_marker_candidate(tcx, graph, edge, config);
    }

    statement
        .map(Into::into)
        .or_else(|| enclosing_block_marker_candidate(tcx, graph, edge, config))
}

fn enclosing_block_marker_candidate(
    tcx: TyCtxt<'_>,
    graph: &ReachabilityGraph<'_>,
    edge: &ReachabilityEdge,
    config: &PanicConfig,
) -> Option<PanicMarkerCandidate> {
    let owner = match &graph.node(edge.origin).kind {
        ReachabilityNodeKind::Instance(instance) => instance.def_id().as_local()?,
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::MacroExpansion { .. }
        | ReachabilityNodeKind::IndirectCall { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => return None,
    };

    enclosing_block_spans(tcx, owner, edge.span)
        .into_iter()
        .find_map(|span| span_panic_marker_block(tcx, span, config.marker_probing).map(Into::into))
}

fn enclosing_block_spans(tcx: TyCtxt<'_>, owner: LocalDefId, target: Span) -> Vec<Span> {
    let Ok((thir, root)) = tcx.thir_body(owner) else {
        return Vec::new();
    };
    let thir = thir.borrow();
    let mut visitor = EnclosingBlockVisitor {
        thir: &thir,
        target,
        block_depth: 0,
        spans: Vec::new(),
    };
    visitor.visit_expr(&thir[root]);
    visitor.spans.sort_by_key(|span| {
        let span = span.source_callsite();
        (span.hi().0.saturating_sub(span.lo().0), span.lo().0)
    });
    visitor.spans.dedup_by_key(|span| {
        let span = span.source_callsite();
        (span.lo(), span.hi())
    });
    visitor.spans
}

struct EnclosingBlockVisitor<'a, 'tcx> {
    thir: &'a Thir<'tcx>,
    target: Span,
    block_depth: usize,
    spans: Vec<Span>,
}

impl<'a, 'tcx> Visitor<'a, 'tcx> for EnclosingBlockVisitor<'a, 'tcx> {
    fn thir(&self) -> &'a Thir<'tcx> {
        self.thir
    }

    fn visit_block(&mut self, block: &'a Block) {
        if self.block_depth > 0 && span_contains(block.span, self.target) {
            self.spans.push(block.span);
        }
        self.block_depth += 1;
        visit::walk_block(self, block);
        self.block_depth -= 1;
    }
}

fn span_contains(outer: Span, inner: Span) -> bool {
    let outer = outer.source_callsite();
    let inner = inner.source_callsite();
    !outer.is_dummy() && !inner.is_dummy() && outer.lo() <= inner.lo() && inner.hi() <= outer.hi()
}

fn spans_start_on_same_line(tcx: TyCtxt<'_>, left: Span, right: Span) -> bool {
    let left = left.source_callsite();
    let right = right.source_callsite();
    if left.is_dummy() || right.is_dummy() {
        return true;
    }
    let source_map = tcx.sess.source_map();
    source_map.lookup_char_pos(left.lo()).line == source_map.lookup_char_pos(right.lo()).line
}

#[cfg(test)]
mod tests {
    use super::{PanicRequirement, line_has_panic_heading, parse_panic_doc_lines};
    use rustc_span::DUMMY_SP;

    #[test]
    fn panic_doc_headings_match_supported_styles() {
        assert!(line_has_panic_heading("# Panics"));
        assert!(line_has_panic_heading("   ## Panics   "));
        assert!(line_has_panic_heading("### PANICS"));
        assert!(line_has_panic_heading("#### Panic(s)"));
    }

    #[test]
    fn panic_doc_headings_do_not_match_arbitrary_text() {
        assert!(!line_has_panic_heading("Panics: no heading"));
        assert!(!line_has_panic_heading("#Panics"));
        assert!(!line_has_panic_heading("# Panics in rare cases"));
        assert!(!line_has_panic_heading("# Safety"));
    }

    #[test]
    fn panic_doc_requirements_are_named_bullets_under_panics() {
        let summary = parse_panic_doc_lines([
            "# Panics",
            "",
            "Panics when the caller violates any listed requirement.",
            "",
            "Requirements:",
            "",
            "- nonzero: denominator must not be zero",
            "* index in bounds: index must be within the slice",
            "- something[var_1]:",
            "# Safety",
            "- ignored: this is outside the panic section",
        ]);

        assert!(summary.has_docs);
        assert_eq!(
            summary.requirements,
            [
                PanicRequirement {
                    name: String::from("nonzero"),
                    condition: String::from("denominator must not be zero"),
                    span: DUMMY_SP,
                },
                PanicRequirement {
                    name: String::from("index in bounds"),
                    condition: String::from("index must be within the slice"),
                    span: DUMMY_SP,
                },
                PanicRequirement {
                    name: String::from("something[var_1]"),
                    condition: String::new(),
                    span: DUMMY_SP,
                },
            ]
        );
    }

    #[test]
    fn panic_doc_duplicate_requirement_names_are_ambiguous() {
        let summary = parse_panic_doc_lines([
            "# Panics",
            "- nonzero: denominator must not be zero",
            "- nonzero!: total must be bounded",
        ]);

        assert_eq!(summary.ambiguous_requirements.len(), 1);
        assert_eq!(summary.ambiguous_requirements[0].normalized_name, "nonzero");
        assert_eq!(summary.ambiguous_requirements[0].requirements.len(), 2);
    }
}
