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

use std::collections::HashSet;

use reachability::{
    CallableEdgeInfo, ReachabilityEdgeId, ReachabilityEdgeKind, ReachabilityGraph,
    ReachabilityNodeKind, ReachabilityView, ReachedEdge,
};
use rustc_hir::def_id::DefId;
use rustc_middle::mir::AssertKind;
use rustc_middle::ty::{self, Ty, TyCtxt};
use rustc_span::Span;

use crate::config::{PanicBoundaryPolicy, PanicConfig};
use crate::contracts::{ContractDocSummary, ContractRequirement, EffectKind, contract_doc_summary};
use crate::effect_tracker::{
    EffectEvidence, EffectMarkerIndex, EffectPathDecision, EffectTrace, ambiguous_marker_uses,
    effect_path_edge_ids_to_edge, find_unsatisfied_effect_traces_to_edge_with,
};
use crate::namespace::canonical_namespace;
use crate::source_markers::MarkerBlockKey;

#[derive(Debug, Clone)]
pub(crate) struct PanicAnalysis {
    pub evidence: Vec<PanicEvidence>,
    pub ambiguous_markers: Vec<AmbiguousPanicMarker>,
    pub ambiguous_names: Vec<AmbiguousPanicRequirementName>,
}

#[derive(Debug, Clone)]
pub(crate) struct PanicEvidence {
    /// Edge that directly triggered this evidence before report-local adjustment.
    pub edge_id: ReachabilityEdgeId,
    /// Reachability path from the root to the triggering edge.
    pub trace: PanicTrace,
    /// Raw reason found in MIR/reachability data.
    pub kind: PanicEvidenceKind,
    /// Policy decision for whether this propagates as a raw panic path.
    pub decision: EffectPathDecision,
    /// Contract requirements not satisfied along this path.
    pub missing_requirements: Vec<PanicRequirement>,
}

pub(crate) type PanicTrace = EffectTrace;

#[derive(Debug, Clone)]
pub(crate) struct AmbiguousPanicMarker {
    pub marker_span: Span,
    pub edge_ids: Vec<ReachabilityEdgeId>,
}

#[derive(Debug, Clone)]
pub(crate) struct AmbiguousPanicRequirementName {
    pub def_id: DefId,
    pub normalized_name: String,
    pub requirements: Vec<PanicRequirement>,
}

pub(crate) type PanicRequirement = ContractRequirement;

/// Raw panic evidence found in the graph.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PanicEvidenceKind {
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

#[must_use]
pub(crate) fn analyze_panic_evidence<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    config: &PanicConfig,
) -> PanicAnalysis {
    let graph = view.graph();
    let marker_index = EffectMarkerIndex::new(tcx, view, EffectKind::Panic, config.marker_probing);
    let ambiguous_names = collect_ambiguous_panic_requirement_names(tcx, view, config);
    let mut evidence = Vec::new();
    let mut marker_claims = Vec::new();
    let collect_marker_claims =
        panic_obligation_node_kind(tcx, view.root().kind(), config).is_none();
    for raw in probe_panic_evidence(tcx, view, config) {
        let edge = raw.endpoint;
        let kind = raw.details;
        let report_evidence = edge.origin().instance().is_some();
        let resolved = raw.resolve_paths(
            tcx,
            EffectKind::Panic,
            config.marker_probing,
            || {
                marker_index.blocks(effect_path_edge_ids_to_edge(view, edge, |node| {
                    panic_path_node_is_boundary(tcx, node, config)
                }))
            },
            |requirements| {
                if !report_evidence {
                    return Vec::new();
                }
                find_unsatisfied_effect_traces_to_edge_with(
                    view,
                    edge,
                    requirements,
                    |node| panic_path_node_is_boundary(tcx, node, config),
                    |edge_id, requirement| marker_index.satisfies(edge_id, requirement),
                )
            },
        );
        if collect_marker_claims {
            marker_claims.extend(
                resolved
                    .path_markers
                    .into_iter()
                    .map(|marker| (marker.key, marker.span, edge.id())),
            );
        }
        if !report_evidence {
            continue;
        }
        let decision = panic_path_decision(edge.id(), kind);
        for unresolved in resolved.unresolved_traces {
            evidence.push(PanicEvidence {
                edge_id: edge.id(),
                trace: unresolved.trace,
                kind,
                decision,
                missing_requirements: unresolved.missing_requirements,
            });
        }
    }
    suppress_resolved_callable_indirect_boundaries(graph, &mut evidence);

    PanicAnalysis {
        evidence,
        ambiguous_markers: collect_ambiguous_panic_markers(marker_claims),
        ambiguous_names,
    }
}

fn probe_panic_evidence<'view, 'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    config: &PanicConfig,
) -> Vec<EffectEvidence<ReachedEdge<'view, 'tcx>, PanicEvidenceKind>> {
    let mut evidence = Vec::new();
    for edge in view.edges() {
        let Some(kind) = classify_edge_without_marker(tcx, edge, config) else {
            continue;
        };
        let requirements = panic_evidence_requirements(tcx, kind, config);
        evidence.push(EffectEvidence {
            endpoint: edge,
            requirements,
            terminal_marker_spans: Vec::new(),
            details: kind,
        });
    }
    evidence
}

fn panic_path_decision(edge_id: ReachabilityEdgeId, kind: PanicEvidenceKind) -> EffectPathDecision {
    match kind {
        PanicEvidenceKind::PanicObligation { def_id } => EffectPathDecision::Obligation {
            edge_id: Some(edge_id),
            def_id,
        },
        PanicEvidenceKind::CompilerAssert
        | PanicEvidenceKind::PanicSink { .. }
        | PanicEvidenceKind::IndirectBoundary { .. } => EffectPathDecision::RawEffect,
    }
}

fn panic_evidence_requirements(
    tcx: TyCtxt<'_>,
    kind: PanicEvidenceKind,
    config: &PanicConfig,
) -> Vec<PanicRequirement> {
    match kind {
        PanicEvidenceKind::PanicObligation { def_id } => {
            panic_doc_summary(tcx, def_id, config).requirements
        }
        PanicEvidenceKind::CompilerAssert
        | PanicEvidenceKind::PanicSink { .. }
        | PanicEvidenceKind::IndirectBoundary { .. } => Vec::new(),
    }
}

fn collect_ambiguous_panic_markers(
    marker_claims: impl IntoIterator<Item = (MarkerBlockKey, Span, ReachabilityEdgeId)>,
) -> Vec<AmbiguousPanicMarker> {
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
    ambiguous_markers
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
pub(crate) fn trace_edges_until(
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
pub(crate) fn trigger_edge_id(
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

/// Stable plain-text description for cached evidence reasons.
#[must_use]
pub(crate) fn describe_panic_evidence_kind(tcx: TyCtxt<'_>, kind: &PanicEvidenceKind) -> String {
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

pub(crate) fn panic_path_node_is_boundary<'tcx>(
    tcx: TyCtxt<'tcx>,
    node: &ReachabilityNodeKind<'tcx>,
    config: &PanicConfig,
) -> bool {
    node_kind_is_ignored_namespace(tcx, node, config)
        || panic_obligation_node_kind(tcx, node, config).is_some()
}

#[must_use]
pub(crate) fn has_panic_docs(tcx: TyCtxt<'_>, def_id: DefId, config: &PanicConfig) -> bool {
    panic_doc_summary(tcx, def_id, config).has_docs
}

type PanicDocSummary = ContractDocSummary;

pub(crate) fn panic_doc_summary(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    config: &PanicConfig,
) -> PanicDocSummary {
    contract_doc_summary(
        tcx,
        def_id,
        EffectKind::Panic,
        &config.documentation_overrides,
    )
}

fn collect_ambiguous_panic_requirement_names<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    config: &PanicConfig,
) -> Vec<AmbiguousPanicRequirementName> {
    let graph = view.graph();
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
        let trace = PanicTrace::from_edge(edge);
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
