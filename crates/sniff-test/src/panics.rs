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
use crate::contracts::{ContractDocSummary, ContractRequirement, panic_contract_doc_summary};
use crate::effect_tracker::{EffectPathDecision, EffectTrace};
use crate::namespace::canonical_namespace;

#[derive(Debug, Clone)]
pub(crate) struct PanicAnalysis {
    pub evidence: Vec<PanicEvidence>,
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

/// Panic source discovered before comments and reachability paths are resolved.
#[derive(Debug, Clone)]
pub(crate) struct PanicSourceEvidence {
    pub(crate) edge_id: ReachabilityEdgeId,
    pub(crate) kind: PanicEvidenceKind,
    pub(crate) decision: EffectPathDecision,
    pub(crate) requirements: Vec<PanicRequirement>,
    /// Some graph bridge edges participate in marker attribution but do not
    /// represent a user-visible panic site.
    pub(crate) reportable: bool,
}

#[derive(Debug, Clone, Copy)]
enum PanicProbeKind {
    CompilerAssert,
    Call { def_id: DefId, indirect: bool },
    PanicSink { def_id: DefId },
    OpaqueIndirectCall,
}

#[must_use]
pub(crate) fn probe_panic_sources<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    config: &PanicConfig,
) -> Vec<PanicSourceEvidence> {
    let mut sources = Vec::new();
    for edge in view.edges() {
        let Some(probe) = probe_panic_edge(tcx, edge, config) else {
            continue;
        };
        let Some((kind, requirements)) = resolve_panic_probe(tcx, edge, probe, config) else {
            continue;
        };
        sources.push(PanicSourceEvidence {
            edge_id: edge.id(),
            kind,
            decision: panic_path_decision(edge.id(), kind),
            requirements,
            reportable: edge.origin().instance().is_some(),
        });
    }
    sources
}

fn resolve_panic_probe<'tcx>(
    tcx: TyCtxt<'tcx>,
    edge: ReachedEdge<'_, 'tcx>,
    probe: PanicProbeKind,
    config: &PanicConfig,
) -> Option<(PanicEvidenceKind, Vec<PanicRequirement>)> {
    let kind = match probe {
        PanicProbeKind::CompilerAssert => {
            let ReachabilityNodeKind::CompilerAssert { message, .. } = edge.target().kind() else {
                unreachable!("compiler-assert probe must target a compiler assert");
            };
            if compiler_assert_is_safety_precondition(tcx, edge, message, config) {
                return None;
            }
            PanicEvidenceKind::CompilerAssert
        }
        PanicProbeKind::PanicSink { def_id } => PanicEvidenceKind::PanicSink { def_id },
        PanicProbeKind::OpaqueIndirectCall => PanicEvidenceKind::IndirectBoundary { def_id: None },
        PanicProbeKind::Call { def_id, indirect } => {
            let summary = panic_doc_summary(tcx, def_id, config);
            if summary.has_docs {
                return Some((
                    PanicEvidenceKind::PanicObligation { def_id },
                    summary.requirements,
                ));
            }
            if indirect && config.panic_boundary_policy(tcx, def_id) == PanicBoundaryPolicy::Normal
            {
                PanicEvidenceKind::IndirectBoundary {
                    def_id: Some(def_id),
                }
            } else {
                return None;
            }
        }
    };
    Some((kind, Vec::new()))
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

pub(crate) fn suppress_resolved_callable_indirect_boundaries(
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

pub(crate) fn is_trusted_panic_obligation(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    config: &PanicConfig,
) -> bool {
    config.panic_boundary_policy(tcx, def_id) == PanicBoundaryPolicy::TrustedPanicObligation
}

type PanicDocSummary = ContractDocSummary;

pub(crate) fn panic_doc_summary(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    config: &PanicConfig,
) -> PanicDocSummary {
    panic_contract_doc_summary(tcx, def_id, &config.documentation_overrides)
}

pub(crate) fn collect_ambiguous_panic_requirement_names<'tcx>(
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

fn probe_panic_edge<'tcx>(
    tcx: TyCtxt<'tcx>,
    edge: ReachedEdge<'_, 'tcx>,
    config: &PanicConfig,
) -> Option<PanicProbeKind> {
    let target = edge.target().kind();
    match target {
        ReachabilityNodeKind::CompilerAssert { .. } => Some(PanicProbeKind::CompilerAssert),
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
                PanicBoundaryPolicy::PanicSink => Some(PanicProbeKind::PanicSink { def_id }),
                PanicBoundaryPolicy::TrustedPanicObligation | PanicBoundaryPolicy::Normal => {
                    Some(PanicProbeKind::Call {
                        def_id,
                        indirect: false,
                    })
                }
            }
        }
        ReachabilityNodeKind::IndirectCall { callee_ty } => {
            let Some(def_id) = indirect_callee_def_id(*callee_ty) else {
                // Opaque callable: nothing to descend into or consult.
                return Some(PanicProbeKind::OpaqueIndirectCall);
            };
            if config.ignores_def(tcx, def_id) {
                return None;
            }

            match config.panic_boundary_policy(tcx, def_id) {
                PanicBoundaryPolicy::PanicSink => Some(PanicProbeKind::PanicSink { def_id }),
                PanicBoundaryPolicy::TrustedPanicObligation | PanicBoundaryPolicy::Normal => {
                    Some(PanicProbeKind::Call {
                        def_id,
                        indirect: true,
                    })
                }
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
