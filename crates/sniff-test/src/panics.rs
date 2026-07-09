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
    ReachabilityEdge, ReachabilityEdgeId, ReachabilityGraph, ReachabilityNodeKind,
    ReachabilitySnapshot, ReachedEdge, ReachedNode,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::{self, Ty, TyCtxt};
use rustc_span::Span;

use crate::config::{PanicBoundaryPolicy, PanicConfig};
use crate::contracts::{
    ContractDocSummary, ContractKind, ContractRequirement, contract_doc_summary,
    normalize_requirement_name,
};
use crate::namespace::canonical_namespace;
use crate::source_markers::{PanicSatisfaction, span_panic_satisfactions};

#[derive(Debug, Clone)]
pub struct PanicAnalysis {
    pub evidence: Vec<PanicEvidence>,
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

/// Edge-id trace through a reachability graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanicTrace {
    pub edge_ids: Vec<ReachabilityEdgeId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanicRequirement {
    pub name: String,
    pub condition: String,
}

impl From<ContractRequirement> for PanicRequirement {
    fn from(requirement: ContractRequirement) -> Self {
        Self {
            name: requirement.name,
            condition: requirement.condition,
        }
    }
}

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

#[must_use]
pub fn analyze_panic_evidence<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    result: &ReachabilitySnapshot<'tcx>,
    config: &PanicConfig,
) -> PanicAnalysis {
    let view = graph.view(result);
    let root = view.root();
    let mut seen_panic_obligations = HashSet::new();
    let evidence = view
        .edges()
        .filter_map(|edge| {
            let edge_id = edge.id();
            let kind = classify_edge(tcx, edge, config)?;
            let trace = PanicTrace {
                edge_ids: trace_to_edge_ids(edge),
            };
            if trace_crosses_satisfied_panic_marker(tcx, graph, &trace) {
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
        .collect();

    PanicAnalysis { evidence }
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
    let mut edge_ids = trace_to_node(edge.source());
    edge_ids.push(edge.id());
    edge_ids
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
    if let Some(def_id) = panic_obligation_node_kind(tcx, root.kind(), config) {
        return PanicPathDecision::PanicObligation {
            edge_id: None,
            def_id,
        };
    }

    for edge_id in &trace.edge_ids {
        let edge = graph.edge(*edge_id);
        let target = &graph.node(edge.target).kind;
        if let Some(def_id) = panic_obligation_node_kind(tcx, target, config) {
            return PanicPathDecision::PanicObligation {
                edge_id: Some(*edge_id),
                def_id,
            };
        }
    }

    PanicPathDecision::RawPanic
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
        && has_panic_docs(tcx, def_id))
    .then_some(def_id)
}

#[must_use]
pub fn has_panic_docs(tcx: TyCtxt<'_>, def_id: DefId) -> bool {
    panic_doc_summary(tcx, def_id).has_docs
}

#[must_use]
pub fn panic_requirements(tcx: TyCtxt<'_>, def_id: DefId) -> Vec<PanicRequirement> {
    panic_doc_summary(tcx, def_id).requirements
}

#[derive(Debug, Default)]
struct PanicDocSummary {
    has_docs: bool,
    requirements: Vec<PanicRequirement>,
}

impl From<ContractDocSummary> for PanicDocSummary {
    fn from(summary: ContractDocSummary) -> Self {
        Self {
            has_docs: summary.has_docs,
            requirements: summary
                .requirements
                .into_iter()
                .map(PanicRequirement::from)
                .collect(),
        }
    }
}

fn panic_doc_summary(tcx: TyCtxt<'_>, def_id: DefId) -> PanicDocSummary {
    contract_doc_summary(tcx, def_id, ContractKind::Panic).into()
}

#[cfg(test)]
fn line_has_panic_heading(line: &str) -> bool {
    crate::contracts::line_has_contract_heading(line, ContractKind::Panic)
}

#[cfg(test)]
fn parse_panic_doc_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> PanicDocSummary {
    crate::contracts::parse_contract_doc_lines(lines, ContractKind::Panic).into()
}

fn trace_to_node(mut node: ReachedNode<'_, '_>) -> Vec<ReachabilityEdgeId> {
    let mut edge_ids = Vec::new();
    while let Some(edge) = node.predecessor_edge() {
        let edge_id = edge.id();
        edge_ids.push(edge_id);
        node = edge.source();
    }
    edge_ids.reverse();
    edge_ids
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
) -> bool {
    trace.edge_ids.iter().any(|edge_id| {
        let edge = graph.edge(*edge_id);
        let target = &graph.node(edge.target).kind;
        edge_panic_marker_suppresses(tcx, edge, target)
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
) -> Option<PanicEvidenceKind> {
    let target = edge.target().kind();
    if edge_panic_marker_suppresses(tcx, edge.edge(), target) {
        return None;
    }

    match target {
        ReachabilityNodeKind::CompilerAssert { .. } => Some(PanicEvidenceKind::CompilerAssert),
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
                    has_panic_docs(tcx, def_id)
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
                PanicBoundaryPolicy::TrustedPanicObligation => has_panic_docs(tcx, def_id)
                    .then_some(PanicEvidenceKind::PanicObligation { def_id }),
                PanicBoundaryPolicy::Normal => Some(if has_panic_docs(tcx, def_id) {
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

fn edge_panic_marker_suppresses<'tcx>(
    tcx: TyCtxt<'tcx>,
    edge: &ReachabilityEdge,
    target: &ReachabilityNodeKind<'tcx>,
) -> bool {
    let satisfactions = edge_marker_satisfactions(tcx, edge);
    if satisfactions.is_empty() {
        return false;
    }

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
    let requirements = panic_requirements(tcx, contract_def_id);
    requirements.is_empty() || panic_requirements_satisfied(&requirements, &satisfactions)
}

/// Markers that justify a call edge.
///
/// Markers adjacent to the callee segment always apply, so a `// PANIC:`
/// between the links of a multi-line method chain justifies exactly its link.
/// Statement-level markers apply in full on single-line statements; on
/// multi-line chains an unnamed blanket marker above the statement cannot
/// single out one link, so only named satisfactions carry across lines.
fn edge_marker_satisfactions(tcx: TyCtxt<'_>, edge: &ReachabilityEdge) -> Vec<PanicSatisfaction> {
    let statement = span_panic_satisfactions(tcx, edge.span);
    let Some(callee_span) = edge.callee_span else {
        return statement;
    };
    if spans_start_on_same_line(tcx, edge.span, callee_span) {
        return statement;
    }

    span_panic_satisfactions(tcx, callee_span)
        .into_iter()
        .chain(
            statement
                .into_iter()
                .filter(|satisfaction| satisfaction.requirement.is_some()),
        )
        .collect()
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

fn panic_requirements_satisfied(
    requirements: &[PanicRequirement],
    satisfactions: &[PanicSatisfaction],
) -> bool {
    let satisfied_requirements = satisfactions
        .iter()
        .filter(|satisfaction| !satisfaction.reason.trim().is_empty())
        .filter_map(|satisfaction| satisfaction.requirement.as_deref())
        .map(normalize_requirement_name)
        .collect::<HashSet<_>>();

    requirements.iter().all(|requirement| {
        satisfied_requirements.contains(&normalize_requirement_name(&requirement.name))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        PanicRequirement, line_has_panic_heading, panic_requirements_satisfied,
        parse_panic_doc_lines,
    };
    use crate::source_markers::PanicSatisfaction;

    #[test]
    fn panic_doc_headings_match_supported_styles() {
        assert!(line_has_panic_heading("# Panics"));
        assert!(line_has_panic_heading("    ## Panics   "));
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
                },
                PanicRequirement {
                    name: String::from("index in bounds"),
                    condition: String::from("index must be within the slice"),
                },
                PanicRequirement {
                    name: String::from("something[var_1]"),
                    condition: String::new(),
                },
            ]
        );
    }

    #[test]
    fn all_named_requirements_must_be_satisfied() {
        let requirements = [
            PanicRequirement {
                name: String::from("index_in_bounds"),
                condition: String::from("index must be valid"),
            },
            PanicRequirement {
                name: String::from("nonzero"),
                condition: String::from("denominator must be nonzero"),
            },
            PanicRequirement {
                name: String::from("something[var_1]"),
                condition: String::new(),
            },
        ];
        let partial = [PanicSatisfaction {
            requirement: Some(String::from("index in bounds")),
            reason: String::from("checked"),
        }];
        let complete_with_empty_reason = [
            PanicSatisfaction {
                requirement: Some(String::from("index in bounds")),
                reason: String::from("checked"),
            },
            PanicSatisfaction {
                requirement: Some(String::from("nonzero")),
                reason: String::new(),
            },
            PanicSatisfaction {
                requirement: Some(String::from("something var_1")),
                reason: String::from("checked"),
            },
        ];
        let complete = [
            PanicSatisfaction {
                requirement: Some(String::from("index in bounds")),
                reason: String::from("checked"),
            },
            PanicSatisfaction {
                requirement: Some(String::from("nonzero")),
                reason: String::from("checked"),
            },
            PanicSatisfaction {
                requirement: Some(String::from("something var_1")),
                reason: String::from("checked"),
            },
        ];

        assert!(!panic_requirements_satisfied(&requirements, &partial));
        assert!(!panic_requirements_satisfied(
            &requirements,
            &complete_with_empty_reason
        ));
        assert!(panic_requirements_satisfied(&requirements, &complete));
    }
}
