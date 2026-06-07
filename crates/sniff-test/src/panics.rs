//! Panic evidence classification over a reachability graph.
//!
//! The reachability crate records graph structure. This module interprets edges
//! and nodes as panic evidence:
//!
//! - compiler assert nodes are direct panic evidence;
//! - calls to configured panic sink namespaces are direct panic evidence;
//! - calls through functions documented with `# Panics`, or configured as panic
//!   obligations, can stop propagation depending on caller trust policy.

use reachability::{
    ReachabilityEdge, ReachabilityEdgeKind, ReachabilityGraph, ReachabilityNodeId,
    ReachabilityNodeKind,
};
use rustc_hir::Attribute;
use rustc_hir::attrs::{AttributeKind, HasAttrs};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;

use crate::config::PanicConfig;
use crate::namespace::canonical_namespace;

#[derive(Debug, Clone)]
pub struct PanicAnalysis {
    pub evidence: Vec<PanicEvidence>,
}

#[derive(Debug, Clone)]
pub struct PanicEvidence {
    /// Edge that directly triggered this evidence before report-local adjustment.
    pub edge_index: usize,
    /// Reachability path from the root to the triggering edge.
    pub trace: PanicTrace,
    /// Raw reason found in MIR/reachability data.
    pub kind: PanicEvidenceKind,
    /// Policy decision for whether this propagates as a raw panic path.
    pub decision: PanicPathDecision,
}

/// Edge-index trace through a reachability graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanicTrace {
    pub edge_indices: Vec<usize>,
}

/// Raw panic evidence found in the graph.
#[derive(Debug, Clone)]
pub enum PanicEvidenceKind {
    /// Compiler-generated MIR assert, such as bounds, overflow, or invalid shift checks.
    CompilerAssert,
    /// Direct call to a configured panic sink.
    PanicSink { def_id: DefId },
}

/// Propagation decision for one panic evidence path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanicPathDecision {
    /// No documented/configured obligation stopped this path.
    RawPanic,
    /// The path reached a function boundary that documents or declares panic behavior.
    PanicObligation {
        edge_index: Option<usize>,
        def_id: DefId,
    },
}

#[must_use]
pub fn analyze_panic_evidence<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    config: &PanicConfig,
) -> PanicAnalysis {
    let predecessor_edges = predecessor_edges(graph);
    let evidence = graph
        .edges()
        .iter()
        .enumerate()
        .filter_map(|(edge_index, edge)| {
            let kind = classify_edge(tcx, graph, edge, config)?;
            let trace = PanicTrace {
                edge_indices: trace_to_edge_indices_with_predecessors(
                    graph,
                    &predecessor_edges,
                    edge_index,
                ),
            };
            if trace_crosses_ignored_namespace(tcx, graph, &trace, config) {
                return None;
            }
            let decision = classify_panic_path(tcx, graph, &trace, config);

            Some(PanicEvidence {
                edge_index,
                trace,
                kind,
                decision,
            })
        })
        .collect();

    PanicAnalysis { evidence }
}

/// Returns the evidence trace up to and including `edge_index`.
#[must_use]
pub fn trace_edges_until(evidence: &PanicEvidence, edge_index: Option<usize>) -> Vec<usize> {
    let Some(edge_index) = edge_index else {
        return Vec::new();
    };
    let Some(position) = evidence
        .trace
        .edge_indices
        .iter()
        .position(|trace_edge_index| *trace_edge_index == edge_index)
    else {
        return evidence.trace.edge_indices.clone();
    };

    evidence.trace.edge_indices[..=position].to_vec()
}

/// Chooses the edge to show as the local trigger for an evidence path.
///
/// Reports prefer the last edge whose source is local, because dependency
/// internals can otherwise hide the current-crate call site that matters most.
#[must_use]
pub fn trigger_edge_index(graph: &ReachabilityGraph<'_>, evidence: &PanicEvidence) -> usize {
    evidence
        .trace
        .edge_indices
        .iter()
        .copied()
        .rev()
        .find(|edge_index| {
            matches!(
                &graph.nodes()[graph.edges()[*edge_index].source.index()].kind,
                ReachabilityNodeKind::Instance(instance) if instance.def_id().is_local()
            )
        })
        .unwrap_or(evidence.edge_index)
}

/// Returns the graph trace up to and including `edge_index`.
#[must_use]
pub fn trace_to_edge_indices(graph: &ReachabilityGraph<'_>, edge_index: usize) -> Vec<usize> {
    let predecessor_edges = predecessor_edges(graph);
    trace_to_edge_indices_with_predecessors(graph, &predecessor_edges, edge_index)
}

/// Stable plain-text description for cached evidence reasons.
#[must_use]
pub fn describe_panic_evidence_kind(tcx: TyCtxt<'_>, kind: &PanicEvidenceKind) -> String {
    match kind {
        PanicEvidenceKind::CompilerAssert => String::from("compiler assert"),
        PanicEvidenceKind::PanicSink { def_id } => {
            format!("panic sink {}", canonical_namespace(tcx, *def_id))
        }
    }
}

fn classify_panic_path<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    trace: &PanicTrace,
    config: &PanicConfig,
) -> PanicPathDecision {
    if let Some(def_id) = panic_obligation_instance_node(tcx, graph, graph.root(), config) {
        return PanicPathDecision::PanicObligation {
            edge_index: None,
            def_id,
        };
    }

    for edge_index in &trace.edge_indices {
        let edge = &graph.edges()[*edge_index];
        if let Some(def_id) = panic_obligation_instance_node(tcx, graph, edge.target, config) {
            return PanicPathDecision::PanicObligation {
                edge_index: Some(*edge_index),
                def_id,
            };
        }
    }

    PanicPathDecision::RawPanic
}

fn panic_obligation_instance_node<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    node: ReachabilityNodeId,
    config: &PanicConfig,
) -> Option<DefId> {
    match &graph.nodes()[node.index()].kind {
        ReachabilityNodeKind::Instance(instance) => {
            let def_id = instance.def_id();
            let crate_name = tcx.crate_name(def_id.krate).to_string();
            let path = canonical_namespace(tcx, def_id);
            (!config.ignores_namespace(&crate_name)
                && !config.ignores_namespace(&path)
                && (has_panic_docs(tcx, def_id) || config.marks_panic_obligation_function(&path)))
            .then_some(def_id)
        }
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::IndirectCall { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => None,
    }
}

#[must_use]
pub fn has_panic_docs(tcx: TyCtxt<'_>, def_id: DefId) -> bool {
    HasAttrs::get_attrs(def_id, &tcx)
        .iter()
        .filter_map(doc_comment)
        .any(doc_has_panic_heading)
}

fn doc_comment(attr: &Attribute) -> Option<&str> {
    match attr {
        Attribute::Parsed(AttributeKind::DocComment { comment, .. }) => Some(comment.as_str()),
        Attribute::Parsed(_) | Attribute::Unparsed(_) => None,
    }
}

fn doc_has_panic_heading(doc: &str) -> bool {
    doc.lines().any(line_has_panic_heading)
}

fn line_has_panic_heading(line: &str) -> bool {
    let Some(rest) = line.trim_start().strip_prefix('#') else {
        return false;
    };
    let rest = rest.trim_start_matches('#');
    if !rest.starts_with(char::is_whitespace) {
        return false;
    }

    let heading = rest.trim();
    let heading = heading.trim_end_matches([':', '-']).trim();

    matches!(
        heading.to_ascii_lowercase().as_str(),
        "panic" | "panics" | "panic(s)"
    )
}

fn predecessor_edges(graph: &ReachabilityGraph<'_>) -> Vec<Option<usize>> {
    let mut reached = vec![false; graph.nodes().len()];
    let mut predecessors = vec![None; graph.nodes().len()];
    reached[graph.root().index()] = true;

    for (edge_index, edge) in graph.edges().iter().enumerate() {
        let source_index = edge.source.index();
        let target_index = edge.target.index();
        if reached[source_index] && !reached[target_index] {
            reached[target_index] = true;
            predecessors[target_index] = Some(edge_index);
        }
    }

    predecessors
}

fn trace_to_edge_indices_with_predecessors(
    graph: &ReachabilityGraph<'_>,
    predecessor_edges: &[Option<usize>],
    edge_index: usize,
) -> Vec<usize> {
    let mut edge_indices =
        trace_to_node(graph, predecessor_edges, graph.edges()[edge_index].source);
    edge_indices.push(edge_index);
    edge_indices
}

fn trace_to_node(
    graph: &ReachabilityGraph<'_>,
    predecessor_edges: &[Option<usize>],
    mut node: ReachabilityNodeId,
) -> Vec<usize> {
    let mut edge_indices = Vec::new();
    while node != graph.root() {
        let Some(edge_index) = predecessor_edges[node.index()] else {
            break;
        };
        edge_indices.push(edge_index);
        node = graph.edges()[edge_index].source;
    }
    edge_indices.reverse();
    edge_indices
}

fn trace_crosses_ignored_namespace<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    trace: &PanicTrace,
    config: &PanicConfig,
) -> bool {
    trace.edge_indices.iter().any(|edge_index| {
        let edge = &graph.edges()[*edge_index];
        node_is_ignored_namespace(tcx, graph, edge.source, config)
            || node_is_ignored_namespace(tcx, graph, edge.target, config)
    })
}

fn node_is_ignored_namespace<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    node: ReachabilityNodeId,
    config: &PanicConfig,
) -> bool {
    match &graph.nodes()[node.index()].kind {
        ReachabilityNodeKind::Instance(instance) => {
            let def_id = instance.def_id();
            let crate_name = tcx.crate_name(def_id.krate).to_string();
            let path = canonical_namespace(tcx, def_id);
            config.ignores_namespace(&crate_name) || config.ignores_namespace(&path)
        }
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::IndirectCall { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => false,
    }
}

fn classify_edge<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge: &ReachabilityEdge,
    config: &PanicConfig,
) -> Option<PanicEvidenceKind> {
    let target = &graph.nodes()[edge.target.index()].kind;
    match target {
        ReachabilityNodeKind::CompilerAssert { .. } => Some(PanicEvidenceKind::CompilerAssert),
        ReachabilityNodeKind::Instance(instance)
            if matches!(
                edge.kind,
                ReachabilityEdgeKind::DirectCall | ReachabilityEdgeKind::TailCall
            ) =>
        {
            let def_id = instance.def_id();
            let crate_name = tcx.crate_name(def_id.krate).to_string();
            let path = canonical_namespace(tcx, def_id);
            (!config.ignores_namespace(&crate_name)
                && !config.ignores_namespace(&path)
                && config.marks_panic_sink_namespace(&path))
            .then_some(PanicEvidenceKind::PanicSink { def_id })
        }
        ReachabilityNodeKind::Instance(_)
        | ReachabilityNodeKind::IndirectCall { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::line_has_panic_heading;

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
}
