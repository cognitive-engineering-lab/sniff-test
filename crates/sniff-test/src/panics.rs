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
    ReachabilityEdge, ReachabilityEdgeId, ReachabilityEdgeKind, ReachabilityGraph,
    ReachabilityNodeKind, ReachabilitySnapshot, ReachedEdge, ReachedNode,
};
use rustc_hir::Attribute;
use rustc_hir::attrs::{AttributeKind, HasAttrs};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;

use crate::config::{PanicBoundaryPolicy, PanicConfig};
use crate::namespace::canonical_namespace;
use crate::source_markers::{
    PanicSatisfaction, normalize_requirement_name, span_panic_satisfactions,
};

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

/// Raw panic evidence found in the graph.
#[derive(Debug, Clone, Copy)]
pub enum PanicEvidenceKind {
    /// Compiler-generated MIR assert, such as bounds, overflow, or invalid shift checks.
    CompilerAssert,
    /// Direct call to a function documented or configured as panicable.
    PanicObligation { def_id: DefId },
    /// Direct call to a configured panic sink.
    PanicSink { def_id: DefId },
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
                PanicEvidenceKind::CompilerAssert | PanicEvidenceKind::PanicSink { .. } => {
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
    match node {
        ReachabilityNodeKind::Instance(instance) => {
            let def_id = instance.def_id();
            (!config.ignores_def(tcx, def_id)
                && config.panic_boundary_policy(tcx, def_id) != PanicBoundaryPolicy::PanicSink
                && has_panic_docs(tcx, def_id))
            .then_some(def_id)
        }
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::IndirectCall { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => None,
    }
}

#[must_use]
pub fn has_panic_docs(tcx: TyCtxt<'_>, def_id: DefId) -> bool {
    panic_doc_summary(tcx, def_id).has_panic_docs
}

#[must_use]
pub fn panic_requirements(tcx: TyCtxt<'_>, def_id: DefId) -> Vec<PanicRequirement> {
    panic_doc_summary(tcx, def_id).requirements
}

fn doc_comment(attr: &Attribute) -> Option<&str> {
    match attr {
        Attribute::Parsed(AttributeKind::DocComment { comment, .. }) => Some(comment.as_str()),
        Attribute::Parsed(_) | Attribute::Unparsed(_) => None,
    }
}

#[derive(Debug, Default)]
struct PanicDocSummary {
    has_panic_docs: bool,
    requirements: Vec<PanicRequirement>,
}

fn panic_doc_summary(tcx: TyCtxt<'_>, def_id: DefId) -> PanicDocSummary {
    parse_panic_doc_lines(
        HasAttrs::get_attrs(def_id, &tcx)
            .iter()
            .filter_map(doc_comment)
            .flat_map(str::lines),
    )
}

fn parse_panic_doc_lines<'a>(lines: impl IntoIterator<Item = &'a str>) -> PanicDocSummary {
    let mut summary = PanicDocSummary::default();
    let mut in_panics_section = false;

    for line in lines {
        if let Some(heading) = markdown_heading_text(line) {
            in_panics_section = line_has_panic_heading_text(heading);
            summary.has_panic_docs |= in_panics_section;
            continue;
        }

        if in_panics_section && let Some(requirement) = parse_panic_requirement_bullet(line) {
            summary.requirements.push(requirement);
        }
    }

    summary
}

fn parse_panic_requirement_bullet(line: &str) -> Option<PanicRequirement> {
    let line = line.trim_start();
    let body = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .or_else(|| line.strip_prefix("+ "))?;
    let (name, condition) = body.split_once(':')?;
    let name = name.trim();
    let condition = condition.trim();

    (!normalize_requirement_name(name).is_empty()).then(|| PanicRequirement {
        name: name.to_owned(),
        condition: condition.to_owned(),
    })
}

#[cfg(test)]
fn line_has_panic_heading(line: &str) -> bool {
    markdown_heading_text(line).is_some_and(line_has_panic_heading_text)
}

fn markdown_heading_text(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix('#')?;
    let rest = rest.trim_start_matches('#');
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }

    let heading = rest.trim();
    Some(heading.trim_end_matches([':', '-']).trim())
}

fn line_has_panic_heading_text(heading: &str) -> bool {
    matches!(
        heading.to_ascii_lowercase().as_str(),
        "panic" | "panics" | "panic(s)"
    )
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
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::IndirectCall { .. }
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
        ReachabilityNodeKind::Instance(instance)
            if matches!(
                edge.kind(),
                ReachabilityEdgeKind::DirectCall | ReachabilityEdgeKind::TailCall
            ) =>
        {
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
        ReachabilityNodeKind::Instance(_)
        | ReachabilityNodeKind::IndirectCall { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => None,
    }
}

fn edge_panic_marker_suppresses<'tcx>(
    tcx: TyCtxt<'tcx>,
    edge: &ReachabilityEdge,
    target: &ReachabilityNodeKind<'tcx>,
) -> bool {
    let satisfactions = span_panic_satisfactions(tcx, edge.span);
    if satisfactions.is_empty() {
        return false;
    }

    match target {
        ReachabilityNodeKind::Instance(instance) => {
            let requirements = panic_requirements(tcx, instance.def_id());
            requirements.is_empty() || panic_requirements_satisfied(&requirements, &satisfactions)
        }
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::IndirectCall { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => true,
    }
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

        assert!(summary.has_panic_docs);
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
