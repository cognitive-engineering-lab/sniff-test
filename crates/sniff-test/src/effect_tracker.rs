//! Effect-independent reachability path tracking.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

use reachability::{
    ReachabilityEdgeId, ReachabilityNodeId, ReachabilityNodeKind, ReachabilityView, ReachedEdge,
    ReachedNode,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use crate::config::MarkerProbing;
use crate::contracts::EffectKind;
use crate::contracts::{
    ContractCheck, ContractRequirement, check_contract, normalize_requirement_name,
};
use crate::source_markers::{
    EffectMarkerBlock, MarkerBlockKey, effect_edge_marker_block, span_marker_block,
};

/// Source-level location of an effect detected inside one function body.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EffectSite {
    pub owner: DefId,
    pub span: Span,
}

/// Raw effect evidence before comment contracts are resolved.
pub(crate) struct EffectEvidence<Endpoint, Details> {
    pub(crate) endpoint: Endpoint,
    pub(crate) requirements: Vec<ContractRequirement>,
    pub(crate) terminal_marker_spans: Vec<Span>,
    pub(crate) details: Details,
}

impl<Endpoint, Details> EffectEvidence<Endpoint, Details> {
    pub(crate) fn resolve_paths(
        &self,
        tcx: TyCtxt<'_>,
        kind: EffectKind,
        probing: MarkerProbing,
        path_markers: impl FnOnce() -> Vec<EffectMarkerBlock>,
        find_unsatisfied: impl FnOnce(&[ContractRequirement]) -> Vec<UnsatisfiedEffectTrace>,
    ) -> ResolvedEffectPaths {
        resolve_effect_paths(
            tcx,
            kind,
            probing,
            &self.requirements,
            &self.terminal_marker_spans,
            path_markers,
            find_unsatisfied,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ResolvedEffectMarker {
    pub(crate) key: MarkerBlockKey,
    pub(crate) span: Span,
}

#[derive(Debug)]
pub(crate) struct EffectEvidenceResolution {
    pub(crate) contract: ContractCheck,
    pub(crate) markers: Vec<ResolvedEffectMarker>,
}

pub(crate) struct ResolvedEffectPaths {
    pub(crate) terminal_markers: Vec<ResolvedEffectMarker>,
    pub(crate) path_markers: Vec<ResolvedEffectMarker>,
    pub(crate) unresolved_traces: Vec<UnsatisfiedEffectTrace>,
}

pub(crate) struct EffectMarkerIndex {
    markers: HashMap<ReachabilityEdgeId, EffectMarkerBlock>,
}

impl EffectMarkerIndex {
    pub(crate) fn new(
        tcx: TyCtxt<'_>,
        view: ReachabilityView<'_, '_>,
        kind: EffectKind,
        probing: MarkerProbing,
    ) -> Self {
        let graph = view.graph();
        let markers = view
            .edges()
            .filter_map(|edge| {
                effect_edge_marker_block(tcx, graph, edge.edge(), kind, probing)
                    .map(|marker| (edge.id(), marker))
            })
            .collect();
        Self { markers }
    }

    pub(crate) fn blocks(
        &self,
        edge_ids: impl IntoIterator<Item = ReachabilityEdgeId>,
    ) -> Vec<EffectMarkerBlock> {
        edge_ids
            .into_iter()
            .filter_map(|edge_id| self.markers.get(&edge_id).cloned())
            .collect()
    }

    pub(crate) fn satisfies(&self, edge_id: ReachabilityEdgeId, requirement: Option<&str>) -> bool {
        self.markers.get(&edge_id).is_some_and(|marker| {
            marker
                .satisfactions
                .iter()
                .any(|satisfaction| satisfaction.satisfies_requirement(requirement))
        })
    }
}

pub(crate) fn resolve_effect_paths(
    tcx: TyCtxt<'_>,
    kind: EffectKind,
    probing: MarkerProbing,
    requirements: &[ContractRequirement],
    terminal_marker_spans: &[Span],
    path_markers: impl FnOnce() -> Vec<EffectMarkerBlock>,
    find_unsatisfied: impl FnOnce(&[ContractRequirement]) -> Vec<UnsatisfiedEffectTrace>,
) -> ResolvedEffectPaths {
    let terminal_markers = terminal_marker_spans
        .iter()
        .filter_map(|span| span_marker_block(tcx, *span, kind, probing))
        .collect::<Vec<_>>();
    let terminal = resolve_effect_evidence(requirements, &terminal_markers);
    let requirements = match terminal.contract {
        ContractCheck::Satisfied => {
            return ResolvedEffectPaths {
                terminal_markers: terminal.markers,
                path_markers: Vec::new(),
                unresolved_traces: Vec::new(),
            };
        }
        ContractCheck::MissingJustification => Vec::new(),
        ContractCheck::MissingRequirements(missing) => missing,
    };
    let path = resolve_effect_evidence(&requirements, &path_markers());
    let unresolved_traces = find_unsatisfied(&requirements);
    ResolvedEffectPaths {
        terminal_markers: terminal.markers,
        path_markers: path.markers,
        unresolved_traces,
    }
}

pub(crate) fn resolve_effect_evidence<'a>(
    requirements: &[ContractRequirement],
    markers: impl IntoIterator<Item = &'a EffectMarkerBlock>,
) -> EffectEvidenceResolution {
    let markers = markers.into_iter().collect::<Vec<_>>();
    let satisfactions = markers
        .iter()
        .flat_map(|marker| marker.satisfactions.iter().cloned())
        .collect::<Vec<_>>();
    let contract = check_contract(requirements, &satisfactions);
    let markers = markers
        .into_iter()
        .filter(|marker| marker_contributes_to_contract(marker, requirements))
        .map(|marker| ResolvedEffectMarker {
            key: marker.key,
            span: marker.span,
        })
        .collect();

    EffectEvidenceResolution { contract, markers }
}

fn marker_contributes_to_contract(
    marker: &EffectMarkerBlock,
    requirements: &[ContractRequirement],
) -> bool {
    if requirements.is_empty() {
        return marker
            .satisfactions
            .iter()
            .any(|satisfaction| satisfaction.satisfies_requirement(None));
    }
    requirements.iter().any(|requirement| {
        let normalized = normalize_requirement_name(&requirement.name);
        marker
            .satisfactions
            .iter()
            .any(|satisfaction| satisfaction.satisfies_requirement(Some(&normalized)))
    })
}

pub(crate) fn effect_path_edge_ids_to_edge<'view, 'tcx>(
    view: ReachabilityView<'view, 'tcx>,
    effect_edge: ReachedEdge<'view, 'tcx>,
    is_boundary: impl Fn(&ReachabilityNodeKind<'tcx>) -> bool + Copy,
) -> Vec<ReachabilityEdgeId> {
    effect_path_edge_ids_to_nodes(view, [effect_edge.target().id()], is_boundary, true)
}

pub(crate) fn effect_path_edge_ids_to_nodes<'view, 'tcx>(
    view: ReachabilityView<'view, 'tcx>,
    targets: impl IntoIterator<Item = ReachabilityNodeId>,
    is_boundary: impl Fn(&ReachabilityNodeKind<'tcx>) -> bool + Copy,
    permit_boundary_targets: bool,
) -> Vec<ReachabilityEdgeId> {
    if is_boundary(view.root().kind()) {
        return Vec::new();
    }
    let targets = targets
        .into_iter()
        .filter(|target| {
            permit_boundary_targets
                || view
                    .node(*target)
                    .is_some_and(|node| !is_boundary(node.kind()))
        })
        .collect::<Vec<_>>();
    let edges = view
        .edges()
        .map(|edge| (edge.id(), edge.source().id(), edge.target().id()))
        .collect::<Vec<_>>();
    edges_on_paths_to_targets(view.root().id(), &edges, targets, |_, target| {
        view.node(target)
            .is_some_and(|node| !is_boundary(node.kind()))
    })
}

fn edges_on_paths_to_targets<Node, Edge>(
    root: Node,
    edges: &[(Edge, Node, Node)],
    targets: impl IntoIterator<Item = Node>,
    permits_intermediate_target: impl Fn(Edge, Node) -> bool + Copy,
) -> Vec<Edge>
where
    Node: Copy + Eq + Hash,
    Edge: Copy,
{
    let targets = targets.into_iter().collect::<HashSet<_>>();
    let mut reached = HashSet::from([root]);
    loop {
        let mut changed = false;
        for &(edge, source, target) in edges {
            if targets.contains(&source)
                || !reached.contains(&source)
                || (!targets.contains(&target) && !permits_intermediate_target(edge, target))
            {
                continue;
            }
            changed |= reached.insert(target);
        }
        if !changed {
            break;
        }
    }

    let mut reaches_target = targets.clone();
    loop {
        let mut changed = false;
        for &(edge, source, target) in edges.iter().rev() {
            if !reached.contains(&source)
                || !reaches_target.contains(&target)
                || (!targets.contains(&target) && !permits_intermediate_target(edge, target))
            {
                continue;
            }
            changed |= reaches_target.insert(source);
        }
        if !changed {
            break;
        }
    }

    edges
        .iter()
        .filter_map(|&(edge, source, target)| {
            (reached.contains(&source)
                && reaches_target.contains(&target)
                && !targets.contains(&source)
                && (targets.contains(&target) || permits_intermediate_target(edge, target)))
            .then_some(edge)
        })
        .collect()
}

#[derive(Debug)]
pub(crate) struct AmbiguousMarkerUse<Group> {
    pub(crate) marker_span: Span,
    pub(crate) groups: Vec<Group>,
}

pub(crate) fn ambiguous_marker_uses<Group>(
    claims: impl IntoIterator<Item = (MarkerBlockKey, Span, Group)>,
) -> Vec<AmbiguousMarkerUse<Group>>
where
    Group: Copy + Eq + Hash,
{
    let mut uses: HashMap<MarkerBlockKey, (Span, Vec<Group>)> = HashMap::new();
    for (key, marker_span, group) in claims {
        let groups = &mut uses.entry(key).or_insert((marker_span, Vec::new())).1;
        if !groups.contains(&group) {
            groups.push(group);
        }
    }

    uses.into_values()
        .filter_map(|(marker_span, groups)| {
            (groups.len() > 1).then_some(AmbiguousMarkerUse {
                marker_span,
                groups,
            })
        })
        .collect()
}

/// Edge-id trace from one report root to an effect site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectTrace {
    pub edge_ids: Vec<ReachabilityEdgeId>,
}

impl EffectTrace {
    pub(crate) fn from_edge(edge: ReachedEdge<'_, '_>) -> Self {
        let mut trace = Self::from_node(edge.source());
        trace.edge_ids.push(edge.id());
        trace
    }

    pub(crate) fn from_node(mut node: ReachedNode<'_, '_>) -> Self {
        let mut edge_ids = Vec::new();
        while let Some(edge) = node.predecessor_edge() {
            edge_ids.push(edge.id());
            node = edge.source();
        }
        edge_ids.reverse();
        Self { edge_ids }
    }
}

#[derive(Debug)]
pub(crate) struct UnsatisfiedEffectTrace {
    pub(crate) trace: EffectTrace,
    pub(crate) missing_requirements: Vec<ContractRequirement>,
}

pub(crate) fn find_effect_trace<'view, 'tcx>(
    view: ReachabilityView<'view, 'tcx>,
    mut is_target: impl FnMut(ReachedNode<'view, 'tcx>) -> bool,
    mut permits_edge: impl FnMut(ReachedEdge<'view, 'tcx>) -> bool,
) -> Option<EffectTrace> {
    if is_target(view.root()) {
        return Some(EffectTrace {
            edge_ids: Vec::new(),
        });
    }

    let mut seen = HashSet::from([view.root().id()]);
    let mut predecessors = HashMap::new();
    let mut queue = VecDeque::from([view.root().id()]);
    while let Some(node) = queue.pop_front() {
        for edge in view.outgoing_edges(node) {
            if !permits_edge(edge) {
                continue;
            }
            let target = edge.target();
            if !seen.insert(target.id()) {
                continue;
            }
            predecessors.insert(target.id(), edge.id());
            if is_target(target) {
                return Some(EffectTrace {
                    edge_ids: reconstruct_trace(view, &predecessors, target.id()),
                });
            }
            queue.push_back(target.id());
        }
    }

    None
}

fn reconstruct_trace(
    view: ReachabilityView<'_, '_>,
    predecessors: &HashMap<ReachabilityNodeId, ReachabilityEdgeId>,
    mut node: ReachabilityNodeId,
) -> Vec<ReachabilityEdgeId> {
    let mut edge_ids = Vec::new();
    while node != view.root().id() {
        let edge_id = predecessors[&node];
        edge_ids.push(edge_id);
        node = view.graph().edge(edge_id).source;
    }
    edge_ids.reverse();
    edge_ids
}

pub(crate) fn find_unsatisfied_effect_traces_to_edge_with<'view, 'tcx>(
    view: ReachabilityView<'view, 'tcx>,
    effect_edge: ReachedEdge<'view, 'tcx>,
    requirements: &[ContractRequirement],
    is_boundary: impl Fn(&ReachabilityNodeKind<'tcx>) -> bool + Copy,
    marker_satisfies: impl Fn(ReachabilityEdgeId, Option<&str>) -> bool + Copy,
) -> Vec<UnsatisfiedEffectTrace> {
    unsatisfied_effect_traces(
        requirements,
        |requirement| {
            find_effect_trace_to_edge_with(
                view,
                effect_edge,
                |edge| {
                    !is_boundary(edge.target().kind()) && !marker_satisfies(edge.id(), requirement)
                },
                |root| !is_boundary(root),
                |edge| !marker_satisfies(edge.id(), requirement),
            )
        },
        marker_satisfies,
    )
}

pub(crate) fn find_effect_trace_to_edge<'view, 'tcx>(
    view: ReachabilityView<'view, 'tcx>,
    effect_edge: ReachedEdge<'view, 'tcx>,
    is_boundary: impl Fn(&ReachabilityNodeKind<'tcx>) -> bool + Copy,
) -> Option<EffectTrace> {
    find_effect_trace_to_edge_with(
        view,
        effect_edge,
        |edge| !is_boundary(edge.target().kind()),
        |root| !is_boundary(root),
        |_| true,
    )
}

fn find_effect_trace_to_edge_with<'view, 'tcx>(
    view: ReachabilityView<'view, 'tcx>,
    effect_edge: ReachedEdge<'view, 'tcx>,
    mut permits_edge: impl FnMut(ReachedEdge<'view, 'tcx>) -> bool,
    mut permits_root: impl FnMut(&ReachabilityNodeKind<'tcx>) -> bool,
    mut permits_effect_edge: impl FnMut(ReachedEdge<'view, 'tcx>) -> bool,
) -> Option<EffectTrace> {
    if !permits_root(view.root().kind()) {
        return None;
    }
    let mut trace = find_effect_trace(
        view,
        |node| node.id() == effect_edge.source().id(),
        &mut permits_edge,
    )?;
    if !permits_effect_edge(effect_edge) {
        return None;
    }
    trace.edge_ids.push(effect_edge.id());
    Some(trace)
}

pub(crate) fn find_unsatisfied_effect_traces_with<'view, 'tcx>(
    view: ReachabilityView<'view, 'tcx>,
    is_target: impl FnMut(ReachedNode<'view, 'tcx>) -> bool + Copy,
    requirements: &[ContractRequirement],
    is_boundary: impl Fn(&ReachabilityNodeKind<'tcx>) -> bool + Copy,
    marker_satisfies: impl Fn(ReachabilityEdgeId, Option<&str>) -> bool + Copy,
) -> Vec<UnsatisfiedEffectTrace> {
    if is_boundary(view.root().kind()) {
        return Vec::new();
    }
    unsatisfied_effect_traces(
        requirements,
        |requirement| {
            find_effect_trace(view, is_target, |edge| {
                !is_boundary(edge.target().kind()) && !marker_satisfies(edge.id(), requirement)
            })
        },
        marker_satisfies,
    )
}

fn unsatisfied_effect_traces(
    requirements: &[ContractRequirement],
    mut find_trace: impl FnMut(Option<&str>) -> Option<EffectTrace>,
    marker_satisfies: impl Fn(ReachabilityEdgeId, Option<&str>) -> bool + Copy,
) -> Vec<UnsatisfiedEffectTrace> {
    deduplicate_unsatisfied_traces(unresolved_requirement_names(requirements).filter_map(
        |requirement| {
            let trace = find_trace(requirement.as_deref())?;
            Some(UnsatisfiedEffectTrace {
                missing_requirements: missing_requirements_on_trace(
                    &trace,
                    requirements,
                    marker_satisfies,
                ),
                trace,
            })
        },
    ))
}

fn deduplicate_unsatisfied_traces(
    traces: impl IntoIterator<Item = UnsatisfiedEffectTrace>,
) -> Vec<UnsatisfiedEffectTrace> {
    let mut unique = Vec::<UnsatisfiedEffectTrace>::new();
    for trace in traces {
        if unique.iter().any(|existing| {
            existing.trace == trace.trace
                && existing.missing_requirements == trace.missing_requirements
        }) {
            continue;
        }
        unique.push(trace);
    }
    unique
}

fn missing_requirements_on_trace(
    trace: &EffectTrace,
    requirements: &[ContractRequirement],
    marker_satisfies: impl Fn(ReachabilityEdgeId, Option<&str>) -> bool,
) -> Vec<ContractRequirement> {
    requirements
        .iter()
        .filter(|requirement| {
            let normalized_name = normalize_requirement_name(&requirement.name);
            !trace
                .edge_ids
                .iter()
                .any(|edge_id| marker_satisfies(*edge_id, Some(&normalized_name)))
        })
        .cloned()
        .collect()
}

fn unresolved_requirement_names(
    requirements: &[ContractRequirement],
) -> impl Iterator<Item = Option<String>> {
    let mut names = if requirements.is_empty() {
        vec![None]
    } else {
        requirements
            .iter()
            .map(|requirement| Some(normalize_requirement_name(&requirement.name)))
            .collect::<Vec<_>>()
    };
    names.sort();
    names.dedup();
    names.into_iter()
}

/// How an effect path reaches the selected report root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EffectPathDecision {
    /// No documented or configured obligation stopped this path.
    RawEffect,
    /// The path reached a function boundary that declares the effect.
    Obligation {
        edge_id: Option<ReachabilityEdgeId>,
        def_id: DefId,
    },
}

#[cfg(test)]
mod tests {
    use rustc_span::DUMMY_SP;

    use crate::contracts::{ContractCheck, ContractRequirement, MarkerSatisfaction};
    use crate::source_markers::{EffectMarkerBlock, MarkerBlockKey};

    use super::{edges_on_paths_to_targets, resolve_effect_evidence};

    #[test]
    fn path_edge_collection_includes_all_converging_routes() {
        let edges = [(10, 0, 1), (11, 0, 2), (12, 1, 3), (13, 2, 3), (14, 2, 4)];

        let path_edges = edges_on_paths_to_targets(0, &edges, [3], |_, _| true);

        assert_eq!(path_edges, vec![10, 11, 12, 13]);
    }

    #[test]
    fn path_edge_collection_stops_at_intermediate_boundaries() {
        let edges = [(10, 0, 1), (11, 1, 2), (12, 2, 3)];

        let path_edges = edges_on_paths_to_targets(0, &edges, [3], |_, target| target != 2);

        assert!(path_edges.is_empty());
    }

    #[test]
    fn path_edge_collection_allows_the_effect_edge_to_enter_a_boundary() {
        let edges = [(10, 0, 1), (11, 1, 2)];

        let path_edges = edges_on_paths_to_targets(0, &edges, [2], |_, target| target != 2);

        assert_eq!(path_edges, vec![10, 11]);
    }

    #[test]
    fn evidence_resolution_checks_named_requirements_and_returns_claimed_markers() {
        let marker = EffectMarkerBlock {
            key: MarkerBlockKey {
                file_start: 1,
                start_line: 2,
                end_line: 3,
            },
            span: DUMMY_SP,
            satisfactions: vec![MarkerSatisfaction {
                requirement: Some(String::from("valid_ptr")),
                reason: String::from("checked by the caller"),
            }],
        };
        let resolution = resolve_effect_evidence(
            &[ContractRequirement {
                name: String::from("valid_ptr"),
                condition: String::from("pointer must be valid"),
                span: DUMMY_SP,
            }],
            [&marker],
        );

        assert_eq!(resolution.contract, ContractCheck::Satisfied);
        assert_eq!(resolution.markers.len(), 1);
        assert_eq!(resolution.markers[0].key, marker.key);
    }

    #[test]
    fn unresolved_evidence_does_not_claim_markers() {
        let marker = EffectMarkerBlock {
            key: MarkerBlockKey {
                file_start: 1,
                start_line: 2,
                end_line: 3,
            },
            span: DUMMY_SP,
            satisfactions: Vec::new(),
        };
        let resolution = resolve_effect_evidence(&[], [&marker]);

        assert_eq!(resolution.contract, ContractCheck::MissingJustification);
        assert!(resolution.markers.is_empty());
    }

    #[test]
    fn evidence_resolution_claims_only_markers_that_satisfy_the_contract() {
        let unrelated = EffectMarkerBlock {
            key: MarkerBlockKey {
                file_start: 1,
                start_line: 2,
                end_line: 3,
            },
            span: DUMMY_SP,
            satisfactions: vec![MarkerSatisfaction {
                requirement: Some(String::from("initialized")),
                reason: String::from("initialized by the caller"),
            }],
        };
        let relevant = EffectMarkerBlock {
            key: MarkerBlockKey {
                file_start: 1,
                start_line: 4,
                end_line: 5,
            },
            span: DUMMY_SP,
            satisfactions: vec![MarkerSatisfaction {
                requirement: Some(String::from("valid_ptr")),
                reason: String::from("validated by the caller"),
            }],
        };
        let resolution = resolve_effect_evidence(
            &[ContractRequirement {
                name: String::from("valid_ptr"),
                condition: String::from("pointer must be valid"),
                span: DUMMY_SP,
            }],
            [&unrelated, &relevant],
        );

        assert_eq!(resolution.contract, ContractCheck::Satisfied);
        assert_eq!(resolution.markers.len(), 1);
        assert_eq!(resolution.markers[0].key, relevant.key);
    }

    #[test]
    fn evidence_resolution_claims_markers_that_partially_satisfy_the_contract() {
        let marker = EffectMarkerBlock {
            key: MarkerBlockKey {
                file_start: 1,
                start_line: 2,
                end_line: 3,
            },
            span: DUMMY_SP,
            satisfactions: vec![MarkerSatisfaction {
                requirement: Some(String::from("initialized")),
                reason: String::from("initialized by the caller"),
            }],
        };
        let resolution = resolve_effect_evidence(
            &[
                ContractRequirement {
                    name: String::from("initialized"),
                    condition: String::from("memory must be initialized"),
                    span: DUMMY_SP,
                },
                ContractRequirement {
                    name: String::from("valid_ptr"),
                    condition: String::from("pointer must be valid"),
                    span: DUMMY_SP,
                },
            ],
            [&marker],
        );

        assert!(matches!(
            resolution.contract,
            ContractCheck::MissingRequirements(_)
        ));
        assert_eq!(resolution.markers.len(), 1);
        assert_eq!(resolution.markers[0].key, marker.key);
    }
}
