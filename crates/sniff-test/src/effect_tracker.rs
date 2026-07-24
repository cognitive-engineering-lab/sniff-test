//! Effect-independent reachability path tracking.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

use reachability::{
    ReachabilityEdgeId, ReachabilityGraph, ReachabilityNodeId, ReachabilityNodeKind,
    ReachabilityView, ReachedEdge, ReachedNode,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use crate::config::MarkerProbing;
use crate::contracts::EffectKind;
use crate::contracts::{
    ContractCheck, ContractRequirement, check_contract, normalize_requirement_name,
};
use crate::source_markers::{EffectMarkerBlock, MarkerBlockKey, span_marker_block};

/// Source-level location of an effect detected inside one function body.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EffectSite {
    pub owner: DefId,
    pub span: Span,
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
    let markers = if contract.is_satisfied() {
        markers
            .into_iter()
            .filter(|marker| marker_contributes_to_contract(marker, requirements))
            .map(|marker| ResolvedEffectMarker {
                key: marker.key,
                span: marker.span,
            })
            .collect()
    } else {
        Vec::new()
    };

    EffectEvidenceResolution { contract, markers }
}

fn marker_contributes_to_contract(
    marker: &EffectMarkerBlock,
    requirements: &[ContractRequirement],
) -> bool {
    marker.satisfactions.iter().any(|satisfaction| {
        if satisfaction.reason.trim().is_empty() {
            return false;
        }
        if requirements.is_empty() {
            return satisfaction.requirement.is_none();
        }
        satisfaction.requirement.as_deref().is_some_and(|name| {
            let normalized = normalize_requirement_name(name);
            requirements
                .iter()
                .any(|requirement| normalize_requirement_name(&requirement.name) == normalized)
        })
    })
}

pub(crate) fn resolved_trace_marker_claims<Group: Copy>(
    tcx: TyCtxt<'_>,
    graph: &ReachabilityGraph<'_>,
    trace: &EffectTrace,
    kind: EffectKind,
    probing: MarkerProbing,
    requirements: &[ContractRequirement],
    group: Group,
) -> Option<Vec<(MarkerBlockKey, Span, Group)>> {
    let markers = trace
        .edge_ids
        .iter()
        .filter_map(|edge_id| span_marker_block(tcx, graph.edge(*edge_id).span, kind, probing))
        .collect::<Vec<_>>();
    let resolution = resolve_effect_evidence(requirements, &markers);
    resolution.contract.is_satisfied().then(|| {
        resolution
            .markers
            .into_iter()
            .map(|marker| (marker.key, marker.span, group))
            .collect()
    })
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

pub(crate) fn find_unsatisfied_effect_traces_to_edge<'view, 'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    effect_edge: ReachedEdge<'view, 'tcx>,
    kind: EffectKind,
    probing: MarkerProbing,
    requirements: &[ContractRequirement],
    is_boundary: impl Fn(&ReachabilityNodeKind<'tcx>) -> bool + Copy,
) -> Vec<UnsatisfiedEffectTrace> {
    find_unsatisfied_effect_traces_to_edge_with(
        view,
        effect_edge,
        requirements,
        is_boundary,
        |edge_id, requirement| {
            edge_marker_satisfies(
                tcx,
                view.graph().edge(edge_id).span,
                kind,
                probing,
                requirement,
            )
        },
    )
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

pub(crate) fn find_unsatisfied_effect_traces<'view, 'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    is_target: impl FnMut(ReachedNode<'view, 'tcx>) -> bool + Copy,
    kind: EffectKind,
    probing: MarkerProbing,
    requirements: &[ContractRequirement],
    is_boundary: impl Fn(&ReachabilityNodeKind<'tcx>) -> bool + Copy,
) -> Vec<UnsatisfiedEffectTrace> {
    if is_boundary(view.root().kind()) {
        return Vec::new();
    }
    unsatisfied_effect_traces(
        requirements,
        |requirement| {
            find_effect_trace(view, is_target, |edge| {
                !is_boundary(edge.target().kind())
                    && !edge_marker_satisfies(tcx, edge.span(), kind, probing, requirement)
            })
        },
        |edge_id, requirement| {
            edge_marker_satisfies(
                tcx,
                view.graph().edge(edge_id).span,
                kind,
                probing,
                requirement,
            )
        },
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

fn edge_marker_satisfies(
    tcx: TyCtxt<'_>,
    span: Span,
    kind: EffectKind,
    probing: MarkerProbing,
    requirement: Option<&str>,
) -> bool {
    let Some(marker) = span_marker_block(tcx, span, kind, probing) else {
        return false;
    };
    marker.satisfactions.iter().any(|satisfaction| {
        !satisfaction.reason.trim().is_empty()
            && match requirement {
                Some(required) => satisfaction
                    .requirement
                    .as_deref()
                    .is_some_and(|name| normalize_requirement_name(name) == required),
                None => satisfaction.requirement.is_none(),
            }
    })
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

pub(crate) fn trace_to_edge(edge: ReachedEdge<'_, '_>) -> EffectTrace {
    let mut edge_ids = trace_to_node(edge.source());
    edge_ids.push(edge.id());
    EffectTrace { edge_ids }
}

pub(crate) fn trace_to_node(mut node: ReachedNode<'_, '_>) -> Vec<ReachabilityEdgeId> {
    let mut edge_ids = Vec::new();
    while let Some(edge) = node.predecessor_edge() {
        edge_ids.push(edge.id());
        node = edge.source();
    }
    edge_ids.reverse();
    edge_ids
}

#[cfg(test)]
mod tests {
    use rustc_span::DUMMY_SP;

    use crate::contracts::{ContractCheck, ContractRequirement, MarkerSatisfaction};
    use crate::source_markers::{EffectMarkerBlock, MarkerBlockKey};

    use super::resolve_effect_evidence;

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
}
