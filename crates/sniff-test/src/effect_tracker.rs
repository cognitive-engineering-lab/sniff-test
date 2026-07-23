//! Effect-independent reachability path tracking.

use std::collections::HashMap;
use std::hash::Hash;

use reachability::{
    ReachabilityEdgeId, ReachabilityGraph, ReachabilityNodeKind, ReachedEdge, ReachedNode,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use crate::config::MarkerProbing;
use crate::contracts::EffectKind;
use crate::contracts::{ContractCheck, ContractRequirement, check_contract};
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

pub(crate) fn classify_effect_path<'tcx>(
    graph: &ReachabilityGraph<'tcx>,
    root: ReachedNode<'_, 'tcx>,
    trace: &EffectTrace,
    mut obligation_for_node: impl FnMut(&ReachabilityNodeKind<'tcx>) -> Option<DefId>,
) -> EffectPathDecision {
    if let Some(def_id) = obligation_for_node(root.kind()) {
        return EffectPathDecision::Obligation {
            edge_id: None,
            def_id,
        };
    }

    for edge_id in &trace.edge_ids {
        let edge = graph.edge(*edge_id);
        let target = &graph.node(edge.target).kind;
        if let Some(def_id) = obligation_for_node(target) {
            return EffectPathDecision::Obligation {
                edge_id: Some(*edge_id),
                def_id,
            };
        }
    }

    EffectPathDecision::RawEffect
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
}
