//! Effect-independent reachability path tracking.

use std::collections::HashMap;
use std::hash::Hash;

use reachability::{
    ReachabilityEdgeId, ReachabilityGraph, ReachabilityNodeKind, ReachedEdge, ReachedNode,
};
use rustc_hir::def_id::DefId;
use rustc_span::Span;

use crate::source_markers::MarkerBlockKey;

/// Source-level location of an effect detected inside one function body.
#[derive(Debug, Clone, Copy)]
pub struct EffectSite {
    pub owner: DefId,
    pub span: Span,
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
pub struct EffectTrace {
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
