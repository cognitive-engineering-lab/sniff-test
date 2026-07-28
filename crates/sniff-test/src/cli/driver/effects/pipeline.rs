//! Shared effect-probing pipeline contracts.
//!
//! Panic and safety keep ownership of their effect-specific policy. This module
//! names the behavior they share: discover sources, index applicable comments,
//! resolve paths, and emit an effect-specific result.

use reachability::{
    ReachabilityEdgeId, ReachabilityNodeId, ReachabilityNodeKind, ReachabilityView, ReachedEdge,
};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use crate::config::MarkerProbing;
use crate::contracts::ContractRequirement;
use crate::dependency_cache::DependencyAnalysisCache;
use crate::effect_tracker::{
    EffectMarkerIndex, EffectPathIndex, UnsatisfiedEffectTrace,
    find_unsatisfied_effect_traces_to_edge_with, find_unsatisfied_effect_traces_with,
};
use crate::report_roots::ReportRoot;
use crate::source_markers::{EffectMarkerBlock, MarkerBlockKey};

/// Inputs shared by every stage of one effect analysis over one graph view.
#[derive(Clone, Copy)]
pub(super) struct EffectCx<'view, 'tcx> {
    pub(super) tcx: TyCtxt<'tcx>,
    pub(super) root: ReportRoot<'tcx>,
    pub(super) view: ReachabilityView<'view, 'tcx>,
    pub(super) dependency_cache: &'view DependencyAnalysisCache,
    pub(super) marker_probing: MarkerProbing,
}

/// Stable identity for sources that belong to the same semantic effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct EffectGroupId(usize);

/// Allocates effect group identities in source discovery order.
#[derive(Debug, Default)]
pub(super) struct EffectGroupAllocator {
    next: usize,
}

impl EffectGroupAllocator {
    pub(super) fn allocate(&mut self) -> EffectGroupId {
        let group = EffectGroupId(self.next);
        self.next += 1;
        group
    }
}

/// Point where one effect source attaches to the reachability graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PathAnchor {
    nodes: Vec<ReachabilityNodeId>,
    terminal_edge: Option<ReachabilityEdgeId>,
}

impl PathAnchor {
    pub(super) fn from_nodes(nodes: impl IntoIterator<Item = ReachabilityNodeId>) -> Self {
        Self {
            nodes: nodes.into_iter().collect(),
            terminal_edge: None,
        }
    }

    pub(super) fn from_terminal_edge(edge: ReachedEdge<'_, '_>) -> Self {
        Self {
            nodes: vec![edge.source().id()],
            terminal_edge: Some(edge.id()),
        }
    }
}

/// Effect-specific payload attached to shared comment and path information.
#[derive(Debug, Clone)]
pub(super) struct EffectSource<S> {
    pub(super) group: EffectGroupId,
    pub(super) anchor: PathAnchor,
    pub(super) terminal_marker_spans: Vec<Span>,
    pub(super) requirements: Vec<ContractRequirement>,
    pub(super) payload: S,
}

/// Marker use attributed to one semantic effect group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MarkerClaim {
    pub(super) key: MarkerBlockKey,
    pub(super) span: Span,
    pub(super) group: EffectGroupId,
}

/// Unsatisfied path associated with the source group that produced it.
#[derive(Debug)]
pub(super) struct UnresolvedEffect {
    pub(super) source: usize,
    pub(super) path: UnsatisfiedEffectTrace,
}

/// Comment and path indexes shared by all sources in one graph view.
pub(super) struct CommentIndex {
    markers: EffectMarkerIndex,
    paths: EffectPathIndex,
    paths_enabled: bool,
}

impl CommentIndex {
    pub(super) fn panic<'tcx>(
        tcx: TyCtxt<'tcx>,
        view: ReachabilityView<'_, 'tcx>,
        probing: MarkerProbing,
        is_boundary: impl Fn(&ReachabilityNodeKind<'tcx>) -> bool,
    ) -> Self {
        Self::new(
            view,
            EffectMarkerIndex::panic(tcx, view, probing),
            is_boundary,
        )
    }

    pub(super) fn safety<'tcx>(
        tcx: TyCtxt<'tcx>,
        view: ReachabilityView<'_, 'tcx>,
        probing: MarkerProbing,
        is_boundary: impl Fn(&ReachabilityNodeKind<'tcx>) -> bool,
    ) -> Self {
        Self::new(
            view,
            EffectMarkerIndex::safety(tcx, view, probing),
            is_boundary,
        )
    }

    fn new<'tcx>(
        view: ReachabilityView<'_, 'tcx>,
        markers: EffectMarkerIndex,
        is_boundary: impl Fn(&ReachabilityNodeKind<'tcx>) -> bool,
    ) -> Self {
        let paths_enabled = !is_boundary(view.root().kind());
        Self {
            markers,
            paths: EffectPathIndex::new(view, is_boundary),
            paths_enabled,
        }
    }

    /// Returns marker blocks on paths to the supplied anchor, including its
    /// terminal effect edge when present.
    pub(super) fn blocks(&self, anchor: &PathAnchor) -> Vec<EffectMarkerBlock> {
        let mut edge_ids = self
            .paths
            .edges_to_nodes(anchor.nodes.iter().copied(), false);
        if self.paths_enabled
            && let Some(terminal_edge) = anchor.terminal_edge
            && !edge_ids.contains(&terminal_edge)
        {
            edge_ids.push(terminal_edge);
        }
        self.markers.blocks(edge_ids)
    }

    pub(super) fn satisfies(&self, edge: ReachabilityEdgeId, requirement: Option<&str>) -> bool {
        self.markers.satisfies(edge, requirement)
    }
}

/// Effect sources after comments and reachability paths have been resolved.
pub(super) struct EffectResolution<S> {
    pub(super) sources: Vec<EffectSource<S>>,
    pub(super) marker_claims: Vec<MarkerClaim>,
    pub(super) unresolved: Vec<UnresolvedEffect>,
}

/// Behavior shared by effect implementations.
///
/// Snapshot planning, effect identity, and result projection remain outside
/// this contract. Callers decide which graph view to analyze and how resolved
/// sources become reports or cached findings.
pub(super) trait Effect<'tcx> {
    type Source;

    fn is_path_boundary(&self, cx: &EffectCx<'_, 'tcx>, node: &ReachabilityNodeKind<'tcx>) -> bool;

    fn probe_comments(&self, cx: &EffectCx<'_, 'tcx>) -> CommentIndex;

    fn probe_local_sources(&mut self, cx: &EffectCx<'_, 'tcx>) -> Vec<EffectSource<Self::Source>>;

    fn probe_dependency_sources(
        &mut self,
        cx: &EffectCx<'_, 'tcx>,
    ) -> Vec<EffectSource<Self::Source>>;
}

/// Runs source discovery and shared comment/path resolution for one graph view.
pub(super) fn resolve<'view, 'tcx, E>(
    effect: &mut E,
    cx: &EffectCx<'view, 'tcx>,
) -> EffectResolution<E::Source>
where
    E: Effect<'tcx>,
{
    let comments = effect.probe_comments(cx);
    let mut sources = effect.probe_local_sources(cx);
    sources.extend(effect.probe_dependency_sources(cx));

    resolve_sources(effect, cx, &comments, sources)
}

fn resolve_sources<'tcx, E>(
    effect: &E,
    cx: &EffectCx<'_, 'tcx>,
    comments: &CommentIndex,
    sources: Vec<EffectSource<E::Source>>,
) -> EffectResolution<E::Source>
where
    E: Effect<'tcx>,
{
    let mut marker_claims = Vec::new();
    let mut unresolved = Vec::new();

    for (source_index, source) in sources.iter().enumerate() {
        let resolved = comments.markers.resolve_paths(
            cx.tcx,
            &source.requirements,
            &source.terminal_marker_spans,
            || comments.blocks(&source.anchor),
            |requirements| {
                unresolved_paths_for_anchor(effect, cx, comments, &source.anchor, requirements)
            },
        );
        marker_claims.extend(
            resolved
                .terminal_markers
                .into_iter()
                .chain(resolved.path_markers)
                .map(|marker| MarkerClaim {
                    key: marker.key,
                    span: marker.span,
                    group: source.group,
                }),
        );
        unresolved.extend(
            resolved
                .unresolved_traces
                .into_iter()
                .map(|path| UnresolvedEffect {
                    source: source_index,
                    path,
                }),
        );
    }

    EffectResolution {
        sources,
        marker_claims,
        unresolved,
    }
}

fn unresolved_paths_for_anchor<'tcx, E>(
    effect: &E,
    cx: &EffectCx<'_, 'tcx>,
    comments: &CommentIndex,
    anchor: &PathAnchor,
    requirements: &[ContractRequirement],
) -> Vec<UnsatisfiedEffectTrace>
where
    E: Effect<'tcx>,
{
    if let Some(terminal_edge) = anchor.terminal_edge {
        let Some(edge) = cx.view.edges().find(|edge| edge.id() == terminal_edge) else {
            debug_assert!(
                false,
                "path anchor terminal edge is absent from its graph view"
            );
            return Vec::new();
        };
        debug_assert_eq!(
            anchor.nodes.as_slice(),
            [edge.source().id()],
            "terminal edge must start at its path anchor"
        );
        return find_unsatisfied_effect_traces_to_edge_with(
            cx.view,
            edge,
            requirements,
            |node| effect.is_path_boundary(cx, node),
            |edge, requirement| comments.satisfies(edge, requirement),
        );
    }

    let node_anchors = anchor
        .nodes
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    if node_anchors.is_empty() {
        Vec::new()
    } else {
        find_unsatisfied_effect_traces_with(
            cx.view,
            |node| node_anchors.contains(&node.id()),
            requirements,
            |node| effect.is_path_boundary(cx, node),
            |edge, requirement| comments.satisfies(edge, requirement),
        )
    }
}
