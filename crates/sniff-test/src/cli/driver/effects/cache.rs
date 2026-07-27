use std::collections::HashSet;

use reachability::{
    ReachabilityEdgeId, ReachabilityEdgeKind, ReachabilityNodeKind, ReachabilityView,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use crate::cache::{
    CachedEffectSummary, CachedFinding, CachedFindingTarget, CachedFunctionSummary,
};
use crate::cli::report::render_span;
use crate::contracts::{ContractRequirement, EffectKind};
use crate::dependency_cache::DependencyAnalysisCache;
use crate::effect_tracker::{
    EffectMarkerIndex, EffectPathIndex, EffectTrace, find_effect_trace_to_edge,
    find_unsatisfied_effect_traces_to_edge_with, resolve_effect_paths,
};
use crate::namespace::stable_def_path_hash;
use crate::source_markers::MarkerBlockKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct TraceEffectGroup {
    pub(super) boundary_edge: ReachabilityEdgeId,
    pub(super) finding: usize,
    pub(super) span: Span,
}

type TraceMarkerClaim = (MarkerBlockKey, Span, TraceEffectGroup);

pub(super) struct UnresolvedCachedFinding<'cache> {
    pub(super) finding: &'cache CachedFinding,
    pub(super) trace: EffectTrace,
    pub(super) missing_requirements: Vec<ContractRequirement>,
}

struct ResolvedCachedEffect<'cache> {
    unresolved_findings: Vec<UnresolvedCachedFinding<'cache>>,
    marker_claims: Vec<TraceMarkerClaim>,
    has_raw_findings: bool,
}

pub(super) struct CachedEffectPropagation {
    pub(super) cached_findings: Vec<CachedFinding>,
    pub(super) analysis_complete: bool,
}

impl Default for CachedEffectPropagation {
    fn default() -> Self {
        Self {
            cached_findings: Vec::new(),
            analysis_complete: true,
        }
    }
}

pub(super) struct ResolvedCachedBoundary<'view, 'tcx, 'cache> {
    pub(super) edge: reachability::ReachedEdge<'view, 'tcx>,
    pub(super) function: &'cache CachedFunctionSummary,
    pub(super) effect: &'cache CachedEffectSummary,
    pub(super) trace: EffectTrace,
    pub(super) unresolved_findings: Vec<UnresolvedCachedFinding<'cache>>,
    pub(super) marker_claims: Vec<TraceMarkerClaim>,
    pub(super) has_raw_findings: bool,
}

struct CachedEffectBoundary<'view, 'tcx, 'cache> {
    edge: reachability::ReachedEdge<'view, 'tcx>,
    function: &'cache CachedFunctionSummary,
    effect: &'cache CachedEffectSummary,
}

fn dependency_boundary_edges<'view, 'tcx>(
    view: ReachabilityView<'view, 'tcx>,
) -> impl Iterator<Item = reachability::ReachedEdge<'view, 'tcx>> {
    let expanded_sources = view
        .edges()
        .map(|edge| edge.source().id().index())
        .collect::<HashSet<_>>();

    // Any edge into a non-expanded external instance — direct calls, vtable
    // entries, closure definitions, pointer reifications — reaches the cache
    // boundary. Macro-expansion edges are bridge hops rather than calls.
    view.edges().filter(move |edge| {
        edge.kind() != ReachabilityEdgeKind::MacroExpansion
            && !expanded_sources.contains(&edge.target().id().index())
    })
}

fn resolve_cached_effect_boundary<'tcx, 'cache>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    boundary: &CachedEffectBoundary<'_, 'tcx, 'cache>,
    marker_index: &EffectMarkerIndex,
    path_index: &EffectPathIndex,
    is_boundary: impl Fn(&ReachabilityNodeKind<'tcx>) -> bool + Copy,
) -> ResolvedCachedEffect<'cache> {
    let kind = marker_index.kind();
    let mut unresolved_findings = Vec::new();
    let mut marker_claims = Vec::new();
    let mut has_raw_findings = false;
    for (finding_index, finding) in boundary.effect.findings.iter().enumerate() {
        if finding.kind.effect() != Some(kind) {
            continue;
        }
        has_raw_findings |= finding.kind.is_raw_effect();
        let group = TraceEffectGroup {
            boundary_edge: boundary.edge.id(),
            finding: finding_index,
            span: boundary.edge.span(),
        };
        let resolved = resolve_effect_paths(
            tcx,
            kind,
            marker_index.probing(),
            &finding.missing_requirements,
            &[],
            || marker_index.blocks(path_index.edges_to_edge(boundary.edge)),
            |requirements| {
                find_unsatisfied_effect_traces_to_edge_with(
                    view,
                    boundary.edge,
                    requirements,
                    is_boundary,
                    |edge_id, requirement| marker_index.satisfies(edge_id, requirement),
                )
            },
        );
        marker_claims.extend(
            resolved
                .path_markers
                .into_iter()
                .map(|marker| (marker.key, marker.span, group)),
        );
        for unresolved in resolved.unresolved_traces {
            unresolved_findings.push(UnresolvedCachedFinding {
                finding,
                trace: unresolved.trace,
                missing_requirements: unresolved.missing_requirements,
            });
        }
    }
    ResolvedCachedEffect {
        unresolved_findings,
        marker_claims,
        has_raw_findings,
    }
}

pub(super) fn resolved_cached_effect_boundaries<'view, 'tcx, 'cache>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    cache: &'cache DependencyAnalysisCache,
    marker_index: &EffectMarkerIndex,
    path_index: &EffectPathIndex,
    ignores: impl FnMut(DefId) -> bool + 'cache,
    is_boundary: impl Fn(&ReachabilityNodeKind<'tcx>) -> bool + Copy,
) -> Vec<ResolvedCachedBoundary<'view, 'tcx, 'cache>> {
    let kind = marker_index.kind();
    propagating_cached_effect_boundaries(tcx, view, cache, kind, ignores)
        .filter_map(|cached| {
            let trace = find_effect_trace_to_edge(view, cached.edge, is_boundary)?;
            let resolved = resolve_cached_effect_boundary(
                tcx,
                view,
                &cached,
                marker_index,
                path_index,
                is_boundary,
            );
            Some(ResolvedCachedBoundary {
                edge: cached.edge,
                function: cached.function,
                effect: cached.effect,
                trace,
                unresolved_findings: resolved.unresolved_findings,
                marker_claims: resolved.marker_claims,
                has_raw_findings: resolved.has_raw_findings,
            })
        })
        .collect()
}

pub(super) fn rebase_cached_dependency_finding(
    tcx: TyCtxt<'_>,
    edge: reachability::ReachedEdge<'_, '_>,
    trace: &EffectTrace,
    summary: &CachedFunctionSummary,
    cached: &CachedFinding,
) -> Option<CachedFinding> {
    let def_id = edge.target().instance()?.def_id();
    let effect = cached.kind.effect()?;
    Some(CachedFinding {
        kind: cached.kind,
        span: render_span(tcx, edge.span()),
        source_span: cached.source_span.clone(),
        diagnostic_spans: cached.diagnostic_spans.clone(),
        edge_index: Some(edge.id().index()),
        trace: trace
            .edge_ids
            .iter()
            .map(|edge_id| edge_id.index())
            .collect(),
        dependency_trace: summary.effect_trace(effect, cached),
        reason: cached.reason.clone(),
        missing_requirements: cached.missing_requirements.clone(),
        target: Some(CachedFindingTarget::Function {
            path: summary.path.clone(),
            crate_name: tcx.crate_name(def_id.krate).to_string(),
            is_local: false,
        }),
    })
}

fn propagating_cached_effect_boundaries<'view, 'tcx, 'cache>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    cache: &'cache DependencyAnalysisCache,
    kind: EffectKind,
    mut ignores: impl FnMut(DefId) -> bool + 'cache,
) -> impl Iterator<Item = CachedEffectBoundary<'view, 'tcx, 'cache>> {
    dependency_boundary_edges(view).filter_map(move |edge| {
        let def_id = edge.target().instance()?.def_id();
        if def_id.is_local() || ignores(def_id) {
            return None;
        }
        let crate_name = tcx.crate_name(def_id.krate).to_string();
        let function = cache.function(&crate_name, &stable_def_path_hash(tcx, def_id))?;
        let effect = function.effect(kind)?;
        (!effect.has_contract && (effect.is_reachable() || !effect.analysis_complete)).then_some(
            CachedEffectBoundary {
                edge,
                function,
                effect,
            },
        )
    })
}
