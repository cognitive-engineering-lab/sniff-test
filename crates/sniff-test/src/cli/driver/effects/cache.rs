use std::collections::HashSet;

use reachability::{ReachabilityEdgeKind, ReachabilityView};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;

use crate::cache::{
    CachedEffectSummary, CachedFinding, CachedFindingTarget, CachedFunctionSummary,
};
use crate::cli::report::render_span;
use crate::dependency_cache::DependencyAnalysisCache;
use crate::effect_tracker::EffectTrace;
use crate::namespace::stable_def_path_hash;

pub(super) struct CachedEffectBoundary<'view, 'tcx, 'cache> {
    pub(super) edge: reachability::ReachedEdge<'view, 'tcx>,
    pub(super) function: &'cache CachedFunctionSummary,
    pub(super) effect: &'cache CachedEffectSummary,
}

fn dependency_boundary_edges<'view, 'tcx>(
    view: ReachabilityView<'view, 'tcx>,
) -> impl Iterator<Item = reachability::ReachedEdge<'view, 'tcx>> {
    let expanded_sources = view
        .edges()
        .map(|edge| edge.source().id().index())
        .collect::<HashSet<_>>();

    // Any edge into a non-expanded external instance — direct calls, vtable
    // entries, and pointer reifications — reaches the cache
    // boundary. Macro-expansion edges are bridge hops rather than calls.
    view.edges().filter(move |edge| {
        edge.kind() != ReachabilityEdgeKind::MacroExpansion
            && !expanded_sources.contains(&edge.target().id().index())
    })
}

pub(super) fn rebase_cached_dependency_finding(
    tcx: TyCtxt<'_>,
    edge: reachability::ReachedEdge<'_, '_>,
    trace: &EffectTrace,
    summary: &CachedFunctionSummary,
    cached: &CachedFinding,
) -> Option<CachedFinding> {
    let def_id = edge.target().instance()?.def_id();
    let effect = if cached.kind.is_panic() {
        &summary.panic
    } else if cached.kind.is_safety() {
        &summary.safety
    } else {
        return None;
    };
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
        dependency_trace: effect.trace(cached),
        reason: cached.reason.clone(),
        missing_requirements: cached.missing_requirements.clone(),
        target: Some(CachedFindingTarget::Function {
            path: summary.path.clone(),
            crate_name: tcx.crate_name(def_id.krate).to_string(),
            is_local: false,
        }),
    })
}

pub(super) fn propagating_cached_panic_boundaries<'view, 'tcx, 'cache>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    cache: &'cache DependencyAnalysisCache,
    ignores: impl FnMut(DefId) -> bool + 'cache,
) -> impl Iterator<Item = CachedEffectBoundary<'view, 'tcx, 'cache>> {
    propagating_cached_effect_boundaries(tcx, view, cache, ignores, |function| &function.panic)
}

pub(super) fn propagating_cached_safety_boundaries<'view, 'tcx, 'cache>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    cache: &'cache DependencyAnalysisCache,
    ignores: impl FnMut(DefId) -> bool + 'cache,
) -> impl Iterator<Item = CachedEffectBoundary<'view, 'tcx, 'cache>> {
    propagating_cached_effect_boundaries(tcx, view, cache, ignores, |function| &function.safety)
}

fn propagating_cached_effect_boundaries<'view, 'tcx, 'cache>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    cache: &'cache DependencyAnalysisCache,
    mut ignores: impl FnMut(DefId) -> bool + 'cache,
    select: fn(&CachedFunctionSummary) -> &CachedEffectSummary,
) -> impl Iterator<Item = CachedEffectBoundary<'view, 'tcx, 'cache>> {
    dependency_boundary_edges(view).filter_map(move |edge| {
        let def_id = edge.target().instance()?.def_id();
        if def_id.is_local() || ignores(def_id) {
            return None;
        }
        let crate_name = tcx.crate_name(def_id.krate).to_string();
        let function = cache.function(&crate_name, &stable_def_path_hash(tcx, def_id))?;
        let effect = select(function);
        (!effect.has_contract && (effect.is_reachable() || !effect.analysis_complete)).then_some(
            CachedEffectBoundary {
                edge,
                function,
                effect,
            },
        )
    })
}
