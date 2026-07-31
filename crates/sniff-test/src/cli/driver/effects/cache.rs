use std::collections::HashSet;

use reachability::{
    ReachabilityEdgeKind, ReachabilityNodeExpansion, ReachabilityView, ReachedEdge,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::{Instance, InstanceKind, TyCtxt};

use crate::cache::{
    CachedDependencyTraceInput, CachedEffectSummary, CachedFinding, CachedFindingInput,
};
use crate::cli::cache_encode::cached_trace;
use crate::cli::report::render_span;
use crate::dependency_cache::{CachedFunction, DependencyAnalysisCache};
use crate::effect_tracker::EffectTrace;
use crate::namespace::{StableDefPathHash, StableInstanceHash};

pub(super) enum EffectBoundary<'view, 'tcx> {
    Cached {
        edge: ReachedEdge<'view, 'tcx>,
        function: CachedFunction,
    },
    Missing {
        edge: ReachedEdge<'view, 'tcx>,
        target: String,
    },
}

pub(super) fn rebase_cached_dependency_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &reachability::ReachabilityGraph<'tcx>,
    edge: ReachedEdge<'_, 'tcx>,
    trace: &EffectTrace,
    function: &CachedFunction,
    cached: &CachedFinding,
) -> CachedFindingInput {
    let mut cached_trace = cached_trace(tcx, graph, &trace.edge_ids);
    cached_trace.dependency_tail = Some(CachedDependencyTraceInput {
        artifact_id: function.analysis().artifact.artifact_id.clone(),
        analysis_id: function.analysis().analysis_id.clone(),
        trace: cached.trace,
    });
    CachedFindingInput {
        kind: cached.kind,
        span: render_span(tcx, edge.span()),
        source_span: cached.source_span.clone(),
        trace: cached_trace,
        reason: cached.reason.clone(),
        missing_requirements: cached.missing_requirements.clone(),
    }
}

pub(super) fn panic_boundaries<'view, 'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    cache: &DependencyAnalysisCache,
    ignores: impl FnMut(DefId) -> bool,
) -> Vec<EffectBoundary<'view, 'tcx>> {
    effect_boundaries(tcx, view, cache, ignores, |function| {
        &function.summary().panic
    })
}

pub(super) fn safety_boundaries<'view, 'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    cache: &DependencyAnalysisCache,
    ignores: impl FnMut(DefId) -> bool,
) -> Vec<EffectBoundary<'view, 'tcx>> {
    effect_boundaries(tcx, view, cache, ignores, |function| {
        &function.summary().safety
    })
}

fn effect_boundaries<'view, 'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    cache: &DependencyAnalysisCache,
    mut ignores: impl FnMut(DefId) -> bool,
    select: impl Fn(&CachedFunction) -> &CachedEffectSummary,
) -> Vec<EffectBoundary<'view, 'tcx>> {
    let frontier = view
        .frontier()
        .filter(|node| {
            matches!(
                node.expansion(),
                Some(
                    ReachabilityNodeExpansion::DifferentArtifact
                        | ReachabilityNodeExpansion::MirUnavailable
                )
            )
        })
        .map(reachability::ReachedNode::id)
        .collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    let mut boundaries = Vec::new();

    for edge in view.edges().filter(|edge| {
        edge.kind() != ReachabilityEdgeKind::MacroExpansion
            && frontier.contains(&edge.target().id())
    }) {
        let Some(instance) = edge.target().instance() else {
            continue;
        };
        if matches!(
            instance.def,
            InstanceKind::Intrinsic(..) | InstanceKind::Virtual(..)
        ) {
            continue;
        }
        let def_id = instance.def_id();
        if def_id.is_local() || ignores(def_id) {
            continue;
        }
        let managed_dependency = cache
            .has_analysis_for_crate(tcx.stable_crate_id(def_id.krate).as_u64())
            || tcx
                .crate_extern_paths(def_id.krate)
                .iter()
                .any(|path| cache.tracks_artifact_path(path));

        let (edge, function) = function_for_instance(tcx, cache, instance)
            .map(|function| (edge, function))
            .or_else(|| {
                let entry = artifact_entry_edge(edge)?;
                let function = function_for_instance(tcx, cache, entry.target().instance()?)?;
                Some((entry, function))
            })
            .map_or((edge, None), |(edge, function)| (edge, Some(function)));
        if !seen.insert(edge.id()) {
            continue;
        }

        if let Some(function) = function {
            let effect = select(&function);
            if effect.has_contract {
                continue;
            }
            if !effect.findings.is_empty()
                || !effect.analysis_complete
                || function.is_generic_template()
            {
                boundaries.push(EffectBoundary::Cached { edge, function });
            }
        } else if managed_dependency {
            let target = edge.target().instance().map_or_else(
                || String::from("opaque dependency boundary"),
                |instance| tcx.def_path_str(instance.def_id()),
            );
            boundaries.push(EffectBoundary::Missing { edge, target });
        }
    }

    boundaries
}

fn function_for_instance<'tcx>(
    tcx: TyCtxt<'tcx>,
    cache: &DependencyAnalysisCache,
    instance: Instance<'tcx>,
) -> Option<CachedFunction> {
    cache.function(
        StableDefPathHash::from_def_id(tcx, instance.def_id()),
        Some(StableInstanceHash::from_instance(tcx, instance)),
    )
}

fn artifact_entry_edge<'view, 'tcx>(
    frontier: ReachedEdge<'view, 'tcx>,
) -> Option<ReachedEdge<'view, 'tcx>> {
    let artifact = frontier.target().instance()?.def_id().krate;
    if frontier
        .origin()
        .instance()
        .is_some_and(|origin| origin.def_id().krate != artifact)
    {
        return Some(frontier);
    }
    let mut node = frontier.origin();
    let mut entry = frontier;
    while let Some(edge) = node.predecessor_edge() {
        if edge
            .target()
            .instance()
            .is_some_and(|target| target.def_id().krate == artifact)
        {
            entry = edge;
        }
        if edge
            .origin()
            .instance()
            .is_some_and(|origin| origin.def_id().krate != artifact)
        {
            return Some(entry);
        }
        node = edge.origin();
    }
    None
}
