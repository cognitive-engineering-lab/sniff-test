use std::ops::ControlFlow;

use reachability::{
    ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityEdgeKind,
    ReachabilityGraph, ReachabilityHooks, ReachabilityIndex, ReachabilityView,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::{Instance, TyCtxt};
use rustc_span::Span;

use crate::cache::CachedFindingKind;
use crate::cli::cache_encode::cached_boundary_findings;
use crate::cli::findings::FindingKind;
use crate::cli::report::{PanicRootReport, render_node};
use crate::config::{AnalysisConfig, CallableEdgeAttribution, PanicBoundaryPolicy, PanicConfig};
use crate::contracts::EffectKind;
use crate::dependency_cache::DependencyAnalysisCache;
use crate::effect_tracker::{EffectMarkerIndex, EffectPathDecision, EffectPathIndex};
use crate::panics::{
    AmbiguousPanicMarker, PanicAnalysis, PanicEvidence, analyze_panic_evidence,
    is_trusted_panic_obligation,
};
use crate::report_roots::{ReportRoot, ReportRootKind};
use crate::source_markers::MarkerBlockKey;

use super::cache::{
    CachedEffectPropagation, ResolvedCachedBoundary, TraceEffectGroup,
    rebase_cached_dependency_finding, resolved_cached_effect_boundaries,
};
use super::{EffectPass, EffectSnapshotAnalysis, EffectViewPurpose, reachability_options};

struct PanicReachabilityHooks<'config> {
    config: &'config PanicConfig,
    descend_reified_callables: bool,
}

impl<'tcx> ReachabilityHooks<'tcx> for PanicReachabilityHooks<'_> {
    fn should_descend(
        &mut self,
        cx: ReachabilityContext<'tcx>,
        edge: &ReachabilityEdge,
        target: Instance<'tcx>,
    ) -> ReachabilityControl<'tcx, bool> {
        if matches!(
            edge.kind,
            ReachabilityEdgeKind::FnPointerReify | ReachabilityEdgeKind::ClosureFnPointerReify
        ) && !self.descend_reified_callables
        {
            return ControlFlow::Continue(false);
        }

        let def_id = target.def_id();
        ControlFlow::Continue(
            !self.config.ignores_def(cx.tcx, def_id)
                && self.config.panic_boundary_policy(cx.tcx, def_id) == PanicBoundaryPolicy::Normal
                && !crate::panics::has_panic_docs(cx.tcx, def_id, self.config),
        )
    }
}

pub(super) struct PanicPass<'config> {
    pub(super) config: &'config PanicConfig,
    pub(super) include_stack: bool,
}

impl<'tcx> PanicPass<'_> {
    fn query_with_external_mir(
        &self,
        reachability: &mut ReachabilityIndex<'tcx>,
        root: ReportRoot<'tcx>,
        analysis_config: &AnalysisConfig,
        analyze_external: bool,
    ) -> reachability::ReachabilitySnapshot<'tcx> {
        let mut hooks = PanicReachabilityHooks {
            config: self.config,
            descend_reified_callables: analysis_config.callable_edge_attribution
                == CallableEdgeAttribution::ErasureSites,
        };
        reachability.query(
            root.reachability_root(),
            &mut hooks,
            reachability_options(analysis_config, analyze_external),
        )
    }
}

impl<'tcx> EffectPass<'tcx> for PanicPass<'_> {
    fn kind(&self) -> EffectKind {
        EffectKind::Panic
    }

    fn requires_separate_cache_snapshot(&self) -> bool {
        true
    }

    fn query(
        &self,
        reachability: &mut ReachabilityIndex<'tcx>,
        root: ReportRoot<'tcx>,
        analysis_config: &AnalysisConfig,
    ) -> reachability::ReachabilitySnapshot<'tcx> {
        self.query_with_external_mir(reachability, root, analysis_config, false)
    }

    fn query_report(
        &self,
        reachability: &mut ReachabilityIndex<'tcx>,
        root: ReportRoot<'tcx>,
        analysis_config: &AnalysisConfig,
    ) -> reachability::ReachabilitySnapshot<'tcx> {
        self.query_with_external_mir(reachability, root, analysis_config, true)
    }

    fn path_index(&self, tcx: TyCtxt<'tcx>, view: ReachabilityView<'_, 'tcx>) -> EffectPathIndex {
        EffectPathIndex::new(view, |node| {
            crate::panics::panic_path_node_is_boundary(tcx, node, self.config)
        })
    }

    fn has_root_contract(&self, tcx: TyCtxt<'tcx>, root: DefId) -> bool {
        crate::panics::has_panic_docs(tcx, root, self.config)
    }

    fn analyze_snapshot(
        &mut self,
        tcx: TyCtxt<'tcx>,
        view: ReachabilityView<'_, 'tcx>,
        root: ReportRoot<'tcx>,
        purpose: EffectViewPurpose,
        dependency_cache: &DependencyAnalysisCache,
    ) -> EffectSnapshotAnalysis {
        let marker_index =
            EffectMarkerIndex::new(tcx, view, EffectKind::Panic, self.config.marker_probing);
        let path_index = self.path_index(tcx, view);
        let analysis = analyze_panic_evidence(tcx, view, self.config, &marker_index, &path_index);
        let collection = PanicFindingCollection {
            root_kind: root.kind(),
            root_def_id: root.def_id(),
            config: self.config,
            dependency_cache,
            include_stack: self.include_stack,
        };
        if purpose == EffectViewPurpose::Report {
            let mut report = collect_panic_findings(tcx, view, &analysis, collection);
            let propagation = collect_cached_dependency_findings(
                tcx,
                view,
                &collection,
                &marker_index,
                &path_index,
                Some(&mut report),
            );
            EffectSnapshotAnalysis {
                findings: report.findings,
                cached_findings: Vec::new(),
                dependency_complete: propagation.analysis_complete,
            }
        } else {
            let mut cached_findings = cached_boundary_findings(tcx, view, &analysis, self.config);
            let propagation = collect_cached_dependency_findings(
                tcx,
                view,
                &collection,
                &marker_index,
                &path_index,
                None,
            );
            cached_findings.extend(propagation.cached_findings);
            EffectSnapshotAnalysis {
                findings: Vec::new(),
                cached_findings,
                dependency_complete: propagation.analysis_complete,
            }
        }
    }
}
#[derive(Clone, Copy)]
struct PanicFindingCollection<'config> {
    root_kind: ReportRootKind,
    root_def_id: DefId,
    config: &'config PanicConfig,
    dependency_cache: &'config DependencyAnalysisCache,
    include_stack: bool,
}

fn collect_panic_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    analysis: &PanicAnalysis,
    collection: PanicFindingCollection<'_>,
) -> PanicRootReport {
    let graph = view.graph();
    let root_node = view.root();
    let mut report = PanicRootReport::new(
        render_node(tcx, root_node.kind()),
        collection.root_kind,
        collection.root_def_id,
        collection.include_stack,
    );

    for evidence in &analysis.evidence {
        match evidence.decision {
            EffectPathDecision::RawEffect => {
                report.push_panic_evidence(tcx, graph, evidence);
            }
            EffectPathDecision::Obligation { edge_id: None, .. } => {
                // The root's own `# Panics` docs explain its internal panic
                // evidence; callers are checked at the edge where they invoke it.
            }
            EffectPathDecision::Obligation {
                edge_id: Some(edge_id),
                def_id,
            } => {
                push_panic_obligation_finding(
                    tcx,
                    graph,
                    evidence,
                    Some(edge_id),
                    def_id,
                    &collection,
                    &mut report,
                );
            }
        }
    }

    collect_ambiguous_obligation_marker_findings(tcx, graph, analysis, &mut report);
    collect_ambiguous_obligation_name_findings(tcx, analysis, &mut report);

    report
}

fn collect_ambiguous_obligation_marker_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    analysis: &PanicAnalysis,
    report: &mut PanicRootReport,
) {
    for marker in &analysis.ambiguous_markers {
        report.push_ambiguous_obligation_marker(tcx, graph, marker);
    }
}

fn collect_ambiguous_obligation_name_findings(
    tcx: TyCtxt<'_>,
    analysis: &PanicAnalysis,
    report: &mut PanicRootReport,
) {
    for name in &analysis.ambiguous_names {
        report.push_ambiguous_obligation_name(tcx, name);
    }
}

fn push_panic_obligation_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    edge_id: Option<reachability::ReachabilityEdgeId>,
    def_id: DefId,
    collection: &PanicFindingCollection<'_>,
    report: &mut PanicRootReport,
) {
    let trusted = is_trusted_panic_obligation(tcx, def_id, collection.config);
    let kind = if trusted {
        FindingKind::TrustedPanic
    } else {
        FindingKind::DocumentedPanic
    };
    report.push_panic_obligation(tcx, graph, evidence, edge_id, def_id, kind);
}

fn collect_cached_dependency_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    collection: &PanicFindingCollection<'_>,
    marker_index: &EffectMarkerIndex,
    path_index: &EffectPathIndex,
    mut report: Option<&mut PanicRootReport>,
) -> CachedEffectPropagation {
    let graph = view.graph();
    let mut propagation = CachedEffectPropagation::default();
    let mut marker_claims = Vec::new();
    for boundary in resolved_cached_effect_boundaries(
        tcx,
        view,
        collection.dependency_cache,
        marker_index,
        path_index,
        |def_id| {
            collection.config.ignores_def(tcx, def_id)
                || collection.config.panic_boundary_policy(tcx, def_id)
                    != PanicBoundaryPolicy::Normal
        },
        |node| crate::panics::panic_path_node_is_boundary(tcx, node, collection.config),
    ) {
        propagate_cached_panic_boundary(
            tcx,
            view,
            boundary,
            report.as_deref_mut(),
            &mut propagation,
            &mut marker_claims,
        );
    }

    if let Some(report) = report {
        for marker_use in crate::effect_tracker::ambiguous_marker_uses(marker_claims) {
            report.push_ambiguous_obligation_marker(
                tcx,
                graph,
                &AmbiguousPanicMarker {
                    marker_span: marker_use.marker_span,
                    edge_ids: marker_use
                        .groups
                        .into_iter()
                        .map(|group| group.boundary_edge)
                        .collect(),
                },
            );
        }
    }

    propagation
}

fn propagate_cached_panic_boundary<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    boundary: ResolvedCachedBoundary<'_, 'tcx, '_>,
    mut report: Option<&mut PanicRootReport>,
    propagation: &mut CachedEffectPropagation,
    marker_claims: &mut Vec<(MarkerBlockKey, Span, TraceEffectGroup)>,
) {
    let graph = view.graph();
    let edge = boundary.edge;
    let panic = boundary.effect;
    if !panic.analysis_complete {
        propagation.analysis_complete = false;
    }

    marker_claims.extend(boundary.marker_claims);
    for unresolved in boundary.unresolved_findings {
        let mut cached_finding = unresolved.finding.clone();
        cached_finding.missing_requirements = unresolved.missing_requirements;
        let trace = &unresolved.trace;
        let obligation_kind = match cached_finding.kind {
            CachedFindingKind::PanicObligation => Some(FindingKind::DocumentedPanic),
            CachedFindingKind::TrustedPanicObligation => Some(FindingKind::TrustedPanic),
            CachedFindingKind::CompilerAssert
            | CachedFindingKind::PanicInvocation
            | CachedFindingKind::IndirectCallBoundary => {
                if let Some(report) = report.as_deref_mut() {
                    report.push_cached_dependency_panic(
                        tcx,
                        graph,
                        edge.id(),
                        &trace.edge_ids,
                        boundary.function,
                        Some(&cached_finding),
                    );
                }
                None
            }
            CachedFindingKind::CrateBoundary
            | CachedFindingKind::UnsafeCallMissingJustification
            | CachedFindingKind::UnsafeCallMissingRequirements
            | CachedFindingKind::UnsafeOpMissingJustification
            | CachedFindingKind::SafetyObligationMissingJustification
            | CachedFindingKind::SafetyObligationMissingRequirements => continue,
        };
        if let (Some(kind), Some(report)) = (obligation_kind, report.as_deref_mut()) {
            report.push_cached_dependency_obligation(
                tcx,
                graph,
                edge.id(),
                &trace.edge_ids,
                boundary.function,
                Some(&cached_finding),
                kind,
            );
        }
        if let Some(cached_finding) =
            rebase_cached_dependency_finding(tcx, edge, trace, boundary.function, &cached_finding)
        {
            propagation.cached_findings.push(cached_finding);
        }
    }

    // A truncated dependency summary with no raw findings proves nothing:
    // treat it as raw panic evidence rather than silence.
    if !boundary.has_raw_findings
        && !panic.analysis_complete
        && let Some(report) = report
    {
        report.push_cached_dependency_panic(
            tcx,
            graph,
            edge.id(),
            &boundary.trace.edge_ids,
            boundary.function,
            None,
        );
    }
}
