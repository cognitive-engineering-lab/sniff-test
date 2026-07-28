use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use std::rc::Rc;

use reachability::{
    ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityEdgeKind,
    ReachabilityGraph, ReachabilityHooks, ReachabilityIndex, ReachabilityNodeKind,
    ReachabilityView,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::{Instance, TyCtxt};

use crate::cache::{CachedFinding, CachedFindingKind, CachedFunctionSummary};
use crate::cli::cache_encode::{cached_boundary_findings, cached_reachability_graph};
use crate::cli::findings::{Finding, FindingKind};
use crate::cli::report::{PanicRootReport, panic_analysis_incomplete_finding, render_node};
use crate::config::{AnalysisConfig, CallableEdgeAttribution, PanicBoundaryPolicy, PanicConfig};
use crate::dependency_cache::DependencyAnalysisCache;
use crate::effect_tracker::{EffectPathDecision, EffectTrace, find_effect_trace_to_edge};
use crate::panics::{
    AmbiguousPanicMarker, AmbiguousPanicRequirementName, PanicAnalysis, PanicEvidence,
    PanicSourceEvidence, collect_ambiguous_panic_requirement_names, is_trusted_panic_obligation,
    probe_panic_sources, suppress_resolved_callable_indirect_boundaries,
};
use crate::report_roots::{ReportRoot, ReportRootKind};

use super::cache::{propagating_cached_panic_boundaries, rebase_cached_dependency_finding};
use super::pipeline::{
    CommentIndex, Effect, EffectCx, EffectGroupAllocator, EffectGroupId, EffectResolution,
    EffectSource, PathAnchor,
};
use super::{
    EffectCacheOutput, EffectReportOutput, EffectRootAnalysis, finish_effect_root,
    reachability_options,
};

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

struct PanicEffect<'config> {
    config: &'config PanicConfig,
    groups: EffectGroupAllocator,
    ambiguous_names: Vec<AmbiguousPanicRequirementName>,
    incomplete_dependencies: Vec<IncompletePanicDependency>,
}

#[derive(Clone)]
enum PanicSource {
    Local(PanicSourceEvidence),
    Dependency {
        edge_id: reachability::ReachabilityEdgeId,
        function: Rc<CachedFunctionSummary>,
        finding: Rc<CachedFinding>,
    },
}

struct IncompletePanicDependency {
    edge_id: reachability::ReachabilityEdgeId,
    function: Rc<CachedFunctionSummary>,
    trace: EffectTrace,
}

impl PanicSource {
    fn edge_id(&self) -> reachability::ReachabilityEdgeId {
        match self {
            Self::Local(source) => source.edge_id,
            Self::Dependency { edge_id, .. } => *edge_id,
        }
    }
}

impl<'tcx> PanicEffect<'_> {
    fn new(config: &PanicConfig) -> PanicEffect<'_> {
        PanicEffect {
            config,
            groups: EffectGroupAllocator::default(),
            ambiguous_names: Vec::new(),
            incomplete_dependencies: Vec::new(),
        }
    }

    fn query(
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

impl<'tcx> Effect<'tcx> for PanicEffect<'_> {
    type Source = PanicSource;

    fn is_path_boundary(&self, cx: &EffectCx<'_, 'tcx>, node: &ReachabilityNodeKind<'tcx>) -> bool {
        crate::panics::panic_path_node_is_boundary(cx.tcx, node, self.config)
    }

    fn probe_comments(&self, cx: &EffectCx<'_, 'tcx>) -> CommentIndex {
        CommentIndex::panic(cx.tcx, cx.view, cx.marker_probing, |node| {
            self.is_path_boundary(cx, node)
        })
    }

    fn probe_local_sources(&mut self, cx: &EffectCx<'_, 'tcx>) -> Vec<EffectSource<Self::Source>> {
        self.ambiguous_names =
            collect_ambiguous_panic_requirement_names(cx.tcx, cx.view, self.config);
        let edges = cx
            .view
            .edges()
            .map(|edge| (edge.id(), edge))
            .collect::<HashMap<_, _>>();
        let mut sources = probe_panic_sources(cx.tcx, cx.view, self.config);
        let mut candidates = sources
            .iter()
            .filter(|source| source.reportable)
            .filter_map(|source| {
                let edge = *edges.get(&source.edge_id)?;
                Some(PanicEvidence {
                    edge_id: source.edge_id,
                    trace: EffectTrace::from_edge(edge),
                    kind: source.kind,
                    decision: source.decision,
                    missing_requirements: Vec::new(),
                })
            })
            .collect::<Vec<_>>();
        suppress_resolved_callable_indirect_boundaries(cx.view.graph(), &mut candidates);
        let surviving_edges = candidates
            .into_iter()
            .map(|evidence| evidence.edge_id)
            .collect::<HashSet<_>>();
        sources.retain(|source| !source.reportable || surviving_edges.contains(&source.edge_id));

        sources
            .into_iter()
            .filter_map(|source| {
                let edge = *edges.get(&source.edge_id)?;
                Some(EffectSource {
                    group: self.groups.allocate(),
                    anchor: PathAnchor::from_terminal_edge(edge),
                    terminal_marker_spans: Vec::new(),
                    requirements: source.requirements.clone(),
                    payload: PanicSource::Local(source),
                })
            })
            .collect()
    }

    fn probe_dependency_sources(
        &mut self,
        cx: &EffectCx<'_, 'tcx>,
    ) -> Vec<EffectSource<Self::Source>> {
        let mut sources = Vec::new();
        for boundary in
            propagating_cached_panic_boundaries(cx.tcx, cx.view, cx.dependency_cache, |def_id| {
                self.config.ignores_def(cx.tcx, def_id)
                    || self.config.panic_boundary_policy(cx.tcx, def_id)
                        != PanicBoundaryPolicy::Normal
            })
        {
            let Some(trace) = find_effect_trace_to_edge(cx.view, boundary.edge, |node| {
                self.is_path_boundary(cx, node)
            }) else {
                continue;
            };
            let function = Rc::new(boundary.function.clone());
            if !boundary.effect.analysis_complete {
                self.incomplete_dependencies
                    .push(IncompletePanicDependency {
                        edge_id: boundary.edge.id(),
                        function: Rc::clone(&function),
                        trace,
                    });
            }
            for finding in &boundary.effect.findings {
                if !finding.kind.is_panic() {
                    continue;
                }
                sources.push(EffectSource {
                    group: self.groups.allocate(),
                    anchor: PathAnchor::from_terminal_edge(boundary.edge),
                    terminal_marker_spans: Vec::new(),
                    requirements: finding.missing_requirements.clone(),
                    payload: PanicSource::Dependency {
                        edge_id: boundary.edge.id(),
                        function: Rc::clone(&function),
                        finding: Rc::new(finding.clone()),
                    },
                });
            }
        }
        sources
    }
}

pub(super) fn analyze_root<'tcx>(
    tcx: TyCtxt<'tcx>,
    reachability: &mut ReachabilityIndex<'tcx>,
    root: ReportRoot<'tcx>,
    analysis_config: &AnalysisConfig,
    config: &PanicConfig,
    dependency_cache: &DependencyAnalysisCache,
) -> EffectRootAnalysis {
    // Reports can inspect available external MIR, while cached summaries stop
    // at dependency boundaries so downstream crates can compose their caches.
    let mut report_effect = PanicEffect::new(config);
    let report_snapshot = report_effect.query(reachability, root, analysis_config, true);
    let report_view = reachability.graph().view(&report_snapshot);
    let report_cx = EffectCx {
        tcx,
        root,
        view: report_view,
        dependency_cache,
        marker_probing: analysis_config.marker_probing,
    };
    let report_resolution = super::pipeline::resolve(&mut report_effect, &report_cx);
    let findings = panic_report_findings(
        &report_effect,
        &report_cx,
        &report_resolution,
        analysis_config.show_full_stack_trace,
    );
    let report = EffectReportOutput {
        findings,
        query_complete: report_view.halt().is_none(),
    };

    let mut cache_effect = PanicEffect::new(config);
    let cache_snapshot = cache_effect.query(reachability, root, analysis_config, false);
    let cache_view = reachability.graph().view(&cache_snapshot);
    let cache_cx = EffectCx {
        tcx,
        root,
        view: cache_view,
        dependency_cache,
        marker_probing: analysis_config.marker_probing,
    };
    let cache_resolution = super::pipeline::resolve(&mut cache_effect, &cache_cx);
    let findings = panic_cache_findings(&cache_effect, &cache_cx, &cache_resolution);
    let dependencies_complete = cache_effect.incomplete_dependencies.is_empty();
    let cache = EffectCacheOutput {
        findings,
        graph: cached_reachability_graph(tcx, cache_view),
        query_complete: cache_view.halt().is_none(),
        dependencies_complete,
    };

    finish_effect_root(
        tcx,
        root,
        analysis_config,
        panic_analysis_incomplete_finding,
        crate::panics::has_panic_docs(tcx, root.def_id(), config),
        report,
        cache,
    )
}

fn local_panic_analysis(
    effect: &PanicEffect<'_>,
    cx: &EffectCx<'_, '_>,
    resolution: &EffectResolution<PanicSource>,
) -> (PanicAnalysis, HashSet<EffectGroupId>) {
    let mut groups_by_edge = HashMap::new();
    let mut evidence = resolution
        .unresolved
        .iter()
        .filter_map(|unresolved| {
            let effect_source = &resolution.sources[unresolved.source];
            match &effect_source.payload {
                PanicSource::Local(source) if source.reportable => {
                    groups_by_edge.insert(source.edge_id, effect_source.group);
                    Some(PanicEvidence {
                        edge_id: source.edge_id,
                        trace: unresolved.path.trace.clone(),
                        kind: source.kind,
                        decision: source.decision,
                        missing_requirements: unresolved.path.missing_requirements.clone(),
                    })
                }
                PanicSource::Local(_) | PanicSource::Dependency { .. } => None,
            }
        })
        .collect::<Vec<_>>();
    suppress_resolved_callable_indirect_boundaries(cx.view.graph(), &mut evidence);
    let surviving_edges = evidence
        .iter()
        .map(|evidence| evidence.edge_id)
        .collect::<HashSet<_>>();
    let suppressed_groups = groups_by_edge
        .into_iter()
        .filter_map(|(edge_id, group)| (!surviving_edges.contains(&edge_id)).then_some(group))
        .collect();
    (
        PanicAnalysis {
            evidence,
            ambiguous_names: effect.ambiguous_names.clone(),
        },
        suppressed_groups,
    )
}

fn panic_report_findings(
    effect: &PanicEffect<'_>,
    cx: &EffectCx<'_, '_>,
    resolution: &EffectResolution<PanicSource>,
    include_stack: bool,
) -> Vec<Finding> {
    let (analysis, suppressed_groups) = local_panic_analysis(effect, cx, resolution);
    let collection = PanicFindingCollection {
        root_kind: cx.root.kind(),
        root_def_id: cx.root.def_id(),
        config: effect.config,
        include_stack,
    };
    let mut report = collect_panic_findings(cx.tcx, cx.view, &analysis, collection);
    let mut reported_raw_dependencies = HashSet::new();

    for unresolved in &resolution.unresolved {
        let PanicSource::Dependency {
            edge_id,
            function,
            finding,
        } = &resolution.sources[unresolved.source].payload
        else {
            continue;
        };
        let mut finding = finding.as_ref().clone();
        finding
            .missing_requirements
            .clone_from(&unresolved.path.missing_requirements);
        if finding.kind.is_raw_effect() {
            reported_raw_dependencies.insert(*edge_id);
        }
        push_cached_dependency_finding(
            cx,
            &mut report,
            *edge_id,
            function.as_ref(),
            &finding,
            &unresolved.path.trace,
        );
    }

    for boundary in &effect.incomplete_dependencies {
        if reported_raw_dependencies.contains(&boundary.edge_id) {
            continue;
        }
        // A truncated dependency summary with no raw findings proves nothing:
        // treat it as raw panic evidence rather than silence. The same applies
        // when every known raw finding was justified: truncated analysis may
        // have missed another path.
        report.push_cached_dependency_panic(
            cx.tcx,
            cx.view.graph(),
            boundary.edge_id,
            &boundary.trace.edge_ids,
            boundary.function.as_ref(),
            None,
        );
    }

    let source_edges = resolution
        .sources
        .iter()
        .map(|source| (source.group, source.payload.edge_id()))
        .collect::<HashMap<_, _>>();
    let marker_uses = crate::effect_tracker::ambiguous_marker_uses(
        resolution
            .marker_claims
            .iter()
            .filter(|claim| !suppressed_groups.contains(&claim.group))
            .map(|claim| (claim.key, claim.span, claim.group))
            .collect::<Vec<_>>(),
    );
    for marker_use in marker_uses {
        let mut edge_ids = marker_use
            .groups
            .into_iter()
            .filter_map(|group| source_edges.get(&group).copied())
            .collect::<Vec<_>>();
        edge_ids.sort_by_key(|edge_id| edge_id.index());
        report.push_ambiguous_obligation_marker(
            cx.tcx,
            cx.view.graph(),
            &AmbiguousPanicMarker {
                marker_span: marker_use.marker_span,
                edge_ids,
            },
        );
    }

    report.findings
}

fn push_cached_dependency_finding(
    cx: &EffectCx<'_, '_>,
    report: &mut PanicRootReport,
    edge_id: reachability::ReachabilityEdgeId,
    function: &CachedFunctionSummary,
    finding: &CachedFinding,
    trace: &EffectTrace,
) {
    let obligation_kind = match finding.kind {
        CachedFindingKind::PanicObligation => Some(FindingKind::DocumentedPanic),
        CachedFindingKind::TrustedPanicObligation => Some(FindingKind::TrustedPanic),
        CachedFindingKind::CompilerAssert
        | CachedFindingKind::PanicInvocation
        | CachedFindingKind::IndirectCallBoundary => {
            report.push_cached_dependency_panic(
                cx.tcx,
                cx.view.graph(),
                edge_id,
                &trace.edge_ids,
                function,
                Some(finding),
            );
            None
        }
        CachedFindingKind::CrateBoundary
        | CachedFindingKind::UnsafeCallMissingJustification
        | CachedFindingKind::UnsafeCallMissingRequirements
        | CachedFindingKind::UnsafeOpMissingJustification
        | CachedFindingKind::SafetyObligationMissingJustification
        | CachedFindingKind::SafetyObligationMissingRequirements => return,
    };
    if let Some(kind) = obligation_kind {
        report.push_cached_dependency_obligation(
            cx.tcx,
            cx.view.graph(),
            edge_id,
            &trace.edge_ids,
            function,
            Some(finding),
            kind,
        );
    }
}

fn panic_cache_findings(
    effect: &PanicEffect<'_>,
    cx: &EffectCx<'_, '_>,
    resolution: &EffectResolution<PanicSource>,
) -> Vec<CachedFinding> {
    let (analysis, _) = local_panic_analysis(effect, cx, resolution);
    let mut findings = cached_boundary_findings(cx.tcx, cx.view, &analysis, effect.config);
    let edges = cx
        .view
        .edges()
        .map(|edge| (edge.id(), edge))
        .collect::<HashMap<_, _>>();
    for unresolved in &resolution.unresolved {
        let PanicSource::Dependency {
            edge_id,
            function,
            finding,
        } = &resolution.sources[unresolved.source].payload
        else {
            continue;
        };
        let Some(edge) = edges.get(edge_id).copied() else {
            continue;
        };
        let mut finding = finding.as_ref().clone();
        finding
            .missing_requirements
            .clone_from(&unresolved.path.missing_requirements);
        if let Some(cached) = rebase_cached_dependency_finding(
            cx.tcx,
            edge,
            &unresolved.path.trace,
            function.as_ref(),
            &finding,
        ) {
            findings.push(cached);
        }
    }
    findings
}

#[derive(Clone, Copy)]
struct PanicFindingCollection<'config> {
    root_kind: ReportRootKind,
    root_def_id: DefId,
    config: &'config PanicConfig,
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

    collect_ambiguous_obligation_name_findings(tcx, analysis, &mut report);

    report
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
