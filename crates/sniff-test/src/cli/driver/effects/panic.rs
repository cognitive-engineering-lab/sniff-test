use std::collections::HashMap;

use reachability::{
    ArtifactScope, ReachabilityEdgeId, ReachabilityIndex, ReachabilityNodeKind, ReachabilityView,
    ReachedEdge,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use crate::cache::{CachedEffectInput, CachedFinding, CachedFindingInput, CachedFindingKind};
use crate::cli::cache_encode::cached_panic_findings;
use crate::cli::findings::{Finding, FindingKind};
use crate::cli::report::{PanicRootReport, render_node};
use crate::config::{AnalysisConfig, PanicBoundaryPolicy, PanicConfig};
use crate::dependency_cache::{CachedFunction, DependencyAnalysisCache};
use crate::effect_tracker::{
    EffectPathDecision, EffectTarget, EffectTrace, find_effect_trace_to_edge,
};
use crate::panics::{
    AmbiguousPanicMarker, AmbiguousPanicRequirementName, PanicAnalysis, PanicEvidence,
    PanicEvidenceKind, PanicSourceEvidence, collect_ambiguous_panic_requirement_names,
    is_trusted_panic_boundary, panic_effect_target, probe_panic_sources,
};
use crate::report_roots::{ReportRoot, ReportRootKind};
use crate::source_markers::{
    EffectMarkerBlock, panic_effect_edge_marker_block, panic_span_marker_block,
};

use super::cache::{EffectBoundary, panic_boundaries, rebase_cached_dependency_finding};
use super::pipeline::{
    Effect, EffectCx, EffectGroupAllocator, EffectGroupId, EffectReachabilityHooks,
    EffectResolution, EffectSource, PathAnchor,
};
use super::{
    EffectRootAnalysis, IncompleteDependency, dependency_analysis_incomplete_finding,
    reachability_options, root_analysis_incomplete_finding,
};

struct PanicEffect<'config> {
    config: &'config PanicConfig,
    groups: EffectGroupAllocator,
    callable_groups: HashMap<ReachabilityEdgeId, EffectGroupId>,
    ambiguous_names: Vec<AmbiguousPanicRequirementName>,
    incomplete_dependencies: Vec<IncompleteDependency>,
}

#[derive(Clone)]
enum PanicSource {
    Local(PanicSourceEvidence),
    Dependency {
        edge_id: reachability::ReachabilityEdgeId,
        function: CachedFunction,
        finding: CachedFinding,
    },
}

impl PanicEffect<'_> {
    fn local_group(
        &mut self,
        cx: &EffectCx<'_, '_>,
        source: &PanicSourceEvidence,
    ) -> EffectGroupId {
        let callable_call = matches!(source.kind, PanicEvidenceKind::IndirectBoundary { .. })
            && cx.view.graph().edge_callable(source.edge_id).is_some();
        if !callable_call {
            return self.groups.allocate();
        }
        if let Some(group) = self.callable_groups.get(&source.edge_id) {
            return *group;
        }
        let group = self.groups.allocate();
        self.callable_groups.insert(source.edge_id, group);
        group
    }
}

impl<'tcx> Effect<'tcx> for PanicEffect<'_> {
    type Source = PanicSource;

    fn classify_target(&self, tcx: TyCtxt<'tcx>, target: DefId) -> EffectTarget {
        panic_effect_target(tcx, target, self.config)
    }

    fn is_path_boundary(&self, cx: &EffectCx<'_, 'tcx>, node: &ReachabilityNodeKind<'tcx>) -> bool {
        crate::panics::panic_path_node_is_boundary(cx.tcx, node, self.config)
    }

    fn probe_edge_marker(
        &self,
        cx: &EffectCx<'_, 'tcx>,
        edge: ReachedEdge<'_, 'tcx>,
    ) -> Option<EffectMarkerBlock> {
        panic_effect_edge_marker_block(cx.tcx, cx.view.graph(), edge.edge(), cx.marker_probing)
    }

    fn probe_terminal_marker(
        &self,
        cx: &EffectCx<'_, 'tcx>,
        span: Span,
    ) -> Option<EffectMarkerBlock> {
        panic_span_marker_block(cx.tcx, span, cx.marker_probing)
    }

    fn probe_local_sources(&mut self, cx: &EffectCx<'_, 'tcx>) -> Vec<EffectSource<Self::Source>> {
        self.ambiguous_names =
            collect_ambiguous_panic_requirement_names(cx.tcx, cx.view, self.config);
        let edges = cx
            .view
            .edges()
            .map(|edge| (edge.id(), edge))
            .collect::<HashMap<_, _>>();
        probe_panic_sources(cx.tcx, cx.view, self.config)
            .into_iter()
            .filter_map(|source| {
                let edge = *edges.get(&source.edge_id)?;
                let group = self.local_group(cx, &source);
                Some(EffectSource {
                    group,
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
        for boundary in panic_boundaries(cx.tcx, cx.view, cx.dependency_cache, |def_id| {
            self.config.ignores_def(cx.tcx, def_id)
                || self.config.panic_boundary_policy(cx.tcx, def_id) != PanicBoundaryPolicy::Normal
        }) {
            let (edge, function) = match boundary {
                EffectBoundary::Cached { edge, function } => (edge, function),
                EffectBoundary::Missing { edge, target } => {
                    if let Some(trace) = find_effect_trace_to_edge(cx.view, edge, |node| {
                        self.is_path_boundary(cx, node)
                    }) {
                        self.incomplete_dependencies.push(IncompleteDependency {
                            edge_id: edge.id(),
                            target,
                            trace,
                        });
                    }
                    continue;
                }
            };
            let Some(trace) =
                find_effect_trace_to_edge(cx.view, edge, |node| self.is_path_boundary(cx, node))
            else {
                continue;
            };
            let summary = function.summary();
            let target = summary.path.clone();
            let finding_ids = summary.panic.findings.clone();
            let mut incomplete = !summary.panic.analysis_complete || function.is_generic_template();
            for finding_id in finding_ids {
                let Some(finding) = function.finding(finding_id).cloned() else {
                    incomplete = true;
                    continue;
                };
                incomplete |= !function.resolve_trace(finding.trace).complete;
                if !finding.kind.is_panic() {
                    continue;
                }
                sources.push(EffectSource {
                    group: self.groups.allocate(),
                    anchor: PathAnchor::from_terminal_edge(edge),
                    terminal_marker_spans: Vec::new(),
                    requirements: finding.missing_requirements.clone(),
                    payload: PanicSource::Dependency {
                        edge_id: edge.id(),
                        function: function.clone(),
                        finding,
                    },
                });
            }
            if incomplete {
                self.incomplete_dependencies.push(IncompleteDependency {
                    edge_id: edge.id(),
                    target,
                    trace,
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
) -> EffectRootAnalysis<'tcx> {
    let mut effect = PanicEffect {
        config,
        groups: EffectGroupAllocator::default(),
        callable_groups: HashMap::new(),
        ambiguous_names: Vec::new(),
        incomplete_dependencies: Vec::new(),
    };
    let hooks = EffectReachabilityHooks::new(&effect);
    let snapshot = reachability.query(
        root.reachability_root(),
        &hooks,
        reachability_options(analysis_config, ArtifactScope::AllArtifacts),
    );
    let view = reachability.graph().view(&snapshot);
    let cx = EffectCx {
        tcx,
        root,
        view,
        dependency_cache,
        marker_probing: analysis_config.marker_probing,
    };
    let resolution = super::pipeline::resolve(&mut effect, &cx);
    let local_analysis = local_panic_analysis(&effect, &resolution);
    let mut findings = panic_report_findings(
        &effect,
        &cx,
        &resolution,
        &local_analysis,
        analysis_config.show_full_stack_trace,
    );
    let query_complete = view.halt().is_none();
    if !query_complete {
        findings.push(root_analysis_incomplete_finding(
            tcx,
            root,
            analysis_config,
            FindingKind::PanicAnalysisIncomplete,
        ));
    }
    EffectRootAnalysis {
        summary: CachedEffectInput {
            analysis_complete: query_complete && effect.incomplete_dependencies.is_empty(),
            has_contract: crate::panics::has_panic_docs(tcx, root.def_id(), config),
            findings: panic_cache_findings(&effect, &cx, &resolution, &local_analysis),
        },
        findings,
        reached_instances: view
            .nodes()
            .filter_map(reachability::ReachedNode::instance)
            .collect(),
    }
}

fn local_panic_analysis(
    effect: &PanicEffect<'_>,
    resolution: &EffectResolution<PanicSource>,
) -> PanicAnalysis {
    let evidence = resolution
        .unresolved
        .iter()
        .filter_map(|unresolved| {
            let effect_source = &resolution.sources[unresolved.source];
            match &effect_source.payload {
                PanicSource::Local(source) if source.reportable => Some(PanicEvidence {
                    edge_id: source.edge_id,
                    trace: unresolved.path.trace.clone(),
                    kind: source.kind,
                    decision: source.decision,
                    missing_requirements: unresolved.path.missing_requirements.clone(),
                }),
                PanicSource::Local(_) | PanicSource::Dependency { .. } => None,
            }
        })
        .collect::<Vec<_>>();
    PanicAnalysis {
        evidence,
        ambiguous_names: effect.ambiguous_names.clone(),
    }
}

fn panic_report_findings(
    effect: &PanicEffect<'_>,
    cx: &EffectCx<'_, '_>,
    resolution: &EffectResolution<PanicSource>,
    analysis: &PanicAnalysis,
    include_stack: bool,
) -> Vec<Finding> {
    let collection = PanicFindingCollection {
        root_kind: cx.root.kind(),
        root_def_id: cx.root.def_id(),
        config: effect.config,
        include_stack,
    };
    let mut report = collect_panic_findings(cx.tcx, cx.view, analysis, collection);
    for unresolved in &resolution.unresolved {
        let PanicSource::Dependency {
            edge_id,
            function,
            finding,
        } = &resolution.sources[unresolved.source].payload
        else {
            continue;
        };
        let mut finding = finding.clone();
        finding
            .missing_requirements
            .clone_from(&unresolved.path.missing_requirements);
        push_cached_dependency_finding(
            cx,
            &mut report,
            *edge_id,
            function,
            &finding,
            &unresolved.path.trace,
        );
    }

    for dependency in &effect.incomplete_dependencies {
        report.findings.push(dependency_analysis_incomplete_finding(
            cx.tcx,
            cx.view.graph(),
            cx.root,
            dependency,
            FindingKind::PanicAnalysisIncomplete,
            "panic",
        ));
    }

    let source_edges = resolution
        .sources
        .iter()
        .map(|source| {
            let edge_id = match &source.payload {
                PanicSource::Local(source) => source.edge_id,
                PanicSource::Dependency { edge_id, .. } => *edge_id,
            };
            (source.group, edge_id)
        })
        .collect::<HashMap<_, _>>();
    let reached_edges = cx
        .view
        .edges()
        .map(|edge| (edge.id(), edge))
        .collect::<HashMap<_, _>>();
    let marker_uses = crate::effect_tracker::ambiguous_marker_uses(
        resolution
            .marker_claims
            .iter()
            .map(|claim| {
                let group = claim
                    .edge_id
                    .and_then(|edge_id| {
                        let edge = reached_edges.get(&edge_id)?;
                        let callable_call = edge.parent_edge().map_or(edge_id, ReachedEdge::id);
                        effect.callable_groups.get(&callable_call).copied()
                    })
                    .unwrap_or(claim.group);
                (claim.key, claim.span, group)
            })
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
    function: &CachedFunction,
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
        CachedFindingKind::UnsafeCallMissingJustification
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
    analysis: &PanicAnalysis,
) -> Vec<CachedFindingInput> {
    let mut findings = cached_panic_findings(cx.tcx, cx.view, analysis, effect.config);
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
        let mut finding = finding.clone();
        finding
            .missing_requirements
            .clone_from(&unresolved.path.missing_requirements);
        findings.push(rebase_cached_dependency_finding(
            cx.tcx,
            cx.view.graph(),
            edge,
            &unresolved.path.trace,
            function,
            &finding,
        ));
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
                let kind = if is_trusted_panic_boundary(tcx, def_id, collection.config) {
                    FindingKind::TrustedPanic
                } else {
                    FindingKind::DocumentedPanic
                };
                report.push_panic_obligation(tcx, graph, evidence, Some(edge_id), def_id, kind);
            }
        }
    }

    for name in &analysis.ambiguous_names {
        report.push_ambiguous_obligation_name(tcx, name);
    }

    report
}
