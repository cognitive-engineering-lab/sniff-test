use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

use reachability::{
    ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityGraph,
    ReachabilityHooks, ReachabilityIndex, ReachabilityNodeKind, ReachabilityView,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::{Instance, TyCtxt};
use rustc_span::Span;

use crate::cache::{CachedFinding, CachedFunctionSummary};
use crate::cli::cache_encode::cached_safety_finding;
use crate::cli::diagnostics::{
    cached_dependency_safety_diagnostic, cached_dependency_safety_incomplete_diagnostic,
};
use crate::cli::findings::{Finding, FindingKind, safety_finding_report};
use crate::config::{AnalysisConfig, SafetyConfig};
use crate::contracts::EffectKind;
use crate::dependency_cache::DependencyAnalysisCache;
use crate::effect_tracker::{
    EffectMarkerIndex, EffectPathIndex, EffectTrace, find_effect_trace,
    find_unsatisfied_effect_traces_with,
};
use crate::namespace::canonical_namespace;
use crate::report_roots::ReportRoot;
use crate::safety::{SafetyAnalysis, safety_doc_summary};
use crate::source_markers::MarkerBlockKey;

use super::cache::{
    CachedEffectPropagation, TraceEffectGroup, rebase_cached_dependency_finding,
    resolved_cached_effect_boundaries,
};
use super::{EffectPass, EffectSnapshotAnalysis, EffectViewPurpose, reachability_options};

struct SafetyReachabilityHooks<'config> {
    config: &'config SafetyConfig,
}

impl<'tcx> ReachabilityHooks<'tcx> for SafetyReachabilityHooks<'_> {
    fn should_descend(
        &mut self,
        cx: ReachabilityContext<'tcx>,
        _edge: &ReachabilityEdge,
        target: Instance<'tcx>,
    ) -> ReachabilityControl<'tcx, bool> {
        ControlFlow::Continue(!safety_path_node_is_boundary(
            cx.tcx,
            target.def_id(),
            self.config,
        ))
    }
}

pub(super) struct SafetyPass<'config, 'analysis> {
    pub(super) config: &'config SafetyConfig,
    pub(super) analysis: &'analysis mut SafetyAnalysis,
}

impl<'tcx> EffectPass<'tcx> for SafetyPass<'_, '_> {
    fn kind(&self) -> EffectKind {
        EffectKind::Safety
    }

    fn query(
        &self,
        reachability: &mut ReachabilityIndex<'tcx>,
        root: ReportRoot<'tcx>,
        analysis_config: &AnalysisConfig,
    ) -> reachability::ReachabilitySnapshot<'tcx> {
        let mut hooks = SafetyReachabilityHooks {
            config: self.config,
        };
        reachability.query(
            root.reachability_root(),
            &mut hooks,
            reachability_options(analysis_config, false),
        )
    }

    fn path_index(&self, tcx: TyCtxt<'tcx>, view: ReachabilityView<'_, 'tcx>) -> EffectPathIndex {
        EffectPathIndex::new(view, |node| {
            safety_graph_node_is_boundary(tcx, node, self.config)
        })
    }

    fn has_root_contract(&self, tcx: TyCtxt<'tcx>, root: DefId) -> bool {
        safety_doc_summary(tcx, root, &self.config.documentation_overrides).has_docs
    }

    fn analyze_snapshot(
        &mut self,
        tcx: TyCtxt<'tcx>,
        view: ReachabilityView<'_, 'tcx>,
        root: ReportRoot<'tcx>,
        _purpose: EffectViewPurpose,
        dependency_cache: &DependencyAnalysisCache,
    ) -> EffectSnapshotAnalysis {
        let marker_index =
            EffectMarkerIndex::new(tcx, view, EffectKind::Safety, self.config.marker_probing);
        let path_index = self.path_index(tcx, view);
        let (mut findings, mut cached_findings) = collect_local_safety_findings(
            tcx,
            view,
            root,
            self.config,
            self.analysis,
            &marker_index,
            &path_index,
        );
        let (dependency_findings, propagation) = collect_cached_dependency_safety_findings(
            tcx,
            view,
            root,
            self.config,
            dependency_cache,
            &marker_index,
            &path_index,
        );
        findings.extend(dependency_findings);
        cached_findings.extend(propagation.cached_findings);
        EffectSnapshotAnalysis {
            findings,
            cached_findings,
            dependency_complete: propagation.analysis_complete,
        }
    }
}
fn collect_local_safety_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    root: ReportRoot<'tcx>,
    config: &crate::config::SafetyConfig,
    analysis: &mut SafetyAnalysis,
    marker_index: &EffectMarkerIndex,
    path_index: &EffectPathIndex,
) -> (Vec<Finding>, Vec<CachedFinding>) {
    let graph = view.graph();
    let mut findings = Vec::new();
    let mut cached_findings = Vec::new();
    let mut terminal_marker_claims = Vec::new();
    let mut trace_marker_claims = Vec::new();
    let reached_instances = analyze_reached_safety_owners(tcx, view, config, analysis);
    for (owner, owner_instances) in &reached_instances {
        let boundary_trace = safety_boundary_trace(tcx, view, owner_instances, config);
        findings.extend(collect_safety_contract_findings(
            tcx,
            view,
            root,
            config,
            *owner,
            owner_instances,
            analysis.findings(*owner),
        ));

        for (evidence_index, evidence) in analysis.evidence(*owner).iter().enumerate() {
            let resolved = evidence.resolve_paths(
                tcx,
                config,
                || {
                    marker_index.blocks(
                        path_index
                            .edges_to_nodes(owner_instances.iter().map(|owner| owner.id()), false),
                    )
                },
                |requirements| {
                    safety_finding_traces(
                        tcx,
                        view,
                        owner_instances,
                        config,
                        marker_index,
                        requirements,
                    )
                },
            );
            if boundary_trace.is_some() {
                terminal_marker_claims.extend(
                    resolved
                        .terminal_markers
                        .into_iter()
                        .map(|marker| (marker.key, marker.span, evidence.group)),
                );
            }
            if let Some(boundary_edge) = boundary_trace
                .as_ref()
                .and_then(|trace| trace.edge_ids.last().copied())
            {
                let group = TraceEffectGroup {
                    boundary_edge,
                    finding: evidence_index,
                    span: evidence.site().span,
                };
                trace_marker_claims.extend(
                    resolved
                        .path_markers
                        .into_iter()
                        .map(|marker| (marker.key, marker.span, group)),
                );
            }
            for unresolved in resolved.unresolved_traces {
                let trace = &unresolved.trace;
                let safety_finding = evidence.finding(unresolved.missing_requirements);
                let mut finding = safety_finding_report(
                    tcx,
                    safety_finding.clone(),
                    &config.documentation_overrides,
                );
                finding.root = Some(canonical_namespace(tcx, root.def_id()));
                finding.root_kind = Some(root.kind());
                finding.trace = crate::cli::report::render_trace(tcx, graph, &trace.edge_ids);
                if let Some(cached) =
                    cached_safety_finding(tcx, evidence.site(), trace, &safety_finding, &finding)
                {
                    cached_findings.push(cached);
                }
                findings.push(finding);
            }
        }
    }

    findings.extend(safety_ambiguity_findings(
        tcx,
        root,
        config,
        terminal_marker_claims,
        |group| group.span,
    ));
    findings.extend(safety_ambiguity_findings(
        tcx,
        root,
        config,
        trace_marker_claims,
        |group| group.span,
    ));
    (findings, cached_findings)
}

fn analyze_reached_safety_owners<'view, 'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    config: &crate::config::SafetyConfig,
    analysis: &mut SafetyAnalysis,
) -> HashMap<DefId, Vec<reachability::ReachedNode<'view, 'tcx>>> {
    let mut reached_instances = HashMap::<DefId, Vec<_>>::new();
    for node in view.nodes() {
        if let Some(instance) = node.instance() {
            reached_instances
                .entry(instance.def_id())
                .or_default()
                .push(node);
        }
    }
    analysis.analyze_owners(
        tcx,
        config,
        reached_instances
            .keys()
            .filter_map(|def_id| def_id.as_local()),
    );
    reached_instances
}

fn collect_safety_contract_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    root: ReportRoot<'tcx>,
    config: &crate::config::SafetyConfig,
    owner: DefId,
    owner_instances: &[reachability::ReachedNode<'_, 'tcx>],
    safety_findings: &[crate::safety::SafetyFinding],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(owner_instance) = owner_instances.first() else {
        return findings;
    };
    for safety_finding in safety_findings {
        if safety_finding.is_root_contract_finding() && owner != root.def_id() {
            continue;
        }
        let mut finding =
            safety_finding_report(tcx, safety_finding.clone(), &config.documentation_overrides);
        finding.root = Some(canonical_namespace(tcx, root.def_id()));
        finding.root_kind = Some(root.kind());
        finding.trace = crate::cli::report::render_trace(
            tcx,
            view.graph(),
            &EffectTrace::from_node(*owner_instance).edge_ids,
        );
        findings.push(finding);
    }
    findings
}

fn safety_finding_traces<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    owner_instances: &[reachability::ReachedNode<'_, 'tcx>],
    config: &crate::config::SafetyConfig,
    marker_index: &EffectMarkerIndex,
    requirements: &[crate::contracts::ContractRequirement],
) -> Vec<crate::effect_tracker::UnsatisfiedEffectTrace> {
    let owner_ids = owner_instances
        .iter()
        .map(|owner| owner.id())
        .collect::<HashSet<_>>();
    find_unsatisfied_effect_traces_with(
        view,
        |node| owner_ids.contains(&node.id()),
        requirements,
        |node| safety_graph_node_is_boundary(tcx, node, config),
        |edge_id, requirement| marker_index.satisfies(edge_id, requirement),
    )
}

fn safety_path_node_is_boundary(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    config: &crate::config::SafetyConfig,
) -> bool {
    config.ignores_def(tcx, def_id)
        || safety_doc_summary(tcx, def_id, &config.documentation_overrides).has_docs
}

fn safety_graph_node_is_boundary(
    tcx: TyCtxt<'_>,
    node: &ReachabilityNodeKind<'_>,
    config: &crate::config::SafetyConfig,
) -> bool {
    match node {
        ReachabilityNodeKind::Instance(instance) => {
            safety_path_node_is_boundary(tcx, instance.def_id(), config)
        }
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::MacroExpansion { .. }
        | ReachabilityNodeKind::IndirectCall { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => false,
    }
}

fn safety_boundary_trace<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    owner_instances: &[reachability::ReachedNode<'_, 'tcx>],
    config: &crate::config::SafetyConfig,
) -> Option<EffectTrace> {
    let root_def_id = view.root().instance()?.def_id();
    if safety_path_node_is_boundary(tcx, root_def_id, config) {
        return None;
    }
    let owner_ids = owner_instances
        .iter()
        .map(|owner| owner.id())
        .collect::<HashSet<_>>();
    find_effect_trace(
        view,
        |node| owner_ids.contains(&node.id()),
        |edge| {
            edge.target()
                .instance()
                .map(|instance| instance.def_id())
                .is_none_or(|def_id| !safety_path_node_is_boundary(tcx, def_id, config))
        },
    )
}

fn collect_cached_dependency_safety_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    root: ReportRoot<'tcx>,
    config: &crate::config::SafetyConfig,
    dependency_cache: &DependencyAnalysisCache,
    marker_index: &EffectMarkerIndex,
    path_index: &EffectPathIndex,
) -> (Vec<Finding>, CachedEffectPropagation) {
    let graph = view.graph();
    let mut findings = Vec::new();
    let mut propagation = CachedEffectPropagation::default();
    let mut marker_claims = Vec::new();

    for boundary in resolved_cached_effect_boundaries(
        tcx,
        view,
        dependency_cache,
        marker_index,
        path_index,
        |def_id| config.ignores_def(tcx, def_id),
        |node| safety_graph_node_is_boundary(tcx, node, config),
    ) {
        let edge = boundary.edge;
        let safety = boundary.effect;

        if !safety.analysis_complete {
            propagation.analysis_complete = false;
        }

        marker_claims.extend(boundary.marker_claims);
        for unresolved in boundary.unresolved_findings {
            let mut cached = unresolved.finding.clone();
            cached.missing_requirements = unresolved.missing_requirements;
            if let Some((finding, cached_finding)) = cached_dependency_safety_finding(
                tcx,
                graph,
                edge,
                &unresolved.trace,
                root,
                boundary.function,
                &cached,
            ) {
                findings.push(finding);
                propagation.cached_findings.push(cached_finding);
            }
        }
        if !safety.analysis_complete {
            findings.push(cached_dependency_safety_incomplete_finding(
                tcx,
                graph,
                edge,
                &boundary.trace,
                root,
                boundary.function,
            ));
        }
    }

    findings.extend(safety_ambiguity_findings(
        tcx,
        root,
        config,
        marker_claims,
        |group| group.span,
    ));

    (findings, propagation)
}

fn safety_ambiguity_findings<Group>(
    tcx: TyCtxt<'_>,
    root: ReportRoot<'_>,
    config: &crate::config::SafetyConfig,
    marker_claims: Vec<(MarkerBlockKey, Span, Group)>,
    effect_span: impl Fn(Group) -> Span + Copy,
) -> Vec<Finding>
where
    Group: Copy + Eq + std::hash::Hash,
{
    crate::effect_tracker::ambiguous_marker_uses(marker_claims)
        .into_iter()
        .map(|marker_use| {
            let safety_finding = crate::safety::SafetyFinding::AmbiguousMarker {
                caller: root.def_id(),
                marker_span: marker_use.marker_span,
                effect_spans: marker_use.groups.into_iter().map(effect_span).collect(),
            };
            let mut finding =
                safety_finding_report(tcx, safety_finding, &config.documentation_overrides);
            finding.root = Some(canonical_namespace(tcx, root.def_id()));
            finding.root_kind = Some(root.kind());
            finding
        })
        .collect()
}

fn cached_dependency_safety_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge: reachability::ReachedEdge<'_, 'tcx>,
    trace: &EffectTrace,
    root: ReportRoot<'tcx>,
    summary: &CachedFunctionSummary,
    cached: &CachedFinding,
) -> Option<(Finding, CachedFinding)> {
    let kind = FindingKind::from_cached_safety(cached.kind)?;
    let mut rendered_trace = crate::cli::report::render_trace(tcx, graph, &trace.edge_ids);
    rendered_trace.extend(summary.render_effect_trace(EffectKind::Safety, cached));
    let finding = Finding {
        root: Some(canonical_namespace(tcx, root.def_id())),
        root_kind: Some(root.kind()),
        function: None,
        target: Some(summary.path.clone()),
        span: Some(crate::cli::report::render_span(tcx, edge.span())),
        effect_span: Some(crate::cli::report::render_cached_effect_span(cached)),
        trace: rendered_trace,
        missing_requirements: cached
            .missing_requirements
            .iter()
            .map(crate::cache::CachedRequirement::render)
            .collect(),
        requirements: Vec::new(),
        ..Finding::new(
            kind,
            format!(
                "{} has cached safety effect: {}",
                summary.path, cached.reason
            ),
            cached_dependency_safety_diagnostic(tcx, edge.span(), summary, cached),
        )
    };
    let cached_finding = rebase_cached_dependency_finding(tcx, edge, trace, summary, cached)?;
    Some((finding, cached_finding))
}

fn cached_dependency_safety_incomplete_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge: reachability::ReachedEdge<'_, 'tcx>,
    trace: &EffectTrace,
    root: ReportRoot<'tcx>,
    summary: &CachedFunctionSummary,
) -> Finding {
    Finding {
        effect: Some(EffectKind::Safety),
        root: Some(canonical_namespace(tcx, root.def_id())),
        root_kind: Some(root.kind()),
        function: None,
        target: Some(summary.path.clone()),
        span: Some(crate::cli::report::render_span(tcx, edge.span())),
        trace: crate::cli::report::render_trace(tcx, graph, &trace.edge_ids),
        missing_requirements: Vec::new(),
        requirements: Vec::new(),
        ..Finding::new(
            FindingKind::AnalysisIncomplete,
            format!("{} has incomplete cached safety analysis", summary.path),
            cached_dependency_safety_incomplete_diagnostic(edge.span(), summary),
        )
    }
}
