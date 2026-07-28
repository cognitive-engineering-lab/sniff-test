use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use std::rc::Rc;

use reachability::{
    ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityGraph,
    ReachabilityHooks, ReachabilityIndex, ReachabilityNodeKind, ReachabilityView,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::{Instance, TyCtxt};
use rustc_span::Span;

use crate::cache::{CachedFinding, CachedFunctionSummary};
use crate::cli::cache_encode::{cached_reachability_graph, cached_safety_finding};
use crate::cli::diagnostics::{
    cached_dependency_safety_diagnostic, cached_dependency_safety_incomplete_diagnostic,
};
use crate::cli::findings::{Finding, FindingKind, safety_finding_report};
use crate::cli::report::safety_analysis_incomplete_finding;
use crate::config::{AnalysisConfig, SafetyConfig};
use crate::dependency_cache::DependencyAnalysisCache;
use crate::effect_tracker::{EffectTrace, find_effect_trace, find_effect_trace_to_edge};
use crate::namespace::canonical_namespace;
use crate::report_roots::ReportRoot;
use crate::safety::{SafetyAnalysis, SafetyEffectGroup, SafetyEvidence, safety_doc_summary};
use crate::source_markers::MarkerBlockKey;

use super::cache::{propagating_cached_safety_boundaries, rebase_cached_dependency_finding};
use super::pipeline::{
    CommentIndex, Effect, EffectCx, EffectGroupAllocator, EffectGroupId, EffectResolution,
    EffectSource, PathAnchor,
};
use super::{
    EffectCacheOutput, EffectReportOutput, EffectRootAnalysis, finish_effect_root,
    reachability_options,
};

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

struct SafetyEffect<'config, 'analysis> {
    config: &'config SafetyConfig,
    analysis: &'analysis mut SafetyAnalysis,
    groups: EffectGroupAllocator,
    local_groups: HashMap<SafetyEffectGroup, EffectGroupId>,
    incomplete_dependencies: Vec<IncompleteSafetyDependency>,
}

#[derive(Clone)]
enum SafetySource {
    Local {
        evidence: SafetyEvidence,
        effect_span: Span,
    },
    Dependency {
        edge_id: reachability::ReachabilityEdgeId,
        function: Rc<CachedFunctionSummary>,
        finding: Rc<CachedFinding>,
        effect_span: Span,
    },
}

struct IncompleteSafetyDependency {
    edge_id: reachability::ReachabilityEdgeId,
    function: Rc<CachedFunctionSummary>,
    trace: EffectTrace,
}

impl SafetySource {
    fn effect_span(&self) -> Span {
        match self {
            Self::Local { effect_span, .. } | Self::Dependency { effect_span, .. } => *effect_span,
        }
    }
}

impl<'tcx> SafetyEffect<'_, '_> {
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
}

impl<'tcx> Effect<'tcx> for SafetyEffect<'_, '_> {
    type Source = SafetySource;

    fn is_path_boundary(&self, cx: &EffectCx<'_, 'tcx>, node: &ReachabilityNodeKind<'tcx>) -> bool {
        safety_graph_node_is_boundary(cx.tcx, node, self.config)
    }

    fn probe_comments(&self, cx: &EffectCx<'_, 'tcx>) -> CommentIndex {
        CommentIndex::safety(cx.tcx, cx.view, cx.marker_probing, |node| {
            self.is_path_boundary(cx, node)
        })
    }

    fn probe_local_sources(&mut self, cx: &EffectCx<'_, 'tcx>) -> Vec<EffectSource<Self::Source>> {
        let reached_instances =
            analyze_reached_safety_owners(cx.tcx, cx.view, self.config, self.analysis);
        let mut sources = Vec::new();
        for (owner, owner_instances) in reached_instances {
            if safety_boundary_trace(cx.tcx, cx.view, &owner_instances, self.config).is_none() {
                continue;
            }
            let anchor = PathAnchor::from_nodes(owner_instances.iter().map(|node| node.id()));
            for evidence in self.analysis.evidence(owner) {
                let group = if let Some(group) = self.local_groups.get(&evidence.group) {
                    *group
                } else {
                    let group = self.groups.allocate();
                    self.local_groups.insert(evidence.group, group);
                    group
                };
                sources.push(EffectSource {
                    group,
                    anchor: anchor.clone(),
                    terminal_marker_spans: evidence.terminal_marker_spans().to_vec(),
                    requirements: evidence.requirements().to_vec(),
                    payload: SafetySource::Local {
                        evidence: evidence.clone(),
                        effect_span: evidence.group.span,
                    },
                });
            }
        }
        sources
    }

    fn probe_dependency_sources(
        &mut self,
        cx: &EffectCx<'_, 'tcx>,
    ) -> Vec<EffectSource<Self::Source>> {
        let mut sources = Vec::new();
        for boundary in
            propagating_cached_safety_boundaries(cx.tcx, cx.view, cx.dependency_cache, |def_id| {
                self.config.ignores_def(cx.tcx, def_id)
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
                    .push(IncompleteSafetyDependency {
                        edge_id: boundary.edge.id(),
                        function: Rc::clone(&function),
                        trace,
                    });
            }
            for finding in &boundary.effect.findings {
                if FindingKind::from_cached_safety(finding.kind).is_none() {
                    continue;
                }
                sources.push(EffectSource {
                    group: self.groups.allocate(),
                    anchor: PathAnchor::from_terminal_edge(boundary.edge),
                    terminal_marker_spans: Vec::new(),
                    requirements: finding.missing_requirements.clone(),
                    payload: SafetySource::Dependency {
                        edge_id: boundary.edge.id(),
                        function: Rc::clone(&function),
                        finding: Rc::new(finding.clone()),
                        effect_span: boundary.edge.span(),
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
    config: &SafetyConfig,
    analysis: &mut SafetyAnalysis,
    dependency_cache: &DependencyAnalysisCache,
) -> EffectRootAnalysis {
    let mut effect = SafetyEffect {
        config,
        analysis,
        groups: EffectGroupAllocator::default(),
        local_groups: HashMap::new(),
        incomplete_dependencies: Vec::new(),
    };
    let snapshot = effect.query(reachability, root, analysis_config);
    let view = reachability.graph().view(&snapshot);
    let cx = EffectCx {
        tcx,
        root,
        view,
        dependency_cache,
        marker_probing: analysis_config.marker_probing,
    };
    let resolution = super::pipeline::resolve(&mut effect, &cx);
    let findings = safety_report_findings(&effect, &cx, &resolution);
    let cached_findings = safety_cache_findings(&effect, &cx, &resolution);
    let dependencies_complete = effect.incomplete_dependencies.is_empty();
    let query_complete = view.halt().is_none();
    finish_effect_root(
        tcx,
        root,
        analysis_config,
        safety_analysis_incomplete_finding,
        safety_doc_summary(tcx, root.def_id(), &config.documentation_overrides).has_docs,
        EffectReportOutput {
            findings,
            query_complete,
        },
        EffectCacheOutput {
            findings: cached_findings,
            graph: cached_reachability_graph(tcx, view),
            query_complete,
            dependencies_complete,
        },
    )
}

fn safety_report_findings(
    effect: &SafetyEffect<'_, '_>,
    cx: &EffectCx<'_, '_>,
    resolution: &EffectResolution<SafetySource>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (owner, owner_instances) in reached_safety_owners(cx.view) {
        findings.extend(collect_safety_contract_findings(
            cx.tcx,
            cx.view,
            cx.root,
            effect.config,
            owner,
            &owner_instances,
            effect.analysis.findings(owner),
        ));
    }

    for unresolved in &resolution.unresolved {
        let source = &resolution.sources[unresolved.source].payload;
        match source {
            SafetySource::Local { evidence, .. } => {
                let (_, finding) =
                    local_safety_finding(cx, effect.config, evidence, &unresolved.path);
                findings.push(finding);
            }
            SafetySource::Dependency {
                edge_id,
                function,
                finding,
                ..
            } => {
                let Some(edge) = cx.view.edges().find(|edge| edge.id() == *edge_id) else {
                    continue;
                };
                let mut finding = finding.as_ref().clone();
                finding
                    .missing_requirements
                    .clone_from(&unresolved.path.missing_requirements);
                if let Some((finding, _)) = cached_dependency_safety_finding(
                    cx.tcx,
                    cx.view.graph(),
                    edge,
                    &unresolved.path.trace,
                    cx.root,
                    function.as_ref(),
                    &finding,
                ) {
                    findings.push(finding);
                }
            }
        }
    }

    for incomplete in &effect.incomplete_dependencies {
        let Some(edge) = cx.view.edges().find(|edge| edge.id() == incomplete.edge_id) else {
            continue;
        };
        findings.push(cached_dependency_safety_incomplete_finding(
            cx.tcx,
            cx.view.graph(),
            edge,
            &incomplete.trace,
            cx.root,
            incomplete.function.as_ref(),
        ));
    }

    let effect_spans = resolution
        .sources
        .iter()
        .map(|source| (source.group, source.payload.effect_span()))
        .collect::<HashMap<_, _>>();
    findings.extend(safety_ambiguity_findings(
        cx.tcx,
        cx.root,
        effect.config,
        resolution
            .marker_claims
            .iter()
            .map(|claim| (claim.key, claim.span, claim.group))
            .collect(),
        |group| effect_spans[&group],
    ));
    findings
}

fn safety_cache_findings(
    effect: &SafetyEffect<'_, '_>,
    cx: &EffectCx<'_, '_>,
    resolution: &EffectResolution<SafetySource>,
) -> Vec<CachedFinding> {
    let mut findings = Vec::new();
    for unresolved in &resolution.unresolved {
        match &resolution.sources[unresolved.source].payload {
            SafetySource::Local { evidence, .. } => {
                let (safety_finding, finding) =
                    local_safety_finding(cx, effect.config, evidence, &unresolved.path);
                if let Some(cached) = cached_safety_finding(
                    cx.tcx,
                    evidence.site(),
                    &unresolved.path.trace,
                    &safety_finding,
                    &finding,
                ) {
                    findings.push(cached);
                }
            }
            SafetySource::Dependency {
                edge_id,
                function,
                finding,
                ..
            } => {
                let Some(edge) = cx.view.edges().find(|edge| edge.id() == *edge_id) else {
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
        }
    }
    findings
}

fn local_safety_finding(
    cx: &EffectCx<'_, '_>,
    config: &SafetyConfig,
    evidence: &SafetyEvidence,
    unresolved: &crate::effect_tracker::UnsatisfiedEffectTrace,
) -> (crate::safety::SafetyFinding, Finding) {
    let safety_finding = evidence.finding(unresolved.missing_requirements.clone());
    let mut finding = safety_finding_report(
        cx.tcx,
        safety_finding.clone(),
        &config.documentation_overrides,
    );
    finding.root = Some(canonical_namespace(cx.tcx, cx.root.def_id()));
    finding.root_kind = Some(cx.root.kind());
    finding.trace =
        crate::cli::report::render_trace(cx.tcx, cx.view.graph(), &unresolved.trace.edge_ids);
    (safety_finding, finding)
}

fn analyze_reached_safety_owners<'view, 'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'view, 'tcx>,
    config: &crate::config::SafetyConfig,
    analysis: &mut SafetyAnalysis,
) -> Vec<(DefId, Vec<reachability::ReachedNode<'view, 'tcx>>)> {
    let reached_instances = reached_safety_owners(view);
    analysis.analyze_owners(
        tcx,
        config,
        reached_instances
            .iter()
            .filter_map(|(def_id, _)| def_id.as_local()),
    );
    reached_instances
}

fn reached_safety_owners<'view, 'tcx>(
    view: ReachabilityView<'view, 'tcx>,
) -> Vec<(DefId, Vec<reachability::ReachedNode<'view, 'tcx>>)> {
    let mut owner_indexes = HashMap::<DefId, usize>::new();
    let mut reached_instances = Vec::<(DefId, Vec<_>)>::new();
    for node in view.nodes() {
        if let Some(instance) = node.instance() {
            let owner = instance.def_id();
            let index = *owner_indexes.entry(owner).or_insert_with(|| {
                reached_instances.push((owner, Vec::new()));
                reached_instances.len() - 1
            });
            reached_instances[index].1.push(node);
        }
    }
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
    rendered_trace.extend(crate::cli::report::render_cached_trace(
        &summary.safety,
        cached,
    ));
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
        root: Some(canonical_namespace(tcx, root.def_id())),
        root_kind: Some(root.kind()),
        function: None,
        target: Some(summary.path.clone()),
        span: Some(crate::cli::report::render_span(tcx, edge.span())),
        trace: crate::cli::report::render_trace(tcx, graph, &trace.edge_ids),
        missing_requirements: Vec::new(),
        requirements: Vec::new(),
        ..Finding::new(
            FindingKind::SafetyAnalysisIncomplete,
            format!("{} has incomplete cached safety analysis", summary.path),
            cached_dependency_safety_incomplete_diagnostic(edge.span(), summary),
        )
    }
}
