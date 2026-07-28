use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;

use reachability::{
    ArtifactScope, ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityGraph,
    ReachabilityHooks, ReachabilityIndex, ReachabilityNodeKind, ReachabilityView,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::{Instance, TyCtxt};
use rustc_span::Span;

use crate::cache::{CachedEffectInput, CachedFinding, CachedFindingInput};
use crate::cli::cache_encode::cached_safety_finding;
use crate::cli::diagnostics::cached_dependency_safety_diagnostic;
use crate::cli::findings::{Finding, FindingKind, safety_finding_report};
use crate::config::{AnalysisConfig, SafetyConfig};
use crate::dependency_cache::{CachedFunction, DependencyAnalysisCache};
use crate::effect_tracker::{EffectTrace, find_effect_trace, find_effect_trace_to_edge};
use crate::namespace::canonical_namespace;
use crate::report_roots::ReportRoot;
use crate::safety::{SafetyAnalysis, SafetyEffectGroup, SafetyEvidence, safety_doc_summary};
use crate::source_markers::MarkerBlockKey;

use super::cache::{EffectBoundary, rebase_cached_dependency_finding, safety_boundaries};
use super::pipeline::{
    CommentIndex, Effect, EffectCx, EffectGroupAllocator, EffectGroupId, EffectResolution,
    EffectSource, PathAnchor,
};
use super::{
    EffectRootAnalysis, IncompleteDependency, dependency_analysis_incomplete_finding,
    reachability_options, root_analysis_incomplete_finding,
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
    incomplete_dependencies: Vec<IncompleteDependency>,
}

#[derive(Clone)]
enum SafetySource {
    Local {
        evidence: SafetyEvidence,
        effect_span: Span,
    },
    Dependency {
        edge_id: reachability::ReachabilityEdgeId,
        function: CachedFunction,
        finding: CachedFinding,
        effect_span: Span,
    },
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
        let reached_instances = reached_safety_owners(cx.view);
        self.analysis.analyze_owners(
            cx.tcx,
            self.config,
            reached_instances
                .iter()
                .filter_map(|(def_id, _)| def_id.as_local()),
        );
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
        for boundary in safety_boundaries(cx.tcx, cx.view, cx.dependency_cache, |def_id| {
            self.config.ignores_def(cx.tcx, def_id)
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
            let finding_ids = summary.safety.findings.clone();
            let mut incomplete =
                !summary.safety.analysis_complete || function.is_generic_template();
            for finding_id in finding_ids {
                let Some(finding) = function.finding(finding_id).cloned() else {
                    incomplete = true;
                    continue;
                };
                incomplete |= !function.resolve_trace(finding.trace).complete;
                if FindingKind::from_cached_safety(finding.kind).is_none() {
                    continue;
                }
                sources.push(EffectSource {
                    group: self.groups.allocate(),
                    anchor: PathAnchor::from_terminal_edge(edge),
                    terminal_marker_spans: Vec::new(),
                    requirements: finding.missing_requirements.clone(),
                    payload: SafetySource::Dependency {
                        edge_id: edge.id(),
                        function: function.clone(),
                        finding,
                        effect_span: edge.span(),
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
    config: &SafetyConfig,
    analysis: &mut SafetyAnalysis,
    dependency_cache: &DependencyAnalysisCache,
) -> EffectRootAnalysis<'tcx> {
    let mut hooks = SafetyReachabilityHooks { config };
    let snapshot = reachability.query(
        root.reachability_root(),
        &mut hooks,
        reachability_options(analysis_config, ArtifactScope::RootArtifact),
    );
    let mut effect = SafetyEffect {
        config,
        analysis,
        groups: EffectGroupAllocator::default(),
        local_groups: HashMap::new(),
        incomplete_dependencies: Vec::new(),
    };
    let view = reachability.graph().view(&snapshot);
    let cx = EffectCx {
        tcx,
        root,
        view,
        dependency_cache,
        marker_probing: analysis_config.marker_probing,
    };
    let resolution = super::pipeline::resolve(&mut effect, &cx);
    let mut findings = safety_report_findings(&effect, &cx, &resolution);
    let query_complete = view.halt().is_none();
    if !query_complete {
        findings.push(root_analysis_incomplete_finding(
            tcx,
            root,
            analysis_config,
            FindingKind::SafetyAnalysisIncomplete,
        ));
    }
    EffectRootAnalysis {
        summary: CachedEffectInput {
            analysis_complete: query_complete && effect.incomplete_dependencies.is_empty(),
            has_contract: safety_doc_summary(tcx, root.def_id(), &config.documentation_overrides)
                .has_docs,
            findings: safety_cache_findings(&effect, &cx, &resolution),
        },
        findings,
        reached_instances: view
            .nodes()
            .filter_map(reachability::ReachedNode::instance)
            .collect(),
    }
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
                let mut finding = finding.clone();
                finding
                    .missing_requirements
                    .clone_from(&unresolved.path.missing_requirements);
                if let Some(finding) = cached_dependency_safety_finding(
                    cx.tcx,
                    cx.view.graph(),
                    edge,
                    &unresolved.path.trace,
                    cx.root,
                    function,
                    &finding,
                ) {
                    findings.push(finding);
                }
            }
        }
    }

    for dependency in &effect.incomplete_dependencies {
        findings.push(dependency_analysis_incomplete_finding(
            cx.tcx,
            cx.view.graph(),
            cx.root,
            dependency,
            FindingKind::SafetyAnalysisIncomplete,
            "safety",
        ));
    }

    let effect_spans = resolution
        .sources
        .iter()
        .map(|source| {
            let effect_span = match &source.payload {
                SafetySource::Local { effect_span, .. }
                | SafetySource::Dependency { effect_span, .. } => *effect_span,
            };
            (source.group, effect_span)
        })
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
) -> Vec<CachedFindingInput> {
    let mut findings = Vec::new();
    for unresolved in &resolution.unresolved {
        match &resolution.sources[unresolved.source].payload {
            SafetySource::Local { evidence, .. } => {
                let (safety_finding, finding) =
                    local_safety_finding(cx, effect.config, evidence, &unresolved.path);
                if let Some(cached) = cached_safety_finding(
                    cx.tcx,
                    cx.view.graph(),
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
    function: &CachedFunction,
    cached: &CachedFinding,
) -> Option<Finding> {
    let kind = FindingKind::from_cached_safety(cached.kind)?;
    let summary = function.summary();
    let mut rendered_trace = crate::cli::report::render_trace(tcx, graph, &trace.edge_ids);
    rendered_trace.extend(crate::cli::report::render_cached_trace(function, cached));
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
    Some(finding)
}
