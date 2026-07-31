use std::collections::{HashMap, HashSet};

use reachability::{
    ArtifactScope, ReachabilityEdgeKind, ReachabilityGraph, ReachabilityIndex,
    ReachabilityNodeExpansion, ReachabilityNodeKind, ReachabilityView, ReachedEdge,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use crate::cache::{CachedEffectInput, CachedFinding, CachedFindingInput};
use crate::cli::cache_encode::cached_safety_finding;
use crate::cli::diagnostics::cached_dependency_safety_diagnostic;
use crate::cli::findings::{Finding, FindingKind, safety_finding_report};
use crate::config::{AnalysisConfig, SafetyConfig};
use crate::dependency_cache::{CachedFunction, DependencyAnalysisCache};
use crate::effect_tracker::{
    EffectTarget, EffectTrace, find_effect_trace, find_effect_trace_to_edge,
};
use crate::namespace::canonical_namespace;
use crate::report_roots::ReportRoot;
use crate::safety::{SafetyAnalysis, SafetyEffectGroup, SafetyEvidence, safety_doc_summary};
use crate::source_markers::{
    EffectMarkerBlock, MarkerInstanceKey, safety_effect_edge_marker_block, safety_span_marker_block,
};

use super::cache::{EffectBoundary, rebase_cached_dependency_finding, safety_boundaries};
use super::pipeline::{
    Effect, EffectCx, EffectGroupAllocator, EffectGroupId, EffectReachabilityHooks,
    EffectResolution, EffectSource, PathAnchor,
};
use super::{
    EffectRootAnalysis, IncompleteDependency, dependency_analysis_incomplete_finding,
    reachability_options, root_analysis_incomplete_finding,
};

struct SafetyEffect<'config, 'analysis> {
    config: &'config SafetyConfig,
    analysis: &'analysis mut SafetyAnalysis,
    groups: EffectGroupAllocator,
    local_groups: HashMap<SafetyEffectGroup, EffectGroupId>,
    incomplete_dependencies: Vec<IncompleteDependency>,
}

#[derive(Clone)]
enum SafetySource {
    Local(SafetyEvidence),
    Dependency {
        edge_id: reachability::ReachabilityEdgeId,
        function: CachedFunction,
        finding: CachedFinding,
        effect_span: Span,
    },
}

impl SafetyEffect<'_, '_> {
    fn local_source(
        &mut self,
        evidence: SafetyEvidence,
        anchor: PathAnchor,
    ) -> EffectSource<SafetySource> {
        let group = if let Some(group) = self.local_groups.get(&evidence.group) {
            *group
        } else {
            let group = self.groups.allocate();
            self.local_groups.insert(evidence.group, group);
            group
        };
        EffectSource {
            group,
            anchor,
            terminal_marker_spans: evidence.terminal_marker_spans().to_vec(),
            requirements: evidence.requirements().to_vec(),
            payload: SafetySource::Local(evidence),
        }
    }
}

impl<'tcx> Effect<'tcx> for SafetyEffect<'_, '_> {
    type Source = SafetySource;

    fn classify_target(&self, tcx: TyCtxt<'tcx>, target: DefId) -> EffectTarget {
        safety_effect_target(tcx, target, self.config)
    }

    fn is_path_boundary(&self, cx: &EffectCx<'_, 'tcx>, node: &ReachabilityNodeKind<'tcx>) -> bool {
        match node {
            ReachabilityNodeKind::Instance(instance) => {
                safety_path_node_is_boundary(cx.tcx, instance.def_id(), self.config)
            }
            ReachabilityNodeKind::CompilerAssert { .. }
            | ReachabilityNodeKind::MacroExpansion { .. }
            | ReachabilityNodeKind::IndirectCall { .. }
            | ReachabilityNodeKind::DynObjectCast { .. } => false,
        }
    }

    fn probe_edge_marker(
        &self,
        cx: &EffectCx<'_, 'tcx>,
        edge: ReachedEdge<'_, 'tcx>,
    ) -> Option<EffectMarkerBlock> {
        safety_effect_edge_marker_block(cx.tcx, cx.view.graph(), edge.edge(), cx.marker_probing)
    }

    fn probe_terminal_marker(
        &self,
        cx: &EffectCx<'_, 'tcx>,
        span: Span,
    ) -> Option<EffectMarkerBlock> {
        safety_span_marker_block(cx.tcx, span, cx.marker_probing)
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
            for evidence in self.analysis.evidence(owner).to_vec() {
                let resolved_targets = resolved_unsafe_callable_targets(cx.view, &evidence);
                if let Some(targets) = resolved_targets {
                    for (effect_edge, target) in targets {
                        let Some(concrete) = self.analysis.resolved_unsafe_call_evidence(
                            cx.tcx,
                            self.config,
                            &evidence,
                            target,
                        ) else {
                            continue;
                        };
                        sources.push(
                            self.local_source(
                                concrete,
                                PathAnchor::from_terminal_edge(effect_edge),
                            ),
                        );
                    }
                }
                // Callable targets are correlated by erased type, not proven
                // exhaustive by value flow. Concrete evidence enriches this
                // finding but cannot discharge the opaque call itself.
                sources.push(self.local_source(evidence, anchor.clone()));
            }
        }
        for edge in cx
            .view
            .edges()
            .filter(|edge| is_callable_target_edge(edge.kind()))
        {
            let (Some(owner), Some(target)) = (edge.origin().instance(), edge.target().instance())
            else {
                continue;
            };
            let site = crate::effect_tracker::EffectSite {
                owner: owner.def_id(),
                span: edge.span(),
            };
            let Some(evidence) = self.analysis.callable_obligation_evidence(
                cx.tcx,
                self.config,
                site,
                target.def_id(),
            ) else {
                continue;
            };
            sources.push(self.local_source(evidence, PathAnchor::from_terminal_edge(edge)));
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
    let mut effect = SafetyEffect {
        config,
        analysis,
        groups: EffectGroupAllocator::default(),
        local_groups: HashMap::new(),
        incomplete_dependencies: Vec::new(),
    };
    let hooks = EffectReachabilityHooks::new(&effect);
    let snapshot = reachability.query(
        root.reachability_root(),
        &hooks,
        reachability_options(analysis_config, ArtifactScope::RootArtifact),
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
            SafetySource::Local(evidence) => {
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
                SafetySource::Local(evidence) => evidence.group.span,
                SafetySource::Dependency { effect_span, .. } => *effect_span,
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
            SafetySource::Local(evidence) => {
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
    for node in view
        .nodes()
        .filter(|node| node.expansion() == Some(ReachabilityNodeExpansion::Expanded))
    {
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

fn resolved_unsafe_callable_targets<'view, 'tcx>(
    view: ReachabilityView<'view, 'tcx>,
    evidence: &SafetyEvidence,
) -> Option<Vec<(reachability::ReachedEdge<'view, 'tcx>, DefId)>> {
    if !evidence.is_function_pointer_call() {
        return None;
    }
    let site = evidence.site();
    let graph = view.graph();
    let call_edges = view
        .edges()
        .filter(|edge| {
            edge.kind() == ReachabilityEdgeKind::IndirectCall
                && edge
                    .origin()
                    .instance()
                    .is_some_and(|origin| origin.def_id() == site.owner)
                && edge.span() == site.span
        })
        .collect::<Vec<_>>();
    let target_edges = view
        .edges()
        .filter(|edge| is_callable_target_edge(edge.kind()))
        .collect::<Vec<_>>();
    let mut seen = HashSet::new();
    let mut targets = Vec::new();
    for call_edge in call_edges {
        let Some(callable) = graph.edge_callable(call_edge.id()) else {
            continue;
        };
        for target_edge in &target_edges {
            if graph.edge_callable(target_edge.id()) != Some(callable) {
                continue;
            }
            let Some(target) = target_edge
                .target()
                .instance()
                .map(|target| target.def_id())
            else {
                continue;
            };
            let effect_edge = if target_edge.kind() == ReachabilityEdgeKind::FnPointerCallTarget {
                if target_edge.parent_edge().map(reachability::ReachedEdge::id)
                    != Some(call_edge.id())
                {
                    continue;
                }
                *target_edge
            } else {
                call_edge
            };
            if seen.insert((call_edge.id(), target)) {
                targets.push((effect_edge, target));
            }
        }
    }
    (!targets.is_empty()).then_some(targets)
}

fn is_callable_target_edge(kind: ReachabilityEdgeKind) -> bool {
    matches!(
        kind,
        ReachabilityEdgeKind::FnPointerReify
            | ReachabilityEdgeKind::ClosureFnPointerReify
            | ReachabilityEdgeKind::FnPointerCallTarget
            | ReachabilityEdgeKind::VTableEntry
            | ReachabilityEdgeKind::DynDispatchVTableEntry
    )
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

fn safety_effect_target(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    config: &crate::config::SafetyConfig,
) -> EffectTarget {
    if config.ignores_def(tcx, def_id) {
        EffectTarget::Ignored
    } else if safety_doc_summary(tcx, def_id, &config.documentation_overrides).has_docs {
        EffectTarget::Obligation
    } else if config.trusts_safety_boundary_def(tcx, def_id) {
        EffectTarget::Ignored
    } else {
        EffectTarget::Descend
    }
}

fn safety_path_node_is_boundary(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    config: &crate::config::SafetyConfig,
) -> bool {
    safety_effect_target(tcx, def_id, config).blocks_path()
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
    marker_claims: Vec<(MarkerInstanceKey, Span, Group)>,
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
