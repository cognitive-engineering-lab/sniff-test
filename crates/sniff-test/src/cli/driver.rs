//! Per-rustc-unit analysis orchestration.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use crate::cache::{
    CacheError, CacheExpectations, CachedArtifactAnalysis, CachedArtifactInfo, CachedEffectSummary,
    CachedFinding, CachedFindingKind, CachedFindingTarget, CachedFunctionSummary,
    OUTCOME_FORMAT_VERSION, UnitOutcome, artifact_id,
};
use crate::config::{
    AnalysisConfig, CallableEdgeAttribution, PanicBoundaryPolicy, PanicConfig, SniffTestConfig,
};
use crate::contracts::EffectKind;
use crate::dependency_cache::{DependencyAnalysisCache, DependencyInput};
use crate::effect_tracker::{
    EffectMarkerIndex, EffectPathDecision, EffectPathIndex, EffectTrace, find_effect_trace,
    find_effect_trace_to_edge, find_unsatisfied_effect_traces_to_edge_with,
    find_unsatisfied_effect_traces_with, resolve_effect_paths,
};
use crate::namespace::{canonical_namespace, stable_def_path_hash};
use crate::panics::{AmbiguousPanicMarker, PanicAnalysis, PanicEvidence, analyze_panic_evidence};
use crate::report_roots::{
    MissingReportRoot, ReportRoot, ReportRootKind, ReportRootSelection, select_report_roots,
};
use crate::safety::{SafetyAnalysis, safety_doc_summary};
use crate::source_markers::MarkerBlockKey;
use anyhow::Context;
use reachability::{
    ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityEdgeKind,
    ReachabilityGraph, ReachabilityHooks, ReachabilityIndex, ReachabilityNodeKind,
    ReachabilityOptions, ReachabilityView,
};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_middle::ty::{Instance, TyCtxt};
use rustc_session::config::CrateType;
use rustc_span::Span;

use super::args::{self, SniffTestArgs};
use super::cache_encode::{
    cached_boundary_findings, cached_reachability_graph, cached_safety_finding, cached_source_span,
};
use super::diagnostics::{
    cached_dependency_safety_diagnostic, cached_dependency_safety_incomplete_diagnostic,
    emit_finding_diagnostic,
};
use super::findings::{
    Finding, FindingKind, collect_report_root_findings, resolve_findings, safety_finding_report,
};
use super::plugin::rustc_version;
use super::report::{
    AnalysisArtifactReport, CrateOutputScope, PanicRootReport, REPORT_FORMAT_VERSION,
    analysis_incomplete_finding, render_node,
};

struct PanicReachabilityHooks<'config> {
    config: &'config PanicConfig,
    descend_reified_callables: bool,
}

struct SafetyReachabilityHooks<'config> {
    config: &'config crate::config::SafetyConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TraceEffectGroup {
    boundary_edge: reachability::ReachabilityEdgeId,
    finding: usize,
    span: rustc_span::Span,
}

type TraceMarkerClaim = (MarkerBlockKey, Span, TraceEffectGroup);
struct UnresolvedCachedFinding<'cache> {
    finding: &'cache CachedFinding,
    trace: EffectTrace,
    missing_requirements: Vec<crate::contracts::ContractRequirement>,
}

struct ResolvedCachedEffect<'cache> {
    unresolved_findings: Vec<UnresolvedCachedFinding<'cache>>,
    marker_claims: Vec<TraceMarkerClaim>,
    has_raw_findings: bool,
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

pub(crate) fn analyze_crate(
    tcx: TyCtxt<'_>,
    args: &SniffTestArgs,
    config: &SniffTestConfig,
    output_scope: CrateOutputScope,
) {
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();

    let rustc_version = rustc_version();
    let externs = dependency_inputs(tcx);
    let dependency_cache = DependencyAnalysisCache::load(
        &args.cache_dir(),
        &externs,
        config,
        &CacheExpectations {
            tool_version: env!("CARGO_PKG_VERSION"),
            rustc_version: &rustc_version,
        },
    );
    for (extern_name, error) in dependency_cache.load_failures() {
        eprintln!(
            "sniff-test: warning: ignoring cached analysis for dependency `{extern_name}`: {error}"
        );
    }
    for ambiguous in dependency_cache.ambiguous_crate_names() {
        eprintln!(
            "sniff-test: warning: multiple compiled artifacts are named `{ambiguous}`; \
             cached effect evidence for that crate is disabled"
        );
    }

    let selection = select_report_roots(tcx, &config.analysis);
    let selection_has_roots = !selection.roots.is_empty();
    let emit_diagnostics = args.message_format == args::MessageFormat::Human
        && output_scope == CrateOutputScope::Workspace;
    let effect_analysis =
        analyze_effect_roots(tcx, selection, &config.analysis, config, &dependency_cache);
    let empty_report_roots = !selection_has_roots && effect_analysis.missing_roots.is_empty();
    let analysis_findings = collect_report_root_findings(
        tcx,
        &args.manifest_path(),
        empty_report_roots,
        &effect_analysis.missing_roots,
        &config.analysis.report_roots,
        &crate_name,
    );
    let analysis = AnalysisArtifact::new(
        tcx,
        output_scope,
        &dependency_cache,
        config,
        effect_analysis,
        analysis_findings,
    );
    if emit_diagnostics {
        for finding in &analysis.report.findings {
            emit_finding_diagnostic(tcx, finding.level, &finding.finding.diagnostic);
        }
    }
    if let Err(error) = analysis.cache.write(&args.cache_dir()) {
        if args.under_cargo {
            let diagnostic = tcx
                .dcx()
                .struct_err(format!("failed to write analysis cache: {error}"));
            let _ = diagnostic.emit();
        } else {
            eprintln!("sniff-test: warning: failed to write analysis cache: {error}");
        }
    }
    emit_report_and_outcome(
        tcx,
        args,
        &analysis.report,
        analysis.report.scope == CrateOutputScope::Workspace
            && analysis.report.has_denied_findings(),
    );
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
                finding.trace = super::report::render_trace(tcx, graph, &trace.edge_ids);
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
        finding.trace = super::report::render_trace(
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

        marker_claims.extend(boundary.resolved.marker_claims);
        for unresolved in boundary.resolved.unresolved_findings {
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
    let mut rendered_trace = super::report::render_trace(tcx, graph, &trace.edge_ids);
    rendered_trace.extend(summary.render_effect_trace(EffectKind::Safety, cached));
    let finding = Finding {
        root: Some(canonical_namespace(tcx, root.def_id())),
        root_kind: Some(root.kind()),
        function: None,
        target: Some(summary.path.clone()),
        span: Some(super::report::render_span(tcx, edge.span())),
        effect_span: Some(super::report::render_cached_effect_span(cached)),
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

fn rebase_cached_dependency_finding(
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
        span: super::report::render_span(tcx, edge.span()),
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

struct CachedEffectPropagation {
    cached_findings: Vec<CachedFinding>,
    analysis_complete: bool,
}

impl Default for CachedEffectPropagation {
    fn default() -> Self {
        Self {
            cached_findings: Vec::new(),
            analysis_complete: true,
        }
    }
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
        span: Some(super::report::render_span(tcx, edge.span())),
        trace: super::report::render_trace(tcx, graph, &trace.edge_ids),
        missing_requirements: Vec::new(),
        requirements: Vec::new(),
        ..Finding::new(
            FindingKind::AnalysisIncomplete,
            format!("{} has incomplete cached safety analysis", summary.path),
            cached_dependency_safety_incomplete_diagnostic(edge.span(), summary),
        )
    }
}

fn emit_report_and_outcome(
    tcx: TyCtxt<'_>,
    args: &SniffTestArgs,
    report: &AnalysisArtifactReport,
    has_denied_findings: bool,
) {
    let report_json = match serde_json::to_string(report) {
        Ok(report_json) => Some(report_json),
        Err(error) => {
            eprintln!("sniff-test: failed to encode JSON report: {error}");
            None
        }
    };
    if args.message_format == args::MessageFormat::Json
        && let Some(report_json) = &report_json
    {
        println!("{report_json}");
    }
    let outcome = UnitOutcome {
        format_version: OUTCOME_FORMAT_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        artifact_id: report.artifact.artifact_id.clone(),
        has_denied_findings,
        report_json,
    };
    if let Err(error) = write_unit_outcome_and_announce(args, &outcome) {
        report_unit_outcome_write_error(tcx, args, &error);
    }
}

fn report_unit_outcome_write_error(tcx: TyCtxt<'_>, args: &SniffTestArgs, error: &CacheError) {
    if args.under_cargo {
        let diagnostic = tcx
            .dcx()
            .struct_err(format!("failed to write unit outcome: {error}"));
        let _ = diagnostic.emit();
    } else {
        eprintln!("sniff-test: warning: failed to write unit outcome: {error}");
    }
}

fn write_unit_outcome_and_announce(
    args: &SniffTestArgs,
    outcome: &UnitOutcome,
) -> Result<(), CacheError> {
    let result = outcome.write(&args.cache_dir());
    // Deny findings fail this unit's compilation, so cargo never announces it
    // with a compiler-artifact message. This line puts the unit in the
    // frontend's build plan regardless; the frontend swallows it, users never
    // see it.
    if args.under_cargo {
        println!(
            r#"{{"reason":"sniff-test-outcome","artifact-id":{}}}"#,
            serde_json::json!(outcome.artifact_id)
        );
    }
    result
}

struct AnalysisArtifact {
    report: AnalysisArtifactReport,
    cache: CachedArtifactAnalysis,
}

impl AnalysisArtifact {
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor assembles independent analysis outputs without hiding them"
    )]
    fn new(
        tcx: TyCtxt<'_>,
        scope: CrateOutputScope,
        dependency_cache: &DependencyAnalysisCache,
        config: &SniffTestConfig,
        effect_analysis: RootEffectAnalysis,
        mut findings: Vec<Finding>,
    ) -> Self {
        let dependencies = dependency_cache.resolved_dependencies();
        let artifact = artifact_info(tcx);
        let tool_version = env!("CARGO_PKG_VERSION").to_owned();
        let rustc_version = rustc_version();
        findings.extend(effect_analysis.findings);
        let findings = resolve_findings(findings, config);
        let report = AnalysisArtifactReport {
            reason: String::from("sniff-test-artifact"),
            format_version: REPORT_FORMAT_VERSION,
            tool_version: tool_version.clone(),
            rustc_version: rustc_version.clone(),
            artifact: artifact.clone(),
            scope,
            dependencies: dependencies.clone(),
            findings,
        };
        let cache = CachedArtifactAnalysis::new(
            tool_version,
            rustc_version,
            artifact,
            dependencies,
            effect_analysis.function_summaries,
        );

        Self { report, cache }
    }
}

struct RootEffectAnalysis {
    missing_roots: Vec<MissingReportRoot>,
    function_summaries: Vec<CachedFunctionSummary>,
    findings: Vec<Finding>,
}

struct EffectRootAnalysis {
    summary: CachedEffectSummary,
    findings: Vec<Finding>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EffectViewPurpose {
    Report,
    Cache,
}

struct EffectSnapshotAnalysis {
    findings: Vec<Finding>,
    cached_findings: Vec<CachedFinding>,
    dependency_complete: bool,
}

trait EffectPass<'tcx> {
    fn kind(&self) -> EffectKind;
    fn report_includes_external_mir(&self) -> bool {
        false
    }
    fn query(
        &self,
        reachability: &mut ReachabilityIndex<'tcx>,
        root: ReportRoot<'tcx>,
        analysis_config: &AnalysisConfig,
        include_external_mir: bool,
    ) -> reachability::ReachabilitySnapshot<'tcx>;
    fn path_index(&self, tcx: TyCtxt<'tcx>, view: ReachabilityView<'_, 'tcx>) -> EffectPathIndex;
    fn has_root_contract(&self, tcx: TyCtxt<'tcx>, root: DefId) -> bool;
    fn analyze_snapshot(
        &mut self,
        tcx: TyCtxt<'tcx>,
        view: ReachabilityView<'_, 'tcx>,
        root: ReportRoot<'tcx>,
        purpose: EffectViewPurpose,
        dependency_cache: &DependencyAnalysisCache,
        include_stack: bool,
    ) -> EffectSnapshotAnalysis;
}

struct PanicPass<'config> {
    config: &'config PanicConfig,
}

impl<'tcx> EffectPass<'tcx> for PanicPass<'_> {
    fn kind(&self) -> EffectKind {
        EffectKind::Panic
    }

    fn report_includes_external_mir(&self) -> bool {
        true
    }

    fn query(
        &self,
        reachability: &mut ReachabilityIndex<'tcx>,
        root: ReportRoot<'tcx>,
        analysis_config: &AnalysisConfig,
        include_external_mir: bool,
    ) -> reachability::ReachabilitySnapshot<'tcx> {
        let mut hooks = PanicReachabilityHooks {
            config: self.config,
            descend_reified_callables: analysis_config.callable_edge_attribution
                == CallableEdgeAttribution::ErasureSites,
        };
        reachability.query(
            root.reachability_root(),
            &mut hooks,
            reachability_options(analysis_config, include_external_mir),
        )
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
        include_stack: bool,
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
            include_stack,
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

struct SafetyPass<'config, 'analysis> {
    config: &'config crate::config::SafetyConfig,
    analysis: &'analysis mut SafetyAnalysis,
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
        _include_external_mir: bool,
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
        _include_stack: bool,
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

fn analyze_effect_root<'tcx>(
    tcx: TyCtxt<'tcx>,
    reachability: &mut ReachabilityIndex<'tcx>,
    root: ReportRoot<'tcx>,
    analysis_config: &AnalysisConfig,
    dependency_cache: &DependencyAnalysisCache,
    pass: &mut impl EffectPass<'tcx>,
) -> EffectRootAnalysis {
    let kind = pass.kind();
    let report_includes_external_mir = pass.report_includes_external_mir();
    let report_snapshot = pass.query(
        reachability,
        root,
        analysis_config,
        report_includes_external_mir,
    );
    let report_complete = reachability.graph().view(&report_snapshot).halt().is_none();
    let report_analysis = {
        let view = reachability.graph().view(&report_snapshot);
        pass.analyze_snapshot(
            tcx,
            view,
            root,
            EffectViewPurpose::Report,
            dependency_cache,
            analysis_config.show_full_stack_trace,
        )
    };
    let mut findings = report_analysis.findings;

    let (cached_findings, dependency_complete, cache_complete, graph) =
        if report_includes_external_mir {
            // User-facing panic reports can inspect available external MIR. Cached
            // summaries stop at dependency boundaries so downstream crates can
            // combine them with independently versioned dependency caches.
            let cache_snapshot = pass.query(reachability, root, analysis_config, false);
            let view = reachability.graph().view(&cache_snapshot);
            let cache_analysis = pass.analyze_snapshot(
                tcx,
                view,
                root,
                EffectViewPurpose::Cache,
                dependency_cache,
                analysis_config.show_full_stack_trace,
            );
            (
                cache_analysis.cached_findings,
                cache_analysis.dependency_complete,
                view.halt().is_none(),
                cached_reachability_graph(tcx, view),
            )
        } else {
            let view = reachability.graph().view(&report_snapshot);
            (
                report_analysis.cached_findings,
                report_analysis.dependency_complete,
                report_complete,
                cached_reachability_graph(tcx, view),
            )
        };
    let analysis_complete = report_complete && cache_complete && dependency_complete;
    if !report_complete || !cache_complete {
        let mut finding =
            analysis_incomplete_finding(tcx, root.def_id(), analysis_config.node_limit, kind);
        finding.root = Some(canonical_namespace(tcx, root.def_id()));
        finding.root_kind = Some(root.kind());
        findings.push(finding);
    }
    EffectRootAnalysis {
        summary: CachedEffectSummary {
            analysis_complete,
            has_contract: pass.has_root_contract(tcx, root.def_id()),
            graph: Some(graph),
            findings: cached_findings,
        },
        findings,
    }
}

fn analyze_effect_roots<'tcx>(
    tcx: TyCtxt<'tcx>,
    selection: ReportRootSelection<'tcx>,
    analysis_config: &AnalysisConfig,
    config: &SniffTestConfig,
    dependency_cache: &DependencyAnalysisCache,
) -> RootEffectAnalysis {
    let mut analysis = RootEffectAnalysis {
        missing_roots: selection.missing_roots,
        function_summaries: Vec::new(),
        findings: Vec::new(),
    };
    let mut reachability = ReachabilityIndex::new(tcx);
    let mut safety_analysis = SafetyAnalysis::default();
    let mut findings_by_effect = BTreeMap::<EffectKind, Vec<Finding>>::new();

    for root in selection.roots {
        let mut effects = BTreeMap::new();
        for kind in EffectKind::ANALYSIS_ORDER {
            let effect = match kind {
                EffectKind::Panic => analyze_effect_root(
                    tcx,
                    &mut reachability,
                    root,
                    analysis_config,
                    dependency_cache,
                    &mut PanicPass {
                        config: &config.panics,
                    },
                ),
                EffectKind::Safety => analyze_effect_root(
                    tcx,
                    &mut reachability,
                    root,
                    analysis_config,
                    dependency_cache,
                    &mut SafetyPass {
                        config: &config.safety,
                        analysis: &mut safety_analysis,
                    },
                ),
            };
            effects.insert(kind, effect.summary);
            findings_by_effect
                .entry(kind)
                .or_default()
                .extend(effect.findings);
        }
        analysis.function_summaries.push(CachedFunctionSummary {
            def_path_hash: stable_def_path_hash(tcx, root.def_id()),
            path: canonical_namespace(tcx, root.def_id()),
            is_generic: root.kind() == ReportRootKind::Generic,
            root_span: cached_source_span(tcx, tcx.def_span(root.def_id())),
            effects,
        });
    }
    for kind in EffectKind::ANALYSIS_ORDER {
        analysis
            .findings
            .extend(findings_by_effect.remove(&kind).unwrap_or_default());
    }

    analysis
}

impl CrateOutputScope {
    pub(crate) fn current(args: &SniffTestArgs) -> anyhow::Result<Self> {
        let cargo_manifest = std::env::var_os("CARGO_MANIFEST_PATH")
            .map(|path| {
                let path = PathBuf::from(path);
                path.canonicalize().with_context(|| {
                    format!("failed to canonicalize Cargo manifest {}", path.display())
                })
            })
            .transpose()?;
        Ok(Self::from_manifest_paths(
            &args.workspace_manifests,
            cargo_manifest.as_deref(),
            std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some(),
        ))
    }

    #[must_use]
    fn from_manifest_paths(
        workspace_manifests: &[PathBuf],
        cargo_manifest: Option<&Path>,
        primary_package: bool,
    ) -> Self {
        // Membership comes from `cargo metadata`, plumbed by the frontend;
        // path prefixes would demote out-of-dir members and promote vendored
        // crates. Direct driver mode has no member list and falls back to
        // CARGO_PRIMARY_PACKAGE.
        let is_workspace_crate = match cargo_manifest {
            Some(manifest) if !workspace_manifests.is_empty() => {
                workspace_manifests.iter().any(|member| member == manifest)
            }
            _ => primary_package,
        };
        if is_workspace_crate {
            Self::Workspace
        } else {
            Self::Dependency
        }
    }

    pub(crate) fn for_crate(self, tcx: TyCtxt<'_>) -> Self {
        // Proc macros also execute during compilation rather than shipping as
        // target code. Use rustc's effective crate types so crate attributes
        // and command-line options are both handled by the compiler.
        if tcx.crate_types().contains(&CrateType::ProcMacro) {
            Self::Dependency
        } else {
            self
        }
    }
}

pub(crate) fn is_build_script(tcx: TyCtxt<'_>) -> bool {
    // Match rustc's own best-effort Cargo build-script detection in
    // `rustc_attr_parsing/attributes/diagnostic/check_cfg.rs`: Cargo invokes
    // these targets with `--crate-name build_script_build`.
    tcx.crate_name(LOCAL_CRATE).as_str() == "build_script_build"
}

fn reachability_options(
    analysis_config: &AnalysisConfig,
    analyze_external: bool,
) -> ReachabilityOptions {
    ReachabilityOptions {
        node_limit: Some(analysis_config.node_limit),
        analyze_external,
        dyn_dispatch_vtable_edges: analysis_config.callable_edge_attribution.into(),
        fn_pointer_edges: analysis_config.callable_edge_attribution.into(),
    }
}

fn artifact_info(tcx: TyCtxt<'_>) -> CachedArtifactInfo {
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
    let extra_filename = tcx.sess.opts.cg.extra_filename.as_str();
    CachedArtifactInfo {
        artifact_id: artifact_id(
            &crate_name,
            (!extra_filename.is_empty()).then_some(extra_filename),
        ),
        crate_name,
    }
}

fn dependency_inputs(tcx: TyCtxt<'_>) -> Vec<DependencyInput> {
    let mut inputs = Vec::new();
    for (name, entry) in tcx.sess.opts.externs.iter() {
        // rustc accepts `--extern name` and resolves it through library search
        // paths, but without the resolved path we cannot identify one exact
        // artifact cache safely.
        let Some(files) = entry.files() else {
            continue;
        };
        inputs.extend(files.map(|file| DependencyInput {
            name: name.clone(),
            path: file.original().clone(),
        }));
    }
    inputs
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

pub(super) fn is_trusted_panic_obligation(
    tcx: TyCtxt<'_>,
    documented_def_id: DefId,
    config: &PanicConfig,
) -> bool {
    config.panic_boundary_policy(tcx, documented_def_id)
        == PanicBoundaryPolicy::TrustedPanicObligation
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

    marker_claims.extend(boundary.resolved.marker_claims);
    for unresolved in boundary.resolved.unresolved_findings {
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
    if !boundary.resolved.has_raw_findings
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

struct CachedEffectBoundary<'view, 'tcx, 'cache> {
    edge: reachability::ReachedEdge<'view, 'tcx>,
    function: &'cache CachedFunctionSummary,
    effect: &'cache CachedEffectSummary,
}

struct ResolvedCachedBoundary<'view, 'tcx, 'cache> {
    edge: reachability::ReachedEdge<'view, 'tcx>,
    function: &'cache CachedFunctionSummary,
    effect: &'cache CachedEffectSummary,
    trace: EffectTrace,
    resolved: ResolvedCachedEffect<'cache>,
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

fn resolved_cached_effect_boundaries<'view, 'tcx, 'cache>(
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
                resolved,
            })
        })
        .collect()
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

pub(crate) fn load_config(
    args: &SniffTestArgs,
) -> Result<SniffTestConfig, crate::config::ConfigError> {
    let path = args.manifest_path();
    if path.exists() {
        SniffTestConfig::from_manifest_path(path)
    } else {
        Ok(SniffTestConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::CrateOutputScope;

    #[test]
    fn output_scope_classifies_workspace_dependency_and_fallback_crates() {
        let members = [
            PathBuf::from("/repo/crates/sniff-test/Cargo.toml"),
            PathBuf::from("/shared/utils/Cargo.toml"),
        ];

        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                &members,
                Some(Path::new("/repo/crates/sniff-test/Cargo.toml")),
                false,
            ),
            CrateOutputScope::Workspace
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                &members,
                Some(Path::new("/shared/utils/Cargo.toml")),
                false,
            ),
            CrateOutputScope::Workspace
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                &members,
                Some(Path::new("/repo/vendor/foo/Cargo.toml")),
                false,
            ),
            CrateOutputScope::Dependency
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                &members,
                Some(Path::new(
                    "/home/user/.cargo/registry/src/index.crates.io/hashbrown/Cargo.toml",
                )),
                true,
            ),
            CrateOutputScope::Dependency
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(&[], None, true),
            CrateOutputScope::Workspace
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                &[],
                Some(Path::new("/repo/crates/sniff-test/Cargo.toml")),
                false,
            ),
            CrateOutputScope::Dependency
        );
    }
}
