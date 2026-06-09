//! Executable plumbing for the sniff-test Cargo/rustc integration.

#![feature(rustc_private)]
#![deny(warnings)]
#![warn(clippy::pedantic)]

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_span;

use std::collections::HashSet;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use reachability::{
    ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityEdgeId,
    ReachabilityEdgeKind, ReachabilityGraph, ReachabilityHooks, ReachabilityIndex,
    ReachabilityNodeKind, ReachabilityOptions, ReachabilityRoot, ReachabilitySnapshot,
    ReachabilityView,
};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_middle::ty::{Instance, TyCtxt};
use sniff_test::cache::{
    CachedArtifactAnalysis, CachedArtifactInfo, CachedDependencyRef, CachedFinding,
    CachedFindingKind, CachedFindingTarget, CachedFunctionSummary, CachedReachabilityEdge,
    CachedReachabilityEdgeKind, CachedReachabilityGraph, CachedReachabilityNode,
    CachedReachabilityNodeKind, artifact_id, write_artifact_analysis,
};
use sniff_test::config::{PanicConfig, SniffTestConfig, TrustPolicy};
use sniff_test::dependency_cache::{DependencyAnalysisCache, DependencyInput};
use sniff_test::namespace::canonical_namespace;
use sniff_test::panics::{
    PanicAnalysis, PanicEvidence, PanicEvidenceKind, PanicPathDecision, analyze_panic_evidence,
    describe_panic_evidence_kind, trace_edges_until, trace_to_edge_ids, trigger_edge_id,
};
use sniff_test::report_roots::{ReportRoot, ReportRootSelection, select_panic_report_roots};

mod args;
mod plugin;
mod report;
mod rustc_invocation;

pub use args::SniffTestArgs;
pub use plugin::SniffTestPlugin;

use args::colors_enabled;
use report::{
    PanicReport, PanicReportOutput, ReportDetailKind, emit_crate_panic_summary,
    emit_dependency_panic_summary, emit_missing_report_root, render_node, render_span,
    render_span_start,
};
use rustc_invocation::RustcInvocation;

const REACHABILITY_NODE_LIMIT: usize = 4096;

pub(crate) fn absolute_path(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .unwrap_or_else(|error| {
                eprintln!("sniff-test: failed to read current directory: {error}");
                std::process::exit(2);
            })
            .join(path)
    }
}

struct PanicReachabilityHooks<'config> {
    config: &'config PanicConfig,
}

impl<'tcx> ReachabilityHooks<'tcx> for PanicReachabilityHooks<'_> {
    fn should_descend(
        &mut self,
        cx: ReachabilityContext<'tcx>,
        _edge: &ReachabilityEdge,
        target: Instance<'tcx>,
    ) -> ReachabilityControl<'tcx, bool> {
        ControlFlow::Continue(!self.config.ignores_def(cx.tcx, target.def_id()))
    }
}

pub(crate) fn analyze_crate(tcx: TyCtxt<'_>, args: &SniffTestArgs, compiler_args: &[String]) {
    let config = load_config(args);
    let invocation = RustcInvocation::parse(compiler_args);
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
    let color = colors_enabled(args.color, invocation.color);
    let output_scope = CrateOutputScope::current(args);
    let emits_detailed_reports = matches!(output_scope, CrateOutputScope::Workspace);

    if config.panics.ignored_namespace_match(&crate_name).is_some() {
        return;
    }

    let dependency_cache = DependencyAnalysisCache::load(
        &args.cache_dir(),
        invocation.externs.iter().map(|extern_arg| DependencyInput {
            name: extern_arg.name.clone(),
            path: extern_arg.path.clone(),
        }),
        &config.panics,
    );

    let selection = select_panic_report_roots(tcx, &config.panics);
    if emits_detailed_reports {
        for missing_root in &selection.missing_roots {
            emit_missing_report_root(&crate_name, missing_root, color);
        }
    }
    let root_analysis = analyze_report_roots(
        tcx,
        selection,
        &config.panics,
        &dependency_cache,
        emits_detailed_reports.then_some(PanicReportOutput {
            crate_name: &crate_name,
            color,
        }),
    );

    write_analysis_summary(
        tcx,
        args,
        &invocation,
        dependency_cache.resolved_dependencies(),
        root_analysis.function_summaries,
    );

    match output_scope {
        CrateOutputScope::Workspace => emit_crate_panic_summary(
            &crate_name,
            root_analysis.concrete_roots,
            root_analysis.generic_roots,
            root_analysis.counts,
            dependency_cache.hit_count(),
            dependency_cache.dependency_count(),
            color,
        ),
        CrateOutputScope::Dependency => emit_dependency_panic_summary(
            &crate_name,
            root_analysis.concrete_roots,
            root_analysis.generic_roots,
            root_analysis.counts,
            dependency_cache.hit_count(),
            dependency_cache.dependency_count(),
            color,
        ),
    }
}

struct RootAnalysis {
    concrete_roots: usize,
    generic_roots: usize,
    counts: PanicFindingCounts,
    function_summaries: Vec<CachedFunctionSummary>,
}

fn analyze_report_roots<'tcx>(
    tcx: TyCtxt<'tcx>,
    selection: ReportRootSelection<'tcx>,
    config: &PanicConfig,
    dependency_cache: &DependencyAnalysisCache,
    report_output: Option<PanicReportOutput<'_>>,
) -> RootAnalysis {
    let mut analysis = RootAnalysis {
        concrete_roots: 0,
        generic_roots: 0,
        counts: PanicFindingCounts::default(),
        function_summaries: Vec::new(),
    };
    let mut reachability = ReachabilityIndex::new(tcx);

    for root in selection.roots {
        let root = match root {
            ReportRoot::Concrete { instance, .. } => {
                analysis.concrete_roots += 1;
                AnalysisRoot {
                    root: ReachabilityRoot::Instance(instance),
                    def_id: instance.def_id(),
                    is_generic: false,
                }
            }
            ReportRoot::Generic { local } => {
                analysis.generic_roots += 1;
                AnalysisRoot {
                    root: ReachabilityRoot::LocalBody(local),
                    def_id: local.to_def_id(),
                    is_generic: true,
                }
            }
        };
        let (findings, summary) = analyze_root(
            tcx,
            &mut reachability,
            root,
            config,
            dependency_cache,
            report_output,
        );
        analysis.counts.add(findings);
        analysis.function_summaries.push(summary);
    }

    analysis
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrateOutputScope {
    Workspace,
    Dependency,
}

impl CrateOutputScope {
    #[must_use]
    fn current(args: &SniffTestArgs) -> Self {
        let config_path = absolute_path(args.manifest_path());
        let cargo_manifest =
            std::env::var_os("CARGO_MANIFEST_PATH").map(|path| absolute_path(PathBuf::from(path)));
        Self::from_manifest_paths(
            &config_path,
            cargo_manifest.as_deref(),
            std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some(),
        )
    }

    #[must_use]
    fn from_manifest_paths(
        config_path: &Path,
        cargo_manifest: Option<&Path>,
        primary_package: bool,
    ) -> Self {
        let is_workspace_crate = cargo_manifest
            .and_then(|manifest| {
                config_path
                    .parent()
                    .map(|config_root| manifest.starts_with(config_root))
            })
            .unwrap_or(primary_package);
        if is_workspace_crate {
            Self::Workspace
        } else {
            Self::Dependency
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AnalysisRoot<'tcx> {
    root: ReachabilityRoot<'tcx>,
    def_id: DefId,
    is_generic: bool,
}

fn analyze_root<'tcx>(
    tcx: TyCtxt<'tcx>,
    reachability: &mut ReachabilityIndex<'tcx>,
    root: AnalysisRoot<'tcx>,
    config: &PanicConfig,
    dependency_cache: &DependencyAnalysisCache,
    report_output: Option<PanicReportOutput<'_>>,
) -> (PanicFindingCounts, CachedFunctionSummary) {
    let mut hooks = PanicReachabilityHooks { config };
    let result = reachability.query(
        root.root,
        &mut hooks,
        ReachabilityOptions {
            node_limit: Some(REACHABILITY_NODE_LIMIT),
            ..ReachabilityOptions::default()
        },
    );
    let graph = reachability.graph();
    let analysis = analyze_panic_evidence(tcx, graph, &result, config);
    let findings = emit_panic_findings(
        tcx,
        graph,
        &result,
        &analysis,
        config,
        dependency_cache,
        report_output,
    );

    let mut boundary_hooks = PanicReachabilityHooks { config };
    let boundary_result = reachability.query(
        root.root,
        &mut boundary_hooks,
        ReachabilityOptions {
            node_limit: Some(REACHABILITY_NODE_LIMIT),
            analyze_external: false,
            ..ReachabilityOptions::default()
        },
    );
    let graph = reachability.graph();
    let boundary_analysis = analyze_panic_evidence(tcx, graph, &boundary_result, config);
    let cached_findings =
        cached_boundary_findings(tcx, graph, &boundary_result, &boundary_analysis, config);
    let summary = function_summary(
        tcx,
        root.def_id,
        root.is_generic,
        findings,
        Some((graph, &boundary_result)),
        cached_findings,
    );

    (findings, summary)
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PanicFindingCounts {
    pub(crate) raw_panic_paths: usize,
    pub(crate) panic_obligations: usize,
    pub(crate) trusted_panic_obligations: usize,
}

impl PanicFindingCounts {
    fn add(&mut self, other: Self) {
        self.raw_panic_paths += other.raw_panic_paths;
        self.panic_obligations += other.panic_obligations;
        self.trusted_panic_obligations += other.trusted_panic_obligations;
    }
}

fn function_summary<'tcx>(
    tcx: TyCtxt<'tcx>,
    def_id: DefId,
    is_generic: bool,
    counts: PanicFindingCounts,
    graph: Option<(&ReachabilityGraph<'tcx>, &ReachabilitySnapshot<'tcx>)>,
    findings: Vec<CachedFinding>,
) -> CachedFunctionSummary {
    CachedFunctionSummary {
        path: canonical_namespace(tcx, def_id),
        is_generic,
        has_panic_docs: sniff_test::panics::has_panic_docs(tcx, def_id),
        raw_panic_paths: counts.raw_panic_paths,
        panic_obligations: counts.panic_obligations,
        trusted_panic_obligations: counts.trusted_panic_obligations,
        graph: graph.map(|(graph, result)| cached_reachability_graph(tcx, graph, result)),
        findings,
    }
}

fn cached_boundary_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    result: &ReachabilitySnapshot<'tcx>,
    analysis: &PanicAnalysis,
    config: &PanicConfig,
) -> Vec<CachedFinding> {
    let view = graph.view(result);
    let mut findings = analysis
        .evidence
        .iter()
        .map(|evidence| cached_panic_finding(tcx, graph, evidence, config))
        .collect::<Vec<_>>();

    findings.extend(cached_crate_boundary_findings(tcx, view, config));
    findings
}

fn cached_panic_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    config: &PanicConfig,
) -> CachedFinding {
    match evidence.decision {
        PanicPathDecision::RawPanic => {
            let edge_id = trigger_edge_id(graph, evidence);
            let edge = graph.edge(edge_id);
            CachedFinding {
                kind: match &evidence.kind {
                    PanicEvidenceKind::CompilerAssert => CachedFindingKind::CompilerAssert,
                    PanicEvidenceKind::PanicObligation { .. } => CachedFindingKind::PanicObligation,
                    PanicEvidenceKind::PanicSink { .. } => CachedFindingKind::PanicInvocation,
                },
                span: render_span(tcx, edge.span),
                edge_index: Some(edge_id.index()),
                trace: evidence
                    .trace
                    .edge_ids
                    .iter()
                    .map(|edge_id| edge_id.index())
                    .collect(),
                reason: describe_panic_evidence_kind(tcx, &evidence.kind),
                target: Some(cached_finding_target(tcx, graph, edge.target)),
            }
        }
        PanicPathDecision::PanicObligation { edge_id, def_id } => {
            let trusted = is_trusted_panic_obligation(tcx, graph, edge_id, def_id, config);
            let (span, target) = edge_id.map_or_else(
                || {
                    (
                        render_span(tcx, tcx.def_span(def_id)),
                        CachedFindingTarget::Function {
                            path: canonical_namespace(tcx, def_id),
                            crate_name: tcx.crate_name(def_id.krate).to_string(),
                            is_local: def_id.is_local(),
                        },
                    )
                },
                |edge_id| {
                    let edge = graph.edge(edge_id);
                    (
                        render_span(tcx, edge.span),
                        cached_finding_target(tcx, graph, edge.target),
                    )
                },
            );
            CachedFinding {
                kind: if trusted {
                    CachedFindingKind::TrustedPanicObligation
                } else {
                    CachedFindingKind::PanicObligation
                },
                span,
                edge_index: edge_id.map(ReachabilityEdgeId::index),
                trace: trace_edges_until(evidence, edge_id)
                    .iter()
                    .map(|edge_id| edge_id.index())
                    .collect(),
                reason: format!(
                    "{} is documented panicable",
                    canonical_namespace(tcx, def_id)
                ),
                target: Some(target),
            }
        }
    }
}

fn cached_crate_boundary_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    config: &PanicConfig,
) -> Vec<CachedFinding> {
    view.edges()
        .filter_map(|edge| {
            let source = edge.source().instance()?.def_id();
            let target = edge.target().instance()?.def_id();
            if !source.is_local() || target.is_local() {
                return None;
            }
            let target_path = canonical_namespace(tcx, target);
            if config.ignores_def(tcx, target) {
                return None;
            }

            Some(CachedFinding {
                kind: CachedFindingKind::CrateBoundary,
                span: render_span(tcx, edge.span()),
                edge_index: Some(edge.id().index()),
                trace: trace_to_edge_ids(edge)
                    .iter()
                    .map(|edge_id| edge_id.index())
                    .collect(),
                reason: format!("crate boundary {} to {}", edge.kind(), target_path),
                target: Some(CachedFindingTarget::Function {
                    path: target_path,
                    crate_name: tcx.crate_name(target.krate).to_string(),
                    is_local: false,
                }),
            })
        })
        .collect()
}

fn cached_finding_target<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    node: reachability::ReachabilityNodeId,
) -> CachedFindingTarget {
    match &graph.node(node).kind {
        ReachabilityNodeKind::Instance(instance) => CachedFindingTarget::Function {
            path: canonical_namespace(tcx, instance.def_id()),
            crate_name: tcx.crate_name(instance.def_id().krate).to_string(),
            is_local: instance.def_id().is_local(),
        },
        kind => CachedFindingTarget::Node {
            node_index: node.index(),
            label: render_node(tcx, kind),
        },
    }
}

fn cached_reachability_graph<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    result: &ReachabilitySnapshot<'tcx>,
) -> CachedReachabilityGraph {
    let view = graph.view(result);
    CachedReachabilityGraph {
        root: view.root().id().index(),
        nodes: view
            .nodes()
            .map(|node| CachedReachabilityNode {
                id: node.id().index(),
                depth: node.depth(),
                kind: cached_reachability_node_kind(tcx, node.kind()),
            })
            .collect(),
        edges: view
            .edges()
            .map(|edge| CachedReachabilityEdge {
                source: edge.source().id().index(),
                target: edge.target().id().index(),
                kind: cached_reachability_edge_kind(edge.kind()),
                span: render_span(tcx, edge.span()),
            })
            .collect(),
    }
}

fn cached_reachability_node_kind<'tcx>(
    tcx: TyCtxt<'tcx>,
    node: &ReachabilityNodeKind<'tcx>,
) -> CachedReachabilityNodeKind {
    match node {
        ReachabilityNodeKind::Instance(instance) => CachedReachabilityNodeKind::Instance {
            path: canonical_namespace(tcx, instance.def_id()),
            crate_name: tcx.crate_name(instance.def_id().krate).to_string(),
            is_local: instance.def_id().is_local(),
        },
        ReachabilityNodeKind::CompilerAssert { message } => {
            CachedReachabilityNodeKind::CompilerAssert {
                message: format!("{message:?}"),
            }
        }
        ReachabilityNodeKind::IndirectCall { callee_ty } => {
            CachedReachabilityNodeKind::IndirectCall {
                callee_ty: format!("{callee_ty:?}"),
            }
        }
        ReachabilityNodeKind::DynObjectCast {
            source_ty,
            target_ty,
        } => CachedReachabilityNodeKind::DynObjectCast {
            source_ty: format!("{source_ty:?}"),
            target_ty: format!("{target_ty:?}"),
        },
    }
}

fn cached_reachability_edge_kind(kind: ReachabilityEdgeKind) -> CachedReachabilityEdgeKind {
    match kind {
        ReachabilityEdgeKind::DirectCall => CachedReachabilityEdgeKind::DirectCall,
        ReachabilityEdgeKind::TailCall => CachedReachabilityEdgeKind::TailCall,
        ReachabilityEdgeKind::FnPointerReify => CachedReachabilityEdgeKind::FnPointerReify,
        ReachabilityEdgeKind::ClosureFnPointerReify => {
            CachedReachabilityEdgeKind::ClosureFnPointerReify
        }
        ReachabilityEdgeKind::ClosureDefinition => CachedReachabilityEdgeKind::ClosureDefinition,
        ReachabilityEdgeKind::DynObjectCast => CachedReachabilityEdgeKind::DynObjectCast,
        ReachabilityEdgeKind::VTableEntry => CachedReachabilityEdgeKind::VTableEntry,
        ReachabilityEdgeKind::ConstBody => CachedReachabilityEdgeKind::ConstBody,
        ReachabilityEdgeKind::Assert => CachedReachabilityEdgeKind::Assert,
        ReachabilityEdgeKind::IndirectCall => CachedReachabilityEdgeKind::IndirectCall,
    }
}

fn write_analysis_summary(
    tcx: TyCtxt<'_>,
    args: &SniffTestArgs,
    invocation: &RustcInvocation,
    dependencies: Vec<CachedDependencyRef>,
    functions: Vec<CachedFunctionSummary>,
) {
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
    let artifact = CachedArtifactInfo {
        artifact_id: artifact_id(&crate_name, invocation.extra_filename.as_deref()),
        crate_name,
        crate_types: invocation.crate_types.clone(),
        package_name: std::env::var("CARGO_PKG_NAME").ok(),
        package_version: std::env::var("CARGO_PKG_VERSION").ok(),
        manifest_path: std::env::var("CARGO_MANIFEST_PATH").ok(),
        target: invocation.target.clone(),
        metadata: invocation.metadata.clone(),
        extra_filename: invocation.extra_filename.clone(),
    };
    let analysis = CachedArtifactAnalysis::new(
        env!("CARGO_PKG_VERSION"),
        rustc_plugin::CHANNEL,
        artifact,
        dependencies,
        functions,
    );

    if let Err(error) = write_artifact_analysis(&args.cache_dir(), &analysis) {
        eprintln!("sniff-test: failed to write analysis cache: {error}");
    }
}

fn emit_panic_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    result: &ReachabilitySnapshot<'tcx>,
    analysis: &PanicAnalysis,
    config: &PanicConfig,
    dependency_cache: &DependencyAnalysisCache,
    report_output: Option<PanicReportOutput<'_>>,
) -> PanicFindingCounts {
    let mut counts = PanicFindingCounts::default();
    let view = graph.view(result);
    let root_node = view.root();
    let mut report = PanicReport::new(
        render_node(tcx, root_node.kind()),
        root_declaration_span(tcx, root_node.kind()),
        config.show_full_stack_trace,
    );

    for evidence in &analysis.evidence {
        match evidence.decision {
            PanicPathDecision::RawPanic => {
                counts.raw_panic_paths += 1;
                report.push_panic_evidence(tcx, graph, evidence);
            }
            PanicPathDecision::PanicObligation { edge_id, def_id } => {
                if is_trusted_panic_obligation(tcx, graph, edge_id, def_id, config) {
                    counts.trusted_panic_obligations += 1;
                    report.push_panic_obligation(
                        tcx,
                        graph,
                        evidence,
                        edge_id,
                        def_id,
                        ReportDetailKind::TrustedPanicObligation,
                    );
                } else {
                    counts.panic_obligations += 1;
                    report.push_panic_obligation(
                        tcx,
                        graph,
                        evidence,
                        edge_id,
                        def_id,
                        ReportDetailKind::PanicObligation,
                    );
                }
            }
        }
    }

    emit_cached_dependency_findings(
        tcx,
        graph,
        view,
        config,
        dependency_cache,
        &mut counts,
        &mut report,
    );

    if let Some(output) = report_output {
        report.emit(output.crate_name, output.color);
    }
    counts
}

fn root_declaration_span(tcx: TyCtxt<'_>, root: &ReachabilityNodeKind<'_>) -> Option<String> {
    match root {
        ReachabilityNodeKind::Instance(instance) => {
            Some(render_span_start(tcx, tcx.def_span(instance.def_id())))
        }
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::IndirectCall { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => None,
    }
}

fn is_trusted_panic_obligation<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_id: Option<ReachabilityEdgeId>,
    documented_def_id: DefId,
    config: &PanicConfig,
) -> bool {
    match edge_id {
        None => {
            documented_def_id.is_local()
                && config.trust_current_crate_panic_docs == TrustPolicy::Trust
        }
        Some(edge_id) => instance_def_id(graph, graph.edge(edge_id).source)
            .is_some_and(|source_def_id| config.trusts_panic_obligation_def(tcx, source_def_id)),
    }
}

fn instance_def_id(
    graph: &ReachabilityGraph<'_>,
    node: reachability::ReachabilityNodeId,
) -> Option<DefId> {
    match &graph.node(node).kind {
        ReachabilityNodeKind::Instance(instance) => Some(instance.def_id()),
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::IndirectCall { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => None,
    }
}

fn emit_cached_dependency_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    config: &PanicConfig,
    dependency_cache: &DependencyAnalysisCache,
    counts: &mut PanicFindingCounts,
    report: &mut PanicReport,
) {
    let expanded_sources = view
        .edges()
        .map(|edge| edge.source().id().index())
        .collect::<HashSet<_>>();

    for edge in view.edges() {
        if !matches!(
            edge.kind(),
            ReachabilityEdgeKind::DirectCall | ReachabilityEdgeKind::TailCall
        ) || expanded_sources.contains(&edge.target().id().index())
        {
            continue;
        }

        let Some(instance) = edge.target().instance() else {
            continue;
        };
        if instance.def_id().is_local() {
            continue;
        }

        let def_id = instance.def_id();
        let path = canonical_namespace(tcx, def_id);
        if config.ignores_def(tcx, def_id) {
            continue;
        }

        let dependency_crate_name = tcx.crate_name(def_id.krate).to_string();
        let Some(summary) = dependency_cache.function(&dependency_crate_name, &path) else {
            continue;
        };

        if summary.has_panic_docs
            || summary.panic_obligations > 0
            || summary.trusted_panic_obligations > 0
        {
            if is_trusted_panic_obligation(tcx, graph, Some(edge.id()), instance.def_id(), config) {
                counts.trusted_panic_obligations += 1;
                report.push_cached_dependency_obligation(
                    tcx,
                    graph,
                    edge.id(),
                    summary,
                    ReportDetailKind::TrustedPanicObligation,
                );
            } else {
                counts.panic_obligations += 1;
                report.push_cached_dependency_obligation(
                    tcx,
                    graph,
                    edge.id(),
                    summary,
                    ReportDetailKind::PanicObligation,
                );
            }
        } else if summary.raw_panic_paths > 0 {
            counts.raw_panic_paths += 1;
            report.push_cached_dependency_panic(tcx, graph, edge.id(), summary);
        }
    }
}

fn load_config(args: &SniffTestArgs) -> SniffTestConfig {
    let path = args.manifest_path();
    if path.exists() {
        SniffTestConfig::from_manifest_path(path).unwrap_or_else(|error| {
            eprintln!("sniff-test: {error}");
            std::process::exit(2);
        })
    } else {
        SniffTestConfig::default()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::CrateOutputScope;

    #[test]
    fn output_scope_classifies_workspace_dependency_and_fallback_crates() {
        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                Path::new("/repo/sniff-test.toml"),
                Some(Path::new("/repo/crates/sniff-test-cli/Cargo.toml")),
                false,
            ),
            CrateOutputScope::Workspace
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                Path::new("/repo/sniff-test.toml"),
                Some(Path::new(
                    "/home/user/.cargo/registry/src/index.crates.io/hashbrown/Cargo.toml",
                )),
                true,
            ),
            CrateOutputScope::Dependency
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(Path::new("/repo/sniff-test.toml"), None, true),
            CrateOutputScope::Workspace
        );
        assert_eq!(
            CrateOutputScope::from_manifest_paths(Path::new("/repo/sniff-test.toml"), None, false),
            CrateOutputScope::Dependency
        );
    }
}
