//! Executable plumbing for the sniff-test Cargo/rustc integration.

use std::collections::HashSet;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::cache::{
    CachedArtifactAnalysis, CachedArtifactInfo, CachedDependencyRef, CachedDiagnosticSpan,
    CachedFinding, CachedFindingKind, CachedFindingTarget, CachedFunctionSummary,
    CachedReachabilityEdge, CachedReachabilityEdgeKind, CachedReachabilityGraph,
    CachedReachabilityNode, CachedReachabilityNodeKind, CachedSourceSpan, artifact_id,
    write_artifact_analysis,
};
use crate::config::{PanicBoundaryPolicy, PanicConfig, SniffTestConfig};
use crate::dependency_cache::{DependencyAnalysisCache, DependencyInput};
use crate::namespace::canonical_namespace;
use crate::panics::{
    PanicAnalysis, PanicEvidence, PanicEvidenceKind, PanicPathDecision, analyze_panic_evidence,
    describe_panic_evidence_kind, trace_edges_until, trace_to_edge_ids, trigger_edge_id,
};
use crate::report_roots::{ReportRoot, ReportRootSelection, select_panic_report_roots};
use crate::source_markers::span_has_safe_marker;
use reachability::{
    ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityEdgeId,
    ReachabilityEdgeKind, ReachabilityGraph, ReachabilityHooks, ReachabilityIndex,
    ReachabilityNodeKind, ReachabilityOptions, ReachabilityRoot, ReachabilitySnapshot,
    ReachabilityView,
};
use rustc_errors::{Diag, EmissionGuarantee};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_middle::ty::{Instance, TyCtxt};
use rustc_span::Pos;
use serde::Serialize;

mod args;
mod plugin;
mod report;
mod rustc_invocation;

pub use self::args::SniffTestArgs;
pub use self::plugin::driver_main;

use self::args::colors_enabled;
use self::plugin::{
    RAW_PANIC_STATUS_ENV, RUSTC_VERSION_ENV, SNIFF_TEST_ARGS_ENV, current_rustc_version,
    frontend_args, modify_cargo, rustc_version, rustc_version_dir_component,
};
use self::report::{
    PanicRootKind, PanicRootReport, ReportDetailKind, cached_dependency_panic_reason,
    emit_missing_report_root, render_assert_message, render_edge_without_span, render_node,
    render_span, render_span_start,
};
use self::rustc_invocation::RustcInvocation;

const REACHABILITY_NODE_LIMIT: usize = 4096;

#[must_use]
pub fn cargo_frontend() -> ExitCode {
    if std::env::args()
        .skip(1)
        .take_while(|arg| arg != "--")
        .any(|arg| arg == "-V" || arg == "--version")
    {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    let parsed_args = SniffTestArgs::parse_from_env();
    let metadata = match metadata_command(&parsed_args).exec() {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("sniff-test: failed to read Cargo metadata: {error}");
            return ExitCode::FAILURE;
        }
    };
    let rustc_version = current_rustc_version();
    let target_dir = metadata.target_directory.join(format!(
        "sniff-test-{}",
        rustc_version_dir_component(&rustc_version)
    ));
    let args = frontend_args(parsed_args, target_dir.as_std_path());
    let raw_panic_status = args.cache_dir().join("workspace-raw-panic");
    if let Err(error) = std::fs::remove_file(&raw_panic_status)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!(
            "sniff-test: failed to clear {}: {error}",
            raw_panic_status.display()
        );
        return ExitCode::FAILURE;
    }

    let mut cargo = Command::new("cargo");
    cargo.args(["check", "--target-dir"]).arg(&target_dir);
    if std::env::var_os("CARGO_VERBOSE").is_some() {
        cargo.arg("-vv");
    }
    cargo.env(RUSTC_VERSION_ENV, &rustc_version);
    cargo.env(RAW_PANIC_STATUS_ENV, &raw_panic_status);
    cargo.env(
        SNIFF_TEST_ARGS_ENV,
        serde_json::to_string(&args).unwrap_or_else(|error| {
            eprintln!("sniff-test: failed to encode driver arguments: {error}");
            std::process::exit(2);
        }),
    );
    modify_cargo(&mut cargo, &args);

    match cargo.status() {
        Ok(status) if status.success() => {
            if raw_panic_status.exists() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Ok(status) => {
            if raw_panic_status.exists() {
                ExitCode::FAILURE
            } else {
                match status.code() {
                    Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
                    None => ExitCode::FAILURE,
                }
            }
        }
        Err(error) => {
            eprintln!("sniff-test: failed to run Cargo: {error}");
            ExitCode::FAILURE
        }
    }
}

fn metadata_command(args: &SniffTestArgs) -> cargo_metadata::MetadataCommand {
    let mut command = cargo_metadata::MetadataCommand::new();
    command.no_deps();
    command.other_options(metadata_cargo_args(&args.cargo_args));
    command
}

fn metadata_cargo_args(cargo_args: &[String]) -> Vec<String> {
    let mut metadata_args = Vec::new();
    let mut iter = cargo_args.iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--manifest-path" | "-m" | "--features" | "-F" | "--filter-platform" | "--color"
            | "--config" | "-Z" => {
                metadata_args.push(arg.clone());
                if let Some(value) = iter.next() {
                    metadata_args.push(value.clone());
                }
            }
            "--all-features" | "--no-default-features" | "--locked" | "--offline" | "--frozen" => {
                metadata_args.push(arg.clone());
            }
            other
                if other.starts_with("--manifest-path=")
                    || other.starts_with("--features=")
                    || other.starts_with("--filter-platform=")
                    || other.starts_with("--color=")
                    || other.starts_with("--config=") =>
            {
                metadata_args.push(arg.clone());
            }
            _ => {}
        }
    }

    metadata_args
}

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
    fn should_record_edge(
        &mut self,
        cx: ReachabilityContext<'tcx>,
        edge: &ReachabilityEdge,
    ) -> ReachabilityControl<'tcx, bool> {
        ControlFlow::Continue(!span_has_safe_marker(cx.tcx, edge.span))
    }

    fn should_descend(
        &mut self,
        cx: ReachabilityContext<'tcx>,
        _edge: &ReachabilityEdge,
        target: Instance<'tcx>,
    ) -> ReachabilityControl<'tcx, bool> {
        let def_id = target.def_id();
        let should_descend = !self.config.ignores_def(cx.tcx, def_id)
            && self.config.panic_boundary_policy(cx.tcx, def_id) == PanicBoundaryPolicy::Normal;
        ControlFlow::Continue(should_descend)
    }
}

pub(crate) fn analyze_crate(tcx: TyCtxt<'_>, args: &SniffTestArgs, compiler_args: &[String]) {
    let config = load_config(args);
    let invocation = RustcInvocation::parse(compiler_args);
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
    let output_scope = CrateOutputScope::current(args);

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
    let diagnostics = PanicDiagnosticOptions {
        emit: args.message_format == args::MessageFormat::Human
            && output_scope == CrateOutputScope::Workspace,
        include_stack: config.panics.show_full_stack_trace,
    };
    let root_analysis = analyze_report_roots(
        tcx,
        selection,
        &config.panics,
        &dependency_cache,
        diagnostics,
    );

    let analysis = AnalysisArtifact::new(
        tcx,
        &invocation,
        output_scope,
        &dependency_cache,
        root_analysis,
    );
    write_analysis_cache(args, &analysis.cache);
    emit_analysis_artifact(&analysis.report, args, invocation.color);
    if analysis.report.scope == CrateOutputScope::Workspace
        && analysis.report.counts.raw_panic_paths > 0
    {
        record_workspace_raw_panic();
    }
}

struct AnalysisArtifact {
    report: AnalysisArtifactReport,
    cache: CachedArtifactAnalysis,
}

impl AnalysisArtifact {
    fn new(
        tcx: TyCtxt<'_>,
        invocation: &RustcInvocation,
        scope: CrateOutputScope,
        dependency_cache: &DependencyAnalysisCache,
        root_analysis: RootAnalysis,
    ) -> Self {
        let dependencies = dependency_cache.resolved_dependencies();
        let artifact = artifact_info(tcx, invocation);
        let tool_version = env!("CARGO_PKG_VERSION").to_owned();
        let rustc_version = rustc_version();
        let report = AnalysisArtifactReport {
            reason: String::from("sniff-test-artifact"),
            format_version: REPORT_FORMAT_VERSION,
            tool_version: tool_version.clone(),
            rustc_version: rustc_version.clone(),
            artifact: artifact.clone(),
            scope,
            dependency_cache: DependencyCacheReport {
                hits: dependency_cache.hit_count(),
                total: dependency_cache.dependency_count(),
            },
            dependencies: dependencies.clone(),
            missing_roots: root_analysis.missing_roots,
            concrete_roots: root_analysis.concrete_roots,
            generic_roots: root_analysis.generic_roots,
            counts: root_analysis.counts,
            roots: root_analysis.roots,
        };
        let cache = CachedArtifactAnalysis::new(
            tool_version,
            rustc_version,
            artifact,
            dependencies,
            root_analysis.function_summaries,
        );

        Self { report, cache }
    }
}

fn emit_analysis_artifact(
    report: &AnalysisArtifactReport,
    args: &SniffTestArgs,
    rustc_color: Option<args::ColorChoice>,
) {
    if args.message_format == args::MessageFormat::Json {
        emit_json_analysis_artifact_report(report);
    } else {
        emit_human_analysis_artifact_report(report, colors_enabled(args.color, rustc_color));
    }
}

fn emit_human_analysis_artifact_report(report: &AnalysisArtifactReport, color: bool) {
    if report.scope == CrateOutputScope::Workspace {
        for missing_root in &report.missing_roots {
            emit_missing_report_root(&report.artifact.crate_name, missing_root, color);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct AnalysisArtifactReport {
    reason: String,
    format_version: u32,
    tool_version: String,
    rustc_version: String,
    artifact: CachedArtifactInfo,
    scope: CrateOutputScope,
    dependency_cache: DependencyCacheReport,
    dependencies: Vec<CachedDependencyRef>,
    missing_roots: Vec<String>,
    concrete_roots: usize,
    generic_roots: usize,
    counts: PanicFindingCounts,
    roots: Vec<PanicRootReport>,
}

struct RootAnalysis {
    missing_roots: Vec<String>,
    concrete_roots: usize,
    generic_roots: usize,
    counts: PanicFindingCounts,
    function_summaries: Vec<CachedFunctionSummary>,
    roots: Vec<PanicRootReport>,
}

fn analyze_report_roots<'tcx>(
    tcx: TyCtxt<'tcx>,
    selection: ReportRootSelection<'tcx>,
    config: &PanicConfig,
    dependency_cache: &DependencyAnalysisCache,
    diagnostics: PanicDiagnosticOptions,
) -> RootAnalysis {
    let mut analysis = RootAnalysis {
        missing_roots: selection.missing_roots,
        concrete_roots: 0,
        generic_roots: 0,
        counts: PanicFindingCounts::default(),
        function_summaries: Vec::new(),
        roots: Vec::new(),
    };
    let mut reachability = ReachabilityIndex::new(tcx);

    for root in selection.roots {
        let root = match root {
            ReportRoot::Concrete { instance, .. } => AnalysisRoot {
                root: ReachabilityRoot::Instance(instance),
                def_id: instance.def_id(),
                kind: PanicRootKind::Concrete,
            },
            ReportRoot::Generic { local } => AnalysisRoot {
                root: ReachabilityRoot::LocalBody(local),
                def_id: local.to_def_id(),
                kind: PanicRootKind::Generic,
            },
        };
        let (findings, summary, report) = analyze_root(
            tcx,
            &mut reachability,
            root,
            config,
            dependency_cache,
            diagnostics,
        );
        analysis.counts.add(findings);
        analysis.function_summaries.push(summary);
        if !report.findings.is_empty() {
            match report.root_kind {
                PanicRootKind::Concrete => analysis.concrete_roots += 1,
                PanicRootKind::Generic => analysis.generic_roots += 1,
            }
            analysis.roots.push(report);
        }
    }

    analysis
}

fn record_workspace_raw_panic() {
    let Some(path) = std::env::var_os(RAW_PANIC_STATUS_ENV).map(PathBuf::from) else {
        return;
    };
    if let Some(parent) = path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        eprintln!(
            "sniff-test: failed to create raw panic status directory {}: {error}",
            parent.display()
        );
        std::process::exit(1);
    }
    if let Err(error) = std::fs::write(&path, "raw-panic-paths\n") {
        eprintln!(
            "sniff-test: failed to write raw panic status {}: {error}",
            path.display()
        );
        std::process::exit(1);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CrateOutputScope {
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
struct PanicDiagnosticOptions {
    emit: bool,
    include_stack: bool,
}

const REPORT_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
struct DependencyCacheReport {
    hits: usize,
    total: usize,
}

fn emit_json_analysis_artifact_report(report: &AnalysisArtifactReport) {
    let json = serde_json::to_string(report).unwrap_or_else(|error| {
        eprintln!("sniff-test: failed to encode JSON report: {error}");
        std::process::exit(1);
    });
    println!("{json}");
}

#[derive(Debug, Clone, Copy)]
struct AnalysisRoot<'tcx> {
    root: ReachabilityRoot<'tcx>,
    def_id: DefId,
    kind: PanicRootKind,
}

fn analyze_root<'tcx>(
    tcx: TyCtxt<'tcx>,
    reachability: &mut ReachabilityIndex<'tcx>,
    root: AnalysisRoot<'tcx>,
    config: &PanicConfig,
    dependency_cache: &DependencyAnalysisCache,
    diagnostics: PanicDiagnosticOptions,
) -> (PanicFindingCounts, CachedFunctionSummary, PanicRootReport) {
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
    let (findings, report) = collect_panic_findings(
        tcx,
        graph,
        &result,
        &analysis,
        PanicFindingCollection {
            root_kind: root.kind,
            root_def_id: root.def_id,
            config,
            dependency_cache,
            diagnostics,
        },
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
        root.kind == PanicRootKind::Generic,
        findings,
        Some((graph, &boundary_result)),
        cached_findings,
    );

    (findings, summary, report)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
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

    pub(crate) fn increment(&mut self, kind: ReportDetailKind) {
        match kind {
            ReportDetailKind::CompilerAssert
            | ReportDetailKind::PanicInvocation
            | ReportDetailKind::CachedDependencyPanic => self.raw_panic_paths += 1,
            ReportDetailKind::PanicObligation => self.panic_obligations += 1,
            ReportDetailKind::TrustedPanicObligation => self.trusted_panic_obligations += 1,
        }
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
        has_panic_docs: crate::panics::has_panic_docs(tcx, def_id),
        root_span: cached_source_span(tcx, tcx.def_span(def_id)),
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
                source_span: cached_source_span(tcx, edge.span),
                diagnostic_spans: cached_primary_span(
                    tcx,
                    edge.span,
                    Some(cached_finding_span_label(&evidence.kind)),
                ),
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
            let trusted = is_trusted_panic_obligation(tcx, def_id, config);
            let (span, source_span, mut diagnostic_spans, target) = edge_id.map_or_else(
                || {
                    let span = tcx.def_span(def_id);
                    (
                        render_span(tcx, span),
                        cached_source_span(tcx, span),
                        cached_primary_span(tcx, span, Some("documented # Panics contract")),
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
                        cached_source_span(tcx, edge.span),
                        cached_primary_span(
                            tcx,
                            edge.span,
                            Some("call reaches documented panic contract"),
                        ),
                        cached_finding_target(tcx, graph, edge.target),
                    )
                },
            );
            if edge_id.is_some()
                && let Some(span) = cached_diagnostic_span(
                    tcx,
                    tcx.def_span(def_id),
                    false,
                    Some("documented # Panics contract"),
                )
            {
                diagnostic_spans.push(span);
            }
            CachedFinding {
                kind: if trusted {
                    CachedFindingKind::TrustedPanicObligation
                } else {
                    CachedFindingKind::PanicObligation
                },
                span,
                source_span,
                diagnostic_spans,
                edge_index: edge_id.map(ReachabilityEdgeId::index),
                trace: trace_edges_until(evidence, edge_id)
                    .iter()
                    .map(|edge_id| edge_id.index())
                    .collect(),
                reason: format!(
                    "{} has a documented # Panics contract",
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
                source_span: cached_source_span(tcx, edge.span()),
                diagnostic_spans: cached_primary_span(
                    tcx,
                    edge.span(),
                    Some("crate boundary call"),
                ),
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
                source_span: cached_source_span(tcx, edge.span()),
            })
            .collect(),
    }
}

fn cached_source_span(tcx: TyCtxt<'_>, span: rustc_span::Span) -> Option<CachedSourceSpan> {
    if span.is_dummy() {
        return None;
    }

    let source_map = tcx.sess.source_map();
    let start = source_map.lookup_char_pos(span.lo());
    let end = source_map.lookup_char_pos(span.hi());
    Some(CachedSourceSpan {
        file: start.file.name.prefer_local_unconditionally().to_string(),
        line_start: start.line,
        column_start: start.col.to_usize() + 1,
        line_end: end.line,
        column_end: end.col.to_usize() + 1,
    })
}

fn cached_primary_span(
    tcx: TyCtxt<'_>,
    span: rustc_span::Span,
    label: Option<&str>,
) -> Vec<CachedDiagnosticSpan> {
    cached_diagnostic_span(tcx, span, true, label)
        .into_iter()
        .collect()
}

fn cached_diagnostic_span(
    tcx: TyCtxt<'_>,
    span: rustc_span::Span,
    is_primary: bool,
    label: Option<&str>,
) -> Option<CachedDiagnosticSpan> {
    Some(CachedDiagnosticSpan {
        span: cached_source_span(tcx, span)?,
        is_primary,
        label: label.map(str::to_owned),
    })
}

fn cached_finding_span_label(kind: &PanicEvidenceKind) -> &'static str {
    match kind {
        PanicEvidenceKind::CompilerAssert => "compiler assertion",
        PanicEvidenceKind::PanicObligation { .. } => "documented panic contract",
        PanicEvidenceKind::PanicSink { .. } => "panic sink",
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
        ReachabilityNodeKind::CompilerAssert { message, locals } => {
            CachedReachabilityNodeKind::CompilerAssert {
                message: render_assert_message(message, locals),
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

fn write_analysis_cache(args: &SniffTestArgs, analysis: &CachedArtifactAnalysis) {
    if let Err(error) = write_artifact_analysis(&args.cache_dir(), analysis) {
        eprintln!("sniff-test: failed to write analysis cache: {error}");
    }
}

fn artifact_info(tcx: TyCtxt<'_>, invocation: &RustcInvocation) -> CachedArtifactInfo {
    let crate_name = tcx.crate_name(LOCAL_CRATE).to_string();
    CachedArtifactInfo {
        artifact_id: artifact_id(&crate_name, invocation.extra_filename.as_deref()),
        crate_name,
        crate_types: invocation.crate_types.clone(),
        package_name: std::env::var("CARGO_PKG_NAME").ok(),
        package_version: std::env::var("CARGO_PKG_VERSION").ok(),
        manifest_path: std::env::var("CARGO_MANIFEST_PATH").ok(),
        target: invocation.target.clone(),
        metadata: invocation.metadata.clone(),
        extra_filename: invocation.extra_filename.clone(),
    }
}

#[derive(Clone, Copy)]
struct PanicFindingCollection<'config> {
    root_kind: PanicRootKind,
    root_def_id: DefId,
    config: &'config PanicConfig,
    dependency_cache: &'config DependencyAnalysisCache,
    diagnostics: PanicDiagnosticOptions,
}

fn collect_panic_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    result: &ReachabilitySnapshot<'tcx>,
    analysis: &PanicAnalysis,
    collection: PanicFindingCollection<'_>,
) -> (PanicFindingCounts, PanicRootReport) {
    let mut counts = PanicFindingCounts::default();
    let view = graph.view(result);
    let root_node = view.root();
    let mut report = PanicRootReport::new(
        render_node(tcx, root_node.kind()),
        collection.root_kind,
        root_declaration_span(tcx, root_node.kind()),
        crate::panics::has_panic_docs(tcx, collection.root_def_id),
    );

    for evidence in &analysis.evidence {
        match evidence.decision {
            PanicPathDecision::RawPanic => {
                counts.raw_panic_paths += 1;
                report.push_panic_evidence(tcx, graph, evidence);
                if collection.diagnostics.emit {
                    emit_raw_panic_diagnostic(
                        tcx,
                        graph,
                        evidence,
                        collection.root_def_id,
                        collection.diagnostics.include_stack,
                    );
                }
            }
            PanicPathDecision::PanicObligation { edge_id, def_id } => {
                if is_trusted_panic_obligation(tcx, def_id, collection.config) {
                    counts.trusted_panic_obligations += 1;
                    report.push_panic_obligation(
                        tcx,
                        graph,
                        evidence,
                        edge_id,
                        def_id,
                        ReportDetailKind::TrustedPanicObligation,
                    );
                    if collection.diagnostics.emit {
                        emit_panic_contract_diagnostic(
                            tcx,
                            graph,
                            evidence,
                            PanicContractDiagnostic {
                                obligation_edge_id: edge_id,
                                documented_def_id: def_id,
                                root_def_id: collection.root_def_id,
                                trusted: true,
                                include_stack: collection.diagnostics.include_stack,
                            },
                        );
                    }
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
                    if collection.diagnostics.emit {
                        emit_panic_contract_diagnostic(
                            tcx,
                            graph,
                            evidence,
                            PanicContractDiagnostic {
                                obligation_edge_id: edge_id,
                                documented_def_id: def_id,
                                root_def_id: collection.root_def_id,
                                trusted: false,
                                include_stack: collection.diagnostics.include_stack,
                            },
                        );
                    }
                }
            }
        }
    }

    emit_cached_dependency_findings(tcx, graph, view, &collection, &mut counts, &mut report);

    (counts, report)
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

fn is_trusted_panic_obligation(
    tcx: TyCtxt<'_>,
    documented_def_id: DefId,
    config: &PanicConfig,
) -> bool {
    config.panic_boundary_policy(tcx, documented_def_id)
        == PanicBoundaryPolicy::TrustedPanicObligation
}

fn emit_cached_dependency_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    collection: &PanicFindingCollection<'_>,
    counts: &mut PanicFindingCounts,
    report: &mut PanicRootReport,
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
        if collection.config.ignores_def(tcx, def_id) {
            continue;
        }
        if collection.config.panic_boundary_policy(tcx, def_id) != PanicBoundaryPolicy::Normal {
            continue;
        }

        let dependency_crate_name = tcx.crate_name(def_id.krate).to_string();
        let Some(summary) = collection
            .dependency_cache
            .function(&dependency_crate_name, &path)
        else {
            continue;
        };

        if summary.has_panic_docs {
            continue;
        }

        if summary.panic_obligations > 0 || summary.trusted_panic_obligations > 0 {
            if is_trusted_panic_obligation(tcx, instance.def_id(), collection.config) {
                counts.trusted_panic_obligations += 1;
                report.push_cached_dependency_obligation(
                    tcx,
                    graph,
                    edge.id(),
                    summary,
                    ReportDetailKind::TrustedPanicObligation,
                );
                if collection.diagnostics.emit {
                    emit_cached_dependency_contract_diagnostic(
                        tcx,
                        graph,
                        edge.id(),
                        summary,
                        collection.root_def_id,
                        true,
                        collection.diagnostics.include_stack,
                    );
                }
            } else {
                counts.panic_obligations += 1;
                report.push_cached_dependency_obligation(
                    tcx,
                    graph,
                    edge.id(),
                    summary,
                    ReportDetailKind::PanicObligation,
                );
                if collection.diagnostics.emit {
                    emit_cached_dependency_contract_diagnostic(
                        tcx,
                        graph,
                        edge.id(),
                        summary,
                        collection.root_def_id,
                        false,
                        collection.diagnostics.include_stack,
                    );
                }
            }
        } else if summary.raw_panic_paths > 0 {
            counts.raw_panic_paths += 1;
            report.push_cached_dependency_panic(tcx, graph, edge.id(), summary);
            if collection.diagnostics.emit {
                emit_cached_dependency_raw_panic_diagnostic(
                    tcx,
                    graph,
                    edge.id(),
                    summary,
                    collection.root_def_id,
                    collection.diagnostics.include_stack,
                );
            }
        }
    }
}

fn emit_raw_panic_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    root_def_id: DefId,
    include_stack: bool,
) {
    let root = canonical_namespace(tcx, root_def_id);
    let trigger_edge_id = trigger_edge_id(graph, evidence);
    let trigger_edge = graph.edge(trigger_edge_id);
    let mut diag = tcx.dcx().struct_span_err(
        tcx.def_span(root_def_id),
        format!("function `{root}` has an undocumented panic path"),
    );
    diag.span_note(
        trigger_edge.span,
        format!(
            "panic may happen here: {}",
            panic_trigger_note(tcx, graph, evidence)
        ),
    );
    add_trace_notes(
        &mut diag,
        tcx,
        graph,
        &evidence.trace.edge_ids,
        include_stack,
    );
    diag.help(
        "add a guard, document the panic with `# Panics`, or add `// SAFE:` if a local invariant proves it cannot panic",
    );
    let _ = diag.emit();
}

fn emit_panic_contract_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    diagnostic: PanicContractDiagnostic,
) {
    let PanicContractDiagnostic {
        obligation_edge_id,
        documented_def_id,
        root_def_id,
        trusted,
        include_stack,
    } = diagnostic;
    let root = canonical_namespace(tcx, root_def_id);
    let documented = canonical_namespace(tcx, documented_def_id);
    let contract = if trusted {
        "trusted panic contract"
    } else {
        "documented panic contract"
    };
    let primary_span = obligation_edge_id.map_or_else(
        || tcx.def_span(root_def_id),
        |edge_id| graph.edge(edge_id).span,
    );
    let mut diag = tcx.dcx().struct_span_warn(
        primary_span,
        format!("function `{root}` reaches a {contract}"),
    );
    diag.span_note(
        tcx.def_span(documented_def_id),
        format!("`{documented}` documents `# Panics` here"),
    );
    add_trace_notes(
        &mut diag,
        tcx,
        graph,
        &trace_edges_until(evidence, obligation_edge_id),
        include_stack,
    );
    diag.help("ensure this precondition locally or document it on your public API with `# Panics`");
    diag.emit();
}

#[derive(Debug, Clone, Copy)]
struct PanicContractDiagnostic {
    obligation_edge_id: Option<ReachabilityEdgeId>,
    documented_def_id: DefId,
    root_def_id: DefId,
    trusted: bool,
    include_stack: bool,
}

fn emit_cached_dependency_contract_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_id: ReachabilityEdgeId,
    summary: &CachedFunctionSummary,
    root_def_id: DefId,
    trusted: bool,
    include_stack: bool,
) {
    let root = canonical_namespace(tcx, root_def_id);
    let contract = if trusted {
        "trusted panic contract"
    } else {
        "documented panic contract"
    };
    let edge = graph.edge(edge_id);
    let mut diag = tcx.dcx().struct_span_warn(
        edge.span,
        format!("function `{root}` reaches a cached dependency {contract}"),
    );
    diag.note(format!("`{}` has cached {contract} evidence", summary.path));
    add_trace_notes(&mut diag, tcx, graph, &[edge_id], include_stack);
    diag.help("ensure this precondition locally or document it on your public API with `# Panics`");
    diag.emit();
}

fn emit_cached_dependency_raw_panic_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_id: ReachabilityEdgeId,
    summary: &CachedFunctionSummary,
    root_def_id: DefId,
    include_stack: bool,
) {
    let root = canonical_namespace(tcx, root_def_id);
    let edge = graph.edge(edge_id);
    let mut diag = tcx.dcx().struct_span_err(
        edge.span,
        format!("function `{root}` reaches cached undocumented panic evidence from a dependency"),
    );
    diag.note(cached_dependency_panic_reason(summary));
    add_trace_notes(&mut diag, tcx, graph, &[edge_id], include_stack);
    diag.help("guard the call, document the panic with `# Panics`, or add `// SAFE:` if a local invariant proves it cannot panic");
    let _ = diag.emit();
}

fn add_trace_notes<'tcx, G: EmissionGuarantee>(
    diag: &mut Diag<'_, G>,
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_ids: &[ReachabilityEdgeId],
    include_stack: bool,
) {
    if edge_ids.is_empty() {
        return;
    }

    if include_stack {
        for (index, edge_id) in edge_ids.iter().enumerate() {
            let edge = graph.edge(*edge_id);
            diag.span_note(
                edge.span,
                format!(
                    "reachable step {index}: {}",
                    render_edge_without_span(tcx, graph, edge)
                ),
            );
        }
    } else if edge_ids.len() > 1 {
        let first = graph.edge(edge_ids[0]);
        let last = graph.edge(*edge_ids.last().expect("trace is non-empty"));
        diag.note(format!(
            "reachable from {} to {}",
            render_trace_endpoint(tcx, &graph.node(first.source).kind),
            render_trace_endpoint(tcx, &graph.node(last.target).kind)
        ));
        diag.note(
            "set `show-full-stack-trace = true` under `[panics]` in sniff-test.toml to show every reachability step",
        );
    }
}

fn panic_trigger_note<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
) -> String {
    match evidence.kind {
        PanicEvidenceKind::CompilerAssert => {
            let target = &graph.node(graph.edge(evidence.edge_id).target).kind;
            if let ReachabilityNodeKind::CompilerAssert { message, locals } = target {
                format!(
                    "compiler assertion: {}",
                    render_assert_message(message, locals)
                )
            } else {
                format!("compiler assertion: {}", render_node(tcx, target))
            }
        }
        PanicEvidenceKind::PanicSink { def_id } => {
            format!("panic sink `{}`", canonical_namespace(tcx, def_id))
        }
        PanicEvidenceKind::PanicObligation { def_id } => {
            format!(
                "documented panic contract `{}`",
                canonical_namespace(tcx, def_id)
            )
        }
    }
}

fn render_trace_endpoint<'tcx>(tcx: TyCtxt<'tcx>, node: &ReachabilityNodeKind<'tcx>) -> String {
    let rendered = render_node(tcx, node);
    if matches!(node, ReachabilityNodeKind::CompilerAssert { .. }) {
        rendered
    } else {
        format!("`{rendered}`")
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

    use super::{CrateOutputScope, metadata_cargo_args};

    #[test]
    fn output_scope_classifies_workspace_dependency_and_fallback_crates() {
        assert_eq!(
            CrateOutputScope::from_manifest_paths(
                Path::new("/repo/sniff-test.toml"),
                Some(Path::new("/repo/crates/sniff-test/Cargo.toml")),
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

    #[test]
    fn metadata_cargo_args_keep_metadata_compatible_options() {
        let args = [
            "--manifest-path",
            "crate/Cargo.toml",
            "-p",
            "selected",
            "--features",
            "dangerous",
            "--offline",
            "--target",
            "wasm32-unknown-unknown",
        ]
        .map(String::from);

        assert_eq!(
            metadata_cargo_args(&args),
            [
                "--manifest-path",
                "crate/Cargo.toml",
                "--features",
                "dangerous",
                "--offline",
            ]
            .map(String::from)
        );
    }
}
