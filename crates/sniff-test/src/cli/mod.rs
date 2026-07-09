//! Executable plumbing for the sniff-test Cargo/rustc integration.

use std::collections::HashSet;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::cache::{
    CacheExpectations, CachedArtifactAnalysis, CachedArtifactInfo, CachedDependencyRef,
    CachedFunctionSummary, artifact_id, write_artifact_analysis,
};
use crate::config::{
    AnalysisConfig, LintLevel, PanicBoundaryPolicy, PanicConfig, SafetyLintConfig, SniffTestConfig,
};
use crate::dependency_cache::{DependencyAnalysisCache, DependencyInput};
use crate::namespace::stable_def_path_hash;
use crate::panics::{PanicAnalysis, PanicEvidence, PanicPathDecision, analyze_panic_evidence};
use crate::report_roots::{
    MissingReportRoot, ReportRoot, ReportRootSelection, select_report_roots,
};
use crate::safety::{SafetyAnalysis, analyze_safety};
use reachability::{
    ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityEdgeKind,
    ReachabilityGraph, ReachabilityHooks, ReachabilityIndex, ReachabilityNodeKind,
    ReachabilityOptions, ReachabilityRoot, ReachabilitySnapshot, ReachabilityView,
};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_middle::ty::{Instance, TyCtxt};
use serde::Serialize;

mod args;
mod cache_encode;
mod diagnostics;
mod plugin;
mod report;
mod rustc_invocation;
mod safety_report;

pub use self::args::SniffTestArgs;
pub use self::plugin::driver_main;

use self::cache_encode::{cached_boundary_findings, function_summary};
use self::diagnostics::{
    CachedDependencyContractDiagnostic, PanicContractDiagnostic, PanicDiagnosticOptions,
    emit_cached_dependency_contract_diagnostic, emit_cached_dependency_raw_panic_diagnostic,
    emit_missing_report_root_diagnostics, emit_panic_contract_diagnostic,
    emit_raw_panic_diagnostic, emit_safety_diagnostics,
};
use self::plugin::{
    DENIED_FINDING_STATUS_ENV, RUSTC_VERSION_ENV, SNIFF_TEST_ARGS_ENV, current_rustc_version,
    frontend_args, modify_cargo, rustc_version, rustc_version_dir_component,
};
use self::report::{
    PanicObligationReport, PanicRootKind, PanicRootReport, ReportDetailKind, render_node,
    render_span_start,
};
use self::rustc_invocation::RustcInvocation;
use self::safety_report::SafetyArtifactReport;

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
    let denied_finding_status = args.cache_dir().join("workspace-denied-findings");
    if let Err(error) = std::fs::remove_file(&denied_finding_status)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!(
            "sniff-test: failed to clear {}: {error}",
            denied_finding_status.display()
        );
        return ExitCode::FAILURE;
    }

    let mut cargo = Command::new("cargo");
    cargo.args(["check", "--target-dir"]).arg(&target_dir);
    if std::env::var_os("CARGO_VERBOSE").is_some() {
        cargo.arg("-vv");
    }
    cargo.env(RUSTC_VERSION_ENV, &rustc_version);
    cargo.env(DENIED_FINDING_STATUS_ENV, &denied_finding_status);
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
            if denied_finding_status.exists() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Ok(status) => {
            if denied_finding_status.exists() {
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

    let rustc_version = rustc_version();
    let dependency_cache = DependencyAnalysisCache::load(
        &args.cache_dir(),
        invocation.externs.iter().map(|extern_arg| DependencyInput {
            name: extern_arg.name.clone(),
            path: extern_arg.path.clone(),
        }),
        &config.panics,
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
             cached panic evidence for that crate is disabled"
        );
    }

    let selection = select_report_roots(tcx, &config.analysis, &config.panics);
    let diagnostics = PanicDiagnosticOptions {
        emit: args.message_format == args::MessageFormat::Human
            && output_scope == CrateOutputScope::Workspace,
        include_stack: config.analysis.show_full_stack_trace,
    };
    let root_analysis = analyze_report_roots(
        tcx,
        selection,
        &config.analysis,
        &config.panics,
        &dependency_cache,
        diagnostics,
    );
    let safety_analysis = if output_scope == CrateOutputScope::Workspace {
        analyze_safety(tcx, &config.safety)
    } else {
        SafetyAnalysis::default()
    };
    let has_denied_safety_findings = safety_analysis.has_denied_findings(config.safety.lints);
    if diagnostics.emit {
        emit_safety_diagnostics(tcx, &safety_analysis, config.safety.lints);
        emit_missing_report_root_diagnostics(
            tcx,
            &args.manifest_path(),
            &root_analysis.missing_roots,
        );
    }

    let analysis = AnalysisArtifact::new(
        tcx,
        &invocation,
        output_scope,
        &dependency_cache,
        root_analysis,
        safety_analysis,
        config.safety.lints,
    );
    write_analysis_cache(args, &analysis.cache);
    emit_analysis_artifact(&analysis.report, args);
    let has_denied_panic_findings = analysis
        .report
        .counts
        .has_denied_findings(config.panics.lints);
    if analysis.report.scope == CrateOutputScope::Workspace
        && (has_denied_panic_findings || has_denied_safety_findings)
    {
        record_workspace_denied_finding();
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
        safety_analysis: SafetyAnalysis,
        safety_lints: SafetyLintConfig,
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
                failed: dependency_cache.failed_count(),
            },
            dependencies: dependencies.clone(),
            missing_roots: root_analysis
                .missing_roots
                .iter()
                .map(|root| root.path.clone())
                .collect(),
            concrete_roots: root_analysis.concrete_roots,
            generic_roots: root_analysis.generic_roots,
            counts: root_analysis.counts,
            roots: root_analysis.roots,
            safety: SafetyArtifactReport::from_analysis(tcx, safety_analysis, safety_lints),
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

fn emit_analysis_artifact(report: &AnalysisArtifactReport, args: &SniffTestArgs) {
    if args.message_format == args::MessageFormat::Json {
        emit_json_analysis_artifact_report(report);
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
    #[serde(skip_serializing_if = "Option::is_none")]
    safety: Option<SafetyArtifactReport>,
}

struct RootAnalysis {
    missing_roots: Vec<MissingReportRoot>,
    concrete_roots: usize,
    generic_roots: usize,
    counts: PanicFindingCounts,
    function_summaries: Vec<CachedFunctionSummary>,
    roots: Vec<PanicRootReport>,
}

fn analyze_report_roots<'tcx>(
    tcx: TyCtxt<'tcx>,
    selection: ReportRootSelection<'tcx>,
    analysis_config: &AnalysisConfig,
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
            analysis_config,
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

fn record_workspace_denied_finding() {
    let Some(path) = std::env::var_os(DENIED_FINDING_STATUS_ENV).map(PathBuf::from) else {
        return;
    };
    if let Some(parent) = path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        eprintln!(
            "sniff-test: failed to create denied finding status directory {}: {error}",
            parent.display()
        );
        std::process::exit(1);
    }
    if let Err(error) = std::fs::write(&path, "denied-findings\n") {
        eprintln!(
            "sniff-test: failed to write denied finding status {}: {error}",
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

const REPORT_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
struct DependencyCacheReport {
    hits: usize,
    total: usize,
    /// Cache files that exist but were unreadable or version-mismatched,
    /// distinguishing corruption from dependencies never analyzed.
    failed: usize,
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
    analysis_config: &AnalysisConfig,
    config: &PanicConfig,
    dependency_cache: &DependencyAnalysisCache,
    diagnostics: PanicDiagnosticOptions,
) -> (PanicFindingCounts, CachedFunctionSummary, PanicRootReport) {
    let mut hooks = PanicReachabilityHooks { config };
    let result = reachability.query(
        root.root,
        &mut hooks,
        reachability_options(analysis_config, true),
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
        reachability_options(analysis_config, false),
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

fn reachability_options(
    analysis_config: &AnalysisConfig,
    analyze_external: bool,
) -> ReachabilityOptions {
    ReachabilityOptions {
        node_limit: Some(REACHABILITY_NODE_LIMIT),
        analyze_external,
        dyn_dispatch_vtable_edges: analysis_config.dyn_dispatch_vtable_edges.into(),
        ..ReachabilityOptions::default()
    }
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

    fn has_denied_findings(self, lints: crate::config::PanicLintConfig) -> bool {
        (self.raw_panic_paths > 0 && lints.undocumented_panic_path == LintLevel::Deny)
            || (self.panic_obligations > 0 && lints.documented_panic_contract == LintLevel::Deny)
            || (self.trusted_panic_obligations > 0
                && lints.trusted_panic_contract == LintLevel::Deny)
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
                emit_raw_panic_finding(tcx, graph, evidence, &collection, &mut counts, &mut report);
            }
            PanicPathDecision::PanicObligation { edge_id, def_id } => {
                emit_panic_obligation_finding(
                    tcx,
                    graph,
                    evidence,
                    PanicObligationFinding { edge_id, def_id },
                    &collection,
                    &mut counts,
                    &mut report,
                );
            }
        }
    }

    emit_cached_dependency_findings(tcx, graph, view, &collection, &mut counts, &mut report);

    (counts, report)
}

fn emit_raw_panic_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    collection: &PanicFindingCollection<'_>,
    counts: &mut PanicFindingCounts,
    report: &mut PanicRootReport,
) {
    let kind = ReportDetailKind::from_evidence(&evidence.kind);
    let level = kind.lint_level(collection.config.lints);
    if level == LintLevel::Allow {
        return;
    }

    counts.raw_panic_paths += 1;
    report.push_panic_evidence(tcx, graph, evidence, level);
    if collection.diagnostics.emit {
        emit_raw_panic_diagnostic(
            tcx,
            graph,
            evidence,
            collection.root_def_id,
            level,
            collection.diagnostics.include_stack,
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct PanicObligationFinding {
    edge_id: Option<reachability::ReachabilityEdgeId>,
    def_id: DefId,
}

fn emit_panic_obligation_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    finding: PanicObligationFinding,
    collection: &PanicFindingCollection<'_>,
    counts: &mut PanicFindingCounts,
    report: &mut PanicRootReport,
) {
    let trusted = is_trusted_panic_obligation(tcx, finding.def_id, collection.config);
    let kind = if trusted {
        ReportDetailKind::TrustedPanicObligation
    } else {
        ReportDetailKind::PanicObligation
    };
    let level = kind.lint_level(collection.config.lints);
    if level == LintLevel::Allow {
        return;
    }

    if trusted {
        counts.trusted_panic_obligations += 1;
    } else {
        counts.panic_obligations += 1;
    }
    report.push_panic_obligation(
        tcx,
        graph,
        evidence,
        PanicObligationReport {
            obligation_edge_id: finding.edge_id,
            documented_def_id: finding.def_id,
            kind,
            level,
        },
    );
    if collection.diagnostics.emit {
        emit_panic_contract_diagnostic(
            tcx,
            graph,
            evidence,
            PanicContractDiagnostic {
                obligation_edge_id: finding.edge_id,
                documented_def_id: finding.def_id,
                root_def_id: collection.root_def_id,
                trusted,
                level,
                include_stack: collection.diagnostics.include_stack,
            },
        );
    }
}

fn root_declaration_span(tcx: TyCtxt<'_>, root: &ReachabilityNodeKind<'_>) -> Option<String> {
    match root {
        ReachabilityNodeKind::Instance(instance) => {
            Some(render_span_start(tcx, tcx.def_span(instance.def_id())))
        }
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::MacroExpansion { .. }
        | ReachabilityNodeKind::IndirectCall { .. }
        | ReachabilityNodeKind::DynObjectCast { .. } => None,
    }
}

pub(super) fn is_trusted_panic_obligation(
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
        if collection.config.ignores_def(tcx, def_id) {
            continue;
        }
        if collection.config.panic_boundary_policy(tcx, def_id) != PanicBoundaryPolicy::Normal {
            continue;
        }

        let dependency_crate_name = tcx.crate_name(def_id.krate).to_string();
        let Some(summary) = collection
            .dependency_cache
            .function(&dependency_crate_name, &stable_def_path_hash(tcx, def_id))
        else {
            continue;
        };

        if summary.has_panic_docs {
            continue;
        }

        if summary.panic_obligations > 0 || summary.trusted_panic_obligations > 0 {
            emit_cached_dependency_obligation_finding(
                tcx,
                graph,
                CachedDependencyFinding {
                    edge_id: edge.id(),
                    def_id: instance.def_id(),
                    summary,
                },
                collection,
                counts,
                report,
            );
        } else if summary.raw_panic_paths > 0 {
            let kind = ReportDetailKind::CachedDependencyPanic;
            let level = kind.lint_level(collection.config.lints);
            if level == LintLevel::Allow {
                continue;
            }
            counts.raw_panic_paths += 1;
            report.push_cached_dependency_panic(tcx, graph, edge.id(), summary, level);
            if collection.diagnostics.emit {
                emit_cached_dependency_raw_panic_diagnostic(
                    tcx,
                    graph,
                    edge.id(),
                    summary,
                    collection.root_def_id,
                    level,
                    collection.diagnostics.include_stack,
                );
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CachedDependencyFinding<'summary> {
    edge_id: reachability::ReachabilityEdgeId,
    def_id: DefId,
    summary: &'summary CachedFunctionSummary,
}

fn emit_cached_dependency_obligation_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    finding: CachedDependencyFinding<'_>,
    collection: &PanicFindingCollection<'_>,
    counts: &mut PanicFindingCounts,
    report: &mut PanicRootReport,
) {
    let trusted = is_trusted_panic_obligation(tcx, finding.def_id, collection.config);
    let kind = if trusted {
        ReportDetailKind::TrustedPanicObligation
    } else {
        ReportDetailKind::PanicObligation
    };
    let level = kind.lint_level(collection.config.lints);
    if level == LintLevel::Allow {
        return;
    }

    if trusted {
        counts.trusted_panic_obligations += 1;
    } else {
        counts.panic_obligations += 1;
    }
    report.push_cached_dependency_obligation(
        tcx,
        graph,
        finding.edge_id,
        finding.summary,
        kind,
        level,
    );
    if collection.diagnostics.emit {
        emit_cached_dependency_contract_diagnostic(
            tcx,
            graph,
            finding.summary,
            CachedDependencyContractDiagnostic {
                edge_id: finding.edge_id,
                root_def_id: collection.root_def_id,
                trusted,
                level,
                include_stack: collection.diagnostics.include_stack,
            },
        );
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
