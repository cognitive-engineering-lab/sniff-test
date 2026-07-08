//! Executable plumbing for the sniff-test Cargo/rustc integration.

use std::collections::HashSet;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::cache::{
    CacheExpectations, CachedArtifactAnalysis, CachedArtifactInfo, CachedDependencyRef,
    CachedFunctionSummary, OUTCOME_FORMAT_VERSION, UnitOutcome, artifact_id, read_unit_outcome,
    write_artifact_analysis, write_unit_outcome,
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
    emit_analysis_incomplete_diagnostic, emit_cached_dependency_contract_diagnostic,
    emit_cached_dependency_raw_panic_diagnostic, emit_indirect_boundary_diagnostic,
    emit_missing_report_root_diagnostics, emit_panic_contract_diagnostic,
    emit_raw_panic_diagnostic, emit_safety_diagnostics,
};
use self::plugin::{
    RUSTC_VERSION_ENV, SNIFF_TEST_ARGS_ENV, current_rustc_version, frontend_args, modify_cargo,
    rustc_version, rustc_version_dir_component,
};
use self::report::{
    PanicObligationReport, PanicRootKind, PanicRootReport, ReportDetailKind, render_node,
    render_span_start,
};
use self::rustc_invocation::RustcInvocation;
use self::safety_report::SafetyArtifactReport;

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
    if parsed_args
        .cargo_args
        .iter()
        .any(|arg| arg == "--message-format" || arg.starts_with("--message-format="))
    {
        // The frontend owns cargo's message format: it reads the JSON stream
        // to learn the build plan.
        eprintln!(
            "sniff-test: pass --message-format to sniff-test itself, before any `--` separator"
        );
        return ExitCode::FAILURE;
    }
    let metadata = match metadata_command(&parsed_args).exec() {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!("sniff-test: failed to read Cargo metadata: {error}");
            return ExitCode::FAILURE;
        }
    };
    let parsed_args = discover_manifest(parsed_args, metadata.workspace_root.as_std_path());
    let rustc_version = current_rustc_version();
    let target_dir = metadata.target_directory.join(format!(
        "sniff-test-{}",
        rustc_version_dir_component(&rustc_version)
    ));
    let mut args = frontend_args(parsed_args, target_dir.as_std_path());
    args.workspace_manifests = metadata
        .packages
        .iter()
        .map(|package| absolute_path(package.manifest_path.clone().into_std_path_buf()))
        .collect();

    let mut cargo = Command::new("cargo");
    cargo.args(["check", "--target-dir"]).arg(&target_dir);
    // json-render-diagnostics keeps rustc diagnostics on stderr exactly as in
    // human mode while cargo's own messages arrive as JSON on stdout, which
    // is how the frontend learns the build plan, fresh units included.
    cargo.args(["--message-format", "json-render-diagnostics"]);
    if std::env::var_os("CARGO_VERBOSE").is_some() {
        cargo.arg("-vv");
    }
    cargo.env(RUSTC_VERSION_ENV, &rustc_version);
    cargo.env(
        SNIFF_TEST_ARGS_ENV,
        serde_json::to_string(&args).unwrap_or_else(|error| {
            eprintln!("sniff-test: failed to encode driver arguments: {error}");
            std::process::exit(2);
        }),
    );
    modify_cargo(&mut cargo, &args);
    cargo.stdout(std::process::Stdio::piped());

    let mut child = match cargo.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("sniff-test: failed to run Cargo: {error}");
            return ExitCode::FAILURE;
        }
    };
    let Some(stdout) = child.stdout.take() else {
        eprintln!("sniff-test: failed to capture Cargo output");
        let _ = child.kill();
        return ExitCode::FAILURE;
    };
    let mut plan = Vec::new();
    let mut planned = HashSet::new();
    let mut streamed = HashSet::new();
    for line in std::io::BufRead::lines(std::io::BufReader::new(stdout)) {
        let Ok(line) = line else {
            break;
        };
        process_cargo_message(&line, &args, &mut plan, &mut planned, &mut streamed);
    }
    let status = child.wait();

    let denied = consume_unit_outcomes(&args, &plan, &streamed);
    match status {
        Ok(status) if status.success() => {
            if denied {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Ok(status) => {
            if denied {
                ExitCode::FAILURE
            } else {
                match status.code() {
                    Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
                    None => ExitCode::FAILURE,
                }
            }
        }
        Err(error) => {
            eprintln!("sniff-test: failed to wait for Cargo: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Resolves the sniff-test manifest by searching upward from the invocation
/// directory to the cargo workspace root when `--manifest` was not passed.
///
/// The empty default policy is intentional; discovery only ensures the same
/// command finds the same config from any directory of the workspace.
fn discover_manifest(mut args: SniffTestArgs, workspace_root: &Path) -> SniffTestArgs {
    if let Some(path) = &args.manifest_path {
        eprintln!(
            "sniff-test: using config {}",
            absolute_path(path.clone()).display()
        );
        return args;
    }

    let cwd = std::env::current_dir().unwrap_or_else(|error| {
        eprintln!("sniff-test: failed to read current directory: {error}");
        std::process::exit(2);
    });
    let mut dir = cwd.as_path();
    loop {
        let candidate = dir.join(crate::config::DEFAULT_MANIFEST_FILE);
        if candidate.is_file() {
            eprintln!("sniff-test: using config {}", candidate.display());
            args.manifest_path = Some(candidate);
            return args;
        }
        if dir == workspace_root || !dir.starts_with(workspace_root) {
            break;
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }

    eprintln!(
        "sniff-test: no {} found between {} and {}; running with the empty default policy",
        crate::config::DEFAULT_MANIFEST_FILE,
        cwd.display(),
        workspace_root.display(),
    );
    args
}

fn process_cargo_message(
    line: &str,
    args: &SniffTestArgs,
    plan: &mut Vec<String>,
    planned: &mut HashSet<String>,
    streamed: &mut HashSet<String>,
) {
    let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
        return;
    };
    match message.get("reason").and_then(serde_json::Value::as_str) {
        Some("compiler-artifact") => {
            if let Some(id) = compiler_artifact_id(&message)
                && planned.insert(id.clone())
            {
                plan.push(id);
            }
        }
        // The driver announces every unit it analyzed, including units whose
        // deny findings failed the compile and thus never produce a
        // compiler-artifact message.
        Some("sniff-test-outcome") => {
            if let Some(id) = message
                .get("artifact-id")
                .and_then(serde_json::Value::as_str)
                && planned.insert(id.to_owned())
            {
                plan.push(id.to_owned());
            }
        }
        Some("sniff-test-artifact") => {
            // Driver output passing through cargo: forward it verbatim so the
            // streaming UX is unchanged, and remember the unit so its stored
            // report is not printed twice.
            if args.message_format == args::MessageFormat::Json {
                println!("{line}");
            }
            if let Some(id) = message
                .get("artifact")
                .and_then(|artifact| artifact.get("artifact-id"))
                .and_then(serde_json::Value::as_str)
            {
                streamed.insert(id.to_owned());
            }
        }
        _ => {}
    }
}

fn compiler_artifact_id(message: &serde_json::Value) -> Option<String> {
    let filenames = message.get("filenames")?.as_array()?;
    let mut fallback = None;
    for name in filenames.iter().filter_map(serde_json::Value::as_str) {
        let path = Path::new(name);
        let Some(id) = crate::cache::artifact_id_from_extern_path(path) else {
            continue;
        };
        // The hashed artifacts live in deps/; other entries are unhashed
        // copies whose stems are not artifact ids.
        if path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|dir| dir == "deps")
        {
            return Some(id);
        }
        fallback.get_or_insert(id);
    }
    fallback
}

/// Unions the persisted verdicts of every unit in this run's build plan and
/// re-prints stored reports for fresh units the driver never ran for.
fn consume_unit_outcomes(
    args: &SniffTestArgs,
    plan: &[String],
    streamed: &HashSet<String>,
) -> bool {
    let mut denied = false;
    for artifact_id in plan {
        match read_unit_outcome(&args.cache_dir(), artifact_id, env!("CARGO_PKG_VERSION")) {
            Ok(outcome) => {
                denied |= outcome.has_denied_findings;
                if args.message_format == args::MessageFormat::Json
                    && !streamed.contains(artifact_id)
                    && let Some(report_json) = &outcome.report_json
                {
                    println!("{report_json}");
                }
            }
            // Missing outcomes stay clean: the rebuild invariant means a unit
            // without one was never analyzed as part of this configuration.
            Err(error) if error.is_missing_file() => {}
            Err(error) => {
                eprintln!(
                    "sniff-test: warning: ignoring unit outcome for `{artifact_id}`: {error}"
                );
            }
        }
    }
    denied
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
    let output_scope = CrateOutputScope::current(args, &invocation);

    if config.panics.ignored_namespace_match(&crate_name).is_some() {
        // A config change that newly ignores this crate must not leave a
        // stale denied verdict behind.
        write_unit_outcome_file(
            args,
            &UnitOutcome {
                format_version: OUTCOME_FORMAT_VERSION,
                tool_version: env!("CARGO_PKG_VERSION").to_owned(),
                artifact_id: artifact_id(&crate_name, invocation.extra_filename.as_deref()),
                has_denied_findings: false,
                report_json: None,
            },
        );
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
    if diagnostics.emit
        && root_analysis.concrete_roots == 0
        && root_analysis.generic_roots == 0
        && root_analysis.missing_roots.is_empty()
    {
        // An empty selection exits clean; without this note that reads as
        // "verified panic-free" when nothing was analyzed at all.
        tcx.dcx().warn(format!(
            "report-roots = {} matched no functions in `{crate_name}`; nothing was analyzed",
            config.analysis.report_roots.description(),
        ));
    }
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
    let has_denied_panic_findings = analysis
        .report
        .counts
        .has_denied_findings(config.panics.lints);
    emit_report_and_outcome(
        args,
        &analysis.report,
        analysis.report.scope == CrateOutputScope::Workspace
            && (has_denied_panic_findings || has_denied_safety_findings),
    );
}

fn emit_report_and_outcome(
    args: &SniffTestArgs,
    report: &AnalysisArtifactReport,
    has_denied_findings: bool,
) {
    let report_json = render_json_analysis_artifact_report(report);
    if args.message_format == args::MessageFormat::Json
        && let Some(report_json) = &report_json
    {
        println!("{report_json}");
    }
    write_unit_outcome_file(
        args,
        &UnitOutcome {
            format_version: OUTCOME_FORMAT_VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            artifact_id: report.artifact.artifact_id.clone(),
            has_denied_findings,
            report_json,
        },
    );
}

fn write_unit_outcome_file(args: &SniffTestArgs, outcome: &UnitOutcome) {
    if let Err(error) = write_unit_outcome(&args.cache_dir(), outcome) {
        eprintln!("sniff-test: failed to write unit outcome: {error}");
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CrateOutputScope {
    Workspace,
    Dependency,
}

impl CrateOutputScope {
    #[must_use]
    fn current(args: &SniffTestArgs, invocation: &RustcInvocation) -> Self {
        // Build scripts and proc macros never ship as target code; workspace
        // deny gating and diagnostics would fail builds over their normal
        // panic-on-error idiom.
        if std::env::var("CARGO_CRATE_NAME").is_ok_and(|name| name.starts_with("build_script_"))
            || invocation
                .crate_types
                .iter()
                .any(|crate_type| crate_type == "proc-macro")
        {
            return Self::Dependency;
        }

        let cargo_manifest =
            std::env::var_os("CARGO_MANIFEST_PATH").map(|path| absolute_path(PathBuf::from(path)));
        Self::from_manifest_paths(
            &args.workspace_manifests,
            cargo_manifest.as_deref(),
            std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some(),
        )
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

fn render_json_analysis_artifact_report(report: &AnalysisArtifactReport) -> Option<String> {
    match serde_json::to_string(report) {
        Ok(json) => Some(json),
        Err(error) => {
            eprintln!("sniff-test: failed to encode JSON report: {error}");
            None
        }
    }
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
    let (mut findings, mut report) = collect_panic_findings(
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
    let transitive_complete = graph.view(&result).halt().is_none();

    // A second, boundary-only query per root is deliberate: body expansion is
    // memoized across queries and policy/marker verdicts are cached, so this
    // re-traverses the in-memory graph cheaply, while deriving boundary
    // findings from the transitive snapshot would change the serialized
    // cache graphs and their trace semantics.
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
    let analysis_complete = transitive_complete && graph.view(&boundary_result).halt().is_none();
    if !analysis_complete {
        emit_analysis_incomplete_finding(
            tcx,
            root.def_id,
            analysis_config.node_limit,
            config,
            diagnostics,
            &mut findings,
            &mut report,
        );
    }
    let summary = function_summary(
        tcx,
        root.def_id,
        root.kind == PanicRootKind::Generic,
        analysis_complete,
        findings,
        Some((graph, &boundary_result)),
        cached_findings,
    );

    (findings, summary, report)
}

fn emit_analysis_incomplete_finding(
    tcx: TyCtxt<'_>,
    root_def_id: DefId,
    node_limit: usize,
    config: &PanicConfig,
    diagnostics: PanicDiagnosticOptions,
    counts: &mut PanicFindingCounts,
    report: &mut PanicRootReport,
) {
    let level = ReportDetailKind::AnalysisIncomplete.lint_level(config.lints);
    if level == LintLevel::Allow {
        return;
    }

    counts.analysis_incomplete += 1;
    report.push_analysis_incomplete(tcx, root_def_id, node_limit, level);
    if diagnostics.emit {
        emit_analysis_incomplete_diagnostic(tcx, root_def_id, node_limit, level);
    }
}

fn reachability_options(
    analysis_config: &AnalysisConfig,
    analyze_external: bool,
) -> ReachabilityOptions {
    ReachabilityOptions {
        node_limit: Some(analysis_config.node_limit),
        analyze_external,
        dyn_dispatch_vtable_edges: analysis_config.dyn_dispatch_vtable_edges.into(),
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct PanicFindingCounts {
    pub(crate) raw_panic_paths: usize,
    pub(crate) panic_obligations: usize,
    pub(crate) trusted_panic_obligations: usize,
    pub(crate) indirect_call_boundaries: usize,
    pub(crate) analysis_incomplete: usize,
}

impl PanicFindingCounts {
    fn add(&mut self, other: Self) {
        self.raw_panic_paths += other.raw_panic_paths;
        self.panic_obligations += other.panic_obligations;
        self.trusted_panic_obligations += other.trusted_panic_obligations;
        self.indirect_call_boundaries += other.indirect_call_boundaries;
        self.analysis_incomplete += other.analysis_incomplete;
    }

    pub(crate) fn increment(&mut self, kind: ReportDetailKind) {
        match kind {
            ReportDetailKind::CompilerAssert
            | ReportDetailKind::PanicInvocation
            | ReportDetailKind::CachedDependencyPanic => self.raw_panic_paths += 1,
            ReportDetailKind::PanicObligation => self.panic_obligations += 1,
            ReportDetailKind::TrustedPanicObligation => self.trusted_panic_obligations += 1,
            ReportDetailKind::IndirectCallBoundary => self.indirect_call_boundaries += 1,
            ReportDetailKind::AnalysisIncomplete => self.analysis_incomplete += 1,
        }
    }

    fn has_denied_findings(self, lints: crate::config::PanicLintConfig) -> bool {
        (self.raw_panic_paths > 0 && lints.undocumented_panic_path == LintLevel::Deny)
            || (self.panic_obligations > 0 && lints.documented_panic_contract == LintLevel::Deny)
            || (self.trusted_panic_obligations > 0
                && lints.trusted_panic_contract == LintLevel::Deny)
            || (self.indirect_call_boundaries > 0
                && lints.indirect_call_boundary == LintLevel::Deny)
            || (self.analysis_incomplete > 0 && lints.analysis_incomplete == LintLevel::Deny)
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
                // Unverifiable boundaries get their own lint: they are not
                // proof of a panic, only of a blind spot.
                if matches!(
                    evidence.kind,
                    crate::panics::PanicEvidenceKind::IndirectBoundary { .. }
                ) {
                    emit_indirect_boundary_finding(
                        tcx,
                        graph,
                        evidence,
                        &collection,
                        &mut counts,
                        &mut report,
                    );
                } else {
                    emit_raw_panic_finding(
                        tcx,
                        graph,
                        evidence,
                        &collection,
                        &mut counts,
                        &mut report,
                    );
                }
            }
            PanicPathDecision::PanicObligation { edge_id: None, .. } => {
                // The root's own `# Panics` docs explain its internal panic
                // evidence; callers are checked at the edge where they invoke it.
            }
            PanicPathDecision::PanicObligation {
                edge_id: Some(edge_id),
                def_id,
            } => {
                emit_panic_obligation_finding(
                    tcx,
                    graph,
                    evidence,
                    PanicObligationFinding {
                        edge_id: Some(edge_id),
                        def_id,
                    },
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

fn emit_indirect_boundary_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    collection: &PanicFindingCollection<'_>,
    counts: &mut PanicFindingCounts,
    report: &mut PanicRootReport,
) {
    let level = ReportDetailKind::IndirectCallBoundary.lint_level(collection.config.lints);
    if level == LintLevel::Allow {
        return;
    }

    counts.indirect_call_boundaries += 1;
    report.push_panic_evidence(tcx, graph, evidence, level);
    if collection.diagnostics.emit {
        emit_indirect_boundary_diagnostic(
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
        // Any edge into a non-expanded, non-local instance — direct calls,
        // vtable entries, closure definitions, pointer reifications — carries
        // the same obligation a direct call does; macro-expansion edges are
        // bridge hops, not calls.
        if edge.kind() == ReachabilityEdgeKind::MacroExpansion
            || expanded_sources.contains(&edge.target().id().index())
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

        // A truncated dependency summary with clean counts proves nothing:
        // treat it as raw panic evidence rather than silence.
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
        } else if summary.raw_panic_paths > 0 || !summary.analysis_complete {
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
    use std::path::{Path, PathBuf};

    use super::{CrateOutputScope, metadata_cargo_args};

    #[test]
    fn output_scope_classifies_workspace_dependency_and_fallback_crates() {
        let members = [
            PathBuf::from("/repo/crates/sniff-test/Cargo.toml"),
            // Members can live outside the config directory.
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
        // Vendored crates under the repo root are not members.
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
        // Direct driver mode: no member list, fall back to primary-package.
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
