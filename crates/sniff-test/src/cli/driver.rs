//! Per-rustc-unit analysis orchestration.

use std::collections::HashSet;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use crate::cache::{
    CacheExpectations, CachedArtifactAnalysis, CachedArtifactInfo, CachedFunctionSummary,
    OUTCOME_FORMAT_VERSION, UnitOutcome, artifact_id, write_artifact_analysis, write_unit_outcome,
};
use crate::config::{
    AnalysisConfig, CallableEdgeAttribution, PanicBoundaryPolicy, PanicConfig, SniffTestConfig,
};
use crate::dependency_cache::{DependencyAnalysisCache, DependencyInput};
use crate::namespace::{canonical_namespace, stable_def_path_hash};
use crate::panics::{PanicAnalysis, PanicEvidence, PanicPathDecision, analyze_panic_evidence};
use crate::report_roots::{
    MissingReportRoot, ReportRoot, ReportRootSelection, select_report_roots,
};
use crate::safety::{SafetyAnalysis, analyze_safety};
use reachability::{
    ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityEdgeKind,
    ReachabilityGraph, ReachabilityHooks, ReachabilityIndex, ReachabilityOptions, ReachabilityRoot,
    ReachabilitySnapshot, ReachabilityView,
};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_middle::ty::{Instance, TyCtxt};

use super::args::{self, SniffTestArgs};
use super::cache_encode::{
    cached_boundary_findings, cached_reachability_graph, cached_source_span,
};
use super::diagnostics::emit_finding_diagnostic;
use super::findings::{
    Finding, FindingKind, PanicRootKind, collect_report_root_findings, collect_safety_findings,
    resolve_findings,
};
use super::plugin::rustc_version;
use super::report::{
    AnalysisArtifactReport, CrateOutputScope, PanicRootReport, REPORT_FORMAT_VERSION,
    render_json_analysis_artifact_report, render_node,
};
use super::rustc_invocation::RustcInvocation;

struct PanicReachabilityHooks<'config> {
    config: &'config PanicConfig,
    descend_reified_callables: bool,
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
    let selection_has_roots = !selection.roots.is_empty();
    let emit_diagnostics = args.message_format == args::MessageFormat::Human
        && output_scope == CrateOutputScope::Workspace;
    let root_analysis = analyze_report_roots(
        tcx,
        selection,
        &config.analysis,
        &config.panics,
        &dependency_cache,
        config.analysis.show_full_stack_trace,
    );
    let empty_report_roots = !selection_has_roots && root_analysis.missing_roots.is_empty();
    let safety_analysis = if output_scope == CrateOutputScope::Workspace {
        analyze_safety(tcx, &config.safety)
    } else {
        SafetyAnalysis::default()
    };
    let analysis_findings = collect_report_root_findings(
        tcx,
        &args.manifest_path(),
        empty_report_roots,
        &root_analysis.missing_roots,
        &config.analysis.report_roots,
        &crate_name,
    );
    let analysis = AnalysisArtifact::new(
        tcx,
        &invocation,
        output_scope,
        &dependency_cache,
        &config,
        root_analysis,
        safety_analysis,
        analysis_findings,
    );
    if emit_diagnostics {
        for finding in &analysis.report.findings {
            emit_finding_diagnostic(tcx, finding.level, &finding.finding.diagnostic);
        }
    }
    write_analysis_cache(args, &analysis.cache);
    emit_report_and_outcome(
        args,
        &analysis.report,
        analysis.report.scope == CrateOutputScope::Workspace
            && analysis.report.has_denied_findings(),
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
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor assembles independent analysis outputs without hiding them"
    )]
    fn new(
        tcx: TyCtxt<'_>,
        invocation: &RustcInvocation,
        scope: CrateOutputScope,
        dependency_cache: &DependencyAnalysisCache,
        config: &SniffTestConfig,
        root_analysis: RootAnalysis,
        safety_analysis: SafetyAnalysis,
        mut findings: Vec<Finding>,
    ) -> Self {
        let dependencies = dependency_cache.resolved_dependencies();
        let artifact = artifact_info(tcx, invocation);
        let tool_version = env!("CARGO_PKG_VERSION").to_owned();
        let rustc_version = rustc_version();
        findings.extend(root_analysis.findings);
        findings.extend(collect_safety_findings(
            tcx,
            safety_analysis,
            &config.safety.documentation_overrides,
        ));
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
            root_analysis.function_summaries,
        );

        Self { report, cache }
    }
}

struct RootAnalysis {
    missing_roots: Vec<MissingReportRoot>,
    function_summaries: Vec<CachedFunctionSummary>,
    findings: Vec<Finding>,
}

fn analyze_report_roots<'tcx>(
    tcx: TyCtxt<'tcx>,
    selection: ReportRootSelection<'tcx>,
    analysis_config: &AnalysisConfig,
    config: &PanicConfig,
    dependency_cache: &DependencyAnalysisCache,
    include_stack: bool,
) -> RootAnalysis {
    let mut analysis = RootAnalysis {
        missing_roots: selection.missing_roots,
        function_summaries: Vec::new(),
        findings: Vec::new(),
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
        let (summary, report) = analyze_root(
            tcx,
            &mut reachability,
            root,
            analysis_config,
            config,
            dependency_cache,
            include_stack,
        );
        analysis.function_summaries.push(summary);
        analysis.findings.extend(report.findings);
    }

    analysis
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

        let cargo_manifest = std::env::var_os("CARGO_MANIFEST_PATH").map(|path| {
            let path = PathBuf::from(path);
            path.canonicalize().unwrap_or_else(|error| {
                eprintln!(
                    "sniff-test: failed to canonicalize Cargo manifest {}: {error}",
                    path.display()
                );
                std::process::exit(2);
            })
        });
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
    include_stack: bool,
) -> (CachedFunctionSummary, PanicRootReport) {
    let descend_reified_callables =
        analysis_config.callable_edge_attribution == CallableEdgeAttribution::ErasureSites;
    let mut hooks = PanicReachabilityHooks {
        config,
        descend_reified_callables,
    };
    let result = reachability.query(
        root.root,
        &mut hooks,
        reachability_options(analysis_config, true),
    );
    let graph = reachability.graph();
    let analysis = analyze_panic_evidence(tcx, graph, &result, config);
    let mut report = collect_panic_findings(
        tcx,
        graph,
        &result,
        &analysis,
        PanicFindingCollection {
            root_kind: root.kind,
            root_def_id: root.def_id,
            config,
            dependency_cache,
            include_stack,
        },
    );
    let transitive_complete = graph.view(&result).halt().is_none();

    // A second, boundary-only query per root is deliberate: body expansion is
    // memoized across queries and policy/marker verdicts are cached, so this
    // re-traverses the in-memory graph cheaply, while deriving boundary
    // findings from the transitive snapshot would change the serialized
    // cache graphs and their trace semantics.
    let mut boundary_hooks = PanicReachabilityHooks {
        config,
        descend_reified_callables,
    };
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
        report.push_analysis_incomplete(tcx, root.def_id, analysis_config.node_limit);
    }
    let raw_panic_paths = report
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                FindingKind::CompilerAssert
                    | FindingKind::PanicInvocation
                    | FindingKind::CachedDependencyPanic
            )
        })
        .count();
    let panic_obligations = report
        .findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::DocumentedPanic)
        .count();
    let trusted_panic_obligations = report
        .findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::TrustedPanic)
        .count();
    let summary = CachedFunctionSummary {
        def_path_hash: stable_def_path_hash(tcx, root.def_id),
        path: canonical_namespace(tcx, root.def_id),
        is_generic: root.kind == PanicRootKind::Generic,
        analysis_complete,
        has_panic_docs: crate::panics::has_panic_docs(tcx, root.def_id, config),
        root_span: cached_source_span(tcx, tcx.def_span(root.def_id)),
        raw_panic_paths,
        panic_obligations,
        trusted_panic_obligations,
        graph: Some(cached_reachability_graph(tcx, graph, &boundary_result)),
        findings: cached_findings,
    };

    (summary, report)
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
    }
}

#[derive(Clone, Copy)]
struct PanicFindingCollection<'config> {
    root_kind: PanicRootKind,
    root_def_id: DefId,
    config: &'config PanicConfig,
    dependency_cache: &'config DependencyAnalysisCache,
    include_stack: bool,
}

fn collect_panic_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    result: &ReachabilitySnapshot<'tcx>,
    analysis: &PanicAnalysis,
    collection: PanicFindingCollection<'_>,
) -> PanicRootReport {
    let view = graph.view(result);
    let root_node = view.root();
    let mut report = PanicRootReport::new(
        render_node(tcx, root_node.kind()),
        collection.root_kind,
        collection.root_def_id,
        collection.include_stack,
    );

    for evidence in &analysis.evidence {
        match evidence.decision {
            PanicPathDecision::RawPanic => {
                report.push_panic_evidence(tcx, graph, evidence);
            }
            PanicPathDecision::PanicObligation { edge_id: None, .. } => {
                // The root's own `# Panics` docs explain its internal panic
                // evidence; callers are checked at the edge where they invoke it.
            }
            PanicPathDecision::PanicObligation {
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

    collect_cached_dependency_findings(tcx, graph, view, &collection, &mut report);

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
    graph: &ReachabilityGraph<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    collection: &PanicFindingCollection<'_>,
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
        if collection.config.ignores_def(tcx, def_id)
            || collection.config.panic_boundary_policy(tcx, def_id) != PanicBoundaryPolicy::Normal
        {
            continue;
        }

        let dependency_crate_name = tcx.crate_name(def_id.krate).to_string();
        let Some(summary) = collection
            .dependency_cache
            .function(&dependency_crate_name, &stable_def_path_hash(tcx, def_id))
            .filter(|summary| !summary.has_panic_docs)
        else {
            continue;
        };

        let local_trace = crate::panics::trace_to_edge_ids(edge);

        // A truncated dependency summary with clean counts proves nothing:
        // treat it as raw panic evidence rather than silence.
        if summary.panic_obligations > 0 || summary.trusted_panic_obligations > 0 {
            let kind = if is_trusted_panic_obligation(tcx, def_id, collection.config) {
                FindingKind::TrustedPanic
            } else {
                FindingKind::DocumentedPanic
            };
            let mut emitted = false;
            for cached_finding in summary.findings.iter().filter(|finding| {
                matches!(
                    finding.kind,
                    crate::cache::CachedFindingKind::PanicObligation
                        | crate::cache::CachedFindingKind::TrustedPanicObligation
                )
            }) {
                emitted = true;
                report.push_cached_dependency_obligation(
                    tcx,
                    graph,
                    edge.id(),
                    &local_trace,
                    summary,
                    Some(cached_finding),
                    kind,
                );
            }
            if !emitted {
                report.push_cached_dependency_obligation(
                    tcx,
                    graph,
                    edge.id(),
                    &local_trace,
                    summary,
                    None,
                    kind,
                );
            }
        } else if summary.raw_panic_paths > 0 || !summary.analysis_complete {
            let mut emitted = false;
            for cached_finding in summary.findings.iter().filter(|finding| {
                matches!(
                    finding.kind,
                    crate::cache::CachedFindingKind::CompilerAssert
                        | crate::cache::CachedFindingKind::PanicInvocation
                        | crate::cache::CachedFindingKind::IndirectCallBoundary
                )
            }) {
                emitted = true;
                report.push_cached_dependency_panic(
                    tcx,
                    graph,
                    edge.id(),
                    &local_trace,
                    summary,
                    Some(cached_finding),
                );
            }
            if !emitted {
                report.push_cached_dependency_panic(
                    tcx,
                    graph,
                    edge.id(),
                    &local_trace,
                    summary,
                    None,
                );
            }
        }
    }
}

pub(crate) fn load_config(args: &SniffTestArgs) -> SniffTestConfig {
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
