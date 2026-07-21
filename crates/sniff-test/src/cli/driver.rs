//! Per-rustc-unit analysis orchestration.

use std::collections::{HashMap, HashSet};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use crate::cache::{
    CacheError, CacheExpectations, CachedArtifactAnalysis, CachedArtifactInfo,
    CachedFunctionSummary, OUTCOME_FORMAT_VERSION, UnitOutcome, artifact_id,
};
use crate::config::{
    AnalysisConfig, CallableEdgeAttribution, PanicBoundaryPolicy, PanicConfig, SniffTestConfig,
};
use crate::dependency_cache::{DependencyAnalysisCache, DependencyInput};
use crate::effect_tracker::{EffectPathDecision, EffectTrace, classify_effect_path, trace_to_node};
use crate::namespace::{canonical_namespace, stable_def_path_hash};
use crate::panics::{PanicAnalysis, PanicEvidence, PanicPathDecision, analyze_panic_evidence};
use crate::report_roots::{
    MissingReportRoot, ReportRoot, ReportRootKind, ReportRootSelection, select_report_roots,
};
use crate::safety::{SafetyAnalysis, analyze_safety, safety_doc_summary};
use anyhow::Context;
use reachability::{
    ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityEdgeKind,
    ReachabilityGraph, ReachabilityHooks, ReachabilityIndex, ReachabilityNodeKind,
    ReachabilityOptions, ReachabilityView,
};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_middle::ty::{Instance, TyCtxt};
use rustc_session::config::CrateType;

use super::args::{self, SniffTestArgs};
use super::cache_encode::{
    cached_boundary_findings, cached_reachability_graph, cached_source_span,
};
use super::diagnostics::emit_finding_diagnostic;
use super::findings::{
    Finding, FindingKind, collect_report_root_findings, resolve_findings, safety_finding_report,
};
use super::plugin::rustc_version;
use super::report::{
    AnalysisArtifactReport, CrateOutputScope, PanicRootReport, REPORT_FORMAT_VERSION, render_node,
};

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

    let selection = select_report_roots(tcx, &config.analysis);
    let selection_has_roots = !selection.roots.is_empty();
    let emit_diagnostics = args.message_format == args::MessageFormat::Human
        && output_scope == CrateOutputScope::Workspace;
    let safety_analysis =
        (output_scope == CrateOutputScope::Workspace).then(|| analyze_safety(tcx, &config.safety));
    let effect_analysis = analyze_effect_roots(
        tcx,
        selection,
        &config.analysis,
        &config.panics,
        safety_analysis.as_ref(),
        &config.safety,
        &dependency_cache,
    );
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

fn analyze_safety_root<'tcx>(
    tcx: TyCtxt<'tcx>,
    reachability: &mut ReachabilityIndex<'tcx>,
    root: ReportRoot<'tcx>,
    analysis_config: &AnalysisConfig,
    safety_config: &crate::config::SafetyConfig,
    analysis: &SafetyAnalysis,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut hooks = reachability::NoopReachabilityHooks;
    let snapshot = reachability.query(
        root.reachability_root(),
        &mut hooks,
        reachability_options(analysis_config, false),
    );
    let graph = reachability.graph();
    let view = graph.view(&snapshot);
    let mut reached_instances = HashMap::<DefId, Vec<_>>::new();
    for node in view.nodes() {
        if let Some(instance) = node.instance() {
            reached_instances
                .entry(instance.def_id())
                .or_default()
                .push(node);
        }
    }
    for safety_finding in &analysis.findings {
        if safety_finding.is_root_contract_finding() && safety_finding.owner() != root.def_id() {
            continue;
        }
        let Some(owner_instances) = reached_instances.get(&safety_finding.owner()) else {
            continue;
        };
        let Some(trace) = safety_finding_trace(
            tcx,
            graph,
            view.root(),
            owner_instances,
            safety_config,
            safety_finding.is_effect_site(),
        ) else {
            continue;
        };

        let mut finding = safety_finding_report(
            tcx,
            safety_finding.clone(),
            &safety_config.documentation_overrides,
        );
        finding.root = Some(canonical_namespace(tcx, root.def_id()));
        finding.root_kind = Some(root.kind());
        finding.trace = super::report::render_trace(tcx, graph, &trace.edge_ids);
        findings.push(finding);
    }

    for safety_finding in analysis.ambiguous_marker_findings(root.def_id(), |owner_id| {
        reached_instances.get(&owner_id).is_some_and(|instances| {
            safety_finding_trace(tcx, graph, view.root(), instances, safety_config, true).is_some()
        })
    }) {
        let mut finding =
            safety_finding_report(tcx, safety_finding, &safety_config.documentation_overrides);
        finding.root = Some(canonical_namespace(tcx, root.def_id()));
        finding.root_kind = Some(root.kind());
        findings.push(finding);
    }

    findings
}

fn safety_finding_trace<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    root: reachability::ReachedNode<'_, 'tcx>,
    owner_instances: &[reachability::ReachedNode<'_, 'tcx>],
    config: &crate::config::SafetyConfig,
    require_raw_path: bool,
) -> Option<EffectTrace> {
    owner_instances.iter().find_map(|owner| {
        let trace = EffectTrace {
            edge_ids: trace_to_node(*owner),
        };
        (!require_raw_path || safety_path_is_raw(tcx, graph, root, &trace, config)).then_some(trace)
    })
}

fn safety_path_is_raw<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    root: reachability::ReachedNode<'_, 'tcx>,
    trace: &EffectTrace,
    config: &crate::config::SafetyConfig,
) -> bool {
    matches!(
        classify_effect_path(graph, root, trace, |node| {
            let ReachabilityNodeKind::Instance(instance) = node else {
                return None;
            };
            let def_id = instance.def_id();
            (config.ignores_def(tcx, def_id)
                || safety_doc_summary(tcx, def_id, &config.documentation_overrides).has_docs)
                .then_some(def_id)
        }),
        EffectPathDecision::RawEffect
    )
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

fn analyze_effect_roots<'tcx>(
    tcx: TyCtxt<'tcx>,
    selection: ReportRootSelection<'tcx>,
    analysis_config: &AnalysisConfig,
    panic_config: &PanicConfig,
    safety_analysis: Option<&SafetyAnalysis>,
    safety_config: &crate::config::SafetyConfig,
    dependency_cache: &DependencyAnalysisCache,
) -> RootEffectAnalysis {
    let mut analysis = RootEffectAnalysis {
        missing_roots: selection.missing_roots,
        function_summaries: Vec::new(),
        findings: Vec::new(),
    };
    let mut reachability = ReachabilityIndex::new(tcx);
    let mut panic_findings = Vec::new();

    for root in selection.roots {
        if let Some(safety_analysis) = safety_analysis {
            analysis.findings.extend(analyze_safety_root(
                tcx,
                &mut reachability,
                root,
                analysis_config,
                safety_config,
                safety_analysis,
            ));
        }
        let (summary, report) = analyze_panic_root(
            tcx,
            &mut reachability,
            root,
            analysis_config,
            panic_config,
            dependency_cache,
            analysis_config.show_full_stack_trace,
        );
        analysis.function_summaries.push(summary);
        panic_findings.extend(report.findings);
    }
    analysis.findings.extend(panic_findings);

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

fn analyze_panic_root<'tcx>(
    tcx: TyCtxt<'tcx>,
    reachability: &mut ReachabilityIndex<'tcx>,
    root: ReportRoot<'tcx>,
    analysis_config: &AnalysisConfig,
    config: &PanicConfig,
    dependency_cache: &DependencyAnalysisCache,
    include_stack: bool,
) -> (CachedFunctionSummary, PanicRootReport) {
    let root_def_id = root.def_id();
    let root_kind = root.kind();
    let descend_reified_callables =
        analysis_config.callable_edge_attribution == CallableEdgeAttribution::ErasureSites;
    let mut hooks = PanicReachabilityHooks {
        config,
        descend_reified_callables,
    };
    let result = reachability.query(
        root.reachability_root(),
        &mut hooks,
        reachability_options(analysis_config, true),
    );
    let graph = reachability.graph();
    let view = graph.view(&result);
    let analysis = analyze_panic_evidence(tcx, view, config);
    let mut report = collect_panic_findings(
        tcx,
        view,
        &analysis,
        PanicFindingCollection {
            root_kind,
            root_def_id,
            config,
            dependency_cache,
            include_stack,
        },
    );
    let transitive_complete = view.halt().is_none();

    // The user-facing report follows available MIR across crate boundaries.
    // The cached summary stops at those boundaries so downstream crates can
    // combine it with separately versioned dependency caches. ReachabilityIndex
    // memoizes body expansion, making this traversal cheaper than rebuilding
    // the graph.
    let mut boundary_hooks = PanicReachabilityHooks {
        config,
        descend_reified_callables,
    };
    let boundary_result = reachability.query(
        root.reachability_root(),
        &mut boundary_hooks,
        reachability_options(analysis_config, false),
    );
    let graph = reachability.graph();
    let boundary_view = graph.view(&boundary_result);
    let boundary_analysis = analyze_panic_evidence(tcx, boundary_view, config);
    let cached_findings = cached_boundary_findings(tcx, boundary_view, &boundary_analysis, config);
    let analysis_complete = transitive_complete && boundary_view.halt().is_none();
    if !analysis_complete {
        report.push_analysis_incomplete(tcx, root_def_id, analysis_config.node_limit);
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
        def_path_hash: stable_def_path_hash(tcx, root_def_id),
        path: canonical_namespace(tcx, root_def_id),
        is_generic: root_kind == ReportRootKind::Generic,
        analysis_complete,
        has_panic_docs: crate::panics::has_panic_docs(tcx, root_def_id, config),
        root_span: cached_source_span(tcx, tcx.def_span(root_def_id)),
        raw_panic_paths,
        panic_obligations,
        trusted_panic_obligations,
        graph: Some(cached_reachability_graph(tcx, boundary_view)),
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
