//! Effect-independent root analysis and built-in effect pipelines.

mod cache;
mod panic;
mod pipeline;
mod safety;

use reachability::{ReachabilityIndex, ReachabilityOptions};
use rustc_middle::ty::TyCtxt;

use crate::cache::{
    CachedEffectSummary, CachedFinding, CachedFunctionSummary, CachedReachabilityGraph,
};
use crate::cli::cache_encode::cached_source_span;
use crate::cli::findings::{Finding, FindingKind};
use crate::cli::report::analysis_incomplete_finding;
use crate::config::{AnalysisConfig, SniffTestConfig};
use crate::dependency_cache::DependencyAnalysisCache;
use crate::namespace::{canonical_namespace, stable_def_path_hash};
use crate::report_roots::{MissingReportRoot, ReportRoot, ReportRootKind, ReportRootSelection};
use crate::safety::SafetyAnalysis;

pub(super) struct RootEffectAnalysis {
    pub(super) missing_roots: Vec<MissingReportRoot>,
    pub(super) function_summaries: Vec<CachedFunctionSummary>,
    pub(super) findings: Vec<Finding>,
}

struct EffectRootAnalysis {
    summary: CachedEffectSummary,
    findings: Vec<Finding>,
}

struct EffectReportOutput {
    findings: Vec<Finding>,
    query_complete: bool,
}

struct EffectCacheOutput {
    findings: Vec<CachedFinding>,
    graph: CachedReachabilityGraph,
    query_complete: bool,
    dependencies_complete: bool,
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

fn finish_effect_root<'tcx>(
    tcx: TyCtxt<'tcx>,
    root: ReportRoot<'tcx>,
    analysis_config: &AnalysisConfig,
    incomplete_finding_kind: FindingKind,
    has_contract: bool,
    report: EffectReportOutput,
    cache: EffectCacheOutput,
) -> EffectRootAnalysis {
    let mut findings = report.findings;
    let analysis_complete =
        report.query_complete && cache.query_complete && cache.dependencies_complete;
    if !report.query_complete || !cache.query_complete {
        let mut finding = analysis_incomplete_finding(
            tcx,
            root.def_id(),
            analysis_config.node_limit,
            incomplete_finding_kind,
        );
        finding.root = Some(canonical_namespace(tcx, root.def_id()));
        finding.root_kind = Some(root.kind());
        findings.push(finding);
    }
    EffectRootAnalysis {
        summary: CachedEffectSummary {
            analysis_complete,
            has_contract,
            graph: cache.graph,
            findings: cache.findings,
        },
        findings,
    }
}

pub(super) fn analyze_effect_roots<'tcx>(
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
    let mut safety_findings = Vec::new();
    let mut panic_findings = Vec::new();

    for root in selection.roots {
        let safety = safety::analyze_root(
            tcx,
            &mut reachability,
            root,
            analysis_config,
            &config.safety,
            &mut safety_analysis,
            dependency_cache,
        );
        let panic = panic::analyze_root(
            tcx,
            &mut reachability,
            root,
            analysis_config,
            &config.panics,
            dependency_cache,
        );
        safety_findings.extend(safety.findings);
        panic_findings.extend(panic.findings);
        analysis.function_summaries.push(CachedFunctionSummary {
            def_path_hash: stable_def_path_hash(tcx, root.def_id()),
            path: canonical_namespace(tcx, root.def_id()),
            is_generic: root.kind() == ReportRootKind::Generic,
            root_span: cached_source_span(tcx, tcx.def_span(root.def_id())),
            panic: panic.summary,
            safety: safety.summary,
        });
    }
    analysis.findings.extend(safety_findings);
    analysis.findings.extend(panic_findings);

    analysis
}
