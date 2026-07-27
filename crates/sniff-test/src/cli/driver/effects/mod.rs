//! Effect-independent root analysis and built-in effect passes.

mod cache;
mod panic;
mod safety;

use std::collections::BTreeMap;

use reachability::{ReachabilityIndex, ReachabilityOptions, ReachabilityView};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;

use crate::cache::{CachedEffectSummary, CachedFinding, CachedFunctionSummary};
use crate::cli::cache_encode::{cached_reachability_graph, cached_source_span};
use crate::cli::findings::Finding;
use crate::cli::report::analysis_incomplete_finding;
use crate::config::{AnalysisConfig, SniffTestConfig};
use crate::contracts::EffectKind;
use crate::dependency_cache::DependencyAnalysisCache;
use crate::effect_tracker::EffectPathIndex;
use crate::namespace::{canonical_namespace, stable_def_path_hash};
use crate::report_roots::{MissingReportRoot, ReportRoot, ReportRootKind, ReportRootSelection};
use crate::safety::SafetyAnalysis;
use panic::PanicPass;
use safety::SafetyPass;

pub(super) struct RootEffectAnalysis {
    pub(super) missing_roots: Vec<MissingReportRoot>,
    pub(super) function_summaries: Vec<CachedFunctionSummary>,
    pub(super) findings: Vec<Finding>,
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

    fn requires_separate_cache_snapshot(&self) -> bool {
        false
    }

    fn query(
        &self,
        reachability: &mut ReachabilityIndex<'tcx>,
        root: ReportRoot<'tcx>,
        analysis_config: &AnalysisConfig,
    ) -> reachability::ReachabilitySnapshot<'tcx>;

    fn query_report(
        &self,
        reachability: &mut ReachabilityIndex<'tcx>,
        root: ReportRoot<'tcx>,
        analysis_config: &AnalysisConfig,
    ) -> reachability::ReachabilitySnapshot<'tcx> {
        self.query(reachability, root, analysis_config)
    }

    fn path_index(&self, tcx: TyCtxt<'tcx>, view: ReachabilityView<'_, 'tcx>) -> EffectPathIndex;

    fn has_root_contract(&self, tcx: TyCtxt<'tcx>, root: DefId) -> bool;

    fn analyze_snapshot(
        &mut self,
        tcx: TyCtxt<'tcx>,
        view: ReachabilityView<'_, 'tcx>,
        root: ReportRoot<'tcx>,
        purpose: EffectViewPurpose,
        dependency_cache: &DependencyAnalysisCache,
    ) -> EffectSnapshotAnalysis;
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

fn analyze_effect_root<'tcx>(
    tcx: TyCtxt<'tcx>,
    reachability: &mut ReachabilityIndex<'tcx>,
    root: ReportRoot<'tcx>,
    analysis_config: &AnalysisConfig,
    dependency_cache: &DependencyAnalysisCache,
    pass: &mut impl EffectPass<'tcx>,
) -> EffectRootAnalysis {
    let kind = pass.kind();
    let requires_separate_cache_snapshot = pass.requires_separate_cache_snapshot();
    let report_snapshot = pass.query_report(reachability, root, analysis_config);
    let report_complete = reachability.graph().view(&report_snapshot).halt().is_none();
    let report_analysis = {
        let view = reachability.graph().view(&report_snapshot);
        pass.analyze_snapshot(tcx, view, root, EffectViewPurpose::Report, dependency_cache)
    };
    let mut findings = report_analysis.findings;

    let (cached_findings, dependency_complete, cache_complete, graph) =
        if requires_separate_cache_snapshot {
            // User-facing panic reports can inspect available external MIR. Cached
            // summaries stop at dependency boundaries so downstream crates can
            // combine them with independently versioned dependency caches.
            let cache_snapshot = pass.query(reachability, root, analysis_config);
            let view = reachability.graph().view(&cache_snapshot);
            let cache_analysis =
                pass.analyze_snapshot(tcx, view, root, EffectViewPurpose::Cache, dependency_cache);
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
    let mut findings_by_effect = BTreeMap::<EffectKind, Vec<Finding>>::new();

    for root in selection.roots {
        let mut effects = BTreeMap::new();
        for kind in EffectKind::ALL {
            let effect = match kind {
                EffectKind::Panic => analyze_effect_root(
                    tcx,
                    &mut reachability,
                    root,
                    analysis_config,
                    dependency_cache,
                    &mut PanicPass {
                        config: &config.panics,
                        include_stack: analysis_config.show_full_stack_trace,
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
    for kind in EffectKind::ALL {
        analysis
            .findings
            .extend(findings_by_effect.remove(&kind).unwrap_or_default());
    }

    analysis
}
