//! Effect-independent root analysis and built-in effect passes.

use super::{
    AnalysisConfig, BTreeMap, CachedEffectSummary, CachedFinding, CachedFunctionSummary,
    CallableEdgeAttribution, DefId, DependencyAnalysisCache, EffectKind, EffectMarkerIndex,
    EffectPathIndex, Finding, MissingReportRoot, PanicConfig, PanicFindingCollection,
    PanicReachabilityHooks, ReachabilityIndex, ReachabilityView, ReportRoot, ReportRootKind,
    ReportRootSelection, SafetyAnalysis, SafetyReachabilityHooks, SniffTestConfig, TyCtxt,
    analysis_incomplete_finding, analyze_panic_evidence, cached_boundary_findings,
    cached_reachability_graph, cached_source_span, canonical_namespace,
    collect_cached_dependency_findings, collect_cached_dependency_safety_findings,
    collect_local_safety_findings, collect_panic_findings, reachability_options,
    safety_doc_summary, safety_graph_node_is_boundary, stable_def_path_hash,
};

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

struct PanicPass<'config> {
    config: &'config PanicConfig,
    include_stack: bool,
}

impl<'tcx> PanicPass<'_> {
    fn query_with_external_mir(
        &self,
        reachability: &mut ReachabilityIndex<'tcx>,
        root: ReportRoot<'tcx>,
        analysis_config: &AnalysisConfig,
        analyze_external: bool,
    ) -> reachability::ReachabilitySnapshot<'tcx> {
        let mut hooks = PanicReachabilityHooks {
            config: self.config,
            descend_reified_callables: analysis_config.callable_edge_attribution
                == CallableEdgeAttribution::ErasureSites,
        };
        reachability.query(
            root.reachability_root(),
            &mut hooks,
            reachability_options(analysis_config, analyze_external),
        )
    }
}

impl<'tcx> EffectPass<'tcx> for PanicPass<'_> {
    fn kind(&self) -> EffectKind {
        EffectKind::Panic
    }

    fn requires_separate_cache_snapshot(&self) -> bool {
        true
    }

    fn query(
        &self,
        reachability: &mut ReachabilityIndex<'tcx>,
        root: ReportRoot<'tcx>,
        analysis_config: &AnalysisConfig,
    ) -> reachability::ReachabilitySnapshot<'tcx> {
        self.query_with_external_mir(reachability, root, analysis_config, false)
    }

    fn query_report(
        &self,
        reachability: &mut ReachabilityIndex<'tcx>,
        root: ReportRoot<'tcx>,
        analysis_config: &AnalysisConfig,
    ) -> reachability::ReachabilitySnapshot<'tcx> {
        self.query_with_external_mir(reachability, root, analysis_config, true)
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
            include_stack: self.include_stack,
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
