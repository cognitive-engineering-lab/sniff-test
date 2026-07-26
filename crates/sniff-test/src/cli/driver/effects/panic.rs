use std::ops::ControlFlow;

use reachability::{
    ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityEdgeKind,
    ReachabilityHooks, ReachabilityIndex, ReachabilityView,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::{Instance, TyCtxt};

use crate::config::{AnalysisConfig, CallableEdgeAttribution, PanicBoundaryPolicy, PanicConfig};
use crate::contracts::EffectKind;
use crate::dependency_cache::DependencyAnalysisCache;
use crate::effect_tracker::{EffectMarkerIndex, EffectPathIndex};
use crate::panics::analyze_panic_evidence;
use crate::report_roots::ReportRoot;

use super::super::{
    PanicFindingCollection, cached_boundary_findings, collect_cached_dependency_findings,
    collect_panic_findings, reachability_options,
};
use super::{EffectPass, EffectSnapshotAnalysis, EffectViewPurpose};

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
        ControlFlow::Continue(
            !self.config.ignores_def(cx.tcx, def_id)
                && self.config.panic_boundary_policy(cx.tcx, def_id) == PanicBoundaryPolicy::Normal
                && !crate::panics::has_panic_docs(cx.tcx, def_id, self.config),
        )
    }
}

pub(super) struct PanicPass<'config> {
    pub(super) config: &'config PanicConfig,
    pub(super) include_stack: bool,
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
