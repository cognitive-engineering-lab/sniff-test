use std::ops::ControlFlow;

use reachability::{
    ReachabilityContext, ReachabilityControl, ReachabilityEdge, ReachabilityHooks,
    ReachabilityIndex, ReachabilityView,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::{Instance, TyCtxt};

use crate::config::{AnalysisConfig, SafetyConfig};
use crate::contracts::EffectKind;
use crate::dependency_cache::DependencyAnalysisCache;
use crate::effect_tracker::{EffectMarkerIndex, EffectPathIndex};
use crate::report_roots::ReportRoot;
use crate::safety::{SafetyAnalysis, safety_doc_summary};

use super::super::{
    collect_cached_dependency_safety_findings, collect_local_safety_findings, reachability_options,
    safety_graph_node_is_boundary, safety_path_node_is_boundary,
};
use super::{EffectPass, EffectSnapshotAnalysis, EffectViewPurpose};

struct SafetyReachabilityHooks<'config> {
    config: &'config SafetyConfig,
}

impl<'tcx> ReachabilityHooks<'tcx> for SafetyReachabilityHooks<'_> {
    fn should_descend(
        &mut self,
        cx: ReachabilityContext<'tcx>,
        _edge: &ReachabilityEdge,
        target: Instance<'tcx>,
    ) -> ReachabilityControl<'tcx, bool> {
        ControlFlow::Continue(!safety_path_node_is_boundary(
            cx.tcx,
            target.def_id(),
            self.config,
        ))
    }
}

pub(super) struct SafetyPass<'config, 'analysis> {
    pub(super) config: &'config SafetyConfig,
    pub(super) analysis: &'analysis mut SafetyAnalysis,
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
