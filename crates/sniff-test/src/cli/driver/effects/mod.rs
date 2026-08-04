//! Effect-independent root analysis and built-in effect pipelines.

mod cache;
mod panic;
mod pipeline;
mod safety;

use std::collections::HashSet;
use std::collections::VecDeque;

use reachability::{
    ArtifactScope, ReachabilityEdgeId, ReachabilityGraph, ReachabilityIndex, ReachabilityOptions,
};
use rustc_hir::def::DefKind;
use rustc_middle::ty::{GenericArgs, Instance, InstanceKind, TyCtxt};

use crate::cache::{CachedEffectInput, CachedFunctionInput, CachedItemKey};
use crate::cli::diagnostics::analysis_incomplete_diagnostic;
use crate::cli::findings::{DiagnosticMessage, Finding, FindingDiagnostic, FindingKind};
use crate::cli::report::{render_span, render_trace};
use crate::config::{AnalysisConfig, SniffTestConfig};
use crate::dependency_cache::DependencyAnalysisCache;
use crate::effect_tracker::EffectTrace;
use crate::namespace::{StableDefPathHash, StableInstanceHash, canonical_namespace};
use crate::report_roots::{MissingReportRoot, ReportRoot, ReportRootSelection};
use crate::safety::SafetyAnalysis;

pub(super) struct RootEffectAnalysis {
    pub(super) missing_roots: Vec<MissingReportRoot>,
    pub(super) functions: Vec<CachedFunctionInput>,
    pub(super) findings: Vec<Finding>,
}

struct EffectRootAnalysis<'tcx> {
    summary: CachedEffectInput,
    findings: Vec<Finding>,
    reached_instances: Vec<Instance<'tcx>>,
}

struct IncompleteDependency {
    edge_id: ReachabilityEdgeId,
    target: String,
    trace: EffectTrace,
}

fn reachability_options(
    analysis_config: &AnalysisConfig,
    artifact_scope: ArtifactScope,
) -> ReachabilityOptions {
    ReachabilityOptions {
        node_limit: Some(analysis_config.node_limit),
        artifact_scope,
        dyn_dispatch_vtable_edges: analysis_config.callable_edge_attribution.into(),
        fn_pointer_edges: analysis_config.callable_edge_attribution.into(),
    }
}

fn root_analysis_incomplete_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    root: ReportRoot<'tcx>,
    node_limit: usize,
    kind: FindingKind,
) -> Finding {
    let root_def_id = root.def_id();
    Finding {
        root: Some(canonical_namespace(tcx, root_def_id)),
        root_kind: Some(root.kind()),
        span: Some(render_span(tcx, tcx.def_span(root_def_id))),
        ..Finding::new(
            kind,
            format!(
                "reachability analysis halted at the {node_limit}-instance node limit \
                 before the call graph was exhausted"
            ),
            analysis_incomplete_diagnostic(tcx, root_def_id, node_limit),
        )
    }
}

fn dependency_analysis_incomplete_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    root: ReportRoot<'tcx>,
    dependency: &IncompleteDependency,
    kind: FindingKind,
    effect: &str,
) -> Finding {
    let edge = graph.edge(dependency.edge_id);
    let root_name = canonical_namespace(tcx, root.def_id());
    Finding {
        root: Some(root_name.clone()),
        root_kind: Some(root.kind()),
        target: Some(dependency.target.clone()),
        span: Some(render_span(tcx, edge.span)),
        trace: render_trace(tcx, graph, &dependency.trace.edge_ids),
        ..Finding::new(
            kind,
            format!(
                "{} has no complete cached {effect} analysis",
                dependency.target
            ),
            FindingDiagnostic {
                span: Some(edge.span),
                message: format!(
                    "function `{root_name}` reaches a dependency without complete {effect} analysis"
                ),
                messages: vec![DiagnosticMessage::Note(format!(
                    "cache evidence for `{}` is missing, stale, or incomplete",
                    dependency.target
                ))],
            },
        )
        .with_dependency_analysis_lint()
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
        functions: Vec::new(),
        findings: Vec::new(),
    };
    let mut reachability = ReachabilityIndex::new(tcx);
    let mut safety_analysis = SafetyAnalysis::default();
    let mut safety_findings = Vec::new();
    let mut panic_findings = Vec::new();
    let mut seen = HashSet::new();
    let mut pending = selection
        .roots
        .into_iter()
        .map(|root| (root, true))
        .collect::<VecDeque<_>>();

    while let Some((root, report_findings)) = pending.pop_front() {
        let key = cached_item_key(tcx, root);
        if !seen.insert(key) {
            continue;
        }
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
        for instance in safety
            .reached_instances
            .iter()
            .chain(&panic.reached_instances)
        {
            if let Some(root) = resume_root(tcx, *instance) {
                pending.push_back((root, false));
            }
        }
        if report_findings {
            safety_findings.extend(safety.findings);
            panic_findings.extend(panic.findings);
        }
        analysis.functions.push(CachedFunctionInput {
            key,
            path: canonical_namespace(tcx, root.def_id()),
            panic: panic.summary,
            safety: safety.summary,
        });
    }
    analysis.findings.extend(safety_findings);
    analysis.findings.extend(panic_findings);

    analysis
}

fn cached_item_key<'tcx>(tcx: TyCtxt<'tcx>, root: ReportRoot<'tcx>) -> CachedItemKey {
    let def_path_hash = StableDefPathHash::from_def_id(tcx, root.def_id());
    match root {
        ReportRoot::Concrete { instance } => CachedItemKey::exact_item(
            def_path_hash,
            StableInstanceHash::from_instance(tcx, instance),
        ),
        ReportRoot::Generic { .. } => CachedItemKey::generic_template(def_path_hash),
    }
}

fn resume_root<'tcx>(tcx: TyCtxt<'tcx>, instance: Instance<'tcx>) -> Option<ReportRoot<'tcx>> {
    let InstanceKind::Item(def_id) = instance.def else {
        return None;
    };
    let local = def_id.as_local()?;
    if !matches!(tcx.def_kind(local), DefKind::Fn | DefKind::AssocFn) {
        return None;
    }
    if tcx.generics_of(def_id).requires_monomorphization(tcx)
        && instance.args == GenericArgs::identity_for_item(tcx, def_id)
    {
        Some(ReportRoot::Generic { local })
    } else {
        Some(ReportRoot::Concrete { instance })
    }
}
