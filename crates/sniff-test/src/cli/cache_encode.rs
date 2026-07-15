use std::collections::{BTreeMap, BTreeSet};

use crate::cache::{
    CachedDiagnosticSpan, CachedFinding, CachedFindingKind, CachedFindingTarget,
    CachedFunctionSummary, CachedSourceSpan, CachedTraceArena, CachedTraceFrame,
    CachedTraceFrameKind, CachedTraceNode,
};
use crate::config::PanicConfig;
use crate::namespace::{canonical_namespace, stable_def_path_hash};
use crate::panics::{
    PanicAnalysis, PanicEvidence, PanicEvidenceKind, PanicPathDecision,
    describe_panic_evidence_kind, trace_edges_until, trace_to_edge_ids, trigger_edge_id,
};
use reachability::{
    ReachabilityEdgeKind, ReachabilityGraph, ReachabilityNodeKind, ReachabilitySnapshot,
    ReachabilityView,
};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::Pos;

use super::report::{
    PanicFindingReport, ReportDetailKind, render_assert_message, render_node, render_span,
};

pub(super) fn function_summary(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    is_generic: bool,
    analysis_complete: bool,
    report_findings: &[PanicFindingReport],
    config: &PanicConfig,
    trace_arena: CachedTraceArena,
    findings: Vec<CachedFinding>,
) -> CachedFunctionSummary {
    let raw_panic_paths = report_findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                ReportDetailKind::CompilerAssert
                    | ReportDetailKind::PanicInvocation
                    | ReportDetailKind::CachedDependencyPanic
            )
        })
        .count();
    let panic_obligations = report_findings
        .iter()
        .filter(|finding| finding.kind == ReportDetailKind::DocumentedPanic)
        .count();
    let trusted_panic_obligations = report_findings
        .iter()
        .filter(|finding| finding.kind == ReportDetailKind::TrustedPanic)
        .count();
    CachedFunctionSummary {
        def_path_hash: stable_def_path_hash(tcx, def_id),
        path: canonical_namespace(tcx, def_id),
        is_generic,
        analysis_complete,
        has_panic_docs: crate::panics::has_panic_docs(tcx, def_id, config),
        root_span: cached_source_span(tcx, tcx.def_span(def_id)),
        raw_panic_paths,
        panic_obligations,
        trusted_panic_obligations,
        trace_arena,
        findings,
    }
}

pub(super) fn cached_boundary_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    result: &ReachabilitySnapshot<'tcx>,
    analysis: &PanicAnalysis,
    config: &PanicConfig,
) -> (Vec<CachedFinding>, CachedTraceArena) {
    let view = graph.view(result);
    let mut findings = analysis
        .evidence
        .iter()
        .map(|evidence| cached_panic_finding(tcx, graph, evidence, config))
        .collect::<Vec<_>>();

    findings.extend(cached_crate_boundary_findings(tcx, view, config));
    let trace_arena = cached_trace_arena(tcx, graph, result, &mut findings);
    (findings, trace_arena)
}

fn cached_panic_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    config: &PanicConfig,
) -> CachedFinding {
    match evidence.decision {
        PanicPathDecision::RawPanic => {
            let edge_id = trigger_edge_id(graph, evidence);
            let edge = graph.edge(edge_id);
            CachedFinding {
                kind: match &evidence.kind {
                    PanicEvidenceKind::CompilerAssert => CachedFindingKind::CompilerAssert,
                    PanicEvidenceKind::PanicObligation { .. } => CachedFindingKind::PanicObligation,
                    PanicEvidenceKind::PanicSink { .. } => CachedFindingKind::PanicInvocation,
                    PanicEvidenceKind::IndirectBoundary { .. } => {
                        CachedFindingKind::IndirectCallBoundary
                    }
                },
                span: render_span(tcx, edge.span),
                source_span: cached_source_span(tcx, edge.span),
                diagnostic_spans: cached_primary_span(
                    tcx,
                    edge.span,
                    Some(cached_finding_span_label(&evidence.kind)),
                ),
                trace: evidence
                    .trace
                    .edge_ids
                    .iter()
                    .map(|edge_id| edge_id.index())
                    .collect(),
                reason: describe_panic_evidence_kind(tcx, &evidence.kind),
                target: Some(cached_finding_target(tcx, graph, edge.target)),
            }
        }
        PanicPathDecision::PanicObligation { edge_id, def_id } => {
            let trusted = super::is_trusted_panic_obligation(tcx, def_id, config);
            let (span, source_span, mut diagnostic_spans, target) = edge_id.map_or_else(
                || {
                    let span = tcx.def_span(def_id);
                    (
                        render_span(tcx, span),
                        cached_source_span(tcx, span),
                        cached_primary_span(tcx, span, Some("documented # Panics behavior")),
                        CachedFindingTarget::Function {
                            path: canonical_namespace(tcx, def_id),
                            crate_name: tcx.crate_name(def_id.krate).to_string(),
                            is_local: def_id.is_local(),
                        },
                    )
                },
                |edge_id| {
                    let edge = graph.edge(edge_id);
                    (
                        render_span(tcx, edge.span),
                        cached_source_span(tcx, edge.span),
                        cached_primary_span(
                            tcx,
                            edge.span,
                            Some("call reaches documented panic behavior"),
                        ),
                        cached_finding_target(tcx, graph, edge.target),
                    )
                },
            );
            if edge_id.is_some()
                && let Some(span) = cached_diagnostic_span(
                    tcx,
                    tcx.def_span(def_id),
                    false,
                    Some("documented # Panics behavior"),
                )
            {
                diagnostic_spans.push(span);
            }
            CachedFinding {
                kind: if trusted {
                    CachedFindingKind::TrustedPanicObligation
                } else {
                    CachedFindingKind::PanicObligation
                },
                span,
                source_span,
                diagnostic_spans,
                trace: trace_edges_until(evidence, edge_id)
                    .iter()
                    .map(|edge_id| edge_id.index())
                    .collect(),
                reason: format!(
                    "{} documents when it may panic under # Panics",
                    canonical_namespace(tcx, def_id)
                ),
                target: Some(target),
            }
        }
    }
}

fn cached_crate_boundary_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    config: &PanicConfig,
) -> Vec<CachedFinding> {
    view.edges()
        .filter_map(|edge| {
            // The origin skips macro-expansion bridge nodes, so calls made
            // through macros still attribute to the calling instance.
            let source = edge.origin().instance()?.def_id();
            let target = edge.target().instance()?.def_id();
            if !source.is_local() || target.is_local() {
                return None;
            }
            let target_path = canonical_namespace(tcx, target);
            if config.ignores_def(tcx, target) {
                return None;
            }

            Some(CachedFinding {
                kind: CachedFindingKind::CrateBoundary,
                span: render_span(tcx, edge.span()),
                source_span: cached_source_span(tcx, edge.span()),
                diagnostic_spans: cached_primary_span(
                    tcx,
                    edge.span(),
                    Some("crate boundary call"),
                ),
                trace: trace_to_edge_ids(edge)
                    .iter()
                    .map(|edge_id| edge_id.index())
                    .collect(),
                reason: format!("crate boundary {} to {}", edge.kind(), target_path),
                target: Some(CachedFindingTarget::Function {
                    path: target_path,
                    crate_name: tcx.crate_name(target.krate).to_string(),
                    is_local: false,
                }),
            })
        })
        .collect()
}

fn cached_finding_target<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    node: reachability::ReachabilityNodeId,
) -> CachedFindingTarget {
    match &graph.node(node).kind {
        ReachabilityNodeKind::Instance(instance) => CachedFindingTarget::Function {
            path: canonical_namespace(tcx, instance.def_id()),
            crate_name: tcx.crate_name(instance.def_id().krate).to_string(),
            is_local: instance.def_id().is_local(),
        },
        kind => CachedFindingTarget::Node {
            label: render_node(tcx, kind),
        },
    }
}

fn cached_trace_arena<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    result: &ReachabilitySnapshot<'tcx>,
    findings: &mut [CachedFinding],
) -> CachedTraceArena {
    let referenced_edges = findings
        .iter()
        .flat_map(|finding| finding.trace.iter().copied())
        .collect::<BTreeSet<_>>();
    let mut node_indices = BTreeMap::new();
    let mut frame_indices = BTreeMap::new();
    let mut nodes = Vec::new();
    let mut frames = Vec::new();

    for edge in graph
        .view(result)
        .edges()
        .filter(|edge| referenced_edges.contains(&edge.id().index()))
    {
        let from = cached_trace_node_index(
            tcx,
            edge.source().id().index(),
            edge.source().kind(),
            &mut node_indices,
            &mut nodes,
        );
        let to = cached_trace_node_index(
            tcx,
            edge.target().id().index(),
            edge.target().kind(),
            &mut node_indices,
            &mut nodes,
        );
        frame_indices.insert(edge.id().index(), frames.len());
        frames.push(CachedTraceFrame {
            from,
            to,
            kind: cached_trace_frame_kind(edge.kind()),
            span: render_span(tcx, edge.span()),
            source_span: cached_source_span(tcx, edge.span()),
        });
    }

    for finding in findings {
        finding.trace = finding
            .trace
            .iter()
            .map(|edge| {
                *frame_indices
                    .get(edge)
                    .expect("finding trace edge must belong to its reachability snapshot")
            })
            .collect();
    }

    CachedTraceArena { nodes, frames }
}

fn cached_source_span(tcx: TyCtxt<'_>, span: rustc_span::Span) -> Option<CachedSourceSpan> {
    if span.is_dummy() {
        return None;
    }

    let source_map = tcx.sess.source_map();
    let start = source_map.lookup_char_pos(span.lo());
    let end = source_map.lookup_char_pos(span.hi());
    Some(CachedSourceSpan {
        file: start.file.name.prefer_local_unconditionally().to_string(),
        line_start: start.line,
        column_start: start.col.to_usize() + 1,
        line_end: end.line,
        column_end: end.col.to_usize() + 1,
    })
}

fn cached_primary_span(
    tcx: TyCtxt<'_>,
    span: rustc_span::Span,
    label: Option<&str>,
) -> Vec<CachedDiagnosticSpan> {
    cached_diagnostic_span(tcx, span, true, label)
        .into_iter()
        .collect()
}

fn cached_diagnostic_span(
    tcx: TyCtxt<'_>,
    span: rustc_span::Span,
    is_primary: bool,
    label: Option<&str>,
) -> Option<CachedDiagnosticSpan> {
    Some(CachedDiagnosticSpan {
        span: cached_source_span(tcx, span)?,
        is_primary,
        label: label.map(str::to_owned),
    })
}

fn cached_finding_span_label(kind: &PanicEvidenceKind) -> &'static str {
    match kind {
        PanicEvidenceKind::CompilerAssert => "compiler assertion",
        PanicEvidenceKind::PanicObligation { .. } => "documented panic",
        PanicEvidenceKind::PanicSink { .. } => "panic sink",
        PanicEvidenceKind::IndirectBoundary { .. } => "indirect call boundary",
    }
}

fn cached_trace_node_index<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph_index: usize,
    kind: &ReachabilityNodeKind<'tcx>,
    indices: &mut BTreeMap<usize, usize>,
    nodes: &mut Vec<CachedTraceNode>,
) -> usize {
    if let Some(index) = indices.get(&graph_index) {
        return *index;
    }

    let index = nodes.len();
    nodes.push(cached_trace_node(tcx, kind));
    indices.insert(graph_index, index);
    index
}

fn cached_trace_node<'tcx>(
    tcx: TyCtxt<'tcx>,
    node: &ReachabilityNodeKind<'tcx>,
) -> CachedTraceNode {
    match node {
        ReachabilityNodeKind::Instance(instance) => CachedTraceNode::Function {
            path: canonical_namespace(tcx, instance.def_id()),
        },
        ReachabilityNodeKind::CompilerAssert { message, locals } => {
            CachedTraceNode::CompilerAssert {
                message: render_assert_message(message, locals),
            }
        }
        ReachabilityNodeKind::MacroExpansion { def_id } => CachedTraceNode::Macro {
            path: canonical_namespace(tcx, *def_id),
        },
        ReachabilityNodeKind::IndirectCall { callee_ty } => CachedTraceNode::IndirectCall {
            callee_ty: format!("{callee_ty:?}"),
        },
        ReachabilityNodeKind::DynObjectCast {
            source_ty,
            target_ty,
        } => CachedTraceNode::DynObjectCast {
            source_ty: format!("{source_ty:?}"),
            target_ty: format!("{target_ty:?}"),
        },
    }
}

fn cached_trace_frame_kind(kind: ReachabilityEdgeKind) -> CachedTraceFrameKind {
    match kind {
        ReachabilityEdgeKind::DirectCall => CachedTraceFrameKind::DirectCall,
        ReachabilityEdgeKind::TailCall => CachedTraceFrameKind::TailCall,
        ReachabilityEdgeKind::FnPointerReify => CachedTraceFrameKind::FnPointerReify,
        ReachabilityEdgeKind::ClosureFnPointerReify => CachedTraceFrameKind::ClosureFnPointerReify,
        ReachabilityEdgeKind::ClosureDefinition => CachedTraceFrameKind::ClosureDefinition,
        ReachabilityEdgeKind::FnPointerCallTarget => CachedTraceFrameKind::FnPointerCallTarget,
        ReachabilityEdgeKind::DynObjectCast => CachedTraceFrameKind::DynObjectCast,
        ReachabilityEdgeKind::VTableEntry => CachedTraceFrameKind::VTableEntry,
        ReachabilityEdgeKind::DynDispatchVTableEntry => {
            CachedTraceFrameKind::DynDispatchVTableEntry
        }
        ReachabilityEdgeKind::MacroExpansion => CachedTraceFrameKind::MacroExpansion,
        ReachabilityEdgeKind::ConstBody => CachedTraceFrameKind::ConstBody,
        ReachabilityEdgeKind::Assert => CachedTraceFrameKind::Assert,
        ReachabilityEdgeKind::IndirectCall => CachedTraceFrameKind::IndirectCall,
    }
}
