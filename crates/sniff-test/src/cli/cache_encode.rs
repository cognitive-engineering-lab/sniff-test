use crate::cache::{CachedFindingInput, CachedFindingKind, CachedSourceSpan, CachedTraceInput};
use crate::config::PanicConfig;
use crate::namespace::canonical_namespace;
use crate::panics::{
    PanicAnalysis, PanicEvidence, PanicEvidenceKind, describe_panic_evidence_kind,
    panic_obligation_reason, trace_edges_until, trigger_edge_id,
};
use reachability::{ReachabilityEdgeId, ReachabilityGraph, ReachabilityView};
use rustc_middle::ty::TyCtxt;
use rustc_span::Pos;

use crate::EffectSite;
use crate::effect_tracker::EffectPathDecision;
use crate::safety::SafetyFinding;

use super::findings::{Finding, FindingKind};
use super::report::{render_span, render_trace};

pub(super) fn cached_safety_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    site: EffectSite,
    trace: &crate::effect_tracker::EffectTrace,
    safety_finding: &SafetyFinding,
    finding: &Finding,
) -> Option<CachedFindingInput> {
    let kind = match finding.kind {
        FindingKind::UnsafeCallMissingJustification => {
            CachedFindingKind::UnsafeCallMissingJustification
        }
        FindingKind::UnsafeCallMissingRequirements => {
            CachedFindingKind::UnsafeCallMissingRequirements
        }
        FindingKind::UnsafeOpMissingJustification => {
            CachedFindingKind::UnsafeOpMissingJustification
        }
        FindingKind::SafetyObligationMissingJustification => {
            CachedFindingKind::SafetyObligationMissingJustification
        }
        FindingKind::SafetyObligationMissingRequirements => {
            CachedFindingKind::SafetyObligationMissingRequirements
        }
        _ => return None,
    };
    let missing_requirements = match safety_finding {
        SafetyFinding::CallMissingRequirements {
            missing_requirements,
            ..
        } => missing_requirements.clone(),
        _ => Vec::new(),
    };
    Some(CachedFindingInput {
        kind,
        compiler_assert_kind: finding.compiler_assert_kind,
        safety_op_kind: finding.safety_op_kind,
        span: render_span(tcx, site.span),
        source_span: cached_source_span(tcx, site.span),
        trace: cached_trace(tcx, graph, &trace.edge_ids),
        reason: finding.reason.clone(),
        missing_requirements,
    })
}

pub(super) fn cached_panic_findings<'tcx>(
    tcx: TyCtxt<'tcx>,
    view: ReachabilityView<'_, 'tcx>,
    analysis: &PanicAnalysis,
    config: &PanicConfig,
) -> Vec<CachedFindingInput> {
    let graph = view.graph();
    analysis
        .evidence
        .iter()
        .map(|evidence| cached_panic_finding(tcx, graph, evidence, config))
        .collect()
}

fn cached_panic_finding<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    config: &PanicConfig,
) -> CachedFindingInput {
    match evidence.decision {
        EffectPathDecision::RawEffect => {
            let edge_id = trigger_edge_id(graph, evidence);
            let edge = graph.edge(edge_id);
            CachedFindingInput {
                kind: match &evidence.kind {
                    PanicEvidenceKind::CompilerAssert { .. } => CachedFindingKind::CompilerAssert,
                    PanicEvidenceKind::PanicObligation { .. } => CachedFindingKind::PanicObligation,
                    PanicEvidenceKind::PanicSink { .. } => CachedFindingKind::PanicInvocation,
                    PanicEvidenceKind::IndirectBoundary { .. } => {
                        CachedFindingKind::IndirectCallBoundary
                    }
                },
                compiler_assert_kind: match evidence.kind {
                    PanicEvidenceKind::CompilerAssert { kind } => Some(kind),
                    _ => None,
                },
                safety_op_kind: None,
                span: render_span(tcx, edge.span),
                source_span: cached_source_span(tcx, edge.span),
                trace: cached_trace(tcx, graph, &evidence.trace.edge_ids),
                reason: describe_panic_evidence_kind(tcx, &evidence.kind),
                missing_requirements: Vec::new(),
            }
        }
        EffectPathDecision::Obligation { edge_id, def_id } => {
            let trusted = crate::panics::is_trusted_panic_boundary(tcx, def_id, config);
            let (span, source_span) = edge_id.map_or_else(
                || {
                    let span = tcx.def_span(def_id);
                    (render_span(tcx, span), cached_source_span(tcx, span))
                },
                |edge_id| {
                    let edge = graph.edge(edge_id);
                    (
                        render_span(tcx, edge.span),
                        cached_source_span(tcx, edge.span),
                    )
                },
            );
            CachedFindingInput {
                kind: if trusted {
                    CachedFindingKind::TrustedPanicObligation
                } else {
                    CachedFindingKind::PanicObligation
                },
                compiler_assert_kind: None,
                safety_op_kind: None,
                span,
                source_span,
                trace: cached_trace(tcx, graph, &trace_edges_until(evidence, edge_id)),
                reason: panic_obligation_reason(&canonical_namespace(tcx, def_id)),
                missing_requirements: evidence.missing_requirements.clone(),
            }
        }
    }
}

pub(super) fn cached_trace<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_ids: &[ReachabilityEdgeId],
) -> CachedTraceInput {
    CachedTraceInput {
        steps: render_trace(tcx, graph, edge_ids),
        dependency_tail: None,
    }
}

pub(super) fn cached_source_span(
    tcx: TyCtxt<'_>,
    span: rustc_span::Span,
) -> Option<CachedSourceSpan> {
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
