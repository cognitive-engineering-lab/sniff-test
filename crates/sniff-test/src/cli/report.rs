//! Panic report rendering.
use crate::cache::CachedFunctionSummary;
use crate::config::{LintLevel, PanicLintConfig};
use crate::namespace::canonical_namespace;
use crate::panics::{PanicEvidence, PanicEvidenceKind, trace_edges_until, trigger_edge_id};
use reachability::{
    CompilerAssertLocal, CompilerAssertLocalRole, ReachabilityEdge, ReachabilityEdgeId,
    ReachabilityGraph, ReachabilityNodeKind,
};
use rustc_hir::def_id::DefId;
use rustc_middle::mir::{AssertKind, BinOp, Operand, Place};
use rustc_middle::ty::TyCtxt;
use rustc_span::Pos;
use serde::Serialize;

use super::PanicFindingCounts;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct PanicRootReport {
    pub(crate) root: String,
    pub(crate) root_kind: PanicRootKind,
    pub(crate) root_declaration: Option<String>,
    pub(crate) has_panic_docs: bool,
    pub(crate) counts: PanicFindingCounts,
    pub(crate) findings: Vec<PanicFindingReport>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PanicObligationReport {
    pub(crate) obligation_edge_id: Option<ReachabilityEdgeId>,
    pub(crate) documented_def_id: DefId,
    pub(crate) kind: ReportDetailKind,
    pub(crate) level: LintLevel,
}

impl PanicRootReport {
    pub(crate) fn new(
        root: String,
        root_kind: PanicRootKind,
        root_declaration: Option<String>,
        has_panic_docs: bool,
    ) -> Self {
        Self {
            root,
            root_kind,
            root_declaration,
            has_panic_docs,
            counts: PanicFindingCounts::default(),
            findings: Vec::new(),
        }
    }

    pub(crate) fn push_panic_evidence<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        evidence: &PanicEvidence,
        level: LintLevel,
    ) {
        let trigger_edge_id = trigger_edge_id(graph, evidence);
        let trigger_edge = graph.edge(trigger_edge_id);
        let kind = ReportDetailKind::from_evidence(&evidence.kind);
        let (reason, target) = report_evidence_kind(tcx, graph, evidence);
        self.push_finding(PanicFindingReport {
            kind,
            level,
            span: render_span(tcx, trigger_edge.span),
            edge: Some(render_edge_without_span(tcx, graph, trigger_edge)),
            reason,
            target,
            trace: render_trace(tcx, graph, &evidence.trace.edge_ids),
        });
    }

    pub(crate) fn push_panic_obligation<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        evidence: &PanicEvidence,
        obligation: PanicObligationReport,
    ) {
        let documented = canonical_namespace(tcx, obligation.documented_def_id);
        let (span, edge) = obligation.obligation_edge_id.map_or_else(
            || {
                (
                    render_span(tcx, tcx.def_span(obligation.documented_def_id)),
                    Some(String::from("report root documents panic behavior")),
                )
            },
            |edge_id| {
                let edge = graph.edge(edge_id);
                (
                    render_span(tcx, edge.span),
                    Some(render_edge_without_span(tcx, graph, edge)),
                )
            },
        );
        self.push_finding(PanicFindingReport {
            kind: obligation.kind,
            level: obligation.level,
            span,
            edge,
            reason: documented_panic_contract_reason(&documented),
            target: Some(documented),
            trace: render_trace(
                tcx,
                graph,
                &trace_edges_until(evidence, obligation.obligation_edge_id),
            ),
        });
    }

    pub(crate) fn push_cached_dependency_panic<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        edge_id: ReachabilityEdgeId,
        summary: &CachedFunctionSummary,
        level: LintLevel,
    ) {
        let edge = graph.edge(edge_id);
        self.push_finding(PanicFindingReport {
            kind: ReportDetailKind::CachedDependencyPanic,
            level,
            span: render_span(tcx, edge.span),
            edge: Some(render_edge_without_span(tcx, graph, edge)),
            reason: cached_dependency_panic_reason(summary),
            target: Some(summary.path.clone()),
            trace: vec![render_edge(tcx, graph, edge_id)],
        });
    }

    pub(crate) fn push_cached_dependency_obligation<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        edge_id: ReachabilityEdgeId,
        summary: &CachedFunctionSummary,
        kind: ReportDetailKind,
        level: LintLevel,
    ) {
        let edge = graph.edge(edge_id);
        self.push_finding(PanicFindingReport {
            kind,
            level,
            span: render_span(tcx, edge.span),
            edge: Some(render_edge_without_span(tcx, graph, edge)),
            reason: cached_dependency_contract_reason(summary, kind),
            target: Some(summary.path.clone()),
            trace: vec![render_edge(tcx, graph, edge_id)],
        });
    }

    pub(crate) fn push_analysis_incomplete(
        &mut self,
        tcx: TyCtxt<'_>,
        root_def_id: rustc_hir::def_id::DefId,
        node_limit: usize,
        level: LintLevel,
    ) {
        self.push_finding(PanicFindingReport {
            kind: ReportDetailKind::AnalysisIncomplete,
            level,
            span: render_span(tcx, tcx.def_span(root_def_id)),
            edge: None,
            reason: format!(
                "reachability analysis halted at the {node_limit}-instance node limit \
                 before the call graph was exhausted"
            ),
            target: None,
            trace: Vec::new(),
        });
    }

    fn push_finding(&mut self, finding: PanicFindingReport) {
        self.counts.increment(finding.kind);
        self.findings.push(finding);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PanicRootKind {
    Concrete,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct PanicFindingReport {
    pub(crate) kind: ReportDetailKind,
    pub(crate) level: LintLevel,
    pub(crate) span: String,
    pub(crate) edge: Option<String>,
    pub(crate) reason: String,
    pub(crate) target: Option<String>,
    pub(crate) trace: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ReportDetailKind {
    CompilerAssert,
    PanicInvocation,
    CachedDependencyPanic,
    PanicObligation,
    TrustedPanicObligation,
    IndirectCallBoundary,
    AnalysisIncomplete,
}

impl ReportDetailKind {
    pub(crate) fn from_evidence(kind: &PanicEvidenceKind) -> Self {
        match kind {
            PanicEvidenceKind::CompilerAssert => Self::CompilerAssert,
            PanicEvidenceKind::PanicObligation { .. } => Self::PanicObligation,
            PanicEvidenceKind::PanicSink { .. } => Self::PanicInvocation,
            PanicEvidenceKind::IndirectBoundary { .. } => Self::IndirectCallBoundary,
        }
    }

    pub(crate) fn lint_level(self, lints: PanicLintConfig) -> LintLevel {
        match self {
            Self::CompilerAssert | Self::PanicInvocation | Self::CachedDependencyPanic => {
                lints.undocumented_panic_path
            }
            Self::PanicObligation => lints.documented_panic_contract,
            Self::TrustedPanicObligation => lints.trusted_panic_contract,
            Self::IndirectCallBoundary => lints.indirect_call_boundary,
            Self::AnalysisIncomplete => lints.analysis_incomplete,
        }
    }
}

fn count_text(count: usize, singular: &str, plural: &str) -> String {
    let label = if count == 1 { singular } else { plural };
    format!("{count} {label}")
}

pub(crate) fn render_trace<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_ids: &[ReachabilityEdgeId],
) -> Vec<String> {
    edge_ids
        .iter()
        .map(|edge_id| render_edge(tcx, graph, *edge_id))
        .collect()
}

fn report_evidence_kind<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
) -> (String, Option<String>) {
    match &evidence.kind {
        PanicEvidenceKind::CompilerAssert => {
            let target = render_node(tcx, &graph.node(graph.edge(evidence.edge_id).target).kind);
            (String::from("compiler assert"), Some(target))
        }
        PanicEvidenceKind::PanicObligation { def_id } => {
            let target = canonical_namespace(tcx, *def_id);
            (documented_panic_contract_reason(&target), Some(target))
        }
        PanicEvidenceKind::PanicSink { def_id } => {
            let target = canonical_namespace(tcx, *def_id);
            (format!("panic sink {target}"), Some(target))
        }
        PanicEvidenceKind::IndirectBoundary {
            def_id: Some(def_id),
        } => {
            let target = canonical_namespace(tcx, *def_id);
            (
                format!("indirect call to undocumented trait method {target} cannot be verified"),
                Some(target),
            )
        }
        PanicEvidenceKind::IndirectBoundary { def_id: None } => (
            String::from("indirect call through an opaque callable cannot be verified"),
            None,
        ),
    }
}

pub(crate) fn cached_dependency_panic_reason(summary: &CachedFunctionSummary) -> String {
    let mut reason = format!("{} has cached panic evidence: ", summary.path);
    let mut has_count = false;

    for (count, singular, plural) in [
        (
            summary.raw_panic_paths,
            "undocumented panic path",
            "undocumented panic paths",
        ),
        (
            summary.panic_obligations,
            "documented panic contract",
            "documented panic contracts",
        ),
        (
            summary.trusted_panic_obligations,
            "trusted panic contract",
            "trusted panic contracts",
        ),
    ] {
        if count == 0 {
            continue;
        }
        if has_count {
            reason.push_str(", ");
        }
        reason.push_str(&count_text(count, singular, plural));
        has_count = true;
    }

    if !has_count {
        reason.push_str("0 undocumented panic paths");
    }

    reason
}

fn documented_panic_contract_reason(path: &str) -> String {
    format!("{path} has a documented # Panics contract")
}

fn cached_dependency_contract_reason(
    summary: &CachedFunctionSummary,
    kind: ReportDetailKind,
) -> String {
    let contract = match kind {
        ReportDetailKind::TrustedPanicObligation => "trusted panic contract",
        _ => "documented panic contract",
    };
    format!("{} has cached {contract} evidence", summary.path)
}

pub(crate) fn render_edge<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_id: ReachabilityEdgeId,
) -> String {
    let edge = graph.edge(edge_id);
    format!(
        "{}: {}",
        render_span(tcx, edge.span),
        render_edge_without_span(tcx, graph, edge)
    )
}

pub(crate) fn render_edge_without_span<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge: &ReachabilityEdge,
) -> String {
    format!(
        "{} --{}-> {}",
        render_node(tcx, &graph.node(edge.source).kind),
        edge.kind,
        render_node(tcx, &graph.node(edge.target).kind)
    )
}

pub(crate) fn render_node<'tcx>(tcx: TyCtxt<'tcx>, node: &ReachabilityNodeKind<'tcx>) -> String {
    match node {
        ReachabilityNodeKind::Instance(instance) => canonical_namespace(tcx, instance.def_id()),
        ReachabilityNodeKind::CompilerAssert { message, locals } => {
            format!("compiler assert {}", render_assert_message(message, locals))
        }
        ReachabilityNodeKind::MacroExpansion { def_id } => {
            format!("macro {}", canonical_namespace(tcx, *def_id))
        }
        ReachabilityNodeKind::IndirectCall { callee_ty } => format!("indirect call {callee_ty:?}"),
        ReachabilityNodeKind::DynObjectCast {
            source_ty,
            target_ty,
        } => format!("dyn object cast {source_ty:?} as {target_ty:?}"),
    }
}

pub(crate) fn render_assert_message(
    message: &rustc_middle::mir::AssertMessage<'_>,
    locals: &[CompilerAssertLocal],
) -> String {
    match message {
        AssertKind::BoundsCheck { len, index } => format!(
            "index out of bounds: index {} may exceed length {}",
            render_assert_operand(index, locals),
            render_assert_operand(len, locals)
        ),
        AssertKind::Overflow(operation, left, right) => {
            render_overflow_assert(*operation, left, right, locals)
        }
        AssertKind::OverflowNeg(operand) => format!(
            "attempt to negate {} with overflow",
            render_assert_operand(operand, locals)
        ),
        AssertKind::DivisionByZero(operand) => format!(
            "attempt to divide {} by zero",
            render_assert_operand(operand, locals)
        ),
        AssertKind::RemainderByZero(operand) => format!(
            "attempt to calculate the remainder of {} with a zero divisor",
            render_assert_operand(operand, locals)
        ),
        AssertKind::ResumedAfterReturn(kind) => format!("resumed {kind:?} after completion"),
        AssertKind::ResumedAfterPanic(kind) => format!("resumed {kind:?} after panicking"),
        AssertKind::ResumedAfterDrop(kind) => format!("resumed {kind:?} after async drop"),
        AssertKind::MisalignedPointerDereference { required, found } => format!(
            "misaligned pointer dereference: required alignment {}, found address {}",
            render_assert_operand(required, locals),
            render_assert_operand(found, locals)
        ),
        AssertKind::NullPointerDereference => String::from("null pointer dereference"),
        AssertKind::InvalidEnumConstruction(operand) => format!(
            "invalid enum construction from {}",
            render_assert_operand(operand, locals)
        ),
    }
}

fn render_overflow_assert<'tcx>(
    operation: BinOp,
    left: &Operand<'tcx>,
    right: &Operand<'tcx>,
    locals: &[CompilerAssertLocal],
) -> String {
    let left = render_assert_operand(left, locals);
    let right = render_assert_operand(right, locals);
    match operation {
        BinOp::Add => format!("attempt to compute {left} + {right} with overflow"),
        BinOp::Sub => format!("attempt to compute {left} - {right} with overflow"),
        BinOp::Mul => format!("attempt to compute {left} * {right} with overflow"),
        BinOp::Div => format!("attempt to compute {left} / {right} with overflow"),
        BinOp::Rem => format!("attempt to compute {left} % {right} with overflow"),
        BinOp::Shl => format!("attempt to shift left by {right} with overflow"),
        BinOp::Shr => format!("attempt to shift right by {right} with overflow"),
        other => format!("overflow in {other:?} with operands {left}, {right}"),
    }
}

fn render_assert_operand(operand: &Operand<'_>, locals: &[CompilerAssertLocal]) -> String {
    match operand {
        Operand::Copy(place) | Operand::Move(place) => render_assert_place(*place, locals),
        Operand::Constant(constant) => constant.const_.to_string(),
        Operand::RuntimeChecks(checks) => format!("{checks:?}"),
    }
}

fn render_assert_place(place: Place<'_>, locals: &[CompilerAssertLocal]) -> String {
    let mir_name = format!("{:?}", place.local);
    let Some(local) = locals
        .iter()
        .find(|local| local.index == place.local.index())
    else {
        return format!("`{place:?}`");
    };

    let source_name = local.name.as_deref().unwrap_or(&mir_name);
    let label = if place.projection.is_empty() {
        source_name.to_owned()
    } else {
        format!("{source_name} ({place:?})")
    };
    let role = render_assert_local_role(local);
    if local.name.is_some() {
        format!("`{label}` ({mir_name}, {role})")
    } else {
        format!("`{label}` ({role})")
    }
}

fn render_assert_local_role(local: &CompilerAssertLocal) -> String {
    match local.role {
        CompilerAssertLocalRole::ReturnPointer => String::from("return place"),
        CompilerAssertLocalRole::Argument => format!("argument {}", local.index),
        CompilerAssertLocalRole::Temporary => String::from("temporary"),
    }
}

pub(crate) fn render_span(tcx: TyCtxt<'_>, span: rustc_span::Span) -> String {
    tcx.sess.source_map().span_to_diagnostic_string(span)
}

pub(crate) fn render_span_start(tcx: TyCtxt<'_>, span: rustc_span::Span) -> String {
    let location = tcx.sess.source_map().lookup_char_pos(span.lo());
    format!(
        "{}:{}:{}",
        location.file.name.prefer_local_unconditionally(),
        location.line,
        location.col.to_usize() + 1
    )
}
