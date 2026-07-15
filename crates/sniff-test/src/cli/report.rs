//! Panic report rendering.
use crate::cache::CachedFunctionSummary;
use crate::config::{LintLevel, PanicLintConfig};
use crate::namespace::canonical_namespace;
use crate::panics::{
    AmbiguousPanicMarker, AmbiguousPanicRequirementName, PanicEvidence, PanicEvidenceKind,
    trace_edges_until, trigger_edge_id,
};
use crate::report_roots::ReportRootFindingKind;
use crate::safety::SafetyFindingKind;
use reachability::{
    CompilerAssertLocal, CompilerAssertLocalRole, ReachabilityEdge, ReachabilityEdgeId,
    ReachabilityGraph, ReachabilityNodeKind,
};
use rustc_hir::def_id::DefId;
use rustc_middle::mir::{AssertKind, BinOp, Operand, Place};
use rustc_middle::ty::TyCtxt;
use serde::Serialize;

#[derive(Debug, Clone)]
pub(crate) struct PanicRootReport {
    pub(crate) root: String,
    pub(crate) root_kind: PanicRootKind,
    pub(crate) findings: Vec<FindingReport>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PanicObligationReport {
    pub(crate) obligation_edge_id: Option<ReachabilityEdgeId>,
    pub(crate) documented_def_id: DefId,
    pub(crate) kind: FindingKind,
    pub(crate) level: LintLevel,
}

impl PanicRootReport {
    pub(crate) fn new(root: String, root_kind: PanicRootKind) -> Self {
        Self {
            root,
            root_kind,
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
        let kind = FindingKind::from_evidence(&evidence.kind);
        let (reason, target) = report_evidence_kind(tcx, graph, evidence);
        self.push_finding(FindingReport {
            kind,
            level,
            root: None,
            root_kind: None,
            function: None,
            target,
            span: Some(render_span(tcx, trigger_edge.span)),
            reason,
            trace: render_trace(tcx, graph, &evidence.trace.edge_ids),
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
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
        let span = obligation.obligation_edge_id.map_or_else(
            || render_span(tcx, tcx.def_span(obligation.documented_def_id)),
            |edge_id| {
                let edge = graph.edge(edge_id);
                render_span(tcx, edge.span)
            },
        );
        self.push_finding(FindingReport {
            kind: obligation.kind,
            level: obligation.level,
            root: None,
            root_kind: None,
            function: None,
            target: Some(documented.clone()),
            span: Some(span),
            reason: documented_panic_reason(&documented),
            trace: render_trace(
                tcx,
                graph,
                &trace_edges_until(evidence, obligation.obligation_edge_id),
            ),
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
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
        self.push_finding(FindingReport {
            kind: FindingKind::CachedDependencyPanic,
            level,
            root: None,
            root_kind: None,
            function: None,
            target: Some(summary.path.clone()),
            span: Some(render_span(tcx, edge.span)),
            reason: cached_dependency_panic_reason(summary),
            trace: vec![render_edge(tcx, graph, edge_id)],
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
        });
    }

    pub(crate) fn push_cached_dependency_obligation<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        edge_id: ReachabilityEdgeId,
        summary: &CachedFunctionSummary,
        kind: FindingKind,
        level: LintLevel,
    ) {
        let edge = graph.edge(edge_id);
        self.push_finding(FindingReport {
            kind,
            level,
            root: None,
            root_kind: None,
            function: None,
            target: Some(summary.path.clone()),
            span: Some(render_span(tcx, edge.span)),
            reason: cached_dependency_contract_reason(summary, kind),
            trace: vec![render_edge(tcx, graph, edge_id)],
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
        });
    }

    pub(crate) fn push_analysis_incomplete(
        &mut self,
        tcx: TyCtxt<'_>,
        root_def_id: rustc_hir::def_id::DefId,
        node_limit: usize,
        level: LintLevel,
    ) {
        self.push_finding(FindingReport {
            kind: FindingKind::AnalysisIncomplete,
            level,
            root: None,
            root_kind: None,
            function: None,
            target: None,
            span: Some(render_span(tcx, tcx.def_span(root_def_id))),
            reason: format!(
                "reachability analysis halted at the {node_limit}-instance node limit \
                 before the call graph was exhausted"
            ),
            trace: Vec::new(),
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
        });
    }

    pub(crate) fn push_ambiguous_obligation_marker<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        marker: &AmbiguousPanicMarker,
        level: LintLevel,
    ) {
        self.push_finding(FindingReport {
            kind: FindingKind::AmbiguousPanicMarker,
            level,
            root: None,
            root_kind: None,
            function: None,
            target: None,
            span: Some(render_span(tcx, marker.marker_span)),
            reason: format!(
                "one `// PANIC:` marker applies to {} panic obligation sites",
                marker.edge_ids.len()
            ),
            trace: render_trace(tcx, graph, &marker.edge_ids),
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
        });
    }

    pub(crate) fn push_ambiguous_obligation_name(
        &mut self,
        tcx: TyCtxt<'_>,
        name: &AmbiguousPanicRequirementName,
        level: LintLevel,
    ) {
        let target = canonical_namespace(tcx, name.def_id);
        let span = name
            .requirements
            .first()
            .map_or_else(|| tcx.def_span(name.def_id), |requirement| requirement.span);
        self.push_finding(FindingReport {
            kind: FindingKind::AmbiguousPanicRequirement,
            level,
            root: None,
            root_kind: None,
            function: None,
            target: Some(target.clone()),
            span: Some(render_span(tcx, span)),
            reason: format!(
                "`{target}` has {} # Panics requirements named `{}`",
                name.requirements.len(),
                name.normalized_name
            ),
            trace: Vec::new(),
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
        });
    }

    fn push_finding(&mut self, mut finding: FindingReport) {
        finding.root = Some(self.root.clone());
        finding.root_kind = Some(self.root_kind);
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
pub(crate) struct FindingReport {
    pub(crate) kind: FindingKind,
    pub(crate) level: LintLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) root_kind: Option<PanicRootKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) span: Option<String>,
    pub(crate) reason: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) trace: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) missing_requirements: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) requirements: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FindingKind {
    CompilerAssert,
    PanicInvocation,
    CachedDependencyPanic,
    DocumentedPanic,
    TrustedPanic,
    IndirectCallBoundary,
    AmbiguousPanicMarker,
    AmbiguousPanicRequirement,
    AnalysisIncomplete,
    EmptyReportRoots,
    MissingReportRoot,
    IgnoredReportRoot,
    MissingSafetyDocs,
    UnsafeCallMissingJustification,
    UnsafeCallMissingRequirements,
    UnsafeOpMissingJustification,
    SafetyObligationMissingJustification,
    SafetyObligationMissingRequirements,
    AmbiguousSafetyRequirement,
}

impl FindingKind {
    pub(crate) fn from_evidence(kind: &PanicEvidenceKind) -> Self {
        match kind {
            PanicEvidenceKind::CompilerAssert => Self::CompilerAssert,
            PanicEvidenceKind::PanicObligation { .. } => Self::DocumentedPanic,
            PanicEvidenceKind::PanicSink { .. } => Self::PanicInvocation,
            PanicEvidenceKind::IndirectBoundary { .. } => Self::IndirectCallBoundary,
        }
    }

    pub(crate) fn lint_level(self, lints: PanicLintConfig) -> LintLevel {
        match self {
            Self::CompilerAssert => lints.compiler_assert,
            Self::PanicInvocation => lints.panic_invocation,
            Self::CachedDependencyPanic => lints.cached_dependency_panic,
            Self::DocumentedPanic => lints.documented_panic,
            Self::TrustedPanic => lints.trusted_panic,
            Self::IndirectCallBoundary => lints.indirect_call_boundary,
            Self::AmbiguousPanicMarker => {
                unreachable!("ambiguous marker level comes from `[analysis]` policy")
            }
            Self::AmbiguousPanicRequirement => {
                unreachable!("ambiguous obligation-name level comes from `[analysis]` policy")
            }
            Self::AnalysisIncomplete => {
                unreachable!("analysis-incomplete level comes from `[analysis.lints]`")
            }
            Self::EmptyReportRoots
            | Self::MissingReportRoot
            | Self::IgnoredReportRoot
            | Self::MissingSafetyDocs
            | Self::UnsafeCallMissingJustification
            | Self::UnsafeCallMissingRequirements
            | Self::UnsafeOpMissingJustification
            | Self::SafetyObligationMissingJustification
            | Self::SafetyObligationMissingRequirements
            | Self::AmbiguousSafetyRequirement => {
                unreachable!("non-panic finding level comes from its own policy")
            }
        }
    }
}

impl From<ReportRootFindingKind> for FindingKind {
    fn from(kind: ReportRootFindingKind) -> Self {
        match kind {
            ReportRootFindingKind::EmptyReportRoots => Self::EmptyReportRoots,
            ReportRootFindingKind::MissingReportRoot => Self::MissingReportRoot,
            ReportRootFindingKind::IgnoredReportRoot => Self::IgnoredReportRoot,
        }
    }
}

impl From<SafetyFindingKind> for FindingKind {
    fn from(kind: SafetyFindingKind) -> Self {
        match kind {
            SafetyFindingKind::MissingSafetyDocs => Self::MissingSafetyDocs,
            SafetyFindingKind::UnsafeCallMissingJustification => {
                Self::UnsafeCallMissingJustification
            }
            SafetyFindingKind::UnsafeCallMissingRequirements => Self::UnsafeCallMissingRequirements,
            SafetyFindingKind::UnsafeOpMissingJustification => Self::UnsafeOpMissingJustification,
            SafetyFindingKind::SafetyObligationMissingJustification => {
                Self::SafetyObligationMissingJustification
            }
            SafetyFindingKind::SafetyObligationMissingRequirements => {
                Self::SafetyObligationMissingRequirements
            }
            SafetyFindingKind::AmbiguousSafetyRequirement => Self::AmbiguousSafetyRequirement,
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
            (documented_panic_reason(&target), Some(target))
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
            "documented panic",
            "documented panics",
        ),
        (
            summary.trusted_panic_obligations,
            "trusted panic",
            "trusted panics",
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

fn documented_panic_reason(path: &str) -> String {
    format!("{path} documents when it may panic under # Panics")
}

fn cached_dependency_contract_reason(summary: &CachedFunctionSummary, kind: FindingKind) -> String {
    let panic_kind = match kind {
        FindingKind::TrustedPanic => "trusted panic",
        _ => "documented panic",
    };
    format!("{} has cached {panic_kind} evidence", summary.path)
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
