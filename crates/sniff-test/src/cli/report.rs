//! JSON serialization and panic report rendering.
use crate::cache::{
    CachedArtifactInfo, CachedDependencyRef, CachedEffectSummary, CachedFinding,
    CachedFunctionSummary, CachedReachabilityEdgeKind, CachedReachabilityNodeKind,
};
use crate::contracts::EffectKind;
use crate::namespace::canonical_namespace;
use crate::panics::{
    AmbiguousPanicMarker, AmbiguousPanicRequirementName, PanicEvidence, PanicEvidenceKind,
    trace_edges_until, trigger_edge_id,
};
use crate::report_roots::ReportRootKind;
use reachability::{
    CompilerAssertLocal, CompilerAssertLocalRole, ReachabilityEdge, ReachabilityEdgeId,
    ReachabilityGraph, ReachabilityNodeKind,
};
use rustc_hir::def_id::DefId;
use rustc_middle::mir::{AssertKind, BinOp, Operand, Place};
use rustc_middle::ty::TyCtxt;
use serde::Serialize;

use super::diagnostics::{
    CachedDependencyContractDiagnostic, PanicContractDiagnostic,
    ambiguous_obligation_marker_diagnostic, ambiguous_obligation_name_diagnostic,
    analysis_incomplete_diagnostic, cached_dependency_contract_diagnostic,
    cached_dependency_raw_panic_diagnostic, indirect_boundary_diagnostic,
    panic_contract_diagnostic, raw_panic_diagnostic,
};
use super::findings::{Finding, FindingKind, ResolvedFinding};

pub(crate) const REPORT_FORMAT_VERSION: u32 = 8;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct AnalysisArtifactReport {
    pub(crate) reason: String,
    pub(crate) format_version: u32,
    pub(crate) tool_version: String,
    pub(crate) rustc_version: String,
    pub(crate) artifact: CachedArtifactInfo,
    pub(crate) scope: CrateOutputScope,
    pub(crate) dependencies: Vec<CachedDependencyRef>,
    pub(crate) findings: Vec<ResolvedFinding>,
}

impl AnalysisArtifactReport {
    pub(crate) fn has_denied_findings(&self) -> bool {
        self.findings.iter().any(|finding| finding.level.is_deny())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CrateOutputScope {
    Workspace,
    Dependency,
}

#[derive(Debug, Clone)]
pub(crate) struct PanicRootReport {
    pub(crate) root: String,
    pub(crate) root_kind: ReportRootKind,
    root_def_id: DefId,
    include_stack: bool,
    pub(crate) findings: Vec<Finding>,
}

impl PanicRootReport {
    pub(crate) fn new(
        root: String,
        root_kind: ReportRootKind,
        root_def_id: DefId,
        include_stack: bool,
    ) -> Self {
        Self {
            root,
            root_kind,
            root_def_id,
            include_stack,
            findings: Vec::new(),
        }
    }

    pub(crate) fn push_panic_evidence<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        evidence: &PanicEvidence,
    ) {
        let trigger_edge_id = trigger_edge_id(graph, evidence);
        let trigger_edge = graph.edge(trigger_edge_id);
        let kind = FindingKind::from_evidence(&evidence.kind);
        let (reason, target) = report_evidence_kind(tcx, graph, evidence);
        let diagnostic = if matches!(evidence.kind, PanicEvidenceKind::IndirectBoundary { .. }) {
            indirect_boundary_diagnostic(tcx, graph, evidence, self.root_def_id, self.include_stack)
        } else {
            raw_panic_diagnostic(tcx, graph, evidence, self.root_def_id, self.include_stack)
        };
        self.push_finding(Finding {
            target,
            span: Some(render_span(tcx, trigger_edge.span)),
            trace: render_trace(tcx, graph, &evidence.trace.edge_ids),
            ..Finding::new(kind, reason, diagnostic)
        });
    }

    pub(crate) fn push_panic_obligation<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        evidence: &PanicEvidence,
        obligation_edge_id: Option<ReachabilityEdgeId>,
        documented_def_id: DefId,
        kind: FindingKind,
    ) {
        let documented = canonical_namespace(tcx, documented_def_id);
        let span = obligation_edge_id.map_or_else(
            || render_span(tcx, tcx.def_span(documented_def_id)),
            |edge_id| {
                let edge = graph.edge(edge_id);
                render_span(tcx, edge.span)
            },
        );
        let diagnostic = panic_contract_diagnostic(
            tcx,
            graph,
            evidence,
            PanicContractDiagnostic {
                obligation_edge_id,
                documented_def_id,
                root_def_id: self.root_def_id,
                trusted: kind == FindingKind::TrustedPanic,
                include_stack: self.include_stack,
            },
        );
        self.push_finding(Finding {
            target: Some(documented.clone()),
            span: Some(span),
            trace: render_trace(tcx, graph, &trace_edges_until(evidence, obligation_edge_id)),
            missing_requirements: evidence
                .missing_requirements
                .iter()
                .map(crate::contracts::ContractRequirement::render)
                .collect(),
            ..Finding::new(kind, documented_panic_reason(&documented), diagnostic)
        });
    }

    pub(crate) fn push_cached_dependency_panic<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        edge_id: ReachabilityEdgeId,
        local_trace: &[ReachabilityEdgeId],
        summary: &CachedFunctionSummary,
        cached_finding: Option<&CachedFinding>,
    ) {
        let edge = graph.edge(edge_id);
        let diagnostic = cached_dependency_raw_panic_diagnostic(
            tcx,
            graph,
            edge_id,
            local_trace,
            summary,
            self.root_def_id,
            self.include_stack,
        );
        let mut trace = render_trace(tcx, graph, local_trace);
        if let Some(finding) = cached_finding {
            trace.extend(summary.render_effect_trace(EffectKind::Panic, finding));
        }
        self.push_finding(Finding {
            target: Some(summary.path.clone()),
            span: Some(render_span(tcx, edge.span)),
            effect_span: cached_finding.map(render_cached_effect_span),
            trace,
            ..Finding::new(
                FindingKind::CachedDependencyPanic,
                summary.panic_reason(),
                diagnostic,
            )
        });
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the report entry combines independent trace, cache, and policy inputs"
    )]
    pub(crate) fn push_cached_dependency_obligation<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        edge_id: ReachabilityEdgeId,
        local_trace: &[ReachabilityEdgeId],
        summary: &CachedFunctionSummary,
        cached_finding: Option<&CachedFinding>,
        kind: FindingKind,
    ) {
        let edge = graph.edge(edge_id);
        let diagnostic = cached_dependency_contract_diagnostic(
            tcx,
            graph,
            summary,
            local_trace,
            CachedDependencyContractDiagnostic {
                edge_id,
                root_def_id: self.root_def_id,
                trusted: kind == FindingKind::TrustedPanic,
                include_stack: self.include_stack,
            },
        );
        let mut trace = render_trace(tcx, graph, local_trace);
        if let Some(finding) = cached_finding {
            trace.extend(summary.render_effect_trace(EffectKind::Panic, finding));
        }
        self.push_finding(Finding {
            target: Some(summary.path.clone()),
            span: Some(render_span(tcx, edge.span)),
            effect_span: cached_finding.map(render_cached_effect_span),
            trace,
            missing_requirements: cached_finding
                .into_iter()
                .flat_map(|finding| finding.missing_requirements.iter())
                .map(crate::cache::CachedRequirement::render)
                .collect(),
            ..Finding::new(kind, summary.contract_reason(kind), diagnostic)
        });
    }

    pub(crate) fn push_ambiguous_obligation_marker<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        graph: &ReachabilityGraph<'tcx>,
        marker: &AmbiguousPanicMarker,
    ) {
        let diagnostic =
            ambiguous_obligation_marker_diagnostic(tcx, graph, marker, self.root_def_id);
        self.push_finding(Finding {
            span: Some(render_span(tcx, marker.marker_span)),
            trace: render_trace(tcx, graph, &marker.edge_ids),
            ..Finding::new(
                FindingKind::AmbiguousEffectMarker,
                format!(
                    "one `// PANIC:` marker applies to {} panic obligation sites",
                    marker.edge_ids.len()
                ),
                diagnostic,
            )
            .with_effect(crate::contracts::EffectKind::Panic)
        });
    }

    pub(crate) fn push_ambiguous_obligation_name(
        &mut self,
        tcx: TyCtxt<'_>,
        name: &AmbiguousPanicRequirementName,
    ) {
        let target = canonical_namespace(tcx, name.def_id);
        let span = name
            .requirements
            .first()
            .map_or_else(|| tcx.def_span(name.def_id), |requirement| requirement.span);
        let diagnostic = ambiguous_obligation_name_diagnostic(tcx, name, self.root_def_id);
        self.push_finding(Finding {
            target: Some(target.clone()),
            span: Some(render_span(tcx, span)),
            ..Finding::new(
                FindingKind::AmbiguousEffectRequirement,
                format!(
                    "`{target}` has {} # Panics requirements named `{}`",
                    name.requirements.len(),
                    name.normalized_name
                ),
                diagnostic,
            )
            .with_effect(crate::contracts::EffectKind::Panic)
        });
    }

    fn push_finding(&mut self, mut finding: Finding) {
        finding.root = Some(self.root.clone());
        finding.root_kind = Some(self.root_kind);
        self.findings.push(finding);
    }
}

pub(crate) fn analysis_incomplete_finding(
    tcx: TyCtxt<'_>,
    root_def_id: DefId,
    node_limit: usize,
    effect: EffectKind,
) -> Finding {
    Finding {
        span: Some(render_span(tcx, tcx.def_span(root_def_id))),
        ..Finding::new(
            FindingKind::AnalysisIncomplete,
            format!(
                "reachability analysis halted at the {node_limit}-instance node limit \
                 before the call graph was exhausted"
            ),
            analysis_incomplete_diagnostic(tcx, root_def_id, node_limit),
        )
        .with_effect(effect)
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

impl CachedFunctionSummary {
    pub(crate) fn panic_reason(&self) -> String {
        let mut reason = format!("{} has cached panic evidence: ", self.path);
        let mut has_count = false;
        let panic = self.effect(crate::contracts::EffectKind::Panic);

        for (count, singular, plural) in [
            (
                panic.map_or(0, CachedEffectSummary::raw_path_count),
                "undocumented panic path",
                "undocumented panic paths",
            ),
            (
                panic.map_or(0, CachedEffectSummary::panic_obligation_count),
                "documented panic",
                "documented panics",
            ),
            (
                panic.map_or(0, CachedEffectSummary::trusted_panic_obligation_count),
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

    fn contract_reason(&self, kind: FindingKind) -> String {
        let panic_kind = match kind {
            FindingKind::TrustedPanic => "trusted panic",
            _ => "documented panic",
        };
        format!("{} has cached {panic_kind} evidence", self.path)
    }

    pub(crate) fn render_effect_trace(
        &self,
        effect: crate::contracts::EffectKind,
        finding: &CachedFinding,
    ) -> Vec<String> {
        self.effect_trace(effect, finding)
            .into_iter()
            .map(|step| {
                format!(
                    "{}: {} --{}-> {}",
                    step.span,
                    step.source.render(),
                    step.kind.label(),
                    step.target.render(),
                )
            })
            .collect()
    }
}

fn documented_panic_reason(path: &str) -> String {
    format!("{path} documents when it may panic under # Panics")
}

impl CachedReachabilityNodeKind {
    fn render(&self) -> String {
        match self {
            Self::Instance { path, .. } => path.clone(),
            Self::CompilerAssert { message } => {
                format!("compiler assert {message}")
            }
            Self::MacroExpansion { path, .. } => format!("macro {path}"),
            Self::IndirectCall { callee_ty } => {
                format!("indirect call {callee_ty}")
            }
            Self::DynObjectCast {
                source_ty,
                target_ty,
            } => format!("dyn object cast {source_ty} as {target_ty}"),
        }
    }
}

impl CachedReachabilityEdgeKind {
    fn label(self) -> &'static str {
        match self {
            Self::DirectCall => "direct-call",
            Self::TailCall => "tail-call",
            Self::FnPointerReify => "fn-pointer-reify",
            Self::ClosureFnPointerReify => "closure-fn-pointer-reify",
            Self::ClosureDefinition => "closure-definition",
            Self::FnPointerCallTarget => "fn-pointer-call-target",
            Self::DynObjectCast => "dyn-object-cast",
            Self::VTableEntry => "vtable-entry",
            Self::DynDispatchVTableEntry => "dyn-dispatch-vtable-entry",
            Self::MacroExpansion => "macro-expansion",
            Self::ConstBody => "const-body",
            Self::Assert => "assert",
            Self::IndirectCall => "indirect-call",
        }
    }
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

pub(crate) fn render_cached_effect_span(finding: &CachedFinding) -> String {
    finding.source_span.as_ref().map_or_else(
        || finding.span.clone(),
        |span| {
            format!(
                "{}:{}:{}: {}:{}",
                span.file, span.line_start, span.column_start, span.line_end, span.column_end
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{AnalysisArtifactReport, CrateOutputScope, REPORT_FORMAT_VERSION};
    use crate::cache::CachedArtifactInfo;
    use crate::cli::findings::{Finding, FindingDiagnostic, FindingKind, ResolvedFinding};
    use crate::config::LintLevel;

    #[test]
    fn public_report_serializes_flat_findings() {
        let report = AnalysisArtifactReport {
            reason: String::from("sniff-test-artifact"),
            format_version: REPORT_FORMAT_VERSION,
            tool_version: String::from("0.1.0"),
            rustc_version: String::from("rustc test"),
            artifact: CachedArtifactInfo {
                artifact_id: String::from("demo-1234"),
                crate_name: String::from("demo"),
            },
            scope: CrateOutputScope::Workspace,
            dependencies: Vec::new(),
            findings: vec![ResolvedFinding {
                level: LintLevel::Warn,
                finding: Finding::new(
                    FindingKind::EmptyReportRoots,
                    String::from("no roots"),
                    FindingDiagnostic {
                        span: None,
                        message: String::from("no roots"),
                        messages: Vec::new(),
                    },
                ),
            }],
        };

        let json = serde_json::to_value(report).expect("serialize report");
        let object = json.as_object().expect("report object");
        assert_eq!(object["format-version"], REPORT_FORMAT_VERSION);
        assert_eq!(object["findings"].as_array().expect("findings").len(), 1);
    }
}
