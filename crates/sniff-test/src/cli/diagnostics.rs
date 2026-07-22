use std::path::Path;

use crate::cache::{CachedFinding, CachedFindingKind, CachedFunctionSummary, CachedSourceSpan};
use crate::config::{ContractDocOverrides, LintLevel, ReportRootSet};
use crate::namespace::canonical_namespace;
use crate::panics::{
    AmbiguousPanicMarker, AmbiguousPanicRequirementName, PanicEvidence, PanicEvidenceKind,
    trace_edges_until, trigger_edge_id,
};
use crate::report_roots::MissingReportRoot;
use crate::safety::{SafetyCallee, SafetyFinding};
use reachability::{ReachabilityEdgeId, ReachabilityGraph, ReachabilityNodeKind};
use rustc_errors::{Diag, EmissionGuarantee};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::{BytePos, SourceFile, Span};

use super::findings::{DiagnosticMessage, FindingDiagnostic};
use super::report::{render_assert_message, render_edge_without_span, render_node};

#[derive(Debug, Clone, Copy)]
pub(super) struct PanicContractDiagnostic {
    pub(super) obligation_edge_id: Option<ReachabilityEdgeId>,
    pub(super) documented_def_id: DefId,
    pub(super) root_def_id: DefId,
    pub(super) trusted: bool,
    pub(super) include_stack: bool,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CachedDependencyContractDiagnostic {
    pub(super) edge_id: ReachabilityEdgeId,
    pub(super) root_def_id: DefId,
    pub(super) trusted: bool,
    pub(super) include_stack: bool,
}

/// The diagnostic surface findings decorate, bridging the two `Diag`
/// emission-guarantee types (warn vs deny) behind one emission skeleton.
trait LintDiag {
    fn note(&mut self, note: String);
    fn span_note(&mut self, span: Span, note: String);
    fn span_label(&mut self, span: Span, label: String);
    fn span_help(&mut self, span: Span, help: &'static str);
    fn help(&mut self, help: &'static str);
}

impl<G: EmissionGuarantee> LintDiag for Diag<'_, G> {
    fn note(&mut self, note: String) {
        Diag::note(self, note);
    }

    fn span_note(&mut self, span: Span, note: String) {
        Diag::span_note(self, span, note);
    }

    fn span_label(&mut self, span: Span, label: String) {
        Diag::span_label(self, span, label);
    }

    fn span_help(&mut self, span: Span, help: &'static str) {
        Diag::span_help(self, span, help);
    }

    fn help(&mut self, help: &'static str) {
        Diag::help(self, help);
    }
}

impl LintDiag for FindingDiagnostic {
    fn note(&mut self, note: String) {
        self.messages.push(DiagnosticMessage::Note(note));
    }

    fn span_note(&mut self, span: Span, note: String) {
        self.messages.push(DiagnosticMessage::SpanNote(span, note));
    }

    fn span_label(&mut self, span: Span, label: String) {
        self.messages
            .push(DiagnosticMessage::SpanLabel(span, label));
    }

    fn span_help(&mut self, span: Span, help: &'static str) {
        self.messages.push(DiagnosticMessage::SpanHelp(span, help));
    }

    fn help(&mut self, help: &'static str) {
        self.messages.push(DiagnosticMessage::Help(help));
    }
}

fn finding_diagnostic(
    span: Option<Span>,
    message: String,
    decorate: impl FnOnce(&mut dyn LintDiag),
) -> FindingDiagnostic {
    let mut diagnostic = FindingDiagnostic {
        span,
        message,
        messages: Vec::new(),
    };
    decorate(&mut diagnostic);
    diagnostic
}

pub(super) fn emit_finding_diagnostic(
    tcx: TyCtxt<'_>,
    level: LintLevel,
    diagnostic: &FindingDiagnostic,
) {
    emit_lint_diagnostic_at(
        tcx,
        level,
        diagnostic.span,
        diagnostic.message.clone(),
        |diag| {
            for message in &diagnostic.messages {
                match message {
                    DiagnosticMessage::Note(note) => diag.note(note.clone()),
                    DiagnosticMessage::SpanNote(span, note) => {
                        diag.span_note(*span, note.clone());
                    }
                    DiagnosticMessage::SpanLabel(span, label) => {
                        diag.span_label(*span, label.clone());
                    }
                    DiagnosticMessage::SpanHelp(span, help) => diag.span_help(*span, help),
                    DiagnosticMessage::Help(help) => diag.help(help),
                }
            }
        },
    );
}

fn emit_lint_diagnostic_at(
    tcx: TyCtxt<'_>,
    level: LintLevel,
    span: Option<Span>,
    message: String,
    decorate: impl FnOnce(&mut dyn LintDiag),
) {
    match (level, span) {
        (LintLevel::Allow, _) => {}
        (LintLevel::Warn, Some(span)) => {
            let mut diag = tcx.dcx().struct_span_warn(span, message);
            decorate(&mut diag);
            diag.emit();
        }
        (LintLevel::Warn, None) => {
            let mut diag = tcx.dcx().struct_warn(message);
            decorate(&mut diag);
            diag.emit();
        }
        (LintLevel::Deny, Some(span)) => {
            let mut diag = tcx.dcx().struct_span_err(span, message);
            decorate(&mut diag);
            let _ = diag.emit();
        }
        (LintLevel::Deny, None) => {
            let mut diag = tcx.dcx().struct_err(message);
            decorate(&mut diag);
            let _ = diag.emit();
        }
    }
}

pub(super) fn analysis_incomplete_diagnostic(
    tcx: TyCtxt<'_>,
    root_def_id: DefId,
    node_limit: usize,
) -> FindingDiagnostic {
    let root = canonical_namespace(tcx, root_def_id);
    let message = format!(
        "analysis of `{root}` is incomplete: reachability halted at the \
         {node_limit}-instance node limit"
    );
    finding_diagnostic(Some(tcx.def_span(root_def_id)), message, |diag| {
        diag.help(
            "raise `node-limit` under `[analysis]` in sniff-test.toml, or shrink the traversal \
             by trusting or ignoring namespaces",
        );
    })
}

pub(super) fn ambiguous_obligation_marker_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    marker: &AmbiguousPanicMarker,
    root_def_id: DefId,
) -> FindingDiagnostic {
    let root = canonical_namespace(tcx, root_def_id);
    let message = format!("function `{root}` has an ambiguous `// PANIC:` marker");
    finding_diagnostic(Some(marker.marker_span), message, |diag| {
        for edge_id in &marker.edge_ids {
            let edge = graph.edge(*edge_id);
            diag.span_note(
                edge.span,
                format!(
                    "this obligation also resolves to the same marker: {}",
                    render_edge_without_span(tcx, graph, edge)
                ),
            );
        }
        diag.help(
            "move the marker directly above one obligation, split it into separate markers, or set `ambiguous-effect-marker = \"allow\"` under `[analysis.lints]`",
        );
    })
}

pub(super) fn ambiguous_obligation_name_diagnostic(
    tcx: TyCtxt<'_>,
    name: &AmbiguousPanicRequirementName,
    root_def_id: DefId,
) -> FindingDiagnostic {
    let root = canonical_namespace(tcx, root_def_id);
    let target = canonical_namespace(tcx, name.def_id);
    let message = format!("function `{root}` reaches an ambiguous `# Panics` requirement name");
    let primary_span = name
        .requirements
        .first()
        .map_or_else(|| tcx.def_span(name.def_id), |requirement| requirement.span);
    finding_diagnostic(Some(primary_span), message, |diag| {
        diag.note(format!(
            "`{target}` has multiple `# Panics` requirements that normalize to `{}`",
            name.normalized_name
        ));
        for requirement in &name.requirements {
            diag.span_label(
                requirement.span,
                format!(
                    "`{}` normalizes to `{}`",
                    requirement.render(),
                    name.normalized_name
                ),
            );
        }
        diag.help(
            "give each requirement a unique name, or set `ambiguous-effect-requirement = \"allow\"` under `[analysis.lints]`",
        );
    })
}

pub(super) fn indirect_boundary_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    root_def_id: DefId,
    include_stack: bool,
) -> FindingDiagnostic {
    let root = canonical_namespace(tcx, root_def_id);
    let trigger_edge_id = trigger_edge_id(graph, evidence);
    let trigger_edge = graph.edge(trigger_edge_id);
    let message = format!("function `{root}` reaches an unverifiable indirect call");
    finding_diagnostic(Some(tcx.def_span(root_def_id)), message, |diag| {
        decorate_indirect_boundary_diagnostic(
            diag,
            tcx,
            graph,
            evidence,
            trigger_edge.span,
            include_stack,
        );
    })
}

pub(super) fn raw_panic_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    root_def_id: DefId,
    include_stack: bool,
) -> FindingDiagnostic {
    let root = canonical_namespace(tcx, root_def_id);
    let trigger_edge_id = trigger_edge_id(graph, evidence);
    let trigger_edge = graph.edge(trigger_edge_id);
    let message = format!("function `{root}` has an undocumented panic path");
    finding_diagnostic(Some(tcx.def_span(root_def_id)), message, |diag| {
        decorate_raw_panic_diagnostic(diag, tcx, graph, evidence, trigger_edge.span, include_stack);
    })
}

fn decorate_raw_panic_diagnostic<'tcx>(
    diag: &mut dyn LintDiag,
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    trigger_span: Span,
    include_stack: bool,
) {
    diag.span_note(
        trigger_span,
        format!(
            "panic may happen here: {}",
            panic_trigger_note(tcx, graph, evidence)
        ),
    );
    add_trace_notes(diag, tcx, graph, &evidence.trace.edge_ids, include_stack);
    // The sink span above already shows where the panic originates. Add a
    // second, spanned help only when the user would place the guard or
    // `// PANIC:` marker at an earlier entry edge; otherwise keep the fix list
    // as a generic help because the alternatives land in different places.
    if let Some(entry_span) = evidence
        .trace
        .edge_ids
        .first()
        .map(|edge_id| graph.edge(*edge_id).span)
        .filter(|entry_span| !entry_span.source_equal(trigger_span))
    {
        diag.span_help(
            entry_span,
            "guard this path, or add `// PANIC:` here if a local invariant proves it cannot panic",
        );
    }
    diag.help(
        "add a guard, document the panic with `# Panics`, or add `// PANIC:` if a local invariant proves it cannot panic",
    );
}

fn decorate_indirect_boundary_diagnostic<'tcx>(
    diag: &mut dyn LintDiag,
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    trigger_span: Span,
    include_stack: bool,
) {
    diag.span_note(
        trigger_span,
        format!(
            "panic behavior cannot be verified here: {}",
            panic_trigger_note(tcx, graph, evidence)
        ),
    );
    add_trace_notes(diag, tcx, graph, &evidence.trace.edge_ids, include_stack);
    diag.help(
        "document this boundary with `# Panics`, add `// PANIC:` only if every possible callee is locally constrained, or configure `indirect-call-boundary` if this opacity is acceptable",
    );
}

fn decorate_panic_contract_diagnostic<'tcx>(
    diag: &mut dyn LintDiag,
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    diagnostic: &PanicContractDiagnostic,
    documented: &str,
) {
    diag.span_note(
        tcx.def_span(diagnostic.documented_def_id),
        format!("the reached callee `{documented}` documents `# Panics` here"),
    );
    add_trace_notes(
        diag,
        tcx,
        graph,
        &trace_edges_until(evidence, diagnostic.obligation_edge_id),
        diagnostic.include_stack,
    );
    if let Some(edge_id) = diagnostic.obligation_edge_id {
        diag.span_help(
            graph.edge(edge_id).span,
            "add `// PANIC:` directly above this call explaining why its documented panic conditions cannot occur",
        );
    }
    diag.span_help(
        tcx.def_span(diagnostic.root_def_id),
        "document when this function may panic with `/// # Panics` here",
    );
    diag.help("ensure the callee's panic conditions cannot occur, justify that with `// PANIC:`, or document when the caller may panic with `# Panics`");
}

fn decorate_cached_dependency_contract_diagnostic<'tcx>(
    diag: &mut dyn LintDiag,
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    summary: &CachedFunctionSummary,
    panic_kind: &str,
    local_trace: &[ReachabilityEdgeId],
    diagnostic: &CachedDependencyContractDiagnostic,
) {
    diag.note(format!(
        "`{}` has cached {panic_kind} evidence",
        summary.path
    ));
    add_trace_notes(diag, tcx, graph, local_trace, diagnostic.include_stack);
    add_cached_trace_notes(diag, summary, diagnostic.include_stack, |kind| {
        matches!(
            kind,
            CachedFindingKind::PanicObligation | CachedFindingKind::TrustedPanicObligation
        )
    });
    diag.span_help(
        graph.edge(diagnostic.edge_id).span,
        "add `// PANIC:` directly above this call explaining why the dependency's documented panic conditions cannot occur",
    );
    diag.span_help(
        tcx.def_span(diagnostic.root_def_id),
        "document when this function may panic with `/// # Panics` here",
    );
    diag.help("ensure the dependency's panic conditions cannot occur, justify that with `// PANIC:`, or document when the caller may panic with `# Panics`");
}

fn decorate_cached_dependency_raw_panic_diagnostic<'tcx>(
    diag: &mut dyn LintDiag,
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_id: ReachabilityEdgeId,
    local_trace: &[ReachabilityEdgeId],
    summary: &CachedFunctionSummary,
    include_stack: bool,
) {
    diag.note(summary.panic_reason());
    add_cached_dependency_panic_site_notes(diag, tcx, summary);
    add_trace_notes(diag, tcx, graph, local_trace, include_stack);
    add_cached_trace_notes(diag, summary, include_stack, |kind| {
        matches!(
            kind,
            CachedFindingKind::CompilerAssert
                | CachedFindingKind::PanicInvocation
                | CachedFindingKind::IndirectCallBoundary
        )
    });
    diag.span_help(
        graph.edge(edge_id).span,
        "guard this path, or add `// PANIC:` here if a local invariant proves it cannot panic",
    );
    diag.help(
        "add a guard, document the panic with `# Panics`, or add `// PANIC:` if a local invariant proves it cannot panic",
    );
}

fn add_cached_trace_notes(
    diag: &mut dyn LintDiag,
    summary: &CachedFunctionSummary,
    include_stack: bool,
    include: impl Fn(CachedFindingKind) -> bool,
) {
    if !include_stack {
        return;
    }
    let Some(panic) = summary.effect(crate::contracts::EffectKind::Panic) else {
        return;
    };
    for finding in panic
        .findings
        .iter()
        .filter(|finding| include(finding.kind))
    {
        for edge in summary.render_effect_trace(crate::contracts::EffectKind::Panic, finding) {
            diag.note(format!("cached trace: {edge}"));
        }
    }
}

fn add_cached_dependency_panic_site_notes(
    diag: &mut dyn LintDiag,
    tcx: TyCtxt<'_>,
    summary: &CachedFunctionSummary,
) {
    let mut notes = 0;
    let Some(panic) = summary.effect(crate::contracts::EffectKind::Panic) else {
        return;
    };
    for finding in panic.findings.iter().filter(|finding| {
        matches!(
            finding.kind,
            CachedFindingKind::CompilerAssert
                | CachedFindingKind::PanicInvocation
                | CachedFindingKind::IndirectCallBoundary
        )
    }) {
        if let Some(span) = finding
            .source_span
            .as_ref()
            .and_then(|source_span| cached_source_span(tcx, source_span))
        {
            diag.span_note(
                span,
                format!(
                    "cached dependency panic evidence was recorded here: {}",
                    finding.reason
                ),
            );
        } else {
            diag.note(cached_dependency_panic_site_note(finding));
        }
        notes += 1;
    }

    if notes == 0 && !panic.analysis_complete {
        diag.note(String::from(
            "dependency analysis was incomplete, so no concrete cached panic site is available",
        ));
    }
}

fn cached_dependency_panic_site_note(finding: &CachedFinding) -> String {
    format!(
        "cached dependency panic evidence was recorded at {}: {}",
        finding.span, finding.reason
    )
}

fn cached_source_span(tcx: TyCtxt<'_>, span: &CachedSourceSpan) -> Option<Span> {
    let file = tcx
        .sess
        .source_map()
        .load_file(Path::new(&span.file))
        .ok()?;
    cached_source_span_in_file(&file, span)
}

fn cached_source_span_in_file(file: &SourceFile, span: &CachedSourceSpan) -> Option<Span> {
    let lo = cached_line_column_pos(file, span.line_start, span.column_start)?;
    let hi = cached_line_column_pos(file, span.line_end, span.column_end)?;
    (lo <= hi).then(|| Span::with_root_ctxt(lo, hi))
}

fn cached_line_column_pos(file: &SourceFile, line: usize, column: usize) -> Option<BytePos> {
    let line_index = line.checked_sub(1)?;
    let column_index = column.checked_sub(1)?;
    let line = file.get_line(line_index)?;
    let byte_offset = byte_offset_for_char_column(line.as_ref(), column_index)?;
    let byte_offset = u32::try_from(byte_offset).ok()?;
    Some(file.line_bounds(line_index).start + BytePos(byte_offset))
}

fn byte_offset_for_char_column(line: &str, column_index: usize) -> Option<usize> {
    line.char_indices()
        .nth(column_index)
        .map(|(byte_offset, _)| byte_offset)
        .or_else(|| (column_index == line.chars().count()).then_some(line.len()))
}

pub(super) fn panic_contract_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    diagnostic: PanicContractDiagnostic,
) -> FindingDiagnostic {
    let root = canonical_namespace(tcx, diagnostic.root_def_id);
    let documented = canonical_namespace(tcx, diagnostic.documented_def_id);
    let panic_kind = if diagnostic.trusted {
        "trusted panic"
    } else {
        "documented panic"
    };
    let primary_span = diagnostic.obligation_edge_id.map_or_else(
        || tcx.def_span(diagnostic.root_def_id),
        |edge_id| graph.edge(edge_id).span,
    );
    let message = format!("function `{root}` may panic through a {panic_kind}");
    finding_diagnostic(Some(primary_span), message, |diag| {
        decorate_panic_contract_diagnostic(diag, tcx, graph, evidence, &diagnostic, &documented);
    })
}

pub(super) fn cached_dependency_contract_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    summary: &CachedFunctionSummary,
    local_trace: &[ReachabilityEdgeId],
    diagnostic: CachedDependencyContractDiagnostic,
) -> FindingDiagnostic {
    let CachedDependencyContractDiagnostic {
        edge_id,
        root_def_id,
        trusted,
        ..
    } = diagnostic;
    let root = canonical_namespace(tcx, root_def_id);
    let panic_kind = if trusted {
        "trusted panic"
    } else {
        "documented panic"
    };
    let edge = graph.edge(edge_id);
    let message = format!("function `{root}` may panic through a cached dependency {panic_kind}");
    finding_diagnostic(Some(edge.span), message, |diag| {
        decorate_cached_dependency_contract_diagnostic(
            diag,
            tcx,
            graph,
            summary,
            panic_kind,
            local_trace,
            &diagnostic,
        );
    })
}

pub(super) fn cached_dependency_raw_panic_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_id: ReachabilityEdgeId,
    local_trace: &[ReachabilityEdgeId],
    summary: &CachedFunctionSummary,
    root_def_id: DefId,
    include_stack: bool,
) -> FindingDiagnostic {
    let root = canonical_namespace(tcx, root_def_id);
    let message =
        format!("function `{root}` reaches cached undocumented panic evidence from a dependency");
    finding_diagnostic(Some(tcx.def_span(root_def_id)), message, |diag| {
        decorate_cached_dependency_raw_panic_diagnostic(
            diag,
            tcx,
            graph,
            edge_id,
            local_trace,
            summary,
            include_stack,
        );
    })
}

pub(super) fn safety_finding_diagnostic(
    tcx: TyCtxt<'_>,
    finding: &SafetyFinding,
    overrides: &ContractDocOverrides,
) -> FindingDiagnostic {
    match finding {
        SafetyFinding::MissingSafetyDocs { def_id, span } => {
            let function = canonical_namespace(tcx, *def_id);
            let message = format!("public unsafe function `{function}` is missing `# Safety` docs");
            finding_diagnostic(Some(*span), message, |diag| {
                diag.help("document the caller obligations under a `# Safety` section");
            })
        }
        SafetyFinding::CallMissingJustification {
            site,
            callee,
            call_kind,
        } => {
            let caller = canonical_namespace(tcx, site.owner);
            let target = callee.name(tcx);
            let call = call_kind.label();
            let message = format!(
                "{call} to `{target}` in `{caller}` is missing a `// SAFETY:` justification"
            );
            finding_diagnostic(Some(site.span), message, |diag| {
                add_safety_callee_note(diag, tcx, *callee, overrides);
                diag.help("add a `// SAFETY:` comment above the unsafe block or call site");
            })
        }
        SafetyFinding::CallMissingRequirements {
            site,
            callee,
            call_kind,
            missing_requirements,
        } => {
            let caller = canonical_namespace(tcx, site.owner);
            let target = callee.name(tcx);
            let call = call_kind.label();
            let message = format!(
                "{call} to `{target}` in `{caller}` does not satisfy all `# Safety` requirements"
            );
            finding_diagnostic(Some(site.span), message, |diag| {
                add_missing_safety_requirement_notes(
                    diag,
                    tcx,
                    *callee,
                    overrides,
                    missing_requirements,
                );
            })
        }
        SafetyFinding::OpMissingJustification { site, op } => {
            let caller = canonical_namespace(tcx, site.owner);
            let operation = op.label();
            let message = format!(
                "unsafe operation ({operation}) in `{caller}` is missing a `// SAFETY:` justification"
            );
            finding_diagnostic(Some(site.span), message, |diag| {
                diag.help("add a `// SAFETY:` comment above the unsafe block or operation");
            })
        }
        SafetyFinding::AmbiguousObligationName {
            caller: _,
            def_id,
            normalized_name,
            requirements,
        } => {
            let function = canonical_namespace(tcx, *def_id);
            let message = format!("`{function}` has an ambiguous `# Safety` requirement name");
            let primary_span = requirements
                .first()
                .map_or_else(|| tcx.def_span(*def_id), |requirement| requirement.span);
            finding_diagnostic(Some(primary_span), message, |diag| {
                diag.note(format!(
                    "multiple `# Safety` requirements normalize to `{normalized_name}`"
                ));
                for requirement in requirements {
                    diag.span_label(
                        requirement.span,
                        format!(
                            "`{}` normalizes to `{normalized_name}`",
                            requirement.render()
                        ),
                    );
                }
                diag.help(
                        "give each requirement a unique name, or set `ambiguous-effect-requirement = \"allow\"` under `[analysis.lints]`",
                );
            })
        }
        SafetyFinding::AmbiguousMarker {
            caller,
            marker_span,
            effect_spans,
        } => ambiguous_safety_marker_diagnostic(tcx, *caller, *marker_span, effect_spans),
    }
}

pub(super) fn cached_dependency_safety_diagnostic(
    tcx: TyCtxt<'_>,
    call_span: Span,
    summary: &CachedFunctionSummary,
    finding: &crate::cache::CachedFinding,
) -> FindingDiagnostic {
    let message = format!(
        "call to `{}` reaches cached undocumented safety effects",
        summary.path
    );
    finding_diagnostic(Some(call_span), message, |diag| {
        if let Some(span) = finding
            .source_span
            .as_ref()
            .and_then(|source_span| cached_source_span(tcx, source_span))
        {
            diag.span_note(span, format!("cached safety effect: {}", finding.reason));
        } else {
            diag.note(format!(
                "cached safety effect at {}: {}",
                finding.span, finding.reason
            ));
        }
    })
}

pub(super) fn cached_dependency_safety_incomplete_diagnostic(
    call_span: Span,
    summary: &CachedFunctionSummary,
) -> FindingDiagnostic {
    let message = format!(
        "call to `{}` reaches an incomplete cached safety analysis",
        summary.path
    );
    finding_diagnostic(Some(call_span), message, |diag| {
        diag.note(String::from(
            "dependency safety analysis stopped before proving that the function has no effects",
        ));
    })
}

fn ambiguous_safety_marker_diagnostic(
    tcx: TyCtxt<'_>,
    caller: DefId,
    marker_span: Span,
    effect_spans: &[Span],
) -> FindingDiagnostic {
    let caller = canonical_namespace(tcx, caller);
    let message = format!("function `{caller}` has an ambiguous `// SAFETY:` marker");
    finding_diagnostic(Some(marker_span), message, |diag| {
        for span in effect_spans {
            diag.span_note(
                *span,
                String::from("this safety effect group resolves to the same marker"),
            );
        }
        diag.help(
            "give each unsafe block or operation its own marker, or set `ambiguous-effect-marker = \"allow\"` under `[analysis.lints]`",
        );
    })
}

fn add_missing_safety_requirement_notes(
    diag: &mut dyn LintDiag,
    tcx: TyCtxt<'_>,
    callee: SafetyCallee,
    overrides: &ContractDocOverrides,
    missing_requirements: &[crate::safety::SafetyRequirement],
) {
    add_safety_callee_note(diag, tcx, callee, overrides);
    for requirement in missing_requirements {
        diag.note(format!(
            "missing safety requirement `{}`",
            requirement.render()
        ));
    }
    diag.help(
        "add named bullets under the applicable `// SAFETY:` comment for each missing requirement",
    );
}

pub(super) fn empty_report_roots_diagnostic(
    tcx: TyCtxt<'_>,
    manifest_path: &Path,
    report_roots: &ReportRootSet,
    crate_name: &str,
) -> FindingDiagnostic {
    let message = format!(
        "`[analysis].report-roots = {}` selected no functions in `{crate_name}`; no effects were analyzed",
        report_roots.description()
    );
    let source_file = tcx.sess.source_map().load_file(manifest_path).ok();
    let span = report_roots.source_span().and_then(|source_span| {
        source_file
            .as_ref()
            .and_then(|file| config_span(file, source_span))
    });

    finding_diagnostic(span, message, |diag| {
        diag.help("update `[analysis].report-roots` to include functions in the current crate");
    })
}

pub(super) fn missing_report_root_diagnostic(
    tcx: TyCtxt<'_>,
    manifest_path: &Path,
    root: &MissingReportRoot,
) -> FindingDiagnostic {
    let source_file = tcx.sess.source_map().load_file(manifest_path).ok();
    let message = "configured report root was not found";
    let span = source_file
        .as_ref()
        .and_then(|file| config_span(file, root.source_span.clone()));
    let message = if span.is_some() {
        String::from(message)
    } else {
        format!("{message}: `{}`", root.path)
    };
    finding_diagnostic(span, message, |diag| {
        diag.note(String::from("configured under `[analysis].report-roots`"));
        diag.help("remove it or update it to a function in the current crate");
    })
}

fn config_span(file: &rustc_span::SourceFile, source_span: std::ops::Range<usize>) -> Option<Span> {
    let start = normalized_offset(file, source_span.start)?;
    let end = normalized_offset(file, source_span.end)?;
    Some(Span::with_root_ctxt(
        file.start_pos + BytePos(start),
        file.start_pos + BytePos(end),
    ))
}

/// Maps a byte offset in the on-disk manifest to the offset in rustc's
/// normalized source, which strips a UTF-8 BOM and the CR bytes of CRLF
/// pairs. TOML spans are raw-file offsets, so they drift on CRLF manifests
/// without this adjustment.
fn normalized_offset(file: &rustc_span::SourceFile, original: usize) -> Option<u32> {
    let original = u32::try_from(original).ok()?;
    let diff = file
        .normalized_pos
        .iter()
        .take_while(|entry| entry.pos.0 + entry.diff <= original)
        .last()
        .map_or(0, |entry| entry.diff);
    Some(original - diff)
}

fn add_safety_callee_note(
    diag: &mut dyn LintDiag,
    tcx: TyCtxt<'_>,
    callee: SafetyCallee,
    overrides: &ContractDocOverrides,
) {
    if let SafetyCallee::Def(def_id) = callee
        && crate::safety::has_safety_docs(tcx, def_id, overrides)
    {
        diag.span_note(
            tcx.def_span(def_id),
            format!(
                "`{}` documents `# Safety` here",
                canonical_namespace(tcx, def_id)
            ),
        );
    }
}

fn add_trace_notes<'tcx>(
    diag: &mut dyn LintDiag,
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_ids: &[ReachabilityEdgeId],
    include_stack: bool,
) {
    if edge_ids.is_empty() {
        return;
    }

    if include_stack {
        for (index, edge_id) in edge_ids.iter().enumerate() {
            let edge = graph.edge(*edge_id);
            diag.span_note(
                edge.span,
                format!(
                    "reachable step {index}: {}",
                    render_edge_without_span(tcx, graph, edge)
                ),
            );
        }
    } else if edge_ids.len() > 1 {
        let first = graph.edge(edge_ids[0]);
        let last = graph.edge(*edge_ids.last().expect("trace is non-empty"));
        diag.note(format!(
            "reachable from {} to {}",
            render_trace_endpoint(tcx, &graph.node(first.source).kind),
            render_trace_endpoint(tcx, &graph.node(last.target).kind)
        ));
        diag.note(String::from(
            "set `show-full-stack-trace = true` under `[analysis]` in sniff-test.toml to show every reachability step",
        ));
    }
}

fn panic_trigger_note<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
) -> String {
    match evidence.kind {
        PanicEvidenceKind::CompilerAssert => {
            let target = &graph.node(graph.edge(evidence.edge_id).target).kind;
            if let ReachabilityNodeKind::CompilerAssert { message, locals } = target {
                format!(
                    "compiler assertion: {}",
                    render_assert_message(message, locals)
                )
            } else {
                format!("compiler assertion: {}", render_node(tcx, target))
            }
        }
        PanicEvidenceKind::PanicSink { def_id } => {
            format!("panic sink `{}`", canonical_namespace(tcx, def_id))
        }
        PanicEvidenceKind::PanicObligation { def_id } => {
            format!(
                "documented panic behavior of `{}`",
                canonical_namespace(tcx, def_id)
            )
        }
        PanicEvidenceKind::IndirectBoundary {
            def_id: Some(def_id),
        } => {
            format!(
                "indirect call to undocumented trait method `{}`",
                canonical_namespace(tcx, def_id)
            )
        }
        PanicEvidenceKind::IndirectBoundary { def_id: None } => {
            String::from("indirect call through an opaque callable")
        }
    }
}

fn render_trace_endpoint<'tcx>(tcx: TyCtxt<'tcx>, node: &ReachabilityNodeKind<'tcx>) -> String {
    let rendered = render_node(tcx, node);
    if matches!(node, ReachabilityNodeKind::CompilerAssert { .. }) {
        rendered
    } else {
        format!("`{rendered}`")
    }
}

#[cfg(test)]
mod tests {
    use crate::cache::CachedSourceSpan;

    use rustc_span::source_map::{FilePathMapping, SourceMap};
    use rustc_span::{BytePos, FileName};

    use super::{cached_source_span_in_file, config_span};

    fn with_source_file(source: &str, check: impl FnOnce(&rustc_span::SourceFile)) {
        rustc_span::create_default_session_globals_then(|| {
            let source_map = SourceMap::new(FilePathMapping::empty());
            let file = source_map.new_source_file(
                FileName::Custom(String::from("sniff-test.toml")),
                source.to_owned(),
            );
            check(&file);
        });
    }

    #[test]
    fn converts_config_byte_range_to_source_span() {
        with_source_file("key = \"value\"\n", |file| {
            let span = config_span(file, 6..13).expect("span should fit in u32");

            assert_eq!(span.lo(), file.start_pos + BytePos(6));
            assert_eq!(span.hi(), file.start_pos + BytePos(13));
        });
    }

    #[test]
    fn crlf_manifest_offsets_account_for_stripped_carriage_returns() {
        // Raw file: `a = 1\r\nkey = "value"\r\n`; toml reports raw offsets,
        // rustc's normalized source has the CR bytes removed.
        with_source_file("a = 1\r\nkey = \"value\"\r\n", |file| {
            let span = config_span(file, 13..20).expect("span should fit in u32");

            assert_eq!(span.lo(), file.start_pos + BytePos(12));
            assert_eq!(span.hi(), file.start_pos + BytePos(19));
        });
    }

    #[test]
    fn bom_prefixed_manifest_offsets_account_for_stripped_bom() {
        with_source_file("\u{feff}key = \"value\"\n", |file| {
            let span = config_span(file, 9..16).expect("span should fit in u32");

            assert_eq!(span.lo(), file.start_pos + BytePos(6));
            assert_eq!(span.hi(), file.start_pos + BytePos(13));
        });
    }

    #[test]
    fn converts_cached_line_columns_to_source_span() {
        with_source_file("first\nsecond\n", |file| {
            let span = cached_source_span_in_file(
                file,
                &CachedSourceSpan {
                    file: String::from("unused.rs"),
                    line_start: 2,
                    column_start: 2,
                    line_end: 2,
                    column_end: 5,
                },
            )
            .expect("span should resolve");

            assert_eq!(span.lo(), file.start_pos + BytePos(7));
            assert_eq!(span.hi(), file.start_pos + BytePos(10));
        });
    }

    #[test]
    fn cached_line_columns_are_character_based() {
        with_source_file("αβγ\n", |file| {
            let span = cached_source_span_in_file(
                file,
                &CachedSourceSpan {
                    file: String::from("unused.rs"),
                    line_start: 1,
                    column_start: 2,
                    line_end: 1,
                    column_end: 3,
                },
            )
            .expect("span should resolve");

            assert_eq!(span.lo(), file.start_pos + BytePos(2));
            assert_eq!(span.hi(), file.start_pos + BytePos(4));
        });
    }
}
