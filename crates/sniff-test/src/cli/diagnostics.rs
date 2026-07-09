use std::path::Path;

use crate::cache::CachedFunctionSummary;
use crate::config::{LintLevel, SafetyLintConfig};
use crate::namespace::canonical_namespace;
use crate::panics::{PanicEvidence, PanicEvidenceKind, trace_edges_until, trigger_edge_id};
use crate::report_roots::{MissingReportRoot, MissingRootReason};
use crate::safety::{
    SafetyAnalysis, SafetyCallee, SafetyFinding, render_safety_requirement, safety_call_label,
    safety_callee_name, safety_op_label,
};
use reachability::{ReachabilityEdgeId, ReachabilityGraph, ReachabilityNodeKind};
use rustc_errors::{Diag, EmissionGuarantee};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;
use rustc_span::{BytePos, Span};

use super::report::{
    cached_dependency_panic_reason, render_assert_message, render_edge_without_span, render_node,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct PanicDiagnosticOptions {
    pub(super) emit: bool,
    pub(super) include_stack: bool,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PanicContractDiagnostic {
    pub(super) obligation_edge_id: Option<ReachabilityEdgeId>,
    pub(super) documented_def_id: DefId,
    pub(super) root_def_id: DefId,
    pub(super) trusted: bool,
    pub(super) level: LintLevel,
    pub(super) include_stack: bool,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CachedDependencyContractDiagnostic {
    pub(super) edge_id: ReachabilityEdgeId,
    pub(super) root_def_id: DefId,
    pub(super) trusted: bool,
    pub(super) level: LintLevel,
    pub(super) include_stack: bool,
}

#[derive(Debug, Clone, Copy)]
struct PanicContractNotes<'a> {
    obligation_edge_id: Option<ReachabilityEdgeId>,
    documented_def_id: DefId,
    documented: &'a str,
    include_stack: bool,
}

pub(super) fn emit_analysis_incomplete_diagnostic(
    tcx: TyCtxt<'_>,
    root_def_id: DefId,
    node_limit: usize,
    level: LintLevel,
) {
    let root = canonical_namespace(tcx, root_def_id);
    let message = format!(
        "analysis of `{root}` is incomplete: reachability halted at the \
         {node_limit}-instance node limit"
    );
    let help = "raise `node-limit` under `[analysis]` in sniff-test.toml, or shrink the traversal by \
         trusting or ignoring namespaces";
    match level {
        LintLevel::Allow => {}
        LintLevel::Warn => {
            let mut diag = tcx
                .dcx()
                .struct_span_warn(tcx.def_span(root_def_id), message);
            diag.help(help);
            diag.emit();
        }
        LintLevel::Deny => {
            let mut diag = tcx
                .dcx()
                .struct_span_err(tcx.def_span(root_def_id), message);
            diag.help(help);
            let _ = diag.emit();
        }
    }
}

pub(super) fn emit_indirect_boundary_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    root_def_id: DefId,
    level: LintLevel,
    include_stack: bool,
) {
    if level == LintLevel::Allow {
        return;
    }
    let root = canonical_namespace(tcx, root_def_id);
    let trigger_edge_id = trigger_edge_id(graph, evidence);
    let trigger_edge = graph.edge(trigger_edge_id);
    let message = format!("function `{root}` reaches an unverifiable indirect call");
    match level {
        LintLevel::Allow => {}
        LintLevel::Warn => {
            let mut diag = tcx
                .dcx()
                .struct_span_warn(tcx.def_span(root_def_id), message);
            decorate_raw_panic_diagnostic(
                &mut diag,
                tcx,
                graph,
                evidence,
                trigger_edge.span,
                include_stack,
            );
            diag.emit();
        }
        LintLevel::Deny => {
            let mut diag = tcx
                .dcx()
                .struct_span_err(tcx.def_span(root_def_id), message);
            decorate_raw_panic_diagnostic(
                &mut diag,
                tcx,
                graph,
                evidence,
                trigger_edge.span,
                include_stack,
            );
            let _ = diag.emit();
        }
    }
}

pub(super) fn emit_raw_panic_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    root_def_id: DefId,
    level: LintLevel,
    include_stack: bool,
) {
    if level == LintLevel::Allow {
        return;
    }
    let root = canonical_namespace(tcx, root_def_id);
    let trigger_edge_id = trigger_edge_id(graph, evidence);
    let trigger_edge = graph.edge(trigger_edge_id);
    let message = format!("function `{root}` has an undocumented panic path");
    match level {
        LintLevel::Allow => {}
        LintLevel::Warn => {
            let mut diag = tcx
                .dcx()
                .struct_span_warn(tcx.def_span(root_def_id), message);
            decorate_raw_panic_diagnostic(
                &mut diag,
                tcx,
                graph,
                evidence,
                trigger_edge.span,
                include_stack,
            );
            diag.emit();
        }
        LintLevel::Deny => {
            let mut diag = tcx
                .dcx()
                .struct_span_err(tcx.def_span(root_def_id), message);
            decorate_raw_panic_diagnostic(
                &mut diag,
                tcx,
                graph,
                evidence,
                trigger_edge.span,
                include_stack,
            );
            let _ = diag.emit();
        }
    }
}

fn decorate_raw_panic_diagnostic<'tcx, G: EmissionGuarantee>(
    diag: &mut Diag<'_, G>,
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
    diag.help(
        "add a guard, document the panic with `# Panics`, or add `// PANIC:` if a local invariant proves it cannot panic",
    );
}

fn decorate_panic_contract_diagnostic<'tcx, G: EmissionGuarantee>(
    diag: &mut Diag<'_, G>,
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    notes: PanicContractNotes<'_>,
) {
    diag.span_note(
        tcx.def_span(notes.documented_def_id),
        format!("`{}` documents `# Panics` here", notes.documented),
    );
    add_trace_notes(
        diag,
        tcx,
        graph,
        &trace_edges_until(evidence, notes.obligation_edge_id),
        notes.include_stack,
    );
    diag.help("ensure this precondition locally or document it on your public API with `# Panics`");
}

fn decorate_cached_dependency_contract_diagnostic<'tcx, G: EmissionGuarantee>(
    diag: &mut Diag<'_, G>,
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_id: ReachabilityEdgeId,
    summary: &CachedFunctionSummary,
    contract: &str,
    include_stack: bool,
) {
    diag.note(format!("`{}` has cached {contract} evidence", summary.path));
    add_trace_notes(diag, tcx, graph, &[edge_id], include_stack);
    diag.help("ensure this precondition locally or document it on your public API with `# Panics`");
}

fn decorate_cached_dependency_raw_panic_diagnostic<'tcx, G: EmissionGuarantee>(
    diag: &mut Diag<'_, G>,
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_id: ReachabilityEdgeId,
    summary: &CachedFunctionSummary,
    include_stack: bool,
) {
    diag.note(cached_dependency_panic_reason(summary));
    add_trace_notes(diag, tcx, graph, &[edge_id], include_stack);
    diag.help("guard the call, document the panic with `# Panics`, or add `// PANIC:` if a local invariant proves it cannot panic");
}

pub(super) fn emit_panic_contract_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    diagnostic: PanicContractDiagnostic,
) {
    let PanicContractDiagnostic {
        obligation_edge_id,
        documented_def_id,
        root_def_id,
        trusted,
        level,
        include_stack,
    } = diagnostic;
    if level == LintLevel::Allow {
        return;
    }
    let root = canonical_namespace(tcx, root_def_id);
    let documented = canonical_namespace(tcx, documented_def_id);
    let contract = if trusted {
        "trusted panic contract"
    } else {
        "documented panic contract"
    };
    let primary_span = obligation_edge_id.map_or_else(
        || tcx.def_span(root_def_id),
        |edge_id| graph.edge(edge_id).span,
    );
    let message = format!("function `{root}` reaches a {contract}");
    match level {
        LintLevel::Allow => {}
        LintLevel::Warn => {
            let mut diag = tcx.dcx().struct_span_warn(primary_span, message);
            decorate_panic_contract_diagnostic(
                &mut diag,
                tcx,
                graph,
                evidence,
                PanicContractNotes {
                    obligation_edge_id,
                    documented_def_id,
                    documented: &documented,
                    include_stack,
                },
            );
            diag.emit();
        }
        LintLevel::Deny => {
            let mut diag = tcx.dcx().struct_span_err(primary_span, message);
            decorate_panic_contract_diagnostic(
                &mut diag,
                tcx,
                graph,
                evidence,
                PanicContractNotes {
                    obligation_edge_id,
                    documented_def_id,
                    documented: &documented,
                    include_stack,
                },
            );
            let _ = diag.emit();
        }
    }
}

pub(super) fn emit_cached_dependency_contract_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    summary: &CachedFunctionSummary,
    diagnostic: CachedDependencyContractDiagnostic,
) {
    let CachedDependencyContractDiagnostic {
        edge_id,
        root_def_id,
        trusted,
        level,
        include_stack,
    } = diagnostic;
    if level == LintLevel::Allow {
        return;
    }
    let root = canonical_namespace(tcx, root_def_id);
    let contract = if trusted {
        "trusted panic contract"
    } else {
        "documented panic contract"
    };
    let edge = graph.edge(edge_id);
    let message = format!("function `{root}` reaches a cached dependency {contract}");
    match level {
        LintLevel::Allow => {}
        LintLevel::Warn => {
            let mut diag = tcx.dcx().struct_span_warn(edge.span, message);
            decorate_cached_dependency_contract_diagnostic(
                &mut diag,
                tcx,
                graph,
                edge_id,
                summary,
                contract,
                include_stack,
            );
            diag.emit();
        }
        LintLevel::Deny => {
            let mut diag = tcx.dcx().struct_span_err(edge.span, message);
            decorate_cached_dependency_contract_diagnostic(
                &mut diag,
                tcx,
                graph,
                edge_id,
                summary,
                contract,
                include_stack,
            );
            let _ = diag.emit();
        }
    }
}

pub(super) fn emit_cached_dependency_raw_panic_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_id: ReachabilityEdgeId,
    summary: &CachedFunctionSummary,
    root_def_id: DefId,
    level: LintLevel,
    include_stack: bool,
) {
    if level == LintLevel::Allow {
        return;
    }
    let root = canonical_namespace(tcx, root_def_id);
    let edge = graph.edge(edge_id);
    let message =
        format!("function `{root}` reaches cached undocumented panic evidence from a dependency");
    match level {
        LintLevel::Allow => {}
        LintLevel::Warn => {
            let mut diag = tcx.dcx().struct_span_warn(edge.span, message);
            decorate_cached_dependency_raw_panic_diagnostic(
                &mut diag,
                tcx,
                graph,
                edge_id,
                summary,
                include_stack,
            );
            diag.emit();
        }
        LintLevel::Deny => {
            let mut diag = tcx.dcx().struct_span_err(edge.span, message);
            decorate_cached_dependency_raw_panic_diagnostic(
                &mut diag,
                tcx,
                graph,
                edge_id,
                summary,
                include_stack,
            );
            let _ = diag.emit();
        }
    }
}

pub(super) fn emit_safety_diagnostics(
    tcx: TyCtxt<'_>,
    analysis: &SafetyAnalysis,
    lints: SafetyLintConfig,
) {
    for finding in &analysis.findings {
        let level = finding.kind().lint_level(lints);
        if level == LintLevel::Allow {
            continue;
        }

        match finding {
            SafetyFinding::MissingSafetyDocs { def_id, span } => {
                let function = canonical_namespace(tcx, *def_id);
                let message =
                    format!("public unsafe function `{function}` is missing `# Safety` docs");
                match level {
                    LintLevel::Allow => {}
                    LintLevel::Warn => {
                        let mut diag = tcx.dcx().struct_span_warn(*span, message);
                        diag.help("document the caller obligations under a `# Safety` section");
                        diag.emit();
                    }
                    LintLevel::Deny => {
                        let mut diag = tcx.dcx().struct_span_err(*span, message);
                        diag.help("document the caller obligations under a `# Safety` section");
                        let _ = diag.emit();
                    }
                }
            }
            SafetyFinding::CallMissingJustification {
                caller,
                callee,
                call_kind,
                span,
            } => {
                let caller = canonical_namespace(tcx, *caller);
                let target = safety_callee_name(tcx, *callee);
                let call = safety_call_label(*call_kind);
                let message = format!(
                    "{call} to `{target}` in `{caller}` is missing a `// SAFETY:` justification"
                );
                match level {
                    LintLevel::Allow => {}
                    LintLevel::Warn => {
                        let mut diag = tcx.dcx().struct_span_warn(*span, message);
                        add_safety_callee_note(&mut diag, tcx, *callee);
                        diag.help("add a `// SAFETY:` comment above the unsafe block or call site");
                        diag.emit();
                    }
                    LintLevel::Deny => {
                        let mut diag = tcx.dcx().struct_span_err(*span, message);
                        add_safety_callee_note(&mut diag, tcx, *callee);
                        diag.help("add a `// SAFETY:` comment above the unsafe block or call site");
                        let _ = diag.emit();
                    }
                }
            }
            SafetyFinding::CallMissingRequirements {
                caller,
                callee,
                call_kind,
                span,
                missing_requirements,
            } => {
                let caller = canonical_namespace(tcx, *caller);
                let target = safety_callee_name(tcx, *callee);
                let call = safety_call_label(*call_kind);
                let message = format!(
                    "{call} to `{target}` in `{caller}` does not satisfy all `# Safety` requirements"
                );
                match level {
                    LintLevel::Allow => {}
                    LintLevel::Warn => {
                        let mut diag = tcx.dcx().struct_span_warn(*span, message);
                        add_missing_safety_requirement_notes(
                            &mut diag,
                            tcx,
                            *callee,
                            missing_requirements,
                        );
                        diag.emit();
                    }
                    LintLevel::Deny => {
                        let mut diag = tcx.dcx().struct_span_err(*span, message);
                        add_missing_safety_requirement_notes(
                            &mut diag,
                            tcx,
                            *callee,
                            missing_requirements,
                        );
                        let _ = diag.emit();
                    }
                }
            }
            SafetyFinding::OpMissingJustification { caller, op, span } => {
                emit_safety_op_diagnostic(tcx, *caller, *op, *span, level);
            }
        }
    }
}

fn emit_safety_op_diagnostic(
    tcx: TyCtxt<'_>,
    caller: DefId,
    op: crate::safety::SafetyOpKind,
    span: Span,
    level: LintLevel,
) {
    let caller = canonical_namespace(tcx, caller);
    let operation = safety_op_label(op);
    let message = format!(
        "unsafe operation ({operation}) in `{caller}` is missing a `// SAFETY:` justification"
    );
    match level {
        LintLevel::Allow => {}
        LintLevel::Warn => {
            let mut diag = tcx.dcx().struct_span_warn(span, message);
            diag.help("add a `// SAFETY:` comment above the unsafe block or operation");
            diag.emit();
        }
        LintLevel::Deny => {
            let mut diag = tcx.dcx().struct_span_err(span, message);
            diag.help("add a `// SAFETY:` comment above the unsafe block or operation");
            let _ = diag.emit();
        }
    }
}

fn add_missing_safety_requirement_notes<G: EmissionGuarantee>(
    diag: &mut Diag<'_, G>,
    tcx: TyCtxt<'_>,
    callee: SafetyCallee,
    missing_requirements: &[crate::safety::SafetyRequirement],
) {
    add_safety_callee_note(diag, tcx, callee);
    for requirement in missing_requirements {
        diag.note(format!(
            "missing safety requirement `{}`",
            render_safety_requirement(requirement)
        ));
    }
    diag.help(
        "add named bullets under the applicable `// SAFETY:` comment for each missing requirement",
    );
}

pub(super) fn emit_missing_report_root_diagnostics(
    tcx: TyCtxt<'_>,
    manifest_path: &Path,
    roots: &[MissingReportRoot],
) {
    let source_file = tcx.sess.source_map().load_file(manifest_path).ok();
    for root in roots {
        let (message, help) = match root.reason {
            MissingRootReason::NotFound => (
                "configured report root was not found",
                "remove it or update it to a function in the current crate",
            ),
            MissingRootReason::Ignored => (
                "configured report root is excluded by `[panics].ignored-namespaces`",
                "remove the root or the ignore pattern covering it",
            ),
        };
        let mut diag = if let Some(span) = source_file
            .as_ref()
            .and_then(|file| config_span(file, root.source_span.clone()))
        {
            tcx.dcx().struct_span_warn(span, message)
        } else {
            tcx.dcx().struct_warn(format!("{message}: `{}`", root.path))
        };
        diag.note("configured under `[analysis].report-roots`");
        diag.help(help);
        diag.emit();
    }
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

fn add_safety_callee_note<G: EmissionGuarantee>(
    diag: &mut Diag<'_, G>,
    tcx: TyCtxt<'_>,
    callee: SafetyCallee,
) {
    if let SafetyCallee::Def(def_id) = callee
        && crate::safety::has_safety_docs(tcx, def_id)
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

fn add_trace_notes<'tcx, G: EmissionGuarantee>(
    diag: &mut Diag<'_, G>,
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
        diag.note(
            "set `show-full-stack-trace = true` under `[analysis]` in sniff-test.toml to show every reachability step",
        );
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
                "documented panic contract `{}`",
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
    use rustc_span::source_map::{FilePathMapping, SourceMap};
    use rustc_span::{BytePos, FileName};

    use super::config_span;

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
}
