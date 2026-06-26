use crate::cache::CachedFunctionSummary;
use crate::namespace::canonical_namespace;
use crate::panics::{PanicEvidence, PanicEvidenceKind, trace_edges_until, trigger_edge_id};
use crate::safety::{
    SafetyAnalysis, SafetyFinding, UnsafeCallee, render_safety_requirement, unsafe_callee_name,
};
use reachability::{ReachabilityEdgeId, ReachabilityGraph, ReachabilityNodeKind};
use rustc_errors::{Diag, EmissionGuarantee};
use rustc_hir::def_id::DefId;
use rustc_middle::ty::TyCtxt;

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
    pub(super) include_stack: bool,
}

pub(super) fn emit_raw_panic_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    evidence: &PanicEvidence,
    root_def_id: DefId,
    include_stack: bool,
) {
    let root = canonical_namespace(tcx, root_def_id);
    let trigger_edge_id = trigger_edge_id(graph, evidence);
    let trigger_edge = graph.edge(trigger_edge_id);
    let mut diag = tcx.dcx().struct_span_err(
        tcx.def_span(root_def_id),
        format!("function `{root}` has an undocumented panic path"),
    );
    diag.span_note(
        trigger_edge.span,
        format!(
            "panic may happen here: {}",
            panic_trigger_note(tcx, graph, evidence)
        ),
    );
    add_trace_notes(
        &mut diag,
        tcx,
        graph,
        &evidence.trace.edge_ids,
        include_stack,
    );
    diag.help(
        "add a guard, document the panic with `# Panics`, or add `// PANIC:` if a local invariant proves it cannot panic",
    );
    let _ = diag.emit();
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
        include_stack,
    } = diagnostic;
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
    let mut diag = tcx.dcx().struct_span_warn(
        primary_span,
        format!("function `{root}` reaches a {contract}"),
    );
    diag.span_note(
        tcx.def_span(documented_def_id),
        format!("`{documented}` documents `# Panics` here"),
    );
    add_trace_notes(
        &mut diag,
        tcx,
        graph,
        &trace_edges_until(evidence, obligation_edge_id),
        include_stack,
    );
    diag.help("ensure this precondition locally or document it on your public API with `# Panics`");
    diag.emit();
}

pub(super) fn emit_cached_dependency_contract_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_id: ReachabilityEdgeId,
    summary: &CachedFunctionSummary,
    root_def_id: DefId,
    trusted: bool,
    include_stack: bool,
) {
    let root = canonical_namespace(tcx, root_def_id);
    let contract = if trusted {
        "trusted panic contract"
    } else {
        "documented panic contract"
    };
    let edge = graph.edge(edge_id);
    let mut diag = tcx.dcx().struct_span_warn(
        edge.span,
        format!("function `{root}` reaches a cached dependency {contract}"),
    );
    diag.note(format!("`{}` has cached {contract} evidence", summary.path));
    add_trace_notes(&mut diag, tcx, graph, &[edge_id], include_stack);
    diag.help("ensure this precondition locally or document it on your public API with `# Panics`");
    diag.emit();
}

pub(super) fn emit_cached_dependency_raw_panic_diagnostic<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge_id: ReachabilityEdgeId,
    summary: &CachedFunctionSummary,
    root_def_id: DefId,
    include_stack: bool,
) {
    let root = canonical_namespace(tcx, root_def_id);
    let edge = graph.edge(edge_id);
    let mut diag = tcx.dcx().struct_span_err(
        edge.span,
        format!("function `{root}` reaches cached undocumented panic evidence from a dependency"),
    );
    diag.note(cached_dependency_panic_reason(summary));
    add_trace_notes(&mut diag, tcx, graph, &[edge_id], include_stack);
    diag.help("guard the call, document the panic with `# Panics`, or add `// PANIC:` if a local invariant proves it cannot panic");
    let _ = diag.emit();
}

pub(super) fn emit_safety_diagnostics(tcx: TyCtxt<'_>, analysis: &SafetyAnalysis) {
    for finding in &analysis.findings {
        match finding {
            SafetyFinding::MissingSafetyDocs { def_id, span } => {
                let function = canonical_namespace(tcx, *def_id);
                let mut diag = tcx.dcx().struct_span_warn(
                    *span,
                    format!("public unsafe function `{function}` is missing `# Safety` docs"),
                );
                diag.help("document the caller obligations under a `# Safety` section");
                diag.emit();
            }
            SafetyFinding::UnsafeCallMissingJustification {
                caller,
                callee,
                span,
            } => {
                let caller = canonical_namespace(tcx, *caller);
                let target = unsafe_callee_name(tcx, *callee);
                let mut diag = tcx.dcx().struct_span_warn(
                    *span,
                    format!(
                        "unsafe call to `{target}` in `{caller}` is missing a `// SAFETY:` justification"
                    ),
                );
                add_safety_callee_note(&mut diag, tcx, *callee);
                diag.help("add a `// SAFETY:` comment above the unsafe block or call site");
                diag.emit();
            }
            SafetyFinding::UnsafeCallMissingRequirements {
                caller,
                callee,
                span,
                missing_requirements,
            } => {
                let caller = canonical_namespace(tcx, *caller);
                let target = unsafe_callee_name(tcx, *callee);
                let mut diag = tcx.dcx().struct_span_warn(
                    *span,
                    format!(
                        "unsafe call to `{target}` in `{caller}` does not satisfy all `# Safety` requirements"
                    ),
                );
                add_safety_callee_note(&mut diag, tcx, *callee);
                for requirement in missing_requirements {
                    diag.note(format!(
                        "missing safety requirement `{}`",
                        render_safety_requirement(requirement)
                    ));
                }
                diag.help(
                    "add named bullets under the applicable `// SAFETY:` comment for each missing requirement",
                );
                diag.emit();
            }
        }
    }
}

fn add_safety_callee_note<G: EmissionGuarantee>(
    diag: &mut Diag<'_, G>,
    tcx: TyCtxt<'_>,
    callee: UnsafeCallee,
) {
    if let UnsafeCallee::Def(def_id) = callee
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
            "set `show-full-stack-trace = true` under `[panics]` in sniff-test.toml to show every reachability step",
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
