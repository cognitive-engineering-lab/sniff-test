//! Adapts policy-neutral interpreter output to diagnostics and JSON findings.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::analysis::cache::RustcArtifactId;
use crate::analysis::extract::ExtractedArtifactBundle;
use crate::analysis::facts::panic::{
    CompilerAssertSemanticNodeRole, CompilerAssertSemanticTrace, CompilerAssertSemanticTraceStep,
    compiler_assert_presentation,
};
use crate::analysis::graph::ArtifactAnalysisGraph;
#[cfg(test)]
use crate::analysis::interpret::{DomainCompleteness, SafetyRootInterpretation};
use crate::analysis::interpret::{
    IncompleteReason, InterpretationRoot, InterpretedFinding, InterpretedFindingKind,
    InterpretedSafetyCallKind, InterpretedTrace, InterpretedTraceStepKind,
};
use crate::analysis::ir::{
    CallEdgeKindIr, ContractRequirementIr, FunctionId, SourceFileId, SourceFileIr, SourceRangeIr,
    StableDefPathHash, StableInstanceHash,
};
use crate::analysis::source::cached_source_span;
use crate::config::SniffTestConfig;
use crate::namespace::canonical_namespace;
use crate::report_roots::{ReportRoot, ReportRootKind};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use super::super::findings::{
    DiagnosticMessage, Finding, FindingDiagnostic, FindingKind, FindingTraceStepOrder,
};
use super::super::report::render_span;
use super::typed_panic::{
    TypedPanicEvaluationError, TypedPanicIssueReport, TypedPanicLocalArtifact,
    TypedPanicRootReport, semantic_edge_label, semantic_edge_order,
};
use super::typed_panic_call::{
    TypedPanicCallBatchReport, TypedPanicCallEvaluationError,
    adapt_prevalidated_typed_panic_ambiguity_reports,
    adapt_prevalidated_typed_panic_call_completeness_batch,
    adapt_prevalidated_typed_panic_call_reports,
    adapt_prevalidated_typed_panic_root_contract_reports, evaluate_typed_panic_call_roots,
    preflight_typed_panic_call_batch,
};
use super::typed_safety::{
    TypedSafetyEvaluationError, adapt_typed_safety_authority_batch, evaluate_typed_safety_roots,
};

/// Atomic failure from typed panic evaluation or its report-v14 adapter.
#[derive(Debug)]
pub(super) enum InterpretWorkspaceError {
    TypedPanicEvaluation(TypedPanicEvaluationError),
    TypedPanicCallEvaluation(TypedPanicCallEvaluationError),
    TypedSafetyEvaluation(TypedSafetyEvaluationError),
    TypedSafetySourceFilesMismatch,
    TypedSafetyFunctionRangesMismatch,
    TypedReportCount {
        expected: usize,
        actual: usize,
    },
    TypedReportRootMismatch {
        index: usize,
        details: Box<TypedReportRootMismatch>,
    },
    TypedIssueRootMismatch {
        root_index: usize,
        issue_index: usize,
    },
    UnsupportedRendererOutput {
        root_index: usize,
        issue_index: usize,
        field: &'static str,
    },
}

#[derive(Debug)]
pub(super) struct TypedReportRootMismatch {
    expected_function: FunctionId,
    actual_function: FunctionId,
    expected_path: String,
    actual_path: String,
    expected_kind: ReportRootKind,
    actual_kind: ReportRootKind,
}

impl Display for InterpretWorkspaceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypedPanicEvaluation(source) => Display::fmt(source, formatter),
            Self::TypedPanicCallEvaluation(source) => Display::fmt(source, formatter),
            Self::TypedSafetyEvaluation(source) => Display::fmt(source, formatter),
            Self::TypedSafetySourceFilesMismatch => write!(
                formatter,
                "typed panic and safety evaluation produced different source-file inventories"
            ),
            Self::TypedSafetyFunctionRangesMismatch => write!(
                formatter,
                "typed panic and safety evaluation produced different function presentation inventories"
            ),
            Self::TypedReportCount { expected, actual } => write!(
                formatter,
                "typed panic evaluation returned {actual} root reports for {expected} traversal roots"
            ),
            Self::TypedReportRootMismatch { index, details } => write!(
                formatter,
                "typed panic root report {index} does not match its traversal root: expected {:?} `{}` ({:?}), got {:?} `{}` ({:?})",
                details.expected_function,
                details.expected_path,
                details.expected_kind,
                details.actual_function,
                details.actual_path,
                details.actual_kind,
            ),
            Self::TypedIssueRootMismatch {
                root_index,
                issue_index,
            } => write!(
                formatter,
                "typed panic issue {issue_index} in root report {root_index} belongs to a different evaluation root"
            ),
            Self::UnsupportedRendererOutput {
                root_index,
                issue_index,
                field,
            } => write!(
                formatter,
                "typed panic renderer for issue {issue_index} in root report {root_index} emitted unsupported `{field}` output"
            ),
        }
    }
}

impl Error for InterpretWorkspaceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TypedPanicEvaluation(source) => Some(source),
            Self::TypedPanicCallEvaluation(source) => Some(source),
            Self::TypedSafetyEvaluation(source) => Some(source),
            Self::TypedReportCount { .. }
            | Self::TypedSafetySourceFilesMismatch
            | Self::TypedSafetyFunctionRangesMismatch
            | Self::TypedReportRootMismatch { .. }
            | Self::TypedIssueRootMismatch { .. }
            | Self::UnsupportedRendererOutput { .. } => None,
        }
    }
}

impl From<TypedPanicEvaluationError> for InterpretWorkspaceError {
    fn from(source: TypedPanicEvaluationError) -> Self {
        Self::TypedPanicEvaluation(source)
    }
}

impl From<TypedPanicCallEvaluationError> for InterpretWorkspaceError {
    fn from(source: TypedPanicCallEvaluationError) -> Self {
        Self::TypedPanicCallEvaluation(source)
    }
}

impl From<TypedSafetyEvaluationError> for InterpretWorkspaceError {
    fn from(source: TypedSafetyEvaluationError) -> Self {
        Self::TypedSafetyEvaluation(source)
    }
}

#[derive(Clone, Copy)]
pub(super) struct InterpretWorkspaceRequest<'a, 'tcx> {
    pub(super) tcx: TyCtxt<'tcx>,
    pub(super) local: &'a ExtractedArtifactBundle,
    pub(super) local_artifact_id: Option<&'a RustcArtifactId>,
    pub(super) local_stable_crate_id: u64,
    pub(super) dependencies: &'a ArtifactAnalysisGraph,
    pub(super) active_runtime_artifacts: &'a [RustcArtifactId],
    pub(super) report_roots: &'a [ReportRoot<'tcx>],
    pub(super) config: &'a SniffTestConfig,
}

pub(super) fn interpret_workspace(
    request: InterpretWorkspaceRequest<'_, '_>,
) -> Result<Vec<Finding>, InterpretWorkspaceError> {
    let roots = request
        .report_roots
        .iter()
        .copied()
        .map(|root| interpretation_root(request.tcx, root))
        .collect::<Vec<_>>();
    let typed_local = request.local_artifact_id.map_or_else(
        || TypedPanicLocalArtifact::in_memory(&request.local.facts, request.local_stable_crate_id),
        |artifact| TypedPanicLocalArtifact::persisted(&request.local.facts, artifact),
    );
    let dependency_artifacts = request.dependencies.artifacts().collect::<Vec<_>>();
    let direct_dependencies = request
        .dependencies
        .direct_dependency_ids()
        .collect::<Vec<_>>();
    let mut typed_reports = evaluate_typed_panic_call_roots(
        typed_local,
        &dependency_artifacts,
        direct_dependencies.clone(),
        request.active_runtime_artifacts,
        &roots,
        request.config,
    )?;
    let mut typed_safety_reports = evaluate_typed_safety_roots(
        typed_local,
        &dependency_artifacts,
        direct_dependencies,
        request.active_runtime_artifacts,
        &roots,
        request.config,
    )?;
    let typed_source_files = std::mem::take(&mut typed_reports.source_files);
    let safety_source_files = std::mem::take(&mut typed_safety_reports.source_files);
    if typed_source_files != safety_source_files {
        return Err(InterpretWorkspaceError::TypedSafetySourceFilesMismatch);
    }
    let function_ranges = std::mem::take(&mut typed_reports.function_ranges);
    let safety_function_ranges = std::mem::take(&mut typed_safety_reports.function_ranges);
    if function_ranges != safety_function_ranges {
        return Err(InterpretWorkspaceError::TypedSafetyFunctionRangesMismatch);
    }
    let sources = SourceResolver {
        tcx: request.tcx,
        typed_source_files,
        function_ranges,
    };

    let mut findings = adapt_typed_panic_authority_batch(
        &sources,
        typed_reports,
        &roots,
        request.config.analysis.show_full_stack_trace,
    )?;
    findings.extend(adapt_typed_safety_authority_batch(
        &sources,
        &typed_safety_reports,
        &roots,
        request.config.analysis.show_full_stack_trace,
    )?);
    Ok(findings)
}

fn interpretation_root<'tcx>(tcx: TyCtxt<'tcx>, root: ReportRoot<'tcx>) -> InterpretationRoot {
    let definition = StableDefPathHash::from_def_id(tcx, root.def_id());
    let function = match root {
        ReportRoot::Concrete { instance } => {
            FunctionId::exact(definition, StableInstanceHash::from_instance(tcx, instance))
        }
        ReportRoot::Generic { .. } => FunctionId::generic(definition),
    };
    InterpretationRoot {
        function,
        path: canonical_namespace(tcx, root.def_id()),
        kind: root.kind(),
    }
}

#[cfg(test)]
struct LegacySafetyRemainder {
    findings: Vec<InterpretedFinding>,
    completeness: DomainCompleteness,
}

#[cfg(test)]
fn legacy_safety_remainder(result: Vec<SafetyRootInterpretation>) -> Vec<LegacySafetyRemainder> {
    result
        .into_iter()
        .map(|root| LegacySafetyRemainder {
            findings: root
                .findings
                .into_iter()
                .filter(|finding| legacy_safety_is_authoritative(&finding.kind))
                .collect(),
            completeness: root.completeness,
        })
        .collect()
}

#[cfg(test)]
const fn legacy_safety_is_authoritative(kind: &InterpretedFindingKind) -> bool {
    match kind {
        InterpretedFindingKind::PanicSink
        | InterpretedFindingKind::DocumentedPanic { .. }
        | InterpretedFindingKind::OpaquePanicBoundary { .. }
        | InterpretedFindingKind::AmbiguousPanicRequirement { .. }
        | InterpretedFindingKind::AmbiguousPanicMarker { .. } => false,
        InterpretedFindingKind::MissingSafetyDocs
        | InterpretedFindingKind::SafetyCall { .. }
        | InterpretedFindingKind::OpaqueSafetyBoundary { .. }
        | InterpretedFindingKind::UnsafeOperation { .. }
        | InterpretedFindingKind::AmbiguousSafetyRequirement { .. }
        | InterpretedFindingKind::AmbiguousSafetyMarker { .. } => true,
    }
}

/// Converts one complete typed panic batch to report-v14 findings.
///
/// Root alignment is validated for the whole batch before issue adaptation.
/// Any later renderer-output failure drops the locally accumulated vector and
/// returns one error, so callers can never observe partial typed findings.
#[cfg(test)]
pub(super) fn adapt_typed_panic_reports(
    sources: &impl FindingSources,
    reports: Vec<TypedPanicRootReport>,
    roots: &[InterpretationRoot],
    show_full_stack_trace: bool,
) -> Result<Vec<Finding>, InterpretWorkspaceError> {
    preflight_typed_panic_reports(&reports, roots)?;
    Ok(adapt_prevalidated_typed_panic_reports(
        sources,
        reports,
        show_full_stack_trace,
    ))
}

fn adapt_prevalidated_typed_panic_reports(
    sources: &impl FindingSources,
    reports: Vec<TypedPanicRootReport>,
    show_full_stack_trace: bool,
) -> Vec<Finding> {
    let capacity = reports.iter().map(|report| report.issues.len()).sum();
    let mut findings = Vec::with_capacity(capacity);
    for report in reports {
        for issue in &report.issues {
            findings.push(adapt_prevalidated_typed_panic_issue(
                sources,
                &report,
                issue,
                show_full_stack_trace,
            ));
        }
    }
    findings
}

/// Adapts every typed panic authority lane after one source-free batch preflight.
///
/// The preflight covers sparse missing-root preparation, every ready report
/// lane, fallible call DTO projection, and renderer-output compatibility before
/// the first source lookup. The returned vector is local until all lane
/// adapters succeed, so callers cannot observe a partial authority result.
pub(super) fn adapt_typed_panic_authority_batch(
    sources: &impl FindingSources,
    batch: TypedPanicCallBatchReport,
    roots: &[InterpretationRoot],
    show_full_stack_trace: bool,
) -> Result<Vec<Finding>, InterpretWorkspaceError> {
    let preflight = preflight_typed_panic_call_batch(&batch, roots)?;
    preflight_typed_panic_reports(&batch.compiler_asserts, &preflight.ready_roots)?;

    let completeness = adapt_prevalidated_typed_panic_call_completeness_batch(
        sources,
        &batch,
        show_full_stack_trace,
    );
    let TypedPanicCallBatchReport {
        compiler_asserts,
        roots: call_reports,
        root_contracts,
        ambiguities,
        ..
    } = batch;
    let mut findings =
        adapt_prevalidated_typed_panic_reports(sources, compiler_asserts, show_full_stack_trace);
    findings.extend(adapt_prevalidated_typed_panic_call_reports(
        sources,
        call_reports,
        &preflight.ready_roots,
        preflight.call_findings,
        show_full_stack_trace,
    ));
    findings.extend(adapt_prevalidated_typed_panic_root_contract_reports(
        sources,
        root_contracts,
        &preflight.ready_roots,
        show_full_stack_trace,
    ));
    findings.extend(adapt_prevalidated_typed_panic_ambiguity_reports(
        sources,
        ambiguities,
        &preflight.ready_roots,
        show_full_stack_trace,
    ));
    findings.extend(completeness);
    Ok(findings)
}

fn preflight_typed_panic_reports(
    reports: &[TypedPanicRootReport],
    roots: &[InterpretationRoot],
) -> Result<(), InterpretWorkspaceError> {
    validate_typed_report_roots(reports, roots)?;
    for (root_index, report) in reports.iter().enumerate() {
        for (issue_index, issue) in report.issues.iter().enumerate() {
            validate_supported_renderer_output(issue, root_index, issue_index)?;
        }
    }
    Ok(())
}

fn validate_typed_report_roots(
    reports: &[TypedPanicRootReport],
    roots: &[InterpretationRoot],
) -> Result<(), InterpretWorkspaceError> {
    if reports.len() != roots.len() {
        return Err(InterpretWorkspaceError::TypedReportCount {
            expected: roots.len(),
            actual: reports.len(),
        });
    }
    for (index, (report, root)) in reports.iter().zip(roots).enumerate() {
        if report.function != root.function || report.path != root.path || report.kind != root.kind
        {
            return Err(InterpretWorkspaceError::TypedReportRootMismatch {
                index,
                details: Box::new(TypedReportRootMismatch {
                    expected_function: root.function,
                    actual_function: report.function,
                    expected_path: root.path.clone(),
                    actual_path: report.path.clone(),
                    expected_kind: root.kind,
                    actual_kind: report.kind,
                }),
            });
        }
        for (issue_index, issue) in report.issues.iter().enumerate() {
            if issue.issue.context.root != report.root {
                return Err(InterpretWorkspaceError::TypedIssueRootMismatch {
                    root_index: index,
                    issue_index,
                });
            }
        }
    }
    Ok(())
}

fn adapt_prevalidated_typed_panic_issue(
    sources: &impl FindingSources,
    report: &TypedPanicRootReport,
    issue: &TypedPanicIssueReport,
    show_full_stack_trace: bool,
) -> Finding {
    let (effect_span, source_error) = sources.resolve(issue.presentation_range.as_ref());
    // Legacy root lookup intentionally discarded root-source failures. The
    // typed function presentation range retains the same verified identity,
    // so preserve that degradation behavior at the report-v14 boundary.
    let root_span = sources.resolve(report.presentation_range.as_ref()).0;
    let diagnostic_span = if source_error.is_some() {
        None
    } else {
        root_span.or(effect_span)
    };
    let trace = render_typed_panic_trace(sources, &issue.trace);
    let mut diagnostic = FindingDiagnostic {
        span: diagnostic_span,
        message: format!("function `{}` has an undocumented panic path", report.path),
        messages: Vec::new(),
    };
    if let Some(error) = source_error {
        diagnostic.messages.push(DiagnosticMessage::Note(format!(
            "the recorded source location was unavailable: {error}"
        )));
    }
    for note in &issue.diagnostic.notes {
        add_effect_note(&mut diagnostic, effect_span, note.clone());
    }
    add_typed_panic_trace_notes(
        sources,
        &mut diagnostic,
        report,
        root_span,
        issue,
        show_full_stack_trace,
    );
    add_typed_panic_help(sources, &mut diagnostic, effect_span, issue);

    Finding {
        root: Some(report.path.clone()),
        root_kind: Some(report.kind),
        root_span: root_span.map(|span| sources.render_span(span)),
        target: Some(issue.target.clone()),
        span: effect_span.map(|span| sources.render_span(span)),
        trace,
        ..Finding::new(
            FindingKind::CompilerAssert {
                compiler_assert_kind: issue.compiler_assert_kind,
            },
            issue.reason.clone(),
            diagnostic,
        )
    }
    .with_source_order(
        issue
            .presentation_range
            .as_ref()
            .and_then(|range| sources.source_file(range)),
        issue.presentation_range.as_ref(),
    )
    .with_trace_order(typed_panic_trace_order(sources, &issue.trace))
}

fn validate_supported_renderer_output(
    issue: &TypedPanicIssueReport,
    root_index: usize,
    issue_index: usize,
) -> Result<(), InterpretWorkspaceError> {
    for (unsupported, present) in [
        ("primary-anchor", issue.diagnostic.primary_anchor.is_some()),
        ("labels", !issue.diagnostic.labels.is_empty()),
        ("trace", !issue.diagnostic.trace.is_empty()),
    ] {
        if present {
            return Err(InterpretWorkspaceError::UnsupportedRendererOutput {
                root_index,
                issue_index,
                field: unsupported,
            });
        }
    }
    Ok(())
}

fn render_typed_panic_trace(
    sources: &impl FindingSources,
    trace: &CompilerAssertSemanticTrace,
) -> Vec<String> {
    trace
        .steps()
        .iter()
        .map(|step| {
            let summary = semantic_trace_summary(step);
            let range = semantic_step_range(step);
            sources
                .resolve(range.as_ref())
                .0
                .map_or(summary.clone(), |span| {
                    format!("{}: {summary}", sources.render_span(span))
                })
        })
        .collect()
}

fn typed_panic_trace_order(
    sources: &impl FindingSources,
    trace: &CompilerAssertSemanticTrace,
) -> Vec<FindingTraceStepOrder> {
    trace
        .steps()
        .iter()
        .map(|step| {
            let range = semantic_step_range(step);
            let caller = semantic_node_label(step.caller_role(), step.caller_display_path());
            FindingTraceStepOrder::new(
                range.as_ref().and_then(|range| sources.source_file(range)),
                range.as_ref(),
                (0, semantic_edge_order(step.edge())),
                &caller,
            )
        })
        .collect()
}

fn semantic_trace_summary(step: &CompilerAssertSemanticTraceStep) -> String {
    let caller = semantic_node_label(step.caller_role(), step.caller_display_path());
    let target = semantic_node_label(step.target_role(), step.target_display_path());
    format!("{caller} --{}-> {target}", semantic_edge_label(step.edge()))
}

fn semantic_node_label(role: CompilerAssertSemanticNodeRole, path: Option<&str>) -> String {
    match role {
        CompilerAssertSemanticNodeRole::Function | CompilerAssertSemanticNodeRole::Callable => {
            path.unwrap_or("unavailable function").to_owned()
        }
        CompilerAssertSemanticNodeRole::Macro => {
            format!("macro {}", path.unwrap_or("unavailable macro"))
        }
        CompilerAssertSemanticNodeRole::CompilerAssert(kind) => format!(
            "compiler assert {}",
            compiler_assert_presentation(kind)
                .public_kind()
                .human_description()
        ),
    }
}

fn semantic_step_range(step: &CompilerAssertSemanticTraceStep) -> Option<SourceRangeIr> {
    step.source_key().map(|anchor| SourceRangeIr {
        file: SourceFileId::new(anchor.file()),
        byte_start: anchor.byte_start(),
        byte_end: anchor.byte_end(),
    })
}

fn add_typed_panic_trace_notes(
    sources: &impl FindingSources,
    diagnostic: &mut FindingDiagnostic,
    report: &TypedPanicRootReport,
    root_span: Option<Span>,
    issue: &TypedPanicIssueReport,
    show_full_stack_trace: bool,
) {
    if issue.trace.steps().is_empty() {
        return;
    }
    if show_full_stack_trace {
        for (index, step) in issue.trace.steps().iter().rev().enumerate() {
            let note = format!("reachable step {index}: {}", semantic_trace_summary(step));
            let range = semantic_step_range(step);
            if let Some(span) = sources.resolve(range.as_ref()).0 {
                diagnostic
                    .messages
                    .push(DiagnosticMessage::SpanNote(span, note));
            } else {
                diagnostic.messages.push(DiagnosticMessage::Note(note));
            }
        }
    } else if issue.trace.steps().len() > 1 {
        let first = &issue.trace.steps()[0];
        let last = issue
            .trace
            .steps()
            .last()
            .expect("typed panic trace is non-empty");
        let caller = semantic_node_label(first.caller_role(), first.caller_display_path());
        let target = semantic_node_label(last.target_role(), last.target_display_path());
        diagnostic.messages.push(DiagnosticMessage::Note(format!(
            "reachable from `{caller}` to `{target}`"
        )));
        diagnostic.messages.push(DiagnosticMessage::Note(String::from(
            "set `show-full-stack-trace = true` under `[analysis]` in sniff-test.toml to show every reachability step",
        )));
    }
    let destination = format!(
        "a compiler assertion that may panic ({})",
        issue.compiler_assert_kind.human_description()
    );
    match root_span {
        Some(span) => diagnostic.messages.push(DiagnosticMessage::SpanNote(
            span,
            format!("this function can reach {destination}"),
        )),
        None => diagnostic.messages.push(DiagnosticMessage::Note(format!(
            "function `{}` can reach {destination}; its source location is unavailable",
            report.path
        ))),
    }
}

fn add_typed_panic_help(
    sources: &impl FindingSources,
    diagnostic: &mut FindingDiagnostic,
    effect_span: Option<Span>,
    issue: &TypedPanicIssueReport,
) {
    if let Some(entry_span) = issue.trace.steps().first().and_then(|step| {
        let range = semantic_step_range(step);
        sources.resolve(range.as_ref()).0
    }) && effect_span.is_some_and(|effect_span| !effect_span.source_equal(entry_span))
    {
        diagnostic.messages.push(DiagnosticMessage::SpanHelp(
            entry_span,
            String::from(
                "guard this path, or add `// PANIC:` here if a local invariant proves it cannot panic",
            ),
        ));
    }
    diagnostic.messages.extend(
        issue
            .diagnostic
            .help
            .iter()
            .cloned()
            .map(DiagnosticMessage::Help),
    );
}

fn adapt_finding(
    sources: &impl FindingSources,
    root: &InterpretationRoot,
    finding: &InterpretedFinding,
    show_full_stack_trace: bool,
) -> Finding {
    let target = match (&finding.kind, finding.target.as_ref()) {
        (InterpretedFindingKind::SafetyCall { .. }, Some(target)) if target.function.is_none() => {
            Some(String::from("unsafe function pointer"))
        }
        (
            InterpretedFindingKind::OpaquePanicBoundary { .. }
            | InterpretedFindingKind::OpaqueSafetyBoundary { .. },
            Some(target),
        ) if target.function.is_none() => None,
        (_, Some(target)) => Some(target.path.clone()),
        (_, None) => None,
    };
    let missing_requirements = finding
        .missing_requirements
        .iter()
        .map(render_requirement)
        .collect::<Vec<_>>();
    let requirements = finding
        .requirements
        .iter()
        .map(render_requirement)
        .collect::<Vec<_>>();
    let (kind, reason, message) = finding_description(finding, root, target.as_deref());
    let (recorded_span, source_error) = sources.resolve(finding.source_range.as_ref());
    let ambiguity_range = ambiguity_primary_range(finding);
    let effect_span = sources.resolve(ambiguity_range).0.or(recorded_span);
    let source_order_range = ambiguity_range.or(finding.source_range.as_ref());
    let root_span = sources.function_span(root.function);
    // A recorded cached location is only diagnostic evidence after source
    // verification succeeds. If it fails, keep reporting the interpreted
    // finding but do not substitute the workspace root as a misleading
    // primary location for an unavailable dependency effect.
    let diagnostic_span = if source_error.is_some() {
        None
    } else {
        diagnostic_primary_span(&finding.kind, root_span, effect_span)
    };
    let trace = render_trace(sources, &finding.trace);
    let function = public_function_path(finding);
    let mut diagnostic = FindingDiagnostic {
        span: diagnostic_span,
        message,
        messages: Vec::new(),
    };
    if let Some(error) = source_error {
        diagnostic.messages.push(DiagnosticMessage::Note(format!(
            "the recorded source location was unavailable: {error}"
        )));
    }
    decorate_finding(
        sources,
        &mut diagnostic,
        root,
        root_span,
        finding,
        effect_span,
        show_full_stack_trace,
    );

    Finding {
        root: Some(root.path.clone()),
        root_kind: Some(root.kind),
        root_span: root_span.map(|span| sources.render_span(span)),
        function,
        target,
        span: effect_span.map(|span| sources.render_span(span)),
        trace,
        missing_requirements,
        requirements,
        trusted_boundary: matches!(
            finding.kind,
            InterpretedFindingKind::SafetyCall { trusted: true, .. }
        ),
        ..Finding::new(kind, reason, diagnostic)
    }
    .with_source_order(
        source_order_range.and_then(|range| sources.source_file(range)),
        source_order_range,
    )
    .with_trace_order(finding_trace_order(sources, &finding.trace))
}

pub(super) fn adapt_typed_panic_call_finding(
    sources: &impl FindingSources,
    root: &InterpretationRoot,
    finding: &InterpretedFinding,
    show_full_stack_trace: bool,
) -> Finding {
    adapt_finding(sources, root, finding, show_full_stack_trace)
}

pub(super) fn adapt_typed_safety_incomplete_finding(
    sources: &impl FindingSources,
    root: &InterpretationRoot,
    reason: IncompleteReason,
    show_full_stack_trace: bool,
) -> Finding {
    adapt_incomplete(
        sources,
        root,
        FindingKind::SafetyAnalysisIncomplete,
        "safety",
        reason,
        show_full_stack_trace,
    )
}

pub(super) fn adapt_typed_panic_ambiguity_finding(
    sources: &impl FindingSources,
    root: &InterpretationRoot,
    finding: &InterpretedFinding,
    show_full_stack_trace: bool,
) -> Finding {
    adapt_finding(sources, root, finding, show_full_stack_trace)
}

pub(super) fn adapt_typed_panic_incomplete_finding(
    sources: &impl FindingSources,
    root: &InterpretationRoot,
    reason: IncompleteReason,
    show_full_stack_trace: bool,
) -> Finding {
    adapt_incomplete(
        sources,
        root,
        FindingKind::PanicAnalysisIncomplete,
        "panic",
        reason,
        show_full_stack_trace,
    )
}

fn public_function_path(finding: &InterpretedFinding) -> Option<String> {
    match &finding.kind {
        InterpretedFindingKind::AmbiguousSafetyRequirement { .. } => finding
            .target
            .as_ref()
            .map(|target| target.path.clone())
            .or_else(|| Some(finding.function_path.clone())),
        InterpretedFindingKind::MissingSafetyDocs
        | InterpretedFindingKind::SafetyCall { .. }
        | InterpretedFindingKind::OpaqueSafetyBoundary { .. }
        | InterpretedFindingKind::UnsafeOperation { .. }
        | InterpretedFindingKind::AmbiguousSafetyMarker { .. } => {
            Some(finding.function_path.clone())
        }
        InterpretedFindingKind::PanicSink
        | InterpretedFindingKind::DocumentedPanic { .. }
        | InterpretedFindingKind::OpaquePanicBoundary { .. }
        | InterpretedFindingKind::AmbiguousPanicRequirement { .. }
        | InterpretedFindingKind::AmbiguousPanicMarker { .. } => None,
    }
}

fn ambiguity_primary_range(finding: &InterpretedFinding) -> Option<&SourceRangeIr> {
    matches!(
        &finding.kind,
        InterpretedFindingKind::AmbiguousPanicRequirement { .. }
            | InterpretedFindingKind::AmbiguousSafetyRequirement { .. }
    )
    .then(|| {
        finding
            .requirements
            .first()
            .and_then(|requirement| requirement.source_range.as_ref())
    })
    .flatten()
}

#[allow(
    clippy::too_many_lines,
    reason = "keeping all finding variants together makes their output mapping easier to compare"
)]
fn finding_description(
    finding: &InterpretedFinding,
    root: &InterpretationRoot,
    target: Option<&str>,
) -> (FindingKind, String, String) {
    match &finding.kind {
        InterpretedFindingKind::PanicSink => {
            let target = target.unwrap_or("panic sink");
            (
                FindingKind::PanicInvocation,
                format!("panic sink {target}"),
                format!("function `{}` has an undocumented panic path", root.path),
            )
        }
        InterpretedFindingKind::DocumentedPanic { trusted } => {
            let target = target.unwrap_or("documented panic boundary");
            let (kind, label) = if *trusted {
                (FindingKind::TrustedPanic, "trusted")
            } else {
                (FindingKind::DocumentedPanic, "documented")
            };
            (
                kind,
                format!("{target} documents when it may panic under # Panics"),
                format!("function `{}` may panic through a {label} panic", root.path),
            )
        }
        InterpretedFindingKind::OpaquePanicBoundary { description } => {
            let boundary = opaque_boundary_summary(description, target).replace('`', "");
            (
                FindingKind::IndirectCallBoundary,
                format!("{boundary} cannot be verified"),
                format!(
                    "function `{}` reaches an unverifiable indirect call",
                    root.path
                ),
            )
        }
        InterpretedFindingKind::MissingSafetyDocs => (
            FindingKind::MissingSafetyDocs,
            format!(
                "public unsafe function `{}` is missing # Safety docs",
                finding.function_path
            ),
            format!(
                "public unsafe function `{}` is missing `# Safety` docs",
                finding.function_path
            ),
        ),
        InterpretedFindingKind::SafetyCall { kind, .. } => {
            let target = target.unwrap_or("unsafe function pointer");
            let requirements_missing = !finding.missing_requirements.is_empty();
            match (kind, requirements_missing) {
                (InterpretedSafetyCallKind::Unsafe, false) => (
                    FindingKind::UnsafeCallMissingJustification,
                    format!("unsafe call to `{target}` has no `// SAFETY:` justification"),
                    format!(
                        "unsafe call to `{target}` in `{}` is missing a `// SAFETY:` justification",
                        finding.function_path
                    ),
                ),
                (InterpretedSafetyCallKind::Unsafe, true) => (
                    FindingKind::UnsafeCallMissingRequirements,
                    format!("unsafe call to `{target}` does not satisfy all # Safety requirements"),
                    format!(
                        "unsafe call to `{target}` in `{}` does not satisfy all `# Safety` requirements",
                        finding.function_path
                    ),
                ),
                (InterpretedSafetyCallKind::Obligation, false) => (
                    FindingKind::SafetyObligationMissingJustification,
                    format!(
                        "safety-obligation call to `{target}` has no `// SAFETY:` justification"
                    ),
                    format!(
                        "safety-obligation call to `{target}` in `{}` is missing a `// SAFETY:` justification",
                        finding.function_path
                    ),
                ),
                (InterpretedSafetyCallKind::Obligation, true) => (
                    FindingKind::SafetyObligationMissingRequirements,
                    format!(
                        "safety-obligation call to `{target}` does not satisfy all # Safety requirements"
                    ),
                    format!(
                        "safety-obligation call to `{target}` in `{}` does not satisfy all `# Safety` requirements",
                        finding.function_path
                    ),
                ),
            }
        }
        InterpretedFindingKind::OpaqueSafetyBoundary { description } => {
            let boundary = opaque_boundary_summary(description, target).replace('`', "");
            (
                FindingKind::IndirectSafetyCallBoundary,
                format!("{boundary} has unverifiable safety requirements"),
                format!(
                    "function `{}` reaches an indirect call whose safety requirements cannot be verified",
                    root.path
                ),
            )
        }
        InterpretedFindingKind::UnsafeOperation { kind } => (
            FindingKind::UnsafeOpMissingJustification {
                safety_op_kind: *kind,
            },
            format!(
                "unsafe operation ({}) has no `// SAFETY:` justification",
                kind.label()
            ),
            format!(
                "unsafe operation ({}) in `{}` is missing a `// SAFETY:` justification",
                kind.label(),
                finding.function_path
            ),
        ),
        InterpretedFindingKind::AmbiguousPanicRequirement { normalized_name } => (
            FindingKind::AmbiguousPanicRequirement,
            format!(
                "`{}` has {} # Panics requirements named `{normalized_name}`",
                target.unwrap_or(&finding.function_path),
                finding.requirements.len()
            ),
            format!(
                "function `{}` reaches an ambiguous `# Panics` requirement name",
                root.path
            ),
        ),
        InterpretedFindingKind::AmbiguousSafetyRequirement { normalized_name } => (
            FindingKind::AmbiguousSafetyRequirement,
            format!(
                "`{}` has multiple # Safety requirements named `{normalized_name}`",
                target.unwrap_or(&finding.function_path)
            ),
            format!(
                "`{}` has an ambiguous `# Safety` requirement name",
                target.unwrap_or(&finding.function_path)
            ),
        ),
        InterpretedFindingKind::AmbiguousPanicMarker { effect_count } => (
            FindingKind::AmbiguousPanicMarker,
            format!("one `// PANIC:` marker applies to {effect_count} panic effect groups"),
            format!(
                "function `{}` has an ambiguous `// PANIC:` marker",
                finding.function_path
            ),
        ),
        InterpretedFindingKind::AmbiguousSafetyMarker { effect_count } => (
            FindingKind::AmbiguousSafetyMarker,
            format!("one `// SAFETY:` marker applies to {effect_count} safety effect groups"),
            format!(
                "function `{}` has an ambiguous `// SAFETY:` marker",
                finding.function_path
            ),
        ),
    }
}

fn diagnostic_primary_span(
    kind: &InterpretedFindingKind,
    root_span: Option<Span>,
    effect_span: Option<Span>,
) -> Option<Span> {
    match kind {
        InterpretedFindingKind::PanicSink | InterpretedFindingKind::OpaquePanicBoundary { .. } => {
            root_span.or(effect_span)
        }
        InterpretedFindingKind::DocumentedPanic { .. }
        | InterpretedFindingKind::MissingSafetyDocs
        | InterpretedFindingKind::SafetyCall { .. }
        | InterpretedFindingKind::OpaqueSafetyBoundary { .. }
        | InterpretedFindingKind::UnsafeOperation { .. }
        | InterpretedFindingKind::AmbiguousPanicRequirement { .. }
        | InterpretedFindingKind::AmbiguousSafetyRequirement { .. }
        | InterpretedFindingKind::AmbiguousPanicMarker { .. }
        | InterpretedFindingKind::AmbiguousSafetyMarker { .. } => effect_span.or(root_span),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the diagnostic variants stay together so their rustc UX remains directly comparable"
)]
fn decorate_finding(
    sources: &impl FindingSources,
    diagnostic: &mut FindingDiagnostic,
    root: &InterpretationRoot,
    root_span: Option<Span>,
    finding: &InterpretedFinding,
    effect_span: Option<Span>,
    show_full_stack_trace: bool,
) {
    match &finding.kind {
        InterpretedFindingKind::PanicSink => {
            let target = finding
                .target
                .as_ref()
                .map_or("panic sink", |target| target.path.as_str());
            add_effect_note(
                diagnostic,
                effect_span,
                format!("panic may happen here: panic sink `{target}`"),
            );
            add_finding_trace_notes(
                sources,
                diagnostic,
                root,
                root_span,
                finding,
                show_full_stack_trace,
            );
            add_panic_help(
                diagnostic,
                effect_span,
                trace_entry_span(sources, &finding.trace),
            );
        }
        InterpretedFindingKind::DocumentedPanic { .. } => {
            add_contract_note(sources, diagnostic, finding, "Panics");
            add_finding_trace_notes(
                sources,
                diagnostic,
                root,
                root_span,
                finding,
                show_full_stack_trace,
            );
            if let Some(span) = effect_span {
                diagnostic.messages.push(DiagnosticMessage::SpanHelp(
                    span,
                    String::from(
                        "add `// PANIC:` directly above this call explaining why its documented panic conditions cannot occur",
                    ),
                ));
            }
            if let Some(span) = sources.function_span(root.function) {
                diagnostic.messages.push(DiagnosticMessage::SpanHelp(
                    span,
                    String::from("document when this function may panic with `/// # Panics` here"),
                ));
            }
            add_missing_requirement_notes(diagnostic, &finding.missing_requirements, "panic");
            diagnostic.messages.push(DiagnosticMessage::Help(
                String::from(
                    "ensure the callee's panic conditions cannot occur, justify that with `// PANIC:`, or document when the caller may panic with `# Panics`",
                ),
            ));
        }
        InterpretedFindingKind::OpaquePanicBoundary { description } => {
            let target = finding
                .target
                .as_ref()
                .filter(|target| target.function.is_some())
                .map(|target| target.path.as_str());
            add_effect_note(
                diagnostic,
                effect_span,
                format!(
                    "panic behavior cannot be verified here: {}",
                    opaque_boundary_summary(description, target)
                ),
            );
            add_finding_trace_notes(
                sources,
                diagnostic,
                root,
                root_span,
                finding,
                show_full_stack_trace,
            );
            diagnostic.messages.push(DiagnosticMessage::Help(
                String::from(
                    "document this boundary with `# Panics`, add `// PANIC:` only if every possible callee is locally constrained, or configure `indirect-call-boundary` if this opacity is acceptable",
                ),
            ));
        }
        InterpretedFindingKind::MissingSafetyDocs => {
            diagnostic
                .messages
                .push(DiagnosticMessage::Help(String::from(
                    "document the caller obligations under a `# Safety` section",
                )));
        }
        InterpretedFindingKind::OpaqueSafetyBoundary { description } => {
            let target = finding
                .target
                .as_ref()
                .filter(|target| target.function.is_some())
                .map(|target| target.path.as_str());
            add_effect_note(
                diagnostic,
                effect_span,
                format!(
                    "safety requirements cannot be verified here: {}",
                    opaque_boundary_summary(description, target)
                ),
            );
            add_finding_trace_notes(
                sources,
                diagnostic,
                root,
                root_span,
                finding,
                show_full_stack_trace,
            );
            diagnostic.messages.push(DiagnosticMessage::Help(String::from(
                "replace the indirect call with a documented concrete boundary, justify every possible target, or configure `indirect-call-boundary` under `[safety.lints]`",
            )));
        }
        InterpretedFindingKind::SafetyCall { kind, .. } => {
            if matches!(kind, InterpretedSafetyCallKind::Obligation)
                || !finding.requirements.is_empty()
            {
                add_contract_note(sources, diagnostic, finding, "Safety");
            }
            if finding.missing_requirements.is_empty() {
                let help = match kind {
                    InterpretedSafetyCallKind::Unsafe => {
                        "add a `// SAFETY:` comment above the unsafe block or call site"
                    }
                    InterpretedSafetyCallKind::Obligation => {
                        "add a `// SAFETY:` comment directly above the call site"
                    }
                };
                diagnostic
                    .messages
                    .push(DiagnosticMessage::Help(help.to_owned()));
            } else {
                add_missing_requirement_notes(diagnostic, &finding.missing_requirements, "safety");
                diagnostic.messages.push(DiagnosticMessage::Help(
                    String::from(
                        "add named bullets under the applicable `// SAFETY:` comment for each missing requirement",
                    ),
                ));
            }
            add_finding_trace_notes(
                sources,
                diagnostic,
                root,
                root_span,
                finding,
                show_full_stack_trace,
            );
        }
        InterpretedFindingKind::UnsafeOperation { .. } => {
            diagnostic
                .messages
                .push(DiagnosticMessage::Help(String::from(
                    "add a `// SAFETY:` comment above the unsafe block or operation",
                )));
            add_finding_trace_notes(
                sources,
                diagnostic,
                root,
                root_span,
                finding,
                show_full_stack_trace,
            );
        }
        InterpretedFindingKind::AmbiguousPanicRequirement { normalized_name } => {
            add_ambiguous_requirement_notes(
                sources,
                diagnostic,
                finding,
                "Panics",
                normalized_name,
            );
            add_finding_trace_notes(
                sources,
                diagnostic,
                root,
                root_span,
                finding,
                show_full_stack_trace,
            );
            diagnostic.messages.push(DiagnosticMessage::Help(
                String::from(
                    "give each requirement a unique name, or set `ambiguous-panic-requirement = \"allow\"` under `[analysis.lints]`",
                ),
            ));
        }
        InterpretedFindingKind::AmbiguousSafetyRequirement { normalized_name } => {
            add_ambiguous_requirement_notes(
                sources,
                diagnostic,
                finding,
                "Safety",
                normalized_name,
            );
            add_finding_trace_notes(
                sources,
                diagnostic,
                root,
                root_span,
                finding,
                show_full_stack_trace,
            );
            diagnostic.messages.push(DiagnosticMessage::Help(
                String::from(
                    "give each requirement a unique name, or set `ambiguous-safety-requirement = \"allow\"` under `[analysis.lints]`",
                ),
            ));
        }
        InterpretedFindingKind::AmbiguousPanicMarker { effect_count } => {
            diagnostic.messages.push(DiagnosticMessage::Note(format!(
                "this marker applies to {effect_count} possible panics"
            )));
            add_finding_trace_notes(
                sources,
                diagnostic,
                root,
                root_span,
                finding,
                show_full_stack_trace,
            );
            diagnostic.messages.push(DiagnosticMessage::Help(
                String::from(
                    "move the marker directly above one obligation, split it into separate markers, or set `ambiguous-panic-marker = \"allow\"` under `[analysis.lints]`",
                ),
            ));
        }
        InterpretedFindingKind::AmbiguousSafetyMarker { effect_count } => {
            diagnostic.messages.push(DiagnosticMessage::Note(format!(
                "this marker applies to {effect_count} safety obligations"
            )));
            add_finding_trace_notes(
                sources,
                diagnostic,
                root,
                root_span,
                finding,
                show_full_stack_trace,
            );
            diagnostic.messages.push(DiagnosticMessage::Help(
                String::from(
                    "give each unsafe block or operation its own marker, or set `ambiguous-safety-marker = \"allow\"` under `[analysis.lints]`",
                ),
            ));
        }
    }
}

fn add_effect_note(diagnostic: &mut FindingDiagnostic, effect_span: Option<Span>, message: String) {
    if let Some(span) = effect_span {
        diagnostic
            .messages
            .push(DiagnosticMessage::SpanNote(span, message));
    } else {
        diagnostic.messages.push(DiagnosticMessage::Note(message));
    }
}

fn add_panic_help(
    diagnostic: &mut FindingDiagnostic,
    effect_span: Option<Span>,
    entry_span: Option<Span>,
) {
    if let Some(span) = entry_span
        && effect_span.is_some_and(|effect_span| !effect_span.source_equal(span))
    {
        diagnostic.messages.push(DiagnosticMessage::SpanHelp(
            span,
            String::from(
                "guard this path, or add `// PANIC:` here if a local invariant proves it cannot panic",
            ),
        ));
    }
    diagnostic.messages.push(DiagnosticMessage::Help(
        String::from(
            "add a guard, document the panic with `# Panics`, or add `// PANIC:` if a local invariant proves it cannot panic",
        ),
    ));
}

fn trace_entry_span(sources: &impl FindingSources, trace: &InterpretedTrace) -> Option<Span> {
    trace
        .steps
        .first()
        .and_then(|step| sources.resolve(step.source_range.as_ref()).0)
}

fn add_contract_note(
    sources: &impl FindingSources,
    diagnostic: &mut FindingDiagnostic,
    finding: &InterpretedFinding,
    heading: &str,
) {
    let Some(target) = &finding.target else {
        return;
    };
    let note = format!("`{}` documents `# {heading}` here", target.path);
    if let Some(span) = target
        .function
        .and_then(|function| sources.function_span(function))
        .or_else(|| {
            finding
                .requirements
                .first()
                .and_then(|requirement| sources.resolve(requirement.source_range.as_ref()).0)
        })
    {
        diagnostic
            .messages
            .push(DiagnosticMessage::SpanNote(span, note));
    } else {
        diagnostic.messages.push(DiagnosticMessage::Note(note));
    }
}

fn add_missing_requirement_notes(
    diagnostic: &mut FindingDiagnostic,
    requirements: &[ContractRequirementIr],
    domain: &str,
) {
    for requirement in requirements {
        let note = format!(
            "missing {domain} requirement `{}`",
            render_requirement(requirement)
        );
        diagnostic.messages.push(DiagnosticMessage::Note(note));
    }
}

fn add_ambiguous_requirement_notes(
    sources: &impl FindingSources,
    diagnostic: &mut FindingDiagnostic,
    finding: &InterpretedFinding,
    heading: &str,
    normalized_name: &str,
) {
    let target = finding
        .target
        .as_ref()
        .map_or(finding.function_path.as_str(), |target| {
            target.path.as_str()
        });
    diagnostic.messages.push(DiagnosticMessage::Note(format!(
        "`{target}` has multiple `# {heading}` requirements that normalize to `{normalized_name}`"
    )));
    for requirement in &finding.requirements {
        let label = format!(
            "`{}` normalizes to `{normalized_name}`",
            render_requirement(requirement)
        );
        if let Some(span) = sources.resolve(requirement.source_range.as_ref()).0 {
            diagnostic
                .messages
                .push(DiagnosticMessage::SpanLabel(span, label));
        } else {
            diagnostic.messages.push(DiagnosticMessage::Note(label));
        }
    }
}

fn opaque_boundary_summary<'a>(description: &'a str, target: Option<&'a str>) -> String {
    if description.starts_with("indirect call") {
        target.map_or_else(
            || description.to_owned(),
            |target| format!("indirect call to undocumented trait method `{target}`"),
        )
    } else {
        description.to_owned()
    }
}

fn adapt_incomplete(
    sources: &impl FindingSources,
    root: &InterpretationRoot,
    kind: FindingKind,
    domain: &str,
    reason: IncompleteReason,
    show_full_stack_trace: bool,
) -> Finding {
    let (target, range, trace, reason, message, body_missing_at_root) = match reason {
        IncompleteReason::NodeLimit { limit } => (
            None,
            None,
            InterpretedTrace { steps: Vec::new() },
            format!("{domain} analysis reached the configured node limit ({limit})"),
            format!(
                "function `{}` exceeded the {domain} analysis node limit ({limit})",
                root.path
            ),
            false,
        ),
        IncompleteReason::MissingBody {
            function,
            path,
            source_range,
            trace,
        } => {
            let body_missing_at_root = function == root.function && trace.steps.is_empty();
            let message =
                missing_body_diagnostic_message(&root.path, &path, domain, body_missing_at_root);
            (
                Some(path.clone()),
                source_range,
                trace,
                format!("{domain} analysis could not load the body for `{path}`"),
                message,
                body_missing_at_root,
            )
        }
    };
    let (effect_span, source_error) = sources.resolve(range.as_ref());
    let root_span = sources.function_span(root.function);
    let rendered_trace = render_trace(sources, &trace);
    let trace_order = finding_trace_order(sources, &trace);
    let mut diagnostic = FindingDiagnostic {
        span: if source_error.is_some() {
            None
        } else {
            root_span.or(effect_span)
        },
        message,
        messages: Vec::new(),
    };
    if let Some(error) = source_error {
        diagnostic.messages.push(DiagnosticMessage::Note(format!(
            "the recorded source location was unavailable: {error}"
        )));
    }
    add_incomplete_reason_note(
        &mut diagnostic,
        target.as_deref(),
        effect_span,
        body_missing_at_root,
        domain,
    );
    let trace_destination = target.as_ref().map_or_else(
        || format!("code that could not be fully inspected during {domain} analysis"),
        |target| {
            let subject = incomplete_analysis_subject(domain);
            format!("the function `{target}`, whose body could not be inspected for {subject}")
        },
    );
    add_trace_notes(
        sources,
        &mut diagnostic,
        root,
        root_span,
        &trace,
        &trace_destination,
        show_full_stack_trace,
    );
    Finding {
        root: Some(root.path.clone()),
        root_kind: Some(root.kind),
        root_span: root_span.map(|span| sources.render_span(span)),
        target,
        span: effect_span.map(|span| sources.render_span(span)),
        trace: rendered_trace,
        ..Finding::new(kind, reason, diagnostic)
    }
    .with_source_order(
        range.as_ref().and_then(|range| sources.source_file(range)),
        range.as_ref(),
    )
    .with_trace_order(trace_order)
}

fn add_incomplete_reason_note(
    diagnostic: &mut FindingDiagnostic,
    target: Option<&str>,
    effect_span: Option<Span>,
    body_missing_at_root: bool,
    domain: &str,
) {
    match (target, effect_span, body_missing_at_root) {
        (Some(target), Some(span), true) => {
            diagnostic.messages.push(DiagnosticMessage::SpanNote(
                span,
                format!("the body for `{target}` was unavailable to {domain} analysis here"),
            ));
        }
        (Some(target), None, true) => {
            diagnostic.messages.push(DiagnosticMessage::Note(format!(
                "the body for `{target}` was unavailable to {domain} analysis"
            )));
        }
        (Some(target), Some(span), false) => {
            diagnostic.messages.push(DiagnosticMessage::SpanNote(
                span,
                format!("{domain} analysis could not continue through `{target}` here"),
            ));
        }
        (Some(target), None, false) => diagnostic.messages.push(DiagnosticMessage::Note(format!(
            "{domain} analysis could not continue through `{target}`"
        ))),
        (None, _, _) => diagnostic.messages.push(DiagnosticMessage::Help(
            String::from(
                "raise `node-limit` under `[analysis]` in sniff-test.toml, or shrink the traversal by trusting or ignoring namespaces",
            ),
        )),
    }
}

fn missing_body_diagnostic_message(
    root: &str,
    target: &str,
    domain: &str,
    body_missing_at_root: bool,
) -> String {
    let subject = incomplete_analysis_subject(domain);
    if body_missing_at_root {
        format!(
            "function `{root}` could not be checked for {subject} because its body was unavailable"
        )
    } else {
        format!(
            "function `{root}` reaches `{target}`, whose body could not be checked for {subject}"
        )
    }
}

fn incomplete_analysis_subject(domain: &str) -> &'static str {
    match domain {
        "panic" => "possible panics",
        "safety" => "unsafe operations",
        _ => "the reported effects",
    }
}

fn render_trace(sources: &impl FindingSources, trace: &InterpretedTrace) -> Vec<String> {
    trace
        .steps
        .iter()
        .map(|step| {
            let target = step.target_path.as_deref().unwrap_or("opaque boundary");
            let edge = format!(
                "{} --{}-> {target}",
                step.caller_path,
                trace_step_kind_label(step.kind)
            );
            sources
                .resolve(step.source_range.as_ref())
                .0
                .map_or(edge.clone(), |span| {
                    format!("{}: {edge}", sources.render_span(span))
                })
        })
        .collect()
}

fn finding_trace_order(
    sources: &impl FindingSources,
    trace: &InterpretedTrace,
) -> Vec<FindingTraceStepOrder> {
    trace
        .steps
        .iter()
        .map(|step| {
            FindingTraceStepOrder::new(
                step.source_range
                    .as_ref()
                    .and_then(|range| sources.source_file(range)),
                step.source_range.as_ref(),
                trace_step_kind_order(step.kind),
                &step.caller_path,
            )
        })
        .collect()
}

const fn trace_step_kind_order(kind: InterpretedTraceStepKind) -> (u8, u8) {
    match kind {
        InterpretedTraceStepKind::Reachability(kind) => (0, edge_kind_order(kind)),
        InterpretedTraceStepKind::UnsafeOperation(kind) => (1, safety_op_kind_order(kind)),
    }
}

const fn edge_kind_order(kind: CallEdgeKindIr) -> u8 {
    match kind {
        CallEdgeKindIr::DirectCall => 0,
        CallEdgeKindIr::TailCall => 1,
        CallEdgeKindIr::FnPointerReify => 2,
        CallEdgeKindIr::ClosureFnPointerReify => 3,
        CallEdgeKindIr::FnPointerCallTarget => 4,
        CallEdgeKindIr::DynObjectCast => 5,
        CallEdgeKindIr::VTableEntry => 6,
        CallEdgeKindIr::DynDispatchVTableEntry => 7,
        CallEdgeKindIr::MacroExpansion => 8,
        CallEdgeKindIr::ConstBody => 9,
        CallEdgeKindIr::CoroutineBody => 10,
        CallEdgeKindIr::Assert => 11,
        CallEdgeKindIr::IndirectCall => 12,
    }
}

const fn safety_op_kind_order(kind: crate::safety::SafetyOpKind) -> u8 {
    match kind {
        crate::safety::SafetyOpKind::DerefRawPointer => 0,
        crate::safety::SafetyOpKind::UseOfMutableStatic => 1,
        crate::safety::SafetyOpKind::UseOfExternStatic => 2,
        crate::safety::SafetyOpKind::AccessToUnionField => 3,
        crate::safety::SafetyOpKind::UseOfUnsafeField => 4,
        crate::safety::SafetyOpKind::InitializingLayoutConstrainedType => 5,
        crate::safety::SafetyOpKind::InitializingTypeWithUnsafeField => 6,
        crate::safety::SafetyOpKind::MutationOfLayoutConstrainedField => 7,
        crate::safety::SafetyOpKind::BorrowOfLayoutConstrainedField => 8,
        crate::safety::SafetyOpKind::InlineAssembly => 9,
        crate::safety::SafetyOpKind::UnsafeBinderCast => 10,
    }
}

fn add_finding_trace_notes(
    sources: &impl FindingSources,
    diagnostic: &mut FindingDiagnostic,
    root: &InterpretationRoot,
    root_span: Option<Span>,
    finding: &InterpretedFinding,
    show_full_stack_trace: bool,
) {
    let destination = trace_destination(finding);
    add_trace_notes(
        sources,
        diagnostic,
        root,
        root_span,
        &finding.trace,
        &destination,
        show_full_stack_trace,
    );
}

fn trace_destination(finding: &InterpretedFinding) -> String {
    match &finding.kind {
        InterpretedFindingKind::PanicSink => String::from("a panic invocation"),
        InterpretedFindingKind::DocumentedPanic { trusted: false } => {
            String::from("a call with `# Panics` documentation")
        }
        InterpretedFindingKind::DocumentedPanic { trusted: true } => {
            String::from("a trusted panic boundary with `# Panics` documentation")
        }
        InterpretedFindingKind::OpaquePanicBoundary { .. } => {
            String::from("a call whose panic behavior cannot be verified")
        }
        InterpretedFindingKind::OpaqueSafetyBoundary { .. } => {
            String::from("a call whose safety requirements cannot be verified")
        }
        InterpretedFindingKind::MissingSafetyDocs => {
            String::from("a public unsafe function without `# Safety` documentation")
        }
        InterpretedFindingKind::SafetyCall {
            kind: InterpretedSafetyCallKind::Unsafe,
            ..
        } if finding.missing_requirements.is_empty() => {
            String::from("an unsafe call without a `// SAFETY:` justification")
        }
        InterpretedFindingKind::SafetyCall {
            kind: InterpretedSafetyCallKind::Unsafe,
            ..
        } => String::from(
            "an unsafe call whose documented `# Safety` requirements are not all satisfied",
        ),
        InterpretedFindingKind::SafetyCall {
            kind: InterpretedSafetyCallKind::Obligation,
            ..
        } if finding.missing_requirements.is_empty() => {
            String::from("a call with `# Safety` documentation but no `// SAFETY:` justification")
        }
        InterpretedFindingKind::SafetyCall {
            kind: InterpretedSafetyCallKind::Obligation,
            ..
        } => String::from("a call whose documented `# Safety` requirements are not all satisfied"),
        InterpretedFindingKind::UnsafeOperation { kind } => format!(
            "an unsafe operation ({}) without a `// SAFETY:` justification",
            kind.label()
        ),
        InterpretedFindingKind::AmbiguousPanicRequirement { normalized_name } => {
            format!(
                "a call whose `# Panics` contract contains multiple requirements with names that normalize to `{normalized_name}`"
            )
        }
        InterpretedFindingKind::AmbiguousSafetyRequirement { normalized_name } => {
            format!(
                "a call whose `# Safety` contract contains multiple requirements with names that normalize to `{normalized_name}`"
            )
        }
        InterpretedFindingKind::AmbiguousPanicMarker { effect_count } => {
            format!("{effect_count} possible panics covered by the same `// PANIC:` marker")
        }
        InterpretedFindingKind::AmbiguousSafetyMarker { effect_count } => {
            format!("{effect_count} safety obligations covered by the same `// SAFETY:` marker")
        }
    }
}

fn add_trace_notes(
    sources: &impl FindingSources,
    diagnostic: &mut FindingDiagnostic,
    root: &InterpretationRoot,
    root_span: Option<Span>,
    trace: &InterpretedTrace,
    destination: &str,
    show_full_stack_trace: bool,
) {
    if trace.steps.is_empty() {
        return;
    }

    if show_full_stack_trace {
        for (index, step) in trace.steps.iter().rev().enumerate() {
            let note = format!("reachable step {index}: {}", render_trace_step(step));
            if let Some(span) = sources.resolve(step.source_range.as_ref()).0 {
                diagnostic
                    .messages
                    .push(DiagnosticMessage::SpanNote(span, note));
            } else {
                diagnostic.messages.push(DiagnosticMessage::Note(note));
            }
        }
    } else if trace.steps.len() > 1 {
        let first = &trace.steps[0];
        let last = trace.steps.last().expect("trace is non-empty");
        let target = last
            .target_path
            .as_deref()
            .unwrap_or("an opaque call boundary");
        diagnostic.messages.push(DiagnosticMessage::Note(format!(
            "reachable from `{}` to `{target}`",
            first.caller_path
        )));
        diagnostic.messages.push(DiagnosticMessage::Note(String::from(
            "set `show-full-stack-trace = true` under `[analysis]` in sniff-test.toml to show every reachability step",
        )));
    }

    match root_span {
        Some(span) => diagnostic.messages.push(DiagnosticMessage::SpanNote(
            span,
            format!("this function can reach {destination}"),
        )),
        None => diagnostic.messages.push(DiagnosticMessage::Note(format!(
            "function `{}` can reach {destination}; its source location is unavailable",
            root.path
        ))),
    }
}

fn render_trace_step(step: &crate::analysis::interpret::InterpretedTraceStep) -> String {
    let target = step.target_path.as_deref().unwrap_or("opaque boundary");
    format!(
        "{} --{}-> {target}",
        step.caller_path,
        trace_step_kind_label(step.kind)
    )
}

const fn trace_step_kind_label(kind: InterpretedTraceStepKind) -> &'static str {
    match kind {
        InterpretedTraceStepKind::Reachability(kind) => edge_kind_label(kind),
        InterpretedTraceStepKind::UnsafeOperation(_) => "unsafe-operation",
    }
}

const fn edge_kind_label(kind: CallEdgeKindIr) -> &'static str {
    match kind {
        CallEdgeKindIr::DirectCall => "direct-call",
        CallEdgeKindIr::TailCall => "tail-call",
        CallEdgeKindIr::FnPointerReify => "fn-pointer-reify",
        CallEdgeKindIr::ClosureFnPointerReify => "closure-fn-pointer-reify",
        CallEdgeKindIr::FnPointerCallTarget => "fn-pointer-call-target",
        CallEdgeKindIr::DynObjectCast => "dyn-object-cast",
        CallEdgeKindIr::VTableEntry => "vtable-entry",
        CallEdgeKindIr::DynDispatchVTableEntry => "dyn-dispatch-vtable-entry",
        CallEdgeKindIr::MacroExpansion => "macro-expansion",
        CallEdgeKindIr::ConstBody => "const-body",
        CallEdgeKindIr::CoroutineBody => "coroutine-body",
        CallEdgeKindIr::Assert => "assert",
        CallEdgeKindIr::IndirectCall => "indirect-call",
    }
}

fn render_requirement(requirement: &ContractRequirementIr) -> String {
    if requirement.condition.is_empty() {
        requirement.name.clone()
    } else {
        format!("{}: {}", requirement.name, requirement.condition)
    }
}

struct SourceResolver<'tcx> {
    tcx: TyCtxt<'tcx>,
    typed_source_files: Vec<SourceFileIr>,
    function_ranges: BTreeMap<FunctionId, SourceRangeIr>,
}

/// Source-verification boundary shared by legacy and typed finding adapters.
///
/// Keeping the adapter generic makes report conversion pure and lets parity
/// tests exercise identical verified/degraded span behavior without a `TyCtxt`.
pub(super) trait FindingSources {
    fn function_span(&self, function: FunctionId) -> Option<Span>;

    fn resolve(&self, range: Option<&SourceRangeIr>) -> (Option<Span>, Option<String>);

    fn source_file<'a>(&'a self, range: &SourceRangeIr) -> Option<&'a SourceFileIr>;

    fn render_span(&self, span: Span) -> String;
}

impl FindingSources for SourceResolver<'_> {
    fn function_span(&self, function: FunctionId) -> Option<Span> {
        let range = function
            .resolution_candidates()
            .find_map(|candidate| self.function_ranges.get(&candidate));
        self.resolve(range).0
    }

    fn resolve(&self, range: Option<&SourceRangeIr>) -> (Option<Span>, Option<String>) {
        let Some(range) = range else {
            return (None, None);
        };
        let Some(source) = self.source_file(range) else {
            return (
                None,
                Some(format!(
                    "source file identity `{}` is absent from the composed artifact graph",
                    range.file.as_str()
                )),
            );
        };
        match cached_source_span(self.tcx, source, range) {
            Ok(span) => (Some(span), None),
            Err(error) => (None, Some(error.to_string())),
        }
    }

    fn source_file(&self, range: &SourceRangeIr) -> Option<&SourceFileIr> {
        self.typed_source_files
            .binary_search_by(|source| source.id.cmp(&range.file))
            .ok()
            .map(|index| &self.typed_source_files[index])
    }

    fn render_span(&self, span: Span) -> String {
        render_span(self.tcx, span)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FindingSources, InterpretWorkspaceError, TypedPanicRootReport, adapt_typed_panic_reports,
        legacy_safety_remainder, missing_body_diagnostic_message,
    };
    use crate::analysis::facts::encoded::EntityRef;
    use crate::analysis::facts::evaluation::{DomainId, EvaluationRoot};
    use crate::analysis::facts::program::FunctionEntity;
    use crate::analysis::facts::schema::{RowSchema, SchemaId};
    use crate::analysis::facts::workspace::{ArtifactScopeId, ScopedEntityRef};
    use crate::analysis::interpret::{
        DomainCompleteness, IncompleteReason, InterpretationRoot, InterpretedFinding,
        InterpretedFindingKind, InterpretedSafetyCallKind, InterpretedTrace,
        SafetyRootInterpretation,
    };
    use crate::analysis::ir::{FunctionId, SourceFileIr, SourceRangeIr, StableDefPathHash};
    use crate::report_roots::ReportRootKind;
    use crate::safety::SafetyOpKind;
    use rustc_span::Span;

    struct NoSources;

    impl FindingSources for NoSources {
        fn function_span(&self, _function: FunctionId) -> Option<Span> {
            None
        }

        fn resolve(&self, _range: Option<&SourceRangeIr>) -> (Option<Span>, Option<String>) {
            (None, None)
        }

        fn source_file<'a>(&'a self, _range: &SourceRangeIr) -> Option<&'a SourceFileIr> {
            None
        }

        fn render_span(&self, _span: Span) -> String {
            String::from("unreachable test span")
        }
    }

    fn function(local: u64) -> FunctionId {
        let definition =
            serde_json::from_str::<StableDefPathHash>(&format!("\"{:016x}{local:016x}\"", 1_u64))
                .expect("valid stable definition hash");
        FunctionId::generic(definition)
    }

    fn root(function: FunctionId, path: &str) -> InterpretationRoot {
        InterpretationRoot {
            function,
            path: path.to_owned(),
            kind: ReportRootKind::Generic,
        }
    }

    fn empty_report(root: &InterpretationRoot, row: u32) -> TypedPanicRootReport {
        let evaluation_root = EvaluationRoot::new(
            DomainId::new("sniff-test.test.typed-report-alignment").expect("valid test domain"),
            ScopedEntityRef::new(
                ArtifactScopeId::for_in_memory(1, 0),
                EntityRef {
                    schema: SchemaId::new(FunctionEntity::ID).expect("valid function schema"),
                    row,
                },
            ),
        );
        TypedPanicRootReport {
            root: evaluation_root,
            function: root.function,
            path: root.path.clone(),
            kind: root.kind,
            presentation_range: None,
            issues: Vec::new(),
        }
    }

    fn legacy_finding(function: FunctionId, kind: InterpretedFindingKind) -> InterpretedFinding {
        InterpretedFinding {
            kind,
            function,
            function_path: String::from("fixture::root"),
            target: None,
            source_range: None,
            trace: InterpretedTrace { steps: Vec::new() },
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
        }
    }

    #[test]
    fn legacy_remainder_exhaustively_retains_only_safety_authority() {
        let function = function(9);
        let requested_root = root(function, "fixture::root");
        let findings = vec![
            legacy_finding(function, InterpretedFindingKind::PanicSink),
            legacy_finding(
                function,
                InterpretedFindingKind::DocumentedPanic { trusted: false },
            ),
            legacy_finding(
                function,
                InterpretedFindingKind::OpaquePanicBoundary {
                    description: String::from("opaque"),
                },
            ),
            legacy_finding(
                function,
                InterpretedFindingKind::AmbiguousPanicRequirement {
                    normalized_name: String::from("ready"),
                },
            ),
            legacy_finding(
                function,
                InterpretedFindingKind::AmbiguousPanicMarker { effect_count: 2 },
            ),
            legacy_finding(function, InterpretedFindingKind::MissingSafetyDocs),
            legacy_finding(
                function,
                InterpretedFindingKind::SafetyCall {
                    kind: InterpretedSafetyCallKind::Unsafe,
                    trusted: false,
                },
            ),
            legacy_finding(
                function,
                InterpretedFindingKind::UnsafeOperation {
                    kind: SafetyOpKind::DerefRawPointer,
                },
            ),
            legacy_finding(
                function,
                InterpretedFindingKind::AmbiguousSafetyRequirement {
                    normalized_name: String::from("valid"),
                },
            ),
            legacy_finding(
                function,
                InterpretedFindingKind::AmbiguousSafetyMarker { effect_count: 2 },
            ),
        ];
        let result = SafetyRootInterpretation {
            root: requested_root,
            findings,
            completeness: DomainCompleteness {
                complete: false,
                visited_bodies: 2,
                reasons: vec![IncompleteReason::NodeLimit { limit: 12 }],
            },
        };

        let remainder = legacy_safety_remainder(vec![result]);
        let [remainder] = remainder.as_slice() else {
            panic!("one legacy root must produce one safety remainder");
        };
        assert_eq!(remainder.findings.len(), 5);
        assert!(matches!(
            remainder.findings.as_slice(),
            [
                InterpretedFinding {
                    kind: InterpretedFindingKind::MissingSafetyDocs,
                    ..
                },
                InterpretedFinding {
                    kind: InterpretedFindingKind::SafetyCall { .. },
                    ..
                },
                InterpretedFinding {
                    kind: InterpretedFindingKind::UnsafeOperation { .. },
                    ..
                },
                InterpretedFinding {
                    kind: InterpretedFindingKind::AmbiguousSafetyRequirement { .. },
                    ..
                },
                InterpretedFinding {
                    kind: InterpretedFindingKind::AmbiguousSafetyMarker { .. },
                    ..
                },
            ]
        ));
        assert_eq!(
            remainder.completeness.reasons,
            [IncompleteReason::NodeLimit { limit: 12 }]
        );
        assert_eq!(remainder.completeness.visited_bodies, 2);
    }

    #[test]
    fn missing_body_diagnostics_distinguish_the_root_from_a_reachable_target() {
        assert_eq!(
            missing_body_diagnostic_message("app::root", "app::root", "panic", true),
            "function `app::root` could not be checked for possible panics because its body was unavailable"
        );
        assert_eq!(
            missing_body_diagnostic_message("app::root", "dep::helper", "safety", false),
            "function `app::root` reaches `dep::helper`, whose body could not be checked for unsafe operations"
        );
    }

    #[test]
    fn typed_adapter_rejects_wrong_root_count_and_reordered_reports() {
        let first = root(function(1), "fixture::first");
        let second = root(function(2), "fixture::second");
        let roots = [first.clone(), second.clone()];

        let count_error =
            adapt_typed_panic_reports(&NoSources, vec![empty_report(&first, 0)], &roots, false)
                .expect_err("the report count is validated before adaptation");
        assert!(matches!(
            count_error,
            InterpretWorkspaceError::TypedReportCount {
                expected: 2,
                actual: 1
            }
        ));

        let order_error = adapt_typed_panic_reports(
            &NoSources,
            vec![empty_report(&second, 1), empty_report(&first, 0)],
            &roots,
            false,
        )
        .expect_err("same-sized reports must retain exact request order");
        assert!(matches!(
            order_error,
            InterpretWorkspaceError::TypedReportRootMismatch { index: 0, .. }
        ));
    }
}
