//! Adapts policy-neutral interpreter output to diagnostics and JSON findings.

use crate::analysis::graph::ArtifactAnalysisGraph;
use crate::analysis::interpret::{
    InMemoryArtifactLookup, IncompleteReason, InterpretationRoot, InterpretedFinding,
    InterpretedFindingKind, InterpretedSafetyCallKind, InterpretedTrace, InterpretedTraceStepKind,
    LayeredFunctionLookup, RootInterpretation, interpret,
};
use crate::analysis::ir::{
    ArtifactAnalysisIr, CallEdgeKindIr, ContractRequirementIr, FunctionBodyIr, FunctionId,
    SourceFileIr, SourceRangeIr, StableDefPathHash, StableInstanceHash,
};
use crate::analysis::source::cached_source_span;
use crate::config::SniffTestConfig;
use crate::namespace::canonical_namespace;
use crate::report_roots::ReportRoot;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use super::super::findings::{
    DiagnosticMessage, Finding, FindingDiagnostic, FindingKind, FindingTraceStepOrder,
};
use super::super::report::render_span;

pub(super) fn interpret_workspace<'tcx>(
    tcx: TyCtxt<'tcx>,
    local: &ArtifactAnalysisIr,
    local_stable_crate_id: u64,
    dependencies: &ArtifactAnalysisGraph,
    report_roots: &[ReportRoot<'tcx>],
    config: &SniffTestConfig,
) -> Vec<Finding> {
    let roots = report_roots
        .iter()
        .copied()
        .map(|root| interpretation_root(tcx, root))
        .collect::<Vec<_>>();
    let local_lookup = InMemoryArtifactLookup::new(local, local_stable_crate_id);
    let lookup = LayeredFunctionLookup::new(vec![&local_lookup, dependencies]);
    let result = interpret(&lookup, &roots, config);
    let sources = SourceResolver {
        tcx,
        local,
        dependencies,
    };

    adapt_result(&sources, result, config.analysis.show_full_stack_trace)
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

fn adapt_result(
    sources: &SourceResolver<'_, '_>,
    result: Vec<RootInterpretation>,
    show_full_stack_trace: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for root in result {
        findings.extend(
            root.findings
                .into_iter()
                .map(|finding| adapt_finding(sources, &root.root, &finding, show_full_stack_trace)),
        );
        for reason in root.completeness.panic.reasons {
            findings.push(adapt_incomplete(
                sources,
                &root.root,
                FindingKind::PanicAnalysisIncomplete,
                "panic",
                reason,
                show_full_stack_trace,
            ));
        }
        for reason in root.completeness.safety.reasons {
            findings.push(adapt_incomplete(
                sources,
                &root.root,
                FindingKind::SafetyAnalysisIncomplete,
                "safety",
                reason,
                show_full_stack_trace,
            ));
        }
    }
    findings
}

fn adapt_finding(
    sources: &SourceResolver<'_, '_>,
    root: &InterpretationRoot,
    finding: &InterpretedFinding,
    show_full_stack_trace: bool,
) -> Finding {
    let target = match (&finding.kind, finding.target.as_ref()) {
        (InterpretedFindingKind::SafetyCall { .. }, Some(target)) if target.function.is_none() => {
            Some(String::from("unsafe function pointer"))
        }
        (InterpretedFindingKind::OpaquePanicBoundary { .. }, Some(target))
            if target.function.is_none() =>
        {
            None
        }
        (_, Some(target)) => Some(target.path.clone()),
        (_, None) => None,
    }
    .or_else(|| match &finding.kind {
        InterpretedFindingKind::CompilerAssert { kind } => {
            Some(format!("compiler assert {}", kind.human_description()))
        }
        _ => None,
    });
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
        root_span: root_span.map(|span| render_span(sources.tcx, span)),
        function,
        target,
        span: effect_span.map(|span| render_span(sources.tcx, span)),
        trace,
        missing_requirements,
        requirements,
        ..Finding::new(kind, reason, diagnostic)
    }
    .with_source_order(
        source_order_range.and_then(|range| sources.source_file(range)),
        source_order_range,
    )
    .with_trace_order(finding_trace_order(sources, &finding.trace))
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
        | InterpretedFindingKind::UnsafeOperation { .. }
        | InterpretedFindingKind::AmbiguousSafetyMarker { .. } => {
            Some(finding.function_path.clone())
        }
        InterpretedFindingKind::CompilerAssert { .. }
        | InterpretedFindingKind::PanicSink
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
        InterpretedFindingKind::CompilerAssert { kind } => (
            FindingKind::CompilerAssert {
                compiler_assert_kind: *kind,
            },
            String::from("compiler assert"),
            format!("function `{}` has an undocumented panic path", root.path),
        ),
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
        InterpretedFindingKind::SafetyCall { kind } => {
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
        InterpretedFindingKind::CompilerAssert { .. }
        | InterpretedFindingKind::PanicSink
        | InterpretedFindingKind::OpaquePanicBoundary { .. } => root_span.or(effect_span),
        InterpretedFindingKind::DocumentedPanic { .. }
        | InterpretedFindingKind::MissingSafetyDocs
        | InterpretedFindingKind::SafetyCall { .. }
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
    sources: &SourceResolver<'_, '_>,
    diagnostic: &mut FindingDiagnostic,
    root: &InterpretationRoot,
    root_span: Option<Span>,
    finding: &InterpretedFinding,
    effect_span: Option<Span>,
    show_full_stack_trace: bool,
) {
    match &finding.kind {
        InterpretedFindingKind::CompilerAssert { kind } => {
            add_effect_note(
                diagnostic,
                effect_span,
                format!(
                    "panic may happen here: compiler assertion: {}",
                    kind.human_description()
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
            add_panic_help(
                diagnostic,
                effect_span,
                trace_entry_span(sources, &finding.trace),
            );
        }
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
                    "add `// PANIC:` directly above this call explaining why its documented panic conditions cannot occur",
                ));
            }
            if let Some(span) = sources.function_span(root.function) {
                diagnostic.messages.push(DiagnosticMessage::SpanHelp(
                    span,
                    "document when this function may panic with `/// # Panics` here",
                ));
            }
            add_missing_requirement_notes(diagnostic, &finding.missing_requirements, "panic");
            diagnostic.messages.push(DiagnosticMessage::Help(
                "ensure the callee's panic conditions cannot occur, justify that with `// PANIC:`, or document when the caller may panic with `# Panics`",
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
                "document this boundary with `# Panics`, add `// PANIC:` only if every possible callee is locally constrained, or configure `indirect-call-boundary` if this opacity is acceptable",
            ));
        }
        InterpretedFindingKind::MissingSafetyDocs => {
            diagnostic.messages.push(DiagnosticMessage::Help(
                "document the caller obligations under a `# Safety` section",
            ));
        }
        InterpretedFindingKind::SafetyCall { kind } => {
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
                diagnostic.messages.push(DiagnosticMessage::Help(help));
            } else {
                add_missing_requirement_notes(diagnostic, &finding.missing_requirements, "safety");
                diagnostic.messages.push(DiagnosticMessage::Help(
                    "add named bullets under the applicable `// SAFETY:` comment for each missing requirement",
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
            diagnostic.messages.push(DiagnosticMessage::Help(
                "add a `// SAFETY:` comment above the unsafe block or operation",
            ));
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
                "give each requirement a unique name, or set `ambiguous-panic-requirement = \"allow\"` under `[analysis.lints]`",
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
                "give each requirement a unique name, or set `ambiguous-safety-requirement = \"allow\"` under `[analysis.lints]`",
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
                "move the marker directly above one obligation, split it into separate markers, or set `ambiguous-panic-marker = \"allow\"` under `[analysis.lints]`",
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
                "give each unsafe block or operation its own marker, or set `ambiguous-safety-marker = \"allow\"` under `[analysis.lints]`",
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
            "guard this path, or add `// PANIC:` here if a local invariant proves it cannot panic",
        ));
    }
    diagnostic.messages.push(DiagnosticMessage::Help(
        "add a guard, document the panic with `# Panics`, or add `// PANIC:` if a local invariant proves it cannot panic",
    ));
}

fn trace_entry_span(sources: &SourceResolver<'_, '_>, trace: &InterpretedTrace) -> Option<Span> {
    trace
        .steps
        .first()
        .and_then(|step| sources.resolve(step.source_range.as_ref()).0)
}

fn add_contract_note(
    sources: &SourceResolver<'_, '_>,
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
    sources: &SourceResolver<'_, '_>,
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
    sources: &SourceResolver<'_, '_>,
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
        root_span: root_span.map(|span| render_span(sources.tcx, span)),
        target,
        span: effect_span.map(|span| render_span(sources.tcx, span)),
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
            "raise `node-limit` under `[analysis]` in sniff-test.toml, or shrink the traversal by trusting or ignoring namespaces",
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

fn render_trace(sources: &SourceResolver<'_, '_>, trace: &InterpretedTrace) -> Vec<String> {
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
                    format!("{}: {edge}", render_span(sources.tcx, span))
                })
        })
        .collect()
}

fn finding_trace_order(
    sources: &SourceResolver<'_, '_>,
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
    sources: &SourceResolver<'_, '_>,
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
        InterpretedFindingKind::CompilerAssert { kind } => format!(
            "a compiler assertion that may panic ({})",
            kind.human_description()
        ),
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
        InterpretedFindingKind::MissingSafetyDocs => {
            String::from("a public unsafe function without `# Safety` documentation")
        }
        InterpretedFindingKind::SafetyCall {
            kind: InterpretedSafetyCallKind::Unsafe,
        } if finding.missing_requirements.is_empty() => {
            String::from("an unsafe call without a `// SAFETY:` justification")
        }
        InterpretedFindingKind::SafetyCall {
            kind: InterpretedSafetyCallKind::Unsafe,
        } => String::from(
            "an unsafe call whose documented `# Safety` requirements are not all satisfied",
        ),
        InterpretedFindingKind::SafetyCall {
            kind: InterpretedSafetyCallKind::Obligation,
        } if finding.missing_requirements.is_empty() => {
            String::from("a call with `# Safety` documentation but no `// SAFETY:` justification")
        }
        InterpretedFindingKind::SafetyCall {
            kind: InterpretedSafetyCallKind::Obligation,
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
    sources: &SourceResolver<'_, '_>,
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

struct SourceResolver<'tcx, 'analysis> {
    tcx: TyCtxt<'tcx>,
    local: &'analysis ArtifactAnalysisIr,
    dependencies: &'analysis ArtifactAnalysisGraph,
}

impl SourceResolver<'_, '_> {
    fn function_body(&self, function: FunctionId) -> Option<&FunctionBodyIr> {
        self.local
            .function_body(function)
            .or_else(|| self.dependencies.function(function).map(|body| body.body()))
    }

    fn function_span(&self, function: FunctionId) -> Option<Span> {
        self.function_body(function)
            .and_then(|body| self.resolve(body.source_range.as_ref()).0)
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
        self.local
            .source_files
            .binary_search_by(|source| source.id.cmp(&range.file))
            .ok()
            .map(|index| &self.local.source_files[index])
            .or_else(|| {
                self.dependencies
                    .source_file(&range.file)
                    .map(|(_, source)| source)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::missing_body_diagnostic_message;

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
}
