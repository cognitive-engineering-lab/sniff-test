//! Adapts effect-trace results to diagnostics and JSON findings.

use std::path::{Path, PathBuf};

use crate::artifact::{
    ArtifactFacts, CallFact, CallId, CallKindFact, ContractRequirementFact, FunctionFact,
    FunctionId, SafetyOpKind, SourceFileFact, SourceRangeFact, StableDefPathHash,
    StableInstanceHash,
};
use crate::artifact_cache::ArtifactScope;
use crate::compiler::source::CachedSourceMap;
use crate::config::SniffTestConfig;
use crate::effects::EffectSelection;
use crate::namespace::canonical_namespace;
use crate::report::{EffectReportError, trace_selected_workspace};
use crate::report_model::{
    IncompleteReason, IncompleteTraceKind, InterpretationRoot, InterpretedFinding,
    InterpretedFindingKind, InterpretedSafetyCallKind, InterpretedTrace, InterpretedTraceStep,
    InterpretedTraceStepKind, RootInterpretation, TraceFrontier, UnresolvedCallCoverage,
    UnresolvedCallMechanism, UnresolvedCallSite,
};
use crate::report_roots::ReportRoot;
use crate::workspace::ArtifactAnalysisGraph;
use rustc_hir::def_id::LOCAL_CRATE;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use super::findings::{
    DiagnosticMessage, Finding, FindingDiagnostic, FindingKind, FindingOwner,
    FindingTraceStepOrder, OwnerScope, SourceEvidence,
};
use super::report::render_span;

pub(super) fn interpret_workspace<'tcx>(
    tcx: TyCtxt<'tcx>,
    local: &ArtifactFacts,
    local_stable_crate_id: u64,
    dependencies: &ArtifactAnalysisGraph,
    report_roots: &[ReportRoot<'tcx>],
    config: &SniffTestConfig,
    effects: EffectSelection,
) -> Result<Vec<Finding>, EffectReportError> {
    let roots = report_roots
        .iter()
        .copied()
        .map(|root| interpretation_root(tcx, root))
        .collect::<Vec<_>>();
    let result = trace_selected_workspace(
        local,
        local_stable_crate_id,
        dependencies,
        &roots,
        config,
        effects,
    )?;
    let sources = SourceResolver {
        tcx,
        cache: CachedSourceMap::new(tcx.sess.source_map()),
        local,
        local_stable_crate_id,
        dependencies,
    };

    Ok(adapt_result(
        &sources,
        result,
        config.analysis.show_full_stack_trace,
    ))
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
        (
            InterpretedFindingKind::UnresolvedPanicCallTarget { .. }
            | InterpretedFindingKind::UnresolvedSafetyCallTarget { .. },
            Some(target),
        ) if target.function.is_none() => None,
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
    let owner = sources.owner(finding.function);
    let source_evidence = finding.marker_evidence.map(SourceEvidence::from);
    let (kind, reason, message) =
        finding_description(finding, root, target.as_deref(), &owner, source_evidence);
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
        diagnostic_primary_span(root_span, effect_span)
    };
    let trace = render_trace(sources, &finding.trace);
    let function = public_function_path(finding);
    let unresolved_call = match &finding.kind {
        InterpretedFindingKind::UnresolvedPanicCallTarget { site }
        | InterpretedFindingKind::UnresolvedSafetyCallTarget { site } => Some(*site),
        _ => None,
    };
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
        finding,
        &owner,
        source_evidence,
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
        owner: Some(owner),
        source_evidence,
        unresolved_call,
        trace,
        missing_requirements,
        requirements,
        effect_span,
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
        | InterpretedFindingKind::UnresolvedSafetyCallTarget { .. }
        | InterpretedFindingKind::UnsafeOperation { .. }
        | InterpretedFindingKind::AmbiguousSafetyMarker { .. } => {
            Some(finding.function_path.clone())
        }
        InterpretedFindingKind::CompilerAssert { .. }
        | InterpretedFindingKind::PanicSink
        | InterpretedFindingKind::DocumentedPanic
        | InterpretedFindingKind::UnresolvedPanicCallTarget { .. }
        | InterpretedFindingKind::AmbiguousPanicRequirement { .. }
        | InterpretedFindingKind::AmbiguousPanicMarker { .. } => None,
    }
}

fn ambiguity_primary_range(finding: &InterpretedFinding) -> Option<&SourceRangeFact> {
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
    owner: &FindingOwner,
    source_evidence: Option<SourceEvidence>,
) -> (FindingKind, String, String) {
    match &finding.kind {
        InterpretedFindingKind::CompilerAssert { kind } => source_marker_description(
            FindingKind::CompilerAssert {
                compiler_assert_kind: *kind,
            },
            &format!("compiler assertion ({})", kind.human_description()),
            MarkerDomain::Panic,
            owner,
            source_evidence,
            false,
        ),
        InterpretedFindingKind::PanicSink => {
            let subject = target.map_or_else(
                || String::from("panic invocation"),
                |target| format!("panic invocation to `{target}`"),
            );
            source_marker_description(
                FindingKind::PanicInvocation,
                &subject,
                MarkerDomain::Panic,
                owner,
                source_evidence,
                false,
            )
        }
        InterpretedFindingKind::DocumentedPanic => {
            let target = target.unwrap_or("documented panic boundary");
            source_marker_description(
                FindingKind::DocumentedPanic,
                &format!("call to `{target}` with a `# Panics` contract"),
                MarkerDomain::Panic,
                owner,
                source_evidence,
                !finding.missing_requirements.is_empty(),
            )
        }
        InterpretedFindingKind::UnresolvedPanicCallTarget { site } => {
            let boundary = unresolved_target_summary(*site, target).replace('`', "");
            (
                FindingKind::UnresolvedPanicCallTarget,
                format!("panic coverage is incomplete for {boundary}"),
                format!("function `{}` has incomplete panic coverage", root.path),
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
            let (kind, subject) = match (kind, requirements_missing) {
                (InterpretedSafetyCallKind::Unsafe, false) => (
                    FindingKind::UnsafeCallMissingJustification,
                    format!("unsafe call to `{target}`"),
                ),
                (InterpretedSafetyCallKind::Unsafe, true) => (
                    FindingKind::UnsafeCallMissingRequirements,
                    format!("unsafe call to `{target}`"),
                ),
                (InterpretedSafetyCallKind::Obligation, false) => (
                    FindingKind::SafetyObligationMissingJustification,
                    format!("call to `{target}` with a `# Safety` contract"),
                ),
                (InterpretedSafetyCallKind::Obligation, true) => (
                    FindingKind::SafetyObligationMissingRequirements,
                    format!("call to `{target}` with a `# Safety` contract"),
                ),
            };
            source_marker_description(
                kind,
                &subject,
                MarkerDomain::Safety,
                owner,
                source_evidence,
                requirements_missing,
            )
        }
        InterpretedFindingKind::UnresolvedSafetyCallTarget { site } => {
            let boundary = unresolved_target_summary(*site, target).replace('`', "");
            (
                FindingKind::UnresolvedSafetyCallTarget,
                format!("safety coverage is incomplete for {boundary}"),
                format!("function `{}` has incomplete safety coverage", root.path),
            )
        }
        InterpretedFindingKind::UnsafeOperation { kind } => source_marker_description(
            FindingKind::UnsafeOpMissingJustification {
                safety_op_kind: *kind,
            },
            &format!("unsafe operation ({})", kind.label()),
            MarkerDomain::Safety,
            owner,
            source_evidence,
            false,
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

#[derive(Clone, Copy)]
enum MarkerDomain {
    Panic,
    Safety,
}

impl MarkerDomain {
    const fn marker(self) -> &'static str {
        match self {
            Self::Panic => "PANIC",
            Self::Safety => "SAFETY",
        }
    }

    const fn heading(self) -> &'static str {
        match self {
            Self::Panic => "Panics",
            Self::Safety => "Safety",
        }
    }

    const fn effect(self) -> &'static str {
        match self {
            Self::Panic => "panic path",
            Self::Safety => "safety obligation",
        }
    }
}

fn source_marker_description(
    kind: FindingKind,
    subject: &str,
    domain: MarkerDomain,
    owner: &FindingOwner,
    evidence: Option<SourceEvidence>,
    has_remaining_requirements: bool,
) -> (FindingKind, String, String) {
    let reason = evidence.map_or_else(
        || subject.to_owned(),
        |evidence| {
            source_evidence_reason(subject, domain, owner, evidence, has_remaining_requirements)
        },
    );
    (kind, reason.clone(), reason)
}

fn source_evidence_reason(
    subject: &str,
    domain: MarkerDomain,
    owner: &FindingOwner,
    evidence: SourceEvidence,
    has_remaining_requirements: bool,
) -> String {
    let marker = domain.marker();
    match evidence {
        SourceEvidence::VerifiedAbsent => match owner.scope {
            OwnerScope::Workspace => {
                format!("{subject} has no recorded `// {marker}:` evidence")
            }
            OwnerScope::Dependency => format!(
                "dependency crate {} has no recorded `// {marker}:` evidence for {subject}",
                owner_crate_label(owner)
            ),
            OwnerScope::Toolchain => format!(
                "toolchain crate {} has no recorded `// {marker}:` evidence for {subject}",
                owner_crate_label(owner)
            ),
            OwnerScope::Unknown => format!(
                "source owner {} has no recorded `// {marker}:` evidence for {subject}",
                owner_crate_label(owner)
            ),
        },
        SourceEvidence::Unverified { reason } => format!(
            "could not verify `// {marker}:` evidence for {subject} in {}: {}",
            owner_location(owner),
            unverified_reason(reason)
        ),
        SourceEvidence::Present if has_remaining_requirements => format!(
            "recorded `// {marker}:` evidence for {subject} does not satisfy the remaining `# {}` requirements",
            domain.heading()
        ),
        SourceEvidence::Present => {
            format!("recorded `// {marker}:` evidence for {subject} is unusable")
        }
    }
}

fn source_evidence_help(
    domain: MarkerDomain,
    owner: &FindingOwner,
    evidence: SourceEvidence,
    has_remaining_requirements: bool,
) -> String {
    let marker = domain.marker();
    match (owner.scope, evidence) {
        (OwnerScope::Workspace, SourceEvidence::VerifiedAbsent) => format!(
            "add `// {marker}:` directly above this source after establishing the invariant that contains this {}",
            domain.effect()
        ),
        (OwnerScope::Workspace, SourceEvidence::Unverified { .. }) => format!(
            "restore usable source evidence, then rerun analysis before deciding how to contain this {}",
            domain.effect()
        ),
        (OwnerScope::Workspace, SourceEvidence::Present) if has_remaining_requirements => format!(
            "update the recorded `// {marker}:` evidence to address each remaining `# {}` requirement",
            domain.heading()
        ),
        (OwnerScope::Workspace, SourceEvidence::Present) => format!(
            "replace the unusable recorded `// {marker}:` evidence with a concrete invariant"
        ),
        (OwnerScope::Dependency, SourceEvidence::VerifiedAbsent) => format!(
            "audit or upgrade dependency crate {}; it has no recorded `// {marker}:` evidence for this source",
            owner_crate_label(owner)
        ),
        (OwnerScope::Dependency, SourceEvidence::Unverified { .. }) => format!(
            "audit or upgrade dependency crate {}; its `// {marker}:` evidence could not be verified",
            owner_crate_label(owner)
        ),
        (OwnerScope::Dependency, SourceEvidence::Present) => format!(
            "audit or upgrade dependency crate {}; its recorded `// {marker}:` evidence does not discharge this finding",
            owner_crate_label(owner)
        ),
        (OwnerScope::Toolchain, SourceEvidence::VerifiedAbsent) => format!(
            "treat this as toolchain audit and coverage information for crate {}; no local source edit can add its `// {marker}:` evidence",
            owner_crate_label(owner)
        ),
        (OwnerScope::Toolchain, SourceEvidence::Unverified { .. }) => format!(
            "treat this as toolchain audit and coverage information for crate {}; its `// {marker}:` evidence could not be verified",
            owner_crate_label(owner)
        ),
        (OwnerScope::Toolchain, SourceEvidence::Present) => format!(
            "review toolchain audit and coverage for crate {}; its recorded `// {marker}:` evidence does not discharge this finding",
            owner_crate_label(owner)
        ),
        (OwnerScope::Unknown, SourceEvidence::VerifiedAbsent) => format!(
            "inspect the source owner before deciding where to record `// {marker}:` evidence"
        ),
        (OwnerScope::Unknown, SourceEvidence::Unverified { .. }) => format!(
            "inspect the source owner and restore verifiable `// {marker}:` evidence before choosing a remediation"
        ),
        (OwnerScope::Unknown, SourceEvidence::Present) => format!(
            "inspect the source owner's recorded `// {marker}:` evidence; it does not discharge this finding"
        ),
    }
}

fn external_containment_help(
    domain: MarkerDomain,
    evidence: SourceEvidence,
    has_partial_path_evidence: bool,
) -> String {
    let action = if has_partial_path_evidence {
        format!(
            "this trace already discharges some `# {}` requirements; at this local call, record only the remaining requirements after verifying them",
            domain.heading()
        )
    } else {
        match evidence {
            SourceEvidence::VerifiedAbsent => format!(
                "guard this local call or record a local `// {}:` containment only after verifying the invariant",
                domain.marker()
            ),
            SourceEvidence::Unverified { .. } => format!(
                "inspect or guard this local call while the external {} evidence remains unverified",
                domain.marker()
            ),
            SourceEvidence::Present => format!(
                "address the remaining external {} obligation at this local call",
                domain.marker()
            ),
        }
    };
    format!(
        "{action}; treating this boundary as trusted must be a deliberate trust decision backed by review"
    )
}

fn owner_crate_label(owner: &FindingOwner) -> String {
    owner
        .crate_name
        .as_deref()
        .map_or_else(|| String::from("<unknown>"), |name| format!("`{name}`"))
}

fn owner_location(owner: &FindingOwner) -> String {
    match owner.scope {
        OwnerScope::Workspace => format!("workspace crate {}", owner_crate_label(owner)),
        OwnerScope::Dependency => format!("dependency crate {}", owner_crate_label(owner)),
        OwnerScope::Toolchain => format!("toolchain crate {}", owner_crate_label(owner)),
        OwnerScope::Unknown => format!("source owner {}", owner_crate_label(owner)),
    }
}

const fn unverified_reason(reason: crate::artifact::UnverifiedMarkerProbeReason) -> &'static str {
    match reason {
        crate::artifact::UnverifiedMarkerProbeReason::NoUsableSourceSpan => {
            "no usable span was available for marker association"
        }
        crate::artifact::UnverifiedMarkerProbeReason::SourceUnavailable => {
            "the recorded source was unavailable"
        }
    }
}

fn diagnostic_primary_span(root_span: Option<Span>, effect_span: Option<Span>) -> Option<Span> {
    effect_span.or(root_span)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the diagnostic variants and their source context stay together so their rustc UX remains directly comparable"
)]
fn decorate_finding(
    sources: &SourceResolver<'_, '_>,
    diagnostic: &mut FindingDiagnostic,
    root: &InterpretationRoot,
    finding: &InterpretedFinding,
    owner: &FindingOwner,
    source_evidence: Option<SourceEvidence>,
    effect_span: Option<Span>,
    show_full_stack_trace: bool,
) {
    match &finding.kind {
        InterpretedFindingKind::CompilerAssert { .. } | InterpretedFindingKind::PanicSink => {
            add_finding_trace_notes(sources, diagnostic, finding, show_full_stack_trace);
            add_source_evidence_guidance(
                sources,
                diagnostic,
                finding,
                owner,
                source_evidence,
                MarkerDomain::Panic,
            );
        }
        InterpretedFindingKind::DocumentedPanic => {
            add_contract_note(sources, diagnostic, finding, "Panics");
            add_missing_requirement_notes(
                diagnostic,
                &finding.missing_requirements,
                "panic",
                source_evidence,
            );
            add_finding_trace_notes(sources, diagnostic, finding, show_full_stack_trace);
            add_source_evidence_guidance(
                sources,
                diagnostic,
                finding,
                owner,
                source_evidence,
                MarkerDomain::Panic,
            );
            if let Some(span) = sources.function_span(root.function) {
                diagnostic.messages.push(DiagnosticMessage::SpanHelp(
                    span,
                    "document when this function may panic with `/// # Panics` here".into(),
                ));
            }
        }
        InterpretedFindingKind::UnresolvedPanicCallTarget { site } => {
            let target = finding
                .target
                .as_ref()
                .filter(|target| target.function.is_some())
                .map(|target| target.path.as_str());
            add_effect_note(
                diagnostic,
                effect_span,
                format!(
                    "panic coverage is incomplete here: {}",
                    unresolved_target_summary(*site, target)
                ),
            );
            diagnostic
                .messages
                .push(DiagnosticMessage::Note(unresolved_coverage_note(
                    *site, target,
                )));
            add_finding_trace_notes(sources, diagnostic, finding, show_full_stack_trace);
            diagnostic.messages.push(DiagnosticMessage::Help(format!(
                "{}; otherwise configure `[panics.lints].unresolved-call-target` if the uncertainty is acceptable",
                unresolved_action(MarkerDomain::Panic, site.mechanism)
            )));
        }
        InterpretedFindingKind::MissingSafetyDocs => {
            diagnostic.messages.push(DiagnosticMessage::Help(
                "document the caller obligations under a `# Safety` section".into(),
            ));
        }
        InterpretedFindingKind::UnresolvedSafetyCallTarget { site } => {
            let target = finding
                .target
                .as_ref()
                .filter(|target| target.function.is_some())
                .map(|target| target.path.as_str());
            add_effect_note(
                diagnostic,
                effect_span,
                format!(
                    "safety coverage is incomplete here: {}",
                    unresolved_target_summary(*site, target)
                ),
            );
            diagnostic
                .messages
                .push(DiagnosticMessage::Note(unresolved_coverage_note(
                    *site, target,
                )));
            add_finding_trace_notes(sources, diagnostic, finding, show_full_stack_trace);
            diagnostic.messages.push(DiagnosticMessage::Help(format!(
                "{}; otherwise configure `[safety.lints].unresolved-call-target` if the uncertainty is acceptable",
                unresolved_action(MarkerDomain::Safety, site.mechanism)
            )));
        }
        InterpretedFindingKind::SafetyCall { kind, .. } => {
            if matches!(kind, InterpretedSafetyCallKind::Obligation)
                || !finding.requirements.is_empty()
            {
                add_contract_note(sources, diagnostic, finding, "Safety");
            }
            add_missing_requirement_notes(
                diagnostic,
                &finding.missing_requirements,
                "safety",
                source_evidence,
            );
            add_finding_trace_notes(sources, diagnostic, finding, show_full_stack_trace);
            add_source_evidence_guidance(
                sources,
                diagnostic,
                finding,
                owner,
                source_evidence,
                MarkerDomain::Safety,
            );
        }
        InterpretedFindingKind::UnsafeOperation { .. } => {
            add_finding_trace_notes(sources, diagnostic, finding, show_full_stack_trace);
            add_source_evidence_guidance(
                sources,
                diagnostic,
                finding,
                owner,
                source_evidence,
                MarkerDomain::Safety,
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
            add_finding_trace_notes(sources, diagnostic, finding, show_full_stack_trace);
            diagnostic.messages.push(DiagnosticMessage::Help(
                "give each requirement a unique name, or set `ambiguous-panic-requirement = \"allow\"` under `[analysis.lints]`".into(),
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
            add_finding_trace_notes(sources, diagnostic, finding, show_full_stack_trace);
            diagnostic.messages.push(DiagnosticMessage::Help(
                "give each requirement a unique name, or set `ambiguous-safety-requirement = \"allow\"` under `[analysis.lints]`".into(),
            ));
        }
        InterpretedFindingKind::AmbiguousPanicMarker { effect_count } => {
            diagnostic.messages.push(DiagnosticMessage::Note(format!(
                "this marker applies to {effect_count} possible panics"
            )));
            add_finding_trace_notes(sources, diagnostic, finding, show_full_stack_trace);
            diagnostic.messages.push(DiagnosticMessage::Help(
                "move the marker directly above one obligation, split it into separate markers, or set `ambiguous-panic-marker = \"allow\"` under `[analysis.lints]`".into(),
            ));
        }
        InterpretedFindingKind::AmbiguousSafetyMarker { effect_count } => {
            diagnostic.messages.push(DiagnosticMessage::Note(format!(
                "this marker applies to {effect_count} safety obligations"
            )));
            add_finding_trace_notes(sources, diagnostic, finding, show_full_stack_trace);
            diagnostic.messages.push(DiagnosticMessage::Help(
                "give each unsafe block or operation its own marker, or set `ambiguous-safety-marker = \"allow\"` under `[analysis.lints]`".into(),
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

fn add_source_evidence_guidance(
    sources: &SourceResolver<'_, '_>,
    diagnostic: &mut FindingDiagnostic,
    finding: &InterpretedFinding,
    owner: &FindingOwner,
    evidence: Option<SourceEvidence>,
    domain: MarkerDomain,
) {
    let Some(evidence) = evidence else {
        return;
    };
    let source_help = source_evidence_help(
        domain,
        owner,
        evidence,
        !finding.missing_requirements.is_empty(),
    );
    if owner.scope == OwnerScope::Workspace {
        diagnostic
            .messages
            .push(DiagnosticMessage::Help(source_help));
        return;
    }

    diagnostic
        .messages
        .push(DiagnosticMessage::Help(source_help));
    let has_partial_path_evidence = !finding.requirements.is_empty()
        && finding.missing_requirements.len() < finding.requirements.len();
    let containment_help = external_containment_help(domain, evidence, has_partial_path_evidence);
    if let Some(span) = nearest_workspace_containment_span(sources, &finding.trace) {
        diagnostic
            .messages
            .push(DiagnosticMessage::SpanHelp(span, containment_help));
    } else {
        diagnostic
            .messages
            .push(DiagnosticMessage::Help(containment_help));
    }
}

fn nearest_workspace_containment_span(
    sources: &SourceResolver<'_, '_>,
    trace: &InterpretedTrace,
) -> Option<Span> {
    trace.steps.iter().rev().find_map(|step| {
        (step.marker_call.is_some() && sources.owner(step.caller).scope == OwnerScope::Workspace)
            .then(|| sources.marker_call_span(step))
            .flatten()
    })
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
    requirements: &[ContractRequirementFact],
    domain: &str,
    evidence: Option<SourceEvidence>,
) {
    for requirement in requirements {
        let requirement = render_requirement(requirement);
        let note = match evidence {
            Some(SourceEvidence::Present) => {
                format!("remaining unsatisfied {domain} requirement `{requirement}`")
            }
            Some(SourceEvidence::VerifiedAbsent) => {
                format!("missing {domain} requirement `{requirement}`")
            }
            Some(SourceEvidence::Unverified { .. }) => {
                format!("could not verify satisfaction of {domain} requirement `{requirement}`")
            }
            None => format!("unsatisfied {domain} requirement `{requirement}`"),
        };
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

fn unresolved_target_summary(site: UnresolvedCallSite, target: Option<&str>) -> String {
    let description = unresolved_target_description(site);
    target.map_or_else(
        || description.clone(),
        |target| format!("{description} ({target})"),
    )
}

fn unresolved_target_description(site: UnresolvedCallSite) -> String {
    let coverage = match site.coverage {
        UnresolvedCallCoverage::None => "unresolved",
        UnresolvedCallCoverage::Partial => "partially resolved",
    };
    let mechanism = match site.mechanism {
        UnresolvedCallMechanism::FunctionPointer => "function-pointer call target",
        UnresolvedCallMechanism::DynamicDispatch => "dynamic-dispatch call target",
        UnresolvedCallMechanism::GenericDispatch => "generic-dispatch call target",
        UnresolvedCallMechanism::Opaque => "opaque call target",
    };
    format!("{coverage} {mechanism}")
}

fn unresolved_coverage_note(site: UnresolvedCallSite, target: Option<&str>) -> String {
    let mechanism = match site.mechanism {
        UnresolvedCallMechanism::DynamicDispatch => "dynamic dispatch",
        UnresolvedCallMechanism::GenericDispatch => "generic dispatch",
        UnresolvedCallMechanism::FunctionPointer => "a function pointer",
        UnresolvedCallMechanism::Opaque => "an unresolved call target",
    };
    let subject = target.map_or_else(
        || String::from("this call"),
        |target| format!("the call to `{target}`"),
    );
    if site.coverage == UnresolvedCallCoverage::Partial {
        format!("{subject} uses {mechanism}; resolved implementations are checked separately")
    } else {
        format!("{subject} uses {mechanism}")
    }
}

fn unresolved_action(domain: MarkerDomain, mechanism: UnresolvedCallMechanism) -> String {
    if matches!(
        mechanism,
        UnresolvedCallMechanism::DynamicDispatch | UnresolvedCallMechanism::GenericDispatch
    ) {
        return match domain {
            MarkerDomain::Panic => String::from(
                "document caller-visible panic behavior under `# Panics` on the trait method declaration",
            ),
            MarkerDomain::Safety => String::from(
                "document caller safety requirements under `# Safety` on the trait method declaration",
            ),
        };
    }
    String::from(
        "make the callee concrete or make its possible implementations available to analysis",
    )
}

fn adapt_incomplete(
    sources: &SourceResolver<'_, '_>,
    root: &InterpretationRoot,
    kind: FindingKind,
    domain: &str,
    reason: IncompleteReason,
    show_full_stack_trace: bool,
) -> Finding {
    let IncompleteFindingParts {
        owner_function,
        target,
        range,
        trace,
        reason,
        message,
        help,
    } = incomplete_finding_parts(root, domain, reason);
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
    add_incomplete_reason_note(&mut diagnostic, target.as_deref(), effect_span, domain);
    let trace_limit = help.is_some();
    if let Some(help) = help {
        diagnostic.messages.push(DiagnosticMessage::Help(help));
    }
    let trace_destination = target.as_ref().map_or_else(
        || format!("code that could not be fully inspected during {domain} analysis"),
        |target| {
            if trace_limit {
                format!("the {domain} trace frontier at function `{target}`")
            } else {
                let subject = incomplete_analysis_subject(domain);
                format!("the function `{target}`, whose body could not be inspected for {subject}")
            }
        },
    );
    add_trace_notes(
        sources,
        &mut diagnostic,
        &trace,
        show_full_stack_trace,
        TracePresentation::CompletenessFinding,
    );
    add_root_trace_summary(&mut diagnostic, root, root_span, &trace_destination);
    Finding {
        root: Some(root.path.clone()),
        root_kind: Some(root.kind),
        root_span: root_span.map(|span| render_span(sources.tcx, span)),
        target,
        span: effect_span.map(|span| render_span(sources.tcx, span)),
        owner: owner_function.map(|function| sources.owner(function)),
        trace: rendered_trace,
        ..Finding::new(kind, reason, diagnostic)
    }
    .with_source_order(
        range.as_ref().and_then(|range| sources.source_file(range)),
        range.as_ref(),
    )
    .with_trace_order(trace_order)
}

struct IncompleteFindingParts {
    owner_function: Option<FunctionId>,
    target: Option<String>,
    range: Option<SourceRangeFact>,
    trace: InterpretedTrace,
    reason: String,
    message: String,
    help: Option<String>,
}

fn incomplete_finding_parts(
    root: &InterpretationRoot,
    domain: &str,
    reason: IncompleteReason,
) -> IncompleteFindingParts {
    match reason {
        IncompleteReason::TraceDepth {
            max_depth,
            trace_kind,
            frontier,
        } => {
            let presentation = incomplete_limit_presentation(
                &root.path,
                &frontier.path,
                trace_kind,
                TraceLimit::Depth(max_depth),
            );
            limit_finding_parts(frontier, presentation)
        }
        IncompleteReason::TraceStateBudget {
            budget,
            trace_kind,
            frontier,
        } => {
            let presentation = incomplete_limit_presentation(
                &root.path,
                &frontier.path,
                trace_kind,
                TraceLimit::StateBudget(budget),
            );
            limit_finding_parts(frontier, presentation)
        }
        IncompleteReason::MissingBody {
            function,
            path,
            source_range,
            trace,
        } => {
            let message = missing_body_diagnostic_message(&root.path, &path, domain);
            IncompleteFindingParts {
                owner_function: Some(function),
                target: Some(path.clone()),
                range: source_range,
                trace,
                reason: format!("{domain} analysis could not load the body for `{path}`"),
                message,
                help: None,
            }
        }
    }
}

#[derive(Clone, Copy)]
enum TraceLimit {
    Depth(usize),
    StateBudget(usize),
}

struct IncompleteLimitPresentation {
    reason: String,
    message: String,
    help: String,
}

fn incomplete_limit_presentation(
    root: &str,
    frontier: &str,
    trace_kind: IncompleteTraceKind,
    limit: TraceLimit,
) -> IncompleteLimitPresentation {
    let subject = match trace_kind {
        IncompleteTraceKind::PanicEffect => "panic effect tracing",
        IncompleteTraceKind::SafetyEffect => "safety effect tracing",
        IncompleteTraceKind::PanicComment => "panic CommentEffect tracing",
        IncompleteTraceKind::SafetyComment => "safety CommentEffect tracing",
    };
    let (reason, message, help) = match limit {
        TraceLimit::Depth(max_depth) => (
            format!(
                "{subject} reached `[analysis].max-trace-depth` ({max_depth}) at frontier `{frontier}`"
            ),
            format!(
                "{subject} for function `{root}` reached the configured maximum depth ({max_depth}) at `{frontier}`"
            ),
            String::from(
                "raise `[analysis].max-trace-depth` in sniff-test.toml, or shrink this trace",
            ),
        ),
        TraceLimit::StateBudget(budget) => (
            format!(
                "{subject} exhausted `[analysis].trace-state-budget` ({budget}) at frontier `{frontier}`"
            ),
            format!(
                "{subject} for function `{root}` exhausted the configured state budget ({budget}) at `{frontier}`"
            ),
            String::from(
                "raise `[analysis].trace-state-budget` in sniff-test.toml, or reduce the number of distinct effect states",
            ),
        ),
    };
    IncompleteLimitPresentation {
        reason,
        message,
        help,
    }
}

fn limit_finding_parts(
    frontier: TraceFrontier,
    presentation: IncompleteLimitPresentation,
) -> IncompleteFindingParts {
    IncompleteFindingParts {
        owner_function: None,
        target: Some(frontier.path),
        range: frontier.source_range,
        trace: frontier.trace,
        reason: presentation.reason,
        message: presentation.message,
        help: Some(presentation.help),
    }
}

fn add_incomplete_reason_note(
    diagnostic: &mut FindingDiagnostic,
    target: Option<&str>,
    effect_span: Option<Span>,
    domain: &str,
) {
    match (target, effect_span) {
        (Some(target), Some(span)) => {
            diagnostic.messages.push(DiagnosticMessage::SpanNote(
                span,
                format!("{domain} analysis could not continue through `{target}` here"),
            ));
        }
        (Some(target), None) => diagnostic.messages.push(DiagnosticMessage::Note(format!(
            "{domain} analysis could not continue through `{target}`"
        ))),
        (None, _) => {}
    }
}

fn missing_body_diagnostic_message(root: &str, target: &str, domain: &str) -> String {
    let subject = incomplete_analysis_subject(domain);
    format!("function `{root}` reaches `{target}`, whose body could not be checked for {subject}")
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
                step.call.index(),
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

const fn edge_kind_order(kind: CallKindFact) -> u8 {
    match kind {
        CallKindFact::DirectCall => 0,
        CallKindFact::TailCall => 1,
        CallKindFact::MacroExpansion => 2,
        CallKindFact::ConstBody => 3,
        CallKindFact::CoroutineBody => 4,
        CallKindFact::Assert => 5,
        CallKindFact::IndirectCall => 6,
    }
}

const fn safety_op_kind_order(kind: SafetyOpKind) -> u8 {
    match kind {
        SafetyOpKind::DerefRawPointer => 0,
        SafetyOpKind::UseOfMutableStatic => 1,
        SafetyOpKind::UseOfExternStatic => 2,
        SafetyOpKind::AccessToUnionField => 3,
        SafetyOpKind::UseOfUnsafeField => 4,
        SafetyOpKind::InitializingLayoutConstrainedType => 5,
        SafetyOpKind::InitializingTypeWithUnsafeField => 6,
        SafetyOpKind::MutationOfLayoutConstrainedField => 7,
        SafetyOpKind::BorrowOfLayoutConstrainedField => 8,
        SafetyOpKind::InlineAssembly => 9,
        SafetyOpKind::UnsafeBinderCast => 10,
    }
}

fn add_finding_trace_notes(
    sources: &SourceResolver<'_, '_>,
    diagnostic: &mut FindingDiagnostic,
    finding: &InterpretedFinding,
    show_full_stack_trace: bool,
) {
    add_trace_notes(
        sources,
        diagnostic,
        &finding.trace,
        show_full_stack_trace,
        TracePresentation::SourceFinding,
    );
}

#[derive(Clone, Copy)]
enum TracePresentation {
    SourceFinding,
    CompletenessFinding,
}

fn add_trace_notes(
    sources: &SourceResolver<'_, '_>,
    diagnostic: &mut FindingDiagnostic,
    trace: &InterpretedTrace,
    show_full_stack_trace: bool,
    presentation: TracePresentation,
) {
    if trace.steps.is_empty() {
        return;
    }

    if show_full_stack_trace {
        for (index, total, step) in full_trace_steps(trace) {
            let note = format!(
                "effect trace step {index}/{total} (public root -> effect source): {}",
                render_trace_step(step)
            );
            if let Some(span) = sources.resolve(step.source_range.as_ref()).0 {
                diagnostic
                    .messages
                    .push(DiagnosticMessage::SpanNote(span, note));
            } else {
                diagnostic.messages.push(DiagnosticMessage::Note(note));
            }
        }
    } else if trace.steps.len() > 1 || matches!(presentation, TracePresentation::SourceFinding) {
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
}

fn add_root_trace_summary(
    diagnostic: &mut FindingDiagnostic,
    root: &InterpretationRoot,
    root_span: Option<Span>,
    destination: &str,
) {
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

fn full_trace_steps(
    trace: &InterpretedTrace,
) -> impl Iterator<Item = (usize, usize, &InterpretedTraceStep)> {
    let total = trace.steps.len();
    trace
        .steps
        .iter()
        .enumerate()
        .map(move |(index, step)| (index + 1, total, step))
}

fn render_trace_step(step: &InterpretedTraceStep) -> String {
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

const fn edge_kind_label(kind: CallKindFact) -> &'static str {
    match kind {
        CallKindFact::DirectCall => "direct-call",
        CallKindFact::TailCall => "tail-call",
        CallKindFact::MacroExpansion => "macro-expansion",
        CallKindFact::ConstBody => "const-body",
        CallKindFact::CoroutineBody => "coroutine-body",
        CallKindFact::Assert => "assert",
        CallKindFact::IndirectCall => "indirect-call",
    }
}

fn render_requirement(requirement: &ContractRequirementFact) -> String {
    if requirement.name.is_empty() {
        requirement.condition.clone()
    } else if requirement.condition.is_empty() {
        requirement.name.clone()
    } else {
        format!("{}: {}", requirement.name, requirement.condition)
    }
}

struct SourceResolver<'tcx, 'analysis> {
    tcx: TyCtxt<'tcx>,
    cache: CachedSourceMap<'tcx>,
    local: &'analysis ArtifactFacts,
    local_stable_crate_id: u64,
    dependencies: &'analysis ArtifactAnalysisGraph,
}

impl SourceResolver<'_, '_> {
    fn owner(&self, function: FunctionId) -> FindingOwner {
        let stable_crate_id = function.def_path_hash.stable_crate_id();
        if stable_crate_id == self.local_stable_crate_id {
            return FindingOwner {
                scope: OwnerScope::Workspace,
                crate_name: Some(self.tcx.crate_name(LOCAL_CRATE).to_string()),
            };
        }
        if let Some(artifact) = self
            .dependencies
            .artifact_info_by_stable_crate_id(stable_crate_id)
        {
            let scope = match artifact.scope {
                ArtifactScope::Workspace => OwnerScope::Workspace,
                ArtifactScope::Dependency => OwnerScope::Dependency,
            };
            return FindingOwner {
                scope,
                crate_name: Some(artifact.crate_name.clone()),
            };
        }
        let Some(crate_num) = self
            .tcx
            .crates(())
            .iter()
            .copied()
            .find(|crate_num| self.tcx.stable_crate_id(*crate_num).as_u64() == stable_crate_id)
        else {
            return FindingOwner {
                scope: OwnerScope::Unknown,
                crate_name: None,
            };
        };
        FindingOwner {
            scope: if extern_paths_are_toolchain(
                self.tcx.crate_extern_paths(crate_num),
                &self.tcx.sess.target_tlib_path.dir,
            ) {
                OwnerScope::Toolchain
            } else {
                OwnerScope::Unknown
            },
            crate_name: Some(self.tcx.crate_name(crate_num).to_string()),
        }
    }

    fn function_body(&self, function: FunctionId) -> Option<&FunctionFact> {
        self.local.function_body(function).or_else(|| {
            self.dependencies
                .artifacts()
                .find_map(|artifact| artifact.facts.defining_function_body(function))
        })
    }

    fn function_span(&self, function: FunctionId) -> Option<Span> {
        self.function_body(function)
            .and_then(|body| self.resolve(body.source_range.as_ref()).0)
    }

    fn marker_call_span(&self, step: &InterpretedTraceStep) -> Option<Span> {
        let marker_call = step.marker_call?;
        let artifacts = std::iter::once(self.local).chain(
            self.dependencies
                .artifacts()
                .map(|artifact| &artifact.facts),
        );
        let exact = exact_function_body_in(artifacts, step.caller);
        let call = select_marker_call(exact, self.function_body(step.caller), marker_call)?;
        self.resolve(call.source_range.as_ref()).0
    }

    fn resolve(&self, range: Option<&SourceRangeFact>) -> (Option<Span>, Option<String>) {
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
        match self.cache.span(source, range) {
            Ok(span) => (Some(span), None),
            Err(error) => (None, Some(error.to_string())),
        }
    }

    fn source_file(&self, range: &SourceRangeFact) -> Option<&SourceFileFact> {
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

fn extern_paths_are_toolchain(extern_paths: &[PathBuf], target_tlib_dir: &Path) -> bool {
    !extern_paths.is_empty()
        && extern_paths
            .iter()
            .all(|path| path.starts_with(target_tlib_dir))
}

fn exact_function_body_in<'a>(
    artifacts: impl IntoIterator<Item = &'a ArtifactFacts>,
    function: FunctionId,
) -> Option<&'a FunctionFact> {
    artifacts.into_iter().find_map(|artifact| {
        artifact
            .functions
            .binary_search_by_key(&function, |body| body.function)
            .ok()
            .map(|index| &artifact.functions[index])
    })
}

fn select_marker_call<'a>(
    exact: Option<&'a FunctionFact>,
    fallback: Option<&'a FunctionFact>,
    call: CallId,
) -> Option<&'a CallFact> {
    exact
        .or(fallback)?
        .calls
        .iter()
        .find(|candidate| candidate.id == call)
}

#[cfg(test)]
mod tests {
    use crate::artifact::{
        ArtifactFacts, CallFact, CallId, CallKindFact, CallSiteId, CallTargetFact,
        ContractRequirementFact, FunctionAttributesFact, FunctionFact, FunctionFactProvenance,
        FunctionId, SafetyEffectGroupId, SourceFileId, SourceRangeFact, StableDefPathHash,
        StableInstanceHash, UnverifiedMarkerProbeReason,
    };
    use crate::cli::findings::{
        DiagnosticMessage, FindingDiagnostic, FindingKind, FindingOwner, OwnerScope, SourceEvidence,
    };
    use crate::report_model::{
        IncompleteTraceKind, InterpretationRoot, InterpretedFinding, InterpretedFindingKind,
        InterpretedTrace, InterpretedTraceStep, InterpretedTraceStepKind, UnresolvedCallCoverage,
        UnresolvedCallMechanism, UnresolvedCallSite,
    };
    use crate::report_roots::ReportRootKind;

    use super::{
        MarkerDomain, TraceLimit, add_missing_requirement_notes, exact_function_body_in,
        extern_paths_are_toolchain, external_containment_help, finding_description,
        full_trace_steps, incomplete_limit_presentation, missing_body_diagnostic_message,
        select_marker_call, source_evidence_help, source_evidence_reason, unresolved_action,
        unresolved_coverage_note,
    };

    #[test]
    fn toolchain_owner_requires_nonempty_extern_paths_all_under_target_tlib() {
        let tlib = std::path::Path::new("/toolchain/lib/rustlib/target/lib");
        assert!(!extern_paths_are_toolchain(&[], tlib));
        assert!(extern_paths_are_toolchain(
            &[
                std::path::PathBuf::from("/toolchain/lib/rustlib/target/lib/libcore.rlib"),
                std::path::PathBuf::from("/toolchain/lib/rustlib/target/lib/liballoc.rlib"),
            ],
            tlib,
        ));
        assert!(!extern_paths_are_toolchain(
            &[
                std::path::PathBuf::from("/toolchain/lib/rustlib/target/lib/libcore.rlib"),
                std::path::PathBuf::from("/workspace/target/debug/deps/liblookalike.rlib"),
            ],
            tlib,
        ));
        assert!(!extern_paths_are_toolchain(
            &[std::path::PathBuf::from(
                "/toolchain/lib/rustlib/target/lib-other/libcore.rlib",
            )],
            tlib,
        ));
    }

    #[test]
    fn containment_call_uses_the_exact_overlay_body_without_call_id_fallback() {
        let def_path =
            serde_json::from_str::<StableDefPathHash>("\"00000000000000000000000000000001\"")
                .expect("valid definition identity");
        let instance =
            serde_json::from_str::<StableInstanceHash>("\"00000000000000000000000000000002\"")
                .expect("valid instance identity");
        let generic = FunctionId::generic(def_path);
        let exact = FunctionId::exact(def_path, instance);
        let definition = ArtifactFacts {
            functions: vec![marker_call_body(
                generic,
                FunctionFactProvenance::DefiningArtifact,
                &[(7, 10), (8, 20)],
            )],
            source_files: Vec::new(),
        };
        let overlay = ArtifactFacts {
            functions: vec![marker_call_body(
                exact,
                FunctionFactProvenance::ConsumerInstantiation {
                    consumer_stable_crate_id: 99,
                },
                &[(7, 100)],
            )],
            source_files: Vec::new(),
        };

        let exact_body = exact_function_body_in([&definition, &overlay], exact)
            .expect("the exact overlay must win across artifacts");
        let fallback = definition.function_body(exact);
        let selected = select_marker_call(Some(exact_body), fallback, CallId::new(7))
            .expect("the exact call should be selected");
        assert_eq!(
            selected.source_range.as_ref().map(|range| range.byte_start),
            Some(100)
        );
        assert!(
            select_marker_call(Some(exact_body), fallback, CallId::new(8)).is_none(),
            "an exact body must not fall back to a colliding artifact-local call ID"
        );
    }

    fn marker_call_body(
        function: FunctionId,
        provenance: FunctionFactProvenance,
        calls: &[(u32, u64)],
    ) -> FunctionFact {
        FunctionFact {
            function,
            provenance,
            display_path: String::from("sample::callable"),
            attributes: FunctionAttributesFact {
                is_unsafe: false,
                is_exported: false,
                has_rust_body: true,
                is_foreign: false,
                namespace_candidates: vec![String::from("sample::callable")],
            },
            contract_declaration: None,
            source_range: None,
            calls: calls
                .iter()
                .map(|&(id, byte_start)| CallFact {
                    id: CallId::new(id),
                    call_site: CallSiteId::new(id),
                    kind: CallKindFact::DirectCall,
                    safety_effect_group: Some(SafetyEffectGroupId::new(id)),
                    requires_unsafe: false,
                    inside_builtin_unsafe: false,
                    source_range: Some(SourceRangeFact {
                        file: SourceFileId::new("sample-source"),
                        byte_start,
                        byte_end: byte_start + 1,
                    }),
                    expanded_range: None,
                    macro_expansions: Vec::new(),
                    callee_range: None,
                    indirect_kind: None,
                    declaration_target: None,
                    target: CallTargetFact::OpaqueBoundary {
                        description: String::from("opaque test target"),
                        target: None,
                    },
                })
                .collect(),
            effects: Vec::new(),
            markers: Vec::new(),
            unverified_marker_probes: Vec::new(),
        }
    }

    #[test]
    fn unverified_evidence_never_claims_a_missing_marker_or_external_source_edit() {
        let owner = FindingOwner {
            scope: OwnerScope::Dependency,
            crate_name: Some(String::from("dependency-safety")),
        };
        let evidence = SourceEvidence::Unverified {
            reason: UnverifiedMarkerProbeReason::NoUsableSourceSpan,
        };
        let reason = source_evidence_reason(
            "unsafe operation (raw pointer dereference)",
            MarkerDomain::Safety,
            &owner,
            evidence,
            false,
        );
        let help = source_evidence_help(MarkerDomain::Safety, &owner, evidence, false);
        let rendered = format!("{reason} {help}");

        assert!(rendered.contains("could not verify"));
        assert!(rendered.contains("no usable span was available for marker association"));
        assert!(!rendered.contains("missing"));
        assert!(!rendered.contains("no recorded"));
        assert!(!rendered.contains("add `// SAFETY:` above"));

        let mut diagnostic = FindingDiagnostic {
            span: None,
            message: String::new(),
            messages: Vec::new(),
        };
        add_missing_requirement_notes(
            &mut diagnostic,
            &[ContractRequirementFact {
                name: String::from("valid"),
                condition: String::from("the pointer remains valid"),
                structural_path: vec![0],
                source_range: None,
            }],
            "safety",
            Some(evidence),
        );
        assert_eq!(
            diagnostic.messages,
            vec![DiagnosticMessage::Note(String::from(
                "could not verify satisfaction of safety requirement `valid: the pointer remains valid`"
            ))]
        );
    }

    #[test]
    fn dependency_absence_recommends_audit_and_local_deliberate_containment() {
        let owner = FindingOwner {
            scope: OwnerScope::Dependency,
            crate_name: Some(String::from("dependency-panic")),
        };
        let reason = source_evidence_reason(
            "panic invocation to `dependency_panic::leaf`",
            MarkerDomain::Panic,
            &owner,
            SourceEvidence::VerifiedAbsent,
            false,
        );
        let help = source_evidence_help(
            MarkerDomain::Panic,
            &owner,
            SourceEvidence::VerifiedAbsent,
            false,
        );
        let containment =
            external_containment_help(MarkerDomain::Panic, SourceEvidence::VerifiedAbsent, false);

        assert!(reason.contains("dependency crate `dependency-panic`"));
        assert!(reason.contains("no recorded `// PANIC:` evidence"));
        assert!(help.contains("audit or upgrade"));
        assert!(containment.contains("local call"));
        assert!(containment.contains("deliberate trust decision"));
    }

    #[test]
    fn partial_path_evidence_only_recommends_recording_remaining_requirements() {
        let containment =
            external_containment_help(MarkerDomain::Safety, SourceEvidence::VerifiedAbsent, true);

        assert!(containment.contains("already discharges some `# Safety` requirements"));
        assert!(containment.contains("record only the remaining requirements"));
        assert!(!containment.contains("record a local `// SAFETY:` containment"));
        assert!(containment.contains("deliberate trust decision"));
    }

    #[test]
    fn present_evidence_describes_remaining_requirements() {
        let owner = FindingOwner {
            scope: OwnerScope::Workspace,
            crate_name: Some(String::from("app")),
        };

        assert!(
            source_evidence_reason(
                "safety-obligation call to `app::obligation`",
                MarkerDomain::Safety,
                &owner,
                SourceEvidence::Present,
                true,
            )
            .contains("remaining `# Safety` requirements")
        );
    }

    #[test]
    fn panic_contracts_use_documented_panic_lint() {
        let hash =
            serde_json::from_str::<StableDefPathHash>("\"00000000000000000000000000000001\"")
                .expect("test hash should deserialize");
        let function = FunctionId::generic(hash);
        let root = InterpretationRoot {
            function,
            path: String::from("app::root"),
            kind: ReportRootKind::Concrete,
        };
        let finding = InterpretedFinding {
            kind: InterpretedFindingKind::DocumentedPanic,
            function,
            function_path: String::from("app::root"),
            target: None,
            source_range: None,
            marker_evidence: None,
            trace: InterpretedTrace { steps: Vec::new() },
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
        };

        let owner = FindingOwner {
            scope: OwnerScope::Workspace,
            crate_name: Some(String::from("app")),
        };
        let (kind, _, message) = finding_description(
            &finding,
            &root,
            Some("core::slice::first"),
            &owner,
            Some(SourceEvidence::VerifiedAbsent),
        );

        assert_eq!(kind, FindingKind::DocumentedPanic);
        assert_eq!(
            message,
            "call to `core::slice::first` with a `# Panics` contract has no recorded `// PANIC:` evidence"
        );
    }

    #[test]
    fn trace_depth_diagnostic_names_its_frontier_and_only_its_exact_knob() {
        let presentation = incomplete_limit_presentation(
            "app::root",
            "app::step_one",
            IncompleteTraceKind::PanicEffect,
            TraceLimit::Depth(4),
        );

        assert_eq!(
            presentation.reason,
            "panic effect tracing reached `[analysis].max-trace-depth` (4) at frontier `app::step_one`"
        );
        assert_eq!(
            presentation.message,
            "panic effect tracing for function `app::root` reached the configured maximum depth (4) at `app::step_one`"
        );
        assert_eq!(
            presentation.help,
            "raise `[analysis].max-trace-depth` in sniff-test.toml, or shrink this trace"
        );
        assert!(!presentation.help.contains("trace-state-budget"));
    }

    #[test]
    fn trace_state_budget_diagnostic_identifies_comment_effect_domain() {
        let presentation = incomplete_limit_presentation(
            "app::root",
            "app::helper",
            IncompleteTraceKind::SafetyComment,
            TraceLimit::StateBudget(32),
        );

        assert_eq!(
            presentation.reason,
            "safety CommentEffect tracing exhausted `[analysis].trace-state-budget` (32) at frontier `app::helper`"
        );
        assert_eq!(
            presentation.message,
            "safety CommentEffect tracing for function `app::root` exhausted the configured state budget (32) at `app::helper`"
        );
        assert_eq!(
            presentation.help,
            "raise `[analysis].trace-state-budget` in sniff-test.toml, or reduce the number of distinct effect states"
        );
        assert!(!presentation.help.contains("max-trace-depth"));
    }

    #[test]
    fn missing_body_diagnostics_name_the_reachable_target() {
        assert_eq!(
            missing_body_diagnostic_message("app::root", "dep::helper", "safety"),
            "function `app::root` reaches `dep::helper`, whose body could not be checked for unsafe operations"
        );
    }

    #[test]
    fn full_trace_steps_follow_public_root_to_effect_source_order() {
        let function = |value: u128| {
            let hash = serde_json::from_str::<StableDefPathHash>(&format!("\"{value:032x}\""))
                .expect("test hash should deserialize");
            FunctionId::generic(hash)
        };
        let root = function(1);
        let helper = function(2);
        let source = function(3);
        let trace = InterpretedTrace {
            steps: vec![
                InterpretedTraceStep {
                    caller: root,
                    caller_path: String::from("app::root"),
                    call: CallId::new(0),
                    marker_call: Some(CallId::new(0)),
                    kind: InterpretedTraceStepKind::Reachability(CallKindFact::DirectCall),
                    source_range: None,
                    target: Some(helper),
                    target_path: Some(String::from("app::helper")),
                },
                InterpretedTraceStep {
                    caller: helper,
                    caller_path: String::from("app::helper"),
                    call: CallId::new(1),
                    marker_call: Some(CallId::new(1)),
                    kind: InterpretedTraceStepKind::Reachability(CallKindFact::DirectCall),
                    source_range: None,
                    target: Some(source),
                    target_path: Some(String::from("core::panicking::panic")),
                },
            ],
        };

        let steps = full_trace_steps(&trace)
            .map(|(index, total, step)| (index, total, step.caller_path.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(steps, [(1, 2, "app::root"), (2, 2, "app::helper")]);
    }

    #[test]
    fn unresolved_coverage_notes_describe_dispatch_without_internal_analysis_terms() {
        let dynamic = UnresolvedCallSite {
            coverage: UnresolvedCallCoverage::None,
            mechanism: UnresolvedCallMechanism::DynamicDispatch,
        };
        let function_pointer = UnresolvedCallSite {
            coverage: UnresolvedCallCoverage::None,
            mechanism: UnresolvedCallMechanism::FunctionPointer,
        };
        let partial_generic = UnresolvedCallSite {
            coverage: UnresolvedCallCoverage::Partial,
            mechanism: UnresolvedCallMechanism::GenericDispatch,
        };
        assert_eq!(
            unresolved_coverage_note(dynamic, Some("app::Runner::run")),
            "the call to `app::Runner::run` uses dynamic dispatch"
        );
        assert_eq!(
            unresolved_coverage_note(function_pointer, None),
            "this call uses a function pointer"
        );
        assert_eq!(
            unresolved_coverage_note(partial_generic, Some("app::Runner::run")),
            "the call to `app::Runner::run` uses generic dispatch; resolved implementations are checked separately"
        );
        assert_eq!(
            unresolved_action(MarkerDomain::Safety, dynamic.mechanism),
            "document caller safety requirements under `# Safety` on the trait method declaration"
        );
    }
}
