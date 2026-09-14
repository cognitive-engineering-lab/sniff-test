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
use crate::source_overrides::{ContractSourceArtifact, resolve_source_contract_overrides};
use crate::workspace::ArtifactAnalysisGraph;
use rustc_hir::def_id::LOCAL_CRATE;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

use super::args::LocalPackageProvenance;
use super::findings::{
    DiagnosticMessage, Finding, FindingDiagnostic, FindingGroupSubtype, FindingKind, FindingOwner,
    FindingTraceStepOrder, OwnerScope, SourceEvidence,
};
use super::report::render_span;

#[allow(
    clippy::too_many_arguments,
    reason = "workspace adaptation requires compiler context, provenance, policy, and selected effect domains"
)]
pub(super) fn interpret_workspace<'tcx>(
    tcx: TyCtxt<'tcx>,
    local: &ArtifactFacts,
    local_stable_crate_id: u64,
    dependencies: &ArtifactAnalysisGraph,
    report_roots: &[ReportRoot<'tcx>],
    config: &SniffTestConfig,
    package: &LocalPackageProvenance,
    effects: EffectSelection,
) -> Result<Vec<Finding>, EffectReportError> {
    let roots = report_roots
        .iter()
        .copied()
        .map(|root| interpretation_root(tcx, root))
        .collect::<Vec<_>>();
    let crate_name = tcx.crate_name(LOCAL_CRATE);
    let local_source = ContractSourceArtifact::new(
        local_stable_crate_id,
        crate_name.as_str(),
        package.package_version.as_deref(),
        local,
    );
    let source_overrides =
        resolve_source_contract_overrides(&config.contracts.overrides, local_source, dependencies)?;
    let result = trace_selected_workspace(
        local,
        local_stable_crate_id,
        dependencies,
        &roots,
        config,
        &source_overrides,
        effects,
    )?;
    let sources = SourceResolver {
        tcx,
        cache: CachedSourceMap::new(tcx.sess.source_map()),
        local,
        local_stable_crate_id,
        dependencies,
        package,
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

fn finding_target(finding: &InterpretedFinding) -> Option<String> {
    match (&finding.kind, finding.target.as_ref()) {
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
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the diagnostic presentation and stable report identity are assembled together"
)]
fn adapt_finding(
    sources: &SourceResolver<'_, '_>,
    root: &InterpretationRoot,
    finding: &InterpretedFinding,
    show_full_stack_trace: bool,
) -> Finding {
    let target = finding_target(finding);
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
    let presentation = finding_presentation(finding, target.as_deref(), &owner, source_evidence);
    let ambiguous_marker_effect_count = match &finding.kind {
        InterpretedFindingKind::AmbiguousPanicMarker { effect_count }
        | InterpretedFindingKind::AmbiguousSafetyMarker { effect_count } => Some(*effect_count),
        _ => None,
    };
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
    let compact = compact_finding_plan(
        sources,
        finding,
        &owner,
        source_evidence,
        effect_span,
        presentation.primary_label.clone(),
        source_error.as_deref(),
    );
    let mut diagnostic = FindingDiagnostic {
        second_primary_span: None,
        span: diagnostic_span,
        message: presentation.headline,
        messages: Vec::new(),
        compact_messages: None,
    };
    if let Some(span) = effect_span {
        diagnostic.messages.push(DiagnosticMessage::SpanLabel(
            span,
            presentation.primary_label,
        ));
    }
    if let Some(error) = source_error {
        diagnostic.messages.push(DiagnosticMessage::Note(format!(
            "the recorded source location was unavailable: {error}"
        )));
    }
    let justification_marker = decorate_finding(
        sources,
        &mut diagnostic,
        root,
        finding,
        &owner,
        source_evidence,
        effect_span,
    );
    let effect_display = match &finding.kind {
        InterpretedFindingKind::UnsafeOperation { kind } => {
            Some(format!("unsafe operation ({})", kind.label()))
        }
        _ => None,
    };
    let local_boundary_span = (owner.scope == OwnerScope::Dependency)
        .then(|| report_root_containment_span(sources, &finding.trace))
        .flatten();
    diagnostic.compact_messages = (!show_full_stack_trace).then(|| compact.into_messages());
    let unresolved_call = match finding.kind {
        InterpretedFindingKind::UnresolvedPanicCallTarget { site }
        | InterpretedFindingKind::UnresolvedSafetyCallTarget { site } => Some(site),
        _ => None,
    };

    let mut adapted = Finding {
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
        ambiguous_marker_effect_count,
        local_boundary_span,
        justification_marker,
        effect_display,
        ..Finding::new(presentation.kind, presentation.reason, diagnostic)
    }
    .with_source_order(
        source_order_range.and_then(|range| sources.source_file(range)),
        source_order_range,
    )
    .with_trace_order(finding_trace_order(sources, &finding.trace));
    adapted.diagnostic_function_path = Some(finding.function_path.clone());
    adapted
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
fn finding_presentation(
    finding: &InterpretedFinding,
    target: Option<&str>,
    owner: &FindingOwner,
    source_evidence: Option<SourceEvidence>,
) -> FindingPresentation {
    match &finding.kind {
        InterpretedFindingKind::CompilerAssert { kind } => {
            let (headline, primary_label) = compiler_assert_presentation(*kind);
            source_marker_presentation(
                FindingKind::CompilerAssert {
                    compiler_assert_kind: *kind,
                },
                &format!("compiler assertion ({})", kind.human_description()),
                headline,
                primary_label,
                MarkerDomain::Panic,
                owner,
                source_evidence,
                false,
            )
        }
        InterpretedFindingKind::PanicSink => {
            let subject = target.map_or_else(
                || String::from("panic invocation"),
                |target| format!("panic invocation to `{target}`"),
            );
            source_marker_presentation(
                FindingKind::PanicInvocation,
                &subject,
                "this panic is not accounted for on every path",
                "the panic originates here",
                MarkerDomain::Panic,
                owner,
                source_evidence,
                false,
            )
        }
        InterpretedFindingKind::DocumentedPanic => {
            let target = target.unwrap_or("documented panic boundary");
            source_marker_presentation(
                FindingKind::DocumentedPanic,
                &format!("call to `{target}` with a `# Panics` obligation"),
                "this call's documented panic conditions are not accounted for",
                format!("`{target}` documents when this call may panic"),
                MarkerDomain::Panic,
                owner,
                source_evidence,
                !finding.missing_requirements.is_empty(),
            )
        }
        InterpretedFindingKind::UnresolvedPanicCallTarget { site } => {
            let boundary = unresolved_target_summary(*site, target);
            FindingPresentation::new(
                FindingKind::UnresolvedPanicCallTarget,
                format!("panic coverage is incomplete for {boundary}"),
                "cannot determine whether this call may panic",
                unresolved_primary_label(site.coverage),
            )
        }
        InterpretedFindingKind::MissingSafetyDocs => FindingPresentation::new(
            FindingKind::MissingSafetyDocs,
            format!(
                "public unsafe function `{}` is missing # Safety docs",
                finding.function_path
            ),
            "unsafe function's docs are missing a `# Safety` section",
            "missing safety documentation",
        ),
        InterpretedFindingKind::SafetyCall { kind, .. } => {
            let target = target.unwrap_or("unsafe function pointer");
            let requirements_missing = !finding.missing_requirements.is_empty();
            let (kind, subject, headline, primary_label) = match (kind, requirements_missing) {
                (InterpretedSafetyCallKind::Unsafe, false) => (
                    FindingKind::UnsafeCallMissingJustification,
                    format!("unsafe call to `{target}`"),
                    String::from("unsafe call requires a safety justification"),
                    "this call requires its safety preconditions to hold",
                ),
                (InterpretedSafetyCallKind::Unsafe, true) => (
                    FindingKind::UnsafeCallMissingRequirements,
                    format!("unsafe call to `{target}`"),
                    String::from("unsafe call has unaccounted safety requirements"),
                    "this call has additional safety preconditions",
                ),
                (InterpretedSafetyCallKind::Obligation, false) => (
                    FindingKind::SafetyObligationMissingJustification,
                    format!("call to `{target}` with a `# Safety` obligation"),
                    String::from("this call's safety requirements are not accounted for"),
                    "this call has documented safety requirements",
                ),
                (InterpretedSafetyCallKind::Obligation, true) => (
                    FindingKind::SafetyObligationMissingRequirements,
                    format!("call to `{target}` with a `# Safety` obligation"),
                    String::from("this call has unaccounted safety requirements"),
                    "this call has additional documented safety requirements",
                ),
            };
            source_marker_presentation(
                kind,
                &subject,
                headline,
                primary_label,
                MarkerDomain::Safety,
                owner,
                source_evidence,
                requirements_missing,
            )
        }
        InterpretedFindingKind::UnresolvedSafetyCallTarget { site } => {
            let boundary = unresolved_target_summary(*site, target);
            FindingPresentation::new(
                FindingKind::UnresolvedSafetyCallTarget,
                format!("safety coverage is incomplete for {boundary}"),
                "cannot determine whether this call has safety requirements",
                unresolved_primary_label(site.coverage),
            )
        }
        InterpretedFindingKind::UnsafeOperation { kind } => {
            let headline = format!("{} requires a safety justification", kind.label());
            source_marker_presentation(
                FindingKind::UnsafeOpMissingJustification {
                    safety_op_kind: *kind,
                },
                &format!("unsafe operation ({})", kind.label()),
                headline,
                safety_op_primary_label(*kind),
                MarkerDomain::Safety,
                owner,
                source_evidence,
                false,
            )
        }
        InterpretedFindingKind::AmbiguousPanicRequirement { normalized_name } => {
            FindingPresentation::new(
                FindingKind::AmbiguousPanicRequirement,
                format!(
                    "`{}` has {} # Panics requirements named `{normalized_name}`",
                    target.unwrap_or(&finding.function_path),
                    finding.requirements.len()
                ),
                format!("multiple `# Panics` requirements use the name `{normalized_name}`"),
                "this requirement name is not unique",
            )
        }
        InterpretedFindingKind::AmbiguousSafetyRequirement { normalized_name } => {
            FindingPresentation::new(
                FindingKind::AmbiguousSafetyRequirement,
                format!(
                    "`{}` has multiple # Safety requirements named `{normalized_name}`",
                    target.unwrap_or(&finding.function_path)
                ),
                format!("multiple `# Safety` requirements use the name `{normalized_name}`"),
                "this requirement name is not unique",
            )
        }
        InterpretedFindingKind::AmbiguousPanicMarker { effect_count } => FindingPresentation::new(
            FindingKind::AmbiguousPanicMarker,
            format!("one `// PANIC:` marker applies to {effect_count} panic effect groups"),
            "`// PANIC:` comment could apply to multiple panic paths",
            format!("this comment matches {effect_count} possible panic paths"),
        ),
        InterpretedFindingKind::AmbiguousSafetyMarker { effect_count } => FindingPresentation::new(
            FindingKind::AmbiguousSafetyMarker,
            format!("one `// SAFETY:` marker applies to {effect_count} safety effect groups"),
            "`// SAFETY:` comment could apply to multiple safety obligations",
            format!("this comment matches {effect_count} possible safety obligations"),
        ),
    }
}

struct FindingPresentation {
    kind: FindingKind,
    reason: String,
    headline: String,
    primary_label: String,
}

impl FindingPresentation {
    fn new(
        kind: FindingKind,
        reason: impl Into<String>,
        headline: impl Into<String>,
        primary_label: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            reason: reason.into(),
            headline: headline.into(),
            primary_label: primary_label.into(),
        }
    }
}

struct CompactFindingPlan {
    primary: Option<(Span, String)>,
    limitation: Option<String>,
    nearest_workspace_action: Option<(Span, String)>,
    primary_help: String,
}

impl CompactFindingPlan {
    fn into_messages(self) -> Vec<DiagnosticMessage> {
        let primary_span = self.primary.as_ref().map(|(span, _)| *span);
        let mut messages = self
            .primary
            .map(|(span, label)| vec![DiagnosticMessage::SpanLabel(span, label)])
            .unwrap_or_default();
        if let Some(limitation) = self.limitation {
            messages.push(DiagnosticMessage::Note(limitation));
        }
        if let Some((span, help)) = self
            .nearest_workspace_action
            .filter(|(span, _)| Some(*span) != primary_span)
        {
            messages.push(DiagnosticMessage::SpanHelp(span, help));
        } else {
            messages.push(DiagnosticMessage::Help(self.primary_help));
        }
        messages
    }
}

fn compact_finding_plan(
    sources: &SourceResolver<'_, '_>,
    finding: &InterpretedFinding,
    owner: &FindingOwner,
    evidence: Option<SourceEvidence>,
    effect_span: Option<Span>,
    primary_label: String,
    source_error: Option<&str>,
) -> CompactFindingPlan {
    let primary_help = match &finding.kind {
        InterpretedFindingKind::CompilerAssert { .. } | InterpretedFindingKind::PanicSink => {
            compact_marker_help(
                MarkerDomain::Panic,
                owner,
                evidence,
                &finding.missing_requirements,
            )
        }
        InterpretedFindingKind::DocumentedPanic => {
            documented_panic_action(&finding.missing_requirements)
        }
        InterpretedFindingKind::UnresolvedPanicCallTarget { site } => {
            unresolved_action(MarkerDomain::Panic, site.mechanism)
        }
        InterpretedFindingKind::UnresolvedSafetyCallTarget { site } => {
            unresolved_action(MarkerDomain::Safety, site.mechanism)
        }
        InterpretedFindingKind::MissingSafetyDocs => {
            String::from("document the caller obligations under a `# Safety` section")
        }
        InterpretedFindingKind::SafetyCall { .. }
        | InterpretedFindingKind::UnsafeOperation { .. } => compact_marker_help(
            MarkerDomain::Safety,
            owner,
            evidence,
            &finding.missing_requirements,
        ),
        InterpretedFindingKind::AmbiguousPanicRequirement { .. }
        | InterpretedFindingKind::AmbiguousSafetyRequirement { .. } => {
            String::from("give each documented requirement a unique name")
        }
        InterpretedFindingKind::AmbiguousPanicMarker { .. } => {
            compact_ambiguous_marker_action(MarkerDomain::Panic, owner)
        }
        InterpretedFindingKind::AmbiguousSafetyMarker { .. } => {
            compact_ambiguous_marker_action(MarkerDomain::Safety, owner)
        }
    };
    let nearest_workspace_action =
        nearest_workspace_containment_span_except(sources, &finding.trace, effect_span)
            .zip(compact_workspace_path_help(finding));
    CompactFindingPlan {
        primary: effect_span.map(|span| (span, primary_label)),
        limitation: source_error.map_or_else(
            || compact_evidence_limitation(finding, evidence),
            |error| {
                Some(format!(
                    "the recorded source location was unavailable: {error}"
                ))
            },
        ),
        nearest_workspace_action,
        primary_help,
    }
}

fn compact_marker_help(
    domain: MarkerDomain,
    owner: &FindingOwner,
    evidence: Option<SourceEvidence>,
    missing_requirements: &[ContractRequirementFact],
) -> String {
    if let Some(requirements) = compact_requirement_names(missing_requirements) {
        return match domain {
            MarkerDomain::Panic => format!(
                "address the remaining `# Panics` requirements with `// PANIC:` or an enclosing `# Panics` contract: {requirements}"
            ),
            MarkerDomain::Safety => format!(
                "address the remaining `# Safety` requirements in `// SAFETY:`: {requirements}"
            ),
        };
    }
    if matches!(domain, MarkerDomain::Panic) && owner.scope == OwnerScope::Workspace {
        return match evidence {
            None | Some(SourceEvidence::VerifiedAbsent) => String::from(
                "document when this panic can occur under `# Panics`, or add `// PANIC:` if an invariant rules it out",
            ),
            Some(SourceEvidence::Unverified { .. }) => String::from(
                "document the panic under `# Panics`, or restore source verification before adding `// PANIC:`",
            ),
            Some(SourceEvidence::Present) => String::from(
                "replace the unusable `// PANIC:` justification, or document the panic under `# Panics`",
            ),
        };
    }
    evidence.map_or_else(
        || match domain {
            MarkerDomain::Panic => String::from(
                "account for this panic with `// PANIC:`, or document it under `# Panics`",
            ),
            MarkerDomain::Safety => String::from(
                "add a `// SAFETY:` comment explaining how the required invariant is upheld",
            ),
        },
        |evidence| source_evidence_help(domain, owner, evidence, false),
    )
}

fn documented_panic_action(missing_requirements: &[ContractRequirementFact]) -> String {
    compact_requirement_names(missing_requirements).map_or_else(
        || {
            String::from(
                "address the documented panic conditions at each affected call with `// PANIC:`",
            )
        },
        |requirements| {
            format!(
                "address the remaining `# Panics` requirements at each affected call with `// PANIC:`: {requirements}"
            )
        },
    )
}

fn compact_ambiguous_marker_action(domain: MarkerDomain, owner: &FindingOwner) -> String {
    if owner.scope == OwnerScope::Workspace {
        return match domain {
            MarkerDomain::Panic => {
                String::from("place a separate `// PANIC:` marker on each panic path")
            }
            MarkerDomain::Safety => {
                String::from("give each safety obligation its own `// SAFETY:` marker")
            }
        };
    }
    let section = match domain {
        MarkerDomain::Panic => "panics",
        MarkerDomain::Safety => "safety",
    };
    owner.crate_name.as_deref().map_or_else(
        || {
            format!(
                "if the defining crate's surface contracts are trusted, configure `[{section}].trusted-boundary-namespaces`; otherwise audit or upgrade it"
            )
        },
        |crate_name| {
            format!(
                "if `{crate_name}`'s surface contracts are trusted, add `{crate_name}` to `[{section}].trusted-boundary-namespaces`; otherwise audit or upgrade it"
            )
        },
    )
}

fn full_ambiguous_marker_action(domain: MarkerDomain, owner: &FindingOwner) -> String {
    let lint = match domain {
        MarkerDomain::Panic => "ambiguous-panic-marker",
        MarkerDomain::Safety => "ambiguous-safety-marker",
    };
    format!(
        "{}; or set `{lint} = \"allow\"` under `[analysis.lints]`",
        compact_ambiguous_marker_action(domain, owner)
    )
}

fn compact_workspace_path_help(finding: &InterpretedFinding) -> Option<String> {
    let missing_requirements = compact_requirement_names(&finding.missing_requirements);
    match &finding.kind {
        InterpretedFindingKind::CompilerAssert { .. } | InterpretedFindingKind::PanicSink => {
            Some(missing_requirements.as_deref().map_or_else(
                || {
                    String::from(
                        "account for this path at this call with `// PANIC:`, or document it under `# Panics`",
                    )
                },
                |requirements| {
                    format!(
                        "address the remaining `# Panics` requirements at this call: {requirements}"
                    )
                },
            ))
        }
        InterpretedFindingKind::DocumentedPanic => {
            Some(documented_panic_action(&finding.missing_requirements))
        }
        InterpretedFindingKind::SafetyCall { .. }
        | InterpretedFindingKind::UnsafeOperation { .. } => Some(
            missing_requirements.as_deref().map_or_else(
                || {
                    String::from(
                        "explain at this call why this path's safety requirements hold with `// SAFETY:`",
                    )
                },
                |requirements| {
                    format!(
                        "address the remaining `# Safety` requirements at this call: {requirements}"
                    )
                },
            ),
        ),
        InterpretedFindingKind::AmbiguousPanicMarker { .. }
        | InterpretedFindingKind::AmbiguousSafetyMarker { .. }
        | InterpretedFindingKind::UnresolvedPanicCallTarget { .. }
        | InterpretedFindingKind::MissingSafetyDocs
        | InterpretedFindingKind::UnresolvedSafetyCallTarget { .. }
        | InterpretedFindingKind::AmbiguousPanicRequirement { .. }
        | InterpretedFindingKind::AmbiguousSafetyRequirement { .. } => None,
    }
}

fn compact_requirement_names(requirements: &[ContractRequirementFact]) -> Option<String> {
    (!requirements.is_empty()).then(|| {
        let shown = requirements
            .iter()
            .take(3)
            .map(|requirement| {
                let name = if requirement.name.is_empty() {
                    render_requirement(requirement)
                } else {
                    requirement.name.clone()
                };
                format!("`{name}`")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let remaining = requirements.len().saturating_sub(3);
        if remaining == 0 {
            shown
        } else {
            format!("{shown}, and {remaining} more")
        }
    })
}

fn compact_evidence_limitation(
    finding: &InterpretedFinding,
    evidence: Option<SourceEvidence>,
) -> Option<String> {
    let SourceEvidence::Unverified { reason } = evidence? else {
        return None;
    };
    let marker = match &finding.kind {
        InterpretedFindingKind::CompilerAssert { .. }
        | InterpretedFindingKind::PanicSink
        | InterpretedFindingKind::DocumentedPanic => "PANIC",
        InterpretedFindingKind::SafetyCall { .. }
        | InterpretedFindingKind::UnsafeOperation { .. } => "SAFETY",
        _ => return None,
    };
    Some(format!(
        "could not verify usable `// {marker}:` justification at the source: {}",
        unverified_reason(reason)
    ))
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

const fn compiler_assert_presentation(
    kind: crate::artifact::CompilerAssertKind,
) -> (&'static str, &'static str) {
    match kind {
        crate::artifact::CompilerAssertKind::BoundsCheck => {
            ("indexing may panic", "the index may be out of bounds")
        }
        crate::artifact::CompilerAssertKind::Overflow => (
            "this arithmetic operation may panic",
            "the operation may overflow",
        ),
        crate::artifact::CompilerAssertKind::OverflowNegation => {
            ("this negation may panic", "the negated value may overflow")
        }
        crate::artifact::CompilerAssertKind::DivisionByZero => {
            ("this division may panic", "the divisor may be zero")
        }
        crate::artifact::CompilerAssertKind::RemainderByZero => (
            "this remainder operation may panic",
            "the divisor may be zero",
        ),
        crate::artifact::CompilerAssertKind::ResumedAfterReturn => (
            "resuming this coroutine may panic",
            "the coroutine may have already returned",
        ),
        crate::artifact::CompilerAssertKind::ResumedAfterPanic => (
            "resuming this coroutine may panic",
            "the coroutine may have already panicked",
        ),
        crate::artifact::CompilerAssertKind::ResumedAfterDrop => (
            "resuming this coroutine may panic",
            "the coroutine may have already been dropped",
        ),
        crate::artifact::CompilerAssertKind::MisalignedPointerDereference => (
            "this pointer dereference may panic",
            "the pointer may be misaligned",
        ),
        crate::artifact::CompilerAssertKind::NullPointerDereference => (
            "this pointer dereference may panic",
            "the pointer may be null",
        ),
        crate::artifact::CompilerAssertKind::InvalidEnumConstruction => (
            "constructing this enum value may panic",
            "the enum discriminant may be invalid",
        ),
    }
}

const fn safety_op_primary_label(kind: SafetyOpKind) -> &'static str {
    match kind {
        SafetyOpKind::DerefRawPointer => {
            "dereferencing requires a valid and properly aligned pointer"
        }
        SafetyOpKind::UseOfMutableStatic => {
            "access requires preserving the mutable static's synchronization invariants"
        }
        SafetyOpKind::UseOfExternStatic => {
            "access requires upholding the external declaration's invariants"
        }
        SafetyOpKind::AccessToUnionField => "the stored value must be valid for this field's type",
        SafetyOpKind::UseOfUnsafeField => "access requires upholding this field's invariant",
        SafetyOpKind::InitializingLayoutConstrainedType => {
            "initialization must preserve this type's layout constraints"
        }
        SafetyOpKind::InitializingTypeWithUnsafeField => {
            "initialization must uphold the unsafe field invariants"
        }
        SafetyOpKind::MutationOfLayoutConstrainedField => {
            "mutation must preserve this field's layout constraints"
        }
        SafetyOpKind::BorrowOfLayoutConstrainedField => {
            "borrowing must preserve this field's layout constraints"
        }
        SafetyOpKind::InlineAssembly => "the assembly's safety invariants must hold",
        SafetyOpKind::UnsafeBinderCast => "the cast requires its safety invariant to hold",
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

    const fn noun(self) -> &'static str {
        match self {
            Self::Panic => "panic",
            Self::Safety => "safety",
        }
    }

    const fn config_table(self) -> &'static str {
        match self {
            Self::Panic => "panics",
            Self::Safety => "safety",
        }
    }

    const fn ambiguous_effects(self) -> &'static str {
        match self {
            Self::Panic => "possible panics",
            Self::Safety => "safety obligations",
        }
    }

    fn ambiguous_marker_help(self) -> String {
        match self {
            Self::Panic => String::from(
                "move the marker directly above one obligation, split it into separate markers, or set `ambiguous-panic-marker = \"allow\"` under `[analysis.lints]`",
            ),
            Self::Safety => String::from(
                "give each unsafe block or operation its own marker, or set `ambiguous-safety-marker = \"allow\"` under `[analysis.lints]`",
            ),
        }
    }

    fn root_documentation_help(self) -> String {
        match self {
            Self::Panic => {
                String::from("document when this function may panic with `/// # Panics` here")
            }
            Self::Safety => {
                String::from("document this function's safety obligations with `/// # Safety` here")
            }
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the presentation keeps its stable report reason beside its human-facing text"
)]
fn source_marker_presentation(
    kind: FindingKind,
    subject: &str,
    headline: impl Into<String>,
    primary_label: impl Into<String>,
    domain: MarkerDomain,
    owner: &FindingOwner,
    evidence: Option<SourceEvidence>,
    has_remaining_requirements: bool,
) -> FindingPresentation {
    let reason = evidence.map_or_else(
        || subject.to_owned(),
        |evidence| {
            source_evidence_reason(subject, domain, owner, evidence, has_remaining_requirements)
        },
    );
    FindingPresentation::new(kind, reason, headline, primary_label)
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
                format!("{subject} has no recorded `// {marker}:` justification")
            }
            OwnerScope::Dependency => format!(
                "dependency crate {} has no recorded `// {marker}:` justification for {subject}",
                owner_crate_label(owner)
            ),
            OwnerScope::Toolchain => format!(
                "toolchain crate {} has no recorded `// {marker}:` justification for {subject}",
                owner_crate_label(owner)
            ),
            OwnerScope::Unknown => format!(
                "source owner {} has no recorded `// {marker}:` justification for {subject}",
                owner_crate_label(owner)
            ),
        },
        SourceEvidence::Unverified { reason } => format!(
            "could not verify `// {marker}:` justification for {subject} in {}: {}",
            owner_location(owner),
            unverified_reason(reason)
        ),
        SourceEvidence::Present if has_remaining_requirements => format!(
            "recorded `// {marker}:` justification for {subject} does not satisfy the remaining `# {}` requirements",
            domain.heading()
        ),
        SourceEvidence::Present => {
            format!("recorded `// {marker}:` justification for {subject} is unusable")
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
        (OwnerScope::Workspace, SourceEvidence::VerifiedAbsent) => match domain {
            MarkerDomain::Panic => String::from(
                "if this panic cannot occur, add `// PANIC:` explaining the invariant that rules it out",
            ),
            MarkerDomain::Safety => String::from(
                "add a `// SAFETY:` comment explaining how the required safety invariant is upheld",
            ),
        },
        (OwnerScope::Workspace, SourceEvidence::Unverified { .. }) => String::from(
            "restore verifiable source information, then rerun sniff-test before adding a justification",
        ),
        (OwnerScope::Workspace, SourceEvidence::Present) if has_remaining_requirements => format!(
            "update the `// {marker}:` comment to address each remaining `# {}` requirement",
            domain.heading()
        ),
        (OwnerScope::Workspace, SourceEvidence::Present) => {
            format!("replace the `// {marker}:` comment with a concrete justification")
        }
        (OwnerScope::Dependency, _) => format!(
            "audit the source or upgrade dependency crate {}",
            owner_crate_label(owner)
        ),
        (OwnerScope::Toolchain, _) => format!(
            "review toolchain crate {} or update the Rust toolchain; this source cannot be changed in the local crate",
            owner_crate_label(owner)
        ),
        (OwnerScope::Unknown, _) => {
            String::from("identify and audit the source owner before choosing a remediation")
        }
    }
}

fn source_evidence_note(
    domain: MarkerDomain,
    owner: &FindingOwner,
    evidence: SourceEvidence,
    has_remaining_requirements: bool,
) -> String {
    let marker = domain.marker();
    match evidence {
        SourceEvidence::VerifiedAbsent => match owner.scope {
            OwnerScope::Workspace => {
                format!("no `// {marker}:` justification was found for this source")
            }
            OwnerScope::Dependency => format!(
                "no `// {marker}:` justification was recorded for this source in dependency crate {}",
                owner_crate_label(owner)
            ),
            OwnerScope::Toolchain => format!(
                "no `// {marker}:` justification was recorded for this source in toolchain crate {}",
                owner_crate_label(owner)
            ),
            OwnerScope::Unknown => format!(
                "no `// {marker}:` justification was recorded for this source; its owner could not be classified"
            ),
        },
        SourceEvidence::Unverified { reason } => format!(
            "could not verify whether this source has a `// {marker}:` justification in {}: {}",
            owner_location(owner),
            unverified_reason(reason)
        ),
        SourceEvidence::Present if has_remaining_requirements => format!(
            "the recorded `// {marker}:` justification does not address all `# {}` requirements",
            domain.heading()
        ),
        SourceEvidence::Present => {
            format!("the recorded `// {marker}:` comment could not be used as a justification")
        }
    }
}

fn external_containment_help(
    domain: MarkerDomain,
    evidence: SourceEvidence,
    has_partial_path_evidence: bool,
) -> String {
    if has_partial_path_evidence {
        format!(
            "this trace already discharges some `# {}` requirements; document only the remaining requirements at this call after verifying them",
            domain.heading()
        )
    } else {
        match evidence {
            SourceEvidence::VerifiedAbsent => match domain {
                MarkerDomain::Panic => String::from(
                    "document this call's panic conditions under `# Panics`, or explain why it cannot panic with `// PANIC:`",
                ),
                MarkerDomain::Safety => String::from(
                    "guard this call or explain why its safety requirements hold with `// SAFETY:`",
                ),
            },
            SourceEvidence::Unverified { .. } => String::from(
                "guard or audit this call while the external justification is unverified",
            ),
            SourceEvidence::Present => {
                String::from("address the remaining external obligation at this call")
            }
        }
    }
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

struct EffectDiagnosticWriter<'a, 'tcx, 'analysis> {
    sources: &'a SourceResolver<'tcx, 'analysis>,
    diagnostic: &'a mut FindingDiagnostic,
    root: &'a InterpretationRoot,
    finding: &'a InterpretedFinding,
    owner: &'a FindingOwner,
    source_evidence: Option<SourceEvidence>,
    effect_span: Option<Span>,
    justification_marker: Option<String>,
}

impl EffectDiagnosticWriter<'_, '_, '_> {
    fn source(&mut self, domain: MarkerDomain, contract: bool) {
        self.justification_marker = Some(domain.marker().to_owned());
        if let Some(evidence) = self.source_evidence {
            self.diagnostic
                .messages
                .push(DiagnosticMessage::Note(source_evidence_note(
                    domain,
                    self.owner,
                    evidence,
                    !self.finding.missing_requirements.is_empty(),
                )));
        }
        let dependency_effect = self
            .source_evidence
            .is_some_and(|evidence| is_unjustified_dependency_effect(self.owner, evidence));
        if dependency_effect {
            add_external_containment_guidance(
                self.sources,
                self.diagnostic,
                self.finding,
                self.owner,
                self.source_evidence,
                domain,
            );
        }
        if !dependency_effect {
            self.source_help(domain);
        }
        if contract {
            add_contract_note(
                self.sources,
                self.diagnostic,
                self.finding,
                domain.heading(),
            );
        }
        add_missing_requirement_notes(
            self.diagnostic,
            &self.finding.missing_requirements,
            domain.noun(),
            self.source_evidence,
        );
        add_trace_notes(self.sources, self.diagnostic, &self.finding.trace);
        if !dependency_effect {
            add_external_containment_guidance(
                self.sources,
                self.diagnostic,
                self.finding,
                self.owner,
                self.source_evidence,
                domain,
            );
        }
        self.document_root(domain);
        if dependency_effect {
            self.source_help(domain);
        }
    }

    fn source_help(&mut self, domain: MarkerDomain) {
        add_source_evidence_help(
            self.diagnostic,
            self.finding,
            self.owner,
            self.source_evidence,
            domain,
            self.effect_span,
        );
    }

    fn unresolved(&mut self, domain: MarkerDomain, site: UnresolvedCallSite) {
        let target = self
            .finding
            .target
            .as_ref()
            .filter(|target| target.function.is_some())
            .map(|target| target.path.as_str());
        add_effect_note(
            self.diagnostic,
            self.effect_span,
            format!(
                "{} coverage is incomplete here: {}",
                domain.noun(),
                unresolved_target_summary(site, target)
            ),
        );
        self.diagnostic
            .messages
            .push(DiagnosticMessage::Note(unresolved_coverage_note(
                site, target,
            )));
        add_trace_notes(self.sources, self.diagnostic, &self.finding.trace);
        self.diagnostic
            .messages
            .push(DiagnosticMessage::Help(format!(
                "{}; otherwise configure `[{}.lints].unresolved-call-target` if the uncertainty is acceptable",
                unresolved_action(domain, site.mechanism),
                domain.config_table()
            )));
    }

    fn ambiguous_requirement(&mut self, domain: MarkerDomain, normalized_name: &str) {
        add_ambiguous_requirement_notes(
            self.sources,
            self.diagnostic,
            self.finding,
            domain.heading(),
            normalized_name,
        );
        add_trace_notes(self.sources, self.diagnostic, &self.finding.trace);
        self.diagnostic
            .messages
            .push(DiagnosticMessage::Help(format!(
                "give each requirement a unique name, or set `ambiguous-{}-requirement = \"allow\"` under `[analysis.lints]`",
                domain.noun()
            )));
    }

    fn ambiguous_marker(&mut self, domain: MarkerDomain, effect_count: usize) {
        self.diagnostic
            .messages
            .push(DiagnosticMessage::Note(format!(
                "this marker applies to {effect_count} {}",
                domain.ambiguous_effects()
            )));
        add_trace_notes(self.sources, self.diagnostic, &self.finding.trace);
        self.diagnostic.messages.push(DiagnosticMessage::Help(
            if self.owner.scope == OwnerScope::Workspace {
                domain.ambiguous_marker_help()
            } else {
                full_ambiguous_marker_action(domain, self.owner)
            },
        ));
    }

    fn document_root(&mut self, domain: MarkerDomain) {
        if let Some(span) = self.sources.function_span(self.root.function) {
            let help = if self.owner.scope == OwnerScope::Dependency {
                format!(
                    "document this function's obligations with `/// # {}` here",
                    domain.heading()
                )
            } else {
                domain.root_documentation_help()
            };
            self.diagnostic
                .messages
                .push(DiagnosticMessage::SpanHelp(span, help));
        }
    }
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
) -> Option<String> {
    let mut writer = EffectDiagnosticWriter {
        sources,
        diagnostic,
        root,
        finding,
        owner,
        source_evidence,
        effect_span,
        justification_marker: None,
    };
    match &finding.kind {
        InterpretedFindingKind::CompilerAssert { .. } | InterpretedFindingKind::PanicSink => {
            writer.source(MarkerDomain::Panic, false);
        }
        InterpretedFindingKind::DocumentedPanic => {
            writer.source(MarkerDomain::Panic, true);
        }
        InterpretedFindingKind::UnresolvedPanicCallTarget { site } => {
            writer.unresolved(MarkerDomain::Panic, *site);
        }
        InterpretedFindingKind::MissingSafetyDocs => {
            writer.diagnostic.messages.push(DiagnosticMessage::Help(
                "document the caller obligations under a `# Safety` section".into(),
            ));
        }
        InterpretedFindingKind::UnresolvedSafetyCallTarget { site } => {
            writer.unresolved(MarkerDomain::Safety, *site);
        }
        InterpretedFindingKind::SafetyCall {
            documents_contract, ..
        } => {
            writer.source(MarkerDomain::Safety, *documents_contract);
        }
        InterpretedFindingKind::UnsafeOperation { .. } => {
            writer.source(MarkerDomain::Safety, false);
        }
        InterpretedFindingKind::AmbiguousPanicRequirement { normalized_name } => {
            writer.ambiguous_requirement(MarkerDomain::Panic, normalized_name);
        }
        InterpretedFindingKind::AmbiguousSafetyRequirement { normalized_name } => {
            writer.ambiguous_requirement(MarkerDomain::Safety, normalized_name);
        }
        InterpretedFindingKind::AmbiguousPanicMarker { effect_count } => {
            writer.ambiguous_marker(MarkerDomain::Panic, *effect_count);
        }
        InterpretedFindingKind::AmbiguousSafetyMarker { effect_count } => {
            writer.ambiguous_marker(MarkerDomain::Safety, *effect_count);
        }
    }
    writer.justification_marker
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

fn add_source_evidence_help(
    diagnostic: &mut FindingDiagnostic,
    finding: &InterpretedFinding,
    owner: &FindingOwner,
    evidence: Option<SourceEvidence>,
    domain: MarkerDomain,
    effect_span: Option<Span>,
) {
    let Some(evidence) = evidence else {
        return;
    };
    if is_unjustified_dependency_effect(owner, evidence) {
        let help = format!(
            "audit dependency crate {} to justify this effect",
            owner_crate_label(owner),
        );
        diagnostic.messages.push(match effect_span {
            Some(span) => DiagnosticMessage::SpanHelp(span, help),
            None => DiagnosticMessage::Help(help),
        });
    } else {
        let source_help = source_evidence_help(
            domain,
            owner,
            evidence,
            !finding.missing_requirements.is_empty(),
        );
        diagnostic
            .messages
            .push(match (owner.scope, evidence, effect_span) {
                (OwnerScope::Workspace, SourceEvidence::VerifiedAbsent, Some(span)) => {
                    DiagnosticMessage::SpanHelp(span, source_help)
                }
                _ => DiagnosticMessage::Help(source_help),
            });
    }
}

fn add_external_containment_guidance(
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
    if owner.scope == OwnerScope::Workspace {
        return;
    }
    let has_partial_path_evidence = !finding.requirements.is_empty()
        && finding.missing_requirements.len() < finding.requirements.len();
    let containment_help =
        if is_unjustified_dependency_effect(owner, evidence) && !has_partial_path_evidence {
            format!(
                "add a local `// {}:` justification after verifying {} obligations",
                domain.marker(),
                domain.noun()
            )
        } else {
            external_containment_help(domain, evidence, has_partial_path_evidence)
        };
    if let Some(span) = report_root_containment_span(sources, &finding.trace) {
        diagnostic
            .messages
            .push(DiagnosticMessage::SpanHelp(span, containment_help));
    } else {
        diagnostic
            .messages
            .push(DiagnosticMessage::Help(containment_help));
    }
}

fn is_unjustified_dependency_effect(owner: &FindingOwner, evidence: SourceEvidence) -> bool {
    owner.scope == OwnerScope::Dependency && evidence == SourceEvidence::VerifiedAbsent
}

fn report_root_containment_span(
    sources: &SourceResolver<'_, '_>,
    trace: &InterpretedTrace,
) -> Option<Span> {
    trace.steps.iter().find_map(|step| {
        (step.marker_call.is_some() && sources.owner(step.caller).scope == OwnerScope::Workspace)
            .then(|| sources.marker_call_span(step))
            .flatten()
    })
}

fn nearest_workspace_containment_span_except(
    sources: &SourceResolver<'_, '_>,
    trace: &InterpretedTrace,
    excluded: Option<Span>,
) -> Option<Span> {
    trace.steps.iter().rev().find_map(|step| {
        (step.marker_call.is_some() && sources.owner(step.caller).scope == OwnerScope::Workspace)
            .then(|| sources.marker_call_span(step))
            .flatten()
            .filter(|span| Some(*span) != excluded)
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
        .or_else(|| sources.resolve(finding.contract_source_range.as_ref()).0)
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
                format!("no justification was found for {domain} requirement `{requirement}`")
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

const fn unresolved_primary_label(coverage: UnresolvedCallCoverage) -> &'static str {
    match coverage {
        UnresolvedCallCoverage::None => "no concrete implementation could be determined",
        UnresolvedCallCoverage::Partial => "some possible implementations could not be determined",
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
    let diagnostic_group_subtype = incomplete_group_subtype(&reason);
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
        second_primary_span: None,
        span: if source_error.is_some() {
            None
        } else {
            root_span.or(effect_span)
        },
        message,
        messages: Vec::new(),
        compact_messages: None,
    };
    if let Some(error) = source_error {
        diagnostic.messages.push(DiagnosticMessage::Note(format!(
            "the recorded source location was unavailable: {error}"
        )));
    }
    add_incomplete_reason_note(&mut diagnostic, target.as_deref(), effect_span, domain);
    let trace_limit = help.is_some();
    let compact_help = help.clone().unwrap_or_else(|| {
        String::from("make this function's body available to analysis, then rerun sniff-test")
    });
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
    add_trace_notes(sources, &mut diagnostic, &trace);
    add_root_trace_summary(&mut diagnostic, root, root_span, &trace_destination);
    let nearest_workspace_action = nearest_workspace_containment_span_except(
        sources,
        &trace,
        effect_span,
    )
    .map(|span| {
        let help = if trace_limit {
            String::from(
                "this path reaches the configured analysis limit; shorten it or raise the limit",
            )
        } else {
            String::from("make the body reached by this call available to analysis")
        };
        (span, help)
    });
    let compact = CompactFindingPlan {
        primary: effect_span.map(|span| {
            (
                span,
                format!("{domain} analysis could not continue past this point"),
            )
        }),
        limitation: None,
        nearest_workspace_action,
        primary_help: compact_help,
    };
    diagnostic.compact_messages = (!show_full_stack_trace).then(|| compact.into_messages());
    let mut adapted = Finding {
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
    .with_diagnostic_group_subtype(diagnostic_group_subtype);
    adapted.diagnostic_function_path = adapted.target.clone();
    adapted
}

fn incomplete_group_subtype(reason: &IncompleteReason) -> FindingGroupSubtype {
    match reason {
        IncompleteReason::TraceDepth { trace_kind, .. } => FindingGroupSubtype::TraceDepth {
            trace_kind: *trace_kind,
        },
        IncompleteReason::TraceStateBudget { trace_kind, .. } => {
            FindingGroupSubtype::TraceStateBudget {
                trace_kind: *trace_kind,
            }
        }
        IncompleteReason::MissingBody { .. } => FindingGroupSubtype::MissingBody,
    }
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

fn add_trace_notes(
    sources: &SourceResolver<'_, '_>,
    diagnostic: &mut FindingDiagnostic,
    trace: &InterpretedTrace,
) {
    if trace.steps.is_empty() {
        return;
    }

    for (index, total, step) in full_trace_steps(trace) {
        diagnostic.messages.push(DiagnosticMessage::TraceStep {
            span: sources.resolve(step.source_range.as_ref()).0,
            index,
            total,
            description: render_trace_step(step),
        });
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
    package: &'analysis LocalPackageProvenance,
}

impl SourceResolver<'_, '_> {
    fn owner(&self, function: FunctionId) -> FindingOwner {
        let stable_crate_id = function.def_path_hash.stable_crate_id();
        if stable_crate_id == self.local_stable_crate_id {
            return FindingOwner {
                scope: OwnerScope::Workspace,
                crate_name: Some(self.tcx.crate_name(LOCAL_CRATE).to_string()),
                package_name: self.package.package_name.clone(),
                package_version: self.package.package_version.clone(),
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
                package_name: artifact.package_name.clone(),
                package_version: artifact.package_version.clone(),
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
                package_name: None,
                package_version: None,
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
            package_name: None,
            package_version: None,
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
        CompilerAssertKind, ContractRequirementFact, FunctionAttributesFact, FunctionFact,
        FunctionFactProvenance, FunctionId, SafetyEffectGroupId, SafetyOpKind, SourceFileId,
        SourceRangeFact, StableDefPathHash, StableInstanceHash, UnverifiedMarkerProbeReason,
    };
    use crate::cli::findings::{
        DiagnosticMessage, FindingDiagnostic, FindingGroupSubtype, FindingKind, FindingOwner,
        OwnerScope, SourceEvidence,
    };
    use crate::report_model::{
        IncompleteReason, IncompleteTraceKind, InterpretedFinding, InterpretedFindingKind,
        InterpretedSafetyCallKind, InterpretedTrace, InterpretedTraceStep,
        InterpretedTraceStepKind, TraceFrontier, UnresolvedCallCoverage, UnresolvedCallMechanism,
        UnresolvedCallSite,
    };
    use rustc_span::{BytePos, Span};

    use super::{
        CompactFindingPlan, MarkerDomain, TraceLimit, add_missing_requirement_notes,
        compact_ambiguous_marker_action, compact_evidence_limitation, compact_marker_help,
        compact_workspace_path_help, documented_panic_action, exact_function_body_in,
        extern_paths_are_toolchain, external_containment_help, finding_presentation,
        full_ambiguous_marker_action, full_trace_steps, incomplete_group_subtype,
        incomplete_limit_presentation, missing_body_diagnostic_message, select_marker_call,
        source_evidence_help, source_evidence_note, source_evidence_reason, unresolved_action,
        unresolved_coverage_note, unresolved_primary_label,
    };

    #[test]
    fn incomplete_group_subtypes_ignore_configured_limit_values() {
        let function = FunctionId::generic(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000000000000000000001\"")
                .expect("test hash should deserialize"),
        );
        let frontier = || TraceFrontier {
            function,
            path: String::from("sample::frontier"),
            source_range: None,
            trace: InterpretedTrace { steps: Vec::new() },
        };

        let depth = |max_depth| IncompleteReason::TraceDepth {
            max_depth,
            trace_kind: IncompleteTraceKind::PanicEffect,
            frontier: frontier(),
        };
        assert_eq!(
            incomplete_group_subtype(&depth(8)),
            incomplete_group_subtype(&depth(64)),
        );

        let budget = |budget| IncompleteReason::TraceStateBudget {
            budget,
            trace_kind: IncompleteTraceKind::PanicComment,
            frontier: frontier(),
        };
        assert_eq!(
            incomplete_group_subtype(&budget(1_000)),
            incomplete_group_subtype(&budget(50_000)),
        );
        assert_ne!(
            incomplete_group_subtype(&depth(8)),
            FindingGroupSubtype::TraceStateBudget {
                trace_kind: IncompleteTraceKind::PanicEffect,
            },
        );
    }

    #[test]
    fn compact_messages_prefer_one_distinct_workspace_action() {
        let primary = Span::with_root_ctxt(BytePos(10), BytePos(20));
        let workspace_call = Span::with_root_ctxt(BytePos(30), BytePos(40));

        let messages = CompactFindingPlan {
            primary: Some((primary, String::from("the panic originates here"))),
            limitation: None,
            nearest_workspace_action: Some((
                workspace_call,
                String::from("account for this path at the nearest local call"),
            )),
            primary_help: String::from("add a source justification"),
        }
        .into_messages();

        assert_eq!(
            messages,
            [
                DiagnosticMessage::SpanLabel(primary, String::from("the panic originates here")),
                DiagnosticMessage::SpanHelp(
                    workspace_call,
                    String::from("account for this path at the nearest local call")
                ),
            ]
        );
    }

    #[test]
    fn compact_messages_avoid_duplicate_spans_and_keep_one_actionable_help() {
        let primary = Span::with_root_ctxt(BytePos(10), BytePos(20));

        let messages = CompactFindingPlan {
            primary: Some((primary, String::from("the panic originates here"))),
            limitation: None,
            nearest_workspace_action: Some((
                primary,
                String::from("do not repeat this span as containment"),
            )),
            primary_help: String::from("add a source justification"),
        }
        .into_messages();

        assert_eq!(
            messages,
            [
                DiagnosticMessage::SpanLabel(primary, String::from("the panic originates here")),
                DiagnosticMessage::Help(String::from("add a source justification")),
            ]
        );
    }

    #[test]
    fn compact_workspace_panic_help_keeps_both_valid_remediations() {
        let owner = FindingOwner {
            scope: OwnerScope::Workspace,
            crate_name: Some(String::from("sample")),
            package_name: None,
            package_version: None,
        };

        let help = compact_marker_help(
            MarkerDomain::Panic,
            &owner,
            Some(SourceEvidence::VerifiedAbsent),
            &[],
        );

        assert!(help.contains("`# Panics`"));
        assert!(help.contains("`// PANIC:`"));
        assert!(help.contains("if an invariant rules it out"));
    }

    #[test]
    fn compact_contract_and_external_ambiguity_actions_match_effect_semantics() {
        let requirement = ContractRequirementFact {
            name: String::from("documented"),
            condition: String::from("the documented condition holds"),
            structural_path: vec![0],
            source_range: None,
        };
        let contract_action = documented_panic_action(&[requirement]);
        assert!(contract_action.contains("`// PANIC:`"));
        assert!(!contract_action.contains("enclosing `# Panics`"));

        let toolchain = FindingOwner {
            scope: OwnerScope::Toolchain,
            crate_name: Some(String::from("core")),
            package_name: None,
            package_version: None,
        };
        assert_eq!(
            compact_ambiguous_marker_action(MarkerDomain::Safety, &toolchain),
            "if `core`'s surface contracts are trusted, add `core` to `[safety].trusted-boundary-namespaces`; otherwise audit or upgrade it"
        );
        let full_action = full_ambiguous_marker_action(MarkerDomain::Safety, &toolchain);
        assert!(full_action.contains("`[safety].trusted-boundary-namespaces`"));
        assert!(full_action.contains("`ambiguous-safety-marker = \"allow\"`"));
        assert!(!full_action.contains("give each safety obligation"));
    }

    #[test]
    fn compact_path_help_stays_at_an_ambiguous_marker_and_names_requirements() {
        let function = FunctionId::generic(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000000000000000000001\"")
                .expect("test hash should deserialize"),
        );
        let finding = |kind, missing_requirements| InterpretedFinding {
            contract_source_range: None,
            kind,
            function,
            function_path: String::from("app::root"),
            target: None,
            source_range: None,
            marker_evidence: None,
            trace: InterpretedTrace { steps: Vec::new() },
            missing_requirements,
            requirements: Vec::new(),
        };
        let ambiguous = finding(
            InterpretedFindingKind::AmbiguousSafetyMarker { effect_count: 2 },
            Vec::new(),
        );
        let initialized = ContractRequirementFact {
            name: String::from("initialized"),
            condition: String::from("state has been initialized"),
            structural_path: vec![0],
            source_range: None,
        };
        let mut partial = finding(
            InterpretedFindingKind::SafetyCall {
                documents_contract: true,
                kind: InterpretedSafetyCallKind::Obligation,
            },
            vec![initialized.clone()],
        );
        partial.requirements = vec![
            initialized,
            ContractRequirementFact {
                name: String::from("exclusive"),
                condition: String::from("access is exclusive"),
                structural_path: vec![1],
                source_range: None,
            },
        ];

        assert_eq!(compact_workspace_path_help(&ambiguous), None);
        assert!(
            compact_workspace_path_help(&partial)
                .expect("safety path has a local action")
                .contains("`initialized`")
        );
    }

    #[test]
    fn compact_unresolved_actions_follow_callable_semantics() {
        assert_eq!(
            unresolved_action(
                MarkerDomain::Panic,
                UnresolvedCallMechanism::DynamicDispatch,
            ),
            "document caller-visible panic behavior under `# Panics` on the trait method declaration"
        );
        assert_eq!(
            unresolved_action(
                MarkerDomain::Safety,
                UnresolvedCallMechanism::GenericDispatch,
            ),
            "document caller safety requirements under `# Safety` on the trait method declaration"
        );
        assert_eq!(
            unresolved_action(
                MarkerDomain::Panic,
                UnresolvedCallMechanism::FunctionPointer,
            ),
            "make the callee concrete or make its possible implementations available to analysis"
        );
    }

    #[test]
    fn compact_unverified_evidence_keeps_one_concise_limitation() {
        let function = FunctionId::generic(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000000000000000000001\"")
                .expect("test hash should deserialize"),
        );
        let finding = InterpretedFinding {
            contract_source_range: None,
            kind: InterpretedFindingKind::UnsafeOperation {
                kind: SafetyOpKind::DerefRawPointer,
            },
            function,
            function_path: String::from("app::root"),
            target: None,
            source_range: None,
            marker_evidence: None,
            trace: InterpretedTrace { steps: Vec::new() },
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
        };

        assert_eq!(
            compact_evidence_limitation(
                &finding,
                Some(SourceEvidence::Unverified {
                    reason: UnverifiedMarkerProbeReason::NoUsableSourceSpan,
                })
            ),
            Some(String::from(
                "could not verify usable `// SAFETY:` justification at the source: no usable span was available for marker association"
            ))
        );
    }

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
            definitions: Vec::new(),
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
            definitions: Vec::new(),
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
            package_name: None,
            package_version: None,
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
        let note = source_evidence_note(MarkerDomain::Safety, &owner, evidence, false);
        let rendered = format!("{reason} {help}");

        assert!(rendered.contains("could not verify"));
        assert!(rendered.contains("no usable span was available for marker association"));
        assert!(note.contains("could not verify"));
        assert!(note.contains("no usable span was available for marker association"));
        assert!(!rendered.contains("missing"));
        assert!(!rendered.contains("no recorded"));
        assert!(!rendered.contains("add `// SAFETY:` above"));
        assert!(!note.contains("missing"));
        assert!(!note.contains("no recorded"));

        let mut diagnostic = FindingDiagnostic {
            second_primary_span: None,
            span: None,
            message: String::new(),
            messages: Vec::new(),
            compact_messages: None,
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
            package_name: None,
            package_version: None,
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
        let note = source_evidence_note(
            MarkerDomain::Panic,
            &owner,
            SourceEvidence::VerifiedAbsent,
            false,
        );
        let containment =
            external_containment_help(MarkerDomain::Panic, SourceEvidence::VerifiedAbsent, false);

        assert!(reason.contains("dependency crate `dependency-panic`"));
        assert!(reason.contains("no recorded `// PANIC:` justification"));
        assert_eq!(
            note,
            "no `// PANIC:` justification was recorded for this source in dependency crate `dependency-panic`"
        );
        assert_eq!(
            help,
            "audit the source or upgrade dependency crate `dependency-panic`"
        );
        assert_eq!(
            containment,
            "document this call's panic conditions under `# Panics`, or explain why it cannot panic with `// PANIC:`"
        );
    }

    #[test]
    fn partial_path_evidence_only_recommends_recording_remaining_requirements() {
        let containment =
            external_containment_help(MarkerDomain::Safety, SourceEvidence::VerifiedAbsent, true);

        assert!(containment.contains("already discharges some `# Safety` requirements"));
        assert!(containment.contains("document only the remaining requirements"));
        assert!(!containment.contains("record a local `// SAFETY:` containment"));
    }

    #[test]
    fn present_evidence_describes_remaining_requirements() {
        let owner = FindingOwner {
            scope: OwnerScope::Workspace,
            crate_name: Some(String::from("app")),
            package_name: None,
            package_version: None,
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
    #[allow(
        clippy::too_many_lines,
        reason = "the table keeps every first-slice diagnostic contract directly comparable"
    )]
    fn human_finding_presentations_separate_headlines_labels_and_report_reasons() {
        struct Case {
            name: &'static str,
            interpreted_kind: InterpretedFindingKind,
            target: Option<&'static str>,
            evidence: Option<SourceEvidence>,
            expected_kind: FindingKind,
            expected_reason: &'static str,
            expected_headline: &'static str,
            expected_primary_label: &'static str,
        }

        let cases = [
            Case {
                name: "panic source",
                interpreted_kind: InterpretedFindingKind::PanicSink,
                target: Some("core::panicking::panic_fmt"),
                evidence: Some(SourceEvidence::VerifiedAbsent),
                expected_kind: FindingKind::PanicInvocation,
                expected_reason: "panic invocation to `core::panicking::panic_fmt` has no recorded `// PANIC:` justification",
                expected_headline: "this panic is not accounted for on every path",
                expected_primary_label: "the panic originates here",
            },
            Case {
                name: "division assertion",
                interpreted_kind: InterpretedFindingKind::CompilerAssert {
                    kind: CompilerAssertKind::DivisionByZero,
                },
                target: Some("compiler assert division by zero"),
                evidence: Some(SourceEvidence::VerifiedAbsent),
                expected_kind: FindingKind::CompilerAssert {
                    compiler_assert_kind: CompilerAssertKind::DivisionByZero,
                },
                expected_reason: "compiler assertion (division by zero) has no recorded `// PANIC:` justification",
                expected_headline: "this division may panic",
                expected_primary_label: "the divisor may be zero",
            },
            Case {
                name: "raw pointer dereference",
                interpreted_kind: InterpretedFindingKind::UnsafeOperation {
                    kind: SafetyOpKind::DerefRawPointer,
                },
                target: None,
                evidence: Some(SourceEvidence::VerifiedAbsent),
                expected_kind: FindingKind::UnsafeOpMissingJustification {
                    safety_op_kind: SafetyOpKind::DerefRawPointer,
                },
                expected_reason: "unsafe operation (raw pointer dereference) has no recorded `// SAFETY:` justification",
                expected_headline: "raw pointer dereference requires a safety justification",
                expected_primary_label: "dereferencing requires a valid and properly aligned pointer",
            },
            Case {
                name: "raw pointer dereference with unverified source evidence",
                interpreted_kind: InterpretedFindingKind::UnsafeOperation {
                    kind: SafetyOpKind::DerefRawPointer,
                },
                target: None,
                evidence: Some(SourceEvidence::Unverified {
                    reason: UnverifiedMarkerProbeReason::NoUsableSourceSpan,
                }),
                expected_kind: FindingKind::UnsafeOpMissingJustification {
                    safety_op_kind: SafetyOpKind::DerefRawPointer,
                },
                expected_reason: "could not verify `// SAFETY:` justification for unsafe operation (raw pointer dereference) in workspace crate `app`: no usable span was available for marker association",
                expected_headline: "raw pointer dereference requires a safety justification",
                expected_primary_label: "dereferencing requires a valid and properly aligned pointer",
            },
            Case {
                name: "unsafe call",
                interpreted_kind: InterpretedFindingKind::SafetyCall {
                    documents_contract: true,
                    kind: InterpretedSafetyCallKind::Unsafe,
                },
                target: Some("app::unsafe_target"),
                evidence: Some(SourceEvidence::VerifiedAbsent),
                expected_kind: FindingKind::UnsafeCallMissingJustification,
                expected_reason: "unsafe call to `app::unsafe_target` has no recorded `// SAFETY:` justification",
                expected_headline: "unsafe call requires a safety justification",
                expected_primary_label: "this call requires its safety preconditions to hold",
            },
            Case {
                name: "documented panic call",
                interpreted_kind: InterpretedFindingKind::DocumentedPanic,
                target: Some("app::documented"),
                evidence: Some(SourceEvidence::VerifiedAbsent),
                expected_kind: FindingKind::DocumentedPanic,
                expected_reason: "call to `app::documented` with a `# Panics` obligation has no recorded `// PANIC:` justification",
                expected_headline: "this call's documented panic conditions are not accounted for",
                expected_primary_label: "`app::documented` documents when this call may panic",
            },
            Case {
                name: "unresolved panic target",
                interpreted_kind: InterpretedFindingKind::UnresolvedPanicCallTarget {
                    site: UnresolvedCallSite {
                        coverage: UnresolvedCallCoverage::None,
                        mechanism: UnresolvedCallMechanism::FunctionPointer,
                    },
                },
                target: None,
                evidence: None,
                expected_kind: FindingKind::UnresolvedPanicCallTarget,
                expected_reason: "panic coverage is incomplete for unresolved function-pointer call target",
                expected_headline: "cannot determine whether this call may panic",
                expected_primary_label: "no concrete implementation could be determined",
            },
            Case {
                name: "unresolved safety target",
                interpreted_kind: InterpretedFindingKind::UnresolvedSafetyCallTarget {
                    site: UnresolvedCallSite {
                        coverage: UnresolvedCallCoverage::None,
                        mechanism: UnresolvedCallMechanism::DynamicDispatch,
                    },
                },
                target: None,
                evidence: None,
                expected_kind: FindingKind::UnresolvedSafetyCallTarget,
                expected_reason: "safety coverage is incomplete for unresolved dynamic-dispatch call target",
                expected_headline: "cannot determine whether this call has safety requirements",
                expected_primary_label: "no concrete implementation could be determined",
            },
        ];

        let hash =
            serde_json::from_str::<StableDefPathHash>("\"00000000000000000000000000000001\"")
                .expect("test hash should deserialize");
        let function = FunctionId::generic(hash);
        let owner = FindingOwner {
            scope: OwnerScope::Workspace,
            crate_name: Some(String::from("app")),
            package_name: None,
            package_version: None,
        };

        for case in cases {
            let finding = InterpretedFinding {
                contract_source_range: None,
                kind: case.interpreted_kind,
                function,
                function_path: String::from("app::root"),
                target: None,
                source_range: None,
                marker_evidence: None,
                trace: InterpretedTrace { steps: Vec::new() },
                missing_requirements: Vec::new(),
                requirements: Vec::new(),
            };

            let presentation = finding_presentation(&finding, case.target, &owner, case.evidence);

            assert_eq!(presentation.kind, case.expected_kind, "{}", case.name);
            assert_eq!(
                presentation.reason, case.expected_reason,
                "{} must preserve the existing JSON report reason",
                case.name
            );
            assert_eq!(
                presentation.headline, case.expected_headline,
                "{} must use a short user-facing headline",
                case.name
            );
            assert_eq!(
                presentation.primary_label, case.expected_primary_label,
                "{} must explain the primary span in user-facing terms",
                case.name
            );
        }
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
    fn full_trace_steps_follow_report_root_to_effect_source_order() {
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
            unresolved_primary_label(UnresolvedCallCoverage::None),
            "no concrete implementation could be determined"
        );
        assert_eq!(
            unresolved_primary_label(UnresolvedCallCoverage::Partial),
            "some possible implementations could not be determined"
        );
        assert_eq!(
            unresolved_action(MarkerDomain::Safety, dynamic.mechanism),
            "document caller safety requirements under `# Safety` on the trait method declaration"
        );
    }
}
