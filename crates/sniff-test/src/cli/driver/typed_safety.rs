//! Unified permanent typed-safety evaluation and report projection.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::analysis::cache::{ArtifactAnalysisCache, RustcArtifactId};
use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
use crate::analysis::facts::composition::{
    CompositionRelationBuilder, WorkspaceEvaluationView, WorkspaceRelationIndex,
};
use crate::analysis::facts::evaluation::{
    EvaluationDb, EvaluationIssueContext, EvaluationRoot, TypedDerivedRow, TypedEvaluatedIssue,
};
use crate::analysis::facts::evidence::{
    AmbiguousEvidenceReuseIssue, EvidenceCoordinatorPack, EvidenceSemanticEdgeOrder,
    EvidenceSemanticOrder, EvidenceSemanticSourceOrder, EvidenceSemanticStepOrder,
    EvidenceUseRecord, canonical_evidence_use,
};
use crate::analysis::facts::human::EvidenceClaimSelector;
use crate::analysis::facts::human::HumanEvidencePack;
use crate::analysis::facts::human::markers::{MarkerClaimEntity, MarkerOccurrenceEntity};
use crate::analysis::facts::pack::{AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::panic::PanicIncompleteReason;
use crate::analysis::facts::panic::trace_route::{
    SelectedTraceRoute, TraceRouteEndpoint, TraceRouteSelector,
};
use crate::analysis::facts::program::root_traversal::{
    MarkerProbe, ResolvedBodyVisit, ResolvedCallBoundary, ResolvedCallMacroCallsite,
    ResolvedCallMacroFrame, ResolvedCallSourceAnchor, ResolvedFollowedCall, ResolvedMarkerClaim,
    ResolvedUnsafeOperationMacroCallsite, ResolvedUnsafeOperationMacroFrame,
    ResolvedUnsafeOperationSourceAnchor, ResolvedUnsafeOperationVisit, RootProgramTraversalError,
};
use crate::analysis::facts::program::topology::{
    CallAttributionRole, CallKind, CallSourceAnchorRole,
};
use crate::analysis::facts::program::{FunctionEntity, FunctionKey};
use crate::analysis::facts::safety::{
    DuplicateSafetyCallRequirementIssue, DuplicateSafetyRootRequirementIssue,
    IndirectSafetyCallBoundaryIssue, MissingSafetyDocsIssue, PreparedSafetyRootBatch,
    SafetyAnalysisIncompleteIssue, SafetyBoundary, SafetyCallIssueKind, SafetyCallIssuePack,
    SafetyCompletenessOutcome, SafetyCompletenessPack, SafetyEvidenceUsePack,
    SafetyOperationIssuePack, SafetyRootInputError, SafetyRootInputs, SafetyRootIssuePack,
    SafetyRootRequest, UnsatisfiedSafetyCallIssue, UnsatisfiedUnsafeOperationIssue, safety_domain,
};
use crate::analysis::facts::schema::{EntitySchema, PassId, RowSchema};
use crate::analysis::facts::workspace::{ArtifactScopeId, ScopedEntityRef, ScopedRowRef};
use crate::analysis::findings::{
    InterpretationRoot, InterpretedFinding, InterpretedFindingKind, InterpretedSafetyCallKind,
    InterpretedTarget, InterpretedTrace, InterpretedTraceStep, InterpretedTraceStepKind,
};
use crate::analysis::ir::{
    CallEdgeKindIr, CallId, ContractRequirementIr, FunctionId, SourceFileIr, SourceRangeIr,
};
use crate::analysis::workspace_closure::{ManagedArtifactManifest, VerifiedWorkspaceClosure};
use crate::config::{CallableEdgeAttribution, MarkerProbing, SniffTestConfig};
use crate::contracts::normalize_requirement_name;

use super::interpretation::{
    FindingSources, adapt_typed_panic_call_finding, adapt_typed_safety_incomplete_finding,
};
use super::typed_panic::{
    FunctionPresentationIndex, TypedPanicLocalArtifact, open_typed_artifacts,
    permanent_source_files, source_range,
};
use super::typed_panic_call::{
    call_edge_kind, function_id, marker_owner_from_activation, merge_physical_marker_owner,
    physical_marker_source,
};
use crate::cli::findings::Finding;

#[derive(Debug)]
pub(super) enum TypedSafetyEvaluationError {
    Registration(Box<PackRegistrationError>),
    Stage {
        stage: &'static str,
        source: Box<dyn Error>,
    },
    PreparedRootCount {
        expected: usize,
        actual: usize,
    },
    InvalidProjection {
        subject: String,
        reason: String,
    },
}

impl Display for TypedSafetyEvaluationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registration(source) => {
                write!(
                    formatter,
                    "typed safety registry initialization failed: {source}"
                )
            }
            Self::Stage { stage, source } => {
                write!(formatter, "typed safety {stage} failed: {source}")
            }
            Self::PreparedRootCount { expected, actual } => write!(
                formatter,
                "typed safety prepared {actual} roots for {expected} requests"
            ),
            Self::InvalidProjection { subject, reason } => {
                write!(formatter, "typed safety {subject} is invalid: {reason}")
            }
        }
    }
}

impl Error for TypedSafetyEvaluationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Registration(source) => Some(source),
            Self::Stage { source, .. } => Some(source.as_ref()),
            Self::PreparedRootCount { .. } | Self::InvalidProjection { .. } => None,
        }
    }
}

fn stage(stage: &'static str, source: impl Error + 'static) -> TypedSafetyEvaluationError {
    TypedSafetyEvaluationError::Stage {
        stage,
        source: Box::new(source),
    }
}

fn invalid(subject: impl Into<String>, reason: impl Into<String>) -> TypedSafetyEvaluationError {
    TypedSafetyEvaluationError::InvalidProjection {
        subject: subject.into(),
        reason: reason.into(),
    }
}

#[derive(Clone, Debug)]
pub(super) struct TypedSafetyRootReport {
    pub(super) request: InterpretationRoot,
    pub(super) root: EvaluationRoot,
    pub(super) presentation_range: Option<SourceRangeIr>,
    pub(super) inputs: SafetyRootInputs,
    pub(super) missing_docs: Vec<TypedEvaluatedIssue<MissingSafetyDocsIssue>>,
    pub(super) duplicate_root_requirements:
        Vec<TypedEvaluatedIssue<DuplicateSafetyRootRequirementIssue>>,
    pub(super) unsafe_operations: Vec<TypedEvaluatedIssue<UnsatisfiedUnsafeOperationIssue>>,
    pub(super) unsatisfied_calls: Vec<TypedEvaluatedIssue<UnsatisfiedSafetyCallIssue>>,
    pub(super) duplicate_call_requirements:
        Vec<TypedEvaluatedIssue<DuplicateSafetyCallRequirementIssue>>,
    pub(super) indirect_calls: Vec<TypedEvaluatedIssue<IndirectSafetyCallBoundaryIssue>>,
    pub(super) completeness: Vec<TypedDerivedRow<SafetyCompletenessOutcome>>,
    pub(super) incomplete: Vec<TypedEvaluatedIssue<SafetyAnalysisIncompleteIssue>>,
    pub(super) evidence_uses: Vec<TypedDerivedRow<EvidenceUseRecord>>,
    pub(super) ambiguities: Vec<TypedEvaluatedIssue<AmbiguousEvidenceReuseIssue>>,
    pub(super) ambiguity_findings: Vec<InterpretedFinding>,
}

#[derive(Clone, Debug)]
pub(super) struct TypedSafetyBatchReport {
    prepared_root_bindings: Vec<TypedSafetyPreparedRootBinding>,
    pub(super) root_preparations: Vec<TypedSafetyRootPreparationReport>,
    pub(super) roots: Vec<TypedSafetyRootReport>,
    pub(super) source_files: Vec<SourceFileIr>,
    pub(super) function_ranges: BTreeMap<FunctionId, SourceRangeIr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TypedSafetyPreparedRootBinding {
    root: EvaluationRoot,
    selected_function: FunctionKey,
    selected_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TypedSafetyRootPreparationReport {
    pub(super) request_ordinal: usize,
    pub(super) request: InterpretationRoot,
    pub(super) expected_scope: ArtifactScopeId,
    pub(super) requested_function: FunctionKey,
    pub(super) outcome: TypedSafetyRootPreparationOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum TypedSafetyRootPreparationOutcome {
    Evaluatable {
        report_index: usize,
        root: EvaluationRoot,
        selected_function: FunctionKey,
    },
    Missing {
        reason: crate::analysis::findings::IncompleteReason,
    },
}

#[derive(Debug)]
struct PendingSafetyRootPreparation {
    request_ordinal: usize,
    request: InterpretationRoot,
    expected_scope: ArtifactScopeId,
    requested_function: FunctionKey,
    outcome: PendingSafetyRootPreparationOutcome,
}

#[derive(Debug)]
enum PendingSafetyRootPreparationOutcome {
    Evaluatable {
        report_index: usize,
        selected_function: FunctionKey,
    },
    Missing {
        reason: crate::analysis::findings::IncompleteReason,
    },
}

fn typed_safety_authority_registry()
-> Result<AnalysisRegistry<SafetyRootInputs>, PackRegistrationError> {
    let mut registry = AnalysisRegistry::new();
    registry.install(&CollectedArtifactSchemaPack)?;
    registry.install(&HumanEvidencePack)?;
    registry.install(&SafetyRootIssuePack)?;
    registry.install(&SafetyOperationIssuePack)?;
    registry.install(&SafetyCallIssuePack)?;
    registry.install(&SafetyEvidenceUsePack)?;
    registry.install(&SafetyCompletenessPack)?;
    registry.install(&EvidenceCoordinatorPack)?;
    Ok(registry)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "mirrors the workspace authority boundary"
)]
pub(super) fn evaluate_typed_safety_roots(
    local: TypedPanicLocalArtifact<'_>,
    dependencies: &[&ArtifactAnalysisCache],
    direct_dependencies: Vec<RustcArtifactId>,
    active_runtime_artifacts: &[RustcArtifactId],
    roots: &[InterpretationRoot],
    config: &SniffTestConfig,
) -> Result<TypedSafetyBatchReport, TypedSafetyEvaluationError> {
    if roots.is_empty() {
        return Ok(TypedSafetyBatchReport {
            prepared_root_bindings: Vec::new(),
            root_preparations: Vec::new(),
            roots: Vec::new(),
            source_files: Vec::new(),
            function_ranges: BTreeMap::new(),
        });
    }
    let registry = typed_safety_authority_registry()
        .map_err(|source| TypedSafetyEvaluationError::Registration(Box::new(source)))?;
    let opened = open_typed_artifacts(local, dependencies, &registry)
        .map_err(|source| stage("artifact opening", source))?;
    let workspace = crate::analysis::facts::workspace::WorkspaceFactView::compose(opened.views)
        .map_err(|source| stage("workspace composition", source))?;
    let source_files =
        permanent_source_files(&workspace).map_err(|source| stage("source projection", source))?;
    let closure = VerifiedWorkspaceClosure::open_with_runtime_inventory(
        &workspace,
        ManagedArtifactManifest::new(opened.local_generation, direct_dependencies),
        opened.dependency_manifests,
        active_runtime_artifacts.iter().cloned(),
    )
    .map_err(|source| stage("workspace closure", source))?;
    let expected_scope = closure.root_scope().clone();
    closure
        .program()
        .validate_workspace(&workspace)
        .map_err(|source| stage("root preparation", source))?;
    let local_stable_crate_id = closure
        .program()
        .stable_crate_id(&expected_scope)
        .map_err(|source| stage("root preparation", source))?;
    let mut pending = Vec::with_capacity(roots.len());
    let mut ready_ordinals = Vec::with_capacity(roots.len());
    let mut ready_requests = Vec::with_capacity(roots.len());
    for (request_ordinal, request) in roots.iter().enumerate() {
        let requested_function = FunctionKey::new(
            request.function.def_path_hash,
            request.function.instance_hash,
        );
        if requested_function.definition().stable_crate_id() != local_stable_crate_id {
            return Err(invalid(
                "root preparation",
                format!(
                    "request {request_ordinal} names a foreign stable crate instead of {local_stable_crate_id:016x}"
                ),
            ));
        }
        let candidates = closure
            .program()
            .body_candidates(&expected_scope, &requested_function)
            .map_err(|source| stage("root preparation", source))?;
        let outcome = if let Some(selected) = candidates.first() {
            let report_index = ready_requests.len();
            ready_ordinals.push(request_ordinal);
            ready_requests.push(safety_root_request(request, config));
            PendingSafetyRootPreparationOutcome::Evaluatable {
                report_index,
                selected_function: *selected.body().data().key(),
            }
        } else {
            PendingSafetyRootPreparationOutcome::Missing {
                reason: crate::analysis::findings::IncompleteReason::MissingBody {
                    function: request.function,
                    path: request.path.clone(),
                    source_range: None,
                    trace: InterpretedTrace { steps: Vec::new() },
                },
            }
        };
        pending.push(PendingSafetyRootPreparation {
            request_ordinal,
            request: request.clone(),
            expected_scope: expected_scope.clone(),
            requested_function,
            outcome,
        });
    }
    let prepared = if ready_requests.is_empty() {
        let probe = safety_root_request(&pending[0].request, config);
        match PreparedSafetyRootBatch::prepare(
            &workspace,
            &closure,
            &config.safety,
            &config.documentation.overrides,
            [probe],
        ) {
            Err(SafetyRootInputError::Traversal(source))
                if matches!(
                    source.as_ref(),
                    RootProgramTraversalError::UnknownRoot { scope, function }
                        if scope == &expected_scope && function == &pending[0].requested_function
                ) =>
            {
                Vec::new()
            }
            Err(source) => return Err(stage("root preparation", source)),
            Ok(_) => {
                return Err(invalid(
                    "root preparation",
                    "the all-missing validation probe unexpectedly resolved",
                ));
            }
        }
    } else {
        PreparedSafetyRootBatch::prepare(
            &workspace,
            &closure,
            &config.safety,
            &config.documentation.overrides,
            ready_requests,
        )
        .map_err(|source| stage("root preparation", source))?
        .into_roots()
    };
    if prepared.len() != ready_ordinals.len() {
        return Err(TypedSafetyEvaluationError::PreparedRootCount {
            expected: ready_ordinals.len(),
            actual: prepared.len(),
        });
    }
    let mut prepared_root_bindings = Vec::with_capacity(prepared.len());
    for (report_index, root) in prepared.iter().enumerate() {
        let request_ordinal = ready_ordinals[report_index];
        let PendingSafetyRootPreparationOutcome::Evaluatable {
            selected_function, ..
        } = pending[request_ordinal].outcome
        else {
            unreachable!("ready ordinals refer only to evaluatable safety roots");
        };
        let selected = workspace
            .entity::<FunctionEntity>(&root.root().entity)
            .map_err(|source| stage("root preparation", source))?;
        if *selected.key() != selected_function {
            return Err(invalid(
                "root preparation",
                "core safety preparation selected a different body than the first candidate",
            ));
        }
        prepared_root_bindings.push(TypedSafetyPreparedRootBinding {
            root: root.root().clone(),
            selected_function,
            selected_path: selected.display_path().to_owned(),
        });
    }
    let root_preparations = pending
        .into_iter()
        .map(|preparation| {
            let outcome = match preparation.outcome {
                PendingSafetyRootPreparationOutcome::Evaluatable {
                    report_index,
                    selected_function,
                } => TypedSafetyRootPreparationOutcome::Evaluatable {
                    report_index,
                    root: prepared[report_index].root().clone(),
                    selected_function,
                },
                PendingSafetyRootPreparationOutcome::Missing { reason } => {
                    TypedSafetyRootPreparationOutcome::Missing { reason }
                }
            };
            TypedSafetyRootPreparationReport {
                request_ordinal: preparation.request_ordinal,
                request: preparation.request,
                expected_scope: preparation.expected_scope,
                requested_function: preparation.requested_function,
                outcome,
            }
        })
        .collect::<Vec<_>>();
    let relation_index = WorkspaceRelationIndex::open(&workspace)
        .map_err(|source| stage("relation indexing", source))?;
    let presentation_anchors = FunctionPresentationIndex::build(&workspace)
        .map_err(|source| stage("presentation", source))?;
    let function_ranges = presentation_anchors.function_ranges();
    let mut reports = Vec::with_capacity(prepared.len());
    for (prepared, request_ordinal) in prepared.into_iter().zip(ready_ordinals) {
        let request = &roots[request_ordinal];
        let root = prepared.root().clone();
        let mut relation_builder =
            CompositionRelationBuilder::new(&root, &workspace, registry.composition_relations())
                .map_err(|source| stage("relation composition", source))?;
        let emitted = prepared
            .emit(&mut relation_builder)
            .map_err(|source| stage("root emission", source))?;
        let relations = relation_builder
            .finalize()
            .map_err(|source| stage("relation composition", source))?;
        let graph = relation_index
            .bind(&root, relations)
            .map_err(|source| stage("relation binding", source))?;
        let inputs = emitted
            .resolve(&graph, registry.composition_relations())
            .map_err(|source| stage("root resolution", source))?;
        let evaluation = WorkspaceEvaluationView::from_graph(&workspace, graph)
            .map_err(|source| stage("evaluation input", source))?;
        let mut evaluated = EvaluationDb::new();
        registry
            .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
            .map_err(|source| stage("evaluation", source))?;
        let results = evaluated
            .finish()
            .map_err(|source| stage("evaluation results", source))?;
        macro_rules! issues {
            ($schema:ty) => {
                results
                    .issues::<$schema>(registry.schemas())
                    .map_err(|source| stage("issue decoding", source))?
            };
        }
        macro_rules! derived {
            ($schema:ty) => {
                results
                    .derived_rows::<$schema>(registry.schemas())
                    .map_err(|source| stage("derived-row decoding", source))?
            };
        }
        let mut report = TypedSafetyRootReport {
            request: request.clone(),
            presentation_range: presentation_anchors
                .range(&root.entity)
                .map_err(|source| stage("presentation", source))?,
            root,
            inputs,
            missing_docs: issues!(MissingSafetyDocsIssue),
            duplicate_root_requirements: issues!(DuplicateSafetyRootRequirementIssue),
            unsafe_operations: issues!(UnsatisfiedUnsafeOperationIssue),
            unsatisfied_calls: issues!(UnsatisfiedSafetyCallIssue),
            duplicate_call_requirements: issues!(DuplicateSafetyCallRequirementIssue),
            indirect_calls: issues!(IndirectSafetyCallBoundaryIssue),
            completeness: derived!(SafetyCompletenessOutcome),
            incomplete: issues!(SafetyAnalysisIncompleteIssue),
            evidence_uses: derived!(EvidenceUseRecord),
            ambiguities: issues!(AmbiguousEvidenceReuseIssue),
            ambiguity_findings: Vec::new(),
        };
        report.ambiguity_findings = project_safety_ambiguity_findings(&report, &evaluation)?;
        reports.push(report);
    }
    Ok(TypedSafetyBatchReport {
        prepared_root_bindings,
        root_preparations,
        roots: reports,
        source_files,
        function_ranges,
    })
}

struct TypedSafetyBatchPreflight {
    ready_roots: Vec<InterpretationRoot>,
    findings: Vec<Vec<InterpretedFinding>>,
    incomplete: Vec<Vec<crate::analysis::findings::IncompleteReason>>,
}

/// Adapts the complete typed-safety authority only after one source-free
/// validation pass over the sparse preparation mapping and every issue lane.
pub(super) fn adapt_typed_safety_authority_batch(
    sources: &impl FindingSources,
    batch: &TypedSafetyBatchReport,
    roots: &[InterpretationRoot],
    show_full_stack_trace: bool,
) -> Result<Vec<Finding>, TypedSafetyEvaluationError> {
    let preflight = preflight_typed_safety_batch(batch, roots)?;
    let capacity = preflight.findings.iter().map(Vec::len).sum::<usize>()
        + preflight.incomplete.iter().map(Vec::len).sum::<usize>()
        + batch
            .root_preparations
            .iter()
            .filter(|preparation| {
                matches!(
                    preparation.outcome,
                    TypedSafetyRootPreparationOutcome::Missing { .. }
                )
            })
            .count();
    let mut findings = Vec::with_capacity(capacity);
    for (report_index, root) in preflight.ready_roots.iter().enumerate() {
        findings.extend(preflight.findings[report_index].iter().map(|finding| {
            adapt_typed_panic_call_finding(sources, root, finding, show_full_stack_trace)
        }));
    }
    let mut ready_index = 0;
    for preparation in &batch.root_preparations {
        match &preparation.outcome {
            TypedSafetyRootPreparationOutcome::Evaluatable { report_index, .. } => {
                if *report_index != ready_index {
                    unreachable!("preflight proved dense safety report indices");
                }
                for reason in &preflight.incomplete[ready_index] {
                    findings.push(adapt_typed_safety_incomplete_finding(
                        sources,
                        &preparation.request,
                        reason.clone(),
                        show_full_stack_trace,
                    ));
                }
                ready_index += 1;
            }
            TypedSafetyRootPreparationOutcome::Missing { reason } => {
                findings.push(adapt_typed_safety_incomplete_finding(
                    sources,
                    &preparation.request,
                    reason.clone(),
                    show_full_stack_trace,
                ));
            }
        }
    }
    Ok(findings)
}

#[allow(
    clippy::too_many_lines,
    reason = "one source-free preflight keeps sparse preparation and all safety lanes atomic"
)]
fn preflight_typed_safety_batch(
    batch: &TypedSafetyBatchReport,
    roots: &[InterpretationRoot],
) -> Result<TypedSafetyBatchPreflight, TypedSafetyEvaluationError> {
    if batch.root_preparations.len() != roots.len() {
        return Err(invalid(
            "root preparation batch",
            "preparation count differs from requested roots",
        ));
    }
    let mut expected_scope = None;
    let mut ready_roots = Vec::new();
    let mut ready_preparations = Vec::new();
    for (ordinal, (preparation, request)) in batch.root_preparations.iter().zip(roots).enumerate() {
        let requested_function = FunctionKey::new(
            request.function.def_path_hash,
            request.function.instance_hash,
        );
        if preparation.request_ordinal != ordinal
            || preparation.request != *request
            || preparation.requested_function != requested_function
        {
            return Err(invalid(
                "root preparation report",
                format!("preparation {ordinal} does not match its request"),
            ));
        }
        if expected_scope
            .as_ref()
            .is_some_and(|scope| scope != &preparation.expected_scope)
        {
            return Err(invalid(
                "root preparation report",
                "preparations disagree about the local scope",
            ));
        }
        expected_scope.get_or_insert_with(|| preparation.expected_scope.clone());
        match &preparation.outcome {
            TypedSafetyRootPreparationOutcome::Evaluatable {
                report_index,
                root,
                selected_function,
            } => {
                if *report_index != ready_roots.len() {
                    return Err(invalid(
                        "root preparation report",
                        "ready report indices are not dense",
                    ));
                }
                let binding = batch
                    .prepared_root_bindings
                    .get(*report_index)
                    .ok_or_else(|| {
                        invalid(
                            "root preparation report",
                            "ready preparation has no producer binding",
                        )
                    })?;
                if root.domain != safety_domain()
                    || root.entity.entity().schema.as_str() != FunctionEntity::ID
                    || root.entity.scope() != &preparation.expected_scope
                    || binding.root != *root
                    || binding.selected_function != *selected_function
                {
                    return Err(invalid(
                        "root preparation report",
                        "prepared root or producer binding changed",
                    ));
                }
                ready_roots.push(request.clone());
                ready_preparations.push(preparation);
            }
            TypedSafetyRootPreparationOutcome::Missing { reason } => {
                let expected = crate::analysis::findings::IncompleteReason::MissingBody {
                    function: request.function,
                    path: request.path.clone(),
                    source_range: None,
                    trace: InterpretedTrace { steps: Vec::new() },
                };
                if reason != &expected {
                    return Err(invalid(
                        "root preparation report",
                        "missing root contains fabricated evidence",
                    ));
                }
            }
        }
    }
    if batch.prepared_root_bindings.len() != ready_roots.len()
        || batch.roots.len() != ready_roots.len()
    {
        return Err(invalid(
            "safety report batch",
            "ready reports or producer bindings are not dense",
        ));
    }
    let mut findings = Vec::with_capacity(batch.roots.len());
    let mut incomplete = Vec::with_capacity(batch.roots.len());
    for (index, ((report, request), preparation)) in batch
        .roots
        .iter()
        .zip(&ready_roots)
        .zip(ready_preparations)
        .enumerate()
    {
        let TypedSafetyRootPreparationOutcome::Evaluatable { root, .. } = &preparation.outcome
        else {
            unreachable!("ready safety preparations are evaluatable");
        };
        let binding = &batch.prepared_root_bindings[index];
        if report.request != *request
            || report.root != *root
            || report.inputs.root() != root
            || function_id(binding.selected_function)
                != function_id(*report.inputs.root_callable_data().key())
            || binding.selected_path != report.inputs.root_callable_data().display_path()
        {
            return Err(invalid(
                "safety root report",
                format!("ready report {index} changed its prepared root binding"),
            ));
        }
        let mut root_findings = project_safety_root_findings(report)?;
        root_findings.extend(project_unsafe_operation_findings(report)?);
        root_findings.extend(project_safety_call_findings(report)?);
        root_findings.extend(project_duplicate_safety_call_findings(report)?);
        root_findings.extend(project_indirect_safety_findings(report)?);
        for ambiguity in &report.ambiguity_findings {
            if !matches!(
                ambiguity.kind,
                InterpretedFindingKind::AmbiguousSafetyMarker { .. }
            ) || ambiguity.target.is_some()
                || ambiguity.source_range.is_none()
            {
                return Err(invalid(
                    "safety ambiguity finding",
                    "owned ambiguity projection changed after evaluation",
                ));
            }
        }
        root_findings.extend(report.ambiguity_findings.clone());
        incomplete.push(project_safety_incomplete_reasons(report)?);
        findings.push(root_findings);
    }
    Ok(TypedSafetyBatchPreflight {
        ready_roots,
        findings,
        incomplete,
    })
}

fn project_unsafe_operation_findings(
    report: &TypedSafetyRootReport,
) -> Result<Vec<InterpretedFinding>, TypedSafetyEvaluationError> {
    const PRODUCER: &str = "sniff-test.safety.report-unsafe-operations";
    let mut actual = std::collections::BTreeMap::new();
    for issue in &report.unsafe_operations {
        if issue.producer.as_str() != PRODUCER {
            return Err(invalid("unsafe-operation issue", "producer changed"));
        }
        if actual.insert(issue.data.witness_order(), issue).is_some() {
            return Err(invalid(
                "unsafe-operation issue",
                "witness order is duplicated",
            ));
        }
    }
    let mut selector = TraceRouteSelector::prepare(report.inputs.traversal());
    let mut findings = Vec::new();
    for visit in report.inputs.traversal().unsafe_operation_visits() {
        let unsatisfied = !visit.active_markers().iter().any(|marker| {
            marker.data().key().domain() == &report.root.domain
                && matches!(marker.data().selector(), EvidenceClaimSelector::Unnamed)
                && !marker.data().rationale().trim().is_empty()
        });
        let issue = actual.remove(&visit.order());
        if !unsatisfied {
            if issue.is_some() {
                return Err(invalid(
                    "unsafe-operation issue",
                    "satisfied operation has a report row",
                ));
            }
            continue;
        }
        let issue = issue.ok_or_else(|| {
            invalid(
                "unsafe-operation issue",
                "unsatisfied operation is missing its report row",
            )
        })?;
        let expected_context = EvaluationIssueContext::new(report.root.clone())
            .with_source(visit.operation().erase().as_row())
            .with_endpoint(visit.operation().erase())
            .with_trace(visit.trace().clone());
        if issue.data != UnsatisfiedUnsafeOperationIssue::new(visit.data().kind(), visit.order())
            || issue.context != expected_context
        {
            return Err(invalid(
                "unsafe-operation issue",
                "payload or full issue context changed",
            ));
        }
        let route = selector
            .select_route(TraceRouteEndpoint::new(
                visit.order(),
                visit.trace(),
                visit.inherited_markers(),
            ))
            .map_err(|source| invalid("unsafe-operation trace", format!("{source:?}")))?;
        findings.push(project_unsafe_operation_finding(visit, &route));
    }
    if !actual.is_empty() {
        return Err(invalid(
            "unsafe-operation issue",
            "report rows contain an orphan witness",
        ));
    }
    Ok(findings)
}

fn project_safety_call_findings(
    report: &TypedSafetyRootReport,
) -> Result<Vec<InterpretedFinding>, TypedSafetyEvaluationError> {
    const PRODUCER: &str = "sniff-test.safety.report-calls";
    let mut actual = std::collections::BTreeMap::new();
    for issue in &report.unsatisfied_calls {
        if issue.producer.as_str() != PRODUCER {
            return Err(invalid("safety-call issue", "producer changed"));
        }
        if actual.insert(issue.data.witness_order(), issue).is_some() {
            return Err(invalid("safety-call issue", "witness order is duplicated"));
        }
    }
    let mut selector = TraceRouteSelector::prepare(report.inputs.traversal());
    let mut findings = Vec::new();
    for boundary in report.inputs.traversal().call_boundaries() {
        let expected = expected_unsatisfied_safety_call(&report.root, boundary);
        let issue = actual.remove(&boundary.order());
        let Some(expected) = expected else {
            if issue.is_some() {
                return Err(invalid(
                    "safety-call issue",
                    "satisfied or non-reportable call has a report row",
                ));
            }
            continue;
        };
        let issue = issue.ok_or_else(|| {
            invalid(
                "safety-call issue",
                "unsatisfied call is missing its report row",
            )
        })?;
        let expected_context = EvaluationIssueContext::new(report.root.clone())
            .with_source(boundary.occurrence().erase().as_row())
            .with_endpoint(boundary.occurrence().erase())
            .with_trace(boundary.trace().clone());
        if issue.data != expected || issue.context != expected_context {
            return Err(invalid(
                "safety-call issue",
                "payload or full issue context changed",
            ));
        }
        let route = selector
            .select_route(TraceRouteEndpoint::new(
                boundary.order(),
                boundary.trace(),
                boundary.inherited_markers(),
            ))
            .map_err(|source| invalid("safety-call trace", format!("{source:?}")))?;
        let owner = selector
            .select_terminal_caller(
                &boundary.occurrence().erase(),
                *boundary.occurrence_data().key().owner(),
                boundary.inherited_markers(),
                boundary.trace(),
            )
            .map_err(|source| invalid("safety-call owner", format!("{source:?}")))?;
        findings.push(project_safety_call_finding(boundary, owner, &route, issue)?);
    }
    if !actual.is_empty() {
        return Err(invalid(
            "safety-call issue",
            "report rows contain an orphan witness",
        ));
    }
    Ok(findings)
}

#[allow(
    clippy::too_many_lines,
    reason = "the duplicate-group bijection and its owned finding projection form one validation boundary"
)]
fn project_duplicate_safety_call_findings(
    report: &TypedSafetyRootReport,
) -> Result<Vec<InterpretedFinding>, TypedSafetyEvaluationError> {
    let mut actual = std::collections::BTreeMap::new();
    for issue in &report.duplicate_call_requirements {
        if issue.producer.as_str() != "sniff-test.safety.report-calls"
            || actual
                .insert(
                    (
                        issue.data.witness_order(),
                        issue.data.normalized_name().to_owned(),
                    ),
                    issue,
                )
                .is_some()
        {
            return Err(invalid(
                "duplicate safety-call requirement",
                "producer or exact group identity changed",
            ));
        }
    }
    let mut selector = TraceRouteSelector::prepare(report.inputs.traversal());
    let mut findings = Vec::new();
    for boundary in report.inputs.traversal().call_boundaries() {
        let SafetyBoundary::CallContract(call_contract) = boundary.payload() else {
            continue;
        };
        let route = selector
            .select_route(TraceRouteEndpoint::new(
                boundary.order(),
                boundary.trace(),
                boundary.inherited_markers(),
            ))
            .map_err(|source| invalid("duplicate safety-call trace", format!("{source:?}")))?;
        let owner = selector
            .select_terminal_caller(
                &boundary.occurrence().erase(),
                *boundary.occurrence_data().key().owner(),
                boundary.inherited_markers(),
                boundary.trace(),
            )
            .map_err(|source| invalid("duplicate safety-call owner", format!("{source:?}")))?;
        for group in call_contract.contract().duplicate_requirement_groups() {
            let issue = actual
                .remove(&(boundary.order(), group.normalized_name().to_owned()))
                .ok_or_else(|| {
                    invalid(
                        "duplicate safety-call requirement",
                        "expected duplicate group is missing",
                    )
                })?;
            let ordinals = group
                .requirements()
                .iter()
                .map(crate::analysis::facts::safety::EffectiveSafetyRequirement::ordinal)
                .collect::<Vec<_>>();
            let mut expected_context = EvaluationIssueContext::new(report.root.clone())
                .with_source(boundary.occurrence().erase().as_row())
                .with_endpoint(boundary.occurrence().erase())
                .with_trace(boundary.trace().clone());
            if let Some(source) = call_contract.contract().raw_contract() {
                expected_context = expected_context.with_source(source.clone());
            }
            if issue.data
                != DuplicateSafetyCallRequirementIssue::new(
                    boundary.order(),
                    group.normalized_name(),
                    ordinals,
                )
                || issue.context != expected_context
            {
                return Err(invalid(
                    "duplicate safety-call requirement",
                    "payload or full issue context changed",
                ));
            }
            let trace = terminal_call_trace(boundary, owner, &route);
            findings.push(InterpretedFinding {
                kind: InterpretedFindingKind::AmbiguousSafetyRequirement {
                    normalized_name: group.normalized_name().to_owned(),
                },
                function: function_id(*owner.data().key()),
                function_path: owner.data().display_path().to_owned(),
                target: boundary.target_data().map(|target| InterpretedTarget {
                    function: Some(function_id(*target.key())),
                    path: target.display_path().to_owned(),
                }),
                source_range: call_contract
                    .contract()
                    .source_anchor()
                    .map(|anchor| source_range(&anchor.data().key())),
                trace,
                missing_requirements: Vec::new(),
                requirements: group
                    .requirements()
                    .iter()
                    .map(safety_requirement)
                    .collect(),
            });
        }
    }
    if !actual.is_empty() {
        return Err(invalid(
            "duplicate safety-call requirement",
            "report rows contain an orphan group",
        ));
    }
    Ok(findings)
}

fn terminal_call_trace(
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        SafetyBoundary,
    >,
    owner: &ResolvedBodyVisit,
    route: &SelectedTraceRoute<'_>,
) -> InterpretedTrace {
    let mut steps = route_steps(route);
    let mut caller = function_id(*owner.data().key());
    let mut caller_path = owner.data().display_path().to_owned();
    let call = CallId::new(boundary.occurrence_data().key().local_id());
    append_call_macro_steps(
        &mut steps,
        &mut caller,
        &mut caller_path,
        call,
        boundary.macro_frames(),
    );
    steps.push(InterpretedTraceStep {
        caller,
        caller_path,
        call,
        kind: InterpretedTraceStepKind::Reachability(call_edge_kind(boundary.effective_kind())),
        source_range: selected_call_source(boundary.source_anchors(), true).map(source_range),
        target: boundary
            .target_data()
            .map(|target| function_id(*target.key())),
        target_path: boundary
            .target_data()
            .map(|target| target.display_path().to_owned()),
    });
    InterpretedTrace { steps }
}

fn project_indirect_safety_findings(
    report: &TypedSafetyRootReport,
) -> Result<Vec<InterpretedFinding>, TypedSafetyEvaluationError> {
    let mut actual = std::collections::BTreeMap::new();
    for issue in &report.indirect_calls {
        if issue.producer.as_str() != "sniff-test.safety.report-calls" {
            return Err(invalid("indirect safety-call issue", "producer changed"));
        }
        if actual.insert(issue.data.witness_order(), issue).is_some() {
            return Err(invalid(
                "indirect safety-call issue",
                "witness order is duplicated",
            ));
        }
    }
    let mut selector = TraceRouteSelector::prepare(report.inputs.traversal());
    let mut findings = Vec::new();
    for boundary in report.inputs.traversal().call_boundaries() {
        let expected_description = match boundary.payload() {
            SafetyBoundary::BodylessDeclaration if is_actual_call(boundary.effective_kind()) => {
                Some(
                    boundary
                        .target_data()
                        .map_or("bodyless declaration", |target| target.display_path()),
                )
            }
            SafetyBoundary::OpaqueCall { description }
                if is_actual_call(boundary.effective_kind()) =>
            {
                Some(description.as_str())
            }
            _ => None,
        };
        let issue = actual.remove(&boundary.order());
        let Some(description) = expected_description else {
            if issue.is_some() {
                return Err(invalid(
                    "indirect safety-call issue",
                    "verifiable or non-call boundary has a report row",
                ));
            }
            continue;
        };
        let issue = issue.ok_or_else(|| {
            invalid(
                "indirect safety-call issue",
                "unverifiable call is missing its report row",
            )
        })?;
        let expected_context = EvaluationIssueContext::new(report.root.clone())
            .with_source(boundary.occurrence().erase().as_row())
            .with_endpoint(boundary.occurrence().erase())
            .with_trace(boundary.trace().clone());
        if issue.data != IndirectSafetyCallBoundaryIssue::new(boundary.order(), description)
            || issue.context != expected_context
        {
            return Err(invalid(
                "indirect safety-call issue",
                "payload or full issue context changed",
            ));
        }
        let route = selector
            .select_route(TraceRouteEndpoint::new(
                boundary.order(),
                boundary.trace(),
                boundary.inherited_markers(),
            ))
            .map_err(|source| invalid("indirect safety-call trace", format!("{source:?}")))?;
        let owner = selector
            .select_terminal_caller(
                &boundary.occurrence().erase(),
                *boundary.occurrence_data().key().owner(),
                boundary.inherited_markers(),
                boundary.trace(),
            )
            .map_err(|source| invalid("indirect safety-call owner", format!("{source:?}")))?;
        findings.push(project_indirect_safety_finding(
            boundary,
            owner,
            &route,
            description,
        ));
    }
    if !actual.is_empty() {
        return Err(invalid(
            "indirect safety-call issue",
            "report rows contain an orphan witness",
        ));
    }
    Ok(findings)
}

fn project_safety_incomplete_reasons(
    report: &TypedSafetyRootReport,
) -> Result<Vec<crate::analysis::findings::IncompleteReason>, TypedSafetyEvaluationError> {
    let [summary] = report.completeness.as_slice() else {
        return Err(invalid(
            "safety completeness",
            "exactly one summary is required",
        ));
    };
    if summary.root != report.root
        || summary.producer.as_str() != "sniff-test.safety.emit-completeness"
    {
        return Err(invalid(
            "safety completeness",
            "summary root or producer changed",
        ));
    }
    let mut issues = std::collections::BTreeMap::new();
    for issue in &report.incomplete {
        if issue.producer.as_str() != "sniff-test.safety.report-incomplete"
            || issues.insert(issue.data.traversal_order(), issue).is_some()
        {
            return Err(invalid(
                "safety completeness",
                "issue producer or traversal-order identity changed",
            ));
        }
    }
    let mut previous = None;
    let mut projected = Vec::with_capacity(summary.data.reasons().len());
    for reason in summary.data.reasons() {
        if previous.is_some_and(|previous| previous >= reason.traversal_order()) {
            return Err(invalid(
                "safety completeness",
                "summary reasons are not in strict traversal order",
            ));
        }
        previous = Some(reason.traversal_order());
        let issue = issues.remove(&reason.traversal_order()).ok_or_else(|| {
            invalid(
                "safety completeness",
                "summary reason is missing its issue row",
            )
        })?;
        let expected_context = safety_completeness_context(&report.root, reason.reason());
        if issue.data.reason() != reason.reason()
            || issue.context != expected_context
            || issue.context.root != report.root
            || matches!(
                reason.reason(),
                PanicIncompleteReason::MissingManagedBody { relation_trace, .. }
                    if relation_trace.root() != &report.root.entity
            )
        {
            return Err(invalid(
                "safety completeness",
                "issue payload or full context changed",
            ));
        }
        projected.push(project_safety_incomplete_reason(reason.reason())?);
    }
    if !issues.is_empty() {
        return Err(invalid(
            "safety completeness",
            "issue rows contain an orphan reason",
        ));
    }
    Ok(projected)
}

#[derive(Clone)]
struct SafetyAmbiguityWitness {
    endpoint: ScopedEntityRef,
    group: ScopedEntityRef,
    trace: crate::analysis::facts::evaluation::RelationTrace,
    semantic_order: EvidenceSemanticOrder,
    activations: BTreeMap<ScopedEntityRef, crate::analysis::facts::evaluation::RelationTrace>,
    interpreted_trace: InterpretedTrace,
}

type SafetyEvidenceUses = BTreeMap<EvidenceUseRecord, PassId>;
type SafetyAmbiguityWitnesses = BTreeMap<(ScopedRowRef, u64), SafetyAmbiguityWitness>;

#[allow(
    clippy::too_many_lines,
    reason = "independent report projection keeps operation and call evidence reconstruction auditable"
)]
fn expected_safety_evidence_uses(
    report: &TypedSafetyRootReport,
) -> Result<(SafetyEvidenceUses, SafetyAmbiguityWitnesses), TypedSafetyEvaluationError> {
    let producer = PassId::new("sniff-test.safety.emit-evidence-uses")
        .expect("built-in safety evidence producer is valid");
    let mut selector = TraceRouteSelector::prepare(report.inputs.traversal());
    let mut uses = BTreeMap::new();
    let mut witnesses = BTreeMap::new();
    for visit in report.inputs.traversal().unsafe_operation_visits() {
        let contributing = visit
            .active_markers()
            .iter()
            .filter(|marker| {
                marker.data().key().domain() == &report.root.domain
                    && !marker.data().rationale().trim().is_empty()
                    && matches!(marker.data().selector(), EvidenceClaimSelector::Unnamed)
            })
            .collect::<Vec<_>>();
        if contributing.is_empty() {
            continue;
        }
        let route = selector
            .select_route(TraceRouteEndpoint::new(
                visit.order(),
                visit.trace(),
                visit.inherited_markers(),
            ))
            .map_err(|source| invalid("safety ambiguity trace", format!("{source:?}")))?;
        let owner = selector
            .select_owner_body(
                visit.owner().erase(),
                visit.inherited_markers(),
                visit.trace(),
            )
            .map_err(|source| invalid("safety ambiguity owner", format!("{source:?}")))?;
        let semantic_order = operation_evidence_order(&route, owner, visit);
        let source = visit.operation().erase().as_row();
        let witness = safety_ambiguity_witness(
            visit.operation().erase(),
            visit.safety_group().erase(),
            visit.trace().clone(),
            semantic_order.clone(),
            visit.active_markers(),
            project_unsafe_operation_finding(visit, &route).trace,
        )?;
        if witnesses
            .insert((source.clone(), visit.order()), witness)
            .is_some()
        {
            return Err(invalid(
                "safety ambiguity witness",
                "operation source/order identity is duplicated",
            ));
        }
        for marker in contributing {
            let usage = EvidenceUseRecord::new(
                report.root.domain.clone(),
                marker.claim().erase(),
                visit.operation().erase(),
                visit.safety_group().erase(),
                source.clone(),
                visit.trace().clone(),
                visit.order(),
                semantic_order.clone(),
            );
            if uses.insert(usage, producer.clone()).is_some() {
                return Err(invalid(
                    "safety evidence use",
                    "prepared operations produce a duplicate exact use",
                ));
            }
        }
    }
    for boundary in report.inputs.traversal().call_boundaries() {
        let contributing = safety_call_contributing_claims(&report.root.domain, boundary);
        if contributing.is_empty() {
            continue;
        }
        let route = selector
            .select_route(TraceRouteEndpoint::new(
                boundary.order(),
                boundary.trace(),
                boundary.inherited_markers(),
            ))
            .map_err(|source| invalid("safety ambiguity trace", format!("{source:?}")))?;
        let owner = selector
            .select_terminal_caller(
                &boundary.occurrence().erase(),
                *boundary.occurrence_data().key().owner(),
                boundary.inherited_markers(),
                boundary.trace(),
            )
            .map_err(|source| invalid("safety ambiguity owner", format!("{source:?}")))?;
        let semantic_order = call_evidence_order(&route, owner, boundary);
        let source = boundary.occurrence().erase().as_row();
        let witness = safety_ambiguity_witness(
            boundary.occurrence().erase(),
            boundary.safety_group().erase(),
            boundary.trace().clone(),
            semantic_order.clone(),
            boundary.active_markers(),
            project_safety_call_trace(boundary, owner, &route),
        )?;
        if witnesses
            .insert((source.clone(), boundary.order()), witness)
            .is_some()
        {
            return Err(invalid(
                "safety ambiguity witness",
                "call source/order identity is duplicated",
            ));
        }
        for marker in boundary
            .active_markers()
            .iter()
            .filter(|marker| contributing.contains(&marker.claim().erase()))
        {
            let usage = EvidenceUseRecord::new(
                report.root.domain.clone(),
                marker.claim().erase(),
                boundary.occurrence().erase(),
                boundary.safety_group().erase(),
                source.clone(),
                boundary.trace().clone(),
                boundary.order(),
                semantic_order.clone(),
            );
            if uses.insert(usage, producer.clone()).is_some() {
                return Err(invalid(
                    "safety evidence use",
                    "prepared calls produce a duplicate exact use",
                ));
            }
        }
    }
    Ok((uses, witnesses))
}

fn safety_ambiguity_witness(
    endpoint: ScopedEntityRef,
    group: ScopedEntityRef,
    trace: crate::analysis::facts::evaluation::RelationTrace,
    semantic_order: EvidenceSemanticOrder,
    markers: &[ResolvedMarkerClaim],
    interpreted_trace: InterpretedTrace,
) -> Result<SafetyAmbiguityWitness, TypedSafetyEvaluationError> {
    let mut activations = BTreeMap::new();
    for marker in markers {
        if activations
            .insert(marker.claim().erase(), marker.trace().clone())
            .is_some()
        {
            return Err(invalid(
                "safety ambiguity witness",
                "active marker claim is duplicated",
            ));
        }
    }
    Ok(SafetyAmbiguityWitness {
        endpoint,
        group,
        trace,
        semantic_order,
        activations,
        interpreted_trace,
    })
}

fn safety_call_contributing_claims(
    domain: &crate::analysis::facts::evaluation::DomainId,
    boundary: &ResolvedCallBoundary<SafetyBoundary>,
) -> BTreeSet<ScopedEntityRef> {
    let requirements = match boundary.payload() {
        SafetyBoundary::CallContract(contract)
            if (boundary.occurrence_data().requires_unsafe()
                && is_actual_call(boundary.effective_kind()))
                || boundary
                    .target_data()
                    .is_some_and(|target| !target.is_unsafe()) =>
        {
            Some(contract.contract().requirements())
        }
        SafetyBoundary::ForeignDeclaration
        | SafetyBoundary::UndocumentedUnsafeCall
        | SafetyBoundary::BodylessDeclaration
        | SafetyBoundary::OpaqueCall { .. }
            if boundary.occurrence_data().requires_unsafe()
                && is_actual_call(boundary.effective_kind()) =>
        {
            Some(&[][..])
        }
        _ => None,
    };
    let Some(requirements) = requirements else {
        return BTreeSet::new();
    };
    let names = requirements
        .iter()
        .map(crate::analysis::facts::safety::EffectiveSafetyRequirement::normalized_name)
        .collect::<BTreeSet<_>>();
    boundary
        .active_markers()
        .iter()
        .filter(|marker| {
            marker.data().key().domain() == domain
                && !marker.data().rationale().trim().is_empty()
                && if requirements.is_empty() {
                    matches!(marker.data().selector(), EvidenceClaimSelector::Unnamed)
                } else {
                    matches!(
                        marker.data().selector(),
                        EvidenceClaimSelector::Named(name)
                            if names.contains(normalize_requirement_name(name).as_str())
                    )
                }
        })
        .map(|marker| marker.claim().erase())
        .collect()
}

#[allow(
    clippy::too_many_lines,
    reason = "the projection validates the complete use/issue/context/owner bijection"
)]
fn project_safety_ambiguity_findings(
    report: &TypedSafetyRootReport,
    evaluation: &WorkspaceEvaluationView<'_>,
) -> Result<Vec<InterpretedFinding>, TypedSafetyEvaluationError> {
    let (expected, witnesses) = expected_safety_evidence_uses(report)?;
    let mut actual = BTreeMap::new();
    for row in &report.evidence_uses {
        if row.root != report.root
            || row.data.domain() != &report.root.domain
            || row.data.semantic_order().validate().is_err()
        {
            return Err(invalid(
                "safety evidence use",
                "root, domain, or semantic order changed",
            ));
        }
        evaluation
            .graph()
            .validate_path(
                row.data.trace().root(),
                row.data.trace().target(),
                row.data.trace().relations(),
            )
            .map_err(|source| invalid("safety evidence trace", source.to_string()))?;
        if actual
            .insert(row.data.clone(), row.producer.clone())
            .is_some()
        {
            return Err(invalid(
                "safety evidence use",
                "derived rows duplicate an exact use",
            ));
        }
    }
    if actual != expected {
        return Err(invalid(
            "safety evidence use",
            "derived rows are not bijective with prepared safety inputs",
        ));
    }
    let mut uses_by_marker = BTreeMap::<ScopedEntityRef, Vec<&EvidenceUseRecord>>::new();
    for usage in expected.keys() {
        let claim = evaluation
            .facts()
            .entity::<MarkerClaimEntity>(usage.claim())
            .map_err(|source| invalid("safety ambiguity claim", source.to_string()))?;
        if claim.key().domain() != usage.domain() {
            return Err(invalid(
                "safety ambiguity claim",
                "claim domain disagrees with evidence use",
            ));
        }
        let marker = evaluation
            .facts()
            .entity_by_key::<MarkerOccurrenceEntity>(
                usage.claim().scope(),
                claim.key().occurrence(),
            )
            .map_err(|source| invalid("safety ambiguity marker", source.to_string()))?
            .ok_or_else(|| invalid("safety ambiguity marker", "physical marker is absent"))?;
        uses_by_marker.entry(marker).or_default().push(usage);
    }
    let producer = PassId::new("sniff-test.evidence.detect-reuse")
        .expect("built-in evidence coordinator ID is valid");
    let mut issues = BTreeMap::new();
    for issue in &report.ambiguities {
        if issue.producer != producer
            || issue.context.root != report.root
            || issue.data.domain() != &report.root.domain
            || issue.context.source.as_ref() != Some(&issue.data.marker().as_row())
            || issues.insert(issue.data.marker().clone(), issue).is_some()
        {
            return Err(invalid(
                "safety ambiguity issue",
                "producer, root, marker context, or marker cardinality changed",
            ));
        }
    }
    let mut findings = Vec::new();
    for (marker, uses) in uses_by_marker {
        let groups = uses
            .iter()
            .map(|usage| usage.group().clone())
            .collect::<BTreeSet<_>>();
        if groups.len() < 2 {
            if issues.contains_key(&marker) {
                return Err(invalid(
                    "safety ambiguity issue",
                    "issue reports fewer than two groups",
                ));
            }
            continue;
        }
        let issue = issues.remove(&marker).ok_or_else(|| {
            invalid(
                "safety ambiguity issue",
                "reused marker has no coordinator issue",
            )
        })?;
        let canonical = canonical_evidence_use(uses.iter().copied())
            .ok_or_else(|| invalid("safety ambiguity issue", "marker has no canonical use"))?;
        let expected_groups = groups.into_iter().collect::<Vec<_>>();
        if issue.data.witness_source() != canonical.source()
            || issue.data.witness_endpoint() != canonical.endpoint()
            || issue.data.witness_order() != canonical.witness_order()
            || issue.data.groups() != expected_groups
            || issue.context.endpoint.as_ref() != Some(canonical.endpoint())
            || issue.context.trace.as_ref() != Some(canonical.trace())
        {
            return Err(invalid(
                "safety ambiguity issue",
                "canonical witness, groups, endpoint, or trace changed",
            ));
        }
        let mut owner = None;
        let mut trace = None;
        for usage in uses {
            let witness = witnesses
                .get(&(usage.source().clone(), usage.witness_order()))
                .ok_or_else(|| {
                    invalid(
                        "safety ambiguity witness",
                        "use has no prepared source/order witness",
                    )
                })?;
            if witness.endpoint != *usage.endpoint()
                || witness.group != *usage.group()
                || witness.trace != *usage.trace()
                || witness.semantic_order != *usage.semantic_order()
            {
                return Err(invalid(
                    "safety ambiguity witness",
                    "use changed after lane-specific reconstruction",
                ));
            }
            let activation = witness.activations.get(usage.claim()).ok_or_else(|| {
                invalid(
                    "safety ambiguity witness",
                    "use has no active marker activation",
                )
            })?;
            let (_, current) =
                marker_owner_from_activation(&report.root, evaluation, usage.claim(), activation)
                    .map_err(|source| invalid("safety marker owner", source.to_string()))?;
            if !merge_physical_marker_owner(
                &mut owner,
                function_id(*current.key()),
                current.display_path(),
            ) {
                return Err(invalid(
                    "safety marker owner",
                    "contributing uses resolve to different owners",
                ));
            }
            if usage == canonical {
                trace = Some(witness.interpreted_trace.clone());
            }
        }
        let (function, function_path) =
            owner.ok_or_else(|| invalid("safety marker owner", "ambiguous marker has no owner"))?;
        let trace = trace.ok_or_else(|| {
            invalid(
                "safety ambiguity witness",
                "canonical witness has no semantic trace",
            )
        })?;
        findings.push(InterpretedFinding {
            kind: InterpretedFindingKind::AmbiguousSafetyMarker {
                effect_count: expected_groups.len(),
            },
            function,
            function_path,
            target: None,
            source_range: Some(
                physical_marker_source(evaluation, &marker)
                    .map_err(|source| invalid("safety marker source", source.to_string()))?,
            ),
            trace,
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
        });
    }
    if !issues.is_empty() {
        return Err(invalid(
            "safety ambiguity issue",
            "coordinator emitted an orphan marker issue",
        ));
    }
    Ok(findings)
}

fn operation_evidence_order(
    route: &SelectedTraceRoute<'_>,
    owner: &ResolvedBodyVisit,
    visit: &ResolvedUnsafeOperationVisit,
) -> EvidenceSemanticOrder {
    let mut steps = route_evidence_steps(route);
    let mut caller = owner.data().display_path().to_owned();
    for frame in visit.macro_frames() {
        let target = frame.data().display_path().to_owned();
        steps.push(evidence_step(
            caller,
            EvidenceSemanticEdgeOrder::Reachability(CallKind::MacroExpansion),
            Some(target.clone()),
            frame
                .callsite()
                .map(ResolvedUnsafeOperationMacroCallsite::key),
        ));
        caller = target;
    }
    steps.push(evidence_step(
        caller,
        EvidenceSemanticEdgeOrder::UnsafeOperation(visit.data().kind()),
        None,
        selected_operation_source(visit.source_anchors(), true),
    ));
    EvidenceSemanticOrder::new(steps, visit.order())
}

fn call_evidence_order(
    route: &SelectedTraceRoute<'_>,
    owner: &ResolvedBodyVisit,
    boundary: &ResolvedCallBoundary<SafetyBoundary>,
) -> EvidenceSemanticOrder {
    let mut steps = route_evidence_steps(route);
    let mut caller = owner.data().display_path().to_owned();
    for frame in boundary.macro_frames() {
        let target = frame.data().display_path().to_owned();
        steps.push(evidence_step(
            caller,
            EvidenceSemanticEdgeOrder::Reachability(CallKind::MacroExpansion),
            Some(target.clone()),
            frame.callsite().map(ResolvedCallMacroCallsite::key),
        ));
        caller = target;
    }
    let target = boundary.target_data().map_or_else(
        || match boundary.payload() {
            SafetyBoundary::OpaqueCall { description } => Some(description.clone()),
            _ => None,
        },
        |target| Some(target.display_path().to_owned()),
    );
    steps.push(evidence_step(
        caller,
        EvidenceSemanticEdgeOrder::Reachability(boundary.effective_kind()),
        target,
        selected_call_source(boundary.source_anchors(), true),
    ));
    EvidenceSemanticOrder::new(steps, boundary.order())
}

fn route_evidence_steps(route: &SelectedTraceRoute<'_>) -> Vec<EvidenceSemanticStepOrder> {
    let mut steps = Vec::new();
    for selected in route.calls() {
        let owner = selected.caller();
        let call = selected.call();
        let mut caller = owner.data().display_path().to_owned();
        for frame in call.macro_frames() {
            let target = frame.data().display_path().to_owned();
            steps.push(evidence_step(
                caller,
                EvidenceSemanticEdgeOrder::Reachability(CallKind::MacroExpansion),
                Some(target.clone()),
                frame.callsite().map(ResolvedCallMacroCallsite::key),
            ));
            caller = target;
        }
        steps.push(evidence_step(
            caller,
            EvidenceSemanticEdgeOrder::Reachability(call.effective_kind()),
            Some(call.target_data().display_path().to_owned()),
            selected_call_source(call.source_anchors(), true),
        ));
    }
    steps
}

fn evidence_step(
    caller: String,
    kind: EvidenceSemanticEdgeOrder,
    target: Option<String>,
    source: Option<&crate::analysis::facts::program::SourceAnchorKey>,
) -> EvidenceSemanticStepOrder {
    EvidenceSemanticStepOrder::new(
        caller,
        kind,
        target,
        source
            .map(|source| EvidenceSemanticSourceOrder::new(source.byte_start(), source.byte_end())),
    )
}

fn safety_completeness_context(
    root: &EvaluationRoot,
    reason: &PanicIncompleteReason,
) -> EvaluationIssueContext {
    let mut context = EvaluationIssueContext::new(root.clone());
    if let PanicIncompleteReason::MissingManagedBody {
        presentation_source,
        relation_trace,
        ..
    } = reason
    {
        if let Some(source) = presentation_source {
            context = context.with_source(source.anchor().as_row());
        }
        context = context
            .with_endpoint(relation_trace.target().clone())
            .with_trace(relation_trace.clone());
    }
    context
}

fn project_safety_incomplete_reason(
    reason: &PanicIncompleteReason,
) -> Result<crate::analysis::findings::IncompleteReason, TypedSafetyEvaluationError> {
    use crate::analysis::findings::IncompleteReason;
    match reason {
        PanicIncompleteReason::NodeLimit { limit } => Ok(IncompleteReason::NodeLimit {
            limit: usize::try_from(*limit)
                .map_err(|_| invalid("safety completeness", "node limit does not fit usize"))?,
        }),
        PanicIncompleteReason::MissingManagedBody {
            function,
            path,
            presentation_source,
            semantic_trace,
            relation_trace,
        } => {
            if relation_trace.root() == relation_trace.target()
                || semantic_trace.last().is_none_or(|terminal| {
                    terminal.target() != Some(*function)
                        || terminal.target_path() != Some(path.as_str())
                })
            {
                return Err(invalid(
                    "safety completeness",
                    "missing-body trace does not terminate at its missing function",
                ));
            }
            Ok(IncompleteReason::MissingBody {
                function: function_id(*function),
                path: path.clone(),
                source_range: presentation_source
                    .as_ref()
                    .map(|source| source_range(source.key())),
                trace: InterpretedTrace {
                    steps: semantic_trace
                        .iter()
                        .map(|step| InterpretedTraceStep {
                            caller: function_id(step.caller()),
                            caller_path: step.caller_path().to_owned(),
                            call: CallId::new(step.call_local_id()),
                            kind: InterpretedTraceStepKind::Reachability(call_edge_kind(
                                step.kind(),
                            )),
                            source_range: step.source().map(source_range),
                            target: step.target().map(function_id),
                            target_path: step.target_path().map(str::to_owned),
                        })
                        .collect(),
                },
            })
        }
    }
}

fn project_indirect_safety_finding(
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        SafetyBoundary,
    >,
    owner: &ResolvedBodyVisit,
    route: &SelectedTraceRoute<'_>,
    description: &str,
) -> InterpretedFinding {
    let mut steps = route_steps(route);
    let mut caller = function_id(*owner.data().key());
    let mut caller_path = owner.data().display_path().to_owned();
    let call = CallId::new(boundary.occurrence_data().key().local_id());
    append_call_macro_steps(
        &mut steps,
        &mut caller,
        &mut caller_path,
        call,
        boundary.macro_frames(),
    );
    let target = boundary.target_data().map_or_else(
        || InterpretedTarget {
            function: None,
            path: description.to_owned(),
        },
        |target| InterpretedTarget {
            function: Some(function_id(*target.key())),
            path: target.display_path().to_owned(),
        },
    );
    steps.push(InterpretedTraceStep {
        caller,
        caller_path,
        call,
        kind: InterpretedTraceStepKind::Reachability(call_edge_kind(boundary.effective_kind())),
        source_range: selected_call_source(boundary.source_anchors(), true).map(source_range),
        target: target.function,
        target_path: Some(target.path.clone()),
    });
    InterpretedFinding {
        kind: InterpretedFindingKind::OpaqueSafetyBoundary {
            description: description.to_owned(),
        },
        function: function_id(*owner.data().key()),
        function_path: owner.data().display_path().to_owned(),
        target: Some(target),
        source_range: selected_call_source(boundary.source_anchors(), false).map(source_range),
        trace: InterpretedTrace { steps },
        missing_requirements: Vec::new(),
        requirements: Vec::new(),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one source-free validator proves both root-owned safety issue families before projection"
)]
fn project_safety_root_findings(
    report: &TypedSafetyRootReport,
) -> Result<Vec<InterpretedFinding>, TypedSafetyEvaluationError> {
    let mut findings = Vec::new();
    match (
        report.inputs.root_missing_safety_docs(),
        report.missing_docs.as_slice(),
    ) {
        (false, []) => {}
        (true, [issue]) => {
            if issue.producer.as_str() != "sniff-test.safety.report-missing-docs" {
                return Err(invalid("missing-safety-docs issue", "producer changed"));
            }
            let expected = EvaluationIssueContext::new(report.root.clone())
                .with_endpoint(report.root.entity.clone())
                .with_trace(crate::analysis::facts::evaluation::RelationTrace::new(
                    report.root.entity.clone(),
                    report.root.entity.clone(),
                    Vec::new(),
                ));
            if issue.data != MissingSafetyDocsIssue::new() || issue.context != expected {
                return Err(invalid(
                    "missing-safety-docs issue",
                    "payload or full issue context changed",
                ));
            }
            findings.push(InterpretedFinding {
                kind: InterpretedFindingKind::MissingSafetyDocs,
                function: function_id(*report.inputs.root_callable_data().key()),
                function_path: report.inputs.root_callable_data().display_path().to_owned(),
                target: None,
                source_range: report.presentation_range.clone(),
                trace: InterpretedTrace { steps: Vec::new() },
                missing_requirements: Vec::new(),
                requirements: Vec::new(),
            });
        }
        _ => {
            return Err(invalid(
                "missing-safety-docs issue",
                "issue cardinality disagrees with prepared root state",
            ));
        }
    }

    let root_boundaries = report
        .inputs
        .traversal()
        .body_boundaries()
        .iter()
        .filter(|boundary| matches!(boundary.payload(), SafetyBoundary::RootContract(_)))
        .collect::<Vec<_>>();
    let expected_groups = root_boundaries
        .first()
        .and_then(|boundary| match boundary.payload() {
            SafetyBoundary::RootContract(contract) => Some((boundary, contract.as_ref())),
            _ => None,
        });
    let mut actual = std::collections::BTreeMap::new();
    for issue in &report.duplicate_root_requirements {
        if issue.producer.as_str() != "sniff-test.safety.report-duplicate-root-requirements" {
            return Err(invalid(
                "duplicate root safety requirement",
                "producer changed",
            ));
        }
        if actual
            .insert(issue.data.normalized_name().to_owned(), issue)
            .is_some()
        {
            return Err(invalid(
                "duplicate root safety requirement",
                "normalized group is duplicated",
            ));
        }
    }
    if root_boundaries.len() > 1 {
        return Err(invalid(
            "duplicate root safety requirement",
            "multiple root contract boundaries were retained",
        ));
    }
    if let Some((boundary, contract)) = expected_groups {
        for group in contract.duplicate_requirement_groups() {
            let issue = actual.remove(group.normalized_name()).ok_or_else(|| {
                invalid(
                    "duplicate root safety requirement",
                    "expected duplicate group is missing",
                )
            })?;
            let ordinals = group
                .requirements()
                .iter()
                .map(crate::analysis::facts::safety::EffectiveSafetyRequirement::ordinal)
                .collect::<Vec<_>>();
            let mut expected_context = EvaluationIssueContext::new(report.root.clone())
                .with_endpoint(boundary.body().erase())
                .with_trace(boundary.trace().clone());
            if let Some(source) = contract.raw_contract() {
                expected_context = expected_context.with_source(source.clone());
            }
            if issue.data
                != DuplicateSafetyRootRequirementIssue::new(group.normalized_name(), ordinals)
                || issue.context != expected_context
            {
                return Err(invalid(
                    "duplicate root safety requirement",
                    "payload or full issue context changed",
                ));
            }
            findings.push(InterpretedFinding {
                kind: InterpretedFindingKind::AmbiguousSafetyRequirement {
                    normalized_name: group.normalized_name().to_owned(),
                },
                function: function_id(boundary.function()),
                function_path: boundary.body_data().display_path().to_owned(),
                target: None,
                source_range: contract
                    .source_anchor()
                    .map(|anchor| source_range(&anchor.data().key())),
                trace: InterpretedTrace { steps: Vec::new() },
                missing_requirements: Vec::new(),
                requirements: group
                    .requirements()
                    .iter()
                    .map(safety_requirement)
                    .collect(),
            });
        }
    }
    if !actual.is_empty() {
        return Err(invalid(
            "duplicate root safety requirement",
            "report rows contain an orphan group",
        ));
    }
    Ok(findings)
}

fn expected_unsatisfied_safety_call(
    root: &EvaluationRoot,
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        SafetyBoundary,
    >,
) -> Option<UnsatisfiedSafetyCallIssue> {
    let kind = if boundary.occurrence_data().requires_unsafe()
        && is_actual_call(boundary.effective_kind())
    {
        Some(SafetyCallIssueKind::Unsafe)
    } else if boundary
        .target_data()
        .is_some_and(|target| !target.is_unsafe())
    {
        Some(SafetyCallIssueKind::Obligation)
    } else {
        None
    }?;
    match boundary.payload() {
        SafetyBoundary::CallContract(call_contract) => {
            let contract = call_contract.contract();
            let missing = if contract.requirements().is_empty() {
                (!has_unnamed_safety_claim(root, boundary)).then(Vec::new)
            } else {
                let named = boundary
                    .active_markers()
                    .iter()
                    .filter_map(|marker| {
                        (marker.data().key().domain() == &root.domain
                            && !marker.data().rationale().trim().is_empty())
                        .then(|| match marker.data().selector() {
                            EvidenceClaimSelector::Named(name) => {
                                Some(crate::contracts::normalize_requirement_name(name))
                            }
                            EvidenceClaimSelector::Unnamed | EvidenceClaimSelector::Explicit(_) => {
                                None
                            }
                        })
                        .flatten()
                    })
                    .collect::<std::collections::BTreeSet<_>>();
                let missing = contract
                    .requirements()
                    .iter()
                    .filter(|requirement| !named.contains(requirement.normalized_name()))
                    .map(crate::analysis::facts::safety::EffectiveSafetyRequirement::ordinal)
                    .collect::<Vec<_>>();
                (!missing.is_empty()).then_some(missing)
            }?;
            Some(UnsatisfiedSafetyCallIssue::new(
                kind,
                boundary.order(),
                missing,
                call_contract.trusted(),
            ))
        }
        SafetyBoundary::ForeignDeclaration
        | SafetyBoundary::UndocumentedUnsafeCall
        | SafetyBoundary::BodylessDeclaration
        | SafetyBoundary::OpaqueCall { .. }
            if kind == SafetyCallIssueKind::Unsafe && !has_unnamed_safety_claim(root, boundary) =>
        {
            Some(UnsatisfiedSafetyCallIssue::new(
                kind,
                boundary.order(),
                Vec::new(),
                false,
            ))
        }
        SafetyBoundary::RootContract(_)
        | SafetyBoundary::TrustedNamespace
        | SafetyBoundary::BuiltinUnsafe
        | SafetyBoundary::ForeignDeclaration
        | SafetyBoundary::UndocumentedUnsafeCall
        | SafetyBoundary::BodylessDeclaration
        | SafetyBoundary::OpaqueCall { .. } => None,
    }
}

fn has_unnamed_safety_claim(
    root: &EvaluationRoot,
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        SafetyBoundary,
    >,
) -> bool {
    boundary.active_markers().iter().any(|marker| {
        marker.data().key().domain() == &root.domain
            && !marker.data().rationale().trim().is_empty()
            && matches!(marker.data().selector(), EvidenceClaimSelector::Unnamed)
    })
}

fn project_safety_call_finding(
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        SafetyBoundary,
    >,
    owner: &ResolvedBodyVisit,
    route: &SelectedTraceRoute<'_>,
    issue: &TypedEvaluatedIssue<UnsatisfiedSafetyCallIssue>,
) -> Result<InterpretedFinding, TypedSafetyEvaluationError> {
    let trace = project_safety_call_trace(boundary, owner, route);
    let (target_function, target_path) = boundary.target_data().map_or_else(
        || {
            let description = match boundary.payload() {
                SafetyBoundary::OpaqueCall { description } => description.clone(),
                _ => String::from("indirect call boundary"),
            };
            (None, description)
        },
        |target| {
            (
                Some(function_id(*target.key())),
                target.display_path().to_owned(),
            )
        },
    );
    let (requirements, missing_requirements) = match boundary.payload() {
        SafetyBoundary::CallContract(call_contract) => {
            let requirements = call_contract
                .contract()
                .requirements()
                .iter()
                .map(safety_requirement)
                .collect::<Vec<_>>();
            let mut missing = Vec::with_capacity(issue.data.missing_requirement_ordinals().len());
            let mut previous = None;
            for ordinal in issue.data.missing_requirement_ordinals() {
                if previous.is_some_and(|previous| previous >= *ordinal) {
                    return Err(invalid(
                        "safety-call requirements",
                        "missing requirement ordinals are not strictly increasing",
                    ));
                }
                previous = Some(*ordinal);
                let requirement = call_contract
                    .contract()
                    .requirements()
                    .get(*ordinal as usize)
                    .filter(|requirement| requirement.ordinal() == *ordinal)
                    .ok_or_else(|| {
                        invalid(
                            "safety-call requirements",
                            "missing requirement ordinal is absent",
                        )
                    })?;
                missing.push(safety_requirement(requirement));
            }
            (requirements, missing)
        }
        _ => (Vec::new(), Vec::new()),
    };
    Ok(InterpretedFinding {
        kind: InterpretedFindingKind::SafetyCall {
            kind: match issue.data.kind() {
                SafetyCallIssueKind::Unsafe => InterpretedSafetyCallKind::Unsafe,
                SafetyCallIssueKind::Obligation => InterpretedSafetyCallKind::Obligation,
            },
            trusted: issue.data.trusted(),
        },
        function: function_id(*owner.data().key()),
        function_path: owner.data().display_path().to_owned(),
        target: Some(InterpretedTarget {
            function: target_function,
            path: target_path,
        }),
        source_range: selected_call_source(boundary.source_anchors(), false).map(source_range),
        trace,
        missing_requirements,
        requirements,
    })
}

fn project_safety_call_trace(
    boundary: &ResolvedCallBoundary<SafetyBoundary>,
    owner: &ResolvedBodyVisit,
    route: &SelectedTraceRoute<'_>,
) -> InterpretedTrace {
    let mut steps = route_steps(route);
    let mut caller = function_id(*owner.data().key());
    let mut caller_path = owner.data().display_path().to_owned();
    let call = CallId::new(boundary.occurrence_data().key().local_id());
    append_call_macro_steps(
        &mut steps,
        &mut caller,
        &mut caller_path,
        call,
        boundary.macro_frames(),
    );
    let (target, target_path) = boundary.target_data().map_or_else(
        || {
            let description = match boundary.payload() {
                SafetyBoundary::OpaqueCall { description } => description.clone(),
                _ => String::from("indirect call boundary"),
            };
            (None, description)
        },
        |target| {
            (
                Some(function_id(*target.key())),
                target.display_path().to_owned(),
            )
        },
    );
    steps.push(InterpretedTraceStep {
        caller,
        caller_path,
        call,
        kind: InterpretedTraceStepKind::Reachability(call_edge_kind(boundary.effective_kind())),
        source_range: selected_call_source(boundary.source_anchors(), true).map(source_range),
        target,
        target_path: Some(target_path),
    });
    InterpretedTrace { steps }
}

fn safety_requirement(
    requirement: &crate::analysis::facts::safety::EffectiveSafetyRequirement,
) -> ContractRequirementIr {
    ContractRequirementIr {
        name: requirement.name().to_owned(),
        condition: requirement.condition().to_owned(),
        source_range: requirement
            .source_anchor()
            .map(|anchor| source_range(&anchor.data().key())),
    }
}

const fn is_actual_call(kind: crate::analysis::facts::program::topology::CallKind) -> bool {
    use crate::analysis::facts::program::topology::CallKind;
    matches!(
        kind,
        CallKind::DirectCall
            | CallKind::TailCall
            | CallKind::FnPointerCallTarget
            | CallKind::DynDispatchVTableEntry
            | CallKind::IndirectCall
    )
}

fn project_unsafe_operation_finding(
    visit: &ResolvedUnsafeOperationVisit,
    route: &SelectedTraceRoute<'_>,
) -> InterpretedFinding {
    let mut steps = route_steps(route);
    let mut caller = function_id(*visit.owner_data().key());
    let mut caller_path = visit.owner_data().display_path().to_owned();
    let call = CallId::new(visit.key().local_id());
    append_operation_macro_steps(
        &mut steps,
        &mut caller,
        &mut caller_path,
        call,
        visit.macro_frames(),
    );
    steps.push(InterpretedTraceStep {
        caller,
        caller_path: caller_path.clone(),
        call,
        kind: InterpretedTraceStepKind::UnsafeOperation(visit.data().kind()),
        source_range: selected_operation_source(visit.source_anchors(), true).map(source_range),
        target: None,
        target_path: Some(format!(
            "unsafe operation ({})",
            visit.data().kind().label()
        )),
    });
    InterpretedFinding {
        kind: InterpretedFindingKind::UnsafeOperation {
            kind: visit.data().kind(),
        },
        function: function_id(*visit.owner_data().key()),
        function_path: visit.owner_data().display_path().to_owned(),
        target: None,
        source_range: selected_operation_source(visit.source_anchors(), false).map(source_range),
        trace: InterpretedTrace { steps },
        missing_requirements: Vec::new(),
        requirements: Vec::new(),
    }
}

fn route_steps(route: &SelectedTraceRoute<'_>) -> Vec<InterpretedTraceStep> {
    let mut steps = Vec::new();
    for selected in route.calls() {
        append_followed_call_steps(&mut steps, selected.caller(), selected.call());
    }
    steps
}

fn append_followed_call_steps(
    steps: &mut Vec<InterpretedTraceStep>,
    owner: &ResolvedBodyVisit,
    call: &ResolvedFollowedCall,
) {
    let mut caller = function_id(*owner.data().key());
    let mut caller_path = owner.data().display_path().to_owned();
    let call_id = CallId::new(call.occurrence_data().key().local_id());
    append_call_macro_steps(
        steps,
        &mut caller,
        &mut caller_path,
        call_id,
        call.macro_frames(),
    );
    steps.push(InterpretedTraceStep {
        caller,
        caller_path,
        call: call_id,
        kind: InterpretedTraceStepKind::Reachability(call_edge_kind(call.effective_kind())),
        source_range: selected_call_source(call.source_anchors(), true).map(source_range),
        target: Some(function_id(*call.target_data().key())),
        target_path: Some(call.target_data().display_path().to_owned()),
    });
}

fn append_call_macro_steps(
    steps: &mut Vec<InterpretedTraceStep>,
    caller: &mut FunctionId,
    caller_path: &mut String,
    call: CallId,
    frames: &[ResolvedCallMacroFrame],
) {
    for frame in frames {
        let target = FunctionId::generic(frame.data().macro_definition());
        let target_path = format!("macro {}", frame.data().display_path());
        steps.push(InterpretedTraceStep {
            caller: *caller,
            caller_path: caller_path.clone(),
            call,
            kind: InterpretedTraceStepKind::Reachability(CallEdgeKindIr::MacroExpansion),
            source_range: frame.callsite().map(|source| source_range(source.key())),
            target: Some(target),
            target_path: Some(target_path.clone()),
        });
        *caller = target;
        *caller_path = target_path;
    }
}

fn append_operation_macro_steps(
    steps: &mut Vec<InterpretedTraceStep>,
    caller: &mut FunctionId,
    caller_path: &mut String,
    call: CallId,
    frames: &[ResolvedUnsafeOperationMacroFrame],
) {
    for frame in frames {
        let target = FunctionId::generic(frame.data().macro_definition());
        let target_path = format!("macro {}", frame.data().display_path());
        steps.push(InterpretedTraceStep {
            caller: *caller,
            caller_path: caller_path.clone(),
            call,
            kind: InterpretedTraceStepKind::Reachability(CallEdgeKindIr::MacroExpansion),
            source_range: frame.callsite().map(|source| source_range(source.key())),
            target: Some(target),
            target_path: Some(target_path.clone()),
        });
        *caller = target;
        *caller_path = target_path;
    }
}

fn selected_call_source(
    anchors: &[ResolvedCallSourceAnchor],
    prefer_expanded: bool,
) -> Option<&crate::analysis::facts::program::SourceAnchorKey> {
    let roles = if prefer_expanded {
        [
            CallSourceAnchorRole::Expanded,
            CallSourceAnchorRole::Presentation,
        ]
    } else {
        [
            CallSourceAnchorRole::Presentation,
            CallSourceAnchorRole::Expanded,
        ]
    };
    roles.into_iter().find_map(|role| {
        anchors
            .iter()
            .find(|anchor| anchor.role() == role)
            .map(ResolvedCallSourceAnchor::key)
    })
}

fn selected_operation_source(
    anchors: &[ResolvedUnsafeOperationSourceAnchor],
    prefer_expanded: bool,
) -> Option<&crate::analysis::facts::program::SourceAnchorKey> {
    use crate::analysis::facts::safety::operations::UnsafeOperationSourceAnchorRole;
    let roles = if prefer_expanded {
        [
            UnsafeOperationSourceAnchorRole::Expanded,
            UnsafeOperationSourceAnchorRole::Presentation,
        ]
    } else {
        [
            UnsafeOperationSourceAnchorRole::Presentation,
            UnsafeOperationSourceAnchorRole::Expanded,
        ]
    };
    roles.into_iter().find_map(|role| {
        anchors
            .iter()
            .find(|anchor| anchor.role() == role)
            .map(ResolvedUnsafeOperationSourceAnchor::key)
    })
}

fn safety_root_request(root: &InterpretationRoot, config: &SniffTestConfig) -> SafetyRootRequest {
    SafetyRootRequest::new(
        FunctionKey::new(root.function.def_path_hash, root.function.instance_hash),
        match config.analysis.callable_edge_attribution {
            CallableEdgeAttribution::ErasureSites => CallAttributionRole::ErasureSite,
            CallableEdgeAttribution::CallSites => CallAttributionRole::CallSite,
        },
        match config.analysis.marker_probing {
            MarkerProbing::SourceCallsite => MarkerProbe::SourceCallsite,
            MarkerProbing::MacroDefinitionFirst => MarkerProbe::MacroDefinitionFirst,
        },
        config.analysis.node_limit,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        TypedSafetyBatchReport, adapt_typed_safety_authority_batch, evaluate_typed_safety_roots,
        project_duplicate_safety_call_findings, project_indirect_safety_findings,
        project_safety_call_findings, project_safety_incomplete_reasons,
        project_safety_root_findings, project_unsafe_operation_findings,
        typed_safety_authority_registry,
    };
    use crate::analysis::facts::encoded::ArtifactFactIr;
    use crate::analysis::facts::evidence::{AmbiguousEvidenceReuseIssue, EvidenceUseRecord};
    use crate::analysis::facts::safety::root_inputs::tests::{root_artifact, root_key};
    use crate::analysis::facts::safety::{
        DuplicateSafetyCallRequirementIssue, DuplicateSafetyRootRequirementIssue,
        IndirectSafetyCallBoundaryIssue, MissingSafetyDocsIssue, SafetyAnalysisIncompleteIssue,
        SafetyCompletenessOutcome, UnsatisfiedSafetyCallIssue, UnsatisfiedUnsafeOperationIssue,
    };
    use crate::analysis::facts::schema::{RowSchema, SchemaId};
    use crate::analysis::findings::InterpretationRoot;
    use crate::analysis::ir::{FunctionId, SourceFileIr, SourceRangeIr};
    use crate::cli::driver::interpretation::FindingSources;
    use crate::cli::driver::typed_panic::TypedPanicLocalArtifact;
    use crate::cli::driver::typed_panic_call::tests::{function, root, root_preparation_artifact};
    use crate::config::SniffTestConfig;
    use crate::report_roots::ReportRootKind;
    use rustc_span::Span;

    struct UnavailableSources;

    impl FindingSources for UnavailableSources {
        fn function_span(&self, _function: FunctionId) -> Option<Span> {
            None
        }

        fn resolve(&self, range: Option<&SourceRangeIr>) -> (Option<Span>, Option<String>) {
            match range {
                Some(_) => (None, Some(String::from("fixture source unavailable"))),
                None => (None, None),
            }
        }

        fn source_file<'a>(&'a self, _range: &SourceRangeIr) -> Option<&'a SourceFileIr> {
            None
        }

        fn render_span(&self, _span: Span) -> String {
            String::from("unreachable")
        }
    }

    fn root_request() -> InterpretationRoot {
        InterpretationRoot {
            function: FunctionId::generic(root_key().definition()),
            path: String::from("crate::root"),
            kind: ReportRootKind::Generic,
        }
    }

    fn evaluate_root(facts: &ArtifactFactIr, config: &SniffTestConfig) -> TypedSafetyBatchReport {
        evaluate_typed_safety_roots(
            TypedPanicLocalArtifact::in_memory(facts, 1),
            &[],
            Vec::new(),
            &[],
            std::slice::from_ref(&root_request()),
            config,
        )
        .expect("the typed safety authority evaluates the fixture root")
    }

    #[test]
    fn authority_registry_installs_every_safety_lane_once() {
        let registry = typed_safety_authority_registry().unwrap();
        for id in [
            MissingSafetyDocsIssue::ID,
            DuplicateSafetyRootRequirementIssue::ID,
            UnsatisfiedUnsafeOperationIssue::ID,
            UnsatisfiedSafetyCallIssue::ID,
            DuplicateSafetyCallRequirementIssue::ID,
            IndirectSafetyCallBoundaryIssue::ID,
            SafetyCompletenessOutcome::ID,
            SafetyAnalysisIncompleteIssue::ID,
            EvidenceUseRecord::ID,
            AmbiguousEvidenceReuseIssue::ID,
        ] {
            assert!(
                registry
                    .schemas()
                    .descriptor(&SchemaId::new(id).unwrap())
                    .is_some(),
                "missing safety authority schema {id}"
            );
        }

        let schedule = registry.evaluation_rules().schedule().unwrap();
        for id in [
            "sniff-test.safety.report-missing-docs",
            "sniff-test.safety.report-duplicate-root-requirements",
            "sniff-test.safety.report-unsafe-operations",
            "sniff-test.safety.report-calls",
            "sniff-test.safety.emit-evidence-uses",
            "sniff-test.safety.emit-completeness",
            "sniff-test.safety.report-incomplete",
            "sniff-test.evidence.detect-reuse",
        ] {
            assert_eq!(
                schedule.iter().filter(|pass| pass.as_str() == id).count(),
                1,
                "safety authority rule {id} must run exactly once"
            );
        }
    }

    #[test]
    fn combined_evaluator_finishes_every_safety_lane_from_one_root() {
        let function = function(991);
        let facts = root_preparation_artifact(&[function]);
        let request = root(function);
        let batch = evaluate_typed_safety_roots(
            TypedPanicLocalArtifact::in_memory(&facts, 1),
            &[],
            Vec::new(),
            &[],
            std::slice::from_ref(&request),
            &SniffTestConfig::default(),
        )
        .expect("the combined safety evaluator accepts one local root");

        let [report] = batch.roots.as_slice() else {
            panic!("one requested root must produce one safety report");
        };
        assert_eq!(report.request, request);
        assert_eq!(report.root, *report.inputs.root());
        assert!(report.missing_docs.is_empty());
        assert!(report.duplicate_root_requirements.is_empty());
        assert!(report.unsafe_operations.is_empty());
        assert!(report.unsatisfied_calls.is_empty());
        assert!(report.duplicate_call_requirements.is_empty());
        assert!(report.indirect_calls.is_empty());
        assert!(report.incomplete.is_empty());
        assert!(report.evidence_uses.is_empty());
        assert!(report.ambiguities.is_empty());
        assert!(matches!(
            report.completeness.as_slice(),
            [summary] if summary.data.complete() && summary.data.expanded_bodies() == 1
        ));
        assert!(batch.source_files.is_empty());
    }

    #[test]
    fn combined_evaluator_projects_unsafe_operation_issues() {
        let (_, facts) = root_artifact(false, false, None, false, false);
        let request = root_request();
        let mut config = SniffTestConfig::default();
        config.analysis.callable_edge_attribution =
            crate::config::CallableEdgeAttribution::CallSites;
        config.analysis.marker_probing = crate::config::MarkerProbing::SourceCallsite;
        let batch = evaluate_root(&facts, &config);

        let [report] = batch.roots.as_slice() else {
            panic!("one requested root must produce one safety report");
        };
        assert_eq!(report.unsafe_operations.len(), 1);
        assert!(report.unsatisfied_calls.is_empty());
        assert!(report.indirect_calls.is_empty());
        assert!(report.completeness[0].data.complete());
        assert!(report.presentation_range.is_none());
        let findings = project_unsafe_operation_findings(report)
            .expect("the typed unsafe-operation report projects");
        let [finding] = findings.as_slice() else {
            panic!("one issue must produce one finding");
        };
        assert_eq!(finding.function, request.function);
        assert_eq!(finding.function_path, request.path);
        assert!(matches!(
            finding.kind,
            crate::analysis::findings::InterpretedFindingKind::UnsafeOperation { .. }
        ));
    }

    #[test]
    fn authority_batch_preflights_and_adapts_every_ready_safety_lane() {
        let (_, facts) = root_artifact(false, false, None, true, false);
        let request = root_request();
        let mut config = SniffTestConfig::default();
        config.analysis.callable_edge_attribution =
            crate::config::CallableEdgeAttribution::CallSites;
        let batch = evaluate_root(&facts, &config);
        let findings = adapt_typed_safety_authority_batch(
            &UnavailableSources,
            &batch,
            std::slice::from_ref(&request),
            false,
        )
        .expect("the complete safety batch preflights before adaptation");
        assert!(findings.iter().any(|finding| {
            finding.kind == crate::cli::findings::FindingKind::IndirectSafetyCallBoundary
        }));
    }

    #[test]
    fn authority_batch_preserves_ready_and_missing_root_order() {
        let ready = function(991);
        let missing = function(992);
        let facts = root_preparation_artifact(&[ready]);
        let roots = [root(ready), root(missing)];
        let batch = evaluate_typed_safety_roots(
            TypedPanicLocalArtifact::in_memory(&facts, 1),
            &[],
            Vec::new(),
            &[],
            &roots,
            &SniffTestConfig::default(),
        )
        .expect("one missing selected safety root is a typed completeness outcome");
        assert_eq!(batch.roots.len(), 1);
        assert!(matches!(
            batch.root_preparations.as_slice(),
            [
                super::TypedSafetyRootPreparationReport {
                    outcome: super::TypedSafetyRootPreparationOutcome::Evaluatable {
                        report_index: 0,
                        ..
                    },
                    ..
                },
                super::TypedSafetyRootPreparationReport {
                    outcome: super::TypedSafetyRootPreparationOutcome::Missing { .. },
                    ..
                }
            ]
        ));
        let findings =
            adapt_typed_safety_authority_batch(&UnavailableSources, &batch, &roots, false)
                .expect("the sparse safety batch adapts atomically");
        assert!(findings.iter().any(|finding| {
            finding.kind == crate::cli::findings::FindingKind::SafetyAnalysisIncomplete
                && finding.root.as_deref() == Some(roots[1].path.as_str())
        }));
    }

    #[test]
    fn safety_call_projection_is_bijective_and_preserves_requirements() {
        let (_, facts) = root_artifact(false, false, Some(false), false, false);
        let request = root_request();
        let mut config = SniffTestConfig::default();
        config.analysis.callable_edge_attribution =
            crate::config::CallableEdgeAttribution::CallSites;
        let batch = evaluate_root(&facts, &config);
        let [report] = batch.roots.as_slice() else {
            panic!("one requested root must produce one safety report");
        };
        let findings = project_safety_call_findings(report)
            .expect("the typed safety-call report projects bijectively");
        let [finding] = findings.as_slice() else {
            panic!(
                "one unsatisfied call must produce one finding, got {}",
                findings.len()
            );
        };
        assert!(matches!(
            finding.kind,
            crate::analysis::findings::InterpretedFindingKind::SafetyCall {
                kind: crate::analysis::findings::InterpretedSafetyCallKind::Obligation,
                ..
            }
        ));
        assert_eq!(finding.function, request.function);
        assert_eq!(finding.target.as_ref().unwrap().path, "crate::target");
        assert_eq!(finding.requirements.len(), 2);
        assert_eq!(finding.missing_requirements, finding.requirements);
        assert_eq!(finding.trace.steps.len(), 1);
        let duplicates = project_duplicate_safety_call_findings(report)
            .expect("duplicate call requirements project bijectively");
        let [duplicate_finding] = duplicates.as_slice() else {
            panic!("the duplicate normalized contract group must be reported once");
        };
        assert!(matches!(
            &duplicate_finding.kind,
            crate::analysis::findings::InterpretedFindingKind::AmbiguousSafetyRequirement { normalized_name }
                if normalized_name == "valid"
        ));
        assert_eq!(duplicate_finding.requirements.len(), 2);
        assert!(duplicate_finding.target.is_some());

        let mut missing = report.clone();
        missing.unsatisfied_calls.clear();
        assert!(project_safety_call_findings(&missing).is_err());
        let mut duplicate = report.clone();
        duplicate
            .unsatisfied_calls
            .push(duplicate.unsatisfied_calls[0].clone());
        assert!(project_safety_call_findings(&duplicate).is_err());
    }

    #[test]
    fn root_safety_projection_preserves_each_policy_finding() {
        enum ExpectedFinding {
            MissingDocs,
            DuplicateRequirement,
        }

        for (has_contract, expected) in [
            (false, ExpectedFinding::MissingDocs),
            (true, ExpectedFinding::DuplicateRequirement),
        ] {
            let (_, facts) = root_artifact(has_contract, false, None, false, false);
            let batch = evaluate_root(&facts, &SniffTestConfig::default());
            let findings = project_safety_root_findings(&batch.roots[0])
                .expect("root safety rows project bijectively");
            let [finding] = findings.as_slice() else {
                panic!("each root policy must project one finding, got {findings:?}");
            };
            match expected {
                ExpectedFinding::MissingDocs => assert!(matches!(
                    finding.kind,
                    crate::analysis::findings::InterpretedFindingKind::MissingSafetyDocs
                )),
                ExpectedFinding::DuplicateRequirement => {
                    assert!(matches!(
                        finding.kind,
                        crate::analysis::findings::InterpretedFindingKind::AmbiguousSafetyRequirement { .. }
                    ));
                    assert!(finding.target.is_none());
                    assert!(finding.trace.steps.is_empty());
                    assert_eq!(finding.requirements.len(), 2);
                }
            }
        }
    }

    #[test]
    fn indirect_safety_boundary_is_visible_and_bijective() {
        let (_, facts) = root_artifact(false, false, None, true, false);
        let mut config = SniffTestConfig::default();
        config.analysis.callable_edge_attribution =
            crate::config::CallableEdgeAttribution::CallSites;
        let batch = evaluate_root(&facts, &config);
        let report = &batch.roots[0];
        let findings = project_indirect_safety_findings(report)
            .expect("the indirect safety report projects bijectively");
        let [finding] = findings.as_slice() else {
            panic!("one opaque call must produce one boundary finding");
        };
        assert!(matches!(
            &finding.kind,
            crate::analysis::findings::InterpretedFindingKind::OpaqueSafetyBoundary { description }
                if description == "indirect call through a function pointer"
        ));
        assert_eq!(finding.target.as_ref().unwrap().function, None);
        assert_eq!(finding.trace.steps.len(), 1);

        let mut missing = report.clone();
        missing.indirect_calls.clear();
        assert!(project_indirect_safety_findings(&missing).is_err());
    }

    #[test]
    fn safety_completeness_projection_preserves_the_canonical_reason() {
        let (_, facts) = root_artifact(false, false, None, false, false);
        let mut config = SniffTestConfig::default();
        config.analysis.node_limit = 0;
        let batch = evaluate_root(&facts, &config);
        let report = &batch.roots[0];
        assert!(matches!(
            project_safety_incomplete_reasons(report)
                .expect("the safety completeness report projects")
                .as_slice(),
            [crate::analysis::findings::IncompleteReason::NodeLimit { limit: 0 }]
        ));

        let mut missing = report.clone();
        missing.incomplete.clear();
        assert!(project_safety_incomplete_reasons(&missing).is_err());
        let mut duplicate = report.clone();
        duplicate.incomplete.push(duplicate.incomplete[0].clone());
        assert!(project_safety_incomplete_reasons(&duplicate).is_err());
    }

    #[test]
    fn safety_ambiguity_projection_is_bijective_and_owns_the_physical_marker() {
        let (_, facts) = root_artifact(false, true, None, false, true);
        let request = root_request();
        let mut config = SniffTestConfig::default();
        config.analysis.callable_edge_attribution =
            crate::config::CallableEdgeAttribution::CallSites;
        config.analysis.marker_probing = crate::config::MarkerProbing::SourceCallsite;
        let batch = evaluate_root(&facts, &config);
        let report = &batch.roots[0];
        assert_eq!(report.evidence_uses.len(), 2);
        assert_eq!(report.ambiguities.len(), 1);
        let [finding] = report.ambiguity_findings.as_slice() else {
            panic!("one reused marker must project one owned finding");
        };
        assert!(matches!(
            finding.kind,
            crate::analysis::findings::InterpretedFindingKind::AmbiguousSafetyMarker {
                effect_count: 2
            }
        ));
        assert_eq!(finding.function, request.function);
        assert!(finding.target.is_none());
        assert!(finding.source_range.is_some());
    }
}
