//! Test-only projection of permanent panic-call issues through the legacy report boundary.

use std::collections::{BTreeMap, btree_map::Entry};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use crate::analysis::cache::{ArtifactAnalysisCache, RustcArtifactId};
use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
use crate::analysis::facts::composition::{
    CompositionRelationBuilder, WorkspaceEvaluationView, WorkspaceRelationIndex,
};
use crate::analysis::facts::evaluation::{
    EvaluationDb, EvaluationRoot, TypedDerivedRow, TypedEvaluatedIssue,
};
use crate::analysis::facts::human::HumanEvidencePack;
use crate::analysis::facts::pack::{AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::panic::{
    DuplicatePanicCallRequirementIssue, PanicCallBoundaryKind, PanicCallInputKind,
    PanicCallInputPack, PanicCallObligation, PanicCallOpaqueKind, PanicCallRequirementMatchId,
    PanicCallRequirementValue, PanicCallResolution, PanicCallSemanticEdge, PanicCallSemanticTrace,
    PanicCallSemanticTraceStepKind, PanicCallTargetAuthority, PanicCallTraceError,
    PanicCallTraceNode, PanicCallTraceProjector, PanicCallableResolutionKind,
    PanicOpaqueBoundaryKind, PanicRootInputs, PreparedCompilerAssertRootBatch,
    UnsatisfiedPanicCallIssue,
};
use crate::analysis::facts::program::FunctionKey;
use crate::analysis::facts::program::root_traversal::{CallTargetSelection, ProgramCallResolution};
use crate::analysis::facts::program::topology::{CallKind, CallSourceAnchorRole};
use crate::analysis::facts::workspace::WorkspaceFactView;
use crate::analysis::interpret::{
    InterpretationRoot, InterpretedFinding, InterpretedFindingKind, InterpretedTarget,
    InterpretedTrace, InterpretedTraceStep, InterpretedTraceStepKind,
};
use crate::analysis::ir::{
    CallEdgeKindIr, CallId, ContractRequirementIr, FunctionId, SourceFileIr, SourceRangeIr,
};
use crate::analysis::workspace_closure::{ManagedArtifactManifest, VerifiedWorkspaceClosure};
use crate::cli::driver::interpretation::{FindingSources, adapt_typed_panic_call_finding};
use crate::cli::findings::Finding;
use crate::config::SniffTestConfig;
use crate::report_roots::ReportRootKind;

use super::typed_panic::{
    FunctionPresentationIndex, TypedPanicEvaluationError, TypedPanicLocalArtifact,
    compiler_assert_root_request, open_typed_artifacts, permanent_source_files, source_range,
};

const EMIT_PANIC_CALL_INPUTS_RULE: &str = "sniff-test.panic.emit-call-inputs";
const REPORT_UNSATISFIED_PANIC_CALLS_RULE: &str =
    "sniff-test.panic.report-unsatisfied-call-obligations";
const REPORT_DUPLICATE_PANIC_CALL_REQUIREMENTS_RULE: &str =
    "sniff-test.panic.report-duplicate-call-requirements";

#[derive(Debug)]
pub(super) enum TypedPanicCallEvaluationError {
    Base(TypedPanicEvaluationError),
    Trace(Box<PanicCallTraceError>),
    InvalidProjection { subject: String, reason: String },
}

impl Display for TypedPanicCallEvaluationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base(source) => Display::fmt(source, formatter),
            Self::Trace(source) => write!(
                formatter,
                "typed panic-call semantic trace projection failed: {source}"
            ),
            Self::InvalidProjection { subject, reason } => {
                write!(formatter, "typed panic-call {subject} is invalid: {reason}")
            }
        }
    }
}

impl Error for TypedPanicCallEvaluationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Base(source) => Some(source),
            Self::Trace(source) => Some(source),
            Self::InvalidProjection { .. } => None,
        }
    }
}

impl From<TypedPanicEvaluationError> for TypedPanicCallEvaluationError {
    fn from(source: TypedPanicEvaluationError) -> Self {
        Self::Base(source)
    }
}

#[derive(Clone, Debug)]
pub(super) struct TypedPanicCallBatchReport {
    pub(super) roots: Vec<TypedPanicCallRootReport>,
    #[allow(
        dead_code,
        reason = "the test-only shadow keeps source inventory parity for the eventual authority switch"
    )]
    pub(super) source_files: Vec<SourceFileIr>,
}

#[derive(Clone, Debug)]
pub(super) struct TypedPanicCallRootReport {
    pub(super) root: EvaluationRoot,
    pub(super) function: FunctionId,
    pub(super) path: String,
    pub(super) kind: ReportRootKind,
    #[allow(
        dead_code,
        reason = "root presentation provenance is retained for the eventual authority switch"
    )]
    pub(super) presentation_range: Option<SourceRangeIr>,
    pub(super) issues: Vec<TypedPanicCallIssueReport>,
}

#[derive(Clone, Debug)]
struct TypedPanicCallProjectionFixture {
    inputs: PanicRootInputs,
    obligations: Vec<TypedDerivedRow<PanicCallObligation>>,
    unsatisfied: Vec<TypedEvaluatedIssue<UnsatisfiedPanicCallIssue>>,
    duplicates: Vec<TypedEvaluatedIssue<DuplicatePanicCallRequirementIssue>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum TypedPanicCallIssueKind {
    Unsatisfied { boundary: PanicCallBoundaryKind },
    Duplicate { normalized_name: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TypedPanicCallTargetReport {
    pub(super) function: Option<FunctionId>,
    pub(super) path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TypedPanicCallRequirementReport {
    pub(super) name: String,
    pub(super) condition: String,
    pub(super) source_range: Option<SourceRangeIr>,
}

#[derive(Clone, Debug)]
pub(super) struct TypedPanicCallIssueReport {
    pub(super) root: EvaluationRoot,
    pub(super) kind: TypedPanicCallIssueKind,
    pub(super) function: FunctionId,
    pub(super) function_path: String,
    pub(super) target: TypedPanicCallTargetReport,
    pub(super) source_range: Option<SourceRangeIr>,
    pub(super) trace: Arc<PanicCallSemanticTrace>,
    pub(super) missing_requirements: Vec<TypedPanicCallRequirementReport>,
    pub(super) requirements: Vec<TypedPanicCallRequirementReport>,
}

type RootTypedPanicCallEvaluation = Result<TypedPanicCallRootReport, TypedPanicCallEvaluationError>;

pub(super) fn evaluate_typed_panic_call_roots(
    local: TypedPanicLocalArtifact<'_>,
    dependencies: &[&ArtifactAnalysisCache],
    direct_dependencies: Vec<RustcArtifactId>,
    active_runtime_artifacts: &[RustcArtifactId],
    roots: &[InterpretationRoot],
    config: &SniffTestConfig,
) -> Result<TypedPanicCallBatchReport, TypedPanicCallEvaluationError> {
    evaluate_typed_panic_call_roots_inner(
        local,
        dependencies,
        direct_dependencies,
        active_runtime_artifacts,
        roots,
        config,
        None,
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the optional test capture mirrors the complete root-evaluation boundary"
)]
fn evaluate_typed_panic_call_roots_inner(
    local: TypedPanicLocalArtifact<'_>,
    dependencies: &[&ArtifactAnalysisCache],
    direct_dependencies: Vec<RustcArtifactId>,
    active_runtime_artifacts: &[RustcArtifactId],
    roots: &[InterpretationRoot],
    config: &SniffTestConfig,
    mut projection_capture: Option<&mut Option<TypedPanicCallProjectionFixture>>,
) -> Result<TypedPanicCallBatchReport, TypedPanicCallEvaluationError> {
    if roots.is_empty() {
        return Ok(TypedPanicCallBatchReport {
            roots: Vec::new(),
            source_files: Vec::new(),
        });
    }
    let registry = typed_panic_call_registry()
        .map_err(|source| TypedPanicEvaluationError::Registration(Box::new(source)))?;
    let opened = open_typed_artifacts(local, dependencies, &registry)?;
    let workspace = WorkspaceFactView::compose(opened.views)
        .map_err(|source| TypedPanicEvaluationError::Workspace(Box::new(source)))?;
    let source_files = permanent_source_files(&workspace)?;
    let closure = VerifiedWorkspaceClosure::open_with_runtime_inventory(
        &workspace,
        ManagedArtifactManifest::new(opened.local_generation, direct_dependencies),
        opened.dependency_manifests,
        active_runtime_artifacts.iter().cloned(),
    )
    .map_err(|source| TypedPanicEvaluationError::Closure(Box::new(source)))?;
    let requests = roots
        .iter()
        .map(|root| compiler_assert_root_request(root, config));
    let batch = PreparedCompilerAssertRootBatch::prepare(
        &workspace,
        &closure,
        &config.panics,
        &config.documentation.overrides,
        requests,
    )
    .map_err(|source| TypedPanicEvaluationError::Input(Box::new(source)))?;
    let prepared_roots = batch.into_roots();
    if prepared_roots.len() != roots.len() {
        return Err(TypedPanicEvaluationError::PreparedRootCount {
            expected: roots.len(),
            actual: prepared_roots.len(),
        }
        .into());
    }
    let presentation_anchors = FunctionPresentationIndex::build(&workspace)?;
    let relation_index = WorkspaceRelationIndex::open(&workspace)
        .map_err(|source| TypedPanicEvaluationError::Relations(Box::new(source)))?;

    let roots = prepared_roots
        .into_iter()
        .zip(roots)
        .map(|(root_input, request)| {
            let root = root_input.root().clone();
            let mut relation_builder = CompositionRelationBuilder::new(
                &root,
                &workspace,
                registry.composition_relations(),
            )
            .map_err(|source| TypedPanicEvaluationError::Composition(Box::new(source)))?;
            let emitted = root_input
                .emit(&mut relation_builder)
                .map_err(|source| TypedPanicEvaluationError::Input(Box::new(source)))?;
            let relations = relation_builder
                .finalize()
                .map_err(|source| TypedPanicEvaluationError::Composition(Box::new(source)))?;
            let graph = relation_index
                .bind(&root, relations)
                .map_err(|source| TypedPanicEvaluationError::Relations(Box::new(source)))?;
            let inputs = emitted
                .resolve_panic(&workspace, &graph, registry.composition_relations())
                .map_err(|source| TypedPanicEvaluationError::Input(Box::new(source)))?;
            let evaluation = WorkspaceEvaluationView::from_graph(&workspace, graph)
                .map_err(|source| TypedPanicEvaluationError::Relations(Box::new(source)))?;
            let mut evaluated = EvaluationDb::new();
            registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .map_err(|source| TypedPanicEvaluationError::Evaluation(Box::new(source)))?;
            let results = evaluated
                .finish()
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            let obligations = results
                .derived_rows::<PanicCallObligation>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            let unsatisfied = results
                .issues::<UnsatisfiedPanicCallIssue>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            let duplicates = results
                .issues::<DuplicatePanicCallRequirementIssue>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            if let Some(capture) = projection_capture.as_deref_mut() {
                *capture = Some(TypedPanicCallProjectionFixture {
                    inputs: inputs.clone(),
                    obligations: obligations.clone(),
                    unsatisfied: unsatisfied.clone(),
                    duplicates: duplicates.clone(),
                });
            }
            project_root_report(
                &inputs,
                &presentation_anchors,
                request,
                &root,
                obligations,
                unsatisfied,
                duplicates,
            )
        })
        .collect::<Result<Vec<_>, TypedPanicCallEvaluationError>>()?;
    Ok(TypedPanicCallBatchReport {
        roots,
        source_files,
    })
}

fn typed_panic_call_registry() -> Result<AnalysisRegistry<PanicRootInputs>, PackRegistrationError> {
    let mut registry = AnalysisRegistry::new();
    registry.install(&CollectedArtifactSchemaPack)?;
    registry.install(&HumanEvidencePack)?;
    registry.install(&PanicCallInputPack)?;
    Ok(registry)
}

fn project_root_report(
    inputs: &PanicRootInputs,
    presentation_anchors: &FunctionPresentationIndex,
    request: &InterpretationRoot,
    root: &EvaluationRoot,
    obligations: Vec<TypedDerivedRow<PanicCallObligation>>,
    unsatisfied: Vec<TypedEvaluatedIssue<UnsatisfiedPanicCallIssue>>,
    duplicates: Vec<TypedEvaluatedIssue<DuplicatePanicCallRequirementIssue>>,
) -> RootTypedPanicCallEvaluation {
    let obligations = index_obligations(inputs, root, obligations)?;
    let projector = PanicCallTraceProjector::prepare(inputs)
        .map_err(|source| TypedPanicCallEvaluationError::Trace(Box::new(source)))?;
    let mut witnesses = BTreeMap::<u64, ProjectedCallWitness>::new();
    let mut issues = Vec::with_capacity(unsatisfied.len() + duplicates.len());
    for issue in unsatisfied {
        let witness = issue.data.witness_order();
        let obligation = obligation(&obligations, witness, "unsatisfied issue")?;
        validate_unsatisfied_issue(root, obligation, &issue)?;
        let projected = projected_witness(&projector, obligation, &mut witnesses)?;
        let missing_requirements = projected
            .requirements
            .select(issue.data.missing_requirements(), "unsatisfied issue")?;
        issues.push(project_unsatisfied_issue(
            projected,
            issue,
            missing_requirements,
        ));
    }
    for issue in duplicates {
        let witness = issue.data.witness_order();
        let obligation = obligation(&obligations, witness, "duplicate issue")?;
        validate_duplicate_issue(root, obligation, &issue)?;
        let projected = projected_witness(&projector, obligation, &mut witnesses)?;
        let requirements = projected
            .requirements
            .select(issue.data.requirements(), "duplicate issue")?;
        if requirements.iter().any(|requirement| {
            requirement_name_normalized(&requirement.name) != issue.data.normalized_name()
        }) {
            return Err(invalid(
                "duplicate issue",
                "selected requirement does not have the reported normalized name",
            ));
        }
        issues.push(project_duplicate_issue(
            obligation,
            projected,
            issue,
            requirements,
        ));
    }
    issues.sort_by(|left, right| projected_issue_order(left).cmp(&projected_issue_order(right)));
    Ok(TypedPanicCallRootReport {
        root: root.clone(),
        function: request.function,
        path: request.path.clone(),
        kind: request.kind,
        presentation_range: presentation_anchors.range(&root.entity)?,
        issues,
    })
}

fn projected_issue_order(issue: &TypedPanicCallIssueReport) -> (u64, u8, &str) {
    let (class, normalized_name) = match &issue.kind {
        TypedPanicCallIssueKind::Duplicate { normalized_name } => (0, normalized_name.as_str()),
        TypedPanicCallIssueKind::Unsatisfied { .. } => (1, ""),
    };
    (
        issue.trace.terminal().traversal_order(),
        class,
        normalized_name,
    )
}

fn index_obligations(
    inputs: &PanicRootInputs,
    root: &EvaluationRoot,
    rows: Vec<TypedDerivedRow<PanicCallObligation>>,
) -> Result<Vec<PanicCallObligation>, TypedPanicCallEvaluationError> {
    let mut indexed = (0..inputs.call_count()).map(|_| None).collect::<Vec<_>>();
    for row in rows {
        let call_id = usize::try_from(row.data.call_id())
            .map_err(|_| invalid("obligation", "call ID does not fit usize"))?;
        if row.root != *root || row.producer.as_str() != EMIT_PANIC_CALL_INPUTS_RULE {
            return Err(invalid(
                "obligation",
                "root or producer disagrees with the call-input rule",
            ));
        }
        let slot = indexed
            .get_mut(call_id)
            .ok_or_else(|| invalid("obligation", "call ID is outside the prepared input batch"))?;
        if slot.replace(row.data).is_some() {
            return Err(invalid("obligation", "call ID is duplicated"));
        }
    }
    indexed
        .into_iter()
        .enumerate()
        .map(|(call_id, row)| {
            row.ok_or_else(|| invalid("obligation", format!("call ID {call_id} is missing")))
        })
        .collect()
}

fn obligation<'a>(
    obligations: &'a [PanicCallObligation],
    witness: u64,
    subject: &str,
) -> Result<&'a PanicCallObligation, TypedPanicCallEvaluationError> {
    let index =
        usize::try_from(witness).map_err(|_| invalid(subject, "witness ID does not fit usize"))?;
    obligations
        .get(index)
        .ok_or_else(|| invalid(subject, "witness ID has no committed obligation"))
}

fn validate_unsatisfied_issue(
    root: &EvaluationRoot,
    obligation: &PanicCallObligation,
    issue: &TypedEvaluatedIssue<UnsatisfiedPanicCallIssue>,
) -> Result<(), TypedPanicCallEvaluationError> {
    if issue.data.missing_requirements().is_empty() {
        return Err(invalid(
            "unsatisfied issue",
            "missing requirement IDs are empty",
        ));
    }
    if issue.producer.as_str() != REPORT_UNSATISFIED_PANIC_CALLS_RULE
        || issue.context.root != *root
        || issue.context.source.as_ref() != Some(issue.data.source())
        || issue.context.endpoint.as_ref() != Some(issue.data.endpoint())
        || issue.context.trace.as_ref() != Some(obligation.trace())
        || issue.data.source() != obligation.source()
        || issue.data.endpoint() != obligation.endpoint()
        || issue.data.boundary_kind() != obligation.boundary_kind()
        || issue.data.witness_order() != obligation.call_id()
    {
        return Err(invalid(
            "unsatisfied issue",
            "stored context disagrees with its exact committed call obligation",
        ));
    }
    Ok(())
}

fn validate_duplicate_issue(
    root: &EvaluationRoot,
    obligation: &PanicCallObligation,
    issue: &TypedEvaluatedIssue<DuplicatePanicCallRequirementIssue>,
) -> Result<(), TypedPanicCallEvaluationError> {
    if issue.data.normalized_name().is_empty()
        || issue.data.requirements().len() < 2
        || !matches!(
            obligation.boundary_kind(),
            PanicCallBoundaryKind::Documented { .. }
        )
        || obligation.contract().is_none()
    {
        return Err(invalid(
            "duplicate issue",
            "duplicate shape is not a documented contract group",
        ));
    }
    if issue.producer.as_str() != REPORT_DUPLICATE_PANIC_CALL_REQUIREMENTS_RULE
        || issue.context.root != *root
        || issue.context.source.as_ref() != Some(issue.data.source())
        || issue.context.endpoint.as_ref() != Some(issue.data.presentation_function().endpoint())
        || issue.context.trace.as_ref() != Some(obligation.trace())
        || issue.data.source() != obligation.source()
        || issue.data.presentation_function() != obligation.presentation_function()
        || issue.data.witness_order() != obligation.call_id()
    {
        return Err(invalid(
            "duplicate issue",
            "stored context disagrees with its exact committed call obligation",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ProjectedCallWitness {
    function: FunctionId,
    function_path: String,
    target: TypedPanicCallTargetReport,
    recorded_source: Option<SourceRangeIr>,
    trace: Arc<PanicCallSemanticTrace>,
    requirements: ProjectedRequirements,
}

#[derive(Clone, Debug)]
enum ProjectedRequirements {
    Unnamed,
    Named(Vec<TypedPanicCallRequirementReport>),
}

impl ProjectedRequirements {
    fn all_named(&self) -> Vec<TypedPanicCallRequirementReport> {
        match self {
            Self::Unnamed => Vec::new(),
            Self::Named(requirements) => requirements.clone(),
        }
    }

    fn select(
        &self,
        ids: &[PanicCallRequirementMatchId],
        subject: &str,
    ) -> Result<Vec<TypedPanicCallRequirementReport>, TypedPanicCallEvaluationError> {
        let mut previous = None;
        let mut selected = Vec::with_capacity(ids.len());
        for id in ids {
            if previous.is_some_and(|previous| previous >= *id) {
                return Err(invalid(
                    subject,
                    "requirement IDs are not in strict declaration order",
                ));
            }
            previous = Some(*id);
            match (self, id) {
                (Self::Unnamed, PanicCallRequirementMatchId::Unnamed) => {}
                (Self::Named(requirements), PanicCallRequirementMatchId::Named { ordinal }) => {
                    let index = usize::try_from(*ordinal)
                        .map_err(|_| invalid(subject, "requirement ordinal does not fit usize"))?;
                    selected.push(
                        requirements
                            .get(index)
                            .ok_or_else(|| invalid(subject, "named requirement ID is absent"))?
                            .clone(),
                    );
                }
                (Self::Unnamed, PanicCallRequirementMatchId::Named { .. })
                | (Self::Named(_), PanicCallRequirementMatchId::Unnamed) => {
                    return Err(invalid(
                        subject,
                        "requirement ID has the wrong requirement kind",
                    ));
                }
            }
        }
        Ok(selected)
    }
}

fn projected_witness<'a>(
    projector: &PanicCallTraceProjector<'_>,
    obligation: &PanicCallObligation,
    cache: &'a mut BTreeMap<u64, ProjectedCallWitness>,
) -> Result<&'a ProjectedCallWitness, TypedPanicCallEvaluationError> {
    if let Entry::Vacant(entry) = cache.entry(obligation.call_id()) {
        let input = projector
            .call(obligation.call_id())
            .map_err(|source| TypedPanicCallEvaluationError::Trace(Box::new(source)))?;
        if input.presentation_function() != obligation.presentation_function() {
            return Err(invalid(
                "trace",
                "prepared presentation endpoint, scope, or function disagrees with the obligation",
            ));
        }
        let trace = projector
            .project(obligation.call_id())
            .map_err(|source| TypedPanicCallEvaluationError::Trace(Box::new(source)))?;
        validate_trace_identity(obligation, &trace)?;
        let projected = project_witness(obligation, Arc::new(trace))?;
        entry.insert(projected);
    }
    cache
        .get(&obligation.call_id())
        .ok_or_else(|| invalid("trace", "projected witness cache lost its inserted entry"))
}

fn validate_trace_identity(
    obligation: &PanicCallObligation,
    trace: &PanicCallSemanticTrace,
) -> Result<(), TypedPanicCallEvaluationError> {
    let terminal = trace.terminal();
    let terminal_id = u64::try_from(terminal.call_id().index())
        .map_err(|_| invalid("trace", "terminal call ID does not fit u64"))?;
    if trace.source() != obligation.source()
        || &trace.endpoint().erase() != obligation.endpoint()
        || trace.endpoint_data() != obligation.occurrence_data()
        || trace.trace_target() != obligation.trace_target()
        || trace.relation_trace() != obligation.trace()
        || trace.witness_order() != obligation.call_id()
        || terminal_id != obligation.call_id()
        || terminal.traversal_order() != obligation.traversal_order()
        || terminal.effective_kind() != obligation.effective_kind()
        || !boundary_matches(obligation.boundary_kind(), terminal.boundary())
        || !boundary_description_matches(obligation.boundary_kind(), trace)
        || !resolution_matches(obligation.resolution(), terminal.resolution())
        || terminal.evidence_group().erase() != *obligation.evidence_group()
        || terminal.evidence_group_data() != obligation.evidence_group_data()
        || !presentation_matches(obligation, trace)
        || !metadata_matches(obligation, trace)
        || !contract_target_matches(obligation, terminal.contract_target())
    {
        return Err(invalid(
            "trace",
            "semantic projection changed the full committed obligation identity",
        ));
    }
    let Some(terminal_step) = trace.steps().last() else {
        return Err(invalid("trace", "semantic trace is empty"));
    };
    if !matches!(
        terminal_step.kind(),
        PanicCallSemanticTraceStepKind::TerminalCall
    ) {
        return Err(invalid("trace", "semantic trace has no terminal call step"));
    }
    Ok(())
}

fn boundary_description_matches(
    boundary: &PanicCallBoundaryKind,
    trace: &PanicCallSemanticTrace,
) -> bool {
    match boundary {
        PanicCallBoundaryKind::Opaque {
            opaque_kind: PanicCallOpaqueKind::BodylessDeclaration,
            description,
        } => trace.terminal().boundary_description() == Some(description.as_str()),
        PanicCallBoundaryKind::Opaque {
            opaque_kind: PanicCallOpaqueKind::ExplicitOpaque,
            description,
        } => trace.terminal().presentation().raw_opaque_description() == Some(description.as_str()),
        PanicCallBoundaryKind::Documented { .. } | PanicCallBoundaryKind::PanicSink => true,
    }
}

fn resolution_matches(obligation: &PanicCallResolution, projected: &ProgramCallResolution) -> bool {
    match (obligation, projected) {
        (PanicCallResolution::Persisted, ProgramCallResolution::Persisted) => true,
        (
            PanicCallResolution::CallableEvidence {
                evidence: left_evidence,
                key: left_key,
                resolution_kind,
            },
            ProgramCallResolution::CallableEvidence {
                evidence: right_evidence,
                key: right_key,
                kind,
            },
        ) => {
            left_evidence == &right_evidence.erase()
                && left_key == right_key
                && resolution_kind == &PanicCallableResolutionKind::from(*kind)
        }
        (PanicCallResolution::Persisted, ProgramCallResolution::CallableEvidence { .. })
        | (PanicCallResolution::CallableEvidence { .. }, ProgramCallResolution::Persisted) => false,
    }
}

fn boundary_matches(boundary: &PanicCallBoundaryKind, projected: PanicCallInputKind) -> bool {
    matches!(
        (boundary, projected),
        (
            PanicCallBoundaryKind::Documented { trusted: left },
            PanicCallInputKind::Documented { trusted: right }
        ) if left == &right
    ) || matches!(
        (boundary, projected),
        (
            PanicCallBoundaryKind::PanicSink,
            PanicCallInputKind::PanicSink
        )
    ) || matches!(
        (boundary, projected),
        (
            PanicCallBoundaryKind::Opaque {
                opaque_kind: PanicCallOpaqueKind::BodylessDeclaration,
                ..
            },
            PanicCallInputKind::Opaque {
                kind: PanicOpaqueBoundaryKind::BodylessDeclaration
            }
        ) | (
            PanicCallBoundaryKind::Opaque {
                opaque_kind: PanicCallOpaqueKind::ExplicitOpaque,
                ..
            },
            PanicCallInputKind::Opaque {
                kind: PanicOpaqueBoundaryKind::ExplicitOpaque
            }
        )
    )
}

fn presentation_matches(obligation: &PanicCallObligation, trace: &PanicCallSemanticTrace) -> bool {
    let presentation = obligation.presentation_function();
    if let Some(callable) = trace.terminal().presentation_callable() {
        presentation.endpoint() == &callable.selection().callable().erase()
            && presentation.function() == callable.data().key()
    } else {
        trace.steps().last().is_some_and(|terminal| {
            presentation.endpoint() == &terminal.owner().body().erase()
                && presentation.scope() == terminal.owner().body().scope()
                && presentation.function() == terminal.owner().data().key()
        })
    }
}

fn metadata_matches(obligation: &PanicCallObligation, trace: &PanicCallSemanticTrace) -> bool {
    match (
        obligation.metadata_target(),
        trace.terminal().metadata_target(),
    ) {
        (None, None) => true,
        (Some(obligation), Some(projected)) => {
            obligation.selection().callable() == &projected.selection().callable().erase()
                && obligation.selection().role() == projected.selection().role()
                && obligation.selection().authority()
                    == PanicCallTargetAuthority::from(projected.selection().authority())
                && obligation.data() == projected.data()
        }
        (None, Some(_)) | (Some(_), None) => false,
    }
}

fn contract_target_matches(
    obligation: &PanicCallObligation,
    projected: Option<&CallTargetSelection>,
) -> bool {
    match (obligation.contract(), projected) {
        (None, None) => true,
        (Some(contract), Some(projected)) => {
            let obligation = contract.target();
            obligation.callable() == &projected.callable().erase()
                && obligation.role() == projected.role()
                && obligation.authority() == PanicCallTargetAuthority::from(projected.authority())
        }
        (None, Some(_)) | (Some(_), None) => false,
    }
}

fn project_unsatisfied_issue(
    projected: &ProjectedCallWitness,
    issue: TypedEvaluatedIssue<UnsatisfiedPanicCallIssue>,
    missing_requirements: Vec<TypedPanicCallRequirementReport>,
) -> TypedPanicCallIssueReport {
    let TypedEvaluatedIssue {
        reference: _,
        data,
        context,
        producer: _,
    } = issue;
    let root = context.root;
    let kind = TypedPanicCallIssueKind::Unsatisfied {
        boundary: data.boundary_kind().clone(),
    };
    TypedPanicCallIssueReport {
        root,
        kind,
        function: projected.function,
        function_path: projected.function_path.clone(),
        target: projected.target.clone(),
        source_range: projected.recorded_source.clone(),
        trace: Arc::clone(&projected.trace),
        missing_requirements,
        requirements: projected.requirements.all_named(),
    }
}

fn project_duplicate_issue(
    obligation: &PanicCallObligation,
    projected: &ProjectedCallWitness,
    issue: TypedEvaluatedIssue<DuplicatePanicCallRequirementIssue>,
    requirements: Vec<TypedPanicCallRequirementReport>,
) -> TypedPanicCallIssueReport {
    let TypedEvaluatedIssue {
        reference: _,
        data,
        context,
        producer: _,
    } = issue;
    let root = context.root;
    let kind = TypedPanicCallIssueKind::Duplicate {
        normalized_name: data.normalized_name().to_owned(),
    };
    let source_range = obligation
        .contract()
        .and_then(|contract| contract.source_anchor())
        .map(|anchor| source_range(anchor.data().anchor()));
    TypedPanicCallIssueReport {
        root,
        kind,
        function: projected.function,
        function_path: projected.function_path.clone(),
        target: projected.target.clone(),
        source_range,
        trace: Arc::clone(&projected.trace),
        missing_requirements: Vec::new(),
        requirements,
    }
}

fn project_witness(
    obligation: &PanicCallObligation,
    trace: Arc<PanicCallSemanticTrace>,
) -> Result<ProjectedCallWitness, TypedPanicCallEvaluationError> {
    let terminal_step = trace
        .steps()
        .last()
        .ok_or_else(|| invalid("trace", "semantic trace is empty"))?;
    if !matches!(
        terminal_step.kind(),
        PanicCallSemanticTraceStepKind::TerminalCall
    ) {
        return Err(invalid("trace", "last semantic step is not terminal"));
    }
    let function = function_id(*terminal_step.owner().data().key());
    let function_path = terminal_step.owner().data().display_path().to_owned();
    let target = if let Some(callable) = trace.terminal().presentation_callable() {
        TypedPanicCallTargetReport {
            function: Some(function_id(*callable.data().key())),
            path: callable.data().display_path().to_owned(),
        }
    } else {
        TypedPanicCallTargetReport {
            function: None,
            path: trace
                .terminal()
                .presentation()
                .semantic_description()
                .ok_or_else(|| invalid("trace", "description presentation has no semantic text"))?
                .to_owned(),
        }
    };
    let recorded_source = trace
        .terminal()
        .source_anchors()
        .iter()
        .find(|anchor| anchor.role() == CallSourceAnchorRole::Presentation)
        .map(|anchor| source_range(anchor.key()));
    let requirements = project_requirements(obligation)?;
    Ok(ProjectedCallWitness {
        function,
        function_path,
        target,
        recorded_source,
        trace,
        requirements,
    })
}

fn project_requirements(
    obligation: &PanicCallObligation,
) -> Result<ProjectedRequirements, TypedPanicCallEvaluationError> {
    if matches!(
        obligation.requirements(),
        [PanicCallRequirementValue::Unnamed]
    ) {
        return Ok(ProjectedRequirements::Unnamed);
    }
    let mut reports = Vec::with_capacity(obligation.requirements().len());
    for (expected, requirement) in obligation.requirements().iter().enumerate() {
        let expected = u32::try_from(expected)
            .map_err(|_| invalid("obligation", "requirement ordinal exceeds u32"))?;
        let PanicCallRequirementValue::Named { ordinal, .. } = requirement else {
            return Err(invalid(
                "obligation",
                "unnamed and named requirement forms are mixed",
            ));
        };
        if *ordinal != expected {
            return Err(invalid(
                "obligation",
                "named requirements are not dense and declaration ordered",
            ));
        }
        reports.push(requirement_report(requirement));
    }
    Ok(ProjectedRequirements::Named(reports))
}

fn requirement_report(requirement: &PanicCallRequirementValue) -> TypedPanicCallRequirementReport {
    match requirement {
        PanicCallRequirementValue::Unnamed => unreachable!("unnamed requirements are not public"),
        PanicCallRequirementValue::Named {
            name,
            condition,
            source_anchor,
            ..
        } => TypedPanicCallRequirementReport {
            name: name.clone(),
            condition: condition.clone(),
            source_range: source_anchor
                .as_deref()
                .map(|anchor| source_range(anchor.data().anchor())),
        },
    }
}

fn requirement_name_normalized(name: &str) -> String {
    crate::contracts::normalize_requirement_name(name)
}

fn function_id(function: FunctionKey) -> FunctionId {
    function.instance().map_or_else(
        || FunctionId::generic(function.definition()),
        |instance| FunctionId::exact(function.definition(), instance),
    )
}

pub(super) fn adapt_typed_panic_call_reports(
    sources: &impl FindingSources,
    reports: Vec<TypedPanicCallRootReport>,
    roots: &[InterpretationRoot],
    show_full_stack_trace: bool,
) -> Result<Vec<Finding>, TypedPanicCallEvaluationError> {
    validate_report_roots(&reports, roots)?;
    let capacity = reports.iter().map(|report| report.issues.len()).sum();
    let mut findings = Vec::with_capacity(capacity);
    for report in reports {
        let root = InterpretationRoot {
            function: report.function,
            path: report.path.clone(),
            kind: report.kind,
        };
        for issue in report.issues {
            let finding = interpreted_finding(&issue)?;
            findings.push(adapt_typed_panic_call_finding(
                sources,
                &root,
                &finding,
                show_full_stack_trace,
            ));
        }
    }
    Ok(findings)
}

fn validate_report_roots(
    reports: &[TypedPanicCallRootReport],
    roots: &[InterpretationRoot],
) -> Result<(), TypedPanicCallEvaluationError> {
    if reports.len() != roots.len() {
        return Err(invalid(
            "report batch",
            format!(
                "returned {} roots for {} requests",
                reports.len(),
                roots.len()
            ),
        ));
    }
    for (index, (report, root)) in reports.iter().zip(roots).enumerate() {
        if report.function != root.function || report.path != root.path || report.kind != root.kind
        {
            return Err(invalid(
                "root report",
                format!("report {index} does not match its requested root"),
            ));
        }
        for issue in &report.issues {
            if issue.root != report.root {
                return Err(invalid(
                    "issue report",
                    format!("an issue under root report {index} belongs to another root"),
                ));
            }
        }
    }
    Ok(())
}

fn interpreted_finding(
    report: &TypedPanicCallIssueReport,
) -> Result<InterpretedFinding, TypedPanicCallEvaluationError> {
    let kind = match &report.kind {
        TypedPanicCallIssueKind::Unsatisfied { boundary } => match boundary {
            PanicCallBoundaryKind::PanicSink => InterpretedFindingKind::PanicSink,
            PanicCallBoundaryKind::Documented { trusted } => {
                InterpretedFindingKind::DocumentedPanic { trusted: *trusted }
            }
            PanicCallBoundaryKind::Opaque { .. } => InterpretedFindingKind::OpaquePanicBoundary {
                description: report
                    .trace
                    .terminal()
                    .boundary_description()
                    .ok_or_else(|| {
                        invalid("issue report", "opaque boundary description is missing")
                    })?
                    .to_owned(),
            },
        },
        TypedPanicCallIssueKind::Duplicate { normalized_name } => {
            InterpretedFindingKind::AmbiguousPanicRequirement {
                normalized_name: normalized_name.clone(),
            }
        }
    };
    Ok(InterpretedFinding {
        kind,
        function: report.function,
        function_path: report.function_path.clone(),
        target: Some(InterpretedTarget {
            function: report.target.function,
            path: report.target.path.clone(),
        }),
        source_range: report.source_range.clone(),
        trace: interpreted_trace(&report.trace)?,
        missing_requirements: report
            .missing_requirements
            .iter()
            .map(interpreted_requirement)
            .collect(),
        requirements: report
            .requirements
            .iter()
            .map(interpreted_requirement)
            .collect(),
    })
}

fn interpreted_requirement(requirement: &TypedPanicCallRequirementReport) -> ContractRequirementIr {
    ContractRequirementIr {
        name: requirement.name.clone(),
        condition: requirement.condition.clone(),
        source_range: requirement.source_range.clone(),
    }
}

fn interpreted_trace(
    trace: &PanicCallSemanticTrace,
) -> Result<InterpretedTrace, TypedPanicCallEvaluationError> {
    let steps = trace
        .steps()
        .iter()
        .map(|step| {
            let (caller, caller_path) = semantic_node_identity(step.caller()).ok_or_else(|| {
                invalid("trace", "a semantic description cannot be a trace caller")
            })?;
            let (target, target_path) = semantic_target(step.target());
            let call = match step.kind() {
                PanicCallSemanticTraceStepKind::Macro {
                    occurrence_data, ..
                } => occurrence_data.key().local_id(),
                PanicCallSemanticTraceStepKind::FollowedCall(followed) => {
                    followed.occurrence_data().key().local_id()
                }
                PanicCallSemanticTraceStepKind::TerminalCall => {
                    trace.endpoint_data().key().local_id()
                }
            };
            Ok(InterpretedTraceStep {
                caller,
                caller_path,
                call: CallId::new(call),
                kind: InterpretedTraceStepKind::Reachability(match step.edge() {
                    PanicCallSemanticEdge::MacroExpansion => CallEdgeKindIr::MacroExpansion,
                    PanicCallSemanticEdge::Call(kind) => call_edge_kind(kind),
                }),
                source_range: step.source_key().map(source_range),
                target,
                target_path: Some(target_path),
            })
        })
        .collect::<Result<Vec<_>, TypedPanicCallEvaluationError>>()?;
    Ok(InterpretedTrace { steps })
}

fn semantic_node_identity(node: &PanicCallTraceNode) -> Option<(FunctionId, String)> {
    match node {
        PanicCallTraceNode::Function { data, .. } => {
            Some((function_id(*data.key()), data.display_path().to_owned()))
        }
        PanicCallTraceNode::Macro { data, .. } => Some((
            FunctionId::generic(data.macro_definition()),
            format!("macro {}", data.display_path()),
        )),
        PanicCallTraceNode::Callable(callable) => Some((
            function_id(*callable.data().key()),
            callable.data().display_path().to_owned(),
        )),
        PanicCallTraceNode::Description(_) => None,
    }
}

fn semantic_target(node: &PanicCallTraceNode) -> (Option<FunctionId>, String) {
    semantic_node_identity(node).map_or_else(
        || {
            let PanicCallTraceNode::Description(description) = node else {
                unreachable!("non-description semantic nodes have stable identities")
            };
            (None, description.clone())
        },
        |(function, path)| (Some(function), path),
    )
}

const fn call_edge_kind(kind: CallKind) -> CallEdgeKindIr {
    match kind {
        CallKind::DirectCall => CallEdgeKindIr::DirectCall,
        CallKind::TailCall => CallEdgeKindIr::TailCall,
        CallKind::FnPointerReify => CallEdgeKindIr::FnPointerReify,
        CallKind::ClosureFnPointerReify => CallEdgeKindIr::ClosureFnPointerReify,
        CallKind::FnPointerCallTarget => CallEdgeKindIr::FnPointerCallTarget,
        CallKind::DynObjectCast => CallEdgeKindIr::DynObjectCast,
        CallKind::VTableEntry => CallEdgeKindIr::VTableEntry,
        CallKind::DynDispatchVTableEntry => CallEdgeKindIr::DynDispatchVTableEntry,
        CallKind::MacroExpansion => CallEdgeKindIr::MacroExpansion,
        CallKind::ConstBody => CallEdgeKindIr::ConstBody,
        CallKind::CoroutineBody => CallEdgeKindIr::CoroutineBody,
        CallKind::Assert => CallEdgeKindIr::Assert,
        CallKind::IndirectCall => CallEdgeKindIr::IndirectCall,
    }
}

fn invalid(subject: impl Into<String>, reason: impl Into<String>) -> TypedPanicCallEvaluationError {
    TypedPanicCallEvaluationError::InvalidProjection {
        subject: subject.into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
fn evaluate_typed_panic_call_with_dependencies<'a>(
    local: TypedPanicLocalArtifact<'_>,
    dependencies: impl IntoIterator<Item = &'a ArtifactAnalysisCache>,
    active_runtime_artifacts: &[RustcArtifactId],
    root: &InterpretationRoot,
    config: &SniffTestConfig,
) -> RootTypedPanicCallEvaluation {
    let dependencies = dependencies.into_iter().collect::<Vec<_>>();
    let direct_dependencies = dependencies
        .iter()
        .map(|dependency| dependency.artifact.id.clone())
        .collect();
    let mut reports = evaluate_typed_panic_call_roots(
        local,
        &dependencies,
        direct_dependencies,
        active_runtime_artifacts,
        std::slice::from_ref(root),
        config,
    )?
    .roots;
    Ok(reports
        .pop()
        .expect("one root request produces one typed panic-call report"))
}

#[cfg(test)]
fn evaluate_typed_panic_call_with_projection_fixture<'a>(
    local: TypedPanicLocalArtifact<'_>,
    dependencies: impl IntoIterator<Item = &'a ArtifactAnalysisCache>,
    active_runtime_artifacts: &[RustcArtifactId],
    root: &InterpretationRoot,
    config: &SniffTestConfig,
) -> Result<
    (TypedPanicCallRootReport, TypedPanicCallProjectionFixture),
    TypedPanicCallEvaluationError,
> {
    let dependencies = dependencies.into_iter().collect::<Vec<_>>();
    let direct_dependencies = dependencies
        .iter()
        .map(|dependency| dependency.artifact.id.clone())
        .collect();
    let mut projection_fixture = None;
    let mut reports = evaluate_typed_panic_call_roots_inner(
        local,
        &dependencies,
        direct_dependencies,
        active_runtime_artifacts,
        std::slice::from_ref(root),
        config,
        Some(&mut projection_fixture),
    )?
    .roots;
    let report = reports
        .pop()
        .expect("one root request produces one typed panic-call report");
    let projection_fixture = projection_fixture.ok_or_else(|| {
        invalid(
            "test projection fixture",
            "single-root evaluation did not expose its pre-projection rows",
        )
    })?;
    Ok((report, projection_fixture))
}

#[cfg(test)]
mod tests;
