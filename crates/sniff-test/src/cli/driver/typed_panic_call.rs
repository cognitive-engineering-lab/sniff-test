//! Unified permanent typed-panic production authority and report-v14 projection.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use crate::analysis::cache::{ArtifactAnalysisCache, RustcArtifactId};
use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
use crate::analysis::facts::composition::{
    CompositionRelationBuilder, WorkspaceEvaluationView, WorkspaceRelationIndex,
    WorkspaceRelationRef,
};
#[cfg(test)]
use crate::analysis::facts::evaluation::DomainId;
use crate::analysis::facts::evaluation::{
    EvaluationDb, EvaluationIssueContext, EvaluationRoot, RelationTrace, TypedDerivedRow,
    TypedEvaluatedIssue,
};
use crate::analysis::facts::evidence::{
    AmbiguousEvidenceReuseIssue, EvidenceCoordinatorPack, EvidenceUseRecord, canonical_evidence_use,
};
use crate::analysis::facts::human::HumanEvidencePack;
#[cfg(test)]
use crate::analysis::facts::human::markers::MarkerOccurrenceHasClaim;
use crate::analysis::facts::human::markers::{
    CallOccurrenceHasMarkerClaimCandidate, EffectSiteHasMarkerClaimCandidate,
    FunctionHasMarkerClaimCandidate, MarkerClaimEntity, MarkerOccurrenceEntity,
    MarkerOccurrenceHasSourceAnchor, UnsafeOperationHasMarkerClaimCandidate,
};
use crate::analysis::facts::pack::{AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::panic::model::{MirAssertFact, UnsatisfiedCompilerAssertIssue};
use crate::analysis::facts::panic::rules::{PanicPack, panic_domain};
use crate::analysis::facts::panic::{
    CompilerAssertInputPack, CompilerAssertRootInputs, CompilerAssertSemanticEdge,
    CompilerAssertSemanticNodeRole, CompilerAssertSemanticTrace, CompilerAssertTraceError,
    CompilerAssertTraceProjector, DuplicatePanicCallRequirementIssue,
    DuplicatePanicRootRequirementIssue, PanicAnalysisIncompleteIssue, PanicCallBoundaryKind,
    PanicCallEvidenceMatch, PanicCallInputKind, PanicCallInputPack, PanicCallObligation,
    PanicCallOpaqueKind, PanicCallRequirementMatchId, PanicCallRequirementValue,
    PanicCallResolution, PanicCallSemanticEdge, PanicCallSemanticTrace,
    PanicCallSemanticTraceStepKind, PanicCallTargetAuthority, PanicCallTraceError,
    PanicCallTraceNode, PanicCallTraceProjector, PanicCallableResolutionKind,
    PanicCompletenessOutcome, PanicCompletenessPack, PanicCompletenessReason,
    PanicIncompleteReason, PanicOpaqueBoundaryKind, PanicRootContractPack, PanicRootInputs,
    PreparedCompilerAssertRootBatch, UnsatisfiedPanicCallIssue, compiler_assert_presentation,
    expected_duplicate_panic_call_requirement_issues, expected_matches_from_obligations,
    expected_unsatisfied_panic_call_issues, root_contract, root_contract_boundary,
};
use crate::analysis::facts::program::root_traversal::{CallTargetSelection, ProgramCallResolution};
#[cfg(test)]
use crate::analysis::facts::program::topology::CallableEntity;
use crate::analysis::facts::program::topology::{
    CallKind, CallOccurrenceEntity, CallSourceAnchorRole,
};
use crate::analysis::facts::program::workspace_index::WorkspaceProgramIndexError;
use crate::analysis::facts::program::{
    EffectSiteEntity, EffectSiteKey, FunctionEntity, FunctionKey, SourceAnchorEntity,
};
use crate::analysis::facts::safety::operations::UnsafeOperationEntity;
use crate::analysis::facts::schema::{PassId, RowSchema};
use crate::analysis::facts::workspace::{
    ArtifactScopeId, ScopedEntityRef, ScopedRowRef, WorkspaceFactView,
};
use crate::analysis::findings::{
    IncompleteReason, InterpretationRoot, InterpretedFinding, InterpretedFindingKind,
    InterpretedTarget, InterpretedTrace, InterpretedTraceStep, InterpretedTraceStepKind,
};
use crate::analysis::ir::{
    CallEdgeKindIr, CallId, ContractRequirementIr, FunctionId, SourceFileIr, SourceRangeIr,
};
use crate::analysis::workspace_closure::{ManagedArtifactManifest, VerifiedWorkspaceClosure};
use crate::cli::driver::interpretation::{
    FindingSources, adapt_typed_panic_ambiguity_finding, adapt_typed_panic_call_finding,
    adapt_typed_panic_incomplete_finding,
};
use crate::cli::findings::Finding;
use crate::config::SniffTestConfig;
use crate::report_roots::ReportRootKind;

use super::typed_panic::{
    FunctionPresentationIndex, TypedPanicEvaluationError, TypedPanicLocalArtifact,
    TypedPanicRootReport, compiler_assert_root_request, open_typed_artifacts,
    permanent_source_files, project_compiler_assert_root_report, source_range,
};

const EMIT_PANIC_CALL_INPUTS_RULE: &str = "sniff-test.panic.emit-call-inputs";
const REPORT_UNSATISFIED_PANIC_CALLS_RULE: &str =
    "sniff-test.panic.report-unsatisfied-call-obligations";
const REPORT_DUPLICATE_PANIC_CALL_REQUIREMENTS_RULE: &str =
    "sniff-test.panic.report-duplicate-call-requirements";
const REPORT_DUPLICATE_PANIC_ROOT_REQUIREMENTS_RULE: &str =
    "sniff-test.panic.report-duplicate-root-requirements";
const EMIT_PANIC_COMPLETENESS_RULE: &str = "sniff-test.panic.emit-completeness";
const REPORT_PANIC_INCOMPLETE_RULE: &str = "sniff-test.panic.report-incomplete";
const MATCH_COMPILER_ASSERT_EVIDENCE_RULE: &str = "sniff-test.panic.match-assert-evidence";
const MATCH_PANIC_CALL_EVIDENCE_RULE: &str = "sniff-test.panic.match-call-evidence";
const DETECT_EVIDENCE_REUSE_RULE: &str = "sniff-test.evidence.detect-reuse";

#[derive(Debug)]
pub(super) enum TypedPanicCallEvaluationError {
    Base(TypedPanicEvaluationError),
    RootPreparation(Box<WorkspaceProgramIndexError>),
    Trace(Box<PanicCallTraceError>),
    CompilerTrace(Box<CompilerAssertTraceError>),
    InvalidProjection { subject: String, reason: String },
}

impl Display for TypedPanicCallEvaluationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base(source) => Display::fmt(source, formatter),
            Self::RootPreparation(source) => {
                write!(formatter, "typed panic root preparation failed: {source}")
            }
            Self::Trace(source) => write!(
                formatter,
                "typed panic-call semantic trace projection failed: {source}"
            ),
            Self::CompilerTrace(source) => write!(
                formatter,
                "typed compiler-assert semantic trace projection failed: {source}"
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
            Self::RootPreparation(source) => Some(source),
            Self::Trace(source) => Some(source),
            Self::CompilerTrace(source) => Some(source),
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
    prepared_root_bindings: Vec<TypedPanicPreparedRootBinding>,
    pub(super) root_preparations: Vec<TypedPanicRootPreparationReport>,
    pub(super) compiler_asserts: Vec<TypedPanicRootReport>,
    pub(super) roots: Vec<TypedPanicCallRootReport>,
    pub(super) root_contracts: Vec<TypedPanicRootContractRootReport>,
    pub(super) completeness: Vec<TypedPanicCompletenessRootReport>,
    pub(super) ambiguities: Vec<TypedPanicAmbiguityRootReport>,
    pub(super) source_files: Vec<SourceFileIr>,
    pub(super) function_ranges: BTreeMap<FunctionId, SourceRangeIr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TypedPanicPreparedRootBinding {
    root: EvaluationRoot,
    selected_function: FunctionKey,
    selected_path: String,
}

/// Source-free proof that every sparse authority lane is aligned and every
/// fallible call DTO has already been converted exactly once.
pub(super) struct TypedPanicCallBatchPreflight {
    pub(super) ready_roots: Vec<InterpretationRoot>,
    pub(super) call_findings: Vec<Vec<InterpretedFinding>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TypedPanicRootPreparationReport {
    pub(super) request_ordinal: usize,
    pub(super) request: InterpretationRoot,
    pub(super) expected_scope: ArtifactScopeId,
    pub(super) requested_function: FunctionKey,
    pub(super) outcome: TypedPanicRootPreparationOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum TypedPanicRootPreparationOutcome {
    Evaluatable {
        report_index: usize,
        root: EvaluationRoot,
        selected_function: FunctionKey,
    },
    Missing {
        reason: IncompleteReason,
    },
}

#[derive(Debug)]
struct PendingTypedPanicRootPreparation {
    request_ordinal: usize,
    request: InterpretationRoot,
    expected_scope: ArtifactScopeId,
    requested_function: FunctionKey,
    outcome: PendingTypedPanicRootPreparationOutcome,
}

#[derive(Debug)]
enum PendingTypedPanicRootPreparationOutcome {
    Evaluatable {
        report_index: usize,
        selected_function: FunctionKey,
    },
    Missing {
        reason: IncompleteReason,
    },
}

#[derive(Clone, Debug)]
pub(super) struct TypedPanicRootContractRootReport {
    pub(super) root: EvaluationRoot,
    pub(super) function: FunctionId,
    pub(super) path: String,
    pub(super) kind: ReportRootKind,
    pub(super) selected_function: Option<FunctionId>,
    pub(super) selected_path: Option<String>,
    pub(super) issues: Vec<TypedPanicRootContractIssueReport>,
}

#[derive(Clone, Debug)]
pub(super) struct TypedPanicRootContractIssueReport {
    pub(super) root: EvaluationRoot,
    pub(super) function: FunctionId,
    pub(super) function_path: String,
    pub(super) source_range: Option<SourceRangeIr>,
    pub(super) normalized_name: String,
    pub(super) requirements: Vec<TypedPanicCallRequirementReport>,
}

#[derive(Clone, Debug)]
pub(super) struct TypedPanicAmbiguityRootReport {
    pub(super) root: EvaluationRoot,
    pub(super) function: FunctionId,
    pub(super) path: String,
    pub(super) kind: ReportRootKind,
    pub(super) issues: Vec<TypedPanicAmbiguityIssueReport>,
}

#[derive(Clone, Debug)]
pub(super) struct TypedPanicAmbiguityIssueReport {
    pub(super) root: EvaluationRoot,
    pub(super) function: FunctionId,
    pub(super) function_path: String,
    pub(super) source_range: Option<SourceRangeIr>,
    pub(super) trace: InterpretedTrace,
    pub(super) effect_count: usize,
}

#[derive(Clone, Debug)]
pub(super) struct TypedPanicCompletenessRootReport {
    pub(super) root: EvaluationRoot,
    pub(super) function: FunctionId,
    pub(super) path: String,
    pub(super) kind: ReportRootKind,
    pub(super) issues: Vec<TypedPanicCompletenessIssueReport>,
}

#[derive(Clone, Debug)]
pub(super) struct TypedPanicCompletenessIssueReport {
    pub(super) root: EvaluationRoot,
    pub(super) traversal_order: u64,
    pub(super) reason: IncompleteReason,
}

#[derive(Clone, Debug)]
pub(super) struct TypedPanicCallRootReport {
    pub(super) root: EvaluationRoot,
    pub(super) function: FunctionId,
    pub(super) path: String,
    pub(super) kind: ReportRootKind,
    pub(super) issues: Vec<TypedPanicCallIssueReport>,
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct TypedPanicCallProjectionFixture {
    inputs: PanicRootInputs,
    obligations: Vec<TypedDerivedRow<PanicCallObligation>>,
    matches: Vec<TypedDerivedRow<PanicCallEvidenceMatch>>,
    unsatisfied: Vec<TypedEvaluatedIssue<UnsatisfiedPanicCallIssue>>,
    duplicates: Vec<TypedEvaluatedIssue<DuplicatePanicCallRequirementIssue>>,
    completeness: Vec<TypedDerivedRow<PanicCompletenessOutcome>>,
    incomplete: Vec<TypedEvaluatedIssue<PanicAnalysisIncompleteIssue>>,
    evidence_uses: Vec<TypedDerivedRow<EvidenceUseRecord>>,
    ambiguities: Vec<TypedEvaluatedIssue<AmbiguousEvidenceReuseIssue>>,
    root_contract_duplicates: Vec<TypedEvaluatedIssue<DuplicatePanicRootRequirementIssue>>,
    root_contract_callable_keys: Option<(FunctionKey, FunctionKey)>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
enum AmbiguityProjectionCorruption {
    EvidenceMissing,
    EvidenceDuplicate,
    EvidenceOrphan,
    EvidenceNonmatchingClaim,
    EvidenceProducer,
    IssueMissing,
    IssueDuplicate,
    IssueOrphan,
    IssueProducer,
    IssueRoot,
    IssueDomain,
    IssueSourceContext,
    IssueEndpointContext,
    IssueTraceContext,
    IssueWitnessSource,
    IssueWitnessEndpoint,
    IssueWitnessOrder,
    IssueGroups,
    ActivationRoot,
    ActivationUnsupportedFinalRelation,
}

#[cfg(test)]
type ProjectionCapture<'a> = Option<&'a mut Option<TypedPanicCallProjectionFixture>>;
#[cfg(not(test))]
struct ProjectionCapture<'a>(std::marker::PhantomData<&'a mut ()>);

#[cfg(test)]
type AmbiguityProjectionHook = Option<AmbiguityProjectionCorruption>;
#[cfg(not(test))]
#[derive(Clone, Copy)]
struct AmbiguityProjectionHook;

fn no_projection_capture<'a>() -> ProjectionCapture<'a> {
    #[cfg(test)]
    {
        None
    }
    #[cfg(not(test))]
    {
        ProjectionCapture(std::marker::PhantomData)
    }
}

fn no_ambiguity_projection_hook() -> AmbiguityProjectionHook {
    #[cfg(test)]
    {
        None
    }
    #[cfg(not(test))]
    {
        AmbiguityProjectionHook
    }
}

#[cfg(test)]
#[allow(
    clippy::too_many_lines,
    reason = "the hostile test seam enumerates every independent ambiguity row boundary"
)]
fn corrupt_ambiguity_rows(
    corruption: AmbiguityProjectionCorruption,
    root: &EvaluationRoot,
    obligations: &[TypedDerivedRow<PanicCallObligation>],
    evidence_uses: &mut Vec<TypedDerivedRow<EvidenceUseRecord>>,
    issues: &mut Vec<TypedEvaluatedIssue<AmbiguousEvidenceReuseIssue>>,
) -> Result<(), TypedPanicCallEvaluationError> {
    let first_use = || {
        evidence_uses
            .first()
            .cloned()
            .ok_or_else(|| invalid("test ambiguity corruption", "fixture has no evidence use"))
    };
    let first_issue = || {
        issues.first().cloned().ok_or_else(|| {
            invalid(
                "test ambiguity corruption",
                "fixture has no ambiguity issue",
            )
        })
    };
    match corruption {
        AmbiguityProjectionCorruption::EvidenceMissing => {
            evidence_uses.pop();
        }
        AmbiguityProjectionCorruption::EvidenceDuplicate => {
            evidence_uses.push(first_use()?);
        }
        AmbiguityProjectionCorruption::EvidenceOrphan => {
            let mut row = first_use()?;
            let usage = &row.data;
            row.data = EvidenceUseRecord::new(
                usage.domain().clone(),
                usage.claim().clone(),
                usage.endpoint().clone(),
                root.entity.clone(),
                usage.source().clone(),
                usage.trace().clone(),
                usage.witness_order(),
                usage.semantic_order().clone(),
            );
            evidence_uses.push(row);
        }
        AmbiguityProjectionCorruption::EvidenceNonmatchingClaim => {
            let (obligation, marker) = obligations
                .iter()
                .find_map(|row| {
                    row.data
                        .active_markers()
                        .iter()
                        .find(|marker| marker.data().key().source_ordinal() == 2)
                        .map(|marker| (&row.data, marker))
                })
                .ok_or_else(|| {
                    invalid(
                        "test ambiguity corruption",
                        "fixture has no active source-ordinal-two marker claim",
                    )
                })?;
            let mut row = evidence_uses
                .iter()
                .find(|row| {
                    row.data.source() == obligation.source()
                        && row.data.witness_order() == obligation.call_id()
                })
                .cloned()
                .ok_or_else(|| {
                    invalid(
                        "test ambiguity corruption",
                        "fixture obligation has no matching evidence-use template",
                    )
                })?;
            let usage = &row.data;
            row.data = EvidenceUseRecord::new(
                usage.domain().clone(),
                marker.claim().clone(),
                obligation.endpoint().clone(),
                obligation.evidence_group().clone(),
                obligation.source().clone(),
                obligation.trace().clone(),
                obligation.call_id(),
                usage.semantic_order().clone(),
            );
            evidence_uses.push(row);
        }
        AmbiguityProjectionCorruption::EvidenceProducer => {
            evidence_uses
                .first_mut()
                .ok_or_else(|| invalid("test ambiguity corruption", "fixture has no evidence use"))?
                .producer = PassId::new("hostile.evidence-producer").unwrap();
        }
        AmbiguityProjectionCorruption::IssueMissing => {
            issues.pop();
        }
        AmbiguityProjectionCorruption::IssueDuplicate => {
            issues.push(first_issue()?);
        }
        AmbiguityProjectionCorruption::IssueOrphan => {
            let mut issue = first_issue()?;
            issue.data = AmbiguousEvidenceReuseIssue::new_for_report_test(
                issue.data.domain().clone(),
                root.entity.clone(),
                issue.data.witness_source().clone(),
                issue.data.witness_endpoint().clone(),
                issue.data.witness_order(),
                issue.data.groups().to_vec(),
            );
            issue.context.source = Some(root.entity.as_row());
            issues.push(issue);
        }
        AmbiguityProjectionCorruption::IssueProducer => {
            issues
                .first_mut()
                .ok_or_else(|| invalid("test ambiguity corruption", "fixture has no issue"))?
                .producer = PassId::new("hostile.issue-producer").unwrap();
        }
        AmbiguityProjectionCorruption::IssueRoot => {
            issues
                .first_mut()
                .ok_or_else(|| invalid("test ambiguity corruption", "fixture has no issue"))?
                .context
                .root
                .domain = DomainId::new("hostile.panic").unwrap();
        }
        AmbiguityProjectionCorruption::IssueDomain
        | AmbiguityProjectionCorruption::IssueWitnessSource
        | AmbiguityProjectionCorruption::IssueWitnessEndpoint
        | AmbiguityProjectionCorruption::IssueWitnessOrder
        | AmbiguityProjectionCorruption::IssueGroups => {
            let issue = issues
                .first_mut()
                .ok_or_else(|| invalid("test ambiguity corruption", "fixture has no issue"))?;
            let domain = if matches!(corruption, AmbiguityProjectionCorruption::IssueDomain) {
                DomainId::new("hostile.panic").unwrap()
            } else {
                issue.data.domain().clone()
            };
            let witness_source = if matches!(
                corruption,
                AmbiguityProjectionCorruption::IssueWitnessSource
            ) {
                issue.data.marker().as_row()
            } else {
                issue.data.witness_source().clone()
            };
            let witness_endpoint = if matches!(
                corruption,
                AmbiguityProjectionCorruption::IssueWitnessEndpoint
            ) {
                root.entity.clone()
            } else {
                issue.data.witness_endpoint().clone()
            };
            let witness_order = issue.data.witness_order()
                + u64::from(matches!(
                    corruption,
                    AmbiguityProjectionCorruption::IssueWitnessOrder
                ));
            let groups = if matches!(corruption, AmbiguityProjectionCorruption::IssueGroups) {
                issue.data.groups()[..1].to_vec()
            } else {
                issue.data.groups().to_vec()
            };
            issue.data = AmbiguousEvidenceReuseIssue::new_for_report_test(
                domain,
                issue.data.marker().clone(),
                witness_source,
                witness_endpoint,
                witness_order,
                groups,
            );
        }
        AmbiguityProjectionCorruption::IssueSourceContext => {
            issues
                .first_mut()
                .ok_or_else(|| invalid("test ambiguity corruption", "fixture has no issue"))?
                .context
                .source = None;
        }
        AmbiguityProjectionCorruption::IssueEndpointContext => {
            issues
                .first_mut()
                .ok_or_else(|| invalid("test ambiguity corruption", "fixture has no issue"))?
                .context
                .endpoint = None;
        }
        AmbiguityProjectionCorruption::IssueTraceContext => {
            issues
                .first_mut()
                .ok_or_else(|| invalid("test ambiguity corruption", "fixture has no issue"))?
                .context
                .trace = None;
        }
        AmbiguityProjectionCorruption::ActivationRoot
        | AmbiguityProjectionCorruption::ActivationUnsupportedFinalRelation => {}
    }
    Ok(())
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
    pub(super) ordinal: u32,
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
        no_projection_capture(),
        no_ambiguity_projection_hook(),
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
    #[allow(unused_mut, unused_variables)] mut projection_capture: ProjectionCapture<'_>,
    ambiguity_corruption: AmbiguityProjectionHook,
) -> Result<TypedPanicCallBatchReport, TypedPanicCallEvaluationError> {
    if roots.is_empty() {
        return Ok(TypedPanicCallBatchReport {
            prepared_root_bindings: Vec::new(),
            root_preparations: Vec::new(),
            compiler_asserts: Vec::new(),
            roots: Vec::new(),
            root_contracts: Vec::new(),
            completeness: Vec::new(),
            ambiguities: Vec::new(),
            source_files: Vec::new(),
            function_ranges: BTreeMap::new(),
        });
    }
    let registry = typed_panic_authority_registry()
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
    let expected_scope = closure.root_scope().clone();
    closure
        .program()
        .validate_workspace(&workspace)
        .map_err(|source| TypedPanicCallEvaluationError::RootPreparation(Box::new(source)))?;
    let local_stable_crate_id = closure
        .program()
        .stable_crate_id(&expected_scope)
        .map_err(|source| TypedPanicCallEvaluationError::RootPreparation(Box::new(source)))?;
    let mut pending_root_preparations = Vec::with_capacity(roots.len());
    let mut ready_request_ordinals = Vec::with_capacity(roots.len());
    let mut ready_requests = Vec::with_capacity(roots.len());
    for (request_ordinal, request) in roots.iter().enumerate() {
        let requested_function = FunctionKey::new(
            request.function.def_path_hash,
            request.function.instance_hash,
        );
        if requested_function.definition().stable_crate_id() != local_stable_crate_id {
            return Err(TypedPanicCallEvaluationError::RootPreparation(Box::new(
                WorkspaceProgramIndexError::InvalidQuery {
                    reason: format!(
                        "request {request_ordinal} names stable crate {:016x}, not local stable crate {local_stable_crate_id:016x}",
                        requested_function.definition().stable_crate_id()
                    ),
                },
            )));
        }
        let candidates = closure
            .program()
            .body_candidates(&expected_scope, &requested_function)
            .map_err(|source| TypedPanicCallEvaluationError::RootPreparation(Box::new(source)))?;
        let outcome = if let Some(selected) = candidates.first() {
            let report_index = ready_requests.len();
            ready_request_ordinals.push(request_ordinal);
            ready_requests.push(compiler_assert_root_request(request, config));
            PendingTypedPanicRootPreparationOutcome::Evaluatable {
                report_index,
                selected_function: *selected.body().data().key(),
            }
        } else {
            PendingTypedPanicRootPreparationOutcome::Missing {
                reason: IncompleteReason::MissingBody {
                    function: request.function,
                    path: request.path.clone(),
                    source_range: None,
                    trace: InterpretedTrace { steps: Vec::new() },
                },
            }
        };
        pending_root_preparations.push(PendingTypedPanicRootPreparation {
            request_ordinal,
            request: request.clone(),
            expected_scope: expected_scope.clone(),
            requested_function,
            outcome,
        });
    }
    let prepared_roots = if ready_requests.is_empty() {
        let probe = compiler_assert_root_request(&pending_root_preparations[0].request, config);
        match PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &config.panics,
            &config.documentation.overrides,
            [probe],
        ) {
            Err(crate::analysis::facts::panic::CompilerAssertInputError::Traversal(source))
                if matches!(
                    source.as_ref(),
                    crate::analysis::facts::program::root_traversal::RootProgramTraversalError::UnknownRoot { scope, function }
                        if scope == &expected_scope
                            && function == &pending_root_preparations[0].requested_function
                ) =>
            {
                Vec::new()
            }
            Err(source) => {
                return Err(TypedPanicEvaluationError::Input(Box::new(source)).into());
            }
            Ok(_) => {
                return Err(invalid(
                    "root preparation",
                    "the all-missing core validation probe unexpectedly resolved",
                ));
            }
        }
    } else {
        PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &config.panics,
            &config.documentation.overrides,
            ready_requests,
        )
        .map_err(|source| TypedPanicEvaluationError::Input(Box::new(source)))?
        .into_roots()
    };
    if prepared_roots.len() != ready_request_ordinals.len() {
        return Err(TypedPanicEvaluationError::PreparedRootCount {
            expected: ready_request_ordinals.len(),
            actual: prepared_roots.len(),
        }
        .into());
    }
    let mut prepared_root_bindings = Vec::with_capacity(prepared_roots.len());
    for (report_index, prepared) in prepared_roots.iter().enumerate() {
        let request_ordinal = ready_request_ordinals[report_index];
        let PendingTypedPanicRootPreparationOutcome::Evaluatable {
            selected_function, ..
        } = &pending_root_preparations[request_ordinal].outcome
        else {
            unreachable!("ready request ordinals refer only to evaluatable roots");
        };
        let selected = workspace
            .entity::<FunctionEntity>(&prepared.root().entity)
            .map_err(|source| TypedPanicEvaluationError::Workspace(Box::new(source)))?;
        if selected.key() != selected_function {
            return Err(invalid(
                "root preparation",
                format!(
                    "prepared root {report_index} selected a different body than the first workspace candidate"
                ),
            ));
        }
        prepared_root_bindings.push(TypedPanicPreparedRootBinding {
            root: prepared.root().clone(),
            selected_function: *selected_function,
            selected_path: selected.display_path().to_owned(),
        });
    }
    let root_preparations = pending_root_preparations
        .into_iter()
        .map(|preparation| {
            let outcome = match preparation.outcome {
                PendingTypedPanicRootPreparationOutcome::Evaluatable {
                    report_index,
                    selected_function,
                } => TypedPanicRootPreparationOutcome::Evaluatable {
                    report_index,
                    root: prepared_roots[report_index].root().clone(),
                    selected_function,
                },
                PendingTypedPanicRootPreparationOutcome::Missing { reason } => {
                    TypedPanicRootPreparationOutcome::Missing { reason }
                }
            };
            TypedPanicRootPreparationReport {
                request_ordinal: preparation.request_ordinal,
                request: preparation.request,
                expected_scope: preparation.expected_scope,
                requested_function: preparation.requested_function,
                outcome,
            }
        })
        .collect::<Vec<_>>();
    let presentation_anchors = FunctionPresentationIndex::build(&workspace)?;
    let function_ranges = presentation_anchors.function_ranges();
    let relation_index = WorkspaceRelationIndex::open(&workspace)
        .map_err(|source| TypedPanicEvaluationError::Relations(Box::new(source)))?;

    let roots = prepared_roots
        .into_iter()
        .zip(ready_request_ordinals)
        .map(|(root_input, request_ordinal)| {
            let request = &roots[request_ordinal];
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
            let compiler_asserts = results
                .issues::<UnsatisfiedCompilerAssertIssue>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            let obligations = results
                .derived_rows::<PanicCallObligation>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            let matches = results
                .derived_rows::<PanicCallEvidenceMatch>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            let unsatisfied = results
                .issues::<UnsatisfiedPanicCallIssue>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            let duplicates = results
                .issues::<DuplicatePanicCallRequirementIssue>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            let root_contract_duplicates = results
                .issues::<DuplicatePanicRootRequirementIssue>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            let completeness = results
                .derived_rows::<PanicCompletenessOutcome>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            let incomplete = results
                .issues::<PanicAnalysisIncompleteIssue>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            #[allow(unused_mut)]
            let mut evidence_uses = results
                .derived_rows::<EvidenceUseRecord>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            #[allow(unused_mut)]
            let mut ambiguities = results
                .issues::<AmbiguousEvidenceReuseIssue>(registry.schemas())
                .map_err(|source| TypedPanicEvaluationError::Results(Box::new(source)))?;
            #[cfg(test)]
            if let Some(corruption) = ambiguity_corruption {
                corrupt_ambiguity_rows(
                    corruption,
                    &root,
                    &obligations,
                    &mut evidence_uses,
                    &mut ambiguities,
                )?;
            }
            #[cfg(test)]
            if let Some(capture) = projection_capture.as_deref_mut() {
                let root_contract_callable_keys = root_contract_boundary(&inputs)
                    .map_err(|source| invalid("root-contract boundary", source.to_string()))?
                    .map(|boundary| {
                        let contract = root_contract(boundary).map_err(|source| {
                            invalid("root-contract boundary", source.to_string())
                        })?;
                        let declaration = workspace
                            .entity::<CallableEntity>(&contract.declaration_owner().erase())
                            .map_err(|source| {
                                TypedPanicEvaluationError::Workspace(Box::new(source))
                            })?;
                        Ok::<_, TypedPanicCallEvaluationError>((
                            *boundary.callable_data().key(),
                            *declaration.key(),
                        ))
                    })
                    .transpose()?;
                *capture = Some(TypedPanicCallProjectionFixture {
                    inputs: inputs.clone(),
                    obligations: obligations.clone(),
                    matches: matches.clone(),
                    unsatisfied: unsatisfied.clone(),
                    duplicates: duplicates.clone(),
                    completeness: completeness.clone(),
                    incomplete: incomplete.clone(),
                    evidence_uses: evidence_uses.clone(),
                    ambiguities: ambiguities.clone(),
                    root_contract_duplicates: root_contract_duplicates.clone(),
                    root_contract_callable_keys,
                });
            }
            drop(results);
            let obligations = index_obligations(&inputs, &root, obligations)?;
            let matches = validate_call_match_rows(&root, &obligations, matches)?;
            let call_projector = PanicCallTraceProjector::prepare(&inputs)
                .map_err(|source| TypedPanicCallEvaluationError::Trace(Box::new(source)))?;
            let compiler_assert_projector =
                prepare_compiler_assert_projector(inputs.compiler_asserts())?;
            let compiler_assert_report = project_compiler_assert_root_report(
                &registry,
                &opened.render_contexts,
                &presentation_anchors,
                &compiler_assert_projector,
                request,
                root.clone(),
                compiler_asserts,
            )?;
            let ambiguity_report = project_ambiguity_report(
                &inputs,
                &evaluation,
                request,
                &root,
                &obligations,
                &call_projector,
                &compiler_assert_projector,
                evidence_uses,
                ambiguities,
                ambiguity_corruption,
            )?;
            let call_report = project_root_report(
                &inputs,
                request,
                &root,
                PanicCallProjectionRows {
                    obligations: &obligations,
                    matches: &matches,
                    projector: &call_projector,
                    unsatisfied,
                    duplicates,
                },
            )?;
            let root_contract_report =
                project_root_contract_report(&inputs, request, &root, root_contract_duplicates)?;
            let completeness_report =
                project_completeness_report(&inputs, request, &root, completeness, incomplete)?;
            Ok((
                compiler_assert_report,
                call_report,
                root_contract_report,
                completeness_report,
                ambiguity_report,
            ))
        })
        .collect::<Result<Vec<_>, TypedPanicCallEvaluationError>>()?;
    let mut compiler_asserts = Vec::with_capacity(roots.len());
    let mut call_reports = Vec::with_capacity(roots.len());
    let mut root_contracts = Vec::with_capacity(roots.len());
    let mut completeness = Vec::with_capacity(roots.len());
    let mut ambiguities = Vec::with_capacity(roots.len());
    for (compiler_assert, call, root_contract, complete, ambiguity) in roots {
        compiler_asserts.push(compiler_assert);
        call_reports.push(call);
        root_contracts.push(root_contract);
        completeness.push(complete);
        ambiguities.push(ambiguity);
    }
    Ok(TypedPanicCallBatchReport {
        prepared_root_bindings,
        root_preparations,
        compiler_asserts,
        roots: call_reports,
        root_contracts,
        completeness,
        ambiguities,
        source_files,
        function_ranges,
    })
}

fn typed_panic_authority_registry()
-> Result<AnalysisRegistry<PanicRootInputs>, PackRegistrationError> {
    let mut registry = AnalysisRegistry::new();
    registry.install(&CollectedArtifactSchemaPack)?;
    registry.install(&HumanEvidencePack)?;
    registry.install(&PanicPack)?;
    registry.install(&CompilerAssertInputPack)?;
    registry.install(&PanicCallInputPack)?;
    registry.install(&PanicRootContractPack)?;
    registry.install(&PanicCompletenessPack)?;
    registry.install(&EvidenceCoordinatorPack)?;
    Ok(registry)
}

type ExpectedEvidenceUses = BTreeMap<EvidenceUseRecord, PassId>;
type AmbiguityWitnessKey = (ScopedRowRef, u64);
type MarkerActivationIndex = BTreeMap<ScopedEntityRef, RelationTrace>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AmbiguityWitnessLane {
    PanicCall,
    CompilerAssert,
}

struct AmbiguityWitnessProjection {
    lane: AmbiguityWitnessLane,
    endpoint: ScopedEntityRef,
    group: ScopedEntityRef,
    relation_trace: RelationTrace,
    semantic_order: crate::analysis::facts::evidence::EvidenceSemanticOrder,
    activations: MarkerActivationIndex,
    interpreted_trace: InterpretedTrace,
}

type AmbiguityWitnessIndex = BTreeMap<AmbiguityWitnessKey, AmbiguityWitnessProjection>;

fn marker_activation_index<'a>(
    markers: impl IntoIterator<Item = (ScopedEntityRef, &'a RelationTrace)>,
    lane: &str,
) -> Result<MarkerActivationIndex, TypedPanicCallEvaluationError> {
    let mut activations = BTreeMap::new();
    for (claim, trace) in markers {
        if activations.insert(claim, trace.clone()).is_some() {
            return Err(invalid(
                "ambiguity witness",
                format!("{lane} markers repeat an exact active claim"),
            ));
        }
    }
    Ok(activations)
}

#[allow(
    clippy::too_many_lines,
    reason = "exact expected-use reconstruction keeps call and compiler-assert lanes visibly bijective"
)]
fn expected_evidence_uses(
    inputs: &PanicRootInputs,
    obligations: &[PanicCallObligation],
    call_projector: &PanicCallTraceProjector<'_>,
    assert_projector: &CompilerAssertTraceProjector<'_>,
    effect_local_ids: &BTreeMap<ScopedEntityRef, u32>,
) -> Result<(ExpectedEvidenceUses, AmbiguityWitnessIndex), TypedPanicCallEvaluationError> {
    let call_producer = PassId::new(MATCH_PANIC_CALL_EVIDENCE_RULE)
        .expect("built-in panic-call matcher ID is valid");
    let assert_producer = PassId::new(MATCH_COMPILER_ASSERT_EVIDENCE_RULE)
        .expect("built-in compiler-assert matcher ID is valid");
    let mut expected = BTreeMap::new();
    let mut witnesses = BTreeMap::new();

    for obligation in obligations {
        let call_id = obligation.call_id();
        let trace = call_projector
            .project(call_id)
            .map_err(|source| TypedPanicCallEvaluationError::Trace(Box::new(source)))?;
        if trace.source() != obligation.source()
            || trace.endpoint().erase() != *obligation.endpoint()
            || trace.trace_target() != obligation.trace_target()
            || trace.relation_trace() != obligation.trace()
            || trace.witness_order() != call_id
        {
            return Err(invalid(
                "evidence use",
                format!("panic-call witness {call_id} changed during semantic projection"),
            ));
        }
        let semantic_order = trace
            .evidence_order_for_report(obligation.traversal_order())
            .map_err(|source| invalid("evidence use", source.to_string()))?;
        let activations = marker_activation_index(
            obligation
                .active_markers()
                .iter()
                .map(|marker| (marker.claim().clone(), marker.trace())),
            "panic-call",
        )?;
        let witness_key = (obligation.source().clone(), call_id);
        if witnesses
            .insert(
                witness_key,
                AmbiguityWitnessProjection {
                    lane: AmbiguityWitnessLane::PanicCall,
                    endpoint: obligation.endpoint().clone(),
                    group: obligation.evidence_group().clone(),
                    relation_trace: obligation.trace().clone(),
                    semantic_order: semantic_order.clone(),
                    activations,
                    interpreted_trace: interpreted_trace(&trace)?,
                },
            )
            .is_some()
        {
            return Err(invalid(
                "ambiguity witness",
                "panic-call inputs repeat an exact source/order witness",
            ));
        }
        let matches = obligation
            .expected_evidence_matches_for_report()
            .map_err(|source| invalid("evidence use", source.to_string()))?;
        for matched in matches {
            let usage = EvidenceUseRecord::new(
                inputs.root().domain.clone(),
                matched.claim().clone(),
                matched.endpoint().clone(),
                matched.group().clone(),
                matched.obligation_source().clone(),
                matched.trace().clone(),
                call_id,
                semantic_order.clone(),
            );
            if expected.insert(usage, call_producer.clone()).is_some() {
                return Err(invalid(
                    "evidence use",
                    "panic-call inputs produce a duplicate exact evidence use",
                ));
            }
        }
    }

    for assertion in inputs.compiler_asserts().assertions() {
        let trace = assert_projector
            .project(assertion.order())
            .map_err(|source| TypedPanicCallEvaluationError::CompilerTrace(Box::new(source)))?;
        if trace.assertion() != assertion.source()
            || trace.endpoint().erase() != assertion.owner().erase()
            || trace.witness_order() != assertion.order()
        {
            return Err(invalid(
                "evidence use",
                format!(
                    "compiler-assert witness {} changed during semantic projection",
                    assertion.order()
                ),
            ));
        }
        let semantic_order = trace
            .evidence_order_for_report(assertion.visit_order())
            .map_err(|source| invalid("evidence use", source.to_string()))?;
        let activations = marker_activation_index(
            assertion
                .markers()
                .iter()
                .map(|marker| (marker.claim().erase(), marker.trace())),
            "compiler-assert",
        )?;
        let witness_key = (assertion.source().clone(), assertion.order());
        if witnesses
            .insert(
                witness_key,
                AmbiguityWitnessProjection {
                    lane: AmbiguityWitnessLane::CompilerAssert,
                    endpoint: assertion.owner().erase(),
                    group: assertion.owner().erase(),
                    relation_trace: assertion.trace().clone(),
                    semantic_order: semantic_order.clone(),
                    activations,
                    interpreted_trace: compiler_assert_interpreted_trace(&trace, effect_local_ids)?,
                },
            )
            .is_some()
        {
            return Err(invalid(
                "ambiguity witness",
                "compiler-assert inputs repeat an exact source/order witness",
            ));
        }
        for marker in assertion
            .markers()
            .iter()
            .filter(|marker| !marker.data().rationale().trim().is_empty())
        {
            let usage = EvidenceUseRecord::new(
                inputs.root().domain.clone(),
                marker.claim().erase(),
                assertion.owner().erase(),
                assertion.owner().erase(),
                assertion.source().clone(),
                assertion.trace().clone(),
                assertion.order(),
                semantic_order.clone(),
            );
            if expected.insert(usage, assert_producer.clone()).is_some() {
                return Err(invalid(
                    "evidence use",
                    "compiler-assert inputs produce a duplicate exact evidence use",
                ));
            }
        }
    }
    Ok((expected, witnesses))
}

fn validate_evidence_use_rows(
    root: &EvaluationRoot,
    evaluation: &WorkspaceEvaluationView<'_>,
    expected: &ExpectedEvidenceUses,
    rows: Vec<TypedDerivedRow<EvidenceUseRecord>>,
) -> Result<(), TypedPanicCallEvaluationError> {
    let mut actual = BTreeMap::new();
    for row in rows {
        if &row.root != root || row.data.domain() != &root.domain {
            return Err(invalid(
                "evidence use",
                "a derived use belongs to a different root or domain",
            ));
        }
        row.data
            .semantic_order()
            .validate()
            .map_err(|reason| invalid("evidence use", reason))?;
        evaluation
            .graph()
            .validate_path(
                row.data.trace().root(),
                row.data.trace().target(),
                row.data.trace().relations(),
            )
            .map_err(|source| invalid("evidence use trace", source.to_string()))?;
        if actual.insert(row.data, row.producer).is_some() {
            return Err(invalid(
                "evidence use",
                "derived uses repeat an exact producer payload",
            ));
        }
    }
    if actual != *expected {
        let missing = expected
            .keys()
            .filter(|usage| !actual.contains_key(*usage))
            .count();
        let orphan = actual
            .keys()
            .filter(|usage| !expected.contains_key(*usage))
            .count();
        let altered_producer = expected
            .iter()
            .filter(|(usage, producer)| {
                actual.get(*usage).is_some_and(|actual| actual != *producer)
            })
            .count();
        return Err(invalid(
            "evidence use",
            format!(
                "derived uses are not bijective with prepared inputs (missing {missing}, orphan {orphan}, altered producer {altered_producer})"
            ),
        ));
    }
    Ok(())
}

fn prepare_compiler_assert_projector(
    inputs: &CompilerAssertRootInputs,
) -> Result<CompilerAssertTraceProjector<'_>, TypedPanicCallEvaluationError> {
    #[cfg(test)]
    COMPILER_ASSERT_PROJECTOR_PREPARES
        .set(COMPILER_ASSERT_PROJECTOR_PREPARES.get().saturating_add(1));
    CompilerAssertTraceProjector::prepare(inputs)
        .map_err(|source| TypedPanicCallEvaluationError::CompilerTrace(Box::new(source)))
}

#[cfg(test)]
std::thread_local! {
    static COMPILER_ASSERT_PROJECTOR_PREPARES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_compiler_assert_projector_prepares() {
    COMPILER_ASSERT_PROJECTOR_PREPARES.set(0);
}

#[cfg(test)]
fn compiler_assert_projector_prepares() -> usize {
    COMPILER_ASSERT_PROJECTOR_PREPARES.get()
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one fail-closed projection owns the complete use/issue/context/marker bijection"
)]
fn project_ambiguity_report(
    inputs: &PanicRootInputs,
    evaluation: &WorkspaceEvaluationView<'_>,
    request: &InterpretationRoot,
    root: &EvaluationRoot,
    obligations: &[PanicCallObligation],
    call_projector: &PanicCallTraceProjector<'_>,
    assert_projector: &CompilerAssertTraceProjector<'_>,
    evidence_uses: Vec<TypedDerivedRow<EvidenceUseRecord>>,
    issues: Vec<TypedEvaluatedIssue<AmbiguousEvidenceReuseIssue>>,
    #[allow(unused_variables)] corruption: AmbiguityProjectionHook,
) -> Result<TypedPanicAmbiguityRootReport, TypedPanicCallEvaluationError> {
    if inputs.root() != root
        || inputs.traversal().root() != root
        || evaluation.root() != root
        || !inputs.belongs_to(evaluation.facts())
    {
        return Err(invalid(
            "ambiguity inputs",
            "prepared inputs, traversal, or workspace belong to a different root",
        ));
    }
    let effect_local_ids = compiler_effect_local_ids(inputs, evaluation.facts())?;
    #[allow(unused_mut)]
    let (expected, mut witnesses) = expected_evidence_uses(
        inputs,
        obligations,
        call_projector,
        assert_projector,
        &effect_local_ids,
    )?;
    validate_evidence_use_rows(root, evaluation, &expected, evidence_uses)?;
    #[cfg(test)]
    if matches!(
        corruption,
        Some(AmbiguityProjectionCorruption::ActivationRoot)
    ) {
        let activation = witnesses
            .values_mut()
            .flat_map(|witness| witness.activations.values_mut())
            .next()
            .ok_or_else(|| {
                invalid(
                    "test ambiguity corruption",
                    "fixture has no marker activation",
                )
            })?;
        *activation = RelationTrace::new(
            activation.target().clone(),
            activation.target().clone(),
            activation.relations().to_vec(),
        );
    }
    #[cfg(test)]
    if matches!(
        corruption,
        Some(AmbiguityProjectionCorruption::ActivationUnsupportedFinalRelation)
    ) {
        return probe_unsupported_marker_activation(root, evaluation, &expected);
    }

    let mut uses_by_marker = BTreeMap::<ScopedEntityRef, Vec<&EvidenceUseRecord>>::new();
    for usage in expected.keys() {
        let claim = evaluation
            .facts()
            .entity::<MarkerClaimEntity>(usage.claim())
            .map_err(|source| invalid("ambiguity claim", source.to_string()))?;
        if claim.key().domain() != usage.domain() {
            return Err(invalid(
                "ambiguity claim",
                "claim domain disagrees with its evidence use",
            ));
        }
        let marker = evaluation
            .facts()
            .entity_by_key::<MarkerOccurrenceEntity>(
                usage.claim().scope(),
                claim.key().occurrence(),
            )
            .map_err(|source| invalid("ambiguity marker", source.to_string()))?
            .ok_or_else(|| {
                invalid(
                    "ambiguity marker",
                    "evidence claim has no physical marker occurrence",
                )
            })?;
        uses_by_marker.entry(marker).or_default().push(usage);
    }

    let issue_producer =
        PassId::new(DETECT_EVIDENCE_REUSE_RULE).expect("built-in evidence coordinator ID is valid");
    let mut issues_by_marker = BTreeMap::new();
    for issue in issues {
        if issue.producer != issue_producer
            || issue.context.root != *root
            || issue.data.domain() != &root.domain
            || issue.context.source.as_ref() != Some(&issue.data.marker().as_row())
        {
            return Err(invalid(
                "ambiguity issue",
                "producer, root, domain, or marker context is not canonical",
            ));
        }
        if issues_by_marker
            .insert(issue.data.marker().clone(), issue)
            .is_some()
        {
            return Err(invalid(
                "ambiguity issue",
                "multiple issues report the same physical marker",
            ));
        }
    }

    let mut projected = Vec::with_capacity(issues_by_marker.len());
    for (marker, uses) in uses_by_marker {
        let groups = uses
            .iter()
            .map(|usage| usage.group().clone())
            .collect::<BTreeSet<_>>();
        if groups.len() < 2 {
            if issues_by_marker.contains_key(&marker) {
                return Err(invalid(
                    "ambiguity issue",
                    "an issue reports a marker with fewer than two groups",
                ));
            }
            continue;
        }
        let issue = issues_by_marker.remove(&marker).ok_or_else(|| {
            invalid(
                "ambiguity issue",
                "a reused physical marker has no coordinator issue",
            )
        })?;
        let canonical = canonical_evidence_use(uses.iter().copied()).ok_or_else(|| {
            invalid(
                "ambiguity issue",
                "a reused marker lost every contributing evidence use",
            )
        })?;
        let expected_groups = groups.into_iter().collect::<Vec<_>>();
        if issue.data.witness_source() != canonical.source()
            || issue.data.witness_endpoint() != canonical.endpoint()
            || issue.data.witness_order() != canonical.witness_order()
            || issue.data.groups() != expected_groups
            || issue.context.endpoint.as_ref() != Some(canonical.endpoint())
            || issue.context.trace.as_ref() != Some(canonical.trace())
        {
            return Err(invalid(
                "ambiguity issue",
                "canonical witness, group union, endpoint, or trace context was altered",
            ));
        }
        let mut common_owner = None;
        let mut canonical_trace = None;
        for usage in uses {
            let witness = ambiguity_witness(usage, &witnesses)?;
            let activation = witness.activations.get(usage.claim()).ok_or_else(|| {
                invalid(
                    "ambiguity witness",
                    "evidence use has no exact active marker activation",
                )
            })?;
            let owner = marker_owner_from_activation(root, evaluation, usage.claim(), activation)?;
            match &common_owner {
                Some((expected, _)) if expected != &owner.0 => {
                    return Err(invalid(
                        "marker owner",
                        "contributing evidence uses resolve the physical marker to different owners",
                    ));
                }
                None => common_owner = Some(owner),
                Some(_) => {}
            }
            if usage == canonical {
                canonical_trace = Some(witness.interpreted_trace.clone());
            }
        }
        let (_, owner_data) = common_owner.ok_or_else(|| {
            invalid(
                "marker owner",
                "a reused marker lost every contributing owner",
            )
        })?;
        let trace = canonical_trace.ok_or_else(|| {
            invalid(
                "ambiguity witness",
                "canonical evidence use has no reconstructed semantic trace",
            )
        })?;
        let source_range = physical_marker_source(evaluation, &marker)?;
        projected.push(TypedPanicAmbiguityIssueReport {
            root: root.clone(),
            function: function_id(*owner_data.key()),
            function_path: owner_data.display_path().to_owned(),
            source_range: Some(source_range),
            trace,
            effect_count: expected_groups.len(),
        });
    }
    if !issues_by_marker.is_empty() {
        return Err(invalid(
            "ambiguity issue",
            "coordinator emitted an orphan physical-marker issue",
        ));
    }
    Ok(TypedPanicAmbiguityRootReport {
        root: root.clone(),
        function: request.function,
        path: request.path.clone(),
        kind: request.kind,
        issues: projected,
    })
}

#[cfg(test)]
fn probe_unsupported_marker_activation(
    root: &EvaluationRoot,
    evaluation: &WorkspaceEvaluationView<'_>,
    expected: &ExpectedEvidenceUses,
) -> Result<TypedPanicAmbiguityRootReport, TypedPanicCallEvaluationError> {
    let usage = expected
        .keys()
        .next()
        .ok_or_else(|| invalid("test ambiguity corruption", "fixture has no evidence use"))?;
    let claim = evaluation
        .facts()
        .entity::<MarkerClaimEntity>(usage.claim())
        .map_err(|source| invalid("test ambiguity corruption", source.to_string()))?;
    let marker = evaluation
        .facts()
        .entity_by_key::<MarkerOccurrenceEntity>(usage.claim().scope(), claim.key().occurrence())
        .map_err(|source| invalid("test ambiguity corruption", source.to_string()))?
        .ok_or_else(|| invalid("test ambiguity corruption", "fixture marker is absent"))?;
    let relation = evaluation
        .graph()
        .outgoing(&marker)
        .find(|relation| {
            relation.to == *usage.claim()
                && relation.relation.schema().as_str() == MarkerOccurrenceHasClaim::ID
        })
        .ok_or_else(|| {
            invalid(
                "test ambiguity corruption",
                "fixture marker-to-claim relation is absent",
            )
        })?;
    let fake_root = EvaluationRoot::new(root.domain.clone(), marker.clone());
    let activation = RelationTrace::new(
        marker,
        usage.claim().clone(),
        vec![relation.relation.clone()],
    );
    match marker_owner_from_activation(&fake_root, evaluation, usage.claim(), &activation) {
        Err(error) => Err(error),
        Ok(_) => Err(invalid(
            "marker activation",
            "unsupported final candidate relation was accepted",
        )),
    }
}

fn ambiguity_witness<'a>(
    usage: &EvidenceUseRecord,
    witnesses: &'a AmbiguityWitnessIndex,
) -> Result<&'a AmbiguityWitnessProjection, TypedPanicCallEvaluationError> {
    let lane = match usage.source().row().schema.as_str() {
        CallOccurrenceEntity::ID => AmbiguityWitnessLane::PanicCall,
        MirAssertFact::ID => AmbiguityWitnessLane::CompilerAssert,
        schema => {
            return Err(invalid(
                "ambiguity witness",
                format!("unsupported witness source schema `{schema}`"),
            ));
        }
    };
    let witness = witnesses
        .get(&(usage.source().clone(), usage.witness_order()))
        .ok_or_else(|| {
            invalid(
                "ambiguity witness",
                "evidence use has no exact prepared source/order witness",
            )
        })?;
    if witness.lane != lane
        || witness.endpoint != *usage.endpoint()
        || witness.group != *usage.group()
        || witness.relation_trace != *usage.trace()
        || witness.semantic_order != *usage.semantic_order()
    {
        return Err(invalid(
            "ambiguity witness",
            "evidence use changed after exact lane-specific reconstruction",
        ));
    }
    Ok(witness)
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive final-relation dispatch keeps every supported marker owner explicit"
)]
pub(super) fn marker_owner_from_activation(
    root: &EvaluationRoot,
    evaluation: &WorkspaceEvaluationView<'_>,
    claim: &ScopedEntityRef,
    activation: &crate::analysis::facts::evaluation::RelationTrace,
) -> Result<(ScopedEntityRef, FunctionEntity), TypedPanicCallEvaluationError> {
    if activation.root() != &root.entity
        || activation.target() != claim
        || activation.relations().is_empty()
    {
        return Err(invalid(
            "marker activation",
            "activation trace starts at another root, is empty, or does not terminate at the selected claim",
        ));
    }
    let resolved = evaluation
        .graph()
        .validate_path(
            activation.root(),
            activation.target(),
            activation.relations(),
        )
        .map_err(|source| invalid("marker activation", source.to_string()))?;
    let final_relation = resolved.last().ok_or_else(|| {
        invalid(
            "marker activation",
            "validated activation trace has no final candidate relation",
        )
    })?;
    if final_relation.to != *claim
        || !matches!(final_relation.relation, WorkspaceRelationRef::Artifact(_))
    {
        return Err(invalid(
            "marker activation",
            "final candidate relation is not a permanent edge into the selected claim",
        ));
    }
    let owner = match final_relation.relation.schema().as_str() {
        FunctionHasMarkerClaimCandidate::ID => {
            evaluation
                .facts()
                .entity::<FunctionEntity>(&final_relation.from)
                .map_err(|source| invalid("marker owner", source.to_string()))?;
            final_relation.from.clone()
        }
        CallOccurrenceHasMarkerClaimCandidate::ID => {
            let call = evaluation
                .facts()
                .entity::<CallOccurrenceEntity>(&final_relation.from)
                .map_err(|source| invalid("marker owner", source.to_string()))?;
            evaluation
                .facts()
                .entity_by_key::<FunctionEntity>(final_relation.from.scope(), call.key().owner())
                .map_err(|source| invalid("marker owner", source.to_string()))?
                .ok_or_else(|| {
                    invalid(
                        "marker owner",
                        "call candidate has no exact owning function entity",
                    )
                })?
        }
        EffectSiteHasMarkerClaimCandidate::ID => {
            let effect = evaluation
                .facts()
                .entity::<EffectSiteEntity>(&final_relation.from)
                .map_err(|source| invalid("marker owner", source.to_string()))?;
            evaluation
                .facts()
                .entity_by_key::<FunctionEntity>(
                    final_relation.from.scope(),
                    effect.site().function(),
                )
                .map_err(|source| invalid("marker owner", source.to_string()))?
                .ok_or_else(|| {
                    invalid(
                        "marker owner",
                        "effect candidate has no exact owning function entity",
                    )
                })?
        }
        UnsafeOperationHasMarkerClaimCandidate::ID => {
            let operation = evaluation
                .facts()
                .entity::<UnsafeOperationEntity>(&final_relation.from)
                .map_err(|source| invalid("marker owner", source.to_string()))?;
            evaluation
                .facts()
                .entity_by_key::<FunctionEntity>(
                    final_relation.from.scope(),
                    operation.key().owner(),
                )
                .map_err(|source| invalid("marker owner", source.to_string()))?
                .ok_or_else(|| {
                    invalid(
                        "marker owner",
                        "unsafe-operation candidate has no exact owning function entity",
                    )
                })?
        }
        schema => {
            return Err(invalid(
                "marker activation",
                format!("unsupported final candidate relation `{schema}`"),
            ));
        }
    };
    let data = evaluation
        .facts()
        .entity::<FunctionEntity>(&owner)
        .map_err(|source| invalid("marker owner", source.to_string()))?;
    Ok((owner, data))
}

pub(super) fn physical_marker_source(
    evaluation: &WorkspaceEvaluationView<'_>,
    marker: &ScopedEntityRef,
) -> Result<SourceRangeIr, TypedPanicCallEvaluationError> {
    let marker_data = evaluation
        .facts()
        .entity::<MarkerOccurrenceEntity>(marker)
        .map_err(|source| invalid("physical marker", source.to_string()))?;
    let mut sources = evaluation.graph().outgoing(marker).filter(|relation| {
        relation.relation.schema().as_str() == MarkerOccurrenceHasSourceAnchor::ID
    });
    let source = sources.next().ok_or_else(|| {
        invalid(
            "physical marker",
            "marker occurrence has no source-anchor relation",
        )
    })?;
    if sources.next().is_some()
        || source.from != *marker
        || !matches!(source.relation, WorkspaceRelationRef::Artifact(_))
    {
        return Err(invalid(
            "physical marker",
            "marker occurrence source-anchor relation is not unique and permanent",
        ));
    }
    let anchor = evaluation
        .facts()
        .entity::<SourceAnchorEntity>(&source.to)
        .map_err(|source| invalid("physical marker", source.to_string()))?;
    if anchor.anchor() != marker_data.key().anchor() {
        return Err(invalid(
            "physical marker",
            "marker occurrence key disagrees with its source-anchor entity",
        ));
    }
    Ok(source_range(anchor.anchor()))
}

fn compiler_effect_local_ids(
    inputs: &PanicRootInputs,
    workspace: &WorkspaceFactView<'_>,
) -> Result<BTreeMap<ScopedEntityRef, u32>, TypedPanicCallEvaluationError> {
    let mut grouped =
        BTreeMap::<(ArtifactScopeId, FunctionKey), BTreeMap<EffectSiteKey, ScopedEntityRef>>::new();
    for assertion in inputs.compiler_asserts().assertions() {
        let effect = assertion.owner().erase();
        let data = workspace
            .entity::<EffectSiteEntity>(&effect)
            .map_err(|source| invalid("compiler-assert trace", source.to_string()))?;
        let previous = grouped
            .entry((effect.scope().clone(), *data.site().function()))
            .or_default()
            .insert(*data.site(), effect.clone());
        if previous.is_some_and(|previous| previous != effect) {
            return Err(invalid(
                "compiler-assert trace",
                "one local effect key resolves to multiple scoped entities",
            ));
        }
    }
    let mut local_ids = BTreeMap::new();
    for effects in grouped.into_values() {
        for (index, effect) in effects.into_values().enumerate() {
            let index = u32::try_from(index)
                .map_err(|_| invalid("compiler-assert trace", "local effect count exceeds u32"))?;
            local_ids.insert(effect, index);
        }
    }
    Ok(local_ids)
}

fn compiler_assert_interpreted_trace(
    trace: &CompilerAssertSemanticTrace,
    effect_local_ids: &BTreeMap<ScopedEntityRef, u32>,
) -> Result<InterpretedTrace, TypedPanicCallEvaluationError> {
    let steps = trace
        .steps()
        .iter()
        .map(|step| {
            let caller_key = step.caller_function().ok_or_else(|| {
                invalid(
                    "compiler-assert trace",
                    "compiler assertion cannot be a semantic trace caller",
                )
            })?;
            let caller_path =
                compiler_trace_node_path(step.caller_role(), step.caller_display_path())?;
            let target_path =
                compiler_trace_node_path(step.target_role(), step.target_display_path())?;
            let local_id = if let Some(local_id) = step.call_local_id() {
                local_id
            } else {
                let effect = step.effect().ok_or_else(|| {
                    invalid(
                        "compiler-assert trace",
                        "semantic step has neither a call nor an effect identity",
                    )
                })?;
                *effect_local_ids.get(&effect.erase()).ok_or_else(|| {
                    invalid(
                        "compiler-assert trace",
                        "semantic effect has no indexed legacy-local identity",
                    )
                })?
            };
            Ok(InterpretedTraceStep {
                caller: function_id(caller_key),
                caller_path,
                call: CallId::new(local_id),
                kind: InterpretedTraceStepKind::Reachability(match step.edge() {
                    CompilerAssertSemanticEdge::MacroExpansion => CallEdgeKindIr::MacroExpansion,
                    CompilerAssertSemanticEdge::Call(kind) => call_edge_kind(kind),
                    CompilerAssertSemanticEdge::Assert(_) => CallEdgeKindIr::Assert,
                }),
                source_range: step.source_key().map(source_range),
                target: step.target_function().map(function_id),
                target_path: Some(target_path),
            })
        })
        .collect::<Result<Vec<_>, TypedPanicCallEvaluationError>>()?;
    Ok(InterpretedTrace { steps })
}

fn compiler_trace_node_path(
    role: CompilerAssertSemanticNodeRole,
    display_path: Option<&str>,
) -> Result<String, TypedPanicCallEvaluationError> {
    match role {
        CompilerAssertSemanticNodeRole::Function | CompilerAssertSemanticNodeRole::Callable => {
            display_path.map(String::from).ok_or_else(|| {
                invalid(
                    "compiler-assert trace",
                    "semantic function or callable has no display path",
                )
            })
        }
        CompilerAssertSemanticNodeRole::Macro => display_path
            .map(|path| format!("macro {path}"))
            .ok_or_else(|| {
                invalid(
                    "compiler-assert trace",
                    "semantic macro has no display path",
                )
            }),
        CompilerAssertSemanticNodeRole::CompilerAssert(kind) => {
            Ok(compiler_assert_presentation(kind).target().to_owned())
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one atomic projection keeps summary, issue, context, and owned DTO joins auditable"
)]
fn project_completeness_report(
    inputs: &PanicRootInputs,
    request: &InterpretationRoot,
    root: &EvaluationRoot,
    summaries: Vec<TypedDerivedRow<PanicCompletenessOutcome>>,
    issues: Vec<TypedEvaluatedIssue<PanicAnalysisIncompleteIssue>>,
) -> Result<TypedPanicCompletenessRootReport, TypedPanicCallEvaluationError> {
    if inputs.root() != root || inputs.traversal().root() != root {
        return Err(invalid(
            "completeness inputs",
            "prepared inputs or traversal belong to a different evaluation root",
        ));
    }
    let [summary] = summaries.try_into().map_err(|summaries: Vec<_>| {
        invalid(
            "completeness summary",
            format!(
                "expected exactly one row for the active root, found {}",
                summaries.len()
            ),
        )
    })?;
    if summary.root != *root || summary.producer.as_str() != EMIT_PANIC_COMPLETENESS_RULE {
        return Err(invalid(
            "completeness summary",
            "root or producer disagrees with the completeness projection rule",
        ));
    }
    let expected_expanded =
        u64::try_from(inputs.traversal().body_visits().len()).map_err(|_| {
            invalid(
                "completeness summary",
                "expanded body count does not fit u64",
            )
        })?;
    if summary.data.expanded_bodies() != expected_expanded {
        return Err(invalid(
            "completeness summary",
            "expanded body count disagrees with the prepared traversal",
        ));
    }
    if summary.data.reasons().len() != issues.len() {
        return Err(invalid(
            "completeness issues",
            "issue count disagrees with the ordered summary reasons",
        ));
    }

    let mut indexed = BTreeMap::new();
    for issue in issues {
        let order = issue.data.traversal_order();
        if indexed.insert(order, issue).is_some() {
            return Err(invalid(
                "completeness issues",
                "multiple issues have the same traversal order",
            ));
        }
    }
    let mut projected = Vec::with_capacity(indexed.len());
    let mut previous_order = None;
    for reason in summary.data.reasons() {
        if previous_order.is_some_and(|previous| previous >= reason.traversal_order()) {
            return Err(invalid(
                "completeness summary",
                "reasons are not in strict traversal order",
            ));
        }
        previous_order = Some(reason.traversal_order());
        let expected_data = PanicAnalysisIncompleteIssue::from_reason(reason.clone());
        let issue = indexed.remove(&reason.traversal_order()).ok_or_else(|| {
            invalid(
                "completeness issues",
                "a summary reason has no issue at its traversal order",
            )
        })?;
        let expected_context = completeness_issue_context(root, reason);
        if issue.data != expected_data
            || issue.producer.as_str() != REPORT_PANIC_INCOMPLETE_RULE
            || issue.context.root != *root
            || issue.context != expected_context
        {
            return Err(invalid(
                "completeness issue",
                "producer, root, or exact context disagrees with its summary reason",
            ));
        }
        validate_incomplete_reason_identity(root, reason.reason())?;
        let legacy_reason = project_incomplete_reason(reason.reason())?;
        projected.push(TypedPanicCompletenessIssueReport {
            root: root.clone(),
            traversal_order: reason.traversal_order(),
            reason: legacy_reason,
        });
    }
    if !indexed.is_empty() {
        return Err(invalid(
            "completeness issues",
            "an issue was not selected by any summary reason",
        ));
    }

    Ok(TypedPanicCompletenessRootReport {
        root: root.clone(),
        function: request.function,
        path: request.path.clone(),
        kind: request.kind,
        issues: projected,
    })
}

fn validate_incomplete_reason_identity(
    root: &EvaluationRoot,
    reason: &PanicIncompleteReason,
) -> Result<(), TypedPanicCallEvaluationError> {
    let PanicIncompleteReason::MissingManagedBody {
        function,
        path,
        semantic_trace,
        relation_trace,
        ..
    } = reason
    else {
        return Ok(());
    };
    if relation_trace.root() != &root.entity {
        return Err(invalid(
            "completeness issue",
            "missing-body relation trace starts at a different evaluation root",
        ));
    }
    if semantic_trace
        .iter()
        .any(|step| step.target().is_none() || step.target_path().is_none())
    {
        return Err(invalid(
            "completeness issue",
            "semantic trace step has mismatched or absent target identity and path",
        ));
    }
    let terminal = semantic_trace
        .last()
        .ok_or_else(|| invalid("completeness issue", "missing-body semantic trace is empty"))?;
    if terminal.target() != Some(*function) || terminal.target_path() != Some(path.as_str()) {
        return Err(invalid(
            "completeness issue",
            "semantic trace terminal target disagrees with the missing function",
        ));
    }
    Ok(())
}

fn completeness_issue_context(
    root: &EvaluationRoot,
    reason: &PanicCompletenessReason,
) -> EvaluationIssueContext {
    let mut context = EvaluationIssueContext::new(root.clone());
    if let PanicIncompleteReason::MissingManagedBody {
        presentation_source,
        relation_trace,
        ..
    } = reason.reason()
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

fn project_incomplete_reason(
    reason: &PanicIncompleteReason,
) -> Result<IncompleteReason, TypedPanicCallEvaluationError> {
    match reason {
        PanicIncompleteReason::NodeLimit { limit } => Ok(IncompleteReason::NodeLimit {
            limit: usize::try_from(*limit).map_err(|_| {
                invalid(
                    "completeness issue",
                    "node limit does not fit the legacy usize boundary",
                )
            })?,
        }),
        PanicIncompleteReason::MissingManagedBody {
            function,
            path,
            presentation_source,
            semantic_trace,
            ..
        } => Ok(IncompleteReason::MissingBody {
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
                        kind: InterpretedTraceStepKind::Reachability(call_edge_kind(step.kind())),
                        source_range: step.source().map(source_range),
                        target: step.target().map(function_id),
                        target_path: step.target_path().map(str::to_owned),
                    })
                    .collect(),
            },
        }),
    }
}

struct PanicCallProjectionRows<'a> {
    obligations: &'a [PanicCallObligation],
    matches: &'a [PanicCallEvidenceMatch],
    projector: &'a PanicCallTraceProjector<'a>,
    unsatisfied: Vec<TypedEvaluatedIssue<UnsatisfiedPanicCallIssue>>,
    duplicates: Vec<TypedEvaluatedIssue<DuplicatePanicCallRequirementIssue>>,
}

fn project_root_report(
    inputs: &PanicRootInputs,
    request: &InterpretationRoot,
    root: &EvaluationRoot,
    rows: PanicCallProjectionRows<'_>,
) -> RootTypedPanicCallEvaluation {
    if inputs.root() != root || inputs.traversal().root() != root {
        return Err(invalid(
            "call inputs",
            "prepared inputs or traversal belong to a different evaluation root",
        ));
    }
    validate_call_issue_rows(
        root,
        rows.obligations,
        rows.matches,
        &rows.unsatisfied,
        &rows.duplicates,
    )?;
    let mut witnesses = BTreeMap::<u64, ProjectedCallWitness>::new();
    let mut issues = Vec::with_capacity(rows.unsatisfied.len() + rows.duplicates.len());
    for issue in rows.unsatisfied {
        let witness = issue.data.witness_order();
        let obligation = obligation(rows.obligations, witness, "unsatisfied issue")?;
        validate_unsatisfied_issue(root, obligation, &issue)?;
        let projected = projected_witness(rows.projector, obligation, &mut witnesses)?;
        let missing_requirements = projected
            .requirements
            .select(issue.data.missing_requirements(), "unsatisfied issue")?;
        issues.push(project_unsatisfied_issue(
            projected,
            issue,
            missing_requirements,
        ));
    }
    for issue in rows.duplicates {
        let witness = issue.data.witness_order();
        let obligation = obligation(rows.obligations, witness, "duplicate issue")?;
        validate_duplicate_issue(root, obligation, &issue)?;
        let projected = projected_witness(rows.projector, obligation, &mut witnesses)?;
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
        issues,
    })
}

fn project_root_contract_report(
    inputs: &PanicRootInputs,
    request: &InterpretationRoot,
    root: &EvaluationRoot,
    rows: Vec<TypedEvaluatedIssue<DuplicatePanicRootRequirementIssue>>,
) -> Result<TypedPanicRootContractRootReport, TypedPanicCallEvaluationError> {
    if inputs.root() != root || inputs.traversal().root() != root {
        return Err(invalid(
            "root-contract inputs",
            "prepared inputs or traversal belong to a different evaluation root",
        ));
    }
    let boundary = root_contract_boundary(inputs)
        .map_err(|source| invalid("root-contract boundary", source.to_string()))?;
    let mut expected = BTreeMap::new();
    let mut projected = Vec::new();
    let mut selected_function = None;
    let mut selected_path = None;
    if let Some(boundary) = boundary {
        let contract = root_contract(boundary)
            .map_err(|source| invalid("root-contract boundary", source.to_string()))?;
        selected_function = Some(function_id(*boundary.body_data().key()));
        selected_path = Some(boundary.body_data().display_path().to_owned());
        projected.reserve(contract.duplicate_requirement_groups().len());
        for group in contract.duplicate_requirement_groups() {
            if group.normalized_name().is_empty() || group.requirements().len() < 2 {
                return Err(invalid(
                    "root-contract issue",
                    "prepared duplicate group is not a complete normalized group",
                ));
            }
            let mut ordinals = Vec::with_capacity(group.requirements().len());
            let mut requirements = Vec::with_capacity(group.requirements().len());
            for requirement in group.requirements() {
                let index = usize::try_from(requirement.ordinal()).map_err(|_| {
                    invalid(
                        "root-contract issue",
                        "requirement ordinal does not fit usize",
                    )
                })?;
                let indexed = contract.requirements().get(index).ok_or_else(|| {
                    invalid(
                        "root-contract issue",
                        "duplicate group requirement is outside the effective contract",
                    )
                })?;
                if indexed != requirement
                    || requirement_name_normalized(requirement.name()) != group.normalized_name()
                    || ordinals
                        .last()
                        .is_some_and(|previous| *previous >= requirement.ordinal())
                {
                    return Err(invalid(
                        "root-contract issue",
                        "duplicate group changed requirement identity or declaration order",
                    ));
                }
                ordinals.push(requirement.ordinal());
                requirements.push(TypedPanicCallRequirementReport {
                    ordinal: requirement.ordinal(),
                    name: requirement.name().to_owned(),
                    condition: requirement.condition().to_owned(),
                    source_range: requirement
                        .source_anchor()
                        .map(|source| source_range(source.data().anchor())),
                });
            }
            let data = DuplicatePanicRootRequirementIssue::new(group.normalized_name(), ordinals);
            let mut context = EvaluationIssueContext::new(root.clone())
                .with_endpoint(boundary.body().erase())
                .with_trace(boundary.trace().clone());
            if let Some(source) = contract.raw_contract() {
                context = context.with_source(source.clone());
            }
            if expected.insert(data, context).is_some() {
                return Err(invalid(
                    "root-contract issue",
                    "prepared contract repeats an exact duplicate group",
                ));
            }
            projected.push(TypedPanicRootContractIssueReport {
                root: root.clone(),
                function: function_id(*boundary.body_data().key()),
                function_path: boundary.body_data().display_path().to_owned(),
                source_range: contract
                    .source_anchor()
                    .map(|source| source_range(source.data().anchor())),
                normalized_name: group.normalized_name().to_owned(),
                requirements,
            });
        }
    }

    validate_root_contract_rows(rows, root, &expected)?;
    Ok(TypedPanicRootContractRootReport {
        root: root.clone(),
        function: request.function,
        path: request.path.clone(),
        kind: request.kind,
        selected_function,
        selected_path,
        issues: projected,
    })
}

fn validate_root_contract_rows(
    rows: Vec<TypedEvaluatedIssue<DuplicatePanicRootRequirementIssue>>,
    root: &EvaluationRoot,
    expected: &BTreeMap<DuplicatePanicRootRequirementIssue, EvaluationIssueContext>,
) -> Result<(), TypedPanicCallEvaluationError> {
    let mut actual = BTreeMap::new();
    let producer = PassId::new(REPORT_DUPLICATE_PANIC_ROOT_REQUIREMENTS_RULE)
        .expect("built-in root-contract reporter ID is valid");
    for row in rows {
        if row.producer != producer || row.context.root != *root {
            return Err(invalid(
                "root-contract issue",
                "issue producer or root is not canonical",
            ));
        }
        if actual.insert(row.data, row.context).is_some() {
            return Err(invalid(
                "root-contract issue",
                "derived issues repeat an exact producer payload",
            ));
        }
    }
    if &actual != expected {
        return Err(invalid(
            "root-contract issue",
            "derived issues are not bijective with the prepared root contract",
        ));
    }
    Ok(())
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

fn validate_call_match_rows(
    root: &EvaluationRoot,
    obligations: &[PanicCallObligation],
    rows: Vec<TypedDerivedRow<PanicCallEvidenceMatch>>,
) -> Result<Vec<PanicCallEvidenceMatch>, TypedPanicCallEvaluationError> {
    let expected = expected_matches_from_obligations(obligations)
        .map_err(|source| invalid("call evidence match", source.to_string()))?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let producer = PassId::new(MATCH_PANIC_CALL_EVIDENCE_RULE)
        .expect("built-in panic-call evidence matcher ID is valid");
    let mut actual = BTreeSet::new();
    for row in rows {
        if row.root != *root || row.producer != producer {
            return Err(invalid(
                "call evidence match",
                "derived match producer or root is not canonical",
            ));
        }
        if !actual.insert(row.data) {
            return Err(invalid(
                "call evidence match",
                "derived matches repeat an exact canonical row",
            ));
        }
    }
    if actual != expected {
        return Err(invalid(
            "call evidence match",
            "derived matches are not bijective with validated call obligations",
        ));
    }
    Ok(actual.into_iter().collect())
}

fn validate_call_issue_rows(
    root: &EvaluationRoot,
    obligations: &[PanicCallObligation],
    matches: &[PanicCallEvidenceMatch],
    unsatisfied: &[TypedEvaluatedIssue<UnsatisfiedPanicCallIssue>],
    duplicates: &[TypedEvaluatedIssue<DuplicatePanicCallRequirementIssue>],
) -> Result<(), TypedPanicCallEvaluationError> {
    let expected_unsatisfied = expected_unsatisfied_panic_call_issues(obligations, matches, root)
        .map_err(|source| invalid("unsatisfied issue", source.to_string()))?
        .into_iter()
        .map(|(data, context)| (data.witness_order(), (data, context)))
        .collect::<BTreeMap<_, _>>();
    let unsatisfied_producer = PassId::new(REPORT_UNSATISFIED_PANIC_CALLS_RULE)
        .expect("built-in unsatisfied-call reporter ID is valid");
    let mut actual_unsatisfied = BTreeMap::new();
    for row in unsatisfied {
        if row.producer != unsatisfied_producer || row.context.root != *root {
            return Err(invalid(
                "unsatisfied issue",
                "issue producer or root is not canonical",
            ));
        }
        if actual_unsatisfied
            .insert(
                row.data.witness_order(),
                (row.data.clone(), row.context.clone()),
            )
            .is_some()
        {
            return Err(invalid("unsatisfied issue", "issues repeat a call witness"));
        }
    }
    if actual_unsatisfied != expected_unsatisfied {
        return Err(invalid(
            "unsatisfied issue",
            "issues are not bijective with validated call obligations and evidence",
        ));
    }

    let expected_duplicates = expected_duplicate_panic_call_requirement_issues(obligations, root)
        .map_err(|source| invalid("duplicate issue", source.to_string()))?
        .into_iter()
        .map(|(data, context)| {
            (
                (data.witness_order(), data.normalized_name().to_owned()),
                (data, context),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let duplicate_producer = PassId::new(REPORT_DUPLICATE_PANIC_CALL_REQUIREMENTS_RULE)
        .expect("built-in duplicate-call reporter ID is valid");
    let mut actual_duplicates = BTreeMap::new();
    for row in duplicates {
        if row.producer != duplicate_producer || row.context.root != *root {
            return Err(invalid(
                "duplicate issue",
                "issue producer or root is not canonical",
            ));
        }
        let key = (
            row.data.witness_order(),
            row.data.normalized_name().to_owned(),
        );
        if actual_duplicates
            .insert(key, (row.data.clone(), row.context.clone()))
            .is_some()
        {
            return Err(invalid(
                "duplicate issue",
                "issues repeat a call witness and normalized requirement",
            ));
        }
    }
    if actual_duplicates != expected_duplicates {
        return Err(invalid(
            "duplicate issue",
            "issues are not bijective with validated call obligations",
        ));
    }
    Ok(())
}

fn index_obligations(
    inputs: &PanicRootInputs,
    root: &EvaluationRoot,
    rows: Vec<TypedDerivedRow<PanicCallObligation>>,
) -> Result<Vec<PanicCallObligation>, TypedPanicCallEvaluationError> {
    #[cfg(test)]
    OBLIGATION_INDEX_PASSES.set(OBLIGATION_INDEX_PASSES.get() + 1);
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

#[cfg(test)]
std::thread_local! {
    static OBLIGATION_INDEX_PASSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_obligation_index_passes() {
    OBLIGATION_INDEX_PASSES.set(0);
}

#[cfg(test)]
fn obligation_index_passes() -> usize {
    OBLIGATION_INDEX_PASSES.get()
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
            ordinal,
            name,
            condition,
            source_anchor,
            ..
        } => TypedPanicCallRequirementReport {
            ordinal: *ordinal,
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

pub(super) fn function_id(function: FunctionKey) -> FunctionId {
    function.instance().map_or_else(
        || FunctionId::generic(function.definition()),
        |instance| FunctionId::exact(function.definition(), instance),
    )
}

#[cfg(test)]
pub(super) fn adapt_typed_panic_call_reports(
    sources: &impl FindingSources,
    reports: Vec<TypedPanicCallRootReport>,
    roots: &[InterpretationRoot],
    show_full_stack_trace: bool,
) -> Result<Vec<Finding>, TypedPanicCallEvaluationError> {
    let projected = validate_report_roots(&reports, roots)?;
    Ok(adapt_prevalidated_typed_panic_call_reports(
        sources,
        reports,
        roots,
        projected,
        show_full_stack_trace,
    ))
}

pub(super) fn adapt_prevalidated_typed_panic_call_reports(
    sources: &impl FindingSources,
    reports: Vec<TypedPanicCallRootReport>,
    roots: &[InterpretationRoot],
    projected: Vec<Vec<InterpretedFinding>>,
    show_full_stack_trace: bool,
) -> Vec<Finding> {
    let capacity = reports.iter().map(|report| report.issues.len()).sum();
    let mut findings = Vec::with_capacity(capacity);
    for ((report, root), projected) in reports.into_iter().zip(roots).zip(projected) {
        debug_assert_eq!(report.issues.len(), projected.len());
        for finding in projected {
            findings.push(adapt_typed_panic_call_finding(
                sources,
                root,
                &finding,
                show_full_stack_trace,
            ));
        }
    }
    findings
}

#[cfg(test)]
pub(super) fn adapt_typed_panic_root_contract_reports(
    sources: &impl FindingSources,
    reports: Vec<TypedPanicRootContractRootReport>,
    roots: &[InterpretationRoot],
    show_full_stack_trace: bool,
) -> Result<Vec<Finding>, TypedPanicCallEvaluationError> {
    validate_root_contract_report_roots(&reports, roots)?;
    Ok(adapt_prevalidated_typed_panic_root_contract_reports(
        sources,
        reports,
        roots,
        show_full_stack_trace,
    ))
}

pub(super) fn adapt_prevalidated_typed_panic_root_contract_reports(
    sources: &impl FindingSources,
    reports: Vec<TypedPanicRootContractRootReport>,
    roots: &[InterpretationRoot],
    show_full_stack_trace: bool,
) -> Vec<Finding> {
    let capacity = reports.iter().map(|report| report.issues.len()).sum();
    let mut findings = Vec::with_capacity(capacity);
    for (report, root) in reports.into_iter().zip(roots) {
        for issue in report.issues {
            let finding = InterpretedFinding {
                kind: InterpretedFindingKind::AmbiguousPanicRequirement {
                    normalized_name: issue.normalized_name,
                },
                function: issue.function,
                function_path: issue.function_path,
                target: None,
                source_range: issue.source_range,
                trace: InterpretedTrace { steps: Vec::new() },
                missing_requirements: Vec::new(),
                requirements: issue
                    .requirements
                    .iter()
                    .map(interpreted_requirement)
                    .collect(),
            };
            findings.push(adapt_typed_panic_call_finding(
                sources,
                root,
                &finding,
                show_full_stack_trace,
            ));
        }
    }
    findings
}

#[cfg(test)]
pub(super) fn adapt_typed_panic_ambiguity_reports(
    sources: &impl FindingSources,
    reports: Vec<TypedPanicAmbiguityRootReport>,
    roots: &[InterpretationRoot],
    show_full_stack_trace: bool,
) -> Result<Vec<Finding>, TypedPanicCallEvaluationError> {
    validate_ambiguity_report_roots(&reports, roots)?;
    Ok(adapt_prevalidated_typed_panic_ambiguity_reports(
        sources,
        reports,
        roots,
        show_full_stack_trace,
    ))
}

pub(super) fn adapt_prevalidated_typed_panic_ambiguity_reports(
    sources: &impl FindingSources,
    reports: Vec<TypedPanicAmbiguityRootReport>,
    roots: &[InterpretationRoot],
    show_full_stack_trace: bool,
) -> Vec<Finding> {
    let capacity = reports.iter().map(|report| report.issues.len()).sum();
    let mut findings = Vec::with_capacity(capacity);
    for (report, root) in reports.into_iter().zip(roots) {
        for issue in report.issues {
            let finding = InterpretedFinding {
                kind: InterpretedFindingKind::AmbiguousPanicMarker {
                    effect_count: issue.effect_count,
                },
                function: issue.function,
                function_path: issue.function_path,
                target: None,
                source_range: issue.source_range,
                trace: issue.trace,
                missing_requirements: Vec::new(),
                requirements: Vec::new(),
            };
            findings.push(adapt_typed_panic_ambiguity_finding(
                sources,
                root,
                &finding,
                show_full_stack_trace,
            ));
        }
    }
    findings
}

#[cfg(test)]
pub(super) fn adapt_typed_panic_call_completeness_batch(
    sources: &impl FindingSources,
    batch: &TypedPanicCallBatchReport,
    roots: &[InterpretationRoot],
    show_full_stack_trace: bool,
) -> Result<Vec<Finding>, TypedPanicCallEvaluationError> {
    validate_typed_panic_call_batch(batch, roots)?;
    Ok(adapt_prevalidated_typed_panic_call_completeness_batch(
        sources,
        batch,
        show_full_stack_trace,
    ))
}

pub(super) fn adapt_prevalidated_typed_panic_call_completeness_batch(
    sources: &impl FindingSources,
    batch: &TypedPanicCallBatchReport,
    show_full_stack_trace: bool,
) -> Vec<Finding> {
    let capacity = batch
        .completeness
        .iter()
        .map(|report| report.issues.len())
        .sum::<usize>()
        + batch
            .root_preparations
            .iter()
            .filter(|preparation| {
                matches!(
                    preparation.outcome,
                    TypedPanicRootPreparationOutcome::Missing { .. }
                )
            })
            .count();
    let mut findings = Vec::with_capacity(capacity);
    for preparation in &batch.root_preparations {
        match &preparation.outcome {
            TypedPanicRootPreparationOutcome::Evaluatable { report_index, .. } => {
                for issue in &batch.completeness[*report_index].issues {
                    findings.push(adapt_typed_panic_incomplete_finding(
                        sources,
                        &preparation.request,
                        issue.reason.clone(),
                        show_full_stack_trace,
                    ));
                }
            }
            TypedPanicRootPreparationOutcome::Missing { reason } => {
                findings.push(adapt_typed_panic_incomplete_finding(
                    sources,
                    &preparation.request,
                    reason.clone(),
                    show_full_stack_trace,
                ));
            }
        }
    }
    findings
}

#[allow(
    clippy::too_many_lines,
    reason = "one source-free preflight keeps every sparse report lane atomic"
)]
#[cfg(test)]
pub(super) fn validate_typed_panic_call_batch(
    batch: &TypedPanicCallBatchReport,
    roots: &[InterpretationRoot],
) -> Result<(), TypedPanicCallEvaluationError> {
    preflight_typed_panic_call_batch(batch, roots).map(drop)
}

#[allow(
    clippy::too_many_lines,
    reason = "one source-free preflight keeps every sparse report lane atomic"
)]
pub(super) fn preflight_typed_panic_call_batch(
    batch: &TypedPanicCallBatchReport,
    roots: &[InterpretationRoot],
) -> Result<TypedPanicCallBatchPreflight, TypedPanicCallEvaluationError> {
    if batch.root_preparations.len() != roots.len() {
        return Err(invalid(
            "root preparation batch",
            format!(
                "returned {} preparations for {} requests",
                batch.root_preparations.len(),
                roots.len()
            ),
        ));
    }
    let mut expected_scope = None;
    let mut ready_roots = Vec::new();
    let mut ready_preparations = Vec::new();
    for (request_ordinal, (preparation, root)) in
        batch.root_preparations.iter().zip(roots).enumerate()
    {
        let requested_function =
            FunctionKey::new(root.function.def_path_hash, root.function.instance_hash);
        if preparation.request_ordinal != request_ordinal
            || preparation.request != *root
            || preparation.requested_function != requested_function
        {
            return Err(invalid(
                "root preparation report",
                format!("preparation {request_ordinal} does not match its requested root"),
            ));
        }
        if let Some(scope) = expected_scope.as_ref() {
            if scope != &preparation.expected_scope {
                return Err(invalid(
                    "root preparation report",
                    format!("preparation {request_ordinal} has a different expected scope"),
                ));
            }
        } else {
            expected_scope = Some(preparation.expected_scope.clone());
        }
        match &preparation.outcome {
            TypedPanicRootPreparationOutcome::Evaluatable {
                report_index,
                root: prepared_root,
                selected_function,
            } => {
                if *report_index != ready_roots.len() {
                    return Err(invalid(
                        "root preparation report",
                        format!(
                            "preparation {request_ordinal} maps to nondense ready report {report_index}"
                        ),
                    ));
                }
                let binding = batch
                    .prepared_root_bindings
                    .get(*report_index)
                    .ok_or_else(|| {
                        invalid(
                            "root preparation report",
                            format!(
                                "preparation {request_ordinal} has no producer-owned root binding"
                            ),
                        )
                    })?;
                if prepared_root.domain != panic_domain()
                    || prepared_root.entity.entity().schema.as_str() != FunctionEntity::ID
                    || prepared_root.entity.scope() != &preparation.expected_scope
                    || binding.root != *prepared_root
                    || binding.selected_function != *selected_function
                    || !is_root_resolution_candidate(
                        preparation.requested_function,
                        *selected_function,
                    )
                {
                    return Err(invalid(
                        "root preparation report",
                        format!(
                            "preparation {request_ordinal} has an invalid prepared evaluation root"
                        ),
                    ));
                }
                ready_roots.push(root.clone());
                ready_preparations.push(preparation);
            }
            TypedPanicRootPreparationOutcome::Missing { reason } => {
                let expected = IncompleteReason::MissingBody {
                    function: root.function,
                    path: root.path.clone(),
                    source_range: None,
                    trace: InterpretedTrace { steps: Vec::new() },
                };
                if reason != &expected {
                    return Err(invalid(
                        "root preparation report",
                        format!(
                            "preparation {request_ordinal} has fabricated or mismatched missing-root evidence"
                        ),
                    ));
                }
            }
        }
    }
    if batch.prepared_root_bindings.len() != ready_roots.len() {
        return Err(invalid(
            "root preparation batch",
            "producer-owned root bindings are not dense with evaluatable requests",
        ));
    }

    let call_findings = validate_report_roots(&batch.roots, &ready_roots)?;
    validate_compiler_assert_report_roots(&batch.compiler_asserts, &ready_roots)?;
    validate_root_contract_report_roots(&batch.root_contracts, &ready_roots)?;
    validate_completeness_report_roots(&batch.completeness, &ready_roots)?;
    validate_ambiguity_report_roots(&batch.ambiguities, &ready_roots)?;

    for (report_index, preparation) in ready_preparations.into_iter().enumerate() {
        let TypedPanicRootPreparationOutcome::Evaluatable {
            root: prepared_root,
            ..
        } = &preparation.outcome
        else {
            unreachable!("ready preparations are selected from evaluatable outcomes");
        };
        let binding = &batch.prepared_root_bindings[report_index];
        if let (Some(function), Some(path)) = (
            batch.root_contracts[report_index].selected_function,
            batch.root_contracts[report_index].selected_path.as_deref(),
        ) && (function != function_id(binding.selected_function)
            || path != binding.selected_path.as_str())
        {
            return Err(invalid(
                "sparse root report batch",
                format!(
                    "ready root-contract report {report_index} disagrees with its prepared body"
                ),
            ));
        }
        if batch.compiler_asserts[report_index].root != *prepared_root
            || batch.roots[report_index].root != *prepared_root
            || batch.root_contracts[report_index].root != *prepared_root
            || batch.completeness[report_index].root != *prepared_root
            || batch.ambiguities[report_index].root != *prepared_root
        {
            return Err(invalid(
                "sparse root report batch",
                format!(
                    "ready report {report_index} disagrees across lanes or with its prepared root"
                ),
            ));
        }
    }
    Ok(TypedPanicCallBatchPreflight {
        ready_roots,
        call_findings,
    })
}

fn is_root_resolution_candidate(requested: FunctionKey, selected: FunctionKey) -> bool {
    selected == requested
        || requested.instance().is_some()
            && selected == FunctionKey::new(requested.definition(), None)
}

fn validate_compiler_assert_report_roots(
    reports: &[TypedPanicRootReport],
    roots: &[InterpretationRoot],
) -> Result<(), TypedPanicCallEvaluationError> {
    if reports.len() != roots.len() {
        return Err(invalid(
            "compiler-assert report batch",
            format!(
                "returned {} roots for {} requests",
                reports.len(),
                roots.len()
            ),
        ));
    }
    for (index, (report, root)) in reports.iter().zip(roots).enumerate() {
        if report.function != root.function
            || report.path != root.path
            || report.kind != root.kind
            || report.root.domain != panic_domain()
            || report.root.entity.entity().schema.as_str() != FunctionEntity::ID
        {
            return Err(invalid(
                "compiler-assert root report",
                format!("report {index} does not match its requested root"),
            ));
        }
        for issue in &report.issues {
            if issue.issue.context.root != report.root {
                return Err(invalid(
                    "compiler-assert issue report",
                    format!("an issue under root report {index} belongs to another root"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn adapt_typed_panic_call_completeness_reports(
    sources: &impl FindingSources,
    reports: Vec<TypedPanicCompletenessRootReport>,
    roots: &[InterpretationRoot],
    show_full_stack_trace: bool,
) -> Result<Vec<Finding>, TypedPanicCallEvaluationError> {
    validate_completeness_report_roots(&reports, roots)?;
    let capacity = reports.iter().map(|report| report.issues.len()).sum();
    let mut findings = Vec::with_capacity(capacity);
    for report in reports {
        let root = InterpretationRoot {
            function: report.function,
            path: report.path,
            kind: report.kind,
        };
        for issue in report.issues {
            findings.push(adapt_typed_panic_incomplete_finding(
                sources,
                &root,
                issue.reason,
                show_full_stack_trace,
            ));
        }
    }
    Ok(findings)
}

fn validate_completeness_report_roots(
    reports: &[TypedPanicCompletenessRootReport],
    roots: &[InterpretationRoot],
) -> Result<(), TypedPanicCallEvaluationError> {
    if reports.len() != roots.len() {
        return Err(invalid(
            "completeness report batch",
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
                "completeness root report",
                format!("report {index} does not match its requested root"),
            ));
        }
        let mut previous_order = None;
        for issue in &report.issues {
            if issue.root != report.root {
                return Err(invalid(
                    "completeness issue report",
                    format!("an issue under root report {index} belongs to another root"),
                ));
            }
            if previous_order.is_some_and(|previous| previous >= issue.traversal_order) {
                return Err(invalid(
                    "completeness issue report",
                    format!("issues under root report {index} are not in traversal order"),
                ));
            }
            previous_order = Some(issue.traversal_order);
        }
    }
    Ok(())
}

fn validate_root_contract_report_roots(
    reports: &[TypedPanicRootContractRootReport],
    roots: &[InterpretationRoot],
) -> Result<(), TypedPanicCallEvaluationError> {
    if reports.len() != roots.len() {
        return Err(invalid(
            "root-contract report batch",
            format!(
                "returned {} roots for {} requests",
                reports.len(),
                roots.len()
            ),
        ));
    }
    for (index, (report, root)) in reports.iter().zip(roots).enumerate() {
        if report.function != root.function
            || report.path != root.path
            || report.kind != root.kind
            || report.root.domain != panic_domain()
            || report.root.entity.entity().schema.as_str() != FunctionEntity::ID
        {
            return Err(invalid(
                "root-contract root report",
                format!("report {index} does not match its requested root"),
            ));
        }
        match (&report.selected_function, &report.selected_path) {
            (Some(function), Some(path))
                if !path.is_empty()
                    && root
                        .function
                        .resolution_candidates()
                        .any(|candidate| candidate == *function) => {}
            (None, None) if report.issues.is_empty() => {}
            _ => {
                return Err(invalid(
                    "root-contract root report",
                    format!("report {index} has an invalid selected-body identity"),
                ));
            }
        }
        let mut previous_name = None;
        for issue in &report.issues {
            let mut previous_ordinal = None;
            if issue.root != report.root
                || report.selected_function.as_ref() != Some(&issue.function)
                || report.selected_path.as_deref() != Some(issue.function_path.as_str())
                || issue.function_path.is_empty()
                || issue.normalized_name.is_empty()
                || issue.requirements.len() < 2
                || issue.requirements.iter().any(|requirement| {
                    let out_of_order =
                        previous_ordinal.is_some_and(|previous| previous >= requirement.ordinal);
                    previous_ordinal = Some(requirement.ordinal);
                    out_of_order
                        || requirement_name_normalized(&requirement.name) != issue.normalized_name
                })
            {
                return Err(invalid(
                    "root-contract issue report",
                    format!("an issue under root report {index} is not a complete normal DTO"),
                ));
            }
            if previous_name.is_some_and(|previous| previous >= issue.normalized_name.as_str()) {
                return Err(invalid(
                    "root-contract issue report",
                    format!("issues under root report {index} are not in normalized-name order"),
                ));
            }
            previous_name = Some(issue.normalized_name.as_str());
        }
    }
    Ok(())
}

fn validate_ambiguity_report_roots(
    reports: &[TypedPanicAmbiguityRootReport],
    roots: &[InterpretationRoot],
) -> Result<(), TypedPanicCallEvaluationError> {
    if reports.len() != roots.len() {
        return Err(invalid(
            "ambiguity report batch",
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
                "ambiguity root report",
                format!("report {index} does not match its requested root"),
            ));
        }
        for issue in &report.issues {
            if issue.root != report.root {
                return Err(invalid(
                    "ambiguity issue report",
                    format!("an issue under root report {index} belongs to another root"),
                ));
            }
            if issue.effect_count < 2
                || issue.function_path.is_empty()
                || issue.source_range.is_none()
                || issue.trace.steps.is_empty()
            {
                return Err(invalid(
                    "ambiguity issue report",
                    format!("an issue under root report {index} is not a complete normal DTO"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_report_roots(
    reports: &[TypedPanicCallRootReport],
    roots: &[InterpretationRoot],
) -> Result<Vec<Vec<InterpretedFinding>>, TypedPanicCallEvaluationError> {
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
    let mut projected = Vec::with_capacity(reports.len());
    for (index, (report, root)) in reports.iter().zip(roots).enumerate() {
        if report.function != root.function || report.path != root.path || report.kind != root.kind
        {
            return Err(invalid(
                "root report",
                format!("report {index} does not match its requested root"),
            ));
        }
        let mut report_findings = Vec::with_capacity(report.issues.len());
        for issue in &report.issues {
            if issue.root != report.root {
                return Err(invalid(
                    "issue report",
                    format!("an issue under root report {index} belongs to another root"),
                ));
            }
            report_findings.push(interpreted_finding(issue)?);
        }
        projected.push(report_findings);
    }
    Ok(projected)
}

#[cfg(test)]
std::thread_local! {
    static INTERPRETED_FINDING_PROJECTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_interpreted_finding_projections() {
    INTERPRETED_FINDING_PROJECTIONS.set(0);
}

#[cfg(test)]
fn interpreted_finding_projections() -> usize {
    INTERPRETED_FINDING_PROJECTIONS.get()
}

fn interpreted_finding(
    report: &TypedPanicCallIssueReport,
) -> Result<InterpretedFinding, TypedPanicCallEvaluationError> {
    #[cfg(test)]
    INTERPRETED_FINDING_PROJECTIONS.set(INTERPRETED_FINDING_PROJECTIONS.get() + 1);
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

pub(super) const fn call_edge_kind(kind: CallKind) -> CallEdgeKindIr {
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
fn evaluate_typed_panic_call_with_completeness<'a>(
    local: TypedPanicLocalArtifact<'_>,
    dependencies: impl IntoIterator<Item = &'a ArtifactAnalysisCache>,
    active_runtime_artifacts: &[RustcArtifactId],
    root: &InterpretationRoot,
    config: &SniffTestConfig,
) -> Result<
    (TypedPanicCallRootReport, TypedPanicCompletenessRootReport),
    TypedPanicCallEvaluationError,
> {
    let dependencies = dependencies.into_iter().collect::<Vec<_>>();
    let direct_dependencies = dependencies
        .iter()
        .map(|dependency| dependency.artifact.id.clone())
        .collect();
    let mut batch = evaluate_typed_panic_call_roots(
        local,
        &dependencies,
        direct_dependencies,
        active_runtime_artifacts,
        std::slice::from_ref(root),
        config,
    )?;
    let call = batch
        .roots
        .pop()
        .expect("one root request produces one typed panic-call report");
    let completeness = batch
        .completeness
        .pop()
        .expect("one root request produces one typed panic-completeness report");
    Ok((call, completeness))
}

#[cfg(test)]
fn evaluate_typed_panic_call_with_projection_fixture<'a>(
    local: TypedPanicLocalArtifact<'_>,
    dependencies: impl IntoIterator<Item = &'a ArtifactAnalysisCache>,
    active_runtime_artifacts: &[RustcArtifactId],
    root: &InterpretationRoot,
    config: &SniffTestConfig,
) -> Result<
    (
        TypedPanicCallRootReport,
        TypedPanicCompletenessRootReport,
        TypedPanicCallProjectionFixture,
    ),
    TypedPanicCallEvaluationError,
> {
    let dependencies = dependencies.into_iter().collect::<Vec<_>>();
    let direct_dependencies = dependencies
        .iter()
        .map(|dependency| dependency.artifact.id.clone())
        .collect();
    let mut projection_fixture = None;
    let mut batch = evaluate_typed_panic_call_roots_inner(
        local,
        &dependencies,
        direct_dependencies,
        active_runtime_artifacts,
        std::slice::from_ref(root),
        config,
        Some(&mut projection_fixture),
        None,
    )?;
    let report = batch
        .roots
        .pop()
        .expect("one root request produces one typed panic-call report");
    let completeness = batch
        .completeness
        .pop()
        .expect("one root request produces one typed panic-completeness report");
    let projection_fixture = projection_fixture.ok_or_else(|| {
        invalid(
            "test projection fixture",
            "single-root evaluation did not expose its pre-projection rows",
        )
    })?;
    Ok((report, completeness, projection_fixture))
}

#[cfg(test)]
fn evaluate_typed_panic_call_with_ambiguity_corruption(
    local: TypedPanicLocalArtifact<'_>,
    root: &InterpretationRoot,
    config: &SniffTestConfig,
    corruption: AmbiguityProjectionCorruption,
) -> Result<TypedPanicCallBatchReport, TypedPanicCallEvaluationError> {
    evaluate_typed_panic_call_roots_inner(
        local,
        &[],
        Vec::new(),
        &[],
        std::slice::from_ref(root),
        config,
        None,
        Some(corruption),
    )
}

#[cfg(test)]
pub(super) mod tests;
