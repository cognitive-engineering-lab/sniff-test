//! Workspace-branded root traversal inputs for typed safety evaluation.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use super::{
    EffectiveSafetyContract, WorkspaceEffectiveSafetyContracts,
    WorkspaceEffectiveSafetyContractsError,
};
use crate::analysis::facts::composition::{
    CompositionRelationBuilder, CompositionRelationRegistry, WorkspaceRelationGraph,
};
use crate::analysis::facts::evaluation::{DomainId, EvaluationRoot};
use crate::analysis::facts::program::FunctionKey;
use crate::analysis::facts::program::root_traversal::{
    BodyPolicyContext, BodyTraversalDecision, CallPolicyContext, CallTargetPolicyCandidate,
    CallTargetSelection, CallTraversalDecision, DefiningMarkerCandidate, DefiningMarkerDecision,
    DefiningMarkerPolicyContext, EmittedRootProgramTraversal, MarkerProbe,
    PreparedRootProgramTraversal, ProgramCallResolution, ReconciledCallTargetPolicyCandidate,
    ResolvedRootProgramTraversal, RootProgramTraversalError, RootProgramTraversalPolicy,
    RootProgramTraversalRequest,
};
use crate::analysis::facts::program::topology::{
    CallAttributionRole, CallKind, CallTargetRole, CallableEntity,
};
use crate::analysis::facts::program::workspace_index::ScopedProgramEntity;
use crate::analysis::facts::workspace::{ArtifactScopeId, WorkspaceFactView};
use crate::analysis::facts::workspace::{ScopedEntityId, WorkspaceIdentity};
use crate::analysis::workspace_closure::VerifiedWorkspaceClosure;
use crate::config::SafetyConfig;
use crate::contracts::ContractDocOverrides;

const SAFETY_DOMAIN: &str = "sniff-test.safety";

#[must_use]
pub(crate) fn safety_domain() -> DomainId {
    DomainId::new(SAFETY_DOMAIN).expect("the safety domain ID is static and valid")
}

/// Domain-neutral knobs required to prepare one safety root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SafetyRootRequest {
    root: FunctionKey,
    attribution: CallAttributionRole,
    marker_probe: MarkerProbe,
    node_budget: usize,
}

impl SafetyRootRequest {
    #[must_use]
    pub(crate) const fn new(
        root: FunctionKey,
        attribution: CallAttributionRole,
        marker_probe: MarkerProbe,
        node_budget: usize,
    ) -> Self {
        Self {
            root,
            attribution,
            marker_probe,
            node_budget,
        }
    }

    fn traversal_request(&self, root_scope: ArtifactScopeId) -> RootProgramTraversalRequest {
        RootProgramTraversalRequest::new(
            safety_domain(),
            root_scope,
            self.root,
            self.attribution,
            self.marker_probe,
            self.node_budget,
        )
    }
}

/// Why safety traversal intentionally stopped before entering a body or call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SafetyBoundary {
    RootContract(Arc<EffectiveSafetyContract>),
    CallContract(SafetyContractCallBoundary),
    TrustedNamespace,
    UndocumentedUnsafeCall,
    ForeignDeclaration,
    BodylessDeclaration,
    OpaqueCall { description: String },
    BuiltinUnsafe,
}

/// Exact documented call boundary retained for safety obligation evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SafetyContractCallBoundary {
    contract: Arc<EffectiveSafetyContract>,
    contract_target: CallTargetSelection,
    trusted: bool,
}

impl SafetyContractCallBoundary {
    #[must_use]
    pub(crate) const fn contract(&self) -> &Arc<EffectiveSafetyContract> {
        &self.contract
    }

    #[must_use]
    pub(crate) const fn contract_target(&self) -> &CallTargetSelection {
        &self.contract_target
    }

    #[must_use]
    pub(crate) const fn trusted(&self) -> bool {
        self.trusted
    }
}

/// Immutable traversal plus root-scoped safety metadata.
#[derive(Clone, Debug)]
pub(crate) struct SafetyRootInputs {
    traversal: ResolvedRootProgramTraversal<SafetyBoundary>,
    root_callable: ScopedEntityId<CallableEntity>,
    root_callable_data: CallableEntity,
    root_missing_safety_docs: bool,
}

impl SafetyRootInputs {
    #[must_use]
    pub(in crate::analysis::facts) const fn workspace_identity(&self) -> &Arc<WorkspaceIdentity> {
        self.traversal.workspace_identity()
    }

    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        self.traversal.root()
    }

    #[must_use]
    pub(crate) fn traversal(&self) -> &ResolvedRootProgramTraversal<SafetyBoundary> {
        &self.traversal
    }

    #[must_use]
    pub(crate) const fn root_callable(&self) -> &ScopedEntityId<CallableEntity> {
        &self.root_callable
    }

    #[must_use]
    pub(crate) const fn root_callable_data(&self) -> &CallableEntity {
        &self.root_callable_data
    }

    #[must_use]
    pub(crate) const fn root_missing_safety_docs(&self) -> bool {
        self.root_missing_safety_docs
    }
}

/// All requested safety roots prepared atomically before composition mutation.
#[derive(Debug)]
pub(crate) struct PreparedSafetyRootBatch {
    roots: Vec<PreparedSafetyRoot>,
}

impl PreparedSafetyRootBatch {
    pub(crate) fn prepare(
        workspace: &WorkspaceFactView<'_>,
        closure: &VerifiedWorkspaceClosure,
        safety: &SafetyConfig,
        overrides: &ContractDocOverrides,
        requests: impl IntoIterator<Item = SafetyRootRequest>,
    ) -> Result<Self, SafetyRootInputError> {
        let requests = requests.into_iter().collect::<Vec<_>>();
        if requests.is_empty() {
            return Ok(Self { roots: Vec::new() });
        }
        let program = closure.program().clone();
        let defining_scopes = closure.defining_scopes_handle();
        let contracts = Arc::new(
            WorkspaceEffectiveSafetyContracts::open(workspace, &program, overrides)
                .map_err(|source| SafetyRootInputError::Contracts(Box::new(source)))?,
        );
        let mut roots = Vec::with_capacity(requests.len());
        for request in requests {
            let traversal_request = request.traversal_request(closure.root_scope().clone());
            let mut policy = SafetyTraversalPolicy::new(workspace, safety, contracts.as_ref());
            let traversal = PreparedRootProgramTraversal::prepare(
                workspace,
                &program,
                defining_scopes.as_ref(),
                &traversal_request,
                &mut policy,
            )
            .map_err(|source| SafetyRootInputError::Traversal(Box::new(source)))?;
            roots.push(PreparedSafetyRoot {
                traversal,
                root_callable: policy.root_callable.ok_or_else(|| {
                    SafetyRootInputError::InvalidPreparedInput {
                        reason: String::from("safety traversal did not retain its root callable"),
                    }
                })?,
                root_missing_safety_docs: policy.root_missing_safety_docs,
            });
        }
        Ok(Self { roots })
    }

    #[must_use]
    pub(crate) fn into_roots(self) -> Vec<PreparedSafetyRoot> {
        self.roots
    }
}

#[derive(Debug)]
pub(crate) struct PreparedSafetyRoot {
    traversal: PreparedRootProgramTraversal<SafetyBoundary, SafetyPolicyError>,
    root_callable: (ScopedEntityId<CallableEntity>, CallableEntity),
    root_missing_safety_docs: bool,
}

impl PreparedSafetyRoot {
    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        self.traversal.root()
    }

    pub(crate) fn emit(
        self,
        builder: &mut CompositionRelationBuilder<'_, '_>,
    ) -> Result<EmittedSafetyRoot, SafetyRootInputError> {
        let traversal = self
            .traversal
            .emit(builder)
            .map_err(|source| SafetyRootInputError::Traversal(Box::new(source)))?;
        Ok(EmittedSafetyRoot {
            traversal,
            root_callable: self.root_callable,
            root_missing_safety_docs: self.root_missing_safety_docs,
        })
    }
}

#[derive(Debug)]
pub(crate) struct EmittedSafetyRoot {
    traversal: EmittedRootProgramTraversal<SafetyBoundary, SafetyPolicyError>,
    root_callable: (ScopedEntityId<CallableEntity>, CallableEntity),
    root_missing_safety_docs: bool,
}

impl EmittedSafetyRoot {
    pub(crate) fn resolve(
        self,
        graph: &WorkspaceRelationGraph,
        registry: &CompositionRelationRegistry,
    ) -> Result<SafetyRootInputs, SafetyRootInputError> {
        let traversal = self
            .traversal
            .resolve(graph, registry)
            .map_err(|source| SafetyRootInputError::Traversal(Box::new(source)))?;
        Ok(SafetyRootInputs {
            traversal,
            root_callable: self.root_callable.0,
            root_callable_data: self.root_callable.1,
            root_missing_safety_docs: self.root_missing_safety_docs,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SafetyPolicyError {
    Contracts(Box<WorkspaceEffectiveSafetyContractsError>),
}

impl Display for SafetyPolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contracts(source) => Display::fmt(source, formatter),
        }
    }
}

impl Error for SafetyPolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contracts(source) => Some(source),
        }
    }
}

#[derive(Debug)]
pub(crate) enum SafetyRootInputError {
    Contracts(Box<WorkspaceEffectiveSafetyContractsError>),
    Traversal(Box<RootProgramTraversalError<SafetyPolicyError>>),
    InvalidPreparedInput { reason: String },
}

impl Display for SafetyRootInputError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contracts(source) => Display::fmt(source, formatter),
            Self::Traversal(source) => Display::fmt(source, formatter),
            Self::InvalidPreparedInput { reason } => {
                write!(formatter, "invalid prepared safety input: {reason}")
            }
        }
    }
}

impl Error for SafetyRootInputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contracts(source) => Some(source),
            Self::Traversal(source) => Some(source),
            Self::InvalidPreparedInput { .. } => None,
        }
    }
}

struct EffectiveTarget<'a> {
    callable: &'a ScopedProgramEntity<CallableEntity>,
    selection: CallTargetSelection,
}

struct EffectiveContractTarget {
    contract: Arc<EffectiveSafetyContract>,
    selection: CallTargetSelection,
}

struct SafetyTraversalPolicy<'workspace, 'facts> {
    workspace: &'workspace WorkspaceFactView<'facts>,
    safety: &'workspace SafetyConfig,
    contracts: &'workspace WorkspaceEffectiveSafetyContracts,
    root_missing_safety_docs: bool,
    root_callable: Option<(ScopedEntityId<CallableEntity>, CallableEntity)>,
}

impl<'workspace, 'facts> SafetyTraversalPolicy<'workspace, 'facts> {
    const fn new(
        workspace: &'workspace WorkspaceFactView<'facts>,
        safety: &'workspace SafetyConfig,
        contracts: &'workspace WorkspaceEffectiveSafetyContracts,
    ) -> Self {
        Self {
            workspace,
            safety,
            contracts,
            root_missing_safety_docs: false,
            root_callable: None,
        }
    }

    fn effective_contract(
        &self,
        callable: &ScopedProgramEntity<CallableEntity>,
    ) -> Result<Option<Arc<EffectiveSafetyContract>>, SafetyPolicyError> {
        self.contracts
            .effective_safety_contract(self.workspace, &callable.id())
            .map_err(|source| SafetyPolicyError::Contracts(Box::new(source)))
    }

    fn call_contract_target(
        &self,
        context: &CallPolicyContext<'_>,
    ) -> Result<Option<EffectiveContractTarget>, SafetyPolicyError> {
        if let Some(reconciliation) = &context.reconciliation {
            for target in &reconciliation.contract_targets {
                if let Some(contract) = self.effective_contract(target.callable)? {
                    return Ok(Some(EffectiveContractTarget {
                        contract,
                        selection: target.selection(),
                    }));
                }
            }
            return Ok(None);
        }
        if let Some(source) = context
            .targets
            .iter()
            .find(|target| target.role == CallTargetRole::SourceContract)
            && let Some(contract) = self.effective_contract(source.callable)?
        {
            return Ok(Some(EffectiveContractTarget {
                contract,
                selection: source.selection(),
            }));
        }
        let raw = effective_raw_target(context.targets);
        if let Some(raw) = raw
            && let Some(contract) = self.effective_contract(raw.callable)?
        {
            return Ok(Some(EffectiveContractTarget {
                contract,
                selection: raw.selection,
            }));
        }
        Ok(None)
    }

    fn decide_targeted_call(
        &self,
        context: &CallPolicyContext<'_>,
        metadata: EffectiveTarget<'_>,
    ) -> Result<CallTraversalDecision<SafetyBoundary>, SafetyPolicyError> {
        let attributes = metadata.callable.data();
        if self
            .safety
            .ignores_candidates(attributes.namespace_candidates())
        {
            return Ok(CallTraversalDecision::Ignore);
        }
        if let Some(contract_target) = self.call_contract_target(context)? {
            let payload = if context.occurrence.data().inside_builtin_unsafe() {
                SafetyBoundary::BuiltinUnsafe
            } else {
                SafetyBoundary::CallContract(SafetyContractCallBoundary {
                    contract: contract_target.contract,
                    contract_target: contract_target.selection,
                    trusted: self
                        .safety
                        .trusts_safety_boundary_candidates(attributes.namespace_candidates()),
                })
            };
            return Ok(call_boundary(metadata.selection, payload));
        }
        if self
            .safety
            .trusts_safety_boundary_candidates(attributes.namespace_candidates())
        {
            return Ok(call_boundary(
                metadata.selection,
                SafetyBoundary::TrustedNamespace,
            ));
        }
        if attributes.is_foreign() {
            return Ok(call_boundary(
                metadata.selection,
                SafetyBoundary::ForeignDeclaration,
            ));
        }
        if !attributes.has_rust_body() {
            return Ok(call_boundary(
                metadata.selection,
                SafetyBoundary::BodylessDeclaration,
            ));
        }
        if matches!(context.resolution, ProgramCallResolution::Persisted)
            && let Some(description) = context.occurrence.data().opaque_target_description()
        {
            return Ok(call_boundary(
                metadata.selection,
                SafetyBoundary::OpaqueCall {
                    description: normalized_opaque_description(
                        context.effective_kind,
                        context.occurrence.data().requires_unsafe(),
                        description,
                    ),
                },
            ));
        }
        if context.occurrence.data().requires_unsafe()
            && is_actual_call(context.effective_kind)
            && !context.occurrence.data().inside_builtin_unsafe()
        {
            return Ok(CallTraversalDecision::FollowAndBoundary {
                follow: metadata.selection.clone(),
                boundary_target: Some(metadata.selection),
                payload: SafetyBoundary::UndocumentedUnsafeCall,
            });
        }
        Ok(CallTraversalDecision::Follow(metadata.selection))
    }
}

impl RootProgramTraversalPolicy for SafetyTraversalPolicy<'_, '_> {
    type Error = SafetyPolicyError;
    type Boundary = SafetyBoundary;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        if let Some(metadata) = effective_metadata_target(context) {
            return self.decide_targeted_call(context, metadata);
        }
        let Some(description) = context.occurrence.data().opaque_target_description() else {
            return Ok(CallTraversalDecision::Ignore);
        };
        if !is_actual_call(context.effective_kind) {
            return Ok(CallTraversalDecision::Ignore);
        }
        Ok(CallTraversalDecision::Boundary {
            target: None,
            payload: SafetyBoundary::OpaqueCall {
                description: normalized_opaque_description(
                    context.effective_kind,
                    context.occurrence.data().requires_unsafe(),
                    description,
                ),
            },
        })
    }

    fn decide_body(
        &mut self,
        context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        let attributes = context.callable.data();
        if context.is_root {
            self.root_callable = Some((context.callable.id(), attributes.clone()));
        }
        if self
            .safety
            .ignores_candidates(attributes.namespace_candidates())
        {
            return Ok(BodyTraversalDecision::Ignore);
        }
        if context.is_root {
            if let Some(contract) = self.effective_contract(context.callable)? {
                return Ok(BodyTraversalDecision::Boundary(
                    SafetyBoundary::RootContract(contract),
                ));
            }
            self.root_missing_safety_docs = attributes.is_exported() && attributes.is_unsafe();
            if self
                .safety
                .trusts_safety_boundary_candidates(attributes.namespace_candidates())
            {
                return Ok(BodyTraversalDecision::Boundary(
                    SafetyBoundary::TrustedNamespace,
                ));
            }
        }
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(if candidates_share_call_site(context.candidates) {
            DefiningMarkerDecision::UseCompleteSet
        } else {
            DefiningMarkerDecision::RejectCompleteSet
        })
    }
}

fn effective_metadata_target<'a>(
    context: &'a CallPolicyContext<'a>,
) -> Option<EffectiveTarget<'a>> {
    context
        .reconciliation
        .as_ref()
        .and_then(|reconciliation| reconciliation.effective_metadata_targets.first())
        .map(reconciled_target)
        .or_else(|| effective_persisted_metadata_target(context.targets))
}

fn effective_persisted_metadata_target<'a>(
    targets: &'a [CallTargetPolicyCandidate<'a>],
) -> Option<EffectiveTarget<'a>> {
    effective_raw_target(targets).or_else(|| {
        targets
            .iter()
            .find(|target| target.role == CallTargetRole::SourceContract)
            .map(|target| EffectiveTarget {
                callable: target.callable,
                selection: target.selection(),
            })
    })
}

fn effective_raw_target<'a>(
    targets: &'a [CallTargetPolicyCandidate<'a>],
) -> Option<EffectiveTarget<'a>> {
    targets
        .iter()
        .filter(|target| {
            matches!(
                target.role,
                CallTargetRole::Runtime
                    | CallTargetRole::OpaqueTrait
                    | CallTargetRole::OpaqueFunction
            )
        })
        .min_by_key(|target| raw_role_precedence(target.role))
        .map(|target| EffectiveTarget {
            callable: target.callable,
            selection: target.selection(),
        })
}

fn reconciled_target<'a>(target: &ReconciledCallTargetPolicyCandidate<'a>) -> EffectiveTarget<'a> {
    EffectiveTarget {
        callable: target.callable,
        selection: target.selection(),
    }
}

const fn raw_role_precedence(role: CallTargetRole) -> u8 {
    match role {
        CallTargetRole::Runtime => 0,
        CallTargetRole::OpaqueTrait => 1,
        CallTargetRole::OpaqueFunction => 2,
        CallTargetRole::SourceContract => 3,
    }
}

const fn is_actual_call(kind: CallKind) -> bool {
    matches!(
        kind,
        CallKind::DirectCall
            | CallKind::TailCall
            | CallKind::FnPointerCallTarget
            | CallKind::DynDispatchVTableEntry
            | CallKind::IndirectCall
    )
}

fn normalized_opaque_description(kind: CallKind, requires_unsafe: bool, raw: &str) -> String {
    if kind != CallKind::IndirectCall {
        return raw.to_owned();
    }
    if requires_unsafe {
        String::from("indirect call through an unsafe function pointer")
    } else {
        String::from("indirect call through a function pointer")
    }
}

fn candidates_share_call_site(candidates: &[DefiningMarkerCandidate]) -> bool {
    let Some(first) = candidates.first() else {
        return false;
    };
    candidates.iter().all(|candidate| {
        candidate.call_site == first.call_site && candidate.call_site_data == first.call_site_data
    })
}

const fn call_boundary(
    target: CallTargetSelection,
    payload: SafetyBoundary,
) -> CallTraversalDecision<SafetyBoundary> {
    CallTraversalDecision::Boundary {
        target: Some(target),
        payload,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        PreparedSafetyRootBatch, SafetyBoundary, SafetyRootRequest, normalized_opaque_description,
    };
    use crate::analysis::cache::RustcArtifactId;
    use crate::analysis::facts::builder::{ArtifactDbBuilder, FactMeta};
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::composition::{
        CompositionRelationBuilder, WorkspaceEvaluationView, WorkspaceRelationIndex,
    };
    use crate::analysis::facts::evaluation::EvaluationDb;
    use crate::analysis::facts::evidence::{
        AmbiguousEvidenceReuseIssue, EvidenceCoordinatorPack, EvidenceUseRecord,
    };
    use crate::analysis::facts::human::EvidenceClaimSelector;
    use crate::analysis::facts::human::markers::{
        MarkerClaimEntity, MarkerClaimKey, MarkerOccurrenceEntity, MarkerOccurrenceHasClaim,
        MarkerOccurrenceHasSourceAnchor, MarkerOccurrenceKey,
        UnsafeOperationHasMarkerClaimCandidate,
    };
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::program::root_traversal::MarkerProbe;
    use crate::analysis::facts::program::topology::{
        CallAttributionRole, CallKind, CallOccurrenceEntity, CallOccurrenceInSafetyEffectGroup,
        CallOccurrenceKey, CallOccurrenceTargetsCallable, CallSiteEntity, CallSiteHasOccurrence,
        CallSiteKey, CallTargetRole, CallableEntity, FunctionDefinesCallable, FunctionOwnsCallSite,
        FunctionOwnsSafetyEffectGroup, SafetyEffectGroupEntity, SafetyEffectGroupKey,
    };
    use crate::analysis::facts::program::{
        FunctionBodyProvenance, FunctionEntity, FunctionKey, SourceAnchorEntity,
        SourceAnchorInFile, SourceAnchorKey, SourceFileEntity,
    };
    use crate::analysis::facts::schema::PassId;
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::analysis::facts::workspace::{ArtifactScopeId, WorkspaceFactView};
    use crate::analysis::workspace_closure::{
        ManagedArtifactGeneration, ManagedArtifactManifest, VerifiedWorkspaceClosure,
    };
    use crate::config::SafetyConfig;
    use crate::contracts::ContractDocOverrides;
    use crate::namespace::{StableDefPathHash, StableInstanceHash};

    use super::super::collector::COLLECT_SAFETY_ARTIFACT_PASS;
    use super::super::operations::{
        FunctionOwnsUnsafeOperation, SafetyOperationKind, UnsafeOperationEntity,
        UnsafeOperationInSafetyEffectGroup, UnsafeOperationKey,
    };
    use super::super::{
        DuplicateSafetyRootRequirementIssue, IndirectSafetyCallBoundaryIssue,
        MissingSafetyDocsIssue, SafetyCallIssuePack, SafetyCompletenessOutcome,
        SafetyCompletenessPack, SafetyContractFact, SafetyEvidenceUsePack,
        SafetyOperationIssuePack, SafetyRequirement, SafetyRootInputs, SafetyRootIssuePack,
        UnsatisfiedSafetyCallIssue, UnsatisfiedUnsafeOperationIssue,
    };

    pub(crate) fn root_key() -> FunctionKey {
        FunctionKey::new(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000031\"")
                .unwrap(),
            None,
        )
    }

    #[allow(
        clippy::fn_params_excessive_bools,
        clippy::too_many_lines,
        reason = "the test fixture exposes independent traversal-policy switches in one canonical artifact"
    )]
    pub(crate) fn root_artifact(
        has_contract: bool,
        has_operation_marker: bool,
        call_marker: Option<bool>,
        has_opaque_call: bool,
        second_marked_operation: bool,
    ) -> (
        AnalysisRegistry<()>,
        crate::analysis::facts::encoded::ArtifactFactIr,
    ) {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let root = root_key();
        let body = builder
            .insert_entity(&FunctionEntity::new(
                root,
                "crate::root",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let callable = builder
            .insert_entity(&CallableEntity::new(
                root,
                "crate::root",
                true,
                true,
                true,
                false,
                vec![String::from("crate::root")],
            ))
            .unwrap();
        builder
            .relate(&body, &callable, &FunctionDefinesCallable::new())
            .unwrap();
        let group = builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                root, 0,
            )))
            .unwrap();
        builder
            .relate(&body, &group, &FunctionOwnsSafetyEffectGroup::new())
            .unwrap();
        let operation = builder
            .insert_entity(&UnsafeOperationEntity::new(
                UnsafeOperationKey::new(root, 0),
                SafetyOperationKind::DerefRawPointer,
            ))
            .unwrap();
        builder
            .relate(&body, &operation, &FunctionOwnsUnsafeOperation::new())
            .unwrap();
        builder
            .relate(
                &operation,
                &group,
                &UnsafeOperationInSafetyEffectGroup::new(),
            )
            .unwrap();
        if has_operation_marker {
            let file = builder
                .insert_entity(&SourceFileEntity::new(
                    "src/lib.rs",
                    "src/lib.rs",
                    "verified-hash",
                    100,
                ))
                .unwrap();
            let anchor_key = SourceAnchorKey::new("src/lib.rs", 20, 40);
            let anchor = builder
                .insert_entity(&SourceAnchorEntity::new(anchor_key.clone()))
                .unwrap();
            builder
                .relate(&anchor, &file, &SourceAnchorInFile::new())
                .unwrap();
            let occurrence_key = MarkerOccurrenceKey::new(anchor_key, None);
            let occurrence = builder
                .insert_entity(&MarkerOccurrenceEntity::new(
                    occurrence_key.clone(),
                    Vec::new(),
                ))
                .unwrap();
            builder
                .relate(
                    &occurrence,
                    &anchor,
                    &MarkerOccurrenceHasSourceAnchor::new(),
                )
                .unwrap();
            let claim = builder
                .insert_entity(&MarkerClaimEntity::new(
                    MarkerClaimKey::new(occurrence_key, super::safety_domain(), 0),
                    EvidenceClaimSelector::Unnamed,
                    "the raw pointer is valid and aligned",
                ))
                .unwrap();
            builder
                .relate(&occurrence, &claim, &MarkerOccurrenceHasClaim::new())
                .unwrap();
            builder
                .relate(
                    &operation,
                    &claim,
                    &UnsafeOperationHasMarkerClaimCandidate::new(true, false),
                )
                .unwrap();
            if second_marked_operation {
                let second_group = builder
                    .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                        root, 1,
                    )))
                    .unwrap();
                builder
                    .relate(&body, &second_group, &FunctionOwnsSafetyEffectGroup::new())
                    .unwrap();
                let second_operation = builder
                    .insert_entity(&UnsafeOperationEntity::new(
                        UnsafeOperationKey::new(root, 1),
                        SafetyOperationKind::DerefRawPointer,
                    ))
                    .unwrap();
                builder
                    .relate(
                        &body,
                        &second_operation,
                        &FunctionOwnsUnsafeOperation::new(),
                    )
                    .unwrap();
                builder
                    .relate(
                        &second_operation,
                        &second_group,
                        &UnsafeOperationInSafetyEffectGroup::new(),
                    )
                    .unwrap();
                builder
                    .relate(
                        &second_operation,
                        &claim,
                        &UnsafeOperationHasMarkerClaimCandidate::new(true, false),
                    )
                    .unwrap();
            }
        }
        if let Some(satisfied) = call_marker {
            let target_key = FunctionKey::new(
                serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000032\"")
                    .unwrap(),
                Some(
                    serde_json::from_str::<StableInstanceHash>(
                        "\"00000000000000010000000000000042\"",
                    )
                    .unwrap(),
                ),
            );
            let target = builder
                .insert_entity(&CallableEntity::new(
                    target_key,
                    "crate::target",
                    false,
                    true,
                    false,
                    false,
                    vec![String::from("crate::target")],
                ))
                .unwrap();
            let site = builder
                .insert_entity(&CallSiteEntity::new(CallSiteKey::new(root, 0)))
                .unwrap();
            builder
                .relate(&body, &site, &FunctionOwnsCallSite::new())
                .unwrap();
            let occurrence = builder
                .insert_entity(&CallOccurrenceEntity::new(
                    CallOccurrenceKey::new(root, 0),
                    CallKind::DirectCall,
                    vec![CallAttributionRole::CallSite],
                    false,
                    false,
                    None,
                ))
                .unwrap();
            builder
                .relate(&site, &occurrence, &CallSiteHasOccurrence::new())
                .unwrap();
            builder
                .relate(
                    &occurrence,
                    &group,
                    &CallOccurrenceInSafetyEffectGroup::new(),
                )
                .unwrap();
            builder
                .relate(
                    &occurrence,
                    &target,
                    &CallOccurrenceTargetsCallable::new(CallTargetRole::Runtime),
                )
                .unwrap();
            let mut metadata = FactMeta::new(PassId::new(COLLECT_SAFETY_ARTIFACT_PASS).unwrap())
                .with_owner(&target)
                .unwrap();
            for requirement in [
                SafetyRequirement::new(target_key, 0, "Valid", "the argument is valid", None),
                SafetyRequirement::new(target_key, 1, "VALID", "the argument remains valid", None),
            ] {
                let requirement = builder.insert_requirement(&requirement).unwrap();
                metadata = metadata.with_requirement(&requirement).unwrap();
            }
            builder
                .insert_fact(&SafetyContractFact::new(), metadata)
                .unwrap();
            if satisfied {
                let file = builder
                    .insert_entity(&SourceFileEntity::new(
                        "src/call.rs",
                        "src/call.rs",
                        "verified-call-hash",
                        100,
                    ))
                    .unwrap();
                let anchor_key = SourceAnchorKey::new("src/call.rs", 20, 40);
                let anchor = builder
                    .insert_entity(&SourceAnchorEntity::new(anchor_key.clone()))
                    .unwrap();
                builder
                    .relate(&anchor, &file, &SourceAnchorInFile::new())
                    .unwrap();
                let occurrence_key = MarkerOccurrenceKey::new(anchor_key, None);
                let marker = builder
                    .insert_entity(&MarkerOccurrenceEntity::new(
                        occurrence_key.clone(),
                        Vec::new(),
                    ))
                    .unwrap();
                builder
                    .relate(&marker, &anchor, &MarkerOccurrenceHasSourceAnchor::new())
                    .unwrap();
                let claim = builder
                    .insert_entity(&MarkerClaimEntity::new(
                        MarkerClaimKey::new(occurrence_key, super::safety_domain(), 0),
                        EvidenceClaimSelector::Named(String::from("VALID")),
                        "the argument came from a validated source",
                    ))
                    .unwrap();
                builder
                    .relate(&marker, &claim, &MarkerOccurrenceHasClaim::new())
                    .unwrap();
                builder
                    .relate(
                        &occurrence,
                        &claim,
                        &crate::analysis::facts::human::markers::CallOccurrenceHasMarkerClaimCandidate::new(true, false),
                    )
                    .unwrap();
            }
        }
        if has_opaque_call {
            let site = builder
                .insert_entity(&CallSiteEntity::new(CallSiteKey::new(root, 0)))
                .unwrap();
            builder
                .relate(&body, &site, &FunctionOwnsCallSite::new())
                .unwrap();
            let occurrence = builder
                .insert_entity(&CallOccurrenceEntity::new(
                    CallOccurrenceKey::new(root, 0),
                    CallKind::IndirectCall,
                    vec![CallAttributionRole::CallSite],
                    false,
                    false,
                    Some(String::from("opaque function pointer")),
                ))
                .unwrap();
            builder
                .relate(&site, &occurrence, &CallSiteHasOccurrence::new())
                .unwrap();
            builder
                .relate(
                    &occurrence,
                    &group,
                    &CallOccurrenceInSafetyEffectGroup::new(),
                )
                .unwrap();
        }
        if has_contract {
            let mut metadata = FactMeta::new(PassId::new(COLLECT_SAFETY_ARTIFACT_PASS).unwrap())
                .with_owner(&callable)
                .unwrap();
            for requirement in [
                SafetyRequirement::new(root, 0, "Valid", "the input is valid", None),
                SafetyRequirement::new(root, 1, "VALID", "the input remains valid", None),
            ] {
                let requirement = builder.insert_requirement(&requirement).unwrap();
                metadata = metadata.with_requirement(&requirement).unwrap();
            }
            builder
                .insert_fact(&SafetyContractFact::new(), metadata)
                .unwrap();
        }
        let artifact = builder.finalize(registry.schemas()).unwrap();
        (registry, artifact)
    }

    fn with_root<T>(
        has_contract: bool,
        has_operation_marker: bool,
        second_marked_operation: bool,
        inspect: impl FnOnce(
            &AnalysisRegistry<SafetyRootInputs>,
            SafetyRootInputs,
            WorkspaceEvaluationView<'_>,
        ) -> T,
    ) -> T {
        let (_, artifact) = root_artifact(
            has_contract,
            has_operation_marker,
            None,
            false,
            second_marked_operation,
        );
        let mut registry = AnalysisRegistry::<SafetyRootInputs>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        registry.install(&SafetyRootIssuePack).unwrap();
        registry.install(&SafetyOperationIssuePack).unwrap();
        registry.install(&SafetyEvidenceUsePack).unwrap();
        registry.install(&EvidenceCoordinatorPack).unwrap();
        registry.install(&SafetyCompletenessPack).unwrap();
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let workspace = WorkspaceFactView::compose([(
            scope,
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(ManagedArtifactGeneration::in_memory(1, 0), vec![]),
            [],
            Vec::<RustcArtifactId>::new(),
        )
        .unwrap();
        let mut roots = PreparedSafetyRootBatch::prepare(
            &workspace,
            &closure,
            &SafetyConfig::default(),
            &ContractDocOverrides::default(),
            [SafetyRootRequest::new(
                root_key(),
                CallAttributionRole::CallSite,
                MarkerProbe::SourceCallsite,
                100,
            )],
        )
        .unwrap()
        .into_roots();
        let prepared = roots.pop().unwrap();
        let root = prepared.root().clone();
        let mut builder =
            CompositionRelationBuilder::new(&root, &workspace, registry.composition_relations())
                .unwrap();
        let emitted = prepared.emit(&mut builder).unwrap();
        let relations = builder.finalize().unwrap();
        let index = WorkspaceRelationIndex::open(&workspace).unwrap();
        let graph = index.bind(&root, relations).unwrap();
        let inputs = emitted
            .resolve(&graph, registry.composition_relations())
            .unwrap();
        let evaluation = WorkspaceEvaluationView::from_graph(&workspace, graph).unwrap();
        inspect(&registry, inputs, evaluation)
    }

    fn with_call_scenario<T>(
        call_marker: Option<bool>,
        has_opaque_call: bool,
        inspect: impl FnOnce(
            &AnalysisRegistry<SafetyRootInputs>,
            SafetyRootInputs,
            WorkspaceEvaluationView<'_>,
        ) -> T,
    ) -> T {
        let (_, artifact) = root_artifact(false, false, call_marker, has_opaque_call, false);
        let mut registry = AnalysisRegistry::<SafetyRootInputs>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        registry.install(&SafetyCallIssuePack).unwrap();
        registry.install(&SafetyEvidenceUsePack).unwrap();
        registry.install(&EvidenceCoordinatorPack).unwrap();
        registry.install(&SafetyCompletenessPack).unwrap();
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let workspace = WorkspaceFactView::compose([(
            scope,
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(ManagedArtifactGeneration::in_memory(1, 0), vec![]),
            [],
            Vec::<RustcArtifactId>::new(),
        )
        .unwrap();
        let mut roots = PreparedSafetyRootBatch::prepare(
            &workspace,
            &closure,
            &SafetyConfig::default(),
            &ContractDocOverrides::default(),
            [SafetyRootRequest::new(
                root_key(),
                CallAttributionRole::CallSite,
                MarkerProbe::SourceCallsite,
                100,
            )],
        )
        .unwrap()
        .into_roots();
        let prepared = roots.pop().unwrap();
        let root = prepared.root().clone();
        let mut builder =
            CompositionRelationBuilder::new(&root, &workspace, registry.composition_relations())
                .unwrap();
        let emitted = prepared.emit(&mut builder).unwrap();
        let relations = builder.finalize().unwrap();
        let index = WorkspaceRelationIndex::open(&workspace).unwrap();
        let graph = index.bind(&root, relations).unwrap();
        let inputs = emitted
            .resolve(&graph, registry.composition_relations())
            .unwrap();
        let evaluation = WorkspaceEvaluationView::from_graph(&workspace, graph).unwrap();
        inspect(&registry, inputs, evaluation)
    }

    fn with_call_root<T>(
        satisfied: bool,
        inspect: impl FnOnce(
            &AnalysisRegistry<SafetyRootInputs>,
            SafetyRootInputs,
            WorkspaceEvaluationView<'_>,
        ) -> T,
    ) -> T {
        with_call_scenario(Some(satisfied), false, inspect)
    }

    #[test]
    fn root_contract_state_drives_traversal_completeness_and_issues() {
        enum ContractState {
            Documented,
            Missing,
        }

        for (has_contract, expected, expanded_bodies) in [
            (true, ContractState::Documented, 0),
            (false, ContractState::Missing, 1),
        ] {
            with_root(
                has_contract,
                false,
                false,
                |registry, inputs, evaluation| {
                    let root = inputs.root().clone();
                    match expected {
                        ContractState::Documented => {
                            assert!(!inputs.root_missing_safety_docs());
                            assert!(inputs.traversal().body_visits().is_empty());
                            assert!(matches!(
                                inputs.traversal().body_boundaries(),
                                [boundary]
                                    if matches!(
                                        boundary.payload(),
                                        SafetyBoundary::RootContract(contract)
                                            if contract.requirements()[0].normalized_name()
                                                == "valid"
                                    )
                            ));
                        }
                        ContractState::Missing => {
                            assert!(inputs.root_missing_safety_docs());
                            assert_eq!(inputs.traversal().body_visits().len(), 1);
                            assert!(inputs.traversal().body_boundaries().is_empty());
                        }
                    }

                    let mut database = EvaluationDb::new();
                    registry
                        .run_workspace_evaluation(&inputs, &root, &evaluation, &mut database)
                        .unwrap();
                    let results = database.finish().unwrap();
                    let summaries = results
                        .derived_rows::<SafetyCompletenessOutcome>(registry.schemas())
                        .unwrap();
                    assert!(matches!(
                        summaries.as_slice(),
                        [summary]
                            if summary.data.expanded_bodies() == expanded_bodies
                                && summary.data.complete()
                    ));
                    let issues = results
                        .issues::<MissingSafetyDocsIssue>(registry.schemas())
                        .unwrap();
                    match expected {
                        ContractState::Documented => assert!(issues.is_empty()),
                        ContractState::Missing => {
                            let [issue] = issues.as_slice() else {
                                panic!("a missing root contract must emit one issue");
                            };
                            assert_eq!(issue.context.root, root);
                            assert_eq!(issue.context.endpoint.as_ref(), Some(&root.entity));
                            assert!(issue.context.source.is_none());
                            assert!(
                                issue
                                    .context
                                    .trace
                                    .as_ref()
                                    .is_some_and(|trace| trace.relations().is_empty())
                            );
                        }
                    }
                },
            );
        }
    }

    #[test]
    fn duplicate_root_safety_requirements_emit_one_exact_issue() {
        with_root(true, false, false, |registry, inputs, evaluation| {
            let root = inputs.root().clone();
            let mut database = EvaluationDb::new();
            registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut database)
                .unwrap();
            let results = database.finish().unwrap();
            let issues = results
                .issues::<DuplicateSafetyRootRequirementIssue>(registry.schemas())
                .unwrap();
            let [issue] = issues.as_slice() else {
                panic!("one duplicate root safety requirement issue must be emitted");
            };
            assert_eq!(issue.data.normalized_name(), "valid");
            assert_eq!(issue.data.requirement_ordinals(), [0, 1]);
            assert_eq!(issue.context.root, root);
            assert_eq!(issue.context.endpoint.as_ref(), Some(&root.entity));
            assert!(issue.context.source.is_some());
            assert!(
                issue
                    .context
                    .trace
                    .as_ref()
                    .is_some_and(|trace| trace.relations().is_empty())
            );
        });
    }

    #[test]
    fn unsafe_operation_evidence_state_projects_an_issue_or_use() {
        enum EvidenceState {
            Missing,
            Matched,
        }

        for (has_marker, expected) in [
            (false, EvidenceState::Missing),
            (true, EvidenceState::Matched),
        ] {
            with_root(false, has_marker, false, |registry, inputs, evaluation| {
                let root = inputs.root().clone();
                let [visit] = inputs.traversal().unsafe_operation_visits() else {
                    panic!("the fixture must retain one unsafe-operation witness");
                };
                assert_eq!(visit.active_markers().len(), usize::from(has_marker));

                let mut database = EvaluationDb::new();
                registry
                    .run_workspace_evaluation(&inputs, &root, &evaluation, &mut database)
                    .unwrap();
                let results = database.finish().unwrap();
                let issues = results
                    .issues::<UnsatisfiedUnsafeOperationIssue>(registry.schemas())
                    .unwrap();
                let uses = results
                    .derived_rows::<EvidenceUseRecord>(registry.schemas())
                    .unwrap();
                match expected {
                    EvidenceState::Missing => {
                        let [issue] = issues.as_slice() else {
                            panic!("missing evidence must produce one unsafe-operation issue");
                        };
                        assert_eq!(issue.data.kind(), SafetyOperationKind::DerefRawPointer);
                        assert_eq!(issue.data.witness_order(), 1);
                        assert_eq!(issue.context.root, root);
                        assert_eq!(
                            issue.context.source.as_ref(),
                            issue
                                .context
                                .endpoint
                                .as_ref()
                                .map(crate::analysis::facts::workspace::ScopedEntityRef::as_row,)
                                .as_ref()
                        );
                        assert!(uses.is_empty());
                    }
                    EvidenceState::Matched => {
                        assert!(issues.is_empty());
                        assert!(matches!(
                            uses.as_slice(),
                            [usage]
                                if usage.data.endpoint() == &visit.operation().erase()
                                    && usage.data.group() == &visit.safety_group().erase()
                        ));
                    }
                }
            });
        }
    }

    #[test]
    fn matching_safety_markers_discharge_named_call_requirements() {
        enum EvidenceState {
            Missing,
            Matched,
        }

        for (satisfied, expected) in [
            (false, EvidenceState::Missing),
            (true, EvidenceState::Matched),
        ] {
            with_call_root(satisfied, |registry, inputs, evaluation| {
                let root = inputs.root().clone();
                let mut database = EvaluationDb::new();
                registry
                    .run_workspace_evaluation(&inputs, &root, &evaluation, &mut database)
                    .unwrap();
                let results = database.finish().unwrap();
                let issues = results
                    .issues::<UnsatisfiedSafetyCallIssue>(registry.schemas())
                    .unwrap();
                let uses = results
                    .derived_rows::<EvidenceUseRecord>(registry.schemas())
                    .unwrap();
                match expected {
                    EvidenceState::Missing => {
                        assert!(matches!(issues.as_slice(), [_]));
                        assert!(uses.is_empty());
                    }
                    EvidenceState::Matched => {
                        assert!(issues.is_empty());
                        assert!(matches!(uses.as_slice(), [_]));
                    }
                }
                let duplicates = results
                    .issues::<super::super::DuplicateSafetyCallRequirementIssue>(registry.schemas())
                    .unwrap();
                assert!(matches!(
                    duplicates.as_slice(),
                    [issue]
                        if issue.data.normalized_name() == "valid"
                            && issue.data.requirement_ordinals() == [0, 1]
                ));
            });
        }
    }

    #[test]
    fn opaque_actual_call_emits_the_typed_safety_boundary_issue() {
        with_call_scenario(None, true, |registry, inputs, evaluation| {
            let root = inputs.root().clone();
            let mut database = EvaluationDb::new();
            registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut database)
                .unwrap();
            let results = database.finish().unwrap();
            let issues = results
                .issues::<IndirectSafetyCallBoundaryIssue>(registry.schemas())
                .unwrap();
            assert!(matches!(
                issues.as_slice(),
                [issue]
                    if issue.data.description() == "indirect call through a function pointer"
                        && issue.context.root == root
                        && issue.context.source == issue.context.endpoint.as_ref().map(
                            crate::analysis::facts::workspace::ScopedEntityRef::as_row
                        )
            ));
        });
    }

    #[test]
    fn indirect_safety_boundaries_use_stable_user_facing_descriptions() {
        assert_eq!(
            normalized_opaque_description(CallKind::IndirectCall, false, "Binder { raw }"),
            "indirect call through a function pointer"
        );
        assert_eq!(
            normalized_opaque_description(CallKind::IndirectCall, true, "Binder { raw }"),
            "indirect call through an unsafe function pointer"
        );
    }

    #[test]
    fn one_safety_marker_reused_across_effect_groups_is_ambiguous() {
        with_root(false, true, true, |registry, inputs, evaluation| {
            let root = inputs.root().clone();
            let mut database = EvaluationDb::new();
            registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut database)
                .unwrap();
            let results = database.finish().unwrap();
            assert_eq!(
                results
                    .derived_rows::<EvidenceUseRecord>(registry.schemas())
                    .unwrap()
                    .len(),
                2
            );
            let issues = results
                .issues::<AmbiguousEvidenceReuseIssue>(registry.schemas())
                .unwrap();
            assert!(matches!(
                issues.as_slice(),
                [issue]
                    if issue.data.domain() == &super::safety_domain()
                        && issue.data.groups().len() == 2
                        && issue.context.root == root
            ));
        });
    }
}
