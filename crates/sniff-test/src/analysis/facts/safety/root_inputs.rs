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
    root_missing_safety_docs: bool,
}

impl SafetyRootInputs {
    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        self.traversal.root()
    }

    #[must_use]
    pub(crate) fn traversal(&self) -> &ResolvedRootProgramTraversal<SafetyBoundary> {
        &self.traversal
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
            root_missing_safety_docs: self.root_missing_safety_docs,
        })
    }
}

#[derive(Debug)]
pub(crate) struct EmittedSafetyRoot {
    traversal: EmittedRootProgramTraversal<SafetyBoundary, SafetyPolicyError>,
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
}

impl Display for SafetyRootInputError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contracts(source) => Display::fmt(source, formatter),
            Self::Traversal(source) => Display::fmt(source, formatter),
        }
    }
}

impl Error for SafetyRootInputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contracts(source) => Some(source),
            Self::Traversal(source) => Some(source),
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
                    description: description.to_owned(),
                },
            ));
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
                description: description.to_owned(),
            },
        })
    }

    fn decide_body(
        &mut self,
        context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        let attributes = context.callable.data();
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
mod tests {
    use super::{PreparedSafetyRootBatch, SafetyBoundary, SafetyRootRequest};
    use crate::analysis::cache::RustcArtifactId;
    use crate::analysis::facts::builder::{ArtifactDbBuilder, FactMeta};
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::composition::{CompositionRelationBuilder, WorkspaceRelationIndex};
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::program::root_traversal::MarkerProbe;
    use crate::analysis::facts::program::topology::{
        CallAttributionRole, CallableEntity, FunctionDefinesCallable,
    };
    use crate::analysis::facts::program::{FunctionBodyProvenance, FunctionEntity, FunctionKey};
    use crate::analysis::facts::schema::PassId;
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::analysis::facts::workspace::{ArtifactScopeId, WorkspaceFactView};
    use crate::analysis::workspace_closure::{
        ManagedArtifactGeneration, ManagedArtifactManifest, VerifiedWorkspaceClosure,
    };
    use crate::config::SafetyConfig;
    use crate::contracts::ContractDocOverrides;
    use crate::namespace::StableDefPathHash;

    use super::super::{SafetyContractFact, SafetyRequirement};

    fn root_key() -> FunctionKey {
        FunctionKey::new(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000031\"")
                .unwrap(),
            None,
        )
    }

    fn root_artifact(
        has_contract: bool,
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
        if has_contract {
            let requirement = builder
                .insert_requirement(&SafetyRequirement::new(
                    root,
                    0,
                    "valid",
                    "the input is valid",
                    None,
                ))
                .unwrap();
            let metadata = FactMeta::new(PassId::new("test.safety.root-input").unwrap())
                .with_owner(&callable)
                .unwrap()
                .with_requirement(&requirement)
                .unwrap();
            builder
                .insert_fact(&SafetyContractFact::new(), metadata)
                .unwrap();
        }
        let artifact = builder.finalize(registry.schemas()).unwrap();
        (registry, artifact)
    }

    fn resolve_root(has_contract: bool) -> super::SafetyRootInputs {
        let (registry, artifact) = root_artifact(has_contract);
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
        emitted
            .resolve(&graph, registry.composition_relations())
            .unwrap()
    }

    #[test]
    fn root_contract_is_a_silent_boundary_and_missing_docs_expand() {
        let documented = resolve_root(true);
        assert!(!documented.root_missing_safety_docs());
        assert!(documented.traversal().body_visits().is_empty());
        assert!(matches!(
            documented.traversal().body_boundaries(),
            [boundary] if matches!(boundary.payload(), SafetyBoundary::RootContract(contract)
                if contract.requirements()[0].normalized_name() == "valid")
        ));

        let undocumented = resolve_root(false);
        assert!(undocumented.root_missing_safety_docs());
        assert_eq!(undocumented.traversal().body_visits().len(), 1);
        assert!(undocumented.traversal().body_boundaries().is_empty());
    }
}
