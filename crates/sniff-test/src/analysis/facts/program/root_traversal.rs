//! Root-scoped, policy-neutral traversal over permanent program facts.
//!
//! Traversal is deliberately split into preparation, composition emission,
//! and exact-path resolution. Preparation never mutates a composition
//! builder. Resolution validates the precise relations selected while
//! traversing and never substitutes a graph-discovered path.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;
use std::sync::Arc;

use super::topology::{
    CallAttributionRole, CallKind, CallMacroExpansionEntity, CallOccurrenceEntity, CallSiteEntity,
    CallSourceAnchorRole, CallTargetRole, CallableEntity, CallableKey, SafetyEffectGroupEntity,
};
use super::workspace_index::{
    CallableBodySelectionKind, CallableInvocationTargetsCallable, CallableResolutionKind,
    CallableSelectsFunctionBody, ConsumerOccurrenceReconcilesWith,
    ConsumerOccurrenceReconciliationKind, ConsumerOverlayUsesDefiningSourceBody,
    ScopedProgramEntity, WorkspaceProgramIndex, WorkspaceProgramIndexError,
};
use super::{
    EffectSiteEntity, EffectSiteKey, EffectSourceAnchorRole, FunctionEntity, FunctionKey,
    MacroExpansionEntity, SourceAnchorEntity, SourceAnchorKey,
};
use crate::analysis::facts::composition::{
    CompositionBuildError, CompositionRelationBuilder, CompositionRelationRef,
    CompositionRelationRegistry, WorkspaceRelationGraph, WorkspaceRelationRef,
};
use crate::analysis::facts::evaluation::{DomainId, EvaluationRoot, RelationTrace};
use crate::analysis::facts::human::markers::MarkerClaimEntity;
use crate::analysis::facts::safety::operations::{
    UnsafeOperationEntity, UnsafeOperationKey, UnsafeOperationMacroExpansionEntity,
    UnsafeOperationSourceAnchorRole,
};
use crate::analysis::facts::schema::RowSchema;
use crate::analysis::facts::workspace::{
    ArtifactScopeId, ScopedEntityId, ScopedEntityRef, ScopedRelationRef, WorkspaceFactView,
    WorkspaceIdentity,
};

mod engine;

#[cfg(test)]
mod tests;

/// Marker attachment strategy selected for this traversal root.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum MarkerProbe {
    SourceCallsite,
    MacroDefinitionFirst,
}

/// Authoritative management status for one stable crate identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum StableCrateResolution {
    Managed(ArtifactScopeId),
    Unmanaged,
}

/// One contextual authority-map entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DefiningScopeAuthority {
    preferred_scope: ArtifactScopeId,
    stable_crate_id: u64,
    resolution: StableCrateResolution,
}

impl DefiningScopeAuthority {
    #[must_use]
    pub(crate) const fn new(
        preferred_scope: ArtifactScopeId,
        stable_crate_id: u64,
        resolution: StableCrateResolution,
    ) -> Self {
        Self {
            preferred_scope,
            stable_crate_id,
            resolution,
        }
    }
}

/// Workspace-branded, explicit stable-crate ownership decisions.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedDefiningScopeMap {
    workspace: Arc<WorkspaceIdentity>,
    resolutions: BTreeMap<(ArtifactScopeId, u64), StableCrateResolution>,
}

impl VerifiedDefiningScopeMap {
    pub(crate) fn new(
        workspace: &WorkspaceFactView<'_>,
        index: &WorkspaceProgramIndex,
        resolutions: impl IntoIterator<Item = DefiningScopeAuthority>,
    ) -> Result<Self, DefiningScopeMapError> {
        index
            .validate_workspace(workspace)
            .map_err(DefiningScopeMapError::Index)?;
        let mut validated = BTreeMap::new();
        for authority in resolutions {
            index
                .stable_crate_id(&authority.preferred_scope)
                .map_err(DefiningScopeMapError::Index)?;
            let key = (authority.preferred_scope, authority.stable_crate_id);
            if validated.contains_key(&key) {
                return Err(DefiningScopeMapError::Invalid {
                    reason: format!(
                        "stable crate {:016x} has more than one authority decision from preferred scope `{}`",
                        key.1, key.0
                    ),
                });
            }
            if let StableCrateResolution::Managed(scope) = &authority.resolution {
                let found = index
                    .stable_crate_id(scope)
                    .map_err(DefiningScopeMapError::Index)?;
                if found != authority.stable_crate_id {
                    return Err(DefiningScopeMapError::Invalid {
                        reason: format!(
                            "managed scope `{scope}` belongs to stable crate {found:016x}, not {:016x}",
                            authority.stable_crate_id
                        ),
                    });
                }
            }
            validated.insert(key, authority.resolution);
        }
        Ok(Self {
            workspace: workspace.identity(),
            resolutions: validated,
        })
    }

    fn validate_workspace(
        &self,
        workspace: &WorkspaceFactView<'_>,
    ) -> Result<(), DefiningScopeMapError> {
        if workspace.has_identity(&self.workspace) {
            Ok(())
        } else {
            Err(DefiningScopeMapError::WorkspaceMismatch)
        }
    }

    fn validate_against(
        &self,
        workspace: &WorkspaceFactView<'_>,
        index: &WorkspaceProgramIndex,
    ) -> Result<(), DefiningScopeMapError> {
        self.validate_workspace(workspace)?;
        index
            .validate_workspace(workspace)
            .map_err(DefiningScopeMapError::Index)?;
        for ((preferred_scope, stable_crate_id), resolution) in &self.resolutions {
            index
                .stable_crate_id(preferred_scope)
                .map_err(DefiningScopeMapError::Index)?;
            if let StableCrateResolution::Managed(scope) = resolution {
                let found = index
                    .stable_crate_id(scope)
                    .map_err(DefiningScopeMapError::Index)?;
                if found != *stable_crate_id {
                    return Err(DefiningScopeMapError::Invalid {
                        reason: format!(
                            "managed scope `{scope}` belongs to stable crate {found:016x}, not {stable_crate_id:016x}"
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    fn resolve(
        &self,
        preferred_scope: &ArtifactScopeId,
        stable_crate_id: u64,
    ) -> Result<&StableCrateResolution, DefiningScopeMapError> {
        self.resolution(preferred_scope, stable_crate_id)
            .ok_or_else(|| DefiningScopeMapError::Invalid {
                reason: format!(
                    "stable crate {stable_crate_id:016x} has no explicit managed-or-unmanaged decision from preferred scope `{preferred_scope}`"
                ),
            })
    }

    fn resolution(
        &self,
        preferred_scope: &ArtifactScopeId,
        stable_crate_id: u64,
    ) -> Option<&StableCrateResolution> {
        self.resolutions
            .get(&(preferred_scope.clone(), stable_crate_id))
    }

    /// Validates the shared authority once before resolving presentation
    /// function scopes for one panic-root input batch.
    pub(crate) fn presentation_function_scopes<'a>(
        &'a self,
        workspace: &WorkspaceFactView<'_>,
        index: &'a WorkspaceProgramIndex,
    ) -> Result<VerifiedPresentationFunctionScopes<'a>, DefiningScopeMapError> {
        self.validate_against(workspace, index)?;
        Ok(VerifiedPresentationFunctionScopes {
            defining_scopes: self,
            index,
        })
    }
}

/// Narrow, one-shot-validated resolver for panic-call presentation functions.
pub(crate) struct VerifiedPresentationFunctionScopes<'a> {
    defining_scopes: &'a VerifiedDefiningScopeMap,
    index: &'a WorkspaceProgramIndex,
}

impl VerifiedPresentationFunctionScopes<'_> {
    /// Resolves only the semantic scope. Callers retain the exact requested
    /// key, including when the selected body candidate is generic.
    pub(crate) fn resolve(
        &self,
        preferred_scope: &ArtifactScopeId,
        requested: &FunctionKey,
    ) -> Result<ArtifactScopeId, DefiningScopeMapError> {
        let local = self
            .index
            .body_candidates(preferred_scope, requested)
            .map_err(DefiningScopeMapError::Index)?;
        if !local.is_empty() {
            return Ok(preferred_scope.clone());
        }

        let stable_crate_id = requested.definition().stable_crate_id();
        match self
            .defining_scopes
            .resolution(preferred_scope, stable_crate_id)
        {
            None | Some(StableCrateResolution::Unmanaged) => Ok(preferred_scope.clone()),
            Some(StableCrateResolution::Managed(defining_scope)) => {
                let candidates = self
                    .index
                    .managed_body_candidates(defining_scope, requested)
                    .map_err(DefiningScopeMapError::Index)?;
                Ok(if candidates.is_empty() {
                    preferred_scope.clone()
                } else {
                    defining_scope.clone()
                })
            }
        }
    }
}

/// Authority-map construction or use failed before traversal policy ran.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DefiningScopeMapError {
    WorkspaceMismatch,
    Invalid { reason: String },
    Index(WorkspaceProgramIndexError),
}

impl Display for DefiningScopeMapError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceMismatch => {
                formatter.write_str("defining-scope map belongs to a replacement workspace view")
            }
            Self::Invalid { reason } => write!(formatter, "invalid defining-scope map: {reason}"),
            Self::Index(source) => Display::fmt(source, formatter),
        }
    }
}

impl Error for DefiningScopeMapError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Index(source) => Some(source),
            Self::WorkspaceMismatch | Self::Invalid { .. } => None,
        }
    }
}

/// Complete root request; no domain policy is inferred by the core.
#[derive(Clone, Debug)]
pub(crate) struct RootProgramTraversalRequest {
    domain: DomainId,
    root_scope: ArtifactScopeId,
    root_function: FunctionKey,
    attribution: CallAttributionRole,
    marker_probe: MarkerProbe,
    node_budget: usize,
}

impl RootProgramTraversalRequest {
    #[must_use]
    pub(crate) const fn new(
        domain: DomainId,
        root_scope: ArtifactScopeId,
        root_function: FunctionKey,
        attribution: CallAttributionRole,
        marker_probe: MarkerProbe,
        node_budget: usize,
    ) -> Self {
        Self {
            domain,
            root_scope,
            root_function,
            attribution,
            marker_probe,
            node_budget,
        }
    }
}

/// Policy disposition for one selected function body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BodyTraversalDecision<B> {
    Expand,
    Boundary(B),
    Ignore,
}

/// Policy disposition for a complete, canonical call target bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CallTraversalDecision<B> {
    Follow(CallTargetSelection),
    Boundary {
        target: Option<CallTargetSelection>,
        payload: B,
    },
    Ignore,
}

/// Exact member of the complete target bundle selected by policy.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CallTargetSelection {
    role: CallTargetRole,
    callable: ScopedEntityId<CallableEntity>,
    authority: ReconciledCallTargetAuthority,
}

impl CallTargetSelection {
    #[must_use]
    pub(crate) const fn role(&self) -> CallTargetRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn callable(&self) -> &ScopedEntityId<CallableEntity> {
        &self.callable
    }

    #[must_use]
    pub(crate) const fn authority(&self) -> ReconciledCallTargetAuthority {
        self.authority
    }
}

/// All-or-none permission to transport defining-source marker claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DefiningMarkerDecision {
    UseCompleteSet,
    RejectCompleteSet,
}

/// How a call selected its callable metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProgramCallResolution {
    Persisted,
    CallableEvidence {
        evidence: ScopedEntityId<CallOccurrenceEntity>,
        key: CallableKey,
        kind: CallableResolutionKind,
    },
}

/// One canonical persisted or reached-evidence callable candidate.
#[derive(Debug)]
pub(crate) struct CallTargetPolicyCandidate<'a> {
    pub(crate) role: CallTargetRole,
    pub(crate) callable: &'a ScopedProgramEntity<CallableEntity>,
}

/// Which exact fact lane supplied one policy-visible reconciliation target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ReconciledCallTargetAuthority {
    ConsumerRaw,
    DefiningTarget,
    DefiningSource,
    ConsumerSource,
}

/// One followable callable selected from an explicit reconciliation route.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReconciledCallTargetPolicyCandidate<'a> {
    pub(crate) authority: ReconciledCallTargetAuthority,
    pub(crate) role: CallTargetRole,
    pub(crate) callable: &'a ScopedProgramEntity<CallableEntity>,
}

impl ReconciledCallTargetPolicyCandidate<'_> {
    #[must_use]
    pub(crate) fn selection(&self) -> CallTargetSelection {
        CallTargetSelection {
            role: self.role,
            callable: self.callable.id(),
            authority: self.authority,
        }
    }
}

impl CallTargetPolicyCandidate<'_> {
    #[must_use]
    pub(crate) fn selection(&self) -> CallTargetSelection {
        CallTargetSelection {
            role: self.role,
            callable: self.callable.id(),
            authority: ReconciledCallTargetAuthority::ConsumerRaw,
        }
    }
}

/// Typed marker data visible to policy without re-reading workspace rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MarkerClaimPolicyValue {
    pub(crate) claim: ScopedEntityId<MarkerClaimEntity>,
    pub(crate) data: MarkerClaimEntity,
}

/// Policy-neutral authority lanes derived from one consumer/source match set.
#[derive(Debug)]
pub(crate) struct CallReconciliationContext<'a> {
    /// Every selected defining occurrence, even when marker transport is rejected.
    pub(crate) candidates: &'a [DefiningMarkerCandidate],
    /// Consumer raw runtime-or-opaque metadata for this raw or synthetic decision.
    pub(crate) raw_target: Option<ReconciledCallTargetPolicyCandidate<'a>>,
    /// Source-contract target shared by every defining candidate.
    pub(crate) defining_source_target: Option<ReconciledCallTargetPolicyCandidate<'a>>,
    /// Shared defining source, or the consumer source contract when no consensus exists.
    pub(crate) effective_source_target: Option<ReconciledCallTargetPolicyCandidate<'a>>,
    /// Complete effective raw target shared by every defining candidate.
    pub(crate) defining_target: Option<ReconciledCallTargetPolicyCandidate<'a>>,
    /// Metadata candidates in `consumer raw -> defining -> effective source` order.
    pub(crate) effective_metadata_targets: Vec<ReconciledCallTargetPolicyCandidate<'a>>,
    /// Contract candidates in effective-source-first order. Defining metadata is
    /// present only when no consumer raw target exists.
    pub(crate) contract_targets: Vec<ReconciledCallTargetPolicyCandidate<'a>>,
}

/// Narrow policy input for a complete callable edge.
#[derive(Debug)]
pub(crate) struct CallPolicyContext<'a> {
    pub(crate) call_site: &'a ScopedProgramEntity<CallSiteEntity>,
    pub(crate) occurrence: &'a ScopedProgramEntity<CallOccurrenceEntity>,
    pub(crate) safety_group: &'a ScopedProgramEntity<SafetyEffectGroupEntity>,
    /// Persisted kind, or the runtime kind proven by callable evidence.
    pub(crate) effective_kind: CallKind,
    pub(crate) targets: &'a [CallTargetPolicyCandidate<'a>],
    pub(crate) resolution: ProgramCallResolution,
    pub(crate) reconciliation: Option<CallReconciliationContext<'a>>,
    pub(crate) inherited_marker_claims: &'a [MarkerClaimPolicyValue],
    pub(crate) attached_marker_candidates: &'a [MarkerClaimPolicyValue],
    pub(crate) active_marker_claims: &'a [MarkerClaimPolicyValue],
}

/// Narrow policy input for one resolved body before it consumes budget.
#[derive(Debug)]
pub(crate) struct BodyPolicyContext<'a> {
    pub(crate) body: &'a ScopedProgramEntity<FunctionEntity>,
    pub(crate) callable: &'a ScopedProgramEntity<CallableEntity>,
    pub(crate) active_marker_claims: &'a [MarkerClaimPolicyValue],
    pub(crate) endpoint_marker_candidates: &'a [MarkerClaimPolicyValue],
    pub(crate) is_root: bool,
}

/// One complete defining occurrence, retaining its marker association.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DefiningMarkerCandidate {
    pub(crate) occurrence: ScopedEntityId<CallOccurrenceEntity>,
    pub(crate) data: CallOccurrenceEntity,
    pub(crate) call_site: ScopedEntityId<CallSiteEntity>,
    pub(crate) call_site_data: super::topology::CallSiteEntity,
    pub(crate) safety_group: ScopedEntityId<SafetyEffectGroupEntity>,
    pub(crate) safety_group_data: SafetyEffectGroupEntity,
    pub(crate) reconciliation_kind: ConsumerOccurrenceReconciliationKind,
    pub(crate) expanded_anchor: ScopedEntityId<SourceAnchorEntity>,
    pub(crate) expanded_anchor_data: SourceAnchorEntity,
    pub(crate) callee_anchor: Option<ScopedEntityId<SourceAnchorEntity>>,
    pub(crate) callee_anchor_data: Option<SourceAnchorEntity>,
    pub(crate) marker_claims: Vec<MarkerClaimPolicyValue>,
}

/// Complete defining-source occurrence candidate set for one overlay call.
#[derive(Debug)]
pub(crate) struct DefiningMarkerPolicyContext<'a> {
    pub(crate) consumer: &'a ScopedProgramEntity<CallOccurrenceEntity>,
    pub(crate) candidates: &'a [DefiningMarkerCandidate],
}

/// Domain-owned boundary decisions consumed by the generic traversal core.
///
/// Implementations should be deterministic for equal contexts. Policy errors
/// abort preparation before any composition relation is emitted.
///
/// `defining_markers` receives the complete source-identical candidate set once
/// per applicable consumer occurrence. Its all-or-none decision controls only
/// marker transport; reconciliation edges and authority lanes remain structural.
pub(crate) trait RootProgramTraversalPolicy {
    type Error: Error;
    type Boundary: Clone + fmt::Debug + Eq;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error>;

    fn decide_body(
        &mut self,
        context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error>;

    fn defining_markers(
        &mut self,
        context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error>;
}

/// Exact reason one route terminated or collapsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TraversalOutcomeKind {
    Ignored,
    UnmanagedStableCrate {
        preferred_scope: ArtifactScopeId,
        stable_crate_id: u64,
        requested: FunctionKey,
    },
    MissingManagedBody {
        preferred_scope: ArtifactScopeId,
        defining_scope: ArtifactScopeId,
        stable_crate_id: u64,
        requested: FunctionKey,
    },
    UnmanagedDefiningSource {
        preferred_scope: ArtifactScopeId,
        stable_crate_id: u64,
        consumer: FunctionKey,
    },
    MissingManagedDefiningSource {
        preferred_scope: ArtifactScopeId,
        defining_scope: ArtifactScopeId,
        stable_crate_id: u64,
        consumer: FunctionKey,
    },
    Cycle,
    Deduplicated,
    BudgetExceeded {
        limit: usize,
    },
}

/// Marker state attached to one accepted body visit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedMarkerClaim {
    claim: ScopedEntityId<MarkerClaimEntity>,
    data: MarkerClaimEntity,
    trace: RelationTrace,
}

impl ResolvedMarkerClaim {
    #[must_use]
    pub(crate) const fn claim(&self) -> &ScopedEntityId<MarkerClaimEntity> {
        &self.claim
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &MarkerClaimEntity {
        &self.data
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }
}

/// One accepted `(body, marker-state)` visit in canonical DFS order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedBodyVisit {
    order: u64,
    body: ScopedEntityId<FunctionEntity>,
    data: FunctionEntity,
    active_markers: Vec<ResolvedMarkerClaim>,
    endpoint_marker_candidates: Vec<ResolvedMarkerClaim>,
    trace: RelationTrace,
}

impl ResolvedBodyVisit {
    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.order
    }

    #[must_use]
    pub(crate) const fn body(&self) -> &ScopedEntityId<FunctionEntity> {
        &self.body
    }

    #[must_use]
    pub(crate) const fn function(&self) -> FunctionKey {
        *self.data.key()
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &FunctionEntity {
        &self.data
    }

    #[must_use]
    pub(crate) fn active_markers(&self) -> &[ResolvedMarkerClaim] {
        &self.active_markers
    }

    #[must_use]
    pub(crate) fn endpoint_marker_candidates(&self) -> &[ResolvedMarkerClaim] {
        &self.endpoint_marker_candidates
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }
}

/// One call occurrence actually encountered under the active attribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedCallSourceAnchor {
    role: CallSourceAnchorRole,
    key: SourceAnchorKey,
    anchor: ScopedEntityId<SourceAnchorEntity>,
    relation: ScopedRelationRef,
}

impl ResolvedCallSourceAnchor {
    #[must_use]
    pub(crate) const fn role(&self) -> CallSourceAnchorRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &SourceAnchorKey {
        &self.key
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> &ScopedEntityId<SourceAnchorEntity> {
        &self.anchor
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// Optional source callsite retained for one exact call macro frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedCallMacroCallsite {
    key: SourceAnchorKey,
    anchor: ScopedEntityId<SourceAnchorEntity>,
    relation: ScopedRelationRef,
}

impl ResolvedCallMacroCallsite {
    #[must_use]
    pub(crate) const fn key(&self) -> &SourceAnchorKey {
        &self.key
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> &ScopedEntityId<SourceAnchorEntity> {
        &self.anchor
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// One outer-to-inner frame on the exact provenance route to a call occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedCallMacroFrame {
    frame: ScopedEntityId<CallMacroExpansionEntity>,
    data: CallMacroExpansionEntity,
    callsite: Option<ResolvedCallMacroCallsite>,
}

impl ResolvedCallMacroFrame {
    #[must_use]
    pub(crate) const fn frame(&self) -> &ScopedEntityId<CallMacroExpansionEntity> {
        &self.frame
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &CallMacroExpansionEntity {
        &self.data
    }

    #[must_use]
    pub(crate) const fn callsite(&self) -> Option<&ResolvedCallMacroCallsite> {
        self.callsite.as_ref()
    }
}

/// One call occurrence actually encountered under the active attribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedOccurrenceVisit {
    order: u64,
    occurrence: ScopedEntityId<CallOccurrenceEntity>,
    data: CallOccurrenceEntity,
    source_anchors: Vec<ResolvedCallSourceAnchor>,
    macro_frames: Vec<ResolvedCallMacroFrame>,
    inherited_markers: Vec<ResolvedMarkerClaim>,
    attached_marker_candidates: Vec<ResolvedMarkerClaim>,
    active_markers: Vec<ResolvedMarkerClaim>,
    trace: RelationTrace,
}

/// One verified source representation retained for an exact effect visit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedEffectSourceAnchor {
    role: EffectSourceAnchorRole,
    key: SourceAnchorKey,
    anchor: ScopedEntityId<SourceAnchorEntity>,
    relation: ScopedRelationRef,
}

impl ResolvedEffectSourceAnchor {
    #[must_use]
    pub(crate) const fn role(&self) -> EffectSourceAnchorRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &SourceAnchorKey {
        &self.key
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> &ScopedEntityId<SourceAnchorEntity> {
        &self.anchor
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// Optional source callsite retained for one exact effect macro frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedEffectMacroCallsite {
    key: SourceAnchorKey,
    anchor: ScopedEntityId<SourceAnchorEntity>,
    relation: ScopedRelationRef,
}

impl ResolvedEffectMacroCallsite {
    #[must_use]
    pub(crate) const fn key(&self) -> &SourceAnchorKey {
        &self.key
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> &ScopedEntityId<SourceAnchorEntity> {
        &self.anchor
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// One outer-to-inner frame on the exact provenance route to an effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedEffectMacroFrame {
    frame: ScopedEntityId<MacroExpansionEntity>,
    data: MacroExpansionEntity,
    callsite: Option<ResolvedEffectMacroCallsite>,
}

impl ResolvedEffectMacroFrame {
    #[must_use]
    pub(crate) const fn frame(&self) -> &ScopedEntityId<MacroExpansionEntity> {
        &self.frame
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &MacroExpansionEntity {
        &self.data
    }

    #[must_use]
    pub(crate) const fn callsite(&self) -> Option<&ResolvedEffectMacroCallsite> {
        self.callsite.as_ref()
    }
}

/// One effect encountered in canonical body-local order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedEffectVisit {
    order: u64,
    effect: ScopedEntityId<EffectSiteEntity>,
    data: EffectSiteEntity,
    source_anchors: Vec<ResolvedEffectSourceAnchor>,
    macro_frames: Vec<ResolvedEffectMacroFrame>,
    inherited_markers: Vec<ResolvedMarkerClaim>,
    attached_marker_candidates: Vec<ResolvedMarkerClaim>,
    active_markers: Vec<ResolvedMarkerClaim>,
    trace: RelationTrace,
}

/// One verified source representation retained for an exact unsafe-operation visit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedUnsafeOperationSourceAnchor {
    role: UnsafeOperationSourceAnchorRole,
    key: SourceAnchorKey,
    anchor: ScopedEntityId<SourceAnchorEntity>,
    relation: ScopedRelationRef,
}

impl ResolvedUnsafeOperationSourceAnchor {
    #[must_use]
    pub(crate) const fn role(&self) -> UnsafeOperationSourceAnchorRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &SourceAnchorKey {
        &self.key
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> &ScopedEntityId<SourceAnchorEntity> {
        &self.anchor
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// Optional invocation anchor retained for one exact unsafe-operation macro frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedUnsafeOperationMacroCallsite {
    key: SourceAnchorKey,
    anchor: ScopedEntityId<SourceAnchorEntity>,
    relation: ScopedRelationRef,
}

impl ResolvedUnsafeOperationMacroCallsite {
    #[must_use]
    pub(crate) const fn key(&self) -> &SourceAnchorKey {
        &self.key
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> &ScopedEntityId<SourceAnchorEntity> {
        &self.anchor
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// One outer-to-inner frame on the exact provenance route to an unsafe operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedUnsafeOperationMacroFrame {
    frame: ScopedEntityId<UnsafeOperationMacroExpansionEntity>,
    data: UnsafeOperationMacroExpansionEntity,
    callsite: Option<ResolvedUnsafeOperationMacroCallsite>,
}

impl ResolvedUnsafeOperationMacroFrame {
    #[must_use]
    pub(crate) const fn frame(&self) -> &ScopedEntityId<UnsafeOperationMacroExpansionEntity> {
        &self.frame
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &UnsafeOperationMacroExpansionEntity {
        &self.data
    }

    #[must_use]
    pub(crate) const fn callsite(&self) -> Option<&ResolvedUnsafeOperationMacroCallsite> {
        self.callsite.as_ref()
    }
}

/// One unsafe operation encountered in canonical body-local order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedUnsafeOperationVisit {
    order: u64,
    operation: ScopedEntityId<UnsafeOperationEntity>,
    data: UnsafeOperationEntity,
    owner: ScopedEntityId<FunctionEntity>,
    owner_data: FunctionEntity,
    owner_relation: ScopedRelationRef,
    safety_group: ScopedEntityId<SafetyEffectGroupEntity>,
    safety_group_data: SafetyEffectGroupEntity,
    safety_group_relation: ScopedRelationRef,
    source_anchors: Vec<ResolvedUnsafeOperationSourceAnchor>,
    macro_frames: Vec<ResolvedUnsafeOperationMacroFrame>,
    inherited_markers: Vec<ResolvedMarkerClaim>,
    attached_marker_candidates: Vec<ResolvedMarkerClaim>,
    active_markers: Vec<ResolvedMarkerClaim>,
    trace: RelationTrace,
}

impl ResolvedUnsafeOperationVisit {
    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.order
    }
    #[must_use]
    pub(crate) const fn operation(&self) -> &ScopedEntityId<UnsafeOperationEntity> {
        &self.operation
    }
    #[must_use]
    pub(crate) const fn key(&self) -> UnsafeOperationKey {
        *self.data.key()
    }
    #[must_use]
    pub(crate) const fn data(&self) -> &UnsafeOperationEntity {
        &self.data
    }
    #[must_use]
    pub(crate) const fn owner(&self) -> &ScopedEntityId<FunctionEntity> {
        &self.owner
    }
    #[must_use]
    pub(crate) const fn owner_data(&self) -> &FunctionEntity {
        &self.owner_data
    }
    #[must_use]
    pub(crate) const fn owner_relation(&self) -> &ScopedRelationRef {
        &self.owner_relation
    }
    #[must_use]
    pub(crate) const fn safety_group(&self) -> &ScopedEntityId<SafetyEffectGroupEntity> {
        &self.safety_group
    }
    #[must_use]
    pub(crate) const fn safety_group_data(&self) -> &SafetyEffectGroupEntity {
        &self.safety_group_data
    }
    #[must_use]
    pub(crate) const fn safety_group_relation(&self) -> &ScopedRelationRef {
        &self.safety_group_relation
    }
    #[must_use]
    pub(crate) fn source_anchors(&self) -> &[ResolvedUnsafeOperationSourceAnchor] {
        &self.source_anchors
    }
    #[must_use]
    pub(crate) fn macro_frames(&self) -> &[ResolvedUnsafeOperationMacroFrame] {
        &self.macro_frames
    }
    #[must_use]
    pub(crate) fn inherited_markers(&self) -> &[ResolvedMarkerClaim] {
        &self.inherited_markers
    }
    #[must_use]
    pub(crate) fn attached_marker_candidates(&self) -> &[ResolvedMarkerClaim] {
        &self.attached_marker_candidates
    }
    #[must_use]
    pub(crate) fn active_markers(&self) -> &[ResolvedMarkerClaim] {
        &self.active_markers
    }
    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }
}

impl ResolvedEffectVisit {
    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.order
    }

    #[must_use]
    pub(crate) const fn effect(&self) -> &ScopedEntityId<EffectSiteEntity> {
        &self.effect
    }

    #[must_use]
    pub(crate) const fn site(&self) -> EffectSiteKey {
        *self.data.site()
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &EffectSiteEntity {
        &self.data
    }

    #[must_use]
    pub(crate) fn source_anchors(&self) -> &[ResolvedEffectSourceAnchor] {
        &self.source_anchors
    }

    #[must_use]
    pub(crate) fn macro_frames(&self) -> &[ResolvedEffectMacroFrame] {
        &self.macro_frames
    }

    #[must_use]
    pub(crate) fn inherited_markers(&self) -> &[ResolvedMarkerClaim] {
        &self.inherited_markers
    }

    #[must_use]
    pub(crate) fn attached_marker_candidates(&self) -> &[ResolvedMarkerClaim] {
        &self.attached_marker_candidates
    }

    #[must_use]
    pub(crate) fn active_markers(&self) -> &[ResolvedMarkerClaim] {
        &self.active_markers
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }
}

impl ResolvedOccurrenceVisit {
    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.order
    }

    #[must_use]
    pub(crate) const fn occurrence(&self) -> &ScopedEntityId<CallOccurrenceEntity> {
        &self.occurrence
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> CallKind {
        self.data.kind()
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &CallOccurrenceEntity {
        &self.data
    }

    #[must_use]
    pub(crate) fn source_anchors(&self) -> &[ResolvedCallSourceAnchor] {
        &self.source_anchors
    }

    #[must_use]
    pub(crate) fn macro_frames(&self) -> &[ResolvedCallMacroFrame] {
        &self.macro_frames
    }

    #[must_use]
    pub(crate) fn inherited_markers(&self) -> &[ResolvedMarkerClaim] {
        &self.inherited_markers
    }

    #[must_use]
    pub(crate) fn attached_marker_candidates(&self) -> &[ResolvedMarkerClaim] {
        &self.attached_marker_candidates
    }

    #[must_use]
    pub(crate) fn active_markers(&self) -> &[ResolvedMarkerClaim] {
        &self.active_markers
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }
}

/// One reached-only erased-callable join with both sides independently proven.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedCallableResolution {
    order: u64,
    invocation: ScopedEntityId<CallOccurrenceEntity>,
    invocation_data: CallOccurrenceEntity,
    evidence: ScopedEntityId<CallOccurrenceEntity>,
    evidence_data: CallOccurrenceEntity,
    callable: ScopedEntityId<CallableEntity>,
    callable_data: CallableEntity,
    key: CallableKey,
    kind: CallableResolutionKind,
    resolution_trace: RelationTrace,
    evidence_trace: RelationTrace,
}

impl ResolvedCallableResolution {
    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.order
    }

    #[must_use]
    pub(crate) const fn invocation(&self) -> &ScopedEntityId<CallOccurrenceEntity> {
        &self.invocation
    }

    #[must_use]
    pub(crate) const fn invocation_data(&self) -> &CallOccurrenceEntity {
        &self.invocation_data
    }

    #[must_use]
    pub(crate) const fn evidence(&self) -> &ScopedEntityId<CallOccurrenceEntity> {
        &self.evidence
    }

    #[must_use]
    pub(crate) const fn evidence_data(&self) -> &CallOccurrenceEntity {
        &self.evidence_data
    }

    #[must_use]
    pub(crate) const fn callable(&self) -> &ScopedEntityId<CallableEntity> {
        &self.callable
    }

    #[must_use]
    pub(crate) const fn callable_data(&self) -> &CallableEntity {
        &self.callable_data
    }

    #[must_use]
    pub(crate) const fn key(&self) -> CallableKey {
        self.key
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> CallableResolutionKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn resolution_trace(&self) -> &RelationTrace {
        &self.resolution_trace
    }

    #[must_use]
    pub(crate) const fn evidence_trace(&self) -> &RelationTrace {
        &self.evidence_trace
    }
}

/// Exact consumer-body to defining-source body selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedConsumerBodySource {
    order: u64,
    consumer: ScopedEntityId<FunctionEntity>,
    consumer_data: FunctionEntity,
    defining: ScopedEntityId<FunctionEntity>,
    defining_data: FunctionEntity,
    selection: CallableBodySelectionKind,
    trace: RelationTrace,
}

impl ResolvedConsumerBodySource {
    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.order
    }

    #[must_use]
    pub(crate) const fn consumer(&self) -> &ScopedEntityId<FunctionEntity> {
        &self.consumer
    }

    #[must_use]
    pub(crate) const fn consumer_data(&self) -> &FunctionEntity {
        &self.consumer_data
    }

    #[must_use]
    pub(crate) const fn defining(&self) -> &ScopedEntityId<FunctionEntity> {
        &self.defining
    }

    #[must_use]
    pub(crate) const fn defining_data(&self) -> &FunctionEntity {
        &self.defining_data
    }

    #[must_use]
    pub(crate) const fn selection(&self) -> CallableBodySelectionKind {
        self.selection
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }
}

/// Exact consumer-call reconciliation selected from the complete candidate set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedConsumerOccurrenceReconciliation {
    order: u64,
    consumer: ScopedEntityId<CallOccurrenceEntity>,
    consumer_data: CallOccurrenceEntity,
    consumer_call_site: ScopedEntityId<CallSiteEntity>,
    consumer_call_site_data: CallSiteEntity,
    consumer_safety_group: ScopedEntityId<SafetyEffectGroupEntity>,
    consumer_safety_group_data: SafetyEffectGroupEntity,
    defining: ScopedEntityId<CallOccurrenceEntity>,
    defining_data: CallOccurrenceEntity,
    defining_call_site: ScopedEntityId<CallSiteEntity>,
    defining_call_site_data: CallSiteEntity,
    defining_safety_group: ScopedEntityId<SafetyEffectGroupEntity>,
    defining_safety_group_data: SafetyEffectGroupEntity,
    kind: ConsumerOccurrenceReconciliationKind,
    trace: RelationTrace,
}

impl ResolvedConsumerOccurrenceReconciliation {
    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.order
    }

    #[must_use]
    pub(crate) const fn consumer(&self) -> &ScopedEntityId<CallOccurrenceEntity> {
        &self.consumer
    }

    #[must_use]
    pub(crate) const fn consumer_data(&self) -> &CallOccurrenceEntity {
        &self.consumer_data
    }
    #[must_use]
    pub(crate) const fn consumer_call_site(&self) -> &ScopedEntityId<CallSiteEntity> {
        &self.consumer_call_site
    }
    #[must_use]
    pub(crate) const fn consumer_call_site_data(&self) -> &CallSiteEntity {
        &self.consumer_call_site_data
    }
    #[must_use]
    pub(crate) const fn consumer_safety_group(&self) -> &ScopedEntityId<SafetyEffectGroupEntity> {
        &self.consumer_safety_group
    }
    #[must_use]
    pub(crate) const fn consumer_safety_group_data(&self) -> &SafetyEffectGroupEntity {
        &self.consumer_safety_group_data
    }

    #[must_use]
    pub(crate) const fn defining(&self) -> &ScopedEntityId<CallOccurrenceEntity> {
        &self.defining
    }

    #[must_use]
    pub(crate) const fn defining_data(&self) -> &CallOccurrenceEntity {
        &self.defining_data
    }
    #[must_use]
    pub(crate) const fn defining_call_site(&self) -> &ScopedEntityId<CallSiteEntity> {
        &self.defining_call_site
    }
    #[must_use]
    pub(crate) const fn defining_call_site_data(&self) -> &CallSiteEntity {
        &self.defining_call_site_data
    }
    #[must_use]
    pub(crate) const fn defining_safety_group(&self) -> &ScopedEntityId<SafetyEffectGroupEntity> {
        &self.defining_safety_group
    }
    #[must_use]
    pub(crate) const fn defining_safety_group_data(&self) -> &SafetyEffectGroupEntity {
        &self.defining_safety_group_data
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> ConsumerOccurrenceReconciliationKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }
}

/// One structured non-fatal traversal outcome and its exact route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedTraversalOutcome {
    order: u64,
    kind: TraversalOutcomeKind,
    trace: RelationTrace,
}

impl ResolvedTraversalOutcome {
    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.order
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> &TraversalOutcomeKind {
        &self.kind
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }
}

/// A policy-owned body boundary with the complete core context retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedBodyBoundary<B> {
    order: u64,
    body: ScopedEntityId<FunctionEntity>,
    body_data: FunctionEntity,
    callable: ScopedEntityId<CallableEntity>,
    callable_data: CallableEntity,
    active_markers: Vec<ResolvedMarkerClaim>,
    endpoint_marker_candidates: Vec<ResolvedMarkerClaim>,
    payload: B,
    trace: RelationTrace,
}

impl<B> ResolvedBodyBoundary<B> {
    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.order
    }
    #[must_use]
    pub(crate) const fn body(&self) -> &ScopedEntityId<FunctionEntity> {
        &self.body
    }
    #[must_use]
    pub(crate) const fn function(&self) -> FunctionKey {
        *self.body_data.key()
    }
    #[must_use]
    pub(crate) const fn body_data(&self) -> &FunctionEntity {
        &self.body_data
    }
    #[must_use]
    pub(crate) const fn callable(&self) -> &ScopedEntityId<CallableEntity> {
        &self.callable
    }
    #[must_use]
    pub(crate) const fn callable_data(&self) -> &CallableEntity {
        &self.callable_data
    }
    #[must_use]
    pub(crate) fn active_markers(&self) -> &[ResolvedMarkerClaim] {
        &self.active_markers
    }
    #[must_use]
    pub(crate) fn endpoint_marker_candidates(&self) -> &[ResolvedMarkerClaim] {
        &self.endpoint_marker_candidates
    }
    #[must_use]
    pub(crate) const fn payload(&self) -> &B {
        &self.payload
    }
    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }
}

/// A policy-owned call boundary with its validated selected target retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedCallBoundary<B> {
    order: u64,
    occurrence: ScopedEntityId<CallOccurrenceEntity>,
    occurrence_data: CallOccurrenceEntity,
    call_site: ScopedEntityId<CallSiteEntity>,
    call_site_data: CallSiteEntity,
    safety_group: ScopedEntityId<SafetyEffectGroupEntity>,
    safety_group_data: SafetyEffectGroupEntity,
    effective_kind: CallKind,
    resolution: ProgramCallResolution,
    source_anchors: Vec<ResolvedCallSourceAnchor>,
    macro_frames: Vec<ResolvedCallMacroFrame>,
    target: Option<CallTargetSelection>,
    target_data: Option<CallableEntity>,
    inherited_markers: Vec<ResolvedMarkerClaim>,
    attached_marker_candidates: Vec<ResolvedMarkerClaim>,
    active_markers: Vec<ResolvedMarkerClaim>,
    payload: B,
    trace: RelationTrace,
}

/// One accepted follow with its exact selected callable route retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedFollowedCall {
    order: u64,
    occurrence: ScopedEntityId<CallOccurrenceEntity>,
    occurrence_data: CallOccurrenceEntity,
    call_site: ScopedEntityId<CallSiteEntity>,
    call_site_data: CallSiteEntity,
    safety_group: ScopedEntityId<SafetyEffectGroupEntity>,
    safety_group_data: SafetyEffectGroupEntity,
    effective_kind: CallKind,
    resolution: ProgramCallResolution,
    source_anchors: Vec<ResolvedCallSourceAnchor>,
    macro_frames: Vec<ResolvedCallMacroFrame>,
    target: CallTargetSelection,
    target_data: CallableEntity,
    inherited_markers: Vec<ResolvedMarkerClaim>,
    attached_marker_candidates: Vec<ResolvedMarkerClaim>,
    active_markers: Vec<ResolvedMarkerClaim>,
    trace: RelationTrace,
}

impl ResolvedFollowedCall {
    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.order
    }
    #[must_use]
    pub(crate) const fn occurrence(&self) -> &ScopedEntityId<CallOccurrenceEntity> {
        &self.occurrence
    }
    #[must_use]
    pub(crate) const fn occurrence_data(&self) -> &CallOccurrenceEntity {
        &self.occurrence_data
    }
    #[must_use]
    pub(crate) const fn call_site(&self) -> &ScopedEntityId<CallSiteEntity> {
        &self.call_site
    }
    #[must_use]
    pub(crate) const fn call_site_data(&self) -> &CallSiteEntity {
        &self.call_site_data
    }
    #[must_use]
    pub(crate) const fn safety_group(&self) -> &ScopedEntityId<SafetyEffectGroupEntity> {
        &self.safety_group
    }
    #[must_use]
    pub(crate) const fn safety_group_data(&self) -> &SafetyEffectGroupEntity {
        &self.safety_group_data
    }
    #[must_use]
    pub(crate) const fn kind(&self) -> CallKind {
        self.occurrence_data.kind()
    }
    #[must_use]
    pub(crate) const fn effective_kind(&self) -> CallKind {
        self.effective_kind
    }
    #[must_use]
    pub(crate) const fn resolution(&self) -> &ProgramCallResolution {
        &self.resolution
    }
    #[must_use]
    pub(crate) fn source_anchors(&self) -> &[ResolvedCallSourceAnchor] {
        &self.source_anchors
    }
    #[must_use]
    pub(crate) fn macro_frames(&self) -> &[ResolvedCallMacroFrame] {
        &self.macro_frames
    }
    #[must_use]
    pub(crate) const fn target(&self) -> &CallTargetSelection {
        &self.target
    }
    #[must_use]
    pub(crate) const fn target_data(&self) -> &CallableEntity {
        &self.target_data
    }
    #[must_use]
    pub(crate) fn inherited_markers(&self) -> &[ResolvedMarkerClaim] {
        &self.inherited_markers
    }
    #[must_use]
    pub(crate) fn attached_marker_candidates(&self) -> &[ResolvedMarkerClaim] {
        &self.attached_marker_candidates
    }
    #[must_use]
    pub(crate) fn active_markers(&self) -> &[ResolvedMarkerClaim] {
        &self.active_markers
    }
    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }
}

impl<B> ResolvedCallBoundary<B> {
    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.order
    }
    #[must_use]
    pub(crate) const fn occurrence(&self) -> &ScopedEntityId<CallOccurrenceEntity> {
        &self.occurrence
    }
    #[must_use]
    pub(crate) const fn occurrence_data(&self) -> &CallOccurrenceEntity {
        &self.occurrence_data
    }
    #[must_use]
    pub(crate) const fn call_site(&self) -> &ScopedEntityId<CallSiteEntity> {
        &self.call_site
    }
    #[must_use]
    pub(crate) const fn call_site_data(&self) -> &CallSiteEntity {
        &self.call_site_data
    }
    #[must_use]
    pub(crate) const fn safety_group(&self) -> &ScopedEntityId<SafetyEffectGroupEntity> {
        &self.safety_group
    }
    #[must_use]
    pub(crate) const fn safety_group_data(&self) -> &SafetyEffectGroupEntity {
        &self.safety_group_data
    }
    #[must_use]
    pub(crate) const fn kind(&self) -> CallKind {
        self.occurrence_data.kind()
    }
    #[must_use]
    pub(crate) const fn effective_kind(&self) -> CallKind {
        self.effective_kind
    }
    #[must_use]
    pub(crate) const fn resolution(&self) -> &ProgramCallResolution {
        &self.resolution
    }
    #[must_use]
    pub(crate) fn source_anchors(&self) -> &[ResolvedCallSourceAnchor] {
        &self.source_anchors
    }
    #[must_use]
    pub(crate) fn macro_frames(&self) -> &[ResolvedCallMacroFrame] {
        &self.macro_frames
    }
    #[must_use]
    pub(crate) const fn target(&self) -> Option<&CallTargetSelection> {
        self.target.as_ref()
    }
    #[must_use]
    pub(crate) const fn target_data(&self) -> Option<&CallableEntity> {
        self.target_data.as_ref()
    }
    #[must_use]
    pub(crate) fn inherited_markers(&self) -> &[ResolvedMarkerClaim] {
        &self.inherited_markers
    }
    #[must_use]
    pub(crate) fn attached_marker_candidates(&self) -> &[ResolvedMarkerClaim] {
        &self.attached_marker_candidates
    }
    #[must_use]
    pub(crate) fn active_markers(&self) -> &[ResolvedMarkerClaim] {
        &self.active_markers
    }
    #[must_use]
    pub(crate) const fn payload(&self) -> &B {
        &self.payload
    }
    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }
}

/// Fully bound output whose every trace was checked against the exact graph.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedRootProgramTraversal<B> {
    workspace: Arc<WorkspaceIdentity>,
    root: EvaluationRoot,
    body_visits: Vec<ResolvedBodyVisit>,
    effect_visits: Vec<ResolvedEffectVisit>,
    unsafe_operation_visits: Vec<ResolvedUnsafeOperationVisit>,
    occurrence_visits: Vec<ResolvedOccurrenceVisit>,
    callable_resolutions: Vec<ResolvedCallableResolution>,
    consumer_body_sources: Vec<ResolvedConsumerBodySource>,
    consumer_reconciliations: Vec<ResolvedConsumerOccurrenceReconciliation>,
    followed_calls: Vec<ResolvedFollowedCall>,
    body_boundaries: Vec<ResolvedBodyBoundary<B>>,
    call_boundaries: Vec<ResolvedCallBoundary<B>>,
    outcomes: Vec<ResolvedTraversalOutcome>,
}

impl<B> ResolvedRootProgramTraversal<B> {
    /// Returns the opaque process-local identity of the workspace that was
    /// used to resolve every retained row, entity, and trace.
    #[must_use]
    pub(in crate::analysis::facts) const fn workspace_identity(&self) -> &Arc<WorkspaceIdentity> {
        &self.workspace
    }

    #[must_use]
    pub(crate) fn belongs_to(&self, workspace: &WorkspaceFactView<'_>) -> bool {
        workspace.has_identity(&self.workspace)
    }

    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        &self.root
    }

    #[must_use]
    pub(crate) fn body_visits(&self) -> &[ResolvedBodyVisit] {
        &self.body_visits
    }

    #[must_use]
    pub(crate) fn effect_visits(&self) -> &[ResolvedEffectVisit] {
        &self.effect_visits
    }

    #[must_use]
    pub(crate) fn unsafe_operation_visits(&self) -> &[ResolvedUnsafeOperationVisit] {
        &self.unsafe_operation_visits
    }

    #[must_use]
    pub(crate) fn occurrence_visits(&self) -> &[ResolvedOccurrenceVisit] {
        &self.occurrence_visits
    }

    #[must_use]
    pub(crate) fn callable_resolutions(&self) -> &[ResolvedCallableResolution] {
        &self.callable_resolutions
    }

    #[must_use]
    pub(crate) fn consumer_body_sources(&self) -> &[ResolvedConsumerBodySource] {
        &self.consumer_body_sources
    }

    #[must_use]
    pub(crate) fn consumer_reconciliations(&self) -> &[ResolvedConsumerOccurrenceReconciliation] {
        &self.consumer_reconciliations
    }

    #[must_use]
    pub(crate) fn followed_calls(&self) -> &[ResolvedFollowedCall] {
        &self.followed_calls
    }

    #[must_use]
    pub(crate) fn body_boundaries(&self) -> &[ResolvedBodyBoundary<B>] {
        &self.body_boundaries
    }

    #[must_use]
    pub(crate) fn call_boundaries(&self) -> &[ResolvedCallBoundary<B>] {
        &self.call_boundaries
    }

    #[must_use]
    pub(crate) fn outcomes(&self) -> &[ResolvedTraversalOutcome] {
        &self.outcomes
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ProgramCompositionEdge {
    CallableBody {
        callable: ScopedEntityId<CallableEntity>,
        body: ScopedEntityId<FunctionEntity>,
        selection: CallableBodySelectionKind,
    },
    CallableInvocation {
        invocation: ScopedEntityId<CallOccurrenceEntity>,
        callable: ScopedEntityId<CallableEntity>,
        evidence: ScopedEntityRef,
        key: CallableKey,
        resolution: CallableResolutionKind,
    },
    ConsumerBody {
        consumer: ScopedEntityId<FunctionEntity>,
        defining: ScopedEntityId<FunctionEntity>,
    },
    ConsumerOccurrence {
        consumer: ScopedEntityId<CallOccurrenceEntity>,
        defining: ScopedEntityId<CallOccurrenceEntity>,
        reconciliation: ConsumerOccurrenceReconciliationKind,
    },
}

impl ProgramCompositionEdge {
    fn schema(&self) -> &'static str {
        match self {
            Self::CallableBody { .. } => CallableSelectsFunctionBody::ID,
            Self::CallableInvocation { .. } => CallableInvocationTargetsCallable::ID,
            Self::ConsumerBody { .. } => ConsumerOverlayUsesDefiningSourceBody::ID,
            Self::ConsumerOccurrence { .. } => ConsumerOccurrenceReconcilesWith::ID,
        }
    }

    fn from(&self) -> ScopedEntityRef {
        match self {
            Self::CallableBody { callable, .. } => callable.erase(),
            Self::CallableInvocation { invocation, .. } => invocation.erase(),
            Self::ConsumerBody { consumer, .. } => consumer.erase(),
            Self::ConsumerOccurrence { consumer, .. } => consumer.erase(),
        }
    }

    fn to(&self) -> ScopedEntityRef {
        match self {
            Self::CallableBody { body, .. } => body.erase(),
            Self::CallableInvocation { callable, .. } => callable.erase(),
            Self::ConsumerBody { defining, .. } => defining.erase(),
            Self::ConsumerOccurrence { defining, .. } => defining.erase(),
        }
    }

    fn source(&self) -> Option<&ScopedEntityRef> {
        match self {
            Self::CallableInvocation { evidence, .. } => Some(evidence),
            Self::CallableBody { .. }
            | Self::ConsumerBody { .. }
            | Self::ConsumerOccurrence { .. } => None,
        }
    }

    fn describe(&self) -> String {
        format!(
            "{} from {:?} to {:?} with source {:?}",
            self.schema(),
            self.from(),
            self.to(),
            self.source()
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PreparedRelationRef {
    Artifact(ScopedRelationRef),
    Composition(ProgramCompositionEdge),
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct PreparedPathId(usize);

#[derive(Clone, Debug)]
struct PreparedPathNode {
    parent: Option<PreparedPathId>,
    relation: Option<PreparedRelationRef>,
    target: ScopedEntityRef,
}

/// Shared backpointer arena keeps scheduling a deep chain O(edges), not O(depth²).
#[derive(Clone, Debug)]
struct PreparedPathArena {
    nodes: Vec<PreparedPathNode>,
}

impl PreparedPathArena {
    fn new(root: ScopedEntityRef) -> Self {
        Self {
            nodes: vec![PreparedPathNode {
                parent: None,
                relation: None,
                target: root,
            }],
        }
    }

    const fn root() -> PreparedPathId {
        PreparedPathId(0)
    }

    fn target(&self, path: PreparedPathId) -> &ScopedEntityRef {
        &self.nodes[path.0].target
    }

    fn append_artifact(
        &mut self,
        path: PreparedPathId,
        from: &ScopedEntityRef,
        to: ScopedEntityRef,
        relation: ScopedRelationRef,
    ) -> Result<PreparedPathId, String> {
        self.append(path, from, to, PreparedRelationRef::Artifact(relation))
    }

    fn append_composition(
        &mut self,
        path: PreparedPathId,
        edge: ProgramCompositionEdge,
    ) -> Result<PreparedPathId, String> {
        let from = edge.from();
        let to = edge.to();
        self.append(path, &from, to, PreparedRelationRef::Composition(edge))
    }

    fn append(
        &mut self,
        path: PreparedPathId,
        from: &ScopedEntityRef,
        to: ScopedEntityRef,
        relation: PreparedRelationRef,
    ) -> Result<PreparedPathId, String> {
        let actual = self.target(path);
        if actual != from {
            return Err(format!(
                "new relation starts at {from:?}, but its parent path ends at {actual:?}"
            ));
        }
        let id = PreparedPathId(self.nodes.len());
        self.nodes.push(PreparedPathNode {
            parent: Some(path),
            relation: Some(relation),
            target: to,
        });
        Ok(id)
    }

    fn relations(&self, path: PreparedPathId) -> Vec<&PreparedRelationRef> {
        let mut cursor = Some(path);
        let mut reversed = Vec::new();
        while let Some(id) = cursor {
            let node = &self.nodes[id.0];
            if let Some(relation) = &node.relation {
                reversed.push(relation);
            }
            cursor = node.parent;
        }
        reversed.reverse();
        reversed
    }
}

#[derive(Clone, Debug)]
struct PreparedMarkerClaim {
    data: MarkerClaimEntity,
    path: PreparedPathId,
}

#[derive(Clone, Debug, Default)]
struct PreparedMarkerState(BTreeMap<ScopedEntityId<MarkerClaimEntity>, PreparedMarkerClaim>);

impl PreparedMarkerState {
    fn signature(&self) -> BTreeSet<ScopedEntityRef> {
        self.0.keys().map(ScopedEntityId::erase).collect()
    }

    fn policy_values(&self) -> Vec<MarkerClaimPolicyValue> {
        self.0
            .iter()
            .map(|(claim, prepared)| MarkerClaimPolicyValue {
                claim: claim.clone(),
                data: prepared.data.clone(),
            })
            .collect()
    }

    fn add_new(&mut self, candidates: &Self) {
        for (claim, prepared) in &candidates.0 {
            self.0
                .entry(claim.clone())
                .or_insert_with(|| prepared.clone());
        }
    }
}

#[derive(Clone, Debug)]
struct PreparedBodyVisit {
    order: u64,
    body: ScopedEntityId<FunctionEntity>,
    data: FunctionEntity,
    active_markers: PreparedMarkerState,
    endpoint_marker_candidates: PreparedMarkerState,
    path: PreparedPathId,
}

#[derive(Clone, Debug)]
struct PreparedOccurrenceVisit {
    order: u64,
    occurrence: ScopedEntityId<CallOccurrenceEntity>,
    data: CallOccurrenceEntity,
    source_anchors: Vec<ResolvedCallSourceAnchor>,
    macro_frames: Vec<ResolvedCallMacroFrame>,
    inherited_markers: PreparedMarkerState,
    attached_marker_candidates: PreparedMarkerState,
    active_markers: PreparedMarkerState,
    path: PreparedPathId,
}

#[derive(Clone, Debug)]
struct PreparedEffectVisit {
    order: u64,
    effect: ScopedEntityId<EffectSiteEntity>,
    data: EffectSiteEntity,
    source_anchors: Vec<ResolvedEffectSourceAnchor>,
    macro_frames: Vec<ResolvedEffectMacroFrame>,
    inherited_markers: PreparedMarkerState,
    attached_marker_candidates: PreparedMarkerState,
    active_markers: PreparedMarkerState,
    path: PreparedPathId,
}

#[derive(Clone, Debug)]
struct PreparedUnsafeOperationVisit {
    order: u64,
    operation: ScopedEntityId<UnsafeOperationEntity>,
    data: UnsafeOperationEntity,
    owner: ScopedEntityId<FunctionEntity>,
    owner_data: FunctionEntity,
    owner_relation: ScopedRelationRef,
    safety_group: ScopedEntityId<SafetyEffectGroupEntity>,
    safety_group_data: SafetyEffectGroupEntity,
    safety_group_relation: ScopedRelationRef,
    source_anchors: Vec<ResolvedUnsafeOperationSourceAnchor>,
    macro_frames: Vec<ResolvedUnsafeOperationMacroFrame>,
    inherited_markers: PreparedMarkerState,
    attached_marker_candidates: PreparedMarkerState,
    active_markers: PreparedMarkerState,
    path: PreparedPathId,
}

#[derive(Clone, Debug)]
struct PreparedTraversalOutcome {
    order: u64,
    kind: TraversalOutcomeKind,
    path: PreparedPathId,
}

#[derive(Clone, Debug)]
struct PreparedBodyBoundary<B> {
    order: u64,
    body: ScopedEntityId<FunctionEntity>,
    body_data: FunctionEntity,
    callable: ScopedEntityId<CallableEntity>,
    callable_data: CallableEntity,
    active_markers: PreparedMarkerState,
    endpoint_marker_candidates: PreparedMarkerState,
    payload: B,
    path: PreparedPathId,
}

#[derive(Clone, Debug)]
struct PreparedCallBoundary<B> {
    order: u64,
    occurrence: ScopedEntityId<CallOccurrenceEntity>,
    occurrence_data: CallOccurrenceEntity,
    call_site: ScopedEntityId<CallSiteEntity>,
    call_site_data: CallSiteEntity,
    safety_group: ScopedEntityId<SafetyEffectGroupEntity>,
    safety_group_data: SafetyEffectGroupEntity,
    effective_kind: CallKind,
    resolution: ProgramCallResolution,
    source_anchors: Vec<ResolvedCallSourceAnchor>,
    macro_frames: Vec<ResolvedCallMacroFrame>,
    target: Option<CallTargetSelection>,
    target_data: Option<CallableEntity>,
    inherited_markers: PreparedMarkerState,
    attached_marker_candidates: PreparedMarkerState,
    active_markers: PreparedMarkerState,
    payload: B,
    path: PreparedPathId,
}

#[derive(Clone, Debug)]
struct PreparedFollowedCall {
    order: u64,
    occurrence: ScopedEntityId<CallOccurrenceEntity>,
    occurrence_data: CallOccurrenceEntity,
    call_site: ScopedEntityId<CallSiteEntity>,
    call_site_data: CallSiteEntity,
    safety_group: ScopedEntityId<SafetyEffectGroupEntity>,
    safety_group_data: SafetyEffectGroupEntity,
    effective_kind: CallKind,
    resolution: ProgramCallResolution,
    source_anchors: Vec<ResolvedCallSourceAnchor>,
    macro_frames: Vec<ResolvedCallMacroFrame>,
    target: CallTargetSelection,
    target_data: CallableEntity,
    inherited_markers: PreparedMarkerState,
    attached_marker_candidates: PreparedMarkerState,
    active_markers: PreparedMarkerState,
    path: PreparedPathId,
}

#[derive(Clone, Debug)]
struct PreparedCallableResolution {
    order: u64,
    edge: ProgramCompositionEdge,
    invocation_data: CallOccurrenceEntity,
    evidence: ScopedEntityId<CallOccurrenceEntity>,
    evidence_data: CallOccurrenceEntity,
    callable_data: CallableEntity,
    resolution_path: PreparedPathId,
    evidence_path: PreparedPathId,
}

#[derive(Clone, Debug)]
struct PreparedConsumerBodySource {
    order: u64,
    consumer: ScopedEntityId<FunctionEntity>,
    consumer_data: FunctionEntity,
    defining: ScopedEntityId<FunctionEntity>,
    defining_data: FunctionEntity,
    selection: CallableBodySelectionKind,
    path: PreparedPathId,
}

#[derive(Clone, Debug)]
struct PreparedConsumerOccurrenceReconciliation {
    order: u64,
    consumer: ScopedEntityId<CallOccurrenceEntity>,
    consumer_data: CallOccurrenceEntity,
    consumer_call_site: ScopedEntityId<CallSiteEntity>,
    consumer_call_site_data: CallSiteEntity,
    consumer_safety_group: ScopedEntityId<SafetyEffectGroupEntity>,
    consumer_safety_group_data: SafetyEffectGroupEntity,
    defining: ScopedEntityId<CallOccurrenceEntity>,
    defining_data: CallOccurrenceEntity,
    defining_call_site: ScopedEntityId<CallSiteEntity>,
    defining_call_site_data: CallSiteEntity,
    defining_safety_group: ScopedEntityId<SafetyEffectGroupEntity>,
    defining_safety_group_data: SafetyEffectGroupEntity,
    kind: ConsumerOccurrenceReconciliationKind,
    path: PreparedPathId,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ConsumerReconciliationMetrics {
    plans_built: usize,
    plan_cache_hits: usize,
    defining_routes_indexed: usize,
    source_bucket_lookups: usize,
    semantic_candidates_inspected: usize,
    unsafe_route_indexes_built: usize,
    unsafe_route_cache_hits: usize,
}

/// Immutable symbolic traversal, ready to emit only its deduplicated edges.
#[derive(Debug)]
pub(crate) struct PreparedRootProgramTraversal<B, E: Error> {
    workspace: Arc<WorkspaceIdentity>,
    root: EvaluationRoot,
    paths: PreparedPathArena,
    composition_edges: BTreeSet<ProgramCompositionEdge>,
    callable_resolutions: Vec<PreparedCallableResolution>,
    consumer_body_sources: Vec<PreparedConsumerBodySource>,
    consumer_reconciliations: Vec<PreparedConsumerOccurrenceReconciliation>,
    body_visits: Vec<PreparedBodyVisit>,
    effect_visits: Vec<PreparedEffectVisit>,
    unsafe_operation_visits: Vec<PreparedUnsafeOperationVisit>,
    occurrence_visits: Vec<PreparedOccurrenceVisit>,
    followed_calls: Vec<PreparedFollowedCall>,
    body_boundaries: Vec<PreparedBodyBoundary<B>>,
    call_boundaries: Vec<PreparedCallBoundary<B>>,
    outcomes: Vec<PreparedTraversalOutcome>,
    #[cfg(test)]
    consumer_reconciliation_metrics: ConsumerReconciliationMetrics,
    error: PhantomData<fn() -> E>,
}

/// Typestate proof that this traversal's program edges were emitted once.
#[derive(Debug)]
pub(crate) struct EmittedRootProgramTraversal<B, E: Error> {
    prepared: PreparedRootProgramTraversal<B, E>,
}

impl<B, E> PreparedRootProgramTraversal<B, E>
where
    B: Clone + fmt::Debug + Eq,
    E: Error,
{
    pub(crate) fn prepare<P>(
        workspace: &WorkspaceFactView<'_>,
        index: &WorkspaceProgramIndex,
        resolver: &VerifiedDefiningScopeMap,
        request: &RootProgramTraversalRequest,
        policy: &mut P,
    ) -> Result<Self, RootProgramTraversalError<E>>
    where
        P: RootProgramTraversalPolicy<Boundary = B, Error = E>,
    {
        engine::prepare(workspace, index, resolver, request, policy)
    }

    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        &self.root
    }

    #[must_use]
    pub(crate) fn composition_edge_count(&self) -> usize {
        self.composition_edges.len()
    }

    pub(crate) fn emit(
        self,
        builder: &mut CompositionRelationBuilder<'_, '_>,
    ) -> Result<EmittedRootProgramTraversal<B, E>, RootProgramTraversalError<E>> {
        if !builder.has_workspace_identity(&self.workspace) {
            return Err(RootProgramTraversalError::WorkspaceMismatch);
        }
        if builder.root() != &self.root {
            return Err(RootProgramTraversalError::RootMismatch {
                expected: Box::new(self.root.clone()),
                found: Box::new(builder.root().clone()),
            });
        }
        builder.transaction(|builder| {
            for edge in &self.composition_edges {
                match edge {
                    ProgramCompositionEdge::CallableBody {
                        callable,
                        body,
                        selection,
                    } => builder.relate(
                        callable,
                        body,
                        &CallableSelectsFunctionBody::new(*selection),
                    ),
                    ProgramCompositionEdge::CallableInvocation {
                        invocation,
                        callable,
                        evidence,
                        key,
                        resolution,
                    } => builder.relate_with_source(
                        invocation,
                        callable,
                        evidence,
                        &CallableInvocationTargetsCallable::try_new(*key, *resolution).map_err(
                            |source| RootProgramTraversalError::InvalidPreparedPath {
                                reason: format!("invalid callable resolution edge: {source}"),
                            },
                        )?,
                    ),
                    ProgramCompositionEdge::ConsumerBody { consumer, defining } => builder.relate(
                        consumer,
                        defining,
                        &ConsumerOverlayUsesDefiningSourceBody::new(),
                    ),
                    ProgramCompositionEdge::ConsumerOccurrence {
                        consumer,
                        defining,
                        reconciliation,
                    } => builder.relate(
                        consumer,
                        defining,
                        &ConsumerOccurrenceReconcilesWith::new(*reconciliation),
                    ),
                }
                .map_err(RootProgramTraversalError::Composition)?;
            }
            Ok(())
        })?;
        Ok(EmittedRootProgramTraversal { prepared: self })
    }
}

impl<B, E> EmittedRootProgramTraversal<B, E>
where
    B: Clone + fmt::Debug + Eq,
    E: Error,
{
    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        &self.prepared.root
    }

    #[allow(
        clippy::too_many_lines,
        reason = "resolution binds each prepared witness category before constructing the immutable result"
    )]
    pub(crate) fn resolve(
        self,
        graph: &WorkspaceRelationGraph,
        registry: &CompositionRelationRegistry,
    ) -> Result<ResolvedRootProgramTraversal<B>, RootProgramTraversalError<E>> {
        if !graph.has_workspace_identity(&self.prepared.workspace) {
            return Err(RootProgramTraversalError::WorkspaceMismatch);
        }
        if graph.root() != &self.prepared.root {
            return Err(RootProgramTraversalError::RootMismatch {
                expected: Box::new(self.prepared.root.clone()),
                found: Box::new(graph.root().clone()),
            });
        }
        let references = self.resolve_composition_edges(graph, registry)?;
        let mut callable_resolutions = Vec::with_capacity(self.prepared.callable_resolutions.len());
        for resolution in &self.prepared.callable_resolutions {
            if !references.contains_key(&resolution.edge) {
                return Err(RootProgramTraversalError::MissingCompositionEdge {
                    edge: resolution.edge.describe(),
                });
            }
            let ProgramCompositionEdge::CallableInvocation {
                invocation,
                callable,
                key,
                resolution: kind,
                ..
            } = &resolution.edge
            else {
                return Err(RootProgramTraversalError::MismatchedCompositionEdge {
                    edge: resolution.edge.describe(),
                });
            };
            callable_resolutions.push(ResolvedCallableResolution {
                order: resolution.order,
                invocation: invocation.clone(),
                invocation_data: resolution.invocation_data.clone(),
                evidence: resolution.evidence.clone(),
                evidence_data: resolution.evidence_data.clone(),
                callable: callable.clone(),
                callable_data: resolution.callable_data.clone(),
                key: *key,
                kind: *kind,
                resolution_trace: self.resolve_trace(
                    graph,
                    &references,
                    resolution.resolution_path,
                )?,
                evidence_trace: self.resolve_trace(graph, &references, resolution.evidence_path)?,
            });
        }
        let mut body_visits = Vec::with_capacity(self.prepared.body_visits.len());
        for visit in &self.prepared.body_visits {
            body_visits.push(ResolvedBodyVisit {
                order: visit.order,
                body: visit.body.clone(),
                data: visit.data.clone(),
                active_markers: self.resolve_markers(graph, &references, &visit.active_markers)?,
                endpoint_marker_candidates: self.resolve_markers(
                    graph,
                    &references,
                    &visit.endpoint_marker_candidates,
                )?,
                trace: self.resolve_trace(graph, &references, visit.path)?,
            });
        }
        let mut effect_visits = Vec::with_capacity(self.prepared.effect_visits.len());
        for visit in &self.prepared.effect_visits {
            effect_visits.push(ResolvedEffectVisit {
                order: visit.order,
                effect: visit.effect.clone(),
                data: visit.data.clone(),
                source_anchors: visit.source_anchors.clone(),
                macro_frames: visit.macro_frames.clone(),
                inherited_markers: self.resolve_markers(
                    graph,
                    &references,
                    &visit.inherited_markers,
                )?,
                attached_marker_candidates: self.resolve_markers(
                    graph,
                    &references,
                    &visit.attached_marker_candidates,
                )?,
                active_markers: self.resolve_markers(graph, &references, &visit.active_markers)?,
                trace: self.resolve_trace(graph, &references, visit.path)?,
            });
        }
        let mut unsafe_operation_visits =
            Vec::with_capacity(self.prepared.unsafe_operation_visits.len());
        for visit in &self.prepared.unsafe_operation_visits {
            unsafe_operation_visits.push(ResolvedUnsafeOperationVisit {
                order: visit.order,
                operation: visit.operation.clone(),
                data: visit.data.clone(),
                owner: visit.owner.clone(),
                owner_data: visit.owner_data.clone(),
                owner_relation: visit.owner_relation.clone(),
                safety_group: visit.safety_group.clone(),
                safety_group_data: visit.safety_group_data.clone(),
                safety_group_relation: visit.safety_group_relation.clone(),
                source_anchors: visit.source_anchors.clone(),
                macro_frames: visit.macro_frames.clone(),
                inherited_markers: self.resolve_markers(
                    graph,
                    &references,
                    &visit.inherited_markers,
                )?,
                attached_marker_candidates: self.resolve_markers(
                    graph,
                    &references,
                    &visit.attached_marker_candidates,
                )?,
                active_markers: self.resolve_markers(graph, &references, &visit.active_markers)?,
                trace: self.resolve_trace(graph, &references, visit.path)?,
            });
        }
        let mut occurrence_visits = Vec::with_capacity(self.prepared.occurrence_visits.len());
        for visit in &self.prepared.occurrence_visits {
            occurrence_visits.push(ResolvedOccurrenceVisit {
                order: visit.order,
                occurrence: visit.occurrence.clone(),
                data: visit.data.clone(),
                source_anchors: visit.source_anchors.clone(),
                macro_frames: visit.macro_frames.clone(),
                inherited_markers: self.resolve_markers(
                    graph,
                    &references,
                    &visit.inherited_markers,
                )?,
                attached_marker_candidates: self.resolve_markers(
                    graph,
                    &references,
                    &visit.attached_marker_candidates,
                )?,
                active_markers: self.resolve_markers(graph, &references, &visit.active_markers)?,
                trace: self.resolve_trace(graph, &references, visit.path)?,
            });
        }
        let consumer_body_sources = self
            .prepared
            .consumer_body_sources
            .iter()
            .map(|source| {
                Ok(ResolvedConsumerBodySource {
                    order: source.order,
                    consumer: source.consumer.clone(),
                    consumer_data: source.consumer_data.clone(),
                    defining: source.defining.clone(),
                    defining_data: source.defining_data.clone(),
                    selection: source.selection,
                    trace: self.resolve_trace(graph, &references, source.path)?,
                })
            })
            .collect::<Result<Vec<_>, RootProgramTraversalError<E>>>()?;
        let consumer_reconciliations = self
            .prepared
            .consumer_reconciliations
            .iter()
            .map(|reconciliation| {
                Ok(ResolvedConsumerOccurrenceReconciliation {
                    order: reconciliation.order,
                    consumer: reconciliation.consumer.clone(),
                    consumer_data: reconciliation.consumer_data.clone(),
                    consumer_call_site: reconciliation.consumer_call_site.clone(),
                    consumer_call_site_data: reconciliation.consumer_call_site_data.clone(),
                    consumer_safety_group: reconciliation.consumer_safety_group.clone(),
                    consumer_safety_group_data: reconciliation.consumer_safety_group_data.clone(),
                    defining: reconciliation.defining.clone(),
                    defining_data: reconciliation.defining_data.clone(),
                    defining_call_site: reconciliation.defining_call_site.clone(),
                    defining_call_site_data: reconciliation.defining_call_site_data.clone(),
                    defining_safety_group: reconciliation.defining_safety_group.clone(),
                    defining_safety_group_data: reconciliation.defining_safety_group_data.clone(),
                    kind: reconciliation.kind,
                    trace: self.resolve_trace(graph, &references, reconciliation.path)?,
                })
            })
            .collect::<Result<Vec<_>, RootProgramTraversalError<E>>>()?;
        let followed_calls = self
            .prepared
            .followed_calls
            .iter()
            .map(|followed| {
                Ok(ResolvedFollowedCall {
                    order: followed.order,
                    occurrence: followed.occurrence.clone(),
                    occurrence_data: followed.occurrence_data.clone(),
                    call_site: followed.call_site.clone(),
                    call_site_data: followed.call_site_data.clone(),
                    safety_group: followed.safety_group.clone(),
                    safety_group_data: followed.safety_group_data.clone(),
                    effective_kind: followed.effective_kind,
                    resolution: followed.resolution.clone(),
                    source_anchors: followed.source_anchors.clone(),
                    macro_frames: followed.macro_frames.clone(),
                    target: followed.target.clone(),
                    target_data: followed.target_data.clone(),
                    inherited_markers: self.resolve_markers(
                        graph,
                        &references,
                        &followed.inherited_markers,
                    )?,
                    attached_marker_candidates: self.resolve_markers(
                        graph,
                        &references,
                        &followed.attached_marker_candidates,
                    )?,
                    active_markers: self.resolve_markers(
                        graph,
                        &references,
                        &followed.active_markers,
                    )?,
                    trace: self.resolve_trace(graph, &references, followed.path)?,
                })
            })
            .collect::<Result<Vec<_>, RootProgramTraversalError<E>>>()?;
        let outcomes = self
            .prepared
            .outcomes
            .iter()
            .map(|outcome| {
                Ok(ResolvedTraversalOutcome {
                    order: outcome.order,
                    kind: outcome.kind.clone(),
                    trace: self.resolve_trace(graph, &references, outcome.path)?,
                })
            })
            .collect::<Result<Vec<_>, RootProgramTraversalError<E>>>()?;
        let body_boundaries = self
            .prepared
            .body_boundaries
            .iter()
            .map(|boundary| {
                Ok(ResolvedBodyBoundary {
                    order: boundary.order,
                    body: boundary.body.clone(),
                    body_data: boundary.body_data.clone(),
                    callable: boundary.callable.clone(),
                    callable_data: boundary.callable_data.clone(),
                    active_markers: self.resolve_markers(
                        graph,
                        &references,
                        &boundary.active_markers,
                    )?,
                    endpoint_marker_candidates: self.resolve_markers(
                        graph,
                        &references,
                        &boundary.endpoint_marker_candidates,
                    )?,
                    payload: boundary.payload.clone(),
                    trace: self.resolve_trace(graph, &references, boundary.path)?,
                })
            })
            .collect::<Result<Vec<_>, RootProgramTraversalError<E>>>()?;
        let call_boundaries = self
            .prepared
            .call_boundaries
            .iter()
            .map(|boundary| {
                Ok(ResolvedCallBoundary {
                    order: boundary.order,
                    occurrence: boundary.occurrence.clone(),
                    occurrence_data: boundary.occurrence_data.clone(),
                    call_site: boundary.call_site.clone(),
                    call_site_data: boundary.call_site_data.clone(),
                    safety_group: boundary.safety_group.clone(),
                    safety_group_data: boundary.safety_group_data.clone(),
                    effective_kind: boundary.effective_kind,
                    resolution: boundary.resolution.clone(),
                    source_anchors: boundary.source_anchors.clone(),
                    macro_frames: boundary.macro_frames.clone(),
                    target: boundary.target.clone(),
                    target_data: boundary.target_data.clone(),
                    inherited_markers: self.resolve_markers(
                        graph,
                        &references,
                        &boundary.inherited_markers,
                    )?,
                    attached_marker_candidates: self.resolve_markers(
                        graph,
                        &references,
                        &boundary.attached_marker_candidates,
                    )?,
                    active_markers: self.resolve_markers(
                        graph,
                        &references,
                        &boundary.active_markers,
                    )?,
                    payload: boundary.payload.clone(),
                    trace: self.resolve_trace(graph, &references, boundary.path)?,
                })
            })
            .collect::<Result<Vec<_>, RootProgramTraversalError<E>>>()?;
        Ok(ResolvedRootProgramTraversal {
            workspace: Arc::clone(&self.prepared.workspace),
            root: self.prepared.root.clone(),
            body_visits,
            effect_visits,
            unsafe_operation_visits,
            occurrence_visits,
            callable_resolutions,
            consumer_body_sources,
            consumer_reconciliations,
            followed_calls,
            body_boundaries,
            call_boundaries,
            outcomes,
        })
    }

    fn resolve_markers(
        &self,
        graph: &WorkspaceRelationGraph,
        references: &BTreeMap<ProgramCompositionEdge, CompositionRelationRef>,
        markers: &PreparedMarkerState,
    ) -> Result<Vec<ResolvedMarkerClaim>, RootProgramTraversalError<E>> {
        markers
            .0
            .iter()
            .map(|(claim, prepared)| {
                Ok(ResolvedMarkerClaim {
                    claim: claim.clone(),
                    data: prepared.data.clone(),
                    trace: self.resolve_trace(graph, references, prepared.path)?,
                })
            })
            .collect()
    }

    fn resolve_trace(
        &self,
        graph: &WorkspaceRelationGraph,
        references: &BTreeMap<ProgramCompositionEdge, CompositionRelationRef>,
        path: PreparedPathId,
    ) -> Result<RelationTrace, RootProgramTraversalError<E>> {
        let relations = self
            .prepared
            .paths
            .relations(path)
            .into_iter()
            .map(|reference| match reference {
                PreparedRelationRef::Artifact(reference) => {
                    Ok(WorkspaceRelationRef::Artifact(reference.clone()))
                }
                PreparedRelationRef::Composition(edge) => references
                    .get(edge)
                    .cloned()
                    .map(WorkspaceRelationRef::Composition)
                    .ok_or_else(|| RootProgramTraversalError::MissingCompositionEdge {
                        edge: edge.describe(),
                    }),
            })
            .collect::<Result<Vec<_>, RootProgramTraversalError<E>>>()?;
        graph
            .validate_path(
                &self.prepared.root.entity,
                self.prepared.paths.target(path),
                &relations,
            )
            .map_err(RootProgramTraversalError::Graph)?;
        Ok(RelationTrace::new(
            self.prepared.root.entity.clone(),
            self.prepared.paths.target(path).clone(),
            relations,
        ))
    }

    fn resolve_composition_edges(
        &self,
        graph: &WorkspaceRelationGraph,
        registry: &CompositionRelationRegistry,
    ) -> Result<
        BTreeMap<ProgramCompositionEdge, CompositionRelationRef>,
        RootProgramTraversalError<E>,
    > {
        let db = graph.composition();
        let mut found = BTreeMap::new();
        for row in db.relations() {
            let schema = row.relation.schema.as_str();
            if !is_program_composition_schema(schema) {
                continue;
            }
            let edge = decode_composition_edge(db, &row.relation, registry)?;
            if row.from != edge.from()
                || row.to != edge.to()
                || row.source.as_ref() != edge.source()
            {
                return Err(RootProgramTraversalError::MismatchedCompositionEdge {
                    edge: edge.describe(),
                });
            }
            if !self.prepared.composition_edges.contains(&edge) {
                return Err(RootProgramTraversalError::UnexpectedCompositionEdge {
                    edge: edge.describe(),
                });
            }
            if found.insert(edge.clone(), row.relation.clone()).is_some() {
                return Err(RootProgramTraversalError::DuplicateCompositionEdge {
                    edge: edge.describe(),
                });
            }
        }
        for edge in &self.prepared.composition_edges {
            if !found.contains_key(edge) {
                return Err(RootProgramTraversalError::MissingCompositionEdge {
                    edge: edge.describe(),
                });
            }
        }
        Ok(found)
    }
}

fn is_program_composition_schema(schema: &str) -> bool {
    schema == CallableSelectsFunctionBody::ID
        || schema == CallableInvocationTargetsCallable::ID
        || schema == ConsumerOverlayUsesDefiningSourceBody::ID
        || schema == ConsumerOccurrenceReconcilesWith::ID
}

fn decode_composition_edge<E: Error>(
    db: &crate::analysis::facts::composition::CompositionRelationDb,
    reference: &CompositionRelationRef,
    registry: &CompositionRelationRegistry,
) -> Result<ProgramCompositionEdge, RootProgramTraversalError<E>> {
    match reference.schema.as_str() {
        CallableSelectsFunctionBody::ID => {
            let row = db
                .relation::<CallableSelectsFunctionBody>(reference, registry)
                .map_err(RootProgramTraversalError::Composition)?;
            Ok(ProgramCompositionEdge::CallableBody {
                callable: row.from,
                body: row.to,
                selection: row.data.selection_kind(),
            })
        }
        CallableInvocationTargetsCallable::ID => {
            let row = db
                .relation::<CallableInvocationTargetsCallable>(reference, registry)
                .map_err(RootProgramTraversalError::Composition)?;
            let evidence =
                row.source
                    .ok_or_else(|| RootProgramTraversalError::MismatchedCompositionEdge {
                        edge: format!(
                            "{} has no evidence source",
                            CallableInvocationTargetsCallable::ID
                        ),
                    })?;
            Ok(ProgramCompositionEdge::CallableInvocation {
                invocation: row.from,
                callable: row.to,
                evidence,
                key: row.data.callable_key(),
                resolution: row.data.resolution_kind(),
            })
        }
        ConsumerOverlayUsesDefiningSourceBody::ID => {
            let row = db
                .relation::<ConsumerOverlayUsesDefiningSourceBody>(reference, registry)
                .map_err(RootProgramTraversalError::Composition)?;
            Ok(ProgramCompositionEdge::ConsumerBody {
                consumer: row.from,
                defining: row.to,
            })
        }
        ConsumerOccurrenceReconcilesWith::ID => {
            let row = db
                .relation::<ConsumerOccurrenceReconcilesWith>(reference, registry)
                .map_err(RootProgramTraversalError::Composition)?;
            Ok(ProgramCompositionEdge::ConsumerOccurrence {
                consumer: row.from,
                defining: row.to,
                reconciliation: row.data.reconciliation_kind(),
            })
        }
        schema => Err(RootProgramTraversalError::UnexpectedCompositionEdge {
            edge: format!("unrecognized program composition schema `{schema}`"),
        }),
    }
}

fn next_witness_order<E: Error>(order: &mut u64) -> Result<u64, RootProgramTraversalError<E>> {
    let current = *order;
    *order = order
        .checked_add(1)
        .ok_or(RootProgramTraversalError::WitnessOrderOverflow)?;
    Ok(current)
}

/// Fatal preparation, emission, or exact-path-resolution failure.
#[derive(Debug)]
pub(crate) enum RootProgramTraversalError<E: Error> {
    WorkspaceMismatch,
    RootMismatch {
        expected: Box<EvaluationRoot>,
        found: Box<EvaluationRoot>,
    },
    UnknownRoot {
        scope: ArtifactScopeId,
        function: FunctionKey,
    },
    AuthorityMap(DefiningScopeMapError),
    Index(WorkspaceProgramIndexError),
    Policy {
        stage: &'static str,
        source: E,
    },
    InvalidPreparedPath {
        reason: String,
    },
    InvalidPolicyDecision {
        reason: String,
    },
    UnsupportedFeature {
        feature: &'static str,
        occurrence: Option<ScopedEntityId<CallOccurrenceEntity>>,
    },
    Composition(CompositionBuildError),
    Graph(crate::analysis::facts::composition::graph::WorkspaceRelationError),
    MissingCompositionEdge {
        edge: String,
    },
    UnexpectedCompositionEdge {
        edge: String,
    },
    DuplicateCompositionEdge {
        edge: String,
    },
    MismatchedCompositionEdge {
        edge: String,
    },
    WitnessOrderOverflow,
}

impl<E: Error> Display for RootProgramTraversalError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceMismatch => {
                formatter.write_str("root traversal belongs to a replacement workspace view")
            }
            Self::RootMismatch { expected, found } => write!(
                formatter,
                "root traversal belongs to evaluation root {expected:?}, not {found:?}"
            ),
            Self::UnknownRoot { scope, function } => {
                write!(
                    formatter,
                    "root function {function:?} is unavailable in `{scope}`"
                )
            }
            Self::AuthorityMap(source) => Display::fmt(source, formatter),
            Self::Index(source) => Display::fmt(source, formatter),
            Self::Policy { stage, source } => {
                write!(
                    formatter,
                    "root traversal policy failed during {stage}: {source}"
                )
            }
            Self::InvalidPreparedPath { reason } => {
                write!(formatter, "prepared traversal path is invalid: {reason}")
            }
            Self::InvalidPolicyDecision { reason } => {
                write!(
                    formatter,
                    "root traversal policy selected an invalid target: {reason}"
                )
            }
            Self::UnsupportedFeature {
                feature,
                occurrence,
            } => {
                write!(
                    formatter,
                    "root traversal checkpoint does not yet support {feature}"
                )?;
                if let Some(occurrence) = occurrence {
                    write!(formatter, " at {occurrence:?}")?;
                }
                Ok(())
            }
            Self::Composition(source) => Display::fmt(source, formatter),
            Self::Graph(source) => Display::fmt(source, formatter),
            Self::MissingCompositionEdge { edge } => {
                write!(formatter, "prepared composition edge is missing: {edge}")
            }
            Self::UnexpectedCompositionEdge { edge } => {
                write!(
                    formatter,
                    "composition contains an unexpected program edge: {edge}"
                )
            }
            Self::DuplicateCompositionEdge { edge } => {
                write!(
                    formatter,
                    "composition repeats a prepared program edge: {edge}"
                )
            }
            Self::MismatchedCompositionEdge { edge } => {
                write!(
                    formatter,
                    "composition edge metadata disagrees with its payload: {edge}"
                )
            }
            Self::WitnessOrderOverflow => {
                formatter.write_str("root traversal exceeds stable witness ordering")
            }
        }
    }
}

impl<E: Error + 'static> Error for RootProgramTraversalError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Index(source) => Some(source),
            Self::AuthorityMap(source) => Some(source),
            Self::Composition(source) => Some(source),
            Self::Graph(source) => Some(source),
            Self::Policy { source, .. } => Some(source),
            Self::WorkspaceMismatch
            | Self::RootMismatch { .. }
            | Self::UnknownRoot { .. }
            | Self::InvalidPreparedPath { .. }
            | Self::InvalidPolicyDecision { .. }
            | Self::UnsupportedFeature { .. }
            | Self::MissingCompositionEdge { .. }
            | Self::UnexpectedCompositionEdge { .. }
            | Self::DuplicateCompositionEdge { .. }
            | Self::MismatchedCompositionEdge { .. }
            | Self::WitnessOrderOverflow => None,
        }
    }
}
