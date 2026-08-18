//! Root-specific derived rows for retained panic-call obligations.

use serde::{Deserialize, Serialize};

use crate::analysis::facts::evaluation::{RelationTrace, deserialize_strict_relation_trace};
use crate::analysis::facts::human::markers::MarkerClaimEntity;
use crate::analysis::facts::program::FunctionKey;
use crate::analysis::facts::program::SourceAnchorEntity;
use crate::analysis::facts::program::root_traversal::ReconciledCallTargetAuthority;
use crate::analysis::facts::program::topology::{
    CallKind, CallOccurrenceEntity, CallSiteEntity, CallTargetRole, CallableEntity, CallableKey,
};
use crate::analysis::facts::program::workspace_index::CallableResolutionKind;
use crate::analysis::facts::schema::{DerivedSchema, IssueSchema, RowSchema};
use crate::analysis::facts::workspace::{ArtifactScopeId, ScopedEntityRef, ScopedRowRef};

/// Exact presentation entity plus its contextually resolved function identity.
///
/// The endpoint is deliberately independent from the semantic scope: a raw
/// consumer callable can present a function whose selected body belongs to a
/// managed defining artifact. The requested function key remains exact even
/// when a generic body supplies that semantic scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicCallPresentationFunction {
    endpoint: ScopedEntityRef,
    scope: ArtifactScopeId,
    function: FunctionKey,
}

impl PanicCallPresentationFunction {
    #[must_use]
    pub(crate) const fn new(
        endpoint: ScopedEntityRef,
        scope: ArtifactScopeId,
        function: FunctionKey,
    ) -> Self {
        Self {
            endpoint,
            scope,
            function,
        }
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityRef {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn scope(&self) -> &ArtifactScopeId {
        &self.scope
    }

    #[must_use]
    pub(crate) const fn function(&self) -> &FunctionKey {
        &self.function
    }
}

/// Root-specific immutable projection of one retained panic-call witness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicCallObligation {
    pub(super) call_id: u64,
    pub(super) evidence_rank: u64,
    pub(super) traversal_order: u64,
    pub(super) source: ScopedRowRef,
    pub(super) occurrence: ScopedEntityRef,
    pub(super) occurrence_data: CallOccurrenceEntity,
    pub(super) endpoint: ScopedEntityRef,
    pub(super) presentation_function: PanicCallPresentationFunction,
    pub(super) evidence_group: ScopedEntityRef,
    pub(super) evidence_group_data: CallSiteEntity,
    pub(super) trace_target: ScopedEntityRef,
    #[serde(deserialize_with = "deserialize_strict_relation_trace")]
    pub(super) trace: RelationTrace,
    pub(super) effective_kind: CallKind,
    pub(super) resolution: PanicCallResolution,
    pub(super) boundary: PanicCallBoundaryKind,
    pub(super) metadata_target: Option<PanicCallMetadataTarget>,
    pub(super) contract: Option<PanicCallContractProvenance>,
    pub(super) requirements: Vec<PanicCallRequirementValue>,
    pub(super) active_markers: Vec<PanicCallMarker>,
}

impl RowSchema for PanicCallObligation {
    const ID: &'static str = "sniff-test.panic.call-obligation";
    const VERSION: u32 = 2;
}

impl DerivedSchema for PanicCallObligation {}

impl PanicCallObligation {
    #[must_use]
    pub(crate) const fn call_id(&self) -> u64 {
        self.call_id
    }

    #[must_use]
    pub(crate) const fn evidence_rank(&self) -> u64 {
        self.evidence_rank
    }

    #[must_use]
    pub(crate) const fn traversal_order(&self) -> u64 {
        self.traversal_order
    }

    #[must_use]
    pub(crate) const fn source(&self) -> &ScopedRowRef {
        &self.source
    }

    #[must_use]
    pub(crate) const fn occurrence(&self) -> &ScopedEntityRef {
        &self.occurrence
    }

    #[must_use]
    pub(crate) const fn occurrence_data(&self) -> &CallOccurrenceEntity {
        &self.occurrence_data
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityRef {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn presentation_function(&self) -> &PanicCallPresentationFunction {
        &self.presentation_function
    }

    #[must_use]
    pub(crate) const fn evidence_group(&self) -> &ScopedEntityRef {
        &self.evidence_group
    }

    #[must_use]
    pub(crate) const fn evidence_group_data(&self) -> &CallSiteEntity {
        &self.evidence_group_data
    }

    #[must_use]
    pub(crate) const fn trace_target(&self) -> &ScopedEntityRef {
        &self.trace_target
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }

    #[must_use]
    pub(crate) const fn effective_kind(&self) -> CallKind {
        self.effective_kind
    }

    #[must_use]
    pub(crate) const fn resolution(&self) -> &PanicCallResolution {
        &self.resolution
    }

    #[must_use]
    pub(crate) const fn boundary_kind(&self) -> &PanicCallBoundaryKind {
        &self.boundary
    }

    #[must_use]
    pub(crate) const fn metadata_target(&self) -> Option<&PanicCallMetadataTarget> {
        self.metadata_target.as_ref()
    }

    #[must_use]
    pub(crate) const fn contract(&self) -> Option<&PanicCallContractProvenance> {
        self.contract.as_ref()
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[PanicCallRequirementValue] {
        &self.requirements
    }

    #[must_use]
    pub(crate) fn active_markers(&self) -> &[PanicCallMarker] {
        &self.active_markers
    }
}

/// Domain classification retained at the policy decision boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    deny_unknown_fields
)]
pub(crate) enum PanicCallBoundaryKind {
    Documented {
        trusted: bool,
    },
    PanicSink,
    Opaque {
        opaque_kind: PanicCallOpaqueKind,
        description: String,
    },
}

/// Lossless subtype for an opaque panic-call boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PanicCallOpaqueKind {
    BodylessDeclaration,
    ExplicitOpaque,
}

/// Root-specific projection of persisted or callable-evidence resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    deny_unknown_fields
)]
pub(crate) enum PanicCallResolution {
    Persisted,
    CallableEvidence {
        evidence: ScopedEntityRef,
        key: CallableKey,
        resolution_kind: PanicCallableResolutionKind,
    },
}

/// Stable schema-local mirror of callable-evidence provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PanicCallableResolutionKind {
    FunctionPointerEvidence,
    DynamicDispatchEvidence,
}

impl From<CallableResolutionKind> for PanicCallableResolutionKind {
    fn from(value: CallableResolutionKind) -> Self {
        match value {
            CallableResolutionKind::FunctionPointerEvidence => Self::FunctionPointerEvidence,
            CallableResolutionKind::DynamicDispatchEvidence => Self::DynamicDispatchEvidence,
        }
    }
}

/// Exact selected target identity, role, and reconciliation authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicCallTarget {
    pub(super) role: CallTargetRole,
    pub(super) callable: ScopedEntityRef,
    pub(super) authority: PanicCallTargetAuthority,
}

impl PanicCallTarget {
    #[must_use]
    pub(crate) const fn role(&self) -> CallTargetRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn callable(&self) -> &ScopedEntityRef {
        &self.callable
    }

    #[must_use]
    pub(crate) const fn authority(&self) -> PanicCallTargetAuthority {
        self.authority
    }
}

/// Stable schema-local mirror of target-selection authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PanicCallTargetAuthority {
    ConsumerRaw,
    DefiningTarget,
    DefiningSource,
    ConsumerSource,
}

impl From<ReconciledCallTargetAuthority> for PanicCallTargetAuthority {
    fn from(value: ReconciledCallTargetAuthority) -> Self {
        match value {
            ReconciledCallTargetAuthority::ConsumerRaw => Self::ConsumerRaw,
            ReconciledCallTargetAuthority::DefiningTarget => Self::DefiningTarget,
            ReconciledCallTargetAuthority::DefiningSource => Self::DefiningSource,
            ReconciledCallTargetAuthority::ConsumerSource => Self::ConsumerSource,
        }
    }
}

/// Selected callable metadata retained independently from contract authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicCallMetadataTarget {
    pub(super) selection: PanicCallTarget,
    pub(super) data: CallableEntity,
}

impl PanicCallMetadataTarget {
    #[must_use]
    pub(crate) const fn selection(&self) -> &PanicCallTarget {
        &self.selection
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &CallableEntity {
        &self.data
    }
}

/// Authority lane that supplied one effective contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PanicCallContractOrigin {
    Override,
    RawExact,
    RawGeneric,
}

/// Exact selected effective-contract identity and provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicCallContractProvenance {
    pub(super) target: PanicCallTarget,
    pub(super) queried_callable: ScopedEntityRef,
    pub(super) declaration_owner: ScopedEntityRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) raw_contract: Option<ScopedRowRef>,
    pub(super) origin: PanicCallContractOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) source_anchor: Option<PanicCallAnchorProvenance>,
}

impl PanicCallContractProvenance {
    #[must_use]
    pub(crate) const fn target(&self) -> &PanicCallTarget {
        &self.target
    }

    #[must_use]
    pub(crate) const fn queried_callable(&self) -> &ScopedEntityRef {
        &self.queried_callable
    }

    #[must_use]
    pub(crate) const fn declaration_owner(&self) -> &ScopedEntityRef {
        &self.declaration_owner
    }

    #[must_use]
    pub(crate) const fn raw_contract(&self) -> Option<&ScopedRowRef> {
        self.raw_contract.as_ref()
    }

    #[must_use]
    pub(crate) const fn origin(&self) -> PanicCallContractOrigin {
        self.origin
    }

    #[must_use]
    pub(crate) fn source_anchor(&self) -> Option<&PanicCallAnchorProvenance> {
        self.source_anchor.as_ref()
    }
}

/// One exact active marker claim retained in canonical source order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicCallMarker {
    pub(super) claim: ScopedEntityRef,
    pub(super) data: MarkerClaimEntity,
    #[serde(deserialize_with = "deserialize_strict_relation_trace")]
    pub(super) trace: RelationTrace,
}

impl PanicCallMarker {
    #[must_use]
    pub(crate) const fn claim(&self) -> &ScopedEntityRef {
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

/// Exact source-anchor provenance retained by an effective contract value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicCallAnchorProvenance {
    pub(super) reference: ScopedEntityRef,
    pub(super) data: SourceAnchorEntity,
}

impl PanicCallAnchorProvenance {
    #[must_use]
    pub(crate) const fn reference(&self) -> &ScopedEntityRef {
        &self.reference
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &SourceAnchorEntity {
        &self.data
    }
}

/// One root-local panic-call requirement occurrence in declaration order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum PanicCallRequirementValue {
    Unnamed,
    Named {
        ordinal: u32,
        name: String,
        #[serde(rename = "normalized-name")]
        normalized_name: String,
        condition: String,
        #[serde(rename = "raw-requirement", skip_serializing_if = "Option::is_none")]
        raw_requirement: Option<ScopedRowRef>,
        #[serde(rename = "source-anchor", skip_serializing_if = "Option::is_none")]
        source_anchor: Option<Box<PanicCallAnchorProvenance>>,
    },
}

impl PanicCallRequirementValue {
    #[must_use]
    pub(crate) const fn unnamed() -> Self {
        Self::Unnamed
    }

    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor preserves one strict named requirement projection"
    )]
    pub(crate) fn named(
        ordinal: u32,
        name: impl Into<String>,
        normalized_name: impl Into<String>,
        condition: impl Into<String>,
        raw_requirement: Option<ScopedRowRef>,
        source_anchor: Option<PanicCallAnchorProvenance>,
    ) -> Self {
        Self::Named {
            ordinal,
            name: name.into(),
            normalized_name: normalized_name.into(),
            condition: condition.into(),
            raw_requirement,
            source_anchor: source_anchor.map(Box::new),
        }
    }

    #[must_use]
    pub(crate) const fn ordinal(&self) -> Option<u32> {
        match self {
            Self::Unnamed => None,
            Self::Named { ordinal, .. } => Some(*ordinal),
        }
    }

    #[must_use]
    pub(crate) const fn raw_requirement(&self) -> Option<&ScopedRowRef> {
        match self {
            Self::Unnamed => None,
            Self::Named {
                raw_requirement, ..
            } => raw_requirement.as_ref(),
        }
    }

    #[must_use]
    pub(crate) fn source_anchor(&self) -> Option<&PanicCallAnchorProvenance> {
        match self {
            Self::Unnamed => None,
            Self::Named { source_anchor, .. } => source_anchor.as_deref(),
        }
    }

    #[must_use]
    pub(crate) fn name(&self) -> Option<&str> {
        match self {
            Self::Unnamed => None,
            Self::Named { name, .. } => Some(name),
        }
    }

    #[must_use]
    pub(crate) fn normalized_name(&self) -> Option<&str> {
        match self {
            Self::Unnamed => None,
            Self::Named {
                normalized_name, ..
            } => Some(normalized_name),
        }
    }

    #[must_use]
    pub(crate) fn condition(&self) -> Option<&str> {
        match self {
            Self::Unnamed => None,
            Self::Named { condition, .. } => Some(condition),
        }
    }
}

/// Call-local identity of one requirement atom in a validated obligation.
///
/// The surrounding match row owns the exact call witness identity, so a named
/// requirement needs only its declaration ordinal. Keeping this identity
/// independent of raw requirement rows also represents value-only overrides
/// without fabricating provenance.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum PanicCallRequirementMatchId {
    Unnamed,
    Named { ordinal: u32 },
}

impl PanicCallRequirementMatchId {
    #[must_use]
    pub(crate) const fn unnamed() -> Self {
        Self::Unnamed
    }

    #[must_use]
    pub(crate) const fn named(ordinal: u32) -> Self {
        Self::Named { ordinal }
    }
}

/// Exact call requirement atoms discharged by one human claim.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct PanicCallEvidenceMatch {
    claim: ScopedEntityRef,
    obligation_source: ScopedRowRef,
    endpoint: ScopedEntityRef,
    group: ScopedEntityRef,
    trace_target: ScopedEntityRef,
    #[serde(deserialize_with = "deserialize_strict_relation_trace")]
    trace: RelationTrace,
    witness_order: u64,
    satisfied_requirements: Vec<PanicCallRequirementMatchId>,
}

impl RowSchema for PanicCallEvidenceMatch {
    const ID: &'static str = "sniff-test.panic.call-evidence-match";
    const VERSION: u32 = 1;
}

impl DerivedSchema for PanicCallEvidenceMatch {}

impl PanicCallEvidenceMatch {
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor mirrors the complete call-witness envelope"
    )]
    pub(crate) fn new(
        claim: ScopedEntityRef,
        obligation_source: ScopedRowRef,
        endpoint: ScopedEntityRef,
        group: ScopedEntityRef,
        trace_target: ScopedEntityRef,
        trace: RelationTrace,
        witness_order: u64,
        mut satisfied_requirements: Vec<PanicCallRequirementMatchId>,
    ) -> Self {
        satisfied_requirements.sort();
        satisfied_requirements.dedup();
        Self::new_declaration_ordered(
            claim,
            obligation_source,
            endpoint,
            group,
            trace_target,
            trace,
            witness_order,
            satisfied_requirements,
        )
    }

    /// Builds a match after the caller proves the requirements are nonempty
    /// and in strict declaration order, keeping projection output-linear.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor mirrors the complete call-witness envelope"
    )]
    pub(super) fn new_declaration_ordered(
        claim: ScopedEntityRef,
        obligation_source: ScopedRowRef,
        endpoint: ScopedEntityRef,
        group: ScopedEntityRef,
        trace_target: ScopedEntityRef,
        trace: RelationTrace,
        witness_order: u64,
        satisfied_requirements: Vec<PanicCallRequirementMatchId>,
    ) -> Self {
        Self {
            claim,
            obligation_source,
            endpoint,
            group,
            trace_target,
            trace,
            witness_order,
            satisfied_requirements,
        }
    }

    #[must_use]
    pub(crate) const fn claim(&self) -> &ScopedEntityRef {
        &self.claim
    }

    #[must_use]
    pub(crate) const fn obligation_source(&self) -> &ScopedRowRef {
        &self.obligation_source
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityRef {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn group(&self) -> &ScopedEntityRef {
        &self.group
    }

    #[must_use]
    pub(crate) const fn trace_target(&self) -> &ScopedEntityRef {
        &self.trace_target
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) fn satisfied_requirements(&self) -> &[PanicCallRequirementMatchId] {
        &self.satisfied_requirements
    }
}

/// One panic-call witness whose local requirement atoms remain unsatisfied.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct UnsatisfiedPanicCallIssue {
    source: ScopedRowRef,
    endpoint: ScopedEntityRef,
    boundary: PanicCallBoundaryKind,
    witness_order: u64,
    missing_requirements: Vec<PanicCallRequirementMatchId>,
}

impl RowSchema for UnsatisfiedPanicCallIssue {
    const ID: &'static str = "sniff-test.panic.unsatisfied-call-obligation";
    const VERSION: u32 = 1;
}

impl IssueSchema for UnsatisfiedPanicCallIssue {}

impl UnsatisfiedPanicCallIssue {
    #[must_use]
    pub(crate) const fn new(
        source: ScopedRowRef,
        endpoint: ScopedEntityRef,
        boundary: PanicCallBoundaryKind,
        witness_order: u64,
        missing_requirements: Vec<PanicCallRequirementMatchId>,
    ) -> Self {
        Self {
            source,
            endpoint,
            boundary,
            witness_order,
            missing_requirements,
        }
    }

    #[must_use]
    pub(crate) const fn source(&self) -> &ScopedRowRef {
        &self.source
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityRef {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn boundary_kind(&self) -> &PanicCallBoundaryKind {
        &self.boundary
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) fn missing_requirements(&self) -> &[PanicCallRequirementMatchId] {
        &self.missing_requirements
    }
}

/// One normalized panic-call contract requirement declared more than once.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct DuplicatePanicCallRequirementIssue {
    source: ScopedRowRef,
    presentation_function: PanicCallPresentationFunction,
    witness_order: u64,
    normalized_name: String,
    requirements: Vec<PanicCallRequirementMatchId>,
}

impl RowSchema for DuplicatePanicCallRequirementIssue {
    const ID: &'static str = "sniff-test.panic.duplicate-call-requirement";
    const VERSION: u32 = 1;
}

impl IssueSchema for DuplicatePanicCallRequirementIssue {}

impl DuplicatePanicCallRequirementIssue {
    #[must_use]
    pub(crate) const fn new(
        source: ScopedRowRef,
        presentation_function: PanicCallPresentationFunction,
        witness_order: u64,
        normalized_name: String,
        requirements: Vec<PanicCallRequirementMatchId>,
    ) -> Self {
        Self {
            source,
            presentation_function,
            witness_order,
            normalized_name,
            requirements,
        }
    }

    #[must_use]
    pub(crate) const fn source(&self) -> &ScopedRowRef {
        &self.source
    }

    #[must_use]
    pub(crate) const fn presentation_function(&self) -> &PanicCallPresentationFunction {
        &self.presentation_function
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) fn normalized_name(&self) -> &str {
        &self.normalized_name
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[PanicCallRequirementMatchId] {
        &self.requirements
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        DuplicatePanicCallRequirementIssue, PanicCallBoundaryKind, PanicCallEvidenceMatch,
        PanicCallOpaqueKind, PanicCallPresentationFunction, PanicCallRequirementMatchId,
        PanicCallRequirementValue, PanicCallResolution, PanicCallableResolutionKind,
        UnsatisfiedPanicCallIssue,
    };
    use crate::analysis::facts::composition::{CompositionRelationRef, WorkspaceRelationRef};
    use crate::analysis::facts::encoded::{EntityRef, RowRef};
    use crate::analysis::facts::evaluation::RelationTrace;
    use crate::analysis::facts::program::FunctionKey;
    use crate::analysis::facts::program::topology::CallableKey;
    use crate::analysis::facts::schema::{RowSchema, SchemaId};
    use crate::analysis::facts::workspace::{ArtifactScopeId, ScopedEntityRef};
    use crate::namespace::StableDefPathHash;

    #[test]
    fn presentation_function_is_a_strict_entity_and_semantic_identity() {
        let endpoint_scope = ArtifactScopeId::for_in_memory(1, 0);
        let semantic_scope = ArtifactScopeId::for_in_memory(2, 0);
        let endpoint = ScopedEntityRef::new(
            endpoint_scope,
            EntityRef {
                schema: SchemaId::new("sample.callable").unwrap(),
                row: 3,
            },
        );
        let function = FunctionKey::new(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000007\"")
                .unwrap(),
            None,
        );
        let presentation =
            PanicCallPresentationFunction::new(endpoint.clone(), semantic_scope.clone(), function);

        assert_eq!(presentation.endpoint(), &endpoint);
        assert_eq!(presentation.scope(), &semantic_scope);
        assert_eq!(presentation.function(), &function);

        let encoded = serde_json::to_value(&presentation).unwrap();
        let mut missing_endpoint = encoded.clone();
        missing_endpoint.as_object_mut().unwrap().remove("endpoint");
        let mut unknown_top_level = encoded.clone();
        unknown_top_level["unexpected"] = json!(true);
        let mut unknown_endpoint = encoded.clone();
        unknown_endpoint["endpoint"]["unexpected"] = json!(true);
        let mut unknown_function = encoded;
        unknown_function["function"]["unexpected"] = json!(true);
        for hostile in [
            missing_endpoint,
            unknown_top_level,
            unknown_endpoint,
            unknown_function,
        ] {
            assert!(serde_json::from_value::<PanicCallPresentationFunction>(hostile).is_err());
        }
    }

    #[test]
    fn unnamed_requirement_is_an_explicit_root_local_value() {
        let requirement = PanicCallRequirementValue::unnamed();

        assert_eq!(requirement.ordinal(), None);
        assert_eq!(
            serde_json::to_value(requirement).unwrap(),
            json!({ "kind": "unnamed" })
        );
    }

    #[test]
    fn unsatisfied_call_issue_is_a_strict_v1_projection() {
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let endpoint = ScopedEntityRef::new(
            scope.clone(),
            EntityRef {
                schema: SchemaId::new("sample.call").unwrap(),
                row: 2,
            },
        );
        let source = crate::analysis::facts::workspace::ScopedRowRef::new(
            scope,
            RowRef {
                schema: SchemaId::new("sample.call").unwrap(),
                row: 2,
            },
        );
        let issue = UnsatisfiedPanicCallIssue::new(
            source.clone(),
            endpoint.clone(),
            PanicCallBoundaryKind::Documented { trusted: true },
            7,
            vec![
                PanicCallRequirementMatchId::named(0),
                PanicCallRequirementMatchId::named(1),
            ],
        );

        assert_eq!(issue.source(), &source);
        assert_eq!(issue.endpoint(), &endpoint);
        assert_eq!(
            issue.boundary_kind(),
            &PanicCallBoundaryKind::Documented { trusted: true }
        );
        assert_eq!(issue.witness_order(), 7);
        assert_eq!(
            issue.missing_requirements(),
            [
                PanicCallRequirementMatchId::named(0),
                PanicCallRequirementMatchId::named(1),
            ]
        );
        assert_eq!(UnsatisfiedPanicCallIssue::VERSION, 1);

        let encoded = serde_json::to_value(&issue).unwrap();
        let mut unknown_top_level = encoded.clone();
        unknown_top_level["unexpected"] = json!(true);
        let mut missing_required_field = encoded.clone();
        missing_required_field
            .as_object_mut()
            .unwrap()
            .remove("witness-order");
        let mut unknown_boundary_field = encoded.clone();
        unknown_boundary_field["boundary"]["unexpected"] = json!(true);
        let mut unknown_requirement_field = encoded;
        unknown_requirement_field["missing-requirements"][0]["unexpected"] = json!(true);
        for hostile in [
            unknown_top_level,
            missing_required_field,
            unknown_boundary_field,
            unknown_requirement_field,
        ] {
            assert!(serde_json::from_value::<UnsatisfiedPanicCallIssue>(hostile).is_err());
        }
    }

    #[test]
    fn duplicate_call_requirement_issue_is_a_strict_v1_projection() {
        let occurrence_scope = ArtifactScopeId::for_in_memory(1, 0);
        let semantic_scope = ArtifactScopeId::for_in_memory(2, 0);
        let endpoint = ScopedEntityRef::new(
            occurrence_scope.clone(),
            EntityRef {
                schema: SchemaId::new("sample.callable").unwrap(),
                row: 3,
            },
        );
        let source = crate::analysis::facts::workspace::ScopedRowRef::new(
            occurrence_scope,
            RowRef {
                schema: SchemaId::new("sample.call").unwrap(),
                row: 2,
            },
        );
        let function = FunctionKey::new(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000007\"")
                .unwrap(),
            None,
        );
        let presentation = PanicCallPresentationFunction::new(endpoint, semantic_scope, function);
        let issue = DuplicatePanicCallRequirementIssue::new(
            source.clone(),
            presentation.clone(),
            7,
            String::from("index in bounds"),
            vec![
                PanicCallRequirementMatchId::named(0),
                PanicCallRequirementMatchId::named(1),
            ],
        );

        assert_eq!(issue.source(), &source);
        assert_eq!(issue.presentation_function(), &presentation);
        assert_eq!(issue.witness_order(), 7);
        assert_eq!(issue.normalized_name(), "index in bounds");
        assert_eq!(
            issue.requirements(),
            [
                PanicCallRequirementMatchId::named(0),
                PanicCallRequirementMatchId::named(1),
            ]
        );
        assert_eq!(DuplicatePanicCallRequirementIssue::VERSION, 1);

        let encoded = serde_json::to_value(&issue).unwrap();
        let mut unknown_top_level = encoded.clone();
        unknown_top_level["unexpected"] = json!(true);
        let mut missing_required_field = encoded.clone();
        missing_required_field
            .as_object_mut()
            .unwrap()
            .remove("normalized-name");
        let mut unknown_presentation_field = encoded.clone();
        unknown_presentation_field["presentation-function"]["unexpected"] = json!(true);
        let mut unknown_requirement_field = encoded;
        unknown_requirement_field["requirements"][0]["unexpected"] = json!(true);
        for hostile in [
            unknown_top_level,
            missing_required_field,
            unknown_presentation_field,
            unknown_requirement_field,
        ] {
            assert!(serde_json::from_value::<DuplicatePanicCallRequirementIssue>(hostile).is_err());
        }
    }

    #[test]
    fn value_only_override_does_not_fabricate_raw_provenance() {
        let requirement = PanicCallRequirementValue::named(
            0,
            "Index_In-Bounds",
            "index in bounds",
            "the index is less than the collection length",
            None,
            None,
        );

        assert_eq!(requirement.ordinal(), Some(0));
        assert_eq!(requirement.raw_requirement(), None);
        assert_eq!(requirement.source_anchor(), None);
        assert_eq!(
            serde_json::to_value(requirement).unwrap(),
            json!({
                "kind": "named",
                "ordinal": 0,
                "name": "Index_In-Bounds",
                "normalized-name": "index in bounds",
                "condition": "the index is less than the collection length"
            })
        );
    }

    #[test]
    fn call_match_keeps_trace_target_and_value_only_requirement_identity() {
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let entity = |schema: &'static str, row| {
            ScopedEntityRef::new(
                scope.clone(),
                EntityRef {
                    schema: SchemaId::new(schema).unwrap(),
                    row,
                },
            )
        };
        let claim = entity("sample.claim", 1);
        let endpoint = entity("sample.call", 2);
        let group = entity("sample.group", 3);
        let trace_target = entity("sample.callable", 4);
        let source = crate::analysis::facts::workspace::ScopedRowRef::new(
            scope,
            RowRef {
                schema: SchemaId::new("sample.call").unwrap(),
                row: 2,
            },
        );
        let matched = PanicCallEvidenceMatch::new(
            claim,
            source,
            endpoint.clone(),
            group,
            trace_target.clone(),
            RelationTrace::new(
                endpoint,
                trace_target,
                vec![WorkspaceRelationRef::Composition(CompositionRelationRef {
                    schema: SchemaId::new("sample.call-trace").unwrap(),
                    row: 0,
                })],
            ),
            7,
            vec![
                PanicCallRequirementMatchId::named(1),
                PanicCallRequirementMatchId::named(0),
                PanicCallRequirementMatchId::named(1),
            ],
        );

        assert_eq!(matched.trace_target(), matched.trace().target());
        assert_eq!(
            matched.satisfied_requirements(),
            [
                PanicCallRequirementMatchId::named(0),
                PanicCallRequirementMatchId::named(1),
            ]
        );
        assert_eq!(
            serde_json::to_value(&matched).unwrap()["satisfied-requirements"],
            json!([
                { "kind": "named", "ordinal": 0 },
                { "kind": "named", "ordinal": 1 },
            ])
        );
        assert_eq!(PanicCallEvidenceMatch::VERSION, 1);

        let encoded = serde_json::to_value(&matched).unwrap();
        let mut unknown_top_level = encoded.clone();
        unknown_top_level["unexpected"] = json!(true);
        let mut missing_trace_target = encoded.clone();
        missing_trace_target
            .as_object_mut()
            .unwrap()
            .remove("trace-target");
        let mut unknown_requirement_field = encoded.clone();
        unknown_requirement_field["satisfied-requirements"][0]["unexpected"] = json!(true);
        let mut unknown_trace_field = encoded.clone();
        unknown_trace_field["trace"]["unexpected"] = json!(true);
        let mut unknown_relation_field = encoded;
        unknown_relation_field["trace"]["relations"][0]["unexpected"] = json!(true);
        for hostile in [
            unknown_top_level,
            missing_trace_target,
            unknown_requirement_field,
            unknown_trace_field,
            unknown_relation_field,
        ] {
            assert!(serde_json::from_value::<PanicCallEvidenceMatch>(hostile).is_err());
        }
    }

    #[test]
    fn enum_struct_variant_fields_are_kebab_case() {
        let evidence = ScopedEntityRef::new(
            ArtifactScopeId::for_in_memory(1, 0),
            EntityRef {
                schema: SchemaId::new("sample.evidence").unwrap(),
                row: 4,
            },
        );
        let key = CallableKey::DynDispatch(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000007\"")
                .unwrap(),
        );

        assert_eq!(
            serde_json::to_value(PanicCallBoundaryKind::Opaque {
                opaque_kind: PanicCallOpaqueKind::ExplicitOpaque,
                description: String::from("opaque"),
            })
            .unwrap(),
            json!({
                "kind": "opaque",
                "opaque-kind": "explicit-opaque",
                "description": "opaque",
            })
        );
        assert_eq!(
            serde_json::to_value(PanicCallResolution::CallableEvidence {
                evidence,
                key,
                resolution_kind: PanicCallableResolutionKind::FunctionPointerEvidence,
            })
            .unwrap()
            .get("resolution-kind"),
            Some(&json!("function-pointer-evidence"))
        );
    }
}
