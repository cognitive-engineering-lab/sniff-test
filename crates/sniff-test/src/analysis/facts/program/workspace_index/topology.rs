//! Artifact-local semantic topology retained by the workspace program index.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use super::super::super::human::markers::{MarkerClaimEntity, MarkerClaimKey};
use super::super::super::safety::operations::{
    UnsafeOperationEntity, UnsafeOperationKey, UnsafeOperationMacroExpansionEntity,
    UnsafeOperationSourceAnchorRole,
};
use super::super::super::schema::RowSchema;
use super::super::super::view::ArtifactDbView;
use super::super::super::workspace::{
    ArtifactScopeId, ScopedEntityId, ScopedEntityRef, ScopedRelationRef, ScopedRowRef,
};
use super::super::topology::{
    CallMacroExpansionEntity, CallOccurrenceEntity, CallOccurrenceHasCallableKey,
    CallOccurrenceInSafetyEffectGroup, CallOccurrenceKey, CallOccurrenceTargetsCallable,
    CallSiteHasOccurrence, CallSiteKey, CallSourceAnchorRole, CallTargetRole, CallableEntity,
    CallableKey, FunctionOwnsCallSite, FunctionOwnsSafetyEffectGroup, SafetyEffectGroupEntity,
    SafetyEffectGroupKey,
};
use super::super::{
    EffectSiteEntity, EffectSiteKey, EffectSourceAnchorRole, FunctionKey, MacroExpansionEntity,
    SourceAnchorEntity, SourceAnchorKey,
};
use super::composition::CallableResolutionKind;
use super::index::{
    ArtifactProgramIndex, ScopedProgramEntity, WorkspaceProgramIndexError, load_relations,
    malformed,
};
use crate::namespace::StableExpansionHash;

mod macro_paths;
mod markers;
mod safety_topology;

/// One exact function-to-call-site ownership edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedCallSite {
    site: CallSiteKey,
    relation: ScopedRelationRef,
}

impl IndexedCallSite {
    pub(super) const fn new(site: CallSiteKey, relation: ScopedRelationRef) -> Self {
        Self { site, relation }
    }

    #[must_use]
    pub(crate) const fn site(&self) -> CallSiteKey {
        self.site
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// One exact call-site-to-occurrence edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedCallOccurrence {
    occurrence: CallOccurrenceKey,
    relation: ScopedRelationRef,
}

impl IndexedCallOccurrence {
    pub(super) const fn new(occurrence: CallOccurrenceKey, relation: ScopedRelationRef) -> Self {
        Self {
            occurrence,
            relation,
        }
    }

    #[must_use]
    pub(crate) const fn occurrence(&self) -> CallOccurrenceKey {
        self.occurrence
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// One typed callable target retained in role order for an exact occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedCallTarget {
    role: CallTargetRole,
    callable: FunctionKey,
    relation: ScopedRelationRef,
}

impl IndexedCallTarget {
    #[must_use]
    pub(super) const fn new(
        role: CallTargetRole,
        callable: FunctionKey,
        relation: ScopedRelationRef,
    ) -> Self {
        Self {
            role,
            callable,
            relation,
        }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> CallTargetRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn callable(&self) -> FunctionKey {
        self.callable
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// One verified source representation for an exact call occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedCallSourceAnchor {
    role: CallSourceAnchorRole,
    anchor_key: SourceAnchorKey,
    anchor: ScopedEntityId<SourceAnchorEntity>,
    relation: ScopedRelationRef,
}

impl IndexedCallSourceAnchor {
    pub(super) const fn new(
        role: CallSourceAnchorRole,
        anchor_key: SourceAnchorKey,
        anchor: ScopedEntityId<SourceAnchorEntity>,
        relation: ScopedRelationRef,
    ) -> Self {
        Self {
            role,
            anchor_key,
            anchor,
            relation,
        }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> CallSourceAnchorRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn anchor_key(&self) -> &SourceAnchorKey {
        &self.anchor_key
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

/// Optional invocation anchor retained for one exact call macro frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedCallMacroCallsite {
    anchor_key: SourceAnchorKey,
    anchor: ScopedEntityId<SourceAnchorEntity>,
    relation: ScopedRelationRef,
}

impl IndexedCallMacroCallsite {
    pub(super) const fn new(
        anchor_key: SourceAnchorKey,
        anchor: ScopedEntityId<SourceAnchorEntity>,
        relation: ScopedRelationRef,
    ) -> Self {
        Self {
            anchor_key,
            anchor,
            relation,
        }
    }

    #[must_use]
    pub(crate) const fn anchor_key(&self) -> &SourceAnchorKey {
        &self.anchor_key
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

/// The exact validated outer-to-inner macro path for one call occurrence.
#[derive(Clone, Debug)]
pub(crate) struct IndexedCallMacroPath {
    frames: Vec<ScopedProgramEntity<CallMacroExpansionEntity>>,
    entry: ScopedRelationRef,
    links: Vec<ScopedRelationRef>,
    exit: ScopedRelationRef,
    callsites: Vec<Option<IndexedCallMacroCallsite>>,
}

impl IndexedCallMacroPath {
    pub(super) const fn new(
        frames: Vec<ScopedProgramEntity<CallMacroExpansionEntity>>,
        entry: ScopedRelationRef,
        links: Vec<ScopedRelationRef>,
        exit: ScopedRelationRef,
        callsites: Vec<Option<IndexedCallMacroCallsite>>,
    ) -> Self {
        Self {
            frames,
            entry,
            links,
            exit,
            callsites,
        }
    }

    #[must_use]
    pub(crate) fn frames(&self) -> &[ScopedProgramEntity<CallMacroExpansionEntity>] {
        &self.frames
    }

    #[must_use]
    pub(crate) const fn entry(&self) -> &ScopedRelationRef {
        &self.entry
    }

    #[must_use]
    pub(crate) fn links(&self) -> &[ScopedRelationRef] {
        &self.links
    }

    #[must_use]
    pub(crate) const fn exit(&self) -> &ScopedRelationRef {
        &self.exit
    }

    #[must_use]
    pub(crate) fn callsites(&self) -> &[Option<IndexedCallMacroCallsite>] {
        &self.callsites
    }
}

/// One exact function-to-effect ownership edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedEffectSite {
    site: EffectSiteKey,
    effect: ScopedEntityId<EffectSiteEntity>,
    relation: ScopedRelationRef,
}

impl IndexedEffectSite {
    pub(super) const fn new(
        site: EffectSiteKey,
        effect: ScopedEntityId<EffectSiteEntity>,
        relation: ScopedRelationRef,
    ) -> Self {
        Self {
            site,
            effect,
            relation,
        }
    }

    #[must_use]
    pub(crate) const fn site(&self) -> EffectSiteKey {
        self.site
    }

    #[must_use]
    pub(crate) const fn effect(&self) -> &ScopedEntityId<EffectSiteEntity> {
        &self.effect
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// One verified source representation for an exact effect site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedEffectSourceAnchor {
    role: EffectSourceAnchorRole,
    anchor_key: SourceAnchorKey,
    anchor: ScopedEntityId<SourceAnchorEntity>,
    relation: ScopedRelationRef,
}

impl IndexedEffectSourceAnchor {
    pub(super) const fn new(
        role: EffectSourceAnchorRole,
        anchor_key: SourceAnchorKey,
        anchor: ScopedEntityId<SourceAnchorEntity>,
        relation: ScopedRelationRef,
    ) -> Self {
        Self {
            role,
            anchor_key,
            anchor,
            relation,
        }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> EffectSourceAnchorRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn anchor_key(&self) -> &SourceAnchorKey {
        &self.anchor_key
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

/// Optional invocation anchor retained for one exact effect macro frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedEffectMacroCallsite {
    anchor_key: SourceAnchorKey,
    anchor: ScopedEntityId<SourceAnchorEntity>,
    relation: ScopedRelationRef,
}

impl IndexedEffectMacroCallsite {
    pub(super) const fn new(
        anchor_key: SourceAnchorKey,
        anchor: ScopedEntityId<SourceAnchorEntity>,
        relation: ScopedRelationRef,
    ) -> Self {
        Self {
            anchor_key,
            anchor,
            relation,
        }
    }

    #[must_use]
    pub(crate) const fn anchor_key(&self) -> &SourceAnchorKey {
        &self.anchor_key
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

/// The exact validated outer-to-inner macro path for one effect site.
#[derive(Clone, Debug)]
pub(crate) struct IndexedEffectMacroPath {
    frames: Vec<ScopedProgramEntity<MacroExpansionEntity>>,
    entry: ScopedRelationRef,
    links: Vec<ScopedRelationRef>,
    exit: ScopedRelationRef,
    callsites: Vec<Option<IndexedEffectMacroCallsite>>,
}

/// One exact function-to-unsafe-operation ownership edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedUnsafeOperation {
    operation: UnsafeOperationKey,
    operation_id: ScopedEntityId<UnsafeOperationEntity>,
    relation: ScopedRelationRef,
}

impl IndexedUnsafeOperation {
    pub(super) const fn new(
        operation: UnsafeOperationKey,
        operation_id: ScopedEntityId<UnsafeOperationEntity>,
        relation: ScopedRelationRef,
    ) -> Self {
        Self {
            operation,
            operation_id,
            relation,
        }
    }

    #[must_use]
    pub(crate) const fn operation(&self) -> UnsafeOperationKey {
        self.operation
    }

    #[must_use]
    pub(crate) const fn operation_id(&self) -> &ScopedEntityId<UnsafeOperationEntity> {
        &self.operation_id
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// The exact safety group assigned to one unsafe operation.
#[derive(Clone, Debug)]
pub(crate) struct IndexedUnsafeOperationSafetyGroup {
    group: ScopedProgramEntity<SafetyEffectGroupEntity>,
    relation: ScopedRelationRef,
}

impl IndexedUnsafeOperationSafetyGroup {
    pub(super) const fn new(
        group: ScopedProgramEntity<SafetyEffectGroupEntity>,
        relation: ScopedRelationRef,
    ) -> Self {
        Self { group, relation }
    }

    #[must_use]
    pub(crate) const fn group(&self) -> &ScopedProgramEntity<SafetyEffectGroupEntity> {
        &self.group
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// One verified source representation for an exact unsafe operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedUnsafeOperationSourceAnchor {
    role: UnsafeOperationSourceAnchorRole,
    anchor_key: SourceAnchorKey,
    anchor: ScopedEntityId<SourceAnchorEntity>,
    relation: ScopedRelationRef,
}

impl IndexedUnsafeOperationSourceAnchor {
    pub(super) const fn new(
        role: UnsafeOperationSourceAnchorRole,
        anchor_key: SourceAnchorKey,
        anchor: ScopedEntityId<SourceAnchorEntity>,
        relation: ScopedRelationRef,
    ) -> Self {
        Self {
            role,
            anchor_key,
            anchor,
            relation,
        }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> UnsafeOperationSourceAnchorRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn anchor_key(&self) -> &SourceAnchorKey {
        &self.anchor_key
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
pub(crate) struct IndexedUnsafeOperationMacroCallsite {
    anchor_key: SourceAnchorKey,
    anchor: ScopedEntityId<SourceAnchorEntity>,
    relation: ScopedRelationRef,
}

impl IndexedUnsafeOperationMacroCallsite {
    pub(super) const fn new(
        anchor_key: SourceAnchorKey,
        anchor: ScopedEntityId<SourceAnchorEntity>,
        relation: ScopedRelationRef,
    ) -> Self {
        Self {
            anchor_key,
            anchor,
            relation,
        }
    }

    #[must_use]
    pub(crate) const fn anchor_key(&self) -> &SourceAnchorKey {
        &self.anchor_key
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

/// The exact validated outer-to-inner macro path for one unsafe operation.
#[derive(Clone, Debug)]
pub(crate) struct IndexedUnsafeOperationMacroPath {
    frames: Vec<ScopedProgramEntity<UnsafeOperationMacroExpansionEntity>>,
    entry: ScopedRelationRef,
    links: Vec<ScopedRelationRef>,
    exit: ScopedRelationRef,
    callsites: Vec<Option<IndexedUnsafeOperationMacroCallsite>>,
}

impl IndexedUnsafeOperationMacroPath {
    pub(super) const fn new(
        frames: Vec<ScopedProgramEntity<UnsafeOperationMacroExpansionEntity>>,
        entry: ScopedRelationRef,
        links: Vec<ScopedRelationRef>,
        exit: ScopedRelationRef,
        callsites: Vec<Option<IndexedUnsafeOperationMacroCallsite>>,
    ) -> Self {
        Self {
            frames,
            entry,
            links,
            exit,
            callsites,
        }
    }

    #[must_use]
    pub(crate) fn frames(&self) -> &[ScopedProgramEntity<UnsafeOperationMacroExpansionEntity>] {
        &self.frames
    }

    #[must_use]
    pub(crate) const fn entry(&self) -> &ScopedRelationRef {
        &self.entry
    }

    #[must_use]
    pub(crate) fn links(&self) -> &[ScopedRelationRef] {
        &self.links
    }

    #[must_use]
    pub(crate) const fn exit(&self) -> &ScopedRelationRef {
        &self.exit
    }

    #[must_use]
    pub(crate) fn callsites(&self) -> &[Option<IndexedUnsafeOperationMacroCallsite>] {
        &self.callsites
    }
}

impl IndexedEffectMacroPath {
    pub(super) const fn new(
        frames: Vec<ScopedProgramEntity<MacroExpansionEntity>>,
        entry: ScopedRelationRef,
        links: Vec<ScopedRelationRef>,
        exit: ScopedRelationRef,
        callsites: Vec<Option<IndexedEffectMacroCallsite>>,
    ) -> Self {
        Self {
            frames,
            entry,
            links,
            exit,
            callsites,
        }
    }

    #[must_use]
    pub(crate) fn frames(&self) -> &[ScopedProgramEntity<MacroExpansionEntity>] {
        &self.frames
    }

    #[must_use]
    pub(crate) const fn entry(&self) -> &ScopedRelationRef {
        &self.entry
    }

    #[must_use]
    pub(crate) fn links(&self) -> &[ScopedRelationRef] {
        &self.links
    }

    #[must_use]
    pub(crate) const fn exit(&self) -> &ScopedRelationRef {
        &self.exit
    }

    #[must_use]
    pub(crate) fn callsites(&self) -> &[Option<IndexedEffectMacroCallsite>] {
        &self.callsites
    }
}

/// One requirement row whose artifact generation remains explicit.
#[derive(Clone, Debug)]
pub(crate) struct ScopedRequirement<R> {
    reference: ScopedRowRef,
    data: R,
}

impl<R> ScopedRequirement<R> {
    #[must_use]
    pub(crate) const fn reference(&self) -> &ScopedRowRef {
        &self.reference
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &R {
        &self.data
    }
}

/// One typed contract boundary and its source-ordered requirements.
#[derive(Clone, Debug)]
pub(crate) struct IndexedContract<R> {
    fact: ScopedRowRef,
    owner: ScopedEntityRef,
    anchor: Option<ScopedEntityRef>,
    requirements: Vec<ScopedRequirement<R>>,
    marker: PhantomData<fn() -> R>,
}

impl<R> IndexedContract<R> {
    #[must_use]
    pub(crate) const fn fact(&self) -> &ScopedRowRef {
        &self.fact
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> &ScopedEntityRef {
        &self.owner
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> Option<&ScopedEntityRef> {
        self.anchor.as_ref()
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[ScopedRequirement<R>] {
        &self.requirements
    }
}

/// One exact callable-evidence occurrence and the runtime callable it proves.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct IndexedCallableEvidence {
    pub(super) occurrence: ScopedEntityId<CallOccurrenceEntity>,
    pub(super) callable: ScopedEntityId<CallableEntity>,
    pub(super) callable_function: FunctionKey,
    pub(super) key: CallableKey,
    pub(super) resolution_kind: CallableResolutionKind,
}

impl IndexedCallableEvidence {
    #[must_use]
    pub(crate) const fn occurrence(&self) -> &ScopedEntityId<CallOccurrenceEntity> {
        &self.occurrence
    }

    #[must_use]
    pub(crate) const fn callable(&self) -> &ScopedEntityId<CallableEntity> {
        &self.callable
    }

    #[must_use]
    pub(crate) const fn callable_function(&self) -> FunctionKey {
        self.callable_function
    }

    #[must_use]
    pub(crate) const fn callable_key(&self) -> CallableKey {
        self.key
    }

    #[must_use]
    pub(crate) const fn resolution_kind(&self) -> CallableResolutionKind {
        self.resolution_kind
    }
}

/// One reachable erased-callable join, ready to become a composition relation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CallableEvidenceCandidate {
    invocation: ScopedEntityId<CallOccurrenceEntity>,
    evidence_occurrence: ScopedEntityId<CallOccurrenceEntity>,
    callable: ScopedEntityId<CallableEntity>,
    callable_key: CallableKey,
    resolution_kind: CallableResolutionKind,
}

impl CallableEvidenceCandidate {
    pub(super) fn new(
        invocation: ScopedEntityId<CallOccurrenceEntity>,
        evidence: &IndexedCallableEvidence,
    ) -> Self {
        Self {
            invocation,
            evidence_occurrence: evidence.occurrence.clone(),
            callable: evidence.callable.clone(),
            callable_key: evidence.key,
            resolution_kind: evidence.resolution_kind,
        }
    }

    #[must_use]
    pub(crate) const fn invocation(&self) -> &ScopedEntityId<CallOccurrenceEntity> {
        &self.invocation
    }

    #[must_use]
    pub(crate) const fn evidence_occurrence(&self) -> &ScopedEntityId<CallOccurrenceEntity> {
        &self.evidence_occurrence
    }

    #[must_use]
    pub(crate) const fn callable(&self) -> &ScopedEntityId<CallableEntity> {
        &self.callable
    }

    #[must_use]
    pub(crate) const fn callable_key(&self) -> CallableKey {
        self.callable_key
    }

    #[must_use]
    pub(crate) const fn resolution_kind(&self) -> CallableResolutionKind {
        self.resolution_kind
    }
}

/// One policy-neutral human-claim attachment candidate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct IndexedMarkerCandidate {
    claim: MarkerClaimKey,
    claim_id: ScopedEntityId<MarkerClaimEntity>,
    relation: ScopedRelationRef,
    source_callsite: bool,
    macro_definition_first: bool,
}

impl IndexedMarkerCandidate {
    pub(super) const fn new(
        claim: MarkerClaimKey,
        claim_id: ScopedEntityId<MarkerClaimEntity>,
        relation: ScopedRelationRef,
        source_callsite: bool,
        macro_definition_first: bool,
    ) -> Self {
        Self {
            claim,
            claim_id,
            relation,
            source_callsite,
            macro_definition_first,
        }
    }

    #[must_use]
    pub(crate) const fn claim(&self) -> &MarkerClaimKey {
        &self.claim
    }

    #[must_use]
    pub(crate) const fn claim_id(&self) -> &ScopedEntityId<MarkerClaimEntity> {
        &self.claim_id
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }

    #[must_use]
    pub(crate) const fn source_callsite(&self) -> bool {
        self.source_callsite
    }

    #[must_use]
    pub(crate) const fn macro_definition_first(&self) -> bool {
        self.macro_definition_first
    }
}

/// Validated artifact-local ownership and call candidate maps.
#[derive(Debug, Default)]
pub(super) struct ArtifactTopology {
    call_sites_by_function: BTreeMap<FunctionKey, Vec<CallSiteKey>>,
    call_site_edges_by_function: BTreeMap<FunctionKey, Vec<IndexedCallSite>>,
    occurrences_by_site: BTreeMap<CallSiteKey, Vec<CallOccurrenceKey>>,
    occurrence_edges_by_site: BTreeMap<CallSiteKey, Vec<IndexedCallOccurrence>>,
    targets_by_occurrence: BTreeMap<CallOccurrenceKey, Vec<IndexedCallTarget>>,
    source_anchors_by_occurrence: BTreeMap<CallOccurrenceKey, Vec<IndexedCallSourceAnchor>>,
    callable_keys_by_occurrence: BTreeMap<CallOccurrenceKey, Vec<CallableKey>>,
    occurrence_groups: BTreeMap<CallOccurrenceKey, SafetyEffectGroupKey>,
    callable_evidence: BTreeMap<CallableKey, Vec<IndexedCallableEvidence>>,
    call_macro_paths: BTreeMap<CallOccurrenceKey, Vec<StableExpansionHash>>,
    indexed_call_macro_paths: BTreeMap<CallOccurrenceKey, IndexedCallMacroPath>,
    effects_by_function: BTreeMap<FunctionKey, Vec<EffectSiteKey>>,
    effect_site_edges_by_function: BTreeMap<FunctionKey, Vec<IndexedEffectSite>>,
    source_anchors_by_effect: BTreeMap<EffectSiteKey, Vec<IndexedEffectSourceAnchor>>,
    effect_macro_paths: BTreeMap<EffectSiteKey, Vec<StableExpansionHash>>,
    indexed_effect_macro_paths: BTreeMap<EffectSiteKey, IndexedEffectMacroPath>,
    unsafe_by_function: BTreeMap<FunctionKey, Vec<UnsafeOperationKey>>,
    unsafe_operation_edges_by_function: BTreeMap<FunctionKey, Vec<IndexedUnsafeOperation>>,
    unsafe_groups: BTreeMap<UnsafeOperationKey, SafetyEffectGroupKey>,
    unsafe_group_edges: BTreeMap<UnsafeOperationKey, IndexedUnsafeOperationSafetyGroup>,
    source_anchors_by_unsafe_operation:
        BTreeMap<UnsafeOperationKey, Vec<IndexedUnsafeOperationSourceAnchor>>,
    unsafe_macro_paths: BTreeMap<UnsafeOperationKey, Vec<StableExpansionHash>>,
    indexed_unsafe_macro_paths: BTreeMap<UnsafeOperationKey, IndexedUnsafeOperationMacroPath>,
    function_marker_candidates: BTreeMap<FunctionKey, Vec<IndexedMarkerCandidate>>,
    call_marker_candidates: BTreeMap<CallOccurrenceKey, Vec<IndexedMarkerCandidate>>,
    effect_marker_candidates: BTreeMap<EffectSiteKey, Vec<IndexedMarkerCandidate>>,
    unsafe_marker_candidates: BTreeMap<UnsafeOperationKey, Vec<IndexedMarkerCandidate>>,
}

impl ArtifactTopology {
    pub(super) fn open(
        scope: &ArtifactScopeId,
        view: ArtifactDbView<'_>,
        entities: &ArtifactProgramIndex,
    ) -> Result<Self, WorkspaceProgramIndexError> {
        let mut topology = Self::default();
        topology.index_function_call_sites(scope, view, entities)?;
        topology.index_call_occurrences(scope, view, entities)?;
        topology.index_safety_groups(scope, view, entities)?;
        topology.index_call_targets(scope, view, entities)?;
        topology.index_callable_keys(scope, view, entities)?;
        macro_paths::validate(scope, view, entities, &mut topology)?;
        safety_topology::validate(scope, view, entities, &mut topology)?;
        markers::validate(scope, view, entities, &mut topology)?;
        topology.build_callable_evidence(scope, entities)?;
        Ok(topology)
    }

    pub(super) fn call_sites_by_function(&self, function: &FunctionKey) -> &[CallSiteKey] {
        self.call_sites_by_function
            .get(function)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn call_site_edges_by_function(&self, function: &FunctionKey) -> &[IndexedCallSite] {
        self.call_site_edges_by_function
            .get(function)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn call_occurrences_at(&self, site: &CallSiteKey) -> &[CallOccurrenceKey] {
        self.occurrences_by_site
            .get(site)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn call_occurrence_edges_at(&self, site: &CallSiteKey) -> &[IndexedCallOccurrence] {
        self.occurrence_edges_by_site
            .get(site)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn call_targets(&self, occurrence: &CallOccurrenceKey) -> &[IndexedCallTarget] {
        self.targets_by_occurrence
            .get(occurrence)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn call_source_anchors(
        &self,
        occurrence: &CallOccurrenceKey,
    ) -> &[IndexedCallSourceAnchor] {
        self.source_anchors_by_occurrence
            .get(occurrence)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn call_macro_path(
        &self,
        occurrence: &CallOccurrenceKey,
    ) -> Option<&IndexedCallMacroPath> {
        self.indexed_call_macro_paths.get(occurrence)
    }

    pub(super) fn occurrence_safety_group(
        &self,
        occurrence: &CallOccurrenceKey,
    ) -> Option<&SafetyEffectGroupKey> {
        self.occurrence_groups.get(occurrence)
    }

    pub(super) fn callable_keys(&self, occurrence: &CallOccurrenceKey) -> &[CallableKey] {
        self.callable_keys_by_occurrence
            .get(occurrence)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) const fn callable_evidence_index(
        &self,
    ) -> &BTreeMap<CallableKey, Vec<IndexedCallableEvidence>> {
        &self.callable_evidence
    }

    pub(super) fn effect_sites_by_function(&self, function: &FunctionKey) -> &[EffectSiteKey] {
        self.effects_by_function
            .get(function)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn effect_site_edges_by_function(
        &self,
        function: &FunctionKey,
    ) -> &[IndexedEffectSite] {
        self.effect_site_edges_by_function
            .get(function)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn effect_source_anchors(
        &self,
        effect: &EffectSiteKey,
    ) -> &[IndexedEffectSourceAnchor] {
        self.source_anchors_by_effect
            .get(effect)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn effect_macro_path(
        &self,
        effect: &EffectSiteKey,
    ) -> Option<&IndexedEffectMacroPath> {
        self.indexed_effect_macro_paths.get(effect)
    }

    pub(super) fn unsafe_operations_by_function(
        &self,
        function: &FunctionKey,
    ) -> &[UnsafeOperationKey] {
        self.unsafe_by_function
            .get(function)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn unsafe_operation_edges_by_function(
        &self,
        function: &FunctionKey,
    ) -> &[IndexedUnsafeOperation] {
        self.unsafe_operation_edges_by_function
            .get(function)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn unsafe_operation_group(
        &self,
        operation: &UnsafeOperationKey,
    ) -> Option<&SafetyEffectGroupKey> {
        self.unsafe_groups.get(operation)
    }

    pub(super) fn unsafe_operation_group_edge(
        &self,
        operation: &UnsafeOperationKey,
    ) -> Option<&IndexedUnsafeOperationSafetyGroup> {
        self.unsafe_group_edges.get(operation)
    }

    pub(super) fn unsafe_operation_source_anchors(
        &self,
        operation: &UnsafeOperationKey,
    ) -> &[IndexedUnsafeOperationSourceAnchor] {
        self.source_anchors_by_unsafe_operation
            .get(operation)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn unsafe_operation_macro_path(
        &self,
        operation: &UnsafeOperationKey,
    ) -> Option<&IndexedUnsafeOperationMacroPath> {
        self.indexed_unsafe_macro_paths.get(operation)
    }

    pub(super) fn function_marker_candidates(
        &self,
        function: &FunctionKey,
    ) -> &[IndexedMarkerCandidate] {
        self.function_marker_candidates
            .get(function)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn call_marker_candidates(
        &self,
        occurrence: &CallOccurrenceKey,
    ) -> &[IndexedMarkerCandidate] {
        self.call_marker_candidates
            .get(occurrence)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn effect_marker_candidates(
        &self,
        effect: &EffectSiteKey,
    ) -> &[IndexedMarkerCandidate] {
        self.effect_marker_candidates
            .get(effect)
            .map_or(&[], Vec::as_slice)
    }

    pub(super) fn unsafe_marker_candidates(
        &self,
        operation: &UnsafeOperationKey,
    ) -> &[IndexedMarkerCandidate] {
        self.unsafe_marker_candidates
            .get(operation)
            .map_or(&[], Vec::as_slice)
    }

    fn index_function_call_sites(
        &mut self,
        scope: &ArtifactScopeId,
        view: ArtifactDbView<'_>,
        entities: &ArtifactProgramIndex,
    ) -> Result<(), WorkspaceProgramIndexError> {
        let mut owner_by_site = BTreeMap::<CallSiteKey, FunctionKey>::new();
        for relation in load_relations::<FunctionOwnsCallSite>(scope, view)? {
            let relation_ref = ScopedRelationRef::new(scope.clone(), relation.relation.clone());
            let owner = entities.functions.key_for_id(
                scope,
                relation.from,
                FunctionOwnsCallSite::ID,
                "from",
            )?;
            let site = entities.call_sites.key_for_id(
                scope,
                relation.to,
                FunctionOwnsCallSite::ID,
                "to",
            )?;
            if site.owner() != &owner {
                return Err(malformed(
                    scope,
                    FunctionOwnsCallSite::ID,
                    format!("call site {site:?} is attached to mismatched owner {owner:?}"),
                ));
            }
            if owner_by_site.insert(site, owner).is_some() {
                return Err(malformed(
                    scope,
                    FunctionOwnsCallSite::ID,
                    format!("call site {site:?} has multiple owning functions"),
                ));
            }
            self.call_sites_by_function
                .entry(owner)
                .or_default()
                .push(site);
            self.call_site_edges_by_function
                .entry(owner)
                .or_default()
                .push(IndexedCallSite::new(site, relation_ref));
        }
        for site in entities.call_sites.by_key.keys() {
            if !owner_by_site.contains_key(site) {
                return Err(malformed(
                    scope,
                    FunctionOwnsCallSite::ID,
                    format!("call site {site:?} has no owning function"),
                ));
            }
        }
        for sites in self.call_sites_by_function.values_mut() {
            sites.sort_unstable();
        }
        for edges in self.call_site_edges_by_function.values_mut() {
            edges.sort_unstable_by_key(IndexedCallSite::site);
        }
        Ok(())
    }

    fn index_call_occurrences(
        &mut self,
        scope: &ArtifactScopeId,
        view: ArtifactDbView<'_>,
        entities: &ArtifactProgramIndex,
    ) -> Result<(), WorkspaceProgramIndexError> {
        let mut site_by_occurrence = BTreeMap::<CallOccurrenceKey, CallSiteKey>::new();
        for relation in load_relations::<CallSiteHasOccurrence>(scope, view)? {
            let relation_ref = ScopedRelationRef::new(scope.clone(), relation.relation.clone());
            let site = entities.call_sites.key_for_id(
                scope,
                relation.from,
                CallSiteHasOccurrence::ID,
                "from",
            )?;
            let occurrence = entities.occurrences.key_for_id(
                scope,
                relation.to,
                CallSiteHasOccurrence::ID,
                "to",
            )?;
            if occurrence.owner() != site.owner() {
                return Err(malformed(
                    scope,
                    CallSiteHasOccurrence::ID,
                    format!("call occurrence {occurrence:?} has mismatched site {site:?}"),
                ));
            }
            if site_by_occurrence.insert(occurrence, site).is_some() {
                return Err(malformed(
                    scope,
                    CallSiteHasOccurrence::ID,
                    format!("call occurrence {occurrence:?} belongs to multiple call sites"),
                ));
            }
            self.occurrences_by_site
                .entry(site)
                .or_default()
                .push(occurrence);
            self.occurrence_edges_by_site
                .entry(site)
                .or_default()
                .push(IndexedCallOccurrence::new(occurrence, relation_ref));
        }
        for occurrence in entities.occurrences.by_key.values() {
            let key = *occurrence.data().key();
            if occurrence.data().applicable_attribution().is_empty() {
                return Err(malformed(
                    scope,
                    CallOccurrenceHasCallableKey::ID,
                    format!("call occurrence {key:?} has no attribution mode"),
                ));
            }
            if occurrence.data().opaque_target_description() == Some("") {
                return Err(malformed(
                    scope,
                    CallOccurrenceTargetsCallable::ID,
                    format!("call occurrence {key:?} has an empty opaque description"),
                ));
            }
            if !site_by_occurrence.contains_key(&key) {
                return Err(malformed(
                    scope,
                    CallSiteHasOccurrence::ID,
                    format!("call occurrence {key:?} has no source call site"),
                ));
            }
        }
        for (site, occurrences) in &mut self.occurrences_by_site {
            occurrences.sort_unstable();
            if occurrences.is_empty() {
                return Err(malformed(
                    scope,
                    CallSiteHasOccurrence::ID,
                    format!("call site {site:?} has no occurrences"),
                ));
            }
        }
        for edges in self.occurrence_edges_by_site.values_mut() {
            edges.sort_unstable_by_key(IndexedCallOccurrence::occurrence);
        }
        for site in entities.call_sites.by_key.keys() {
            if !self.occurrences_by_site.contains_key(site) {
                return Err(malformed(
                    scope,
                    CallSiteHasOccurrence::ID,
                    format!("call site {site:?} has no occurrences"),
                ));
            }
        }
        Ok(())
    }

    fn index_safety_groups(
        &mut self,
        scope: &ArtifactScopeId,
        view: ArtifactDbView<'_>,
        entities: &ArtifactProgramIndex,
    ) -> Result<(), WorkspaceProgramIndexError> {
        let mut group_owners = BTreeMap::<SafetyEffectGroupKey, FunctionKey>::new();
        for relation in load_relations::<FunctionOwnsSafetyEffectGroup>(scope, view)? {
            let owner = entities.functions.key_for_id(
                scope,
                relation.from,
                FunctionOwnsSafetyEffectGroup::ID,
                "from",
            )?;
            let group = entities.safety_groups.key_for_id(
                scope,
                relation.to,
                FunctionOwnsSafetyEffectGroup::ID,
                "to",
            )?;
            if group.owner() != &owner || group_owners.insert(group, owner).is_some() {
                return Err(malformed(
                    scope,
                    FunctionOwnsSafetyEffectGroup::ID,
                    format!("safety group {group:?} has invalid owning function {owner:?}"),
                ));
            }
        }
        for group in entities.safety_groups.by_key.keys() {
            if !group_owners.contains_key(group) {
                return Err(malformed(
                    scope,
                    FunctionOwnsSafetyEffectGroup::ID,
                    format!("safety group {group:?} has no owning function"),
                ));
            }
        }

        for relation in load_relations::<CallOccurrenceInSafetyEffectGroup>(scope, view)? {
            let occurrence = entities.occurrences.key_for_id(
                scope,
                relation.from,
                CallOccurrenceInSafetyEffectGroup::ID,
                "from",
            )?;
            let group = entities.safety_groups.key_for_id(
                scope,
                relation.to,
                CallOccurrenceInSafetyEffectGroup::ID,
                "to",
            )?;
            if occurrence.owner() != group.owner()
                || self.occurrence_groups.insert(occurrence, group).is_some()
            {
                return Err(malformed(
                    scope,
                    CallOccurrenceInSafetyEffectGroup::ID,
                    format!("call occurrence {occurrence:?} has invalid safety group {group:?}"),
                ));
            }
        }
        for occurrence in entities.occurrences.by_key.keys() {
            if !self.occurrence_groups.contains_key(occurrence) {
                return Err(malformed(
                    scope,
                    CallOccurrenceInSafetyEffectGroup::ID,
                    format!("call occurrence {occurrence:?} has no safety group"),
                ));
            }
        }
        Ok(())
    }

    fn index_call_targets(
        &mut self,
        scope: &ArtifactScopeId,
        view: ArtifactDbView<'_>,
        entities: &ArtifactProgramIndex,
    ) -> Result<(), WorkspaceProgramIndexError> {
        let mut roles = BTreeMap::<CallOccurrenceKey, BTreeSet<CallTargetRole>>::new();
        for relation in load_relations::<CallOccurrenceTargetsCallable>(scope, view)? {
            let relation_ref = ScopedRelationRef::new(scope.clone(), relation.relation.clone());
            let occurrence = entities.occurrences.key_for_id(
                scope,
                relation.from,
                CallOccurrenceTargetsCallable::ID,
                "from",
            )?;
            let callable = entities.callables.key_for_id(
                scope,
                relation.to,
                CallOccurrenceTargetsCallable::ID,
                "to",
            )?;
            let role = relation.data.role();
            if !roles.entry(occurrence).or_default().insert(role) {
                return Err(malformed(
                    scope,
                    CallOccurrenceTargetsCallable::ID,
                    format!("call occurrence {occurrence:?} repeats target role {role:?}"),
                ));
            }
            if matches!(role, CallTargetRole::Runtime) != callable.instance().is_some() {
                return Err(malformed(
                    scope,
                    CallOccurrenceTargetsCallable::ID,
                    format!("target role {role:?} has invalid callable identity {callable:?}"),
                ));
            }
            self.targets_by_occurrence
                .entry(occurrence)
                .or_default()
                .push(IndexedCallTarget::new(role, callable, relation_ref));
        }

        for occurrence in entities.occurrences.by_key.values() {
            let key = *occurrence.data().key();
            let targets = self
                .targets_by_occurrence
                .get_mut(&key)
                .map_or(&mut [] as &mut [_], Vec::as_mut_slice);
            targets.sort_unstable_by_key(|target| (target.role, target.callable));
            let has_runtime = targets
                .iter()
                .any(|target| target.role == CallTargetRole::Runtime);
            let opaque_count = targets
                .iter()
                .filter(|target| {
                    matches!(
                        target.role,
                        CallTargetRole::OpaqueTrait | CallTargetRole::OpaqueFunction
                    )
                })
                .count();
            let valid = match occurrence.data().opaque_target_description() {
                None => has_runtime && opaque_count == 0,
                Some(_) => !has_runtime && opaque_count <= 1,
            };
            if !valid {
                return Err(malformed(
                    scope,
                    CallOccurrenceTargetsCallable::ID,
                    format!("call occurrence {key:?} has an invalid target-role shape"),
                ));
            }
        }
        Ok(())
    }

    fn index_callable_keys(
        &mut self,
        scope: &ArtifactScopeId,
        view: ArtifactDbView<'_>,
        entities: &ArtifactProgramIndex,
    ) -> Result<(), WorkspaceProgramIndexError> {
        for relation in load_relations::<CallOccurrenceHasCallableKey>(scope, view)? {
            let occurrence = entities.occurrences.key_for_id(
                scope,
                relation.from,
                CallOccurrenceHasCallableKey::ID,
                "from",
            )?;
            let key = entities.callable_keys.key_for_id(
                scope,
                relation.to,
                CallOccurrenceHasCallableKey::ID,
                "to",
            )?;
            self.callable_keys_by_occurrence
                .entry(occurrence)
                .or_default()
                .push(key);
        }
        for keys in self.callable_keys_by_occurrence.values_mut() {
            keys.sort_unstable();
            if keys.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(malformed(
                    scope,
                    CallOccurrenceHasCallableKey::ID,
                    "one occurrence repeats a callable key",
                ));
            }
        }
        Ok(())
    }

    fn build_callable_evidence(
        &mut self,
        scope: &ArtifactScopeId,
        entities: &ArtifactProgramIndex,
    ) -> Result<(), WorkspaceProgramIndexError> {
        for (occurrence, keys) in &self.callable_keys_by_occurrence {
            let Some(occurrence_entity) = entities.occurrences.get(occurrence) else {
                continue;
            };
            let evidence_kind = match occurrence_entity.data().kind() {
                super::super::topology::CallKind::FnPointerReify
                | super::super::topology::CallKind::ClosureFnPointerReify => {
                    Some(CallableResolutionKind::FunctionPointerEvidence)
                }
                super::super::topology::CallKind::VTableEntry => {
                    Some(CallableResolutionKind::DynamicDispatchEvidence)
                }
                _ => None,
            };
            let Some(evidence_kind) = evidence_kind else {
                continue;
            };
            for key in keys {
                if !matches!(
                    (key, evidence_kind),
                    (
                        CallableKey::FnPointer(_),
                        CallableResolutionKind::FunctionPointerEvidence
                    ) | (
                        CallableKey::DynDispatch(_),
                        CallableResolutionKind::DynamicDispatchEvidence
                    )
                ) {
                    return Err(malformed(
                        scope,
                        CallOccurrenceHasCallableKey::ID,
                        format!(
                            "callable evidence occurrence {occurrence:?} has key {key:?} incompatible with {evidence_kind:?}"
                        ),
                    ));
                }
                let targets = self
                    .targets_by_occurrence
                    .get(occurrence)
                    .cloned()
                    .unwrap_or_default();
                for target in targets {
                    if target.role != CallTargetRole::Runtime {
                        continue;
                    }
                    let Some(callable) = entities.callables.get(&target.callable) else {
                        continue;
                    };
                    self.callable_evidence
                        .entry(*key)
                        .or_default()
                        .push(IndexedCallableEvidence {
                            occurrence: occurrence_entity.id(),
                            callable: callable.id(),
                            callable_function: *callable.data().key(),
                            key: *key,
                            resolution_kind: evidence_kind,
                        });
                }
            }
        }
        for records in self.callable_evidence.values_mut() {
            records.sort_by(|left, right| {
                left.occurrence
                    .cmp(&right.occurrence)
                    .then_with(|| left.callable.cmp(&right.callable))
            });
        }
        Ok(())
    }
}
