//! Owned, policy-neutral compiler facts awaiting typed artifact passes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

use super::facts::human::EvidenceClaimSelector;
use super::facts::human::markers::{
    CallOccurrenceHasMarkerClaimCandidate, EffectSiteHasMarkerClaimCandidate,
    FunctionHasMarkerClaimCandidate, MarkerClaimEntity, MarkerClaimKey, MarkerOccurrenceEntity,
    MarkerOccurrenceKey, UnsafeOperationHasMarkerClaimCandidate,
};
use super::facts::panic::contracts::PanicRequirement;
use super::facts::panic::model::MirAssertKind;
use super::facts::program::topology::{
    CallMacroExpansionEntity, CallOccurrenceEntity, CallOccurrenceKey, CallSiteEntity, CallSiteKey,
    CallSourceAnchorRole, CallTargetRole, CallableEntity, CallableKey, CallableKeyEntity,
    SafetyEffectGroupEntity, SafetyEffectGroupKey,
};
use super::facts::program::{
    EffectSiteEntity, EffectSiteKey, EffectSourceAnchorRole, FunctionBodyProvenance,
    FunctionEntity, FunctionKey, MacroExpansionEntity, SourceAnchorEntity, SourceAnchorKey,
    SourceFileEntity,
};
use super::facts::safety::SafetyRequirement;
use super::facts::safety::operations::{
    UnsafeOperationEntity, UnsafeOperationKey, UnsafeOperationMacroExpansionEntity,
    UnsafeOperationSourceAnchorRole,
};
use crate::namespace::StableExpansionHash;

/// One fully validated artifact collection ready for policy-neutral fact passes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedArtifact {
    program: CollectedProgram,
    unsafe_operations: Vec<CollectedUnsafeOperation>,
    panic_contracts: Vec<CollectedPanicContract>,
    safety_contracts: Vec<CollectedSafetyContract>,
    mir_asserts: Vec<CollectedMirAssert>,
    marker_occurrences: Vec<CollectedMarkerOccurrence>,
}

/// Explicit owned inputs for one artifact collection boundary.
///
/// Keeping domain fields named makes the construction site reviewable and
/// leaves a clean extension point for subsequently migrated fact domains.
pub(crate) struct CollectedArtifactInput {
    pub(crate) program: CollectedProgram,
    pub(crate) unsafe_operations: Vec<CollectedUnsafeOperation>,
    pub(crate) panic_contracts: Vec<CollectedPanicContract>,
    pub(crate) safety_contracts: Vec<CollectedSafetyContract>,
    pub(crate) mir_asserts: Vec<CollectedMirAssert>,
    pub(crate) marker_occurrences: Vec<CollectedMarkerOccurrence>,
}

impl CollectedArtifact {
    /// Canonicalizes and validates every domain against the shared program graph.
    pub(crate) fn try_new(input: CollectedArtifactInput) -> Result<Self, CollectedArtifactError> {
        let CollectedArtifactInput {
            program,
            unsafe_operations,
            panic_contracts,
            safety_contracts,
            mir_asserts,
            marker_occurrences,
        } = input;
        let known_anchors = program
            .source_anchors()
            .iter()
            .map(|entity| entity.anchor().clone())
            .collect::<BTreeSet<_>>();
        let known_callables = program
            .callables()
            .iter()
            .map(|entity| *entity.key())
            .collect::<BTreeSet<_>>();
        let known_bodies = program
            .bodies()
            .iter()
            .map(|body| *body.entity().key())
            .collect::<BTreeSet<_>>();
        let known_groups = program
            .bodies()
            .iter()
            .flat_map(CollectedFunctionBody::safety_effect_groups)
            .map(|group| *group.key())
            .collect::<BTreeSet<_>>();
        let known_effect_sites = program
            .bodies()
            .iter()
            .flat_map(CollectedFunctionBody::effect_sites)
            .map(|site| *site.entity().site())
            .collect::<BTreeSet<_>>();
        let known_call_occurrences = program
            .bodies()
            .iter()
            .flat_map(CollectedFunctionBody::call_sites)
            .flat_map(CollectedCallSite::occurrences)
            .map(|occurrence| *occurrence.entity().key())
            .collect::<BTreeSet<_>>();

        let unsafe_operations = canonicalize_unsafe_operations(
            unsafe_operations,
            &known_bodies,
            &known_groups,
            &known_anchors,
        )?;
        let known_unsafe_operations = unsafe_operations
            .iter()
            .map(|operation| *operation.entity().key())
            .collect::<BTreeSet<_>>();
        let panic_contracts = canonicalize_contracts(
            panic_contracts,
            ContractDomain::Panic,
            &known_callables,
            &known_anchors,
        )?;
        let safety_contracts = canonicalize_contracts(
            safety_contracts,
            ContractDomain::Safety,
            &known_callables,
            &known_anchors,
        )?;
        let mir_asserts = canonicalize_mir_asserts(mir_asserts, &known_effect_sites)?;
        let marker_occurrences = canonicalize_marker_occurrences(
            marker_occurrences,
            &known_anchors,
            &known_bodies,
            &known_call_occurrences,
            &known_effect_sites,
            &known_unsafe_operations,
        )?;

        Ok(Self {
            program,
            unsafe_operations,
            panic_contracts,
            safety_contracts,
            mir_asserts,
            marker_occurrences,
        })
    }

    /// Builds a core-only artifact for focused core-pass tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn new(program: CollectedProgram) -> Self {
        Self {
            program,
            unsafe_operations: Vec::new(),
            panic_contracts: Vec::new(),
            safety_contracts: Vec::new(),
            mir_asserts: Vec::new(),
            marker_occurrences: Vec::new(),
        }
    }

    #[must_use]
    pub(crate) const fn program(&self) -> &CollectedProgram {
        &self.program
    }

    #[must_use]
    pub(crate) fn unsafe_operations(&self) -> &[CollectedUnsafeOperation] {
        &self.unsafe_operations
    }

    #[must_use]
    pub(crate) fn panic_contracts(&self) -> &[CollectedPanicContract] {
        &self.panic_contracts
    }

    #[must_use]
    pub(crate) fn safety_contracts(&self) -> &[CollectedSafetyContract] {
        &self.safety_contracts
    }

    #[must_use]
    pub(crate) fn mir_asserts(&self) -> &[CollectedMirAssert] {
        &self.mir_asserts
    }

    #[must_use]
    pub(crate) fn marker_occurrences(&self) -> &[CollectedMarkerOccurrence] {
        &self.marker_occurrences
    }
}

/// One validated compiler assertion at an exact core MIR effect site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedMirAssert {
    site: EffectSiteKey,
    kind: MirAssertKind,
}

impl CollectedMirAssert {
    #[must_use]
    pub(crate) const fn new(site: EffectSiteKey, kind: MirAssertKind) -> Self {
        Self { site, kind }
    }

    #[must_use]
    pub(crate) const fn site(&self) -> &EffectSiteKey {
        &self.site
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> MirAssertKind {
        self.kind
    }
}

macro_rules! collected_marker_candidate {
    (
        $(#[$meta:meta])*
        $name:ident,
        $endpoint:ty,
        $endpoint_name:ident,
        $relation:ty
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub(crate) struct $name {
            endpoint: $endpoint,
            claim: MarkerClaimKey,
            relation: $relation,
        }

        impl $name {
            #[must_use]
            pub(crate) const fn new(
                endpoint: $endpoint,
                claim: MarkerClaimKey,
                relation: $relation,
            ) -> Self {
                Self {
                    endpoint,
                    claim,
                    relation,
                }
            }

            #[must_use]
            pub(crate) const fn $endpoint_name(&self) -> &$endpoint {
                &self.endpoint
            }

            #[must_use]
            pub(crate) const fn claim(&self) -> &MarkerClaimKey {
                &self.claim
            }

            #[must_use]
            pub(crate) const fn relation(&self) -> &$relation {
                &self.relation
            }
        }
    };
}

/// One typed function-to-claim attachment candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedFunctionMarkerCandidate {
    endpoint: FunctionKey,
    claim: MarkerClaimKey,
    relation: FunctionHasMarkerClaimCandidate,
}

impl CollectedFunctionMarkerCandidate {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn new(
        endpoint: FunctionKey,
        claim: MarkerClaimKey,
        relation: FunctionHasMarkerClaimCandidate,
    ) -> Self {
        Self {
            endpoint,
            claim,
            relation,
        }
    }

    #[must_use]
    pub(crate) const fn function(&self) -> &FunctionKey {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn claim(&self) -> &MarkerClaimKey {
        &self.claim
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &FunctionHasMarkerClaimCandidate {
        &self.relation
    }
}
collected_marker_candidate!(
    /// One typed call-occurrence-to-claim attachment candidate.
    CollectedMarkerCallCandidate,
    CallOccurrenceKey,
    occurrence,
    CallOccurrenceHasMarkerClaimCandidate
);
collected_marker_candidate!(
    /// One typed effect-site-to-claim attachment candidate.
    CollectedEffectMarkerCandidate,
    EffectSiteKey,
    effect_site,
    EffectSiteHasMarkerClaimCandidate
);
collected_marker_candidate!(
    /// One typed unsafe-operation-to-claim attachment candidate.
    CollectedUnsafeOperationMarkerCandidate,
    UnsafeOperationKey,
    unsafe_operation,
    UnsafeOperationHasMarkerClaimCandidate
);

/// One marker occurrence, its claims, and every typed lexical candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedMarkerOccurrence {
    entity: MarkerOccurrenceEntity,
    claims: Vec<MarkerClaimEntity>,
    function_candidates: Vec<CollectedFunctionMarkerCandidate>,
    call_candidates: Vec<CollectedMarkerCallCandidate>,
    effect_candidates: Vec<CollectedEffectMarkerCandidate>,
    unsafe_operation_candidates: Vec<CollectedUnsafeOperationMarkerCandidate>,
}

impl CollectedMarkerOccurrence {
    #[must_use]
    pub(crate) const fn new(
        entity: MarkerOccurrenceEntity,
        claims: Vec<MarkerClaimEntity>,
        function_candidates: Vec<CollectedFunctionMarkerCandidate>,
        call_candidates: Vec<CollectedMarkerCallCandidate>,
        effect_candidates: Vec<CollectedEffectMarkerCandidate>,
        unsafe_operation_candidates: Vec<CollectedUnsafeOperationMarkerCandidate>,
    ) -> Self {
        Self {
            entity,
            claims,
            function_candidates,
            call_candidates,
            effect_candidates,
            unsafe_operation_candidates,
        }
    }

    #[must_use]
    pub(crate) const fn entity(&self) -> &MarkerOccurrenceEntity {
        &self.entity
    }

    #[must_use]
    pub(crate) fn claims(&self) -> &[MarkerClaimEntity] {
        &self.claims
    }

    #[must_use]
    pub(crate) fn function_candidates(&self) -> &[CollectedFunctionMarkerCandidate] {
        &self.function_candidates
    }

    #[must_use]
    pub(crate) fn call_candidates(&self) -> &[CollectedMarkerCallCandidate] {
        &self.call_candidates
    }

    #[must_use]
    pub(crate) fn effect_candidates(&self) -> &[CollectedEffectMarkerCandidate] {
        &self.effect_candidates
    }

    #[must_use]
    pub(crate) fn unsafe_operation_candidates(&self) -> &[CollectedUnsafeOperationMarkerCandidate] {
        &self.unsafe_operation_candidates
    }

    #[cfg(test)]
    fn claims_mut_for_test(&mut self) -> &mut Vec<MarkerClaimEntity> {
        &mut self.claims
    }

    #[cfg(test)]
    fn function_candidates_mut_for_test(&mut self) -> &mut Vec<CollectedFunctionMarkerCandidate> {
        &mut self.function_candidates
    }

    #[cfg(test)]
    fn call_candidates_mut_for_test(&mut self) -> &mut Vec<CollectedMarkerCallCandidate> {
        &mut self.call_candidates
    }

    #[cfg(test)]
    fn effect_candidates_mut_for_test(&mut self) -> &mut Vec<CollectedEffectMarkerCandidate> {
        &mut self.effect_candidates
    }

    #[cfg(test)]
    fn unsafe_operation_candidates_mut_for_test(
        &mut self,
    ) -> &mut Vec<CollectedUnsafeOperationMarkerCandidate> {
        &mut self.unsafe_operation_candidates
    }
}

/// One role-qualified verified source anchor of an unsafe operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedUnsafeOperationSourceAnchor {
    role: UnsafeOperationSourceAnchorRole,
    anchor: SourceAnchorKey,
}

impl CollectedUnsafeOperationSourceAnchor {
    #[must_use]
    pub(crate) const fn new(
        role: UnsafeOperationSourceAnchorRole,
        anchor: SourceAnchorKey,
    ) -> Self {
        Self { role, anchor }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> UnsafeOperationSourceAnchorRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> &SourceAnchorKey {
        &self.anchor
    }
}

/// One frame of an outer-to-inner unsafe-operation macro path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedUnsafeOperationMacroFrame {
    entity: UnsafeOperationMacroExpansionEntity,
    callsite: Option<SourceAnchorKey>,
}

impl CollectedUnsafeOperationMacroFrame {
    #[must_use]
    pub(crate) const fn new(
        entity: UnsafeOperationMacroExpansionEntity,
        callsite: Option<SourceAnchorKey>,
    ) -> Self {
        Self { entity, callsite }
    }

    #[must_use]
    pub(crate) const fn entity(&self) -> &UnsafeOperationMacroExpansionEntity {
        &self.entity
    }

    #[must_use]
    pub(crate) const fn callsite(&self) -> Option<&SourceAnchorKey> {
        self.callsite.as_ref()
    }
}

/// One policy-neutral THIR unsafe operation and its exact core endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedUnsafeOperation {
    entity: UnsafeOperationEntity,
    safety_effect_group: SafetyEffectGroupKey,
    source_anchors: Vec<CollectedUnsafeOperationSourceAnchor>,
    macro_frames: Vec<CollectedUnsafeOperationMacroFrame>,
}

impl CollectedUnsafeOperation {
    #[must_use]
    pub(crate) fn new(
        entity: UnsafeOperationEntity,
        safety_effect_group: SafetyEffectGroupKey,
        source_anchors: Vec<CollectedUnsafeOperationSourceAnchor>,
        macro_frames: Vec<CollectedUnsafeOperationMacroFrame>,
    ) -> Self {
        Self {
            entity,
            safety_effect_group,
            source_anchors,
            macro_frames,
        }
    }

    #[must_use]
    pub(crate) const fn entity(&self) -> &UnsafeOperationEntity {
        &self.entity
    }

    #[must_use]
    pub(crate) const fn safety_effect_group(&self) -> &SafetyEffectGroupKey {
        &self.safety_effect_group
    }

    #[must_use]
    pub(crate) fn source_anchors(&self) -> &[CollectedUnsafeOperationSourceAnchor] {
        &self.source_anchors
    }

    #[must_use]
    pub(crate) fn macro_frames(&self) -> &[CollectedUnsafeOperationMacroFrame] {
        &self.macro_frames
    }

    #[cfg(test)]
    fn replace_safety_effect_group_for_test(&mut self, group: SafetyEffectGroupKey) {
        self.safety_effect_group = group;
    }

    #[cfg(test)]
    fn source_anchors_mut_for_test(&mut self) -> &mut Vec<CollectedUnsafeOperationSourceAnchor> {
        &mut self.source_anchors
    }

    #[cfg(test)]
    fn macro_frames_mut_for_test(&mut self) -> &mut Vec<CollectedUnsafeOperationMacroFrame> {
        &mut self.macro_frames
    }
}

/// One documented `# Panics` declaration and its source-ordered requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedPanicContract {
    owner: FunctionKey,
    source_anchor: Option<SourceAnchorKey>,
    requirements: Vec<PanicRequirement>,
}

impl CollectedPanicContract {
    #[must_use]
    pub(crate) const fn new(
        owner: FunctionKey,
        source_anchor: Option<SourceAnchorKey>,
        requirements: Vec<PanicRequirement>,
    ) -> Self {
        Self {
            owner,
            source_anchor,
            requirements,
        }
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> &FunctionKey {
        &self.owner
    }

    #[must_use]
    pub(crate) const fn source_anchor(&self) -> Option<&SourceAnchorKey> {
        self.source_anchor.as_ref()
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[PanicRequirement] {
        &self.requirements
    }
}

/// One documented `# Safety` declaration and its source-ordered requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedSafetyContract {
    owner: FunctionKey,
    source_anchor: Option<SourceAnchorKey>,
    requirements: Vec<SafetyRequirement>,
}

impl CollectedSafetyContract {
    #[must_use]
    pub(crate) const fn new(
        owner: FunctionKey,
        source_anchor: Option<SourceAnchorKey>,
        requirements: Vec<SafetyRequirement>,
    ) -> Self {
        Self {
            owner,
            source_anchor,
            requirements,
        }
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> &FunctionKey {
        &self.owner
    }

    #[must_use]
    pub(crate) const fn source_anchor(&self) -> Option<&SourceAnchorKey> {
        self.source_anchor.as_ref()
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[SafetyRequirement] {
        &self.requirements
    }
}

/// Canonical core program facts collected directly from compiler queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedProgram {
    source_files: Vec<SourceFileEntity>,
    source_anchors: Vec<SourceAnchorEntity>,
    callables: Vec<CallableEntity>,
    callable_keys: Vec<CallableKeyEntity>,
    bodies: Vec<CollectedFunctionBody>,
}

impl CollectedProgram {
    /// Canonicalizes collection order and validates every core relationship.
    pub(crate) fn try_new(
        source_files: Vec<SourceFileEntity>,
        source_anchors: Vec<SourceAnchorEntity>,
        callables: Vec<CallableEntity>,
        bodies: Vec<CollectedFunctionBody>,
    ) -> Result<Self, CollectedProgramError> {
        let source_files = canonicalize_source_files(source_files)?;
        let file_lengths = source_files
            .iter()
            .map(|file| (file.id().to_owned(), file.byte_len()))
            .collect::<BTreeMap<_, _>>();
        let source_anchors = canonicalize_source_anchors(source_anchors, &file_lengths)?;
        let known_anchors = source_anchors
            .iter()
            .map(|anchor| anchor.anchor().clone())
            .collect::<BTreeSet<_>>();
        let callables = canonicalize_callables(callables)?;
        let known_callables = callables
            .iter()
            .map(|callable| *callable.key())
            .collect::<BTreeSet<_>>();
        let (bodies, callable_keys) =
            canonicalize_bodies(bodies, &known_anchors, &known_callables)?;

        Ok(Self {
            source_files,
            source_anchors,
            callables,
            callable_keys,
            bodies,
        })
    }

    #[must_use]
    pub(crate) fn source_files(&self) -> &[SourceFileEntity] {
        &self.source_files
    }

    #[must_use]
    pub(crate) fn source_anchors(&self) -> &[SourceAnchorEntity] {
        &self.source_anchors
    }

    #[must_use]
    pub(crate) fn callables(&self) -> &[CallableEntity] {
        &self.callables
    }

    #[must_use]
    pub(crate) fn callable_keys(&self) -> &[CallableKeyEntity] {
        &self.callable_keys
    }

    #[must_use]
    pub(crate) fn bodies(&self) -> &[CollectedFunctionBody] {
        &self.bodies
    }
}

/// One owned function body and every core entity rooted at it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedFunctionBody {
    entity: FunctionEntity,
    source_anchor: Option<SourceAnchorKey>,
    call_sites: Vec<CollectedCallSite>,
    safety_effect_groups: Vec<SafetyEffectGroupEntity>,
    effect_sites: Vec<CollectedEffectSite>,
}

impl CollectedFunctionBody {
    #[must_use]
    pub(crate) fn new(
        entity: FunctionEntity,
        source_anchor: Option<SourceAnchorKey>,
        call_sites: Vec<CollectedCallSite>,
        safety_effect_groups: Vec<SafetyEffectGroupEntity>,
        effect_sites: Vec<CollectedEffectSite>,
    ) -> Self {
        Self {
            entity,
            source_anchor,
            call_sites,
            safety_effect_groups,
            effect_sites,
        }
    }

    #[must_use]
    pub(crate) const fn entity(&self) -> &FunctionEntity {
        &self.entity
    }

    #[must_use]
    pub(crate) const fn source_anchor(&self) -> Option<&SourceAnchorKey> {
        self.source_anchor.as_ref()
    }

    #[must_use]
    pub(crate) fn call_sites(&self) -> &[CollectedCallSite] {
        &self.call_sites
    }

    #[must_use]
    pub(crate) fn safety_effect_groups(&self) -> &[SafetyEffectGroupEntity] {
        &self.safety_effect_groups
    }

    #[must_use]
    pub(crate) fn effect_sites(&self) -> &[CollectedEffectSite] {
        &self.effect_sites
    }

    #[cfg(test)]
    fn call_sites_mut_for_test(&mut self) -> &mut Vec<CollectedCallSite> {
        &mut self.call_sites
    }

    #[cfg(test)]
    fn effect_sites_mut_for_test(&mut self) -> &mut Vec<CollectedEffectSite> {
        &mut self.effect_sites
    }

    #[cfg(test)]
    fn safety_effect_groups_mut_for_test(&mut self) -> &mut Vec<SafetyEffectGroupEntity> {
        &mut self.safety_effect_groups
    }
}

/// One source call site and all semantic occurrences resolved from it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedCallSite {
    entity: CallSiteEntity,
    occurrences: Vec<CollectedCallOccurrence>,
}

impl CollectedCallSite {
    #[must_use]
    pub(crate) const fn new(
        entity: CallSiteEntity,
        occurrences: Vec<CollectedCallOccurrence>,
    ) -> Self {
        Self {
            entity,
            occurrences,
        }
    }

    #[must_use]
    pub(crate) const fn entity(&self) -> &CallSiteEntity {
        &self.entity
    }

    #[must_use]
    pub(crate) fn occurrences(&self) -> &[CollectedCallOccurrence] {
        &self.occurrences
    }

    #[cfg(test)]
    fn occurrences_mut_for_test(&mut self) -> &mut Vec<CollectedCallOccurrence> {
        &mut self.occurrences
    }
}

/// One role-qualified callable endpoint of a call occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedCallTarget {
    role: CallTargetRole,
    callable: FunctionKey,
}

impl CollectedCallTarget {
    #[must_use]
    pub(crate) const fn new(role: CallTargetRole, callable: FunctionKey) -> Self {
        Self { role, callable }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> CallTargetRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn callable(&self) -> &FunctionKey {
        &self.callable
    }
}

/// One role-qualified verified source anchor of a call occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedCallSourceAnchor {
    role: CallSourceAnchorRole,
    anchor: SourceAnchorKey,
}

impl CollectedCallSourceAnchor {
    #[must_use]
    pub(crate) const fn new(role: CallSourceAnchorRole, anchor: SourceAnchorKey) -> Self {
        Self { role, anchor }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> CallSourceAnchorRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> &SourceAnchorKey {
        &self.anchor
    }
}

/// One frame of an outer-to-inner call macro path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedCallMacroFrame {
    entity: CallMacroExpansionEntity,
    callsite: Option<SourceAnchorKey>,
}

impl CollectedCallMacroFrame {
    #[must_use]
    pub(crate) const fn new(
        entity: CallMacroExpansionEntity,
        callsite: Option<SourceAnchorKey>,
    ) -> Self {
        Self { entity, callsite }
    }

    #[must_use]
    pub(crate) const fn entity(&self) -> &CallMacroExpansionEntity {
        &self.entity
    }

    #[must_use]
    pub(crate) const fn callsite(&self) -> Option<&SourceAnchorKey> {
        self.callsite.as_ref()
    }
}

/// One call occurrence and all relations emitted for it by the core pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedCallOccurrence {
    entity: CallOccurrenceEntity,
    targets: Vec<CollectedCallTarget>,
    callable_keys: Vec<CallableKey>,
    safety_effect_groups: Vec<SafetyEffectGroupKey>,
    source_anchors: Vec<CollectedCallSourceAnchor>,
    macro_frames: Vec<CollectedCallMacroFrame>,
}

impl CollectedCallOccurrence {
    #[must_use]
    pub(crate) fn new(
        entity: CallOccurrenceEntity,
        targets: Vec<CollectedCallTarget>,
        callable_keys: Vec<CallableKey>,
        safety_effect_groups: Vec<SafetyEffectGroupKey>,
        source_anchors: Vec<CollectedCallSourceAnchor>,
        macro_frames: Vec<CollectedCallMacroFrame>,
    ) -> Self {
        Self {
            entity,
            targets,
            callable_keys,
            safety_effect_groups,
            source_anchors,
            macro_frames,
        }
    }

    #[must_use]
    pub(crate) const fn entity(&self) -> &CallOccurrenceEntity {
        &self.entity
    }

    #[must_use]
    pub(crate) fn targets(&self) -> &[CollectedCallTarget] {
        &self.targets
    }

    #[must_use]
    pub(crate) fn callable_keys(&self) -> &[CallableKey] {
        &self.callable_keys
    }

    /// Returns the exactly one safety group guaranteed by `CollectedProgram`.
    #[must_use]
    pub(crate) fn safety_effect_group(&self) -> &SafetyEffectGroupKey {
        self.safety_effect_groups
            .first()
            .expect("validated call occurrence has exactly one safety group")
    }

    #[must_use]
    pub(crate) fn source_anchors(&self) -> &[CollectedCallSourceAnchor] {
        &self.source_anchors
    }

    #[must_use]
    pub(crate) fn macro_frames(&self) -> &[CollectedCallMacroFrame] {
        &self.macro_frames
    }

    #[cfg(test)]
    fn targets_mut_for_test(&mut self) -> &mut Vec<CollectedCallTarget> {
        &mut self.targets
    }

    #[cfg(test)]
    fn callable_keys_mut_for_test(&mut self) -> &mut Vec<CallableKey> {
        &mut self.callable_keys
    }

    #[cfg(test)]
    fn safety_effect_groups_mut_for_test(&mut self) -> &mut Vec<SafetyEffectGroupKey> {
        &mut self.safety_effect_groups
    }

    #[cfg(test)]
    fn macro_frames_mut_for_test(&mut self) -> &mut Vec<CollectedCallMacroFrame> {
        &mut self.macro_frames
    }

    #[cfg(test)]
    fn source_anchors_mut_for_test(&mut self) -> &mut Vec<CollectedCallSourceAnchor> {
        &mut self.source_anchors
    }

    #[cfg(test)]
    fn replace_entity_for_test(&mut self, entity: CallOccurrenceEntity) {
        self.entity = entity;
    }
}

/// One role-qualified verified source anchor of an exact MIR effect site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedEffectSourceAnchor {
    role: EffectSourceAnchorRole,
    anchor: SourceAnchorKey,
}

impl CollectedEffectSourceAnchor {
    #[must_use]
    pub(crate) const fn new(role: EffectSourceAnchorRole, anchor: SourceAnchorKey) -> Self {
        Self { role, anchor }
    }

    #[must_use]
    pub(crate) const fn role(&self) -> EffectSourceAnchorRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn anchor(&self) -> &SourceAnchorKey {
        &self.anchor
    }
}

/// One frame of an outer-to-inner MIR effect macro path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedEffectMacroFrame {
    entity: MacroExpansionEntity,
    callsite: Option<SourceAnchorKey>,
}

impl CollectedEffectMacroFrame {
    #[must_use]
    pub(crate) const fn new(
        entity: MacroExpansionEntity,
        callsite: Option<SourceAnchorKey>,
    ) -> Self {
        Self { entity, callsite }
    }

    #[must_use]
    pub(crate) const fn entity(&self) -> &MacroExpansionEntity {
        &self.entity
    }

    #[must_use]
    pub(crate) const fn callsite(&self) -> Option<&SourceAnchorKey> {
        self.callsite.as_ref()
    }
}

/// One exact MIR effect site and its verified source provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectedEffectSite {
    entity: EffectSiteEntity,
    source_anchors: Vec<CollectedEffectSourceAnchor>,
    macro_frames: Vec<CollectedEffectMacroFrame>,
}

impl CollectedEffectSite {
    #[must_use]
    pub(crate) const fn new(
        entity: EffectSiteEntity,
        source_anchors: Vec<CollectedEffectSourceAnchor>,
        macro_frames: Vec<CollectedEffectMacroFrame>,
    ) -> Self {
        Self {
            entity,
            source_anchors,
            macro_frames,
        }
    }

    #[must_use]
    pub(crate) const fn entity(&self) -> &EffectSiteEntity {
        &self.entity
    }

    #[must_use]
    pub(crate) fn source_anchors(&self) -> &[CollectedEffectSourceAnchor] {
        &self.source_anchors
    }

    #[must_use]
    pub(crate) fn macro_frames(&self) -> &[CollectedEffectMacroFrame] {
        &self.macro_frames
    }

    #[cfg(test)]
    fn macro_frames_mut_for_test(&mut self) -> &mut Vec<CollectedEffectMacroFrame> {
        &mut self.macro_frames
    }

    #[cfg(test)]
    fn source_anchors_mut_for_test(&mut self) -> &mut Vec<CollectedEffectSourceAnchor> {
        &mut self.source_anchors
    }
}

/// Body-relative relationship whose owner did not match its containing body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectedOwnerRelation {
    CallSite,
    CallOccurrence,
    SafetyEffectGroup,
    EffectSite,
    OccurrenceSafetyEffectGroup,
}

/// Invalid shape of the primary target carried by a call occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CallTargetShapeError {
    ConcreteBoundaryMissingRuntime,
    ConcreteBoundaryHasOpaqueTarget,
    OpaqueBoundaryHasRuntime,
    OpaqueBoundaryHasMultipleStableTargets,
}

/// Invalid artifact-generation identity carried by a role-qualified target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CallTargetIdentityShapeError {
    RuntimeRequiresExactInstance,
    StableTargetRequiresGenericDefinition,
}

/// Contract namespace used by cross-domain validation diagnostics.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ContractDomain {
    Panic,
    Safety,
}

/// Structured failure returned before a domain pass can observe collection state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CollectedArtifactError {
    DuplicateMarkerOccurrence {
        occurrence: Box<MarkerOccurrenceKey>,
    },
    DanglingMarkerSourceAnchor {
        occurrence: Box<MarkerOccurrenceKey>,
        anchor: SourceAnchorKey,
    },
    SourceMarkerHasExpansionPath {
        occurrence: Box<MarkerOccurrenceKey>,
    },
    MacroMarkerMissingExpansionPath {
        occurrence: Box<MarkerOccurrenceKey>,
    },
    MarkerOriginPathMismatch {
        occurrence: Box<MarkerOccurrenceKey>,
        origin: StableExpansionHash,
        actual_last: StableExpansionHash,
    },
    DuplicateMarkerExpansionHash {
        occurrence: Box<MarkerOccurrenceKey>,
        expansion: StableExpansionHash,
    },
    MarkerClaimOwnerMismatch {
        occurrence: Box<MarkerOccurrenceKey>,
        claim: Box<MarkerClaimKey>,
    },
    DuplicateMarkerClaim {
        claim: Box<MarkerClaimKey>,
    },
    NonContiguousMarkerClaimOrdinals {
        occurrence: Box<MarkerOccurrenceKey>,
        domain: super::facts::evaluation::DomainId,
        expected_ordinal: u32,
        actual_ordinal: u32,
    },
    EmptyMarkerClaimRationale {
        claim: Box<MarkerClaimKey>,
    },
    EmptyMarkerClaimSelectorName {
        claim: Box<MarkerClaimKey>,
    },
    EmptyMarkerClaimExplicitSelector {
        claim: Box<MarkerClaimKey>,
    },
    EmptyMarkerClaimExplicitReference {
        claim: Box<MarkerClaimKey>,
        reference_ordinal: u32,
    },
    DuplicateMarkerClaimExplicitReference {
        claim: Box<MarkerClaimKey>,
        first_ordinal: u32,
        duplicate_ordinal: u32,
    },
    MarkerCandidateClaimOwnerMismatch {
        occurrence: Box<MarkerOccurrenceKey>,
        claim: Box<MarkerClaimKey>,
    },
    MissingMarkerCandidateClaim {
        claim: Box<MarkerClaimKey>,
    },
    EmptyMarkerCandidateApplicability {
        claim: Box<MarkerClaimKey>,
    },
    ConflictingFunctionMarkerCandidate {
        function: FunctionKey,
        claim: Box<MarkerClaimKey>,
    },
    DanglingFunctionMarkerCandidate {
        function: FunctionKey,
        claim: Box<MarkerClaimKey>,
    },
    ConflictingCallMarkerCandidate {
        occurrence: CallOccurrenceKey,
        claim: Box<MarkerClaimKey>,
    },
    DanglingCallMarkerCandidate {
        occurrence: CallOccurrenceKey,
        claim: Box<MarkerClaimKey>,
    },
    ConflictingEffectMarkerCandidate {
        effect_site: EffectSiteKey,
        claim: Box<MarkerClaimKey>,
    },
    DanglingEffectMarkerCandidate {
        effect_site: EffectSiteKey,
        claim: Box<MarkerClaimKey>,
    },
    ConflictingUnsafeOperationMarkerCandidate {
        unsafe_operation: UnsafeOperationKey,
        claim: Box<MarkerClaimKey>,
    },
    DanglingUnsafeOperationMarkerCandidate {
        unsafe_operation: UnsafeOperationKey,
        claim: Box<MarkerClaimKey>,
    },
    MissingMirAssertEffectSite {
        site: EffectSiteKey,
    },
    DuplicateMirAssert {
        site: EffectSiteKey,
    },
    MissingUnsafeOperationBody {
        owner: FunctionKey,
    },
    DuplicateUnsafeOperation {
        operation: UnsafeOperationKey,
    },
    NonContiguousUnsafeOperationIds {
        owner: FunctionKey,
        expected_local_id: u32,
        actual_local_id: u32,
    },
    UnsafeOperationSafetyEffectGroupOwnerMismatch {
        operation: UnsafeOperationKey,
        group: SafetyEffectGroupKey,
    },
    DanglingUnsafeOperationSafetyEffectGroup {
        operation: UnsafeOperationKey,
        group: SafetyEffectGroupKey,
    },
    DuplicateUnsafeOperationSourceAnchorRole {
        operation: UnsafeOperationKey,
        role: UnsafeOperationSourceAnchorRole,
    },
    DanglingUnsafeOperationSourceAnchor {
        operation: UnsafeOperationKey,
        anchor: SourceAnchorKey,
        usage: &'static str,
    },
    ConflictingUnsafeOperationMacroFrame {
        operation: UnsafeOperationKey,
        depth: u32,
    },
    UnsafeOperationMacroEndpointMismatch {
        operation: UnsafeOperationKey,
        actual: UnsafeOperationKey,
        depth: u32,
    },
    NonContiguousUnsafeOperationMacroPath {
        operation: UnsafeOperationKey,
        expected_depth: u32,
        actual_depth: u32,
    },
    EmptyUnsafeOperationMacroDisplayPath {
        operation: UnsafeOperationKey,
        depth: u32,
    },
    DuplicateContract {
        domain: ContractDomain,
        owner: FunctionKey,
    },
    MissingContractCallable {
        domain: ContractDomain,
        owner: FunctionKey,
    },
    ContractRequirementOwnerMismatch {
        domain: ContractDomain,
        expected: FunctionKey,
        actual: FunctionKey,
        ordinal: u32,
    },
    NonContiguousContractOrdinals {
        domain: ContractDomain,
        owner: FunctionKey,
        expected_ordinal: u32,
        actual_ordinal: u32,
    },
    EmptyContractRequirementName {
        domain: ContractDomain,
        owner: FunctionKey,
        ordinal: u32,
    },
    DanglingDomainSourceAnchor {
        domain: ContractDomain,
        owner: FunctionKey,
        ordinal: Option<u32>,
        anchor: SourceAnchorKey,
    },
}

impl Display for CollectedArtifactError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid typed artifact collection: {self:?}")
    }
}

impl std::error::Error for CollectedArtifactError {}

/// Structured failure returned before any artifact pass can observe collection state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CollectedProgramError {
    EmptySourceFileField {
        source_file: String,
        field: &'static str,
    },
    ConflictingSourceFile {
        source_file: String,
    },
    DanglingSourceFile {
        anchor: SourceAnchorKey,
    },
    InvalidSourceAnchorRange {
        anchor: SourceAnchorKey,
        file_len: u64,
    },
    ConflictingCallable {
        callable: FunctionKey,
    },
    EmptyCallableDisplayPath {
        callable: FunctionKey,
    },
    EmptyNamespaceCandidates {
        callable: FunctionKey,
    },
    EmptyNamespaceCandidate {
        callable: FunctionKey,
    },
    DuplicateFunctionBody {
        function: FunctionKey,
    },
    EmptyFunctionDisplayPath {
        function: FunctionKey,
    },
    ConsumerInstantiationRequiresExactFunction {
        function: FunctionKey,
    },
    MissingBodyCallable {
        function: FunctionKey,
    },
    DanglingSourceAnchor {
        anchor: SourceAnchorKey,
        usage: &'static str,
    },
    OwnerMismatch {
        relation: CollectedOwnerRelation,
        expected: FunctionKey,
        actual: FunctionKey,
    },
    DuplicateCallSite {
        site: CallSiteKey,
    },
    EmptyCallSite {
        site: CallSiteKey,
    },
    DuplicateCallOccurrence {
        occurrence: CallOccurrenceKey,
    },
    DuplicateSafetyEffectGroup {
        group: SafetyEffectGroupKey,
    },
    DuplicateEffectSite {
        site: EffectSiteKey,
    },
    EmptyCallApplicability {
        occurrence: CallOccurrenceKey,
    },
    EmptyOpaqueTargetDescription {
        occurrence: CallOccurrenceKey,
    },
    DuplicateCallTargetRole {
        occurrence: CallOccurrenceKey,
        role: CallTargetRole,
    },
    InvalidCallTargetShape {
        occurrence: CallOccurrenceKey,
        reason: CallTargetShapeError,
    },
    InvalidCallTargetIdentityShape {
        occurrence: CallOccurrenceKey,
        role: CallTargetRole,
        target: FunctionKey,
        reason: CallTargetIdentityShapeError,
    },
    DanglingCallTarget {
        occurrence: CallOccurrenceKey,
        target: FunctionKey,
    },
    MissingSafetyEffectGroup {
        occurrence: CallOccurrenceKey,
    },
    MultipleSafetyEffectGroups {
        occurrence: CallOccurrenceKey,
    },
    DanglingSafetyEffectGroup {
        occurrence: CallOccurrenceKey,
        group: SafetyEffectGroupKey,
    },
    DuplicateCallSourceAnchorRole {
        occurrence: CallOccurrenceKey,
        role: CallSourceAnchorRole,
    },
    DuplicateEffectSourceAnchorRole {
        site: EffectSiteKey,
        role: EffectSourceAnchorRole,
    },
    EmptyCallMacroDisplayPath {
        occurrence: CallOccurrenceKey,
        depth: u32,
    },
    EmptyEffectMacroDisplayPath {
        site: EffectSiteKey,
        depth: u32,
    },
    ConflictingCallMacroFrame {
        occurrence: CallOccurrenceKey,
        depth: u32,
    },
    ConflictingEffectMacroFrame {
        site: EffectSiteKey,
        depth: u32,
    },
    CallMacroEndpointMismatch {
        occurrence: CallOccurrenceKey,
        actual: CallOccurrenceKey,
        depth: u32,
    },
    EffectMacroEndpointMismatch {
        site: EffectSiteKey,
        actual: EffectSiteKey,
        depth: u32,
    },
    NonContiguousCallMacroPath {
        occurrence: CallOccurrenceKey,
        expected_depth: u32,
        actual_depth: u32,
    },
    NonContiguousEffectMacroPath {
        site: EffectSiteKey,
        expected_depth: u32,
        actual_depth: u32,
    },
}

impl Display for CollectedProgramError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid typed program collection: {self:?}")
    }
}

impl std::error::Error for CollectedProgramError {}

#[allow(
    clippy::too_many_lines,
    reason = "four separate typed candidate tables deliberately avoid a central endpoint enum"
)]
fn canonicalize_marker_occurrences(
    mut occurrences: Vec<CollectedMarkerOccurrence>,
    known_anchors: &BTreeSet<SourceAnchorKey>,
    known_functions: &BTreeSet<FunctionKey>,
    known_calls: &BTreeSet<CallOccurrenceKey>,
    known_effects: &BTreeSet<EffectSiteKey>,
    known_unsafe_operations: &BTreeSet<UnsafeOperationKey>,
) -> Result<Vec<CollectedMarkerOccurrence>, CollectedArtifactError> {
    occurrences.sort_by(|left, right| left.entity.key().cmp(right.entity.key()));
    for adjacent in occurrences.windows(2) {
        if adjacent[0].entity.key() == adjacent[1].entity.key() {
            return Err(CollectedArtifactError::DuplicateMarkerOccurrence {
                occurrence: Box::new(adjacent[0].entity.key().clone()),
            });
        }
    }

    for occurrence in &mut occurrences {
        validate_marker_occurrence_path(occurrence, known_anchors)?;
        canonicalize_marker_claims(occurrence)?;
        let known_claims = occurrence
            .claims
            .iter()
            .map(|claim| claim.key().clone())
            .collect::<BTreeSet<_>>();
        let occurrence_key = occurrence.entity.key().clone();

        canonicalize_marker_candidates(
            &mut occurrence.function_candidates,
            &occurrence_key,
            &known_claims,
            known_functions,
            CollectedFunctionMarkerCandidate::function,
            CollectedFunctionMarkerCandidate::claim,
            |candidate| {
                candidate.relation().source_callsite()
                    || candidate.relation().macro_definition_first()
            },
            |function, claim| CollectedArtifactError::ConflictingFunctionMarkerCandidate {
                function,
                claim: Box::new(claim),
            },
            |function, claim| CollectedArtifactError::DanglingFunctionMarkerCandidate {
                function,
                claim: Box::new(claim),
            },
        )?;
        canonicalize_marker_candidates(
            &mut occurrence.call_candidates,
            &occurrence_key,
            &known_claims,
            known_calls,
            CollectedMarkerCallCandidate::occurrence,
            CollectedMarkerCallCandidate::claim,
            |candidate| {
                candidate.relation().source_callsite()
                    || candidate.relation().macro_definition_first()
            },
            |call, claim| CollectedArtifactError::ConflictingCallMarkerCandidate {
                occurrence: call,
                claim: Box::new(claim),
            },
            |call, claim| CollectedArtifactError::DanglingCallMarkerCandidate {
                occurrence: call,
                claim: Box::new(claim),
            },
        )?;
        canonicalize_marker_candidates(
            &mut occurrence.effect_candidates,
            &occurrence_key,
            &known_claims,
            known_effects,
            CollectedEffectMarkerCandidate::effect_site,
            CollectedEffectMarkerCandidate::claim,
            |candidate| {
                candidate.relation().source_callsite()
                    || candidate.relation().macro_definition_first()
            },
            |effect_site, claim| CollectedArtifactError::ConflictingEffectMarkerCandidate {
                effect_site,
                claim: Box::new(claim),
            },
            |effect_site, claim| CollectedArtifactError::DanglingEffectMarkerCandidate {
                effect_site,
                claim: Box::new(claim),
            },
        )?;
        canonicalize_marker_candidates(
            &mut occurrence.unsafe_operation_candidates,
            &occurrence_key,
            &known_claims,
            known_unsafe_operations,
            CollectedUnsafeOperationMarkerCandidate::unsafe_operation,
            CollectedUnsafeOperationMarkerCandidate::claim,
            |candidate| {
                candidate.relation().source_callsite()
                    || candidate.relation().macro_definition_first()
            },
            |unsafe_operation, claim| {
                CollectedArtifactError::ConflictingUnsafeOperationMarkerCandidate {
                    unsafe_operation,
                    claim: Box::new(claim),
                }
            },
            |unsafe_operation, claim| {
                CollectedArtifactError::DanglingUnsafeOperationMarkerCandidate {
                    unsafe_operation,
                    claim: Box::new(claim),
                }
            },
        )?;
    }
    Ok(occurrences)
}

fn validate_marker_occurrence_path(
    occurrence: &CollectedMarkerOccurrence,
    known_anchors: &BTreeSet<SourceAnchorKey>,
) -> Result<(), CollectedArtifactError> {
    let key = occurrence.entity.key();
    if !known_anchors.contains(key.anchor()) {
        return Err(CollectedArtifactError::DanglingMarkerSourceAnchor {
            occurrence: Box::new(key.clone()),
            anchor: key.anchor().clone(),
        });
    }

    let path = occurrence.entity.expansion_path();
    match (key.origin(), path.last().copied()) {
        (None, Some(_)) => {
            return Err(CollectedArtifactError::SourceMarkerHasExpansionPath {
                occurrence: Box::new(key.clone()),
            });
        }
        (Some(_), None) => {
            return Err(CollectedArtifactError::MacroMarkerMissingExpansionPath {
                occurrence: Box::new(key.clone()),
            });
        }
        (Some(origin), Some(actual_last)) if origin != actual_last => {
            return Err(CollectedArtifactError::MarkerOriginPathMismatch {
                occurrence: Box::new(key.clone()),
                origin,
                actual_last,
            });
        }
        (None, None) | (Some(_), Some(_)) => {}
    }

    let mut seen = BTreeSet::new();
    for expansion in path {
        if !seen.insert(*expansion) {
            return Err(CollectedArtifactError::DuplicateMarkerExpansionHash {
                occurrence: Box::new(key.clone()),
                expansion: *expansion,
            });
        }
    }
    Ok(())
}

fn canonicalize_marker_claims(
    occurrence: &mut CollectedMarkerOccurrence,
) -> Result<(), CollectedArtifactError> {
    let occurrence_key = occurrence.entity.key().clone();
    occurrence
        .claims
        .sort_by(|left, right| left.key().cmp(right.key()));
    for adjacent in occurrence.claims.windows(2) {
        if adjacent[0].key() == adjacent[1].key() {
            return Err(CollectedArtifactError::DuplicateMarkerClaim {
                claim: Box::new(adjacent[0].key().clone()),
            });
        }
    }

    let mut next_ordinal = BTreeMap::new();
    for claim in &occurrence.claims {
        let key = claim.key();
        if key.occurrence() != &occurrence_key {
            return Err(CollectedArtifactError::MarkerClaimOwnerMismatch {
                occurrence: Box::new(occurrence_key.clone()),
                claim: Box::new(key.clone()),
            });
        }
        if claim.rationale().trim().is_empty() {
            return Err(CollectedArtifactError::EmptyMarkerClaimRationale {
                claim: Box::new(key.clone()),
            });
        }
        validate_marker_claim_selector(claim)?;
        let expected = next_ordinal.entry(key.domain().clone()).or_insert(0_u32);
        if key.source_ordinal() != *expected {
            return Err(CollectedArtifactError::NonContiguousMarkerClaimOrdinals {
                occurrence: Box::new(occurrence_key.clone()),
                domain: key.domain().clone(),
                expected_ordinal: *expected,
                actual_ordinal: key.source_ordinal(),
            });
        }
        *expected = expected.checked_add(1).ok_or_else(|| {
            CollectedArtifactError::NonContiguousMarkerClaimOrdinals {
                occurrence: Box::new(occurrence_key.clone()),
                domain: key.domain().clone(),
                expected_ordinal: *expected,
                actual_ordinal: key.source_ordinal(),
            }
        })?;
    }
    Ok(())
}

fn validate_marker_claim_selector(claim: &MarkerClaimEntity) -> Result<(), CollectedArtifactError> {
    match claim.selector() {
        EvidenceClaimSelector::Named(name) if name.trim().is_empty() => {
            Err(CollectedArtifactError::EmptyMarkerClaimSelectorName {
                claim: Box::new(claim.key().clone()),
            })
        }
        EvidenceClaimSelector::Unnamed | EvidenceClaimSelector::Named(_) => Ok(()),
        EvidenceClaimSelector::Explicit(references) if references.is_empty() => {
            Err(CollectedArtifactError::EmptyMarkerClaimExplicitSelector {
                claim: Box::new(claim.key().clone()),
            })
        }
        EvidenceClaimSelector::Explicit(references) => {
            let mut first_ordinal_by_reference = BTreeMap::new();
            for (ordinal, reference) in (0_u32..).zip(references) {
                if reference.trim().is_empty() {
                    return Err(CollectedArtifactError::EmptyMarkerClaimExplicitReference {
                        claim: Box::new(claim.key().clone()),
                        reference_ordinal: ordinal,
                    });
                }
                if let Some(first_ordinal) =
                    first_ordinal_by_reference.insert(reference.as_str(), ordinal)
                {
                    return Err(
                        CollectedArtifactError::DuplicateMarkerClaimExplicitReference {
                            claim: Box::new(claim.key().clone()),
                            first_ordinal,
                            duplicate_ordinal: ordinal,
                        },
                    );
                }
            }
            Ok(())
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the generic validator keeps four typed endpoint relations structurally identical"
)]
fn canonicalize_marker_candidates<C, E, Conflicting, Dangling>(
    candidates: &mut Vec<C>,
    occurrence: &MarkerOccurrenceKey,
    known_claims: &BTreeSet<MarkerClaimKey>,
    known_endpoints: &BTreeSet<E>,
    endpoint: fn(&C) -> &E,
    claim: fn(&C) -> &MarkerClaimKey,
    is_applicable: fn(&C) -> bool,
    conflicting: Conflicting,
    dangling: Dangling,
) -> Result<(), CollectedArtifactError>
where
    C: Eq,
    E: Clone + Ord,
    Conflicting: Fn(E, MarkerClaimKey) -> CollectedArtifactError,
    Dangling: Fn(E, MarkerClaimKey) -> CollectedArtifactError,
{
    candidates.sort_by(|left, right| {
        endpoint(left)
            .cmp(endpoint(right))
            .then_with(|| claim(left).cmp(claim(right)))
    });
    let mut canonical = Vec::with_capacity(candidates.len());
    for candidate in candidates.drain(..) {
        if let Some(previous) = canonical.last()
            && endpoint(previous) == endpoint(&candidate)
            && claim(previous) == claim(&candidate)
        {
            if previous == &candidate {
                continue;
            }
            return Err(conflicting(
                endpoint(&candidate).clone(),
                claim(&candidate).clone(),
            ));
        }
        canonical.push(candidate);
    }
    *candidates = canonical;

    for candidate in candidates {
        let candidate_claim = claim(candidate);
        if candidate_claim.occurrence() != occurrence {
            return Err(CollectedArtifactError::MarkerCandidateClaimOwnerMismatch {
                occurrence: Box::new(occurrence.clone()),
                claim: Box::new(candidate_claim.clone()),
            });
        }
        if !known_claims.contains(candidate_claim) {
            return Err(CollectedArtifactError::MissingMarkerCandidateClaim {
                claim: Box::new(candidate_claim.clone()),
            });
        }
        if !is_applicable(candidate) {
            return Err(CollectedArtifactError::EmptyMarkerCandidateApplicability {
                claim: Box::new(candidate_claim.clone()),
            });
        }
        if !known_endpoints.contains(endpoint(candidate)) {
            return Err(dangling(
                endpoint(candidate).clone(),
                candidate_claim.clone(),
            ));
        }
    }
    Ok(())
}

fn canonicalize_mir_asserts(
    mut assertions: Vec<CollectedMirAssert>,
    known_effect_sites: &BTreeSet<EffectSiteKey>,
) -> Result<Vec<CollectedMirAssert>, CollectedArtifactError> {
    assertions.sort_by_key(|assertion| assertion.site);
    for adjacent in assertions.windows(2) {
        if adjacent[0].site == adjacent[1].site {
            return Err(CollectedArtifactError::DuplicateMirAssert {
                site: adjacent[0].site,
            });
        }
    }
    for assertion in &assertions {
        if !known_effect_sites.contains(&assertion.site) {
            return Err(CollectedArtifactError::MissingMirAssertEffectSite {
                site: assertion.site,
            });
        }
    }
    Ok(assertions)
}

fn canonicalize_unsafe_operations(
    mut operations: Vec<CollectedUnsafeOperation>,
    known_bodies: &BTreeSet<FunctionKey>,
    known_groups: &BTreeSet<SafetyEffectGroupKey>,
    known_anchors: &BTreeSet<SourceAnchorKey>,
) -> Result<Vec<CollectedUnsafeOperation>, CollectedArtifactError> {
    operations.sort_by_key(|operation| *operation.entity.key());
    for adjacent in operations.windows(2) {
        if adjacent[0].entity.key() == adjacent[1].entity.key() {
            return Err(CollectedArtifactError::DuplicateUnsafeOperation {
                operation: *adjacent[0].entity.key(),
            });
        }
    }

    let mut next_local_id = BTreeMap::<FunctionKey, u32>::new();
    for operation in &mut operations {
        let key = *operation.entity.key();
        let owner = *key.owner();
        if !known_bodies.contains(&owner) {
            return Err(CollectedArtifactError::MissingUnsafeOperationBody { owner });
        }
        let expected_local_id = next_local_id.entry(owner).or_default();
        if key.local_id() != *expected_local_id {
            return Err(CollectedArtifactError::NonContiguousUnsafeOperationIds {
                owner,
                expected_local_id: *expected_local_id,
                actual_local_id: key.local_id(),
            });
        }
        *expected_local_id = expected_local_id.checked_add(1).ok_or_else(|| {
            CollectedArtifactError::NonContiguousUnsafeOperationIds {
                owner,
                expected_local_id: *expected_local_id,
                actual_local_id: key.local_id(),
            }
        })?;

        let group = operation.safety_effect_group;
        if group.owner() != &owner {
            return Err(
                CollectedArtifactError::UnsafeOperationSafetyEffectGroupOwnerMismatch {
                    operation: key,
                    group,
                },
            );
        }
        if !known_groups.contains(&group) {
            return Err(
                CollectedArtifactError::DanglingUnsafeOperationSafetyEffectGroup {
                    operation: key,
                    group,
                },
            );
        }

        canonicalize_unsafe_operation_anchors(operation, known_anchors)?;
        canonicalize_unsafe_operation_macro_frames(operation, known_anchors)?;
    }
    Ok(operations)
}

fn canonicalize_unsafe_operation_anchors(
    operation: &mut CollectedUnsafeOperation,
    known_anchors: &BTreeSet<SourceAnchorKey>,
) -> Result<(), CollectedArtifactError> {
    let key = *operation.entity.key();
    operation
        .source_anchors
        .sort_by(|left, right| (left.role, &left.anchor).cmp(&(right.role, &right.anchor)));
    operation.source_anchors.dedup();
    for adjacent in operation.source_anchors.windows(2) {
        if adjacent[0].role == adjacent[1].role {
            return Err(
                CollectedArtifactError::DuplicateUnsafeOperationSourceAnchorRole {
                    operation: key,
                    role: adjacent[0].role,
                },
            );
        }
    }
    for anchor in &operation.source_anchors {
        if !known_anchors.contains(&anchor.anchor) {
            return Err(
                CollectedArtifactError::DanglingUnsafeOperationSourceAnchor {
                    operation: key,
                    anchor: anchor.anchor.clone(),
                    usage: "unsafe operation",
                },
            );
        }
    }
    Ok(())
}

fn canonicalize_unsafe_operation_macro_frames(
    operation: &mut CollectedUnsafeOperation,
    known_anchors: &BTreeSet<SourceAnchorKey>,
) -> Result<(), CollectedArtifactError> {
    let operation_key = *operation.entity.key();
    operation
        .macro_frames
        .sort_by_key(|frame| *frame.entity.key());
    let mut canonical: Vec<CollectedUnsafeOperationMacroFrame> =
        Vec::with_capacity(operation.macro_frames.len());
    for frame in operation.macro_frames.drain(..) {
        if let Some(previous) = canonical.last()
            && previous.entity.key() == frame.entity.key()
        {
            if previous == &frame {
                continue;
            }
            return Err(
                CollectedArtifactError::ConflictingUnsafeOperationMacroFrame {
                    operation: operation_key,
                    depth: frame.entity.key().depth(),
                },
            );
        }
        canonical.push(frame);
    }
    operation.macro_frames = canonical;

    for (expected_depth, frame) in (0_u32..).zip(&operation.macro_frames) {
        let frame_key = frame.entity.key();
        if frame_key.operation() != &operation_key {
            return Err(
                CollectedArtifactError::UnsafeOperationMacroEndpointMismatch {
                    operation: operation_key,
                    actual: *frame_key.operation(),
                    depth: frame_key.depth(),
                },
            );
        }
        if frame_key.depth() != expected_depth {
            return Err(
                CollectedArtifactError::NonContiguousUnsafeOperationMacroPath {
                    operation: operation_key,
                    expected_depth,
                    actual_depth: frame_key.depth(),
                },
            );
        }
        if frame.entity.display_path().is_empty() {
            return Err(
                CollectedArtifactError::EmptyUnsafeOperationMacroDisplayPath {
                    operation: operation_key,
                    depth: frame_key.depth(),
                },
            );
        }
        if let Some(callsite) = frame.callsite.as_ref()
            && !known_anchors.contains(callsite)
        {
            return Err(
                CollectedArtifactError::DanglingUnsafeOperationSourceAnchor {
                    operation: operation_key,
                    anchor: callsite.clone(),
                    usage: "unsafe-operation macro invocation",
                },
            );
        }
    }
    Ok(())
}

trait ContractRequirementOccurrence {
    fn owner(&self) -> &FunctionKey;
    fn ordinal(&self) -> u32;
    fn normalized_name(&self) -> String;
    fn source_anchor(&self) -> Option<&SourceAnchorKey>;
}

impl ContractRequirementOccurrence for PanicRequirement {
    fn owner(&self) -> &FunctionKey {
        PanicRequirement::owner(self)
    }

    fn ordinal(&self) -> u32 {
        PanicRequirement::ordinal(self)
    }

    fn normalized_name(&self) -> String {
        PanicRequirement::normalized_name(self)
    }

    fn source_anchor(&self) -> Option<&SourceAnchorKey> {
        PanicRequirement::source_anchor(self)
    }
}

impl ContractRequirementOccurrence for SafetyRequirement {
    fn owner(&self) -> &FunctionKey {
        SafetyRequirement::owner(self)
    }

    fn ordinal(&self) -> u32 {
        SafetyRequirement::ordinal(self)
    }

    fn normalized_name(&self) -> String {
        SafetyRequirement::normalized_name(self)
    }

    fn source_anchor(&self) -> Option<&SourceAnchorKey> {
        SafetyRequirement::source_anchor(self)
    }
}

trait CollectedContract {
    type Requirement: ContractRequirementOccurrence;

    fn owner(&self) -> &FunctionKey;
    fn source_anchor(&self) -> Option<&SourceAnchorKey>;
    fn requirements_mut(&mut self) -> &mut Vec<Self::Requirement>;
}

impl CollectedContract for CollectedPanicContract {
    type Requirement = PanicRequirement;

    fn owner(&self) -> &FunctionKey {
        CollectedPanicContract::owner(self)
    }

    fn source_anchor(&self) -> Option<&SourceAnchorKey> {
        CollectedPanicContract::source_anchor(self)
    }

    fn requirements_mut(&mut self) -> &mut Vec<Self::Requirement> {
        &mut self.requirements
    }
}

impl CollectedContract for CollectedSafetyContract {
    type Requirement = SafetyRequirement;

    fn owner(&self) -> &FunctionKey {
        CollectedSafetyContract::owner(self)
    }

    fn source_anchor(&self) -> Option<&SourceAnchorKey> {
        CollectedSafetyContract::source_anchor(self)
    }

    fn requirements_mut(&mut self) -> &mut Vec<Self::Requirement> {
        &mut self.requirements
    }
}

fn canonicalize_contracts<C: CollectedContract>(
    mut contracts: Vec<C>,
    domain: ContractDomain,
    known_callables: &BTreeSet<FunctionKey>,
    known_anchors: &BTreeSet<SourceAnchorKey>,
) -> Result<Vec<C>, CollectedArtifactError> {
    contracts.sort_by_key(|contract| *contract.owner());
    for adjacent in contracts.windows(2) {
        if adjacent[0].owner() == adjacent[1].owner() {
            return Err(CollectedArtifactError::DuplicateContract {
                domain,
                owner: *adjacent[0].owner(),
            });
        }
    }

    for contract in &mut contracts {
        let owner = *contract.owner();
        if !known_callables.contains(&owner) {
            return Err(CollectedArtifactError::MissingContractCallable { domain, owner });
        }
        if let Some(anchor) = contract.source_anchor()
            && !known_anchors.contains(anchor)
        {
            return Err(CollectedArtifactError::DanglingDomainSourceAnchor {
                domain,
                owner,
                ordinal: None,
                anchor: anchor.clone(),
            });
        }

        let requirements = contract.requirements_mut();
        requirements.sort_by_key(ContractRequirementOccurrence::ordinal);
        for (expected_ordinal, requirement) in (0_u32..).zip(requirements) {
            let ordinal = requirement.ordinal();
            if requirement.owner() != &owner {
                return Err(CollectedArtifactError::ContractRequirementOwnerMismatch {
                    domain,
                    expected: owner,
                    actual: *requirement.owner(),
                    ordinal,
                });
            }
            if ordinal != expected_ordinal {
                return Err(CollectedArtifactError::NonContiguousContractOrdinals {
                    domain,
                    owner,
                    expected_ordinal,
                    actual_ordinal: ordinal,
                });
            }
            if requirement.normalized_name().is_empty() {
                return Err(CollectedArtifactError::EmptyContractRequirementName {
                    domain,
                    owner,
                    ordinal,
                });
            }
            if let Some(anchor) = requirement.source_anchor()
                && !known_anchors.contains(anchor)
            {
                return Err(CollectedArtifactError::DanglingDomainSourceAnchor {
                    domain,
                    owner,
                    ordinal: Some(ordinal),
                    anchor: anchor.clone(),
                });
            }
        }
    }
    Ok(contracts)
}

fn canonicalize_source_files(
    mut files: Vec<SourceFileEntity>,
) -> Result<Vec<SourceFileEntity>, CollectedProgramError> {
    files.sort_by(|left, right| left.id().cmp(right.id()));
    let mut canonical: Vec<SourceFileEntity> = Vec::with_capacity(files.len());
    for file in files {
        for (field, value) in [
            ("id", file.id()),
            ("filename", file.filename()),
            ("content hash", file.content_hash()),
        ] {
            if value.is_empty() {
                return Err(CollectedProgramError::EmptySourceFileField {
                    source_file: file.id().to_owned(),
                    field,
                });
            }
        }

        if let Some(previous) = canonical.last()
            && previous.id() == file.id()
        {
            if previous == &file {
                continue;
            }
            return Err(CollectedProgramError::ConflictingSourceFile {
                source_file: file.id().to_owned(),
            });
        }
        canonical.push(file);
    }
    Ok(canonical)
}

fn canonicalize_source_anchors(
    mut anchors: Vec<SourceAnchorEntity>,
    file_lengths: &BTreeMap<String, u64>,
) -> Result<Vec<SourceAnchorEntity>, CollectedProgramError> {
    anchors.sort_by(|left, right| left.anchor().cmp(right.anchor()));
    anchors.dedup_by(|left, right| left.anchor() == right.anchor());

    for entity in &anchors {
        let anchor = entity.anchor();
        let Some(file_len) = file_lengths.get(anchor.file()).copied() else {
            return Err(CollectedProgramError::DanglingSourceFile {
                anchor: anchor.clone(),
            });
        };
        if anchor.byte_start() > anchor.byte_end() || anchor.byte_end() > file_len {
            return Err(CollectedProgramError::InvalidSourceAnchorRange {
                anchor: anchor.clone(),
                file_len,
            });
        }
    }
    Ok(anchors)
}

fn canonicalize_callables(
    mut callables: Vec<CallableEntity>,
) -> Result<Vec<CallableEntity>, CollectedProgramError> {
    callables.sort_by_key(|callable| *callable.key());
    let mut canonical: Vec<CallableEntity> = Vec::with_capacity(callables.len());
    for callable in callables {
        let key = *callable.key();
        if callable.display_path().is_empty() {
            return Err(CollectedProgramError::EmptyCallableDisplayPath { callable: key });
        }
        if callable.namespace_candidates().is_empty() {
            return Err(CollectedProgramError::EmptyNamespaceCandidates { callable: key });
        }
        if callable.namespace_candidates().iter().any(String::is_empty) {
            return Err(CollectedProgramError::EmptyNamespaceCandidate { callable: key });
        }

        if let Some(previous) = canonical.last()
            && previous.key() == callable.key()
        {
            if previous == &callable {
                continue;
            }
            return Err(CollectedProgramError::ConflictingCallable { callable: key });
        }
        canonical.push(callable);
    }
    Ok(canonical)
}

fn canonicalize_bodies(
    mut bodies: Vec<CollectedFunctionBody>,
    known_anchors: &BTreeSet<SourceAnchorKey>,
    known_callables: &BTreeSet<FunctionKey>,
) -> Result<(Vec<CollectedFunctionBody>, Vec<CallableKeyEntity>), CollectedProgramError> {
    bodies.sort_by_key(|body| *body.entity.key());
    for adjacent in bodies.windows(2) {
        if adjacent[0].entity.key() == adjacent[1].entity.key() {
            return Err(CollectedProgramError::DuplicateFunctionBody {
                function: *adjacent[0].entity.key(),
            });
        }
    }

    let mut seen_sites = BTreeSet::new();
    let mut seen_occurrences = BTreeSet::new();
    let mut seen_groups = BTreeSet::new();
    let mut seen_effects = BTreeSet::new();
    let mut callable_keys = BTreeSet::new();

    for body in &mut bodies {
        let owner = validate_body_header(body, known_anchors, known_callables)?;

        body.safety_effect_groups.sort_by_key(|group| *group.key());
        let mut body_groups = BTreeSet::new();
        for group in &body.safety_effect_groups {
            let key = *group.key();
            require_owner(
                owner,
                *key.owner(),
                CollectedOwnerRelation::SafetyEffectGroup,
            )?;
            if !seen_groups.insert(key) {
                return Err(CollectedProgramError::DuplicateSafetyEffectGroup { group: key });
            }
            body_groups.insert(key);
        }

        body.call_sites.sort_by_key(|site| *site.entity.key());
        for site in &mut body.call_sites {
            let site_key = *site.entity.key();
            require_owner(owner, *site_key.owner(), CollectedOwnerRelation::CallSite)?;
            if !seen_sites.insert(site_key) {
                return Err(CollectedProgramError::DuplicateCallSite { site: site_key });
            }
            if site.occurrences.is_empty() {
                return Err(CollectedProgramError::EmptyCallSite { site: site_key });
            }

            site.occurrences
                .sort_by_key(|occurrence| *occurrence.entity.key());
            for occurrence in &mut site.occurrences {
                let occurrence_key = *occurrence.entity.key();
                require_owner(
                    owner,
                    *occurrence_key.owner(),
                    CollectedOwnerRelation::CallOccurrence,
                )?;
                if !seen_occurrences.insert(occurrence_key) {
                    return Err(CollectedProgramError::DuplicateCallOccurrence {
                        occurrence: occurrence_key,
                    });
                }
                canonicalize_occurrence(
                    occurrence,
                    owner,
                    &body_groups,
                    known_anchors,
                    known_callables,
                    &mut callable_keys,
                )?;
            }
        }

        body.effect_sites
            .sort_by_key(|effect| *effect.entity.site());
        for effect in &mut body.effect_sites {
            let effect_key = *effect.entity.site();
            require_owner(
                owner,
                *effect_key.function(),
                CollectedOwnerRelation::EffectSite,
            )?;
            if !seen_effects.insert(effect_key) {
                return Err(CollectedProgramError::DuplicateEffectSite { site: effect_key });
            }
            canonicalize_effect(effect, known_anchors)?;
        }
    }

    Ok((
        bodies,
        callable_keys
            .into_iter()
            .map(CallableKeyEntity::new)
            .collect(),
    ))
}

fn validate_body_header(
    body: &CollectedFunctionBody,
    known_anchors: &BTreeSet<SourceAnchorKey>,
    known_callables: &BTreeSet<FunctionKey>,
) -> Result<FunctionKey, CollectedProgramError> {
    let owner = *body.entity.key();
    if body.entity.display_path().is_empty() {
        return Err(CollectedProgramError::EmptyFunctionDisplayPath { function: owner });
    }
    if matches!(
        body.entity.provenance(),
        FunctionBodyProvenance::ConsumerInstantiation { .. }
    ) && owner.instance().is_none()
    {
        return Err(
            CollectedProgramError::ConsumerInstantiationRequiresExactFunction { function: owner },
        );
    }
    if !known_callables.contains(&owner) {
        return Err(CollectedProgramError::MissingBodyCallable { function: owner });
    }
    if let Some(anchor) = body.source_anchor.as_ref() {
        require_anchor(anchor, "function body", known_anchors)?;
    }
    Ok(owner)
}

fn canonicalize_occurrence(
    occurrence: &mut CollectedCallOccurrence,
    owner: FunctionKey,
    body_groups: &BTreeSet<SafetyEffectGroupKey>,
    known_anchors: &BTreeSet<SourceAnchorKey>,
    known_callables: &BTreeSet<FunctionKey>,
    artifact_callable_keys: &mut BTreeSet<CallableKey>,
) -> Result<(), CollectedProgramError> {
    let key = *occurrence.entity.key();
    if occurrence.entity.applicable_attribution().is_empty() {
        return Err(CollectedProgramError::EmptyCallApplicability { occurrence: key });
    }
    if occurrence.entity.opaque_target_description() == Some("") {
        return Err(CollectedProgramError::EmptyOpaqueTargetDescription { occurrence: key });
    }

    canonicalize_targets(occurrence, known_callables)?;

    occurrence.callable_keys.sort_unstable();
    occurrence.callable_keys.dedup();
    artifact_callable_keys.extend(occurrence.callable_keys.iter().copied());

    occurrence.safety_effect_groups.sort_unstable();
    occurrence.safety_effect_groups.dedup();
    let group = match occurrence.safety_effect_groups.as_slice() {
        [] => return Err(CollectedProgramError::MissingSafetyEffectGroup { occurrence: key }),
        [group] => *group,
        [_, _, ..] => {
            return Err(CollectedProgramError::MultipleSafetyEffectGroups { occurrence: key });
        }
    };
    require_owner(
        owner,
        *group.owner(),
        CollectedOwnerRelation::OccurrenceSafetyEffectGroup,
    )?;
    if !body_groups.contains(&group) {
        return Err(CollectedProgramError::DanglingSafetyEffectGroup {
            occurrence: key,
            group,
        });
    }

    canonicalize_call_source_anchors(occurrence, known_anchors)?;
    canonicalize_call_macro_frames(occurrence, known_anchors)
}

fn canonicalize_targets(
    occurrence: &mut CollectedCallOccurrence,
    known_callables: &BTreeSet<FunctionKey>,
) -> Result<(), CollectedProgramError> {
    let key = *occurrence.entity.key();
    occurrence
        .targets
        .sort_by_key(|target| (target.role, target.callable));
    occurrence.targets.dedup();
    for adjacent in occurrence.targets.windows(2) {
        if adjacent[0].role == adjacent[1].role {
            return Err(CollectedProgramError::DuplicateCallTargetRole {
                occurrence: key,
                role: adjacent[0].role,
            });
        }
    }
    for target in &occurrence.targets {
        if !known_callables.contains(&target.callable) {
            return Err(CollectedProgramError::DanglingCallTarget {
                occurrence: key,
                target: target.callable,
            });
        }
    }

    let has_runtime = occurrence
        .targets
        .iter()
        .any(|target| target.role == CallTargetRole::Runtime);
    let opaque_targets = occurrence
        .targets
        .iter()
        .filter(|target| {
            matches!(
                target.role,
                CallTargetRole::OpaqueTrait | CallTargetRole::OpaqueFunction
            )
        })
        .count();
    let violation = match occurrence.entity.opaque_target_description() {
        None if opaque_targets != 0 => Some(CallTargetShapeError::ConcreteBoundaryHasOpaqueTarget),
        None if !has_runtime => Some(CallTargetShapeError::ConcreteBoundaryMissingRuntime),
        Some(_) if has_runtime => Some(CallTargetShapeError::OpaqueBoundaryHasRuntime),
        Some(_) if opaque_targets > 1 => {
            Some(CallTargetShapeError::OpaqueBoundaryHasMultipleStableTargets)
        }
        None | Some(_) => None,
    };
    if let Some(reason) = violation {
        return Err(CollectedProgramError::InvalidCallTargetShape {
            occurrence: key,
            reason,
        });
    }
    for target in &occurrence.targets {
        let reason = match (target.role, target.callable.instance()) {
            (CallTargetRole::Runtime, None) => {
                Some(CallTargetIdentityShapeError::RuntimeRequiresExactInstance)
            }
            (
                CallTargetRole::SourceContract
                | CallTargetRole::OpaqueTrait
                | CallTargetRole::OpaqueFunction,
                Some(_),
            ) => Some(CallTargetIdentityShapeError::StableTargetRequiresGenericDefinition),
            (CallTargetRole::Runtime, Some(_))
            | (
                CallTargetRole::SourceContract
                | CallTargetRole::OpaqueTrait
                | CallTargetRole::OpaqueFunction,
                None,
            ) => None,
        };
        if let Some(reason) = reason {
            return Err(CollectedProgramError::InvalidCallTargetIdentityShape {
                occurrence: key,
                role: target.role,
                target: target.callable,
                reason,
            });
        }
    }
    Ok(())
}

fn canonicalize_call_source_anchors(
    occurrence: &mut CollectedCallOccurrence,
    known_anchors: &BTreeSet<SourceAnchorKey>,
) -> Result<(), CollectedProgramError> {
    let key = *occurrence.entity.key();
    occurrence
        .source_anchors
        .sort_by(|left, right| (left.role, &left.anchor).cmp(&(right.role, &right.anchor)));
    occurrence.source_anchors.dedup();
    for adjacent in occurrence.source_anchors.windows(2) {
        if adjacent[0].role == adjacent[1].role {
            return Err(CollectedProgramError::DuplicateCallSourceAnchorRole {
                occurrence: key,
                role: adjacent[0].role,
            });
        }
    }
    for anchor in &occurrence.source_anchors {
        require_anchor(&anchor.anchor, "call occurrence", known_anchors)?;
    }
    Ok(())
}

fn canonicalize_call_macro_frames(
    occurrence: &mut CollectedCallOccurrence,
    known_anchors: &BTreeSet<SourceAnchorKey>,
) -> Result<(), CollectedProgramError> {
    let occurrence_key = *occurrence.entity.key();
    occurrence
        .macro_frames
        .sort_by_key(|frame| *frame.entity.key());
    let mut canonical: Vec<CollectedCallMacroFrame> =
        Vec::with_capacity(occurrence.macro_frames.len());
    for frame in occurrence.macro_frames.drain(..) {
        if let Some(previous) = canonical.last()
            && previous.entity.key() == frame.entity.key()
        {
            if previous == &frame {
                continue;
            }
            return Err(CollectedProgramError::ConflictingCallMacroFrame {
                occurrence: occurrence_key,
                depth: frame.entity.key().depth(),
            });
        }
        canonical.push(frame);
    }
    occurrence.macro_frames = canonical;

    for (expected_depth, frame) in (0_u32..).zip(&occurrence.macro_frames) {
        let frame_key = frame.entity.key();
        if frame_key.occurrence() != &occurrence_key {
            return Err(CollectedProgramError::CallMacroEndpointMismatch {
                occurrence: occurrence_key,
                actual: *frame_key.occurrence(),
                depth: frame_key.depth(),
            });
        }
        if frame.entity.display_path().is_empty() {
            return Err(CollectedProgramError::EmptyCallMacroDisplayPath {
                occurrence: occurrence_key,
                depth: frame_key.depth(),
            });
        }
        if frame_key.depth() != expected_depth {
            return Err(CollectedProgramError::NonContiguousCallMacroPath {
                occurrence: occurrence_key,
                expected_depth,
                actual_depth: frame_key.depth(),
            });
        }
        if let Some(anchor) = frame.callsite.as_ref() {
            require_anchor(anchor, "call macro invocation", known_anchors)?;
        }
    }
    Ok(())
}

fn canonicalize_effect(
    effect: &mut CollectedEffectSite,
    known_anchors: &BTreeSet<SourceAnchorKey>,
) -> Result<(), CollectedProgramError> {
    canonicalize_effect_source_anchors(effect, known_anchors)?;
    canonicalize_effect_macro_frames(effect, known_anchors)
}

fn canonicalize_effect_source_anchors(
    effect: &mut CollectedEffectSite,
    known_anchors: &BTreeSet<SourceAnchorKey>,
) -> Result<(), CollectedProgramError> {
    let site = *effect.entity.site();
    effect.source_anchors.sort_by(|left, right| {
        effect_anchor_role_order(left.role)
            .cmp(&effect_anchor_role_order(right.role))
            .then_with(|| left.anchor.cmp(&right.anchor))
    });
    effect.source_anchors.dedup();
    for adjacent in effect.source_anchors.windows(2) {
        if adjacent[0].role == adjacent[1].role {
            return Err(CollectedProgramError::DuplicateEffectSourceAnchorRole {
                site,
                role: adjacent[0].role,
            });
        }
    }
    for anchor in &effect.source_anchors {
        require_anchor(&anchor.anchor, "effect site", known_anchors)?;
    }
    Ok(())
}

const fn effect_anchor_role_order(role: EffectSourceAnchorRole) -> u8 {
    match role {
        EffectSourceAnchorRole::Presentation => 0,
        EffectSourceAnchorRole::Expanded => 1,
    }
}

fn canonicalize_effect_macro_frames(
    effect: &mut CollectedEffectSite,
    known_anchors: &BTreeSet<SourceAnchorKey>,
) -> Result<(), CollectedProgramError> {
    let site = *effect.entity.site();
    effect
        .macro_frames
        .sort_by(|left, right| left.entity.expansion().cmp(right.entity.expansion()));
    let mut canonical: Vec<CollectedEffectMacroFrame> =
        Vec::with_capacity(effect.macro_frames.len());
    for frame in effect.macro_frames.drain(..) {
        if let Some(previous) = canonical.last()
            && previous.entity.expansion() == frame.entity.expansion()
        {
            if previous == &frame {
                continue;
            }
            return Err(CollectedProgramError::ConflictingEffectMacroFrame {
                site,
                depth: frame.entity.expansion().depth(),
            });
        }
        canonical.push(frame);
    }
    effect.macro_frames = canonical;

    for (expected_depth, frame) in (0_u32..).zip(&effect.macro_frames) {
        let frame_key = frame.entity.expansion();
        if frame_key.effect_site() != &site {
            return Err(CollectedProgramError::EffectMacroEndpointMismatch {
                site,
                actual: *frame_key.effect_site(),
                depth: frame_key.depth(),
            });
        }
        if frame.entity.display_path().is_empty() {
            return Err(CollectedProgramError::EmptyEffectMacroDisplayPath {
                site,
                depth: frame_key.depth(),
            });
        }
        if frame_key.depth() != expected_depth {
            return Err(CollectedProgramError::NonContiguousEffectMacroPath {
                site,
                expected_depth,
                actual_depth: frame_key.depth(),
            });
        }
        if let Some(anchor) = frame.callsite.as_ref() {
            require_anchor(anchor, "effect macro invocation", known_anchors)?;
        }
    }
    Ok(())
}

fn require_owner(
    expected: FunctionKey,
    actual: FunctionKey,
    relation: CollectedOwnerRelation,
) -> Result<(), CollectedProgramError> {
    if expected == actual {
        Ok(())
    } else {
        Err(CollectedProgramError::OwnerMismatch {
            relation,
            expected,
            actual,
        })
    }
}

fn require_anchor(
    anchor: &SourceAnchorKey,
    usage: &'static str,
    known_anchors: &BTreeSet<SourceAnchorKey>,
) -> Result<(), CollectedProgramError> {
    if known_anchors.contains(anchor) {
        Ok(())
    } else {
        Err(CollectedProgramError::DanglingSourceAnchor {
            anchor: anchor.clone(),
            usage,
        })
    }
}

#[cfg(test)]
mod tests {
    use reachability::MirBodyLocation;

    use super::{
        CallTargetIdentityShapeError, CallTargetShapeError, CollectedArtifact,
        CollectedArtifactError, CollectedArtifactInput, CollectedCallMacroFrame,
        CollectedCallOccurrence, CollectedCallSite, CollectedCallSourceAnchor, CollectedCallTarget,
        CollectedEffectMacroFrame, CollectedEffectMarkerCandidate, CollectedEffectSite,
        CollectedEffectSourceAnchor, CollectedFunctionBody, CollectedFunctionMarkerCandidate,
        CollectedMarkerCallCandidate, CollectedMarkerOccurrence, CollectedMirAssert,
        CollectedPanicContract, CollectedProgram, CollectedProgramError, CollectedSafetyContract,
        CollectedUnsafeOperation, CollectedUnsafeOperationMacroFrame,
        CollectedUnsafeOperationMarkerCandidate, CollectedUnsafeOperationSourceAnchor,
        ContractDomain,
    };
    use crate::analysis::facts::evaluation::DomainId;
    use crate::analysis::facts::human::EvidenceClaimSelector;
    use crate::analysis::facts::human::markers::{
        CallOccurrenceHasMarkerClaimCandidate, EffectSiteHasMarkerClaimCandidate,
        FunctionHasMarkerClaimCandidate, MarkerClaimEntity, MarkerClaimKey, MarkerOccurrenceEntity,
        MarkerOccurrenceKey, UnsafeOperationHasMarkerClaimCandidate,
    };
    use crate::analysis::facts::panic::contracts::PanicRequirement;
    use crate::analysis::facts::panic::model::MirAssertKind;
    use crate::analysis::facts::program::topology::{
        CallAttributionRole, CallKind, CallMacroExpansionEntity, CallMacroExpansionKey,
        CallOccurrenceEntity, CallOccurrenceKey, CallSiteEntity, CallSiteKey, CallSourceAnchorRole,
        CallTargetRole, CallableEntity, CallableKey, SafetyEffectGroupEntity, SafetyEffectGroupKey,
    };
    use crate::analysis::facts::program::{
        EffectSiteEntity, EffectSiteKey, EffectSourceAnchorRole, FunctionBodyProvenance,
        FunctionEntity, FunctionKey, MacroExpansionEntity, MacroExpansionKey, SourceAnchorEntity,
        SourceAnchorKey, SourceFileEntity,
    };
    use crate::analysis::facts::safety::SafetyRequirement;
    use crate::analysis::facts::safety::operations::{
        SafetyOperationKind, UnsafeOperationEntity, UnsafeOperationKey,
        UnsafeOperationMacroExpansionEntity, UnsafeOperationMacroExpansionKey,
        UnsafeOperationSourceAnchorRole,
    };
    use crate::namespace::{
        StableDefPathHash, StableExpansionHash, StableInstanceHash, StableTypeHash,
    };

    fn definition(value: u128) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid definition hash")
    }

    fn instance(value: u128) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid instance hash")
    }

    fn expansion(value: u128) -> StableExpansionHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid expansion hash")
    }

    fn type_hash(value: u128) -> StableTypeHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid type hash")
    }

    fn function(value: u128) -> FunctionKey {
        FunctionKey::new(definition(value), Some(instance(value + 100)))
    }

    fn generic_function(value: u128) -> FunctionKey {
        FunctionKey::new(definition(value), None)
    }

    fn anchor(start: u64, end: u64) -> SourceAnchorKey {
        SourceAnchorKey::new("src/lib.rs", start, end)
    }

    fn callable(key: FunctionKey, display_path: &str) -> CallableEntity {
        CallableEntity::new(
            key,
            display_path,
            false,
            false,
            true,
            false,
            vec![display_path.to_owned()],
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one complete fixture keeps every core relationship internally consistent"
    )]
    fn valid_inputs() -> (
        Vec<SourceFileEntity>,
        Vec<SourceAnchorEntity>,
        Vec<CallableEntity>,
        Vec<CollectedFunctionBody>,
    ) {
        let owner = function(1);
        let target = function(2);
        let source_target = generic_function(2);
        let other_owner = function(3);
        let occurrence = CallOccurrenceKey::new(owner, 9);
        let effect = EffectSiteKey::from_mir(
            owner,
            MirBodyLocation {
                basic_block: 3,
                statement_index: 4,
            },
        )
        .unwrap();

        let call_frames = vec![
            CollectedCallMacroFrame::new(
                CallMacroExpansionEntity::new(
                    CallMacroExpansionKey::new(occurrence, 1),
                    expansion(1_031),
                    definition(31),
                    "inner!",
                ),
                Some(anchor(40, 45)),
            ),
            CollectedCallMacroFrame::new(
                CallMacroExpansionEntity::new(
                    CallMacroExpansionKey::new(occurrence, 0),
                    expansion(1_030),
                    definition(30),
                    "outer!",
                ),
                Some(anchor(30, 35)),
            ),
        ];
        let effect_frames = vec![
            CollectedEffectMacroFrame::new(
                MacroExpansionEntity::new(
                    MacroExpansionKey::new(effect, 1),
                    expansion(1_041),
                    definition(41),
                    "assert_inner!",
                ),
                Some(anchor(60, 65)),
            ),
            CollectedEffectMacroFrame::new(
                MacroExpansionEntity::new(
                    MacroExpansionKey::new(effect, 0),
                    expansion(1_040),
                    definition(40),
                    "assert_outer!",
                ),
                Some(anchor(50, 55)),
            ),
        ];

        let call = CollectedCallOccurrence::new(
            CallOccurrenceEntity::new(
                occurrence,
                CallKind::DirectCall,
                vec![CallAttributionRole::CallSite],
                false,
                false,
                None,
            ),
            vec![
                CollectedCallTarget::new(CallTargetRole::SourceContract, source_target),
                CollectedCallTarget::new(CallTargetRole::Runtime, target),
            ],
            vec![
                CallableKey::FnPointer(type_hash(71)),
                CallableKey::FnPointer(type_hash(70)),
                CallableKey::FnPointer(type_hash(71)),
            ],
            vec![SafetyEffectGroupKey::new(owner, 7)],
            vec![
                CollectedCallSourceAnchor::new(CallSourceAnchorRole::Expanded, anchor(20, 25)),
                CollectedCallSourceAnchor::new(CallSourceAnchorRole::Presentation, anchor(10, 15)),
            ],
            call_frames,
        );
        let effect = CollectedEffectSite::new(
            EffectSiteEntity::new(effect),
            vec![
                CollectedEffectSourceAnchor::new(EffectSourceAnchorRole::Expanded, anchor(80, 85)),
                CollectedEffectSourceAnchor::new(
                    EffectSourceAnchorRole::Presentation,
                    anchor(70, 75),
                ),
            ],
            effect_frames,
        );
        let body = CollectedFunctionBody::new(
            FunctionEntity::new(
                owner,
                "local::body",
                FunctionBodyProvenance::DefiningArtifact,
            ),
            Some(anchor(0, 5)),
            vec![CollectedCallSite::new(
                CallSiteEntity::new(CallSiteKey::new(owner, 2)),
                vec![call],
            )],
            vec![SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                owner, 7,
            ))],
            vec![effect],
        );
        let other_body = CollectedFunctionBody::new(
            FunctionEntity::new(
                other_owner,
                "local::other_body",
                FunctionBodyProvenance::DefiningArtifact,
            ),
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let anchors = [
            anchor(0, 5),
            anchor(10, 15),
            anchor(20, 25),
            anchor(30, 35),
            anchor(40, 45),
            anchor(50, 55),
            anchor(60, 65),
            anchor(70, 75),
            anchor(80, 85),
        ]
        .into_iter()
        .map(SourceAnchorEntity::new)
        .collect();

        (
            vec![
                SourceFileEntity::new(
                    "src/other.rs",
                    "src/other.rs",
                    "other-verified-content-hash",
                    10,
                ),
                SourceFileEntity::new("src/lib.rs", "src/lib.rs", "verified-content-hash", 100),
            ],
            anchors,
            vec![
                callable(target, "dependency::target"),
                callable(source_target, "dependency::target"),
                callable(owner, "local::body"),
                callable(other_owner, "local::other_body"),
            ],
            vec![body, other_body],
        )
    }

    #[test]
    fn collection_is_canonical_and_independent_of_input_order() {
        let (files, anchors, callables, bodies) = valid_inputs();
        let expected = CollectedProgram::try_new(
            files.clone(),
            anchors.clone(),
            callables.clone(),
            bodies.clone(),
        )
        .unwrap();

        let mut files_reversed = files;
        files_reversed.reverse();
        let mut anchors_reversed = anchors;
        anchors_reversed.reverse();
        anchors_reversed.push(anchors_reversed[0].clone());
        let mut callables_reversed = callables;
        callables_reversed.reverse();
        callables_reversed.push(callables_reversed[0].clone());
        let mut bodies_reversed = bodies;
        bodies_reversed.reverse();
        let body = bodies_reversed
            .iter_mut()
            .find(|body| body.entity().key() == &function(1))
            .unwrap();
        body.call_sites_mut_for_test().reverse();
        body.safety_effect_groups_mut_for_test().reverse();
        body.effect_sites_mut_for_test().reverse();
        let occurrence = &mut body.call_sites_mut_for_test()[0].occurrences_mut_for_test()[0];
        occurrence.targets_mut_for_test().reverse();
        let duplicate_target = occurrence.targets_mut_for_test()[0].clone();
        occurrence.targets_mut_for_test().push(duplicate_target);
        occurrence.callable_keys_mut_for_test().reverse();
        occurrence.source_anchors_mut_for_test().reverse();
        occurrence.macro_frames_mut_for_test().reverse();
        let effect = &mut body.effect_sites_mut_for_test()[0];
        effect.source_anchors_mut_for_test().reverse();
        effect.macro_frames_mut_for_test().reverse();

        let actual = CollectedProgram::try_new(
            files_reversed,
            anchors_reversed,
            callables_reversed,
            bodies_reversed,
        )
        .unwrap();
        assert_eq!(actual, expected);

        let artifact = CollectedArtifact::new(actual);
        let program = artifact.program();
        assert_eq!(program.source_files().len(), 2);
        assert_eq!(program.source_anchors().len(), 9);
        assert_eq!(program.callables().len(), 4);
        assert_eq!(program.callable_keys().len(), 2);
        assert_eq!(program.bodies().len(), 2);

        let body = &program.bodies()[0];
        assert_eq!(body.entity().key(), &function(1));
        assert_eq!(body.source_anchor(), Some(&anchor(0, 5)));
        assert_eq!(body.call_sites().len(), 1);
        assert_eq!(body.safety_effect_groups().len(), 1);
        assert_eq!(body.effect_sites().len(), 1);

        let occurrence = &body.call_sites()[0].occurrences()[0];
        assert_eq!(occurrence.callable_keys().len(), 2);
        assert_eq!(occurrence.safety_effect_group().local_id(), 7);
        assert_eq!(occurrence.macro_frames()[0].entity().key().depth(), 0);
        assert_eq!(occurrence.macro_frames()[1].entity().key().depth(), 1);
        assert_eq!(
            body.effect_sites()[0].macro_frames()[0]
                .entity()
                .expansion()
                .depth(),
            0
        );
    }

    #[test]
    fn rejects_conflicting_callable_metadata() {
        let (files, anchors, mut callables, bodies) = valid_inputs();
        let key = function(2);
        callables.push(CallableEntity::new(
            key,
            "dependency::other_name",
            false,
            false,
            true,
            false,
            vec![String::from("dependency::other_name")],
        ));

        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::ConflictingCallable { callable }) if callable == key
        ));
    }

    #[test]
    fn rejects_generic_consumer_instantiation_bodies() {
        let (files, anchors, mut callables, mut bodies) = valid_inputs();
        let generic = FunctionKey::new(definition(50), None);
        callables.push(callable(generic, "dependency::generic"));
        bodies.push(CollectedFunctionBody::new(
            FunctionEntity::new(
                generic,
                "dependency::generic",
                FunctionBodyProvenance::ConsumerInstantiation {
                    consumer_stable_crate_id: 7,
                },
            ),
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ));

        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::ConsumerInstantiationRequiresExactFunction {
                function,
            }) if function == generic
        ));
    }

    #[test]
    fn rejects_dangling_relationships_and_wrong_owners() {
        let (files, mut anchors, callables, mut bodies) = valid_inputs();
        anchors.retain(|entity| entity.anchor() != &anchor(20, 25));
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies.clone()),
            Err(CollectedProgramError::DanglingSourceAnchor { anchor: missing, .. })
                if missing == anchor(20, 25)
        ));

        let wrong_owner = function(99);
        let invalid_site = CollectedCallSite::new(
            CallSiteEntity::new(CallSiteKey::new(wrong_owner, 3)),
            Vec::new(),
        );
        bodies[0].call_sites_mut_for_test().push(invalid_site);
        let (files, anchors, callables, _) = valid_inputs();
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::OwnerMismatch { expected, actual, .. })
                if expected == function(1) && actual == wrong_owner
        ));
    }

    #[test]
    fn rejects_invalid_target_cardinality_and_safety_group_count() {
        let (files, anchors, callables, mut bodies) = valid_inputs();
        let occurrence = bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test();
        occurrence[0]
            .targets_mut_for_test()
            .push(CollectedCallTarget::new(
                CallTargetRole::Runtime,
                function(1),
            ));
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::DuplicateCallTargetRole {
                role: CallTargetRole::Runtime,
                ..
            })
        ));

        let (files, anchors, callables, mut bodies) = valid_inputs();
        bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test()[0]
            .safety_effect_groups_mut_for_test()
            .clear();
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::MissingSafetyEffectGroup { .. })
        ));

        let (files, anchors, callables, mut bodies) = valid_inputs();
        bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test()[0]
            .safety_effect_groups_mut_for_test()
            .push(SafetyEffectGroupKey::new(function(1), 8));
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::MultipleSafetyEffectGroups { .. })
        ));
    }

    #[test]
    fn rejects_invalid_concrete_and_opaque_target_shapes() {
        let (files, anchors, callables, mut bodies) = valid_inputs();
        bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test()[0]
            .targets_mut_for_test()
            .retain(|target| target.role() != CallTargetRole::Runtime);
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::InvalidCallTargetShape {
                reason: CallTargetShapeError::ConcreteBoundaryMissingRuntime,
                ..
            })
        ));

        let (files, anchors, callables, mut bodies) = valid_inputs();
        let occurrence = &mut bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test()[0];
        occurrence.replace_entity_for_test(CallOccurrenceEntity::new(
            CallOccurrenceKey::new(function(1), 9),
            CallKind::IndirectCall,
            vec![CallAttributionRole::CallSite],
            false,
            false,
            Some(String::from("opaque function-pointer boundary")),
        ));
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::InvalidCallTargetShape {
                reason: CallTargetShapeError::OpaqueBoundaryHasRuntime,
                ..
            })
        ));

        let (files, anchors, callables, mut bodies) = valid_inputs();
        let occurrence = &mut bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test()[0];
        occurrence.replace_entity_for_test(CallOccurrenceEntity::new(
            CallOccurrenceKey::new(function(1), 9),
            CallKind::IndirectCall,
            vec![CallAttributionRole::CallSite],
            false,
            false,
            Some(String::from("opaque dynamic boundary")),
        ));
        occurrence.targets_mut_for_test().clear();
        occurrence.targets_mut_for_test().extend([
            CollectedCallTarget::new(CallTargetRole::OpaqueTrait, generic_function(2)),
            CollectedCallTarget::new(CallTargetRole::OpaqueFunction, generic_function(2)),
        ]);
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::InvalidCallTargetShape {
                reason: CallTargetShapeError::OpaqueBoundaryHasMultipleStableTargets,
                ..
            })
        ));
    }

    #[test]
    fn rejects_call_target_keys_from_the_wrong_generation_shape() {
        let (files, anchors, callables, mut bodies) = valid_inputs();
        let occurrence = &mut bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test()[0];
        occurrence.targets_mut_for_test().clear();
        occurrence.targets_mut_for_test().extend([
            CollectedCallTarget::new(CallTargetRole::Runtime, generic_function(2)),
            CollectedCallTarget::new(CallTargetRole::SourceContract, generic_function(2)),
        ]);
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::InvalidCallTargetIdentityShape {
                role: CallTargetRole::Runtime,
                reason: CallTargetIdentityShapeError::RuntimeRequiresExactInstance,
                ..
            })
        ));

        let (files, anchors, callables, mut bodies) = valid_inputs();
        let occurrence = &mut bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test()[0];
        occurrence.targets_mut_for_test().clear();
        occurrence.targets_mut_for_test().extend([
            CollectedCallTarget::new(CallTargetRole::Runtime, function(2)),
            CollectedCallTarget::new(CallTargetRole::SourceContract, function(2)),
        ]);
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::InvalidCallTargetIdentityShape {
                role: CallTargetRole::SourceContract,
                reason: CallTargetIdentityShapeError::StableTargetRequiresGenericDefinition,
                ..
            })
        ));

        for role in [CallTargetRole::OpaqueTrait, CallTargetRole::OpaqueFunction] {
            let (files, anchors, callables, mut bodies) = valid_inputs();
            let occurrence =
                &mut bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test()[0];
            occurrence.replace_entity_for_test(CallOccurrenceEntity::new(
                CallOccurrenceKey::new(function(1), 9),
                CallKind::IndirectCall,
                vec![CallAttributionRole::CallSite],
                false,
                false,
                Some(String::from("opaque boundary")),
            ));
            occurrence.targets_mut_for_test().clear();
            occurrence
                .targets_mut_for_test()
                .push(CollectedCallTarget::new(role, function(2)));
            assert!(matches!(
                CollectedProgram::try_new(files, anchors, callables, bodies),
                Err(CollectedProgramError::InvalidCallTargetIdentityShape {
                    role: actual_role,
                    reason: CallTargetIdentityShapeError::StableTargetRequiresGenericDefinition,
                    ..
                }) if actual_role == role
            ));
        }
    }

    #[test]
    fn rejects_dangling_targets_and_safety_groups() {
        let (files, anchors, callables, mut bodies) = valid_inputs();
        let occurrence = &mut bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test()[0];
        occurrence.targets_mut_for_test().clear();
        occurrence
            .targets_mut_for_test()
            .push(CollectedCallTarget::new(
                CallTargetRole::Runtime,
                function(99),
            ));
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::DanglingCallTarget { target, .. })
                if target == function(99)
        ));

        let (files, anchors, callables, mut bodies) = valid_inputs();
        let groups = bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test()[0]
            .safety_effect_groups_mut_for_test();
        groups.clear();
        groups.push(SafetyEffectGroupKey::new(function(1), 99));
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::DanglingSafetyEffectGroup { group, .. })
                if group == SafetyEffectGroupKey::new(function(1), 99)
        ));
    }

    #[test]
    fn rejects_duplicate_body_site_occurrence_group_and_effect_keys() {
        let (files, anchors, callables, mut bodies) = valid_inputs();
        bodies.push(bodies[0].clone());
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::DuplicateFunctionBody { .. })
        ));

        let (files, anchors, callables, mut bodies) = valid_inputs();
        let duplicate = bodies[0].call_sites_mut_for_test()[0].clone();
        bodies[0].call_sites_mut_for_test().push(duplicate);
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::DuplicateCallSite { .. })
        ));

        let (files, anchors, callables, mut bodies) = valid_inputs();
        let occurrences = bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test();
        occurrences.push(occurrences[0].clone());
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::DuplicateCallOccurrence { .. })
        ));

        let (files, anchors, callables, mut bodies) = valid_inputs();
        let duplicate = bodies[0].safety_effect_groups_mut_for_test()[0].clone();
        bodies[0]
            .safety_effect_groups_mut_for_test()
            .push(duplicate);
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::DuplicateSafetyEffectGroup { .. })
        ));

        let (files, anchors, callables, mut bodies) = valid_inputs();
        let duplicate = bodies[0].effect_sites_mut_for_test()[0].clone();
        bodies[0].effect_sites_mut_for_test().push(duplicate);
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::DuplicateEffectSite { .. })
        ));
    }

    #[test]
    fn rejects_call_sites_without_occurrences() {
        let (files, anchors, callables, mut bodies) = valid_inputs();
        let empty_site = CallSiteKey::new(function(1), 99);
        bodies[0]
            .call_sites_mut_for_test()
            .push(CollectedCallSite::new(
                CallSiteEntity::new(empty_site),
                Vec::new(),
            ));

        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::EmptyCallSite { site }) if site == empty_site
        ));
    }

    #[test]
    fn verifies_anchor_files_and_byte_ranges() {
        let (mut files, anchors, callables, bodies) = valid_inputs();
        files.retain(|file| file.id() != "src/lib.rs");
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::DanglingSourceFile { .. })
        ));

        let (files, mut anchors, callables, bodies) = valid_inputs();
        anchors.push(SourceAnchorEntity::new(anchor(90, 101)));
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::InvalidSourceAnchorRange { file_len: 100, .. })
        ));
    }

    #[test]
    fn rejects_empty_applicability_and_namespace_candidates() {
        let (files, anchors, callables, mut bodies) = valid_inputs();
        bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test()[0]
            .replace_entity_for_test(CallOccurrenceEntity::new(
                CallOccurrenceKey::new(function(1), 9),
                CallKind::DirectCall,
                Vec::new(),
                false,
                false,
                None,
            ));
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::EmptyCallApplicability { .. })
        ));

        let (files, anchors, mut callables, bodies) = valid_inputs();
        callables[0] = CallableEntity::new(
            function(2),
            "dependency::target",
            false,
            false,
            true,
            false,
            Vec::new(),
        );
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::EmptyNamespaceCandidates { .. })
        ));
    }

    #[test]
    fn rejects_noncontiguous_or_foreign_macro_paths() {
        let (files, anchors, callables, mut bodies) = valid_inputs();
        let occurrence = CallOccurrenceKey::new(function(1), 9);
        bodies[0].call_sites_mut_for_test()[0].occurrences_mut_for_test()[0]
            .macro_frames_mut_for_test()[1] = CollectedCallMacroFrame::new(
            CallMacroExpansionEntity::new(
                CallMacroExpansionKey::new(occurrence, 3),
                expansion(1_030),
                definition(30),
                "outer!",
            ),
            Some(anchor(30, 35)),
        );
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::NonContiguousCallMacroPath { .. })
        ));

        let (files, anchors, callables, mut bodies) = valid_inputs();
        let foreign_effect = EffectSiteKey::from_mir(
            function(99),
            MirBodyLocation {
                basic_block: 3,
                statement_index: 4,
            },
        )
        .unwrap();
        bodies[0].effect_sites_mut_for_test()[0].macro_frames_mut_for_test()[0] =
            CollectedEffectMacroFrame::new(
                MacroExpansionEntity::new(
                    MacroExpansionKey::new(foreign_effect, 0),
                    expansion(1_040),
                    definition(40),
                    "assert_outer!",
                ),
                Some(anchor(50, 55)),
            );
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::EffectMacroEndpointMismatch { .. })
        ));

        let (files, anchors, callables, mut bodies) = valid_inputs();
        let site = *bodies[0].effect_sites_mut_for_test()[0].entity().site();
        bodies[0].effect_sites_mut_for_test()[0].macro_frames_mut_for_test()[1] =
            CollectedEffectMacroFrame::new(
                MacroExpansionEntity::new(
                    MacroExpansionKey::new(site, 4),
                    expansion(1_041),
                    definition(41),
                    "assert_inner!",
                ),
                Some(anchor(60, 65)),
            );
        assert!(matches!(
            CollectedProgram::try_new(files, anchors, callables, bodies),
            Err(CollectedProgramError::NonContiguousEffectMacroPath { .. })
        ));
    }

    fn program() -> CollectedProgram {
        let (files, anchors, callables, bodies) = valid_inputs();
        CollectedProgram::try_new(files, anchors, callables, bodies).unwrap()
    }

    fn artifact(
        unsafe_operations: Vec<CollectedUnsafeOperation>,
        panic_contracts: Vec<CollectedPanicContract>,
        safety_contracts: Vec<CollectedSafetyContract>,
    ) -> Result<CollectedArtifact, CollectedArtifactError> {
        CollectedArtifact::try_new(CollectedArtifactInput {
            program: program(),
            unsafe_operations,
            panic_contracts,
            safety_contracts,
            mir_asserts: Vec::new(),
            marker_occurrences: Vec::new(),
        })
    }

    fn unsafe_operation(owner: FunctionKey, local_id: u32) -> CollectedUnsafeOperation {
        let key = UnsafeOperationKey::new(owner, local_id);
        CollectedUnsafeOperation::new(
            UnsafeOperationEntity::new(key, SafetyOperationKind::DerefRawPointer),
            SafetyEffectGroupKey::new(owner, 7),
            vec![
                CollectedUnsafeOperationSourceAnchor::new(
                    UnsafeOperationSourceAnchorRole::Expanded,
                    anchor(20, 25),
                ),
                CollectedUnsafeOperationSourceAnchor::new(
                    UnsafeOperationSourceAnchorRole::Presentation,
                    anchor(10, 15),
                ),
            ],
            vec![
                CollectedUnsafeOperationMacroFrame::new(
                    UnsafeOperationMacroExpansionEntity::new(
                        UnsafeOperationMacroExpansionKey::new(key, 1),
                        expansion(1_081),
                        definition(81),
                        "inner_unsafe!",
                    ),
                    Some(anchor(40, 45)),
                ),
                CollectedUnsafeOperationMacroFrame::new(
                    UnsafeOperationMacroExpansionEntity::new(
                        UnsafeOperationMacroExpansionKey::new(key, 0),
                        expansion(1_080),
                        definition(80),
                        "outer_unsafe!",
                    ),
                    Some(anchor(30, 35)),
                ),
            ],
        )
    }

    fn panic_contract(owner: FunctionKey) -> CollectedPanicContract {
        CollectedPanicContract::new(
            owner,
            Some(anchor(0, 5)),
            vec![
                PanicRequirement::new(owner, 1, "invalid", "the input is invalid", None),
                PanicRequirement::new(
                    owner,
                    0,
                    "empty",
                    "the input is empty",
                    Some(anchor(10, 15)),
                ),
            ],
        )
    }

    fn safety_contract(owner: FunctionKey) -> CollectedSafetyContract {
        CollectedSafetyContract::new(
            owner,
            None,
            vec![SafetyRequirement::new(
                owner,
                0,
                "valid pointer",
                "the pointer is valid",
                Some(anchor(20, 25)),
            )],
        )
    }

    #[test]
    fn artifact_domains_are_canonical_and_preserve_occurrences() {
        let owner = function(1);
        let bodyless = function(2);
        let mut operations = vec![unsafe_operation(owner, 1), unsafe_operation(owner, 0)];
        let mut panic_contracts = vec![panic_contract(bodyless), panic_contract(owner)];
        let safety_contracts = vec![safety_contract(bodyless)];

        let expected = artifact(
            operations.clone(),
            panic_contracts.clone(),
            safety_contracts.clone(),
        )
        .unwrap();
        operations.reverse();
        panic_contracts.reverse();
        let actual = artifact(operations, panic_contracts, safety_contracts).unwrap();

        assert_eq!(actual, expected);
        assert_eq!(actual.unsafe_operations().len(), 2);
        assert_eq!(actual.unsafe_operations()[0].entity().key().local_id(), 0);
        assert_eq!(actual.unsafe_operations()[0].source_anchors().len(), 2);
        assert_eq!(
            actual.unsafe_operations()[0].macro_frames()[0]
                .entity()
                .key()
                .depth(),
            0
        );
        assert_eq!(actual.panic_contracts().len(), 2);
        assert_eq!(actual.panic_contracts()[0].requirements()[0].ordinal(), 0);
        assert_eq!(actual.safety_contracts()[0].owner(), &bodyless);
    }

    #[test]
    fn mir_asserts_require_one_exact_known_effect_site() {
        let known_site = EffectSiteKey::from_mir(
            function(1),
            MirBodyLocation {
                basic_block: 3,
                statement_index: 4,
            },
        )
        .unwrap();
        let duplicate = CollectedArtifact::try_new(CollectedArtifactInput {
            program: program(),
            unsafe_operations: Vec::new(),
            panic_contracts: Vec::new(),
            safety_contracts: Vec::new(),
            mir_asserts: vec![
                CollectedMirAssert::new(known_site, MirAssertKind::BoundsCheck),
                CollectedMirAssert::new(known_site, MirAssertKind::DivisionByZero),
            ],
            marker_occurrences: Vec::new(),
        });
        assert!(matches!(
            duplicate,
            Err(CollectedArtifactError::DuplicateMirAssert { site }) if site == known_site
        ));

        let missing_site = EffectSiteKey::from_mir(
            function(1),
            MirBodyLocation {
                basic_block: 30,
                statement_index: 40,
            },
        )
        .unwrap();
        let missing = CollectedArtifact::try_new(CollectedArtifactInput {
            program: program(),
            unsafe_operations: Vec::new(),
            panic_contracts: Vec::new(),
            safety_contracts: Vec::new(),
            mir_asserts: vec![CollectedMirAssert::new(
                missing_site,
                MirAssertKind::DivisionByZero,
            )],
            marker_occurrences: Vec::new(),
        });
        assert!(matches!(
            missing,
            Err(CollectedArtifactError::MissingMirAssertEffectSite { site })
                if site == missing_site
        ));
    }

    #[test]
    fn rejects_unsafe_operation_owner_group_and_local_id_errors() {
        let owner = function(1);
        let foreign = function(99);
        let operation = unsafe_operation(foreign, 0);
        assert!(matches!(
            artifact(vec![operation], Vec::new(), Vec::new()),
            Err(CollectedArtifactError::MissingUnsafeOperationBody { owner: actual })
                if actual == foreign
        ));

        let mut operation = unsafe_operation(owner, 0);
        operation.replace_safety_effect_group_for_test(SafetyEffectGroupKey::new(owner, 99));
        assert!(matches!(
            artifact(vec![operation], Vec::new(), Vec::new()),
            Err(CollectedArtifactError::DanglingUnsafeOperationSafetyEffectGroup { .. })
        ));

        let mut operation = unsafe_operation(owner, 0);
        operation.replace_safety_effect_group_for_test(SafetyEffectGroupKey::new(function(3), 7));
        assert!(matches!(
            artifact(vec![operation], Vec::new(), Vec::new()),
            Err(CollectedArtifactError::UnsafeOperationSafetyEffectGroupOwnerMismatch { .. })
        ));

        assert!(matches!(
            artifact(vec![unsafe_operation(owner, 1)], Vec::new(), Vec::new()),
            Err(CollectedArtifactError::NonContiguousUnsafeOperationIds {
                expected_local_id: 0,
                actual_local_id: 1,
                ..
            })
        ));
    }

    #[test]
    fn unsafe_local_and_group_ids_are_scoped_by_the_exact_body_key() {
        let owner = function(1);
        let second_owner = FunctionKey::new(definition(1), Some(instance(999)));
        let (files, anchors, mut callables, mut bodies) = valid_inputs();
        callables.push(callable(second_owner, "local::body::second_instance"));
        bodies.push(CollectedFunctionBody::new(
            FunctionEntity::new(
                second_owner,
                "local::body::second_instance",
                FunctionBodyProvenance::DefiningArtifact,
            ),
            None,
            Vec::new(),
            vec![SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                second_owner,
                7,
            ))],
            Vec::new(),
        ));
        let program = CollectedProgram::try_new(files, anchors, callables, bodies).unwrap();

        let artifact = CollectedArtifact::try_new(CollectedArtifactInput {
            program,
            unsafe_operations: vec![
                unsafe_operation(second_owner, 0),
                unsafe_operation(owner, 0),
            ],
            panic_contracts: Vec::new(),
            safety_contracts: Vec::new(),
            mir_asserts: Vec::new(),
            marker_occurrences: Vec::new(),
        })
        .unwrap();

        assert_eq!(artifact.unsafe_operations().len(), 2);
        assert!(
            artifact
                .unsafe_operations()
                .iter()
                .all(|operation| operation.entity().key().local_id() == 0)
        );
        assert!(
            artifact
                .unsafe_operations()
                .iter()
                .all(|operation| operation.safety_effect_group().local_id() == 7)
        );
    }

    #[test]
    fn rejects_duplicate_operation_and_contract_occurrence_keys() {
        let owner = function(1);
        let operation = unsafe_operation(owner, 0);
        assert!(matches!(
            artifact(vec![operation.clone(), operation], Vec::new(), Vec::new(),),
            Err(CollectedArtifactError::DuplicateUnsafeOperation { .. })
        ));

        let contract = panic_contract(owner);
        assert!(matches!(
            artifact(Vec::new(), vec![contract.clone(), contract], Vec::new(),),
            Err(CollectedArtifactError::DuplicateContract {
                domain: ContractDomain::Panic,
                ..
            })
        ));
    }

    #[test]
    fn rejects_unsafe_operation_anchor_and_macro_errors() {
        let owner = function(1);
        let mut operation = unsafe_operation(owner, 0);
        operation
            .source_anchors_mut_for_test()
            .push(CollectedUnsafeOperationSourceAnchor::new(
                UnsafeOperationSourceAnchorRole::Presentation,
                anchor(70, 75),
            ));
        assert!(matches!(
            artifact(vec![operation], Vec::new(), Vec::new()),
            Err(CollectedArtifactError::DuplicateUnsafeOperationSourceAnchorRole { .. })
        ));

        let mut operation = unsafe_operation(owner, 0);
        operation.source_anchors_mut_for_test()[0] = CollectedUnsafeOperationSourceAnchor::new(
            UnsafeOperationSourceAnchorRole::Expanded,
            anchor(95, 99),
        );
        assert!(matches!(
            artifact(vec![operation], Vec::new(), Vec::new()),
            Err(CollectedArtifactError::DanglingUnsafeOperationSourceAnchor { .. })
        ));

        let mut operation = unsafe_operation(owner, 0);
        let foreign_key = UnsafeOperationKey::new(function(3), 0);
        operation.macro_frames_mut_for_test()[0] = CollectedUnsafeOperationMacroFrame::new(
            UnsafeOperationMacroExpansionEntity::new(
                UnsafeOperationMacroExpansionKey::new(foreign_key, 0),
                expansion(1_080),
                definition(80),
                "foreign!",
            ),
            None,
        );
        assert!(matches!(
            artifact(vec![operation], Vec::new(), Vec::new()),
            Err(CollectedArtifactError::UnsafeOperationMacroEndpointMismatch { .. })
        ));

        let mut operation = unsafe_operation(owner, 0);
        let key = *operation.entity().key();
        operation.macro_frames_mut_for_test()[1] = CollectedUnsafeOperationMacroFrame::new(
            UnsafeOperationMacroExpansionEntity::new(
                UnsafeOperationMacroExpansionKey::new(key, 4),
                expansion(1_081),
                definition(81),
                "inner!",
            ),
            None,
        );
        assert!(matches!(
            artifact(vec![operation], Vec::new(), Vec::new()),
            Err(CollectedArtifactError::NonContiguousUnsafeOperationMacroPath { .. })
        ));
    }

    #[test]
    fn rejects_contract_owner_anchor_and_ordinal_errors() {
        let owner = function(1);
        let foreign = function(99);
        assert!(matches!(
            artifact(Vec::new(), vec![panic_contract(foreign)], Vec::new()),
            Err(CollectedArtifactError::MissingContractCallable {
                domain: ContractDomain::Panic,
                owner: actual,
            }) if actual == foreign
        ));

        let contract = CollectedSafetyContract::new(
            owner,
            None,
            vec![SafetyRequirement::new(
                function(2),
                0,
                "valid",
                "valid",
                None,
            )],
        );
        assert!(matches!(
            artifact(Vec::new(), Vec::new(), vec![contract]),
            Err(CollectedArtifactError::ContractRequirementOwnerMismatch {
                domain: ContractDomain::Safety,
                expected,
                actual,
                ordinal: 0,
            }) if expected == owner && actual == function(2)
        ));

        let contract = CollectedPanicContract::new(owner, Some(anchor(95, 99)), Vec::new());
        assert!(matches!(
            artifact(Vec::new(), vec![contract], Vec::new()),
            Err(CollectedArtifactError::DanglingDomainSourceAnchor {
                domain: ContractDomain::Panic,
                ..
            })
        ));

        let contract = CollectedPanicContract::new(
            owner,
            None,
            vec![PanicRequirement::new(owner, 1, "late", "late", None)],
        );
        assert!(matches!(
            artifact(Vec::new(), vec![contract], Vec::new()),
            Err(CollectedArtifactError::NonContiguousContractOrdinals {
                domain: ContractDomain::Panic,
                expected_ordinal: 0,
                actual_ordinal: 1,
                ..
            })
        ));

        let contract = CollectedPanicContract::new(
            owner,
            None,
            vec![PanicRequirement::new(
                owner,
                0,
                "named",
                "condition",
                Some(anchor(95, 99)),
            )],
        );
        assert!(matches!(
            artifact(Vec::new(), vec![contract], Vec::new()),
            Err(CollectedArtifactError::DanglingDomainSourceAnchor {
                domain: ContractDomain::Panic,
                ordinal: Some(0),
                ..
            })
        ));
    }

    fn marker_claim(
        occurrence: &MarkerOccurrenceKey,
        domain: &str,
        ordinal: u32,
        rationale: &str,
    ) -> MarkerClaimEntity {
        MarkerClaimEntity::new(
            MarkerClaimKey::new(occurrence.clone(), DomainId::new(domain).unwrap(), ordinal),
            EvidenceClaimSelector::Unnamed,
            rationale,
        )
    }

    fn marker_occurrence(
        source_anchor: SourceAnchorKey,
        origin: Option<StableExpansionHash>,
        expansion_path: Vec<StableExpansionHash>,
    ) -> CollectedMarkerOccurrence {
        let key = MarkerOccurrenceKey::new(source_anchor, origin);
        let panic_claim = marker_claim(&key, "sniff-test.panic", 0, "panic invariant");
        let safety_claim = marker_claim(&key, "sniff-test.safety", 0, "safety invariant");
        CollectedMarkerOccurrence::new(
            MarkerOccurrenceEntity::new(key.clone(), expansion_path),
            vec![safety_claim.clone(), panic_claim.clone()],
            vec![
                CollectedFunctionMarkerCandidate::new(
                    function(3),
                    panic_claim.key().clone(),
                    FunctionHasMarkerClaimCandidate::new(false, true),
                ),
                CollectedFunctionMarkerCandidate::new(
                    function(1),
                    panic_claim.key().clone(),
                    FunctionHasMarkerClaimCandidate::new(true, true),
                ),
            ],
            vec![CollectedMarkerCallCandidate::new(
                CallOccurrenceKey::new(function(1), 9),
                panic_claim.key().clone(),
                CallOccurrenceHasMarkerClaimCandidate::new(true, false),
            )],
            vec![CollectedEffectMarkerCandidate::new(
                EffectSiteKey::from_mir(
                    function(1),
                    MirBodyLocation {
                        basic_block: 3,
                        statement_index: 4,
                    },
                )
                .unwrap(),
                panic_claim.key().clone(),
                EffectSiteHasMarkerClaimCandidate::new(false, true),
            )],
            vec![CollectedUnsafeOperationMarkerCandidate::new(
                UnsafeOperationKey::new(function(1), 0),
                safety_claim.key().clone(),
                UnsafeOperationHasMarkerClaimCandidate::new(true, true),
            )],
        )
    }

    fn marker_artifact(
        marker_occurrences: Vec<CollectedMarkerOccurrence>,
    ) -> Result<CollectedArtifact, CollectedArtifactError> {
        CollectedArtifact::try_new(CollectedArtifactInput {
            program: program(),
            unsafe_operations: vec![unsafe_operation(function(1), 0)],
            panic_contracts: Vec::new(),
            safety_contracts: Vec::new(),
            mir_asserts: Vec::new(),
            marker_occurrences,
        })
    }

    #[test]
    fn marker_collection_is_canonical_under_complete_input_reversal() {
        let source = marker_occurrence(anchor(10, 15), None, Vec::new());
        let expanded = marker_occurrence(
            anchor(10, 15),
            Some(expansion(102)),
            vec![expansion(101), expansion(102)],
        );
        let expected = marker_artifact(vec![source.clone(), expanded.clone()]).unwrap();

        let mut reversed = vec![expanded, source];
        reversed.reverse();
        for occurrence in &mut reversed {
            occurrence.claims_mut_for_test().reverse();
            occurrence.function_candidates_mut_for_test().reverse();
            occurrence.call_candidates_mut_for_test().reverse();
            occurrence.effect_candidates_mut_for_test().reverse();
            occurrence
                .unsafe_operation_candidates_mut_for_test()
                .reverse();
        }
        let actual = marker_artifact(reversed).unwrap();

        assert_eq!(actual, expected);
        assert_eq!(actual.marker_occurrences().len(), 2);
        assert!(
            actual.marker_occurrences()[0]
                .entity()
                .key()
                .origin()
                .is_none()
        );
        assert_eq!(actual.marker_occurrences()[0].claims().len(), 2);
        assert_eq!(
            actual.marker_occurrences()[0].function_candidates().len(),
            2
        );
        assert_eq!(actual.marker_occurrences()[0].call_candidates().len(), 1);
        assert_eq!(actual.marker_occurrences()[0].effect_candidates().len(), 1);
        assert_eq!(
            actual.marker_occurrences()[0]
                .unsafe_operation_candidates()
                .len(),
            1
        );
    }

    #[test]
    fn marker_collection_accepts_an_empty_table() {
        assert!(
            marker_artifact(Vec::new())
                .unwrap()
                .marker_occurrences()
                .is_empty()
        );
    }

    #[test]
    fn marker_occurrence_identity_and_expansion_path_are_exact() {
        let duplicate = marker_occurrence(anchor(10, 15), None, Vec::new());
        assert!(matches!(
            marker_artifact(vec![duplicate.clone(), duplicate]),
            Err(CollectedArtifactError::DuplicateMarkerOccurrence { .. })
        ));

        let dangling = marker_occurrence(anchor(90, 95), None, Vec::new());
        assert!(matches!(
            marker_artifact(vec![dangling]),
            Err(CollectedArtifactError::DanglingMarkerSourceAnchor { .. })
        ));

        let source_with_path = marker_occurrence(anchor(10, 15), None, vec![expansion(101)]);
        assert!(matches!(
            marker_artifact(vec![source_with_path]),
            Err(CollectedArtifactError::SourceMarkerHasExpansionPath { .. })
        ));

        let macro_without_path =
            marker_occurrence(anchor(10, 15), Some(expansion(101)), Vec::new());
        assert!(matches!(
            marker_artifact(vec![macro_without_path]),
            Err(CollectedArtifactError::MacroMarkerMissingExpansionPath { .. })
        ));

        let wrong_origin =
            marker_occurrence(anchor(10, 15), Some(expansion(102)), vec![expansion(101)]);
        assert!(matches!(
            marker_artifact(vec![wrong_origin]),
            Err(CollectedArtifactError::MarkerOriginPathMismatch { .. })
        ));

        let repeated_frame = marker_occurrence(
            anchor(10, 15),
            Some(expansion(101)),
            vec![expansion(101), expansion(101)],
        );
        assert!(matches!(
            marker_artifact(vec![repeated_frame]),
            Err(CollectedArtifactError::DuplicateMarkerExpansionHash { .. })
        ));
    }

    #[test]
    fn marker_claims_require_exact_ownership_ordinals_and_nonblank_rationales() {
        let mut occurrence = marker_occurrence(anchor(10, 15), None, Vec::new());
        occurrence.claims_mut_for_test()[0] = marker_claim(
            &MarkerOccurrenceKey::new(anchor(20, 25), None),
            "sniff-test.panic",
            0,
            "foreign",
        );
        assert!(matches!(
            marker_artifact(vec![occurrence]),
            Err(CollectedArtifactError::MarkerClaimOwnerMismatch { .. })
        ));

        let mut occurrence = marker_occurrence(anchor(10, 15), None, Vec::new());
        let duplicate = occurrence.claims()[0].clone();
        occurrence.claims_mut_for_test().push(duplicate);
        assert!(matches!(
            marker_artifact(vec![occurrence]),
            Err(CollectedArtifactError::DuplicateMarkerClaim { .. })
        ));

        let key = MarkerOccurrenceKey::new(anchor(10, 15), None);
        let noncontiguous = CollectedMarkerOccurrence::new(
            MarkerOccurrenceEntity::new(key.clone(), Vec::new()),
            vec![marker_claim(&key, "sniff-test.panic", 1, "late")],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert!(matches!(
            marker_artifact(vec![noncontiguous]),
            Err(CollectedArtifactError::NonContiguousMarkerClaimOrdinals {
                expected_ordinal: 0,
                actual_ordinal: 1,
                ..
            })
        ));

        let blank = CollectedMarkerOccurrence::new(
            MarkerOccurrenceEntity::new(key.clone(), Vec::new()),
            vec![marker_claim(&key, "sniff-test.panic", 0, "  \t")],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert!(matches!(
            marker_artifact(vec![blank]),
            Err(CollectedArtifactError::EmptyMarkerClaimRationale { .. })
        ));
    }

    #[test]
    fn marker_claim_selectors_retain_raw_values_but_reject_empty_or_repeated_entries() {
        fn occurrence_with_selector(selector: EvidenceClaimSelector) -> CollectedMarkerOccurrence {
            let occurrence = MarkerOccurrenceKey::new(anchor(10, 15), None);
            let claim = MarkerClaimEntity::new(
                MarkerClaimKey::new(
                    occurrence.clone(),
                    DomainId::new("sniff-test.panic").unwrap(),
                    0,
                ),
                selector,
                "rationale",
            );
            CollectedMarkerOccurrence::new(
                MarkerOccurrenceEntity::new(occurrence, Vec::new()),
                vec![claim],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
        }

        let named = occurrence_with_selector(EvidenceClaimSelector::Named(String::from(
            "  raw Requirement_Name  ",
        )));
        let artifact = marker_artifact(vec![named]).unwrap();
        assert_eq!(
            artifact.marker_occurrences()[0].claims()[0].selector(),
            &EvidenceClaimSelector::Named(String::from("  raw Requirement_Name  "))
        );

        let blank_named =
            occurrence_with_selector(EvidenceClaimSelector::Named(String::from(" \t ")));
        assert!(matches!(
            marker_artifact(vec![blank_named]),
            Err(CollectedArtifactError::EmptyMarkerClaimSelectorName { .. })
        ));

        let empty_explicit = occurrence_with_selector(EvidenceClaimSelector::Explicit(Vec::new()));
        assert!(matches!(
            marker_artifact(vec![empty_explicit]),
            Err(CollectedArtifactError::EmptyMarkerClaimExplicitSelector { .. })
        ));

        let blank_reference = occurrence_with_selector(EvidenceClaimSelector::Explicit(vec![
            String::from("valid"),
            String::from("  "),
        ]));
        assert!(matches!(
            marker_artifact(vec![blank_reference]),
            Err(CollectedArtifactError::EmptyMarkerClaimExplicitReference {
                reference_ordinal: 1,
                ..
            })
        ));

        let repeated_reference = occurrence_with_selector(EvidenceClaimSelector::Explicit(vec![
            String::from("Raw Name"),
            String::from("other"),
            String::from("Raw Name"),
        ]));
        assert!(matches!(
            marker_artifact(vec![repeated_reference]),
            Err(
                CollectedArtifactError::DuplicateMarkerClaimExplicitReference {
                    first_ordinal: 0,
                    duplicate_ordinal: 2,
                    ..
                }
            )
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-driven contract covers ownership and lookup for all four endpoint schemas"
    )]
    fn marker_candidates_require_a_local_claim_and_known_typed_endpoint() {
        let mut occurrence = marker_occurrence(anchor(10, 15), None, Vec::new());
        let missing_claim = marker_claim(
            occurrence.entity().key(),
            "sniff-test.panic",
            1,
            "not collected",
        );
        occurrence
            .function_candidates_mut_for_test()
            .push(CollectedFunctionMarkerCandidate::new(
                function(1),
                missing_claim.key().clone(),
                FunctionHasMarkerClaimCandidate::new(true, false),
            ));
        assert!(matches!(
            marker_artifact(vec![occurrence]),
            Err(CollectedArtifactError::MissingMarkerCandidateClaim { .. })
        ));

        let mut occurrence = marker_occurrence(anchor(10, 15), None, Vec::new());
        let foreign_claim = marker_claim(
            &MarkerOccurrenceKey::new(anchor(20, 25), None),
            "sniff-test.panic",
            0,
            "foreign occurrence",
        );
        occurrence
            .function_candidates_mut_for_test()
            .push(CollectedFunctionMarkerCandidate::new(
                function(1),
                foreign_claim.key().clone(),
                FunctionHasMarkerClaimCandidate::new(true, false),
            ));
        assert!(matches!(
            marker_artifact(vec![occurrence]),
            Err(CollectedArtifactError::MarkerCandidateClaimOwnerMismatch { .. })
        ));

        let mut occurrence = marker_occurrence(anchor(10, 15), None, Vec::new());
        let duplicate = occurrence.function_candidates()[0].clone();
        occurrence.function_candidates_mut_for_test().extend([
            duplicate.clone(),
            CollectedFunctionMarkerCandidate::new(
                *duplicate.function(),
                duplicate.claim().clone(),
                FunctionHasMarkerClaimCandidate::new(true, true),
            ),
        ]);
        assert!(matches!(
            marker_artifact(vec![occurrence]),
            Err(CollectedArtifactError::ConflictingFunctionMarkerCandidate { .. })
        ));

        let mut occurrence = marker_occurrence(anchor(10, 15), None, Vec::new());
        let claim = occurrence.claims()[0].key().clone();
        occurrence.function_candidates_mut_for_test()[0] = CollectedFunctionMarkerCandidate::new(
            function(99),
            claim,
            FunctionHasMarkerClaimCandidate::new(true, false),
        );
        assert!(matches!(
            marker_artifact(vec![occurrence]),
            Err(CollectedArtifactError::DanglingFunctionMarkerCandidate { .. })
        ));

        let mut occurrence = marker_occurrence(anchor(10, 15), None, Vec::new());
        let claim = occurrence.claims()[0].key().clone();
        occurrence.call_candidates_mut_for_test()[0] = CollectedMarkerCallCandidate::new(
            CallOccurrenceKey::new(function(1), 99),
            claim,
            CallOccurrenceHasMarkerClaimCandidate::new(true, false),
        );
        assert!(matches!(
            marker_artifact(vec![occurrence]),
            Err(CollectedArtifactError::DanglingCallMarkerCandidate { .. })
        ));

        let mut occurrence = marker_occurrence(anchor(10, 15), None, Vec::new());
        let claim = occurrence.claims()[0].key().clone();
        occurrence.effect_candidates_mut_for_test()[0] = CollectedEffectMarkerCandidate::new(
            EffectSiteKey::from_mir(
                function(1),
                MirBodyLocation {
                    basic_block: 30,
                    statement_index: 40,
                },
            )
            .unwrap(),
            claim,
            EffectSiteHasMarkerClaimCandidate::new(true, false),
        );
        assert!(matches!(
            marker_artifact(vec![occurrence]),
            Err(CollectedArtifactError::DanglingEffectMarkerCandidate { .. })
        ));

        let mut occurrence = marker_occurrence(anchor(10, 15), None, Vec::new());
        let claim = occurrence.claims()[0].key().clone();
        occurrence.unsafe_operation_candidates_mut_for_test()[0] =
            CollectedUnsafeOperationMarkerCandidate::new(
                UnsafeOperationKey::new(function(1), 99),
                claim,
                UnsafeOperationHasMarkerClaimCandidate::new(true, false),
            );
        assert!(matches!(
            marker_artifact(vec![occurrence]),
            Err(CollectedArtifactError::DanglingUnsafeOperationMarkerCandidate { .. })
        ));
    }

    #[test]
    fn every_marker_candidate_requires_at_least_one_probing_mode() {
        let disable_candidates: [fn(&mut CollectedMarkerOccurrence); 4] = [
            |occurrence| {
                let candidate = &occurrence.function_candidates()[0];
                occurrence.function_candidates_mut_for_test()[0] =
                    CollectedFunctionMarkerCandidate::new(
                        *candidate.function(),
                        candidate.claim().clone(),
                        FunctionHasMarkerClaimCandidate::new(false, false),
                    );
            },
            |occurrence| {
                let candidate = &occurrence.call_candidates()[0];
                occurrence.call_candidates_mut_for_test()[0] = CollectedMarkerCallCandidate::new(
                    *candidate.occurrence(),
                    candidate.claim().clone(),
                    CallOccurrenceHasMarkerClaimCandidate::new(false, false),
                );
            },
            |occurrence| {
                let candidate = &occurrence.effect_candidates()[0];
                occurrence.effect_candidates_mut_for_test()[0] =
                    CollectedEffectMarkerCandidate::new(
                        *candidate.effect_site(),
                        candidate.claim().clone(),
                        EffectSiteHasMarkerClaimCandidate::new(false, false),
                    );
            },
            |occurrence| {
                let candidate = &occurrence.unsafe_operation_candidates()[0];
                occurrence.unsafe_operation_candidates_mut_for_test()[0] =
                    CollectedUnsafeOperationMarkerCandidate::new(
                        *candidate.unsafe_operation(),
                        candidate.claim().clone(),
                        UnsafeOperationHasMarkerClaimCandidate::new(false, false),
                    );
            },
        ];

        for disable in disable_candidates {
            let mut occurrence = marker_occurrence(anchor(10, 15), None, Vec::new());
            disable(&mut occurrence);
            assert!(matches!(
                marker_artifact(vec![occurrence]),
                Err(CollectedArtifactError::EmptyMarkerCandidateApplicability { .. })
            ));
        }
    }
}
