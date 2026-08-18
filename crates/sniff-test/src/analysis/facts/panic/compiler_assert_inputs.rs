//! Private preparation for compiler-assert and additive panic-root inputs.
//!
//! This module does not publish evaluation rows, switch evaluation authority,
//! or own a composition builder. It preserves the compiler-assert input API
//! while retaining panic call obligations and their raw active marker state for
//! a future projection. Marker selector matching is intentionally deferred.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use super::call_model::PanicCallPresentationFunction;
use super::contract_index::{EffectivePanicContract, EffectivePanicRequirement};
use super::{
    WorkspaceEffectivePanicContracts, WorkspaceEffectivePanicContractsError,
    WorkspaceMirAssertIndex, WorkspaceMirAssertIndexError,
};
use crate::analysis::facts::composition::{
    CompositionRelationBuilder, CompositionRelationRegistry, WorkspaceRelationGraph,
};
use crate::analysis::facts::evaluation::{EvaluationRoot, RelationTrace};
use crate::analysis::facts::human::EvidenceClaimSelector;
use crate::analysis::facts::human::markers::MarkerClaimEntity;
use crate::analysis::facts::panic::model::MirAssertKind;
use crate::analysis::facts::program::root_traversal::{
    BodyPolicyContext, BodyTraversalDecision, CallPolicyContext, CallTargetPolicyCandidate,
    CallTargetSelection, CallTraversalDecision, DefiningMarkerCandidate, DefiningMarkerDecision,
    DefiningMarkerPolicyContext, DefiningScopeMapError, EmittedRootProgramTraversal, MarkerProbe,
    PreparedRootProgramTraversal, ProgramCallResolution, ReconciledCallTargetAuthority,
    ReconciledCallTargetPolicyCandidate, ResolvedCallMacroFrame, ResolvedCallSourceAnchor,
    ResolvedEffectMacroFrame, ResolvedEffectSourceAnchor, ResolvedMarkerClaim,
    ResolvedRootProgramTraversal, RootProgramTraversalError, RootProgramTraversalPolicy,
    RootProgramTraversalRequest, VerifiedDefiningScopeMap, VerifiedPresentationFunctionScopes,
};
use crate::analysis::facts::program::topology::{
    CallAttributionRole, CallKind, CallOccurrenceEntity, CallSiteEntity, CallTargetRole,
    CallableEntity,
};
use crate::analysis::facts::program::workspace_index::{
    ScopedProgramEntity, WorkspaceProgramIndex,
};
use crate::analysis::facts::program::{EffectSiteEntity, FunctionEntity, FunctionKey};
use crate::analysis::facts::safety::{
    WorkspaceEffectiveSafetyContracts, WorkspaceEffectiveSafetyContractsError,
};
use crate::analysis::facts::workspace::{
    ArtifactScopeId, ScopedEntityId, ScopedRowRef, WorkspaceFactView, WorkspaceIdentity,
};
use crate::analysis::workspace_closure::VerifiedWorkspaceClosure;
use crate::config::{PanicBoundaryPolicy, PanicConfig};
use crate::contracts::ContractDocOverrides;

/// Domain-neutral knobs required to prepare one compiler-assert root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompilerAssertRootRequest {
    root: FunctionKey,
    attribution: CallAttributionRole,
    marker_probe: MarkerProbe,
    node_budget: usize,
}

impl CompilerAssertRootRequest {
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

    #[must_use]
    pub(crate) fn traversal_request(
        &self,
        root_scope: ArtifactScopeId,
    ) -> RootProgramTraversalRequest {
        RootProgramTraversalRequest::new(
            super::rules::panic_domain(),
            root_scope,
            self.root,
            self.attribution,
            self.marker_probe,
            self.node_budget,
        )
    }
}

/// Why panic traversal intentionally stopped before entering a body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CompilerAssertBoundary {
    PanicContract(PanicContractBoundary),
    TrustedNamespace,
    PanicSink(PanicCallBoundaryContext),
    ForeignDeclaration,
    BodylessDeclaration(PanicCallBoundaryContext),
    OpaqueCall(PanicCallBoundaryContext),
}

/// Exact contract data retained when traversal stops at a documented boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PanicContractBoundary {
    Root {
        contract: Arc<EffectivePanicContract>,
    },
    Call(PanicContractCallBoundary),
}

/// Contract and evidence identities selected independently for one call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PanicContractCallBoundary {
    contract: Arc<EffectivePanicContract>,
    contract_target: CallTargetSelection,
    evidence_group: PanicEvidenceGroup,
    trusted: bool,
}

/// Exact call-site identity and value used to group panic evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PanicEvidenceGroup {
    call_site: ScopedEntityId<CallSiteEntity>,
    data: CallSiteEntity,
}

/// Panic evidence context retained for a non-contract call boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PanicCallBoundaryContext {
    evidence_group: PanicEvidenceGroup,
    opaque: Option<PanicOpaqueBoundary>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PanicOpaqueBoundaryKind {
    BodylessDeclaration,
    ExplicitOpaque,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PanicOpaqueBoundary {
    kind: PanicOpaqueBoundaryKind,
    description: String,
}

impl PanicContractCallBoundary {
    #[must_use]
    pub(crate) fn contract(&self) -> &Arc<EffectivePanicContract> {
        &self.contract
    }

    #[must_use]
    pub(crate) const fn contract_target(&self) -> &CallTargetSelection {
        &self.contract_target
    }

    #[must_use]
    pub(crate) const fn evidence_group(&self) -> &ScopedEntityId<CallSiteEntity> {
        &self.evidence_group.call_site
    }

    #[must_use]
    pub(crate) const fn evidence_group_data(&self) -> &CallSiteEntity {
        &self.evidence_group.data
    }
}

/// Structured policy failure; traversal preparation remains all-or-none.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CompilerAssertPolicyError {
    PanicContracts(WorkspaceEffectivePanicContractsError),
}

impl Display for CompilerAssertPolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PanicContracts(source) => Display::fmt(source, formatter),
        }
    }
}

impl Error for CompilerAssertPolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PanicContracts(source) => Some(source),
        }
    }
}

/// Immutable permanent marker data retained for one reached assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompilerAssertMarkerInput {
    claim: ScopedEntityId<MarkerClaimEntity>,
    data: MarkerClaimEntity,
    trace: RelationTrace,
}

impl CompilerAssertMarkerInput {
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

    #[cfg(test)]
    pub(super) fn test_set_data(&mut self, data: MarkerClaimEntity) {
        self.data = data;
    }

    #[cfg(test)]
    pub(super) fn test_set_trace(&mut self, trace: RelationTrace) {
        self.trace = trace;
    }
}

/// One reachable permanent MIR assertion after exact safety suppression.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReachableCompilerAssertInput {
    id: CompilerAssertInputId,
    order: u64,
    visit_order: u64,
    source: ScopedRowRef,
    owner: ScopedEntityId<EffectSiteEntity>,
    provenance: ScopedEntityId<FunctionEntity>,
    kind: MirAssertKind,
    requirements: Vec<ScopedRowRef>,
    source_anchors: Vec<ResolvedEffectSourceAnchor>,
    macro_frames: Vec<ResolvedEffectMacroFrame>,
    markers: Vec<CompilerAssertMarkerInput>,
    trace: RelationTrace,
}

impl ReachableCompilerAssertInput {
    #[must_use]
    pub(crate) const fn id(&self) -> CompilerAssertInputId {
        self.id
    }

    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.order
    }

    #[must_use]
    pub(crate) const fn visit_order(&self) -> u64 {
        self.visit_order
    }

    #[must_use]
    pub(crate) const fn source(&self) -> &ScopedRowRef {
        &self.source
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> &ScopedEntityId<EffectSiteEntity> {
        &self.owner
    }

    #[must_use]
    pub(crate) const fn provenance(&self) -> &ScopedEntityId<FunctionEntity> {
        &self.provenance
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> MirAssertKind {
        self.kind
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[ScopedRowRef] {
        &self.requirements
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
    pub(crate) fn markers(&self) -> &[CompilerAssertMarkerInput] {
        &self.markers
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }

    #[cfg(test)]
    pub(super) const fn test_set_order(&mut self, order: u64) {
        self.order = order;
    }

    #[cfg(test)]
    pub(super) const fn test_set_kind(&mut self, kind: MirAssertKind) {
        self.kind = kind;
    }

    #[cfg(test)]
    pub(super) fn test_set_source(&mut self, source: ScopedRowRef) {
        self.source = source;
    }

    #[cfg(test)]
    pub(super) fn test_set_owner(&mut self, owner: ScopedEntityId<EffectSiteEntity>) {
        self.owner = owner;
    }

    #[cfg(test)]
    pub(super) fn test_set_trace(&mut self, trace: RelationTrace) {
        self.trace = trace;
    }

    #[cfg(test)]
    pub(super) fn test_clear_requirements(&mut self) {
        self.requirements.clear();
    }

    #[cfg(test)]
    pub(super) fn test_marker_mut(
        &mut self,
        index: usize,
    ) -> Option<&mut CompilerAssertMarkerInput> {
        self.markers.get_mut(index)
    }
}

/// Dense root-local identity of one retained compiler assertion.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct CompilerAssertInputId(usize);

impl CompilerAssertInputId {
    #[must_use]
    pub(crate) const fn index(self) -> usize {
        self.0
    }
}

/// Dense root-local identity reserved for retained panic calls.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct PanicCallInputId(usize);

impl PanicCallInputId {
    #[must_use]
    pub(crate) const fn index(self) -> usize {
        self.0
    }
}

/// Root-local identity of one requirement atom carried by a panic call.
///
/// The call identity precedes the optional contract ordinal semantically;
/// variant declaration order is intentionally not exposed as an ordering.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PanicCallRequirementId {
    Unnamed {
        call: PanicCallInputId,
    },
    Named {
        call: PanicCallInputId,
        ordinal: u32,
    },
}

impl PanicCallRequirementId {
    #[must_use]
    pub(crate) const fn call(self) -> PanicCallInputId {
        match self {
            Self::Unnamed { call } | Self::Named { call, .. } => call,
        }
    }

    #[must_use]
    pub(crate) const fn ordinal(self) -> Option<u32> {
        match self {
            Self::Unnamed { .. } => None,
            Self::Named { ordinal, .. } => Some(ordinal),
        }
    }
}

/// Borrowed atom view; raw provenance remains owned by the effective contract.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PanicCallRequirementView<'a> {
    call: PanicCallInputId,
    value: Option<&'a EffectivePanicRequirement>,
}

impl<'a> PanicCallRequirementView<'a> {
    #[must_use]
    pub(crate) fn id(&self) -> PanicCallRequirementId {
        self.value.map_or(
            PanicCallRequirementId::Unnamed { call: self.call },
            |value| PanicCallRequirementId::Named {
                call: self.call,
                ordinal: value.ordinal(),
            },
        )
    }

    #[must_use]
    pub(crate) const fn call(&self) -> PanicCallInputId {
        self.call
    }

    #[must_use]
    pub(crate) const fn value(&self) -> Option<&'a EffectivePanicRequirement> {
        self.value
    }
}

/// Allocation-free source-order iterator over one call's requirement atoms.
#[derive(Clone, Debug)]
pub(crate) struct PanicCallRequirements<'a> {
    call: PanicCallInputId,
    named: std::slice::Iter<'a, EffectivePanicRequirement>,
    unnamed_pending: bool,
}

impl<'a> PanicCallRequirements<'a> {
    fn new(call: PanicCallInputId, requirements: &'a [EffectivePanicRequirement]) -> Self {
        Self {
            call,
            named: requirements.iter(),
            unnamed_pending: requirements.is_empty(),
        }
    }
}

impl<'a> Iterator for PanicCallRequirements<'a> {
    type Item = PanicCallRequirementView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.unnamed_pending {
            self.unnamed_pending = false;
            return Some(PanicCallRequirementView {
                call: self.call,
                value: None,
            });
        }
        self.named.next().map(|value| PanicCallRequirementView {
            call: self.call,
            value: Some(value),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for PanicCallRequirements<'_> {
    fn len(&self) -> usize {
        if self.unnamed_pending {
            1
        } else {
            self.named.len()
        }
    }
}

/// One retained panic witness independent of its canonical evidence rank.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum PanicWitnessId {
    CompilerAssert(CompilerAssertInputId),
    Call(PanicCallInputId),
}

/// Dense canonical ordering across every panic witness kind.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct PanicEvidenceRank(usize);

impl PanicEvidenceRank {
    #[must_use]
    pub(crate) const fn index(self) -> usize {
        self.0
    }
}

/// One canonical cross-kind evidence-order entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RankedPanicWitness {
    rank: PanicEvidenceRank,
    traversal_order: u64,
    witness: PanicWitnessId,
}

impl RankedPanicWitness {
    #[must_use]
    pub(crate) const fn rank(&self) -> PanicEvidenceRank {
        self.rank
    }

    #[must_use]
    pub(crate) const fn witness(&self) -> PanicWitnessId {
        self.witness
    }

    #[must_use]
    pub(crate) const fn traversal_order(&self) -> u64 {
        self.traversal_order
    }
}

/// Domain meaning retained at policy time for one panic call obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PanicCallInputKind {
    Documented { trusted: bool },
    PanicSink,
    Opaque { kind: PanicOpaqueBoundaryKind },
}

/// Lightweight index into the complete resolved traversal retained by the root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PanicCallInput {
    id: PanicCallInputId,
    boundary_index: usize,
    traversal_order: u64,
    kind: PanicCallInputKind,
    presentation_function: PanicCallPresentationFunction,
    #[cfg(test)]
    clear_metadata_target_data: bool,
    #[cfg(test)]
    markers_override: Option<Vec<ResolvedMarkerClaim>>,
    #[cfg(test)]
    trace_override: Option<RelationTrace>,
}

/// Exact legacy invocation target retained independently from policy metadata.
///
/// A persisted opaque target carries both its optional callable identity and
/// its raw description. Callable evidence replaces that complete raw target,
/// so its presentation has a callable and no opaque description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PanicCallPresentationTarget<'a> {
    callable: Option<PanicCallPresentationCallable<'a>>,
    opaque_description: Option<&'a str>,
}

impl<'a> PanicCallPresentationTarget<'a> {
    #[must_use]
    pub(crate) const fn callable(&self) -> Option<&PanicCallPresentationCallable<'a>> {
        self.callable.as_ref()
    }

    /// Returns the raw extracted description without report-level wording
    /// normalization. The final trace projector owns that normalization.
    #[must_use]
    pub(crate) const fn opaque_description(&self) -> Option<&'a str> {
        self.opaque_description
    }
}

/// Borrowed identity and data for one exact presentation callable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PanicCallPresentationCallable<'a> {
    selection: &'a CallTargetSelection,
    data: &'a CallableEntity,
}

impl<'a> PanicCallPresentationCallable<'a> {
    #[must_use]
    pub(crate) const fn selection(&self) -> &'a CallTargetSelection {
        self.selection
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &'a CallableEntity {
        self.data
    }
}

/// Borrowed view joining one lightweight call index to its resolved boundary.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PanicCallInputView<'a> {
    input: &'a PanicCallInput,
    boundary: &'a crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        CompilerAssertBoundary,
    >,
    evidence_group: &'a PanicEvidenceGroup,
}

impl PanicCallInputView<'_> {
    #[must_use]
    pub(crate) const fn id(&self) -> PanicCallInputId {
        self.input.id
    }
    #[must_use]
    pub(crate) const fn order(&self) -> u64 {
        self.boundary.order()
    }
    #[must_use]
    pub(crate) const fn occurrence(&self) -> &ScopedEntityId<CallOccurrenceEntity> {
        self.boundary.occurrence()
    }
    #[must_use]
    pub(crate) const fn occurrence_data(&self) -> &CallOccurrenceEntity {
        self.boundary.occurrence_data()
    }
    #[must_use]
    pub(crate) fn source(&self) -> ScopedRowRef {
        self.boundary.occurrence().erase().as_row()
    }
    #[must_use]
    pub(crate) fn endpoint(&self) -> crate::analysis::facts::workspace::ScopedEntityRef {
        self.boundary.occurrence().erase()
    }
    #[must_use]
    pub(crate) fn trace_target(&self) -> &crate::analysis::facts::workspace::ScopedEntityRef {
        self.trace().target()
    }
    #[must_use]
    pub(crate) const fn consumer_call_site(&self) -> &ScopedEntityId<CallSiteEntity> {
        self.boundary.call_site()
    }
    #[must_use]
    pub(crate) const fn consumer_call_site_data(&self) -> &CallSiteEntity {
        self.boundary.call_site_data()
    }
    #[must_use]
    pub(crate) const fn effective_kind(&self) -> CallKind {
        self.boundary.effective_kind()
    }
    #[must_use]
    pub(crate) const fn resolution(&self) -> &ProgramCallResolution {
        self.boundary.resolution()
    }
    #[must_use]
    pub(crate) const fn metadata_target(&self) -> Option<&CallTargetSelection> {
        self.boundary.target()
    }
    #[must_use]
    pub(crate) fn metadata_target_data(&self) -> Option<&CallableEntity> {
        #[cfg(test)]
        if self.input.clear_metadata_target_data {
            return None;
        }
        self.boundary.target_data()
    }
    pub(crate) fn presentation_target(
        &self,
    ) -> Result<PanicCallPresentationTarget<'_>, CompilerAssertInputError> {
        resolve_panic_call_presentation_target(
            self.id(),
            self.resolution(),
            self.occurrence_data(),
            self.metadata_target(),
            self.metadata_target_data(),
        )
    }
    #[must_use]
    pub(crate) const fn presentation_function(&self) -> &PanicCallPresentationFunction {
        &self.input.presentation_function
    }
    #[must_use]
    pub(crate) const fn evidence_group(&self) -> &ScopedEntityId<CallSiteEntity> {
        &self.evidence_group.call_site
    }
    #[must_use]
    pub(crate) const fn evidence_group_data(&self) -> &CallSiteEntity {
        &self.evidence_group.data
    }
    #[must_use]
    pub(crate) fn source_anchors(&self) -> &[ResolvedCallSourceAnchor] {
        self.boundary.source_anchors()
    }
    #[must_use]
    pub(crate) fn macro_frames(&self) -> &[ResolvedCallMacroFrame] {
        self.boundary.macro_frames()
    }
    #[must_use]
    pub(crate) fn inherited_markers(&self) -> &[ResolvedMarkerClaim] {
        self.boundary.inherited_markers()
    }
    #[must_use]
    pub(crate) fn attached_marker_candidates(&self) -> &[ResolvedMarkerClaim] {
        self.boundary.attached_marker_candidates()
    }
    #[must_use]
    pub(crate) fn markers(&self) -> &[ResolvedMarkerClaim] {
        #[cfg(test)]
        if let Some(markers) = &self.input.markers_override {
            return markers;
        }
        self.boundary.active_markers()
    }
    #[must_use]
    pub(crate) const fn kind(&self) -> PanicCallInputKind {
        self.input.kind
    }
    #[must_use]
    pub(crate) fn contract(&self) -> Option<&Arc<EffectivePanicContract>> {
        match self.boundary.payload() {
            CompilerAssertBoundary::PanicContract(PanicContractBoundary::Call(payload)) => {
                Some(payload.contract())
            }
            _ => None,
        }
    }
    #[must_use]
    pub(crate) fn contract_target(&self) -> Option<&CallTargetSelection> {
        match self.boundary.payload() {
            CompilerAssertBoundary::PanicContract(PanicContractBoundary::Call(payload)) => {
                Some(payload.contract_target())
            }
            _ => None,
        }
    }
    #[must_use]
    pub(crate) fn requirements(&self) -> PanicCallRequirements<'_> {
        let requirements = self
            .contract()
            .map_or(&[][..], |contract| contract.requirements());
        PanicCallRequirements::new(self.id(), requirements)
    }
    #[must_use]
    pub(crate) fn opaque_description(&self) -> Option<&str> {
        match self.boundary.payload() {
            CompilerAssertBoundary::BodylessDeclaration(context)
            | CompilerAssertBoundary::OpaqueCall(context) => context
                .opaque
                .as_ref()
                .map(|opaque| opaque.description.as_str()),
            _ => None,
        }
    }
    #[must_use]
    pub(crate) fn trace(&self) -> &RelationTrace {
        #[cfg(test)]
        if let Some(trace) = &self.input.trace_override {
            return trace;
        }
        self.boundary.trace()
    }
}

fn resolve_panic_call_presentation_target<'a>(
    call: PanicCallInputId,
    resolution: &ProgramCallResolution,
    occurrence: &'a CallOccurrenceEntity,
    selection: Option<&'a CallTargetSelection>,
    data: Option<&'a CallableEntity>,
) -> Result<PanicCallPresentationTarget<'a>, CompilerAssertInputError> {
    let selected = match (selection, data) {
        (Some(selection), Some(data)) => {
            if matches!(selection.role(), CallTargetRole::Runtime)
                != data.key().instance().is_some()
            {
                return Err(invalid_presentation_target(
                    call,
                    "selected callable role disagrees with its data identity",
                ));
            }
            Some(PanicCallPresentationCallable { selection, data })
        }
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => {
            return Err(invalid_presentation_target(
                call,
                "selected callable identity and data are not paired",
            ));
        }
    };

    if matches!(resolution, ProgramCallResolution::CallableEvidence { .. }) {
        let selected = selected.ok_or_else(|| {
            invalid_presentation_target(call, "callable evidence has no selected callable")
        })?;
        if selected.selection.role() != CallTargetRole::Runtime
            || selected.selection.authority() != ReconciledCallTargetAuthority::ConsumerRaw
        {
            return Err(invalid_presentation_target(
                call,
                "callable evidence does not select its synthetic runtime callable",
            ));
        }
        return Ok(PanicCallPresentationTarget {
            callable: Some(selected),
            opaque_description: None,
        });
    }

    let description = occurrence.opaque_target_description();
    if let Some(selected) = selected
        && selected.selection.authority() == ReconciledCallTargetAuthority::ConsumerRaw
    {
        match selected.selection.role() {
            CallTargetRole::Runtime if description.is_none() => {
                return Ok(PanicCallPresentationTarget {
                    callable: Some(selected),
                    opaque_description: None,
                });
            }
            CallTargetRole::OpaqueTrait | CallTargetRole::OpaqueFunction => {
                let description = required_presentation_description(call, description)?;
                return Ok(PanicCallPresentationTarget {
                    callable: Some(selected),
                    opaque_description: Some(description),
                });
            }
            CallTargetRole::Runtime => {
                return Err(invalid_presentation_target(
                    call,
                    "runtime callable unexpectedly carries an opaque description",
                ));
            }
            CallTargetRole::SourceContract => {}
        }
    }

    Ok(PanicCallPresentationTarget {
        callable: None,
        opaque_description: Some(required_presentation_description(call, description)?),
    })
}

fn resolve_panic_call_presentation_function(
    call: PanicCallInputId,
    program: &WorkspaceProgramIndex,
    scopes: &VerifiedPresentationFunctionScopes<'_>,
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        CompilerAssertBoundary,
    >,
) -> Result<PanicCallPresentationFunction, CompilerAssertInputError> {
    let presentation = resolve_panic_call_presentation_target(
        call,
        boundary.resolution(),
        boundary.occurrence_data(),
        boundary.target(),
        boundary.target_data(),
    )?;
    project_panic_call_presentation_function(
        call,
        program,
        scopes,
        boundary.occurrence().scope(),
        *boundary.occurrence_data().key().owner(),
        presentation,
    )
}

fn project_panic_call_presentation_function(
    call: PanicCallInputId,
    program: &WorkspaceProgramIndex,
    scopes: &VerifiedPresentationFunctionScopes<'_>,
    caller_scope: &ArtifactScopeId,
    caller_function: FunctionKey,
    presentation: PanicCallPresentationTarget<'_>,
) -> Result<PanicCallPresentationFunction, CompilerAssertInputError> {
    let (endpoint, scope, function) = if let Some(callable) = presentation.callable() {
        let indexed = program
            .exact_callable(
                callable.selection().callable().scope(),
                callable.data().key(),
            )
            .ok_or_else(|| {
                invalid_presentation_target(call, "presentation callable is not indexed")
            })?;
        if indexed.id() != *callable.selection().callable() || indexed.data() != callable.data() {
            return Err(invalid_presentation_target(
                call,
                "presentation callable identity disagrees with its data",
            ));
        }
        let function = *callable.data().key();
        let scope = scopes
            .resolve(caller_scope, &function)
            .map_err(|source| invalid_presentation_scope_authority(&source))?;
        (callable.selection().callable().erase(), scope, function)
    } else {
        let caller = program
            .exact_function(caller_scope, &caller_function)
            .ok_or_else(|| {
                invalid_presentation_target(call, "terminal caller function is not indexed")
            })?;
        if caller.data().key() != &caller_function {
            return Err(invalid_presentation_target(
                call,
                "terminal caller function identity disagrees with its data",
            ));
        }
        (caller.id().erase(), caller_scope.clone(), caller_function)
    };
    Ok(PanicCallPresentationFunction::new(
        endpoint, scope, function,
    ))
}

fn invalid_presentation_scope_authority(
    source: &DefiningScopeMapError,
) -> CompilerAssertInputError {
    CompilerAssertInputError::InvalidResolvedInput {
        reason: format!("panic-call presentation scope authority is invalid: {source}"),
    }
}

fn required_presentation_description(
    call: PanicCallInputId,
    description: Option<&str>,
) -> Result<&str, CompilerAssertInputError> {
    description
        .filter(|description| !description.is_empty())
        .ok_or_else(|| {
            invalid_presentation_target(call, "opaque presentation description is missing")
        })
}

fn invalid_presentation_target(
    call: PanicCallInputId,
    reason: impl Display,
) -> CompilerAssertInputError {
    CompilerAssertInputError::InvalidResolvedInput {
        reason: format!(
            "panic call input {} has an invalid presentation target: {reason}",
            call.index()
        ),
    }
}

/// Additive panic-wide wrapper over the existing compiler-assert authority.
#[derive(Clone, Debug)]
pub(crate) struct PanicRootInputs {
    compiler_asserts: CompilerAssertRootInputs,
    calls: Vec<PanicCallInput>,
    evidence_order: Vec<RankedPanicWitness>,
}

impl PanicRootInputs {
    #[must_use]
    pub(in crate::analysis::facts) const fn workspace_identity(&self) -> &Arc<WorkspaceIdentity> {
        self.compiler_asserts.workspace_identity()
    }

    #[must_use]
    pub(crate) fn belongs_to(&self, workspace: &WorkspaceFactView<'_>) -> bool {
        self.compiler_asserts.belongs_to(workspace)
    }

    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        self.compiler_asserts.root()
    }

    #[must_use]
    pub(crate) fn traversal(&self) -> &ResolvedRootProgramTraversal<CompilerAssertBoundary> {
        self.compiler_asserts.traversal()
    }

    #[must_use]
    pub(crate) const fn compiler_asserts(&self) -> &CompilerAssertRootInputs {
        &self.compiler_asserts
    }

    #[must_use]
    pub(crate) const fn call_count(&self) -> usize {
        self.calls.len()
    }

    #[must_use]
    pub(crate) fn calls(
        &self,
    ) -> impl ExactSizeIterator<Item = Result<PanicCallInputView<'_>, CompilerAssertInputError>>
    {
        self.calls.iter().map(|input| {
            let boundary = self
                .compiler_asserts
                .traversal
                .call_boundaries()
                .get(input.boundary_index)
                .ok_or_else(|| CompilerAssertInputError::InvalidResolvedInput {
                    reason: format!(
                        "panic call input {} references missing boundary {}",
                        input.id.index(),
                        input.boundary_index
                    ),
                })?;
            let evidence_group = boundary_evidence_group(boundary.payload()).ok_or_else(|| {
                CompilerAssertInputError::InvalidResolvedInput {
                    reason: format!(
                        "panic call input {} references a non-obligation boundary",
                        input.id.index()
                    ),
                }
            })?;
            Ok(PanicCallInputView {
                input,
                boundary,
                evidence_group,
            })
        })
    }

    #[must_use]
    pub(crate) fn evidence_order(&self) -> &[RankedPanicWitness] {
        &self.evidence_order
    }

    pub(crate) fn validate_retained_call_invariants(&self) -> Result<(), CompilerAssertInputError> {
        let reconciled_groups = expected_reconciliation_groups(&self.compiler_asserts);
        let mut expected = Vec::new();
        for (boundary_index, boundary) in self
            .compiler_asserts
            .traversal
            .call_boundaries()
            .iter()
            .enumerate()
        {
            if let Some(kind) = retained_obligation_kind(boundary)? {
                expected.push((boundary_index, boundary, kind));
            }
        }
        expected.sort_unstable_by_key(|(_, boundary, _)| boundary.order());
        if expected.len() != self.calls.len() {
            return Err(CompilerAssertInputError::InvalidResolvedInput {
                reason: String::from(
                    "panic call inputs are not a bijection over retained obligation boundaries",
                ),
            });
        }
        for (expected_id, (input, (boundary_index, boundary, expected_kind))) in
            self.calls.iter().zip(expected).enumerate()
        {
            if input.id.index() != expected_id || input.boundary_index != boundary_index {
                return Err(CompilerAssertInputError::InvalidResolvedInput {
                    reason: String::from(
                        "panic call indexes are not a dense ordered boundary bijection",
                    ),
                });
            }
            if input.traversal_order != boundary.order() {
                return Err(CompilerAssertInputError::InvalidResolvedInput {
                    reason: format!(
                        "panic call input {} traversal order disagrees with its boundary",
                        input.id.index()
                    ),
                });
            }
            if input.kind != expected_kind {
                return Err(CompilerAssertInputError::InvalidResolvedInput {
                    reason: format!(
                        "panic call input {} kind disagrees with its boundary payload",
                        input.id.index()
                    ),
                });
            }
            let group = boundary_evidence_group(boundary.payload()).ok_or_else(|| {
                CompilerAssertInputError::InvalidResolvedInput {
                    reason: format!(
                        "panic call input {} references a non-obligation boundary",
                        input.id.index()
                    ),
                }
            })?;
            if !evidence_group_matches_expected(
                group,
                boundary.call_site(),
                boundary.call_site_data(),
                reconciled_groups.get(boundary.occurrence()),
            ) {
                return Err(CompilerAssertInputError::InvalidResolvedInput {
                    reason: format!(
                        "panic call input {} evidence group disagrees with reconciliation",
                        input.id.index()
                    ),
                });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn test_set_evidence_traversal_order(
        &mut self,
        index: usize,
        traversal_order: u64,
    ) -> bool {
        let Some(witness) = self.evidence_order.get_mut(index) else {
            return false;
        };
        witness.traversal_order = traversal_order;
        true
    }

    #[cfg(test)]
    pub(super) fn test_swap_evidence_witnesses(&mut self, first: usize, second: usize) -> bool {
        if first >= self.evidence_order.len() || second >= self.evidence_order.len() {
            return false;
        }
        let first_witness = self.evidence_order[first].witness;
        self.evidence_order[first].witness = self.evidence_order[second].witness;
        self.evidence_order[second].witness = first_witness;
        true
    }

    #[cfg(test)]
    pub(super) fn test_set_call_kind(&mut self, index: usize, kind: PanicCallInputKind) -> bool {
        let Some(call) = self.calls.get_mut(index) else {
            return false;
        };
        call.kind = kind;
        true
    }

    #[cfg(test)]
    pub(super) fn test_set_call_trace(&mut self, index: usize, trace: RelationTrace) -> bool {
        let Some(call) = self.calls.get_mut(index) else {
            return false;
        };
        call.trace_override = Some(trace);
        true
    }

    #[cfg(test)]
    pub(super) fn test_clear_call_metadata_target_data(&mut self, index: usize) -> bool {
        let Some(call) = self.calls.get_mut(index) else {
            return false;
        };
        call.clear_metadata_target_data = true;
        true
    }

    #[cfg(test)]
    pub(super) fn test_reverse_call_markers(&mut self, index: usize) -> bool {
        let Some(input) = self.calls.get(index) else {
            return false;
        };
        let Some(boundary) = self
            .compiler_asserts
            .traversal
            .call_boundaries()
            .get(input.boundary_index)
        else {
            return false;
        };
        let mut markers = boundary.active_markers().to_vec();
        if markers.len() < 2 {
            return false;
        }
        markers.reverse();
        self.calls[index].markers_override = Some(markers);
        true
    }

    #[cfg(test)]
    pub(super) fn test_duplicate_call_marker(&mut self, index: usize) -> bool {
        let Some(input) = self.calls.get(index) else {
            return false;
        };
        let Some(boundary) = self
            .compiler_asserts
            .traversal
            .call_boundaries()
            .get(input.boundary_index)
        else {
            return false;
        };
        let mut markers = boundary.active_markers().to_vec();
        let Some(first) = markers.first().cloned() else {
            return false;
        };
        markers.push(first);
        self.calls[index].markers_override = Some(markers);
        true
    }

    #[cfg(test)]
    pub(super) fn test_set_call_boundary_index(
        &mut self,
        index: usize,
        boundary_index: usize,
    ) -> bool {
        let Some(call) = self.calls.get_mut(index) else {
            return false;
        };
        call.boundary_index = boundary_index;
        true
    }

    #[cfg(test)]
    pub(super) fn test_drop_last_call_and_witness(&mut self) -> bool {
        let Some(call) = self.calls.pop() else {
            return false;
        };
        let witness = PanicWitnessId::Call(call.id);
        self.evidence_order
            .retain(|ranked| ranked.witness != witness);
        for (rank, ranked) in self.evidence_order.iter_mut().enumerate() {
            ranked.rank = PanicEvidenceRank(rank);
        }
        true
    }

    #[cfg(test)]
    pub(super) fn test_set_assertion_trace(&mut self, index: usize, trace: RelationTrace) -> bool {
        let Some(assertion) = self.compiler_asserts.test_assertion_mut(index) else {
            return false;
        };
        assertion.test_set_trace(trace);
        true
    }
}

fn retained_boundary_kind(
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        CompilerAssertBoundary,
    >,
) -> Result<PanicCallInputKind, CompilerAssertInputError> {
    match boundary.payload() {
        CompilerAssertBoundary::PanicContract(PanicContractBoundary::Call(payload)) => {
            validate_contract_boundary(payload)?;
            Ok(PanicCallInputKind::Documented {
                trusted: payload.trusted,
            })
        }
        CompilerAssertBoundary::PanicSink(context) if context.opaque.is_none() => {
            Ok(PanicCallInputKind::PanicSink)
        }
        CompilerAssertBoundary::BodylessDeclaration(context) => context
            .opaque
            .as_ref()
            .filter(|opaque| opaque.kind == PanicOpaqueBoundaryKind::BodylessDeclaration)
            .map(|opaque| PanicCallInputKind::Opaque { kind: opaque.kind })
            .ok_or_else(|| CompilerAssertInputError::InvalidResolvedInput {
                reason: String::from("bodyless panic boundary lost its exact subtype"),
            }),
        CompilerAssertBoundary::OpaqueCall(context) => context
            .opaque
            .as_ref()
            .filter(|opaque| opaque.kind == PanicOpaqueBoundaryKind::ExplicitOpaque)
            .map(|opaque| PanicCallInputKind::Opaque { kind: opaque.kind })
            .ok_or_else(|| CompilerAssertInputError::InvalidResolvedInput {
                reason: String::from("opaque panic boundary lost its exact subtype"),
            }),
        CompilerAssertBoundary::PanicContract(PanicContractBoundary::Root { .. })
        | CompilerAssertBoundary::PanicSink(_)
        | CompilerAssertBoundary::TrustedNamespace
        | CompilerAssertBoundary::ForeignDeclaration => {
            Err(CompilerAssertInputError::InvalidResolvedInput {
                reason: String::from("panic call input references a non-obligation boundary"),
            })
        }
    }
}

fn retained_obligation_kind(
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        CompilerAssertBoundary,
    >,
) -> Result<Option<PanicCallInputKind>, CompilerAssertInputError> {
    match boundary.payload() {
        CompilerAssertBoundary::PanicContract(PanicContractBoundary::Call(_))
        | CompilerAssertBoundary::PanicSink(_) => retained_boundary_kind(boundary).map(Some),
        CompilerAssertBoundary::BodylessDeclaration(_) | CompilerAssertBoundary::OpaqueCall(_)
            if is_actual_call(boundary.effective_kind()) =>
        {
            retained_boundary_kind(boundary).map(Some)
        }
        CompilerAssertBoundary::PanicContract(PanicContractBoundary::Root { .. })
        | CompilerAssertBoundary::BodylessDeclaration(_)
        | CompilerAssertBoundary::OpaqueCall(_)
        | CompilerAssertBoundary::TrustedNamespace
        | CompilerAssertBoundary::ForeignDeclaration => Ok(None),
    }
}

/// Projection-neutral, workspace-branded compiler-assert inputs for one root.
#[derive(Clone, Debug)]
pub(crate) struct CompilerAssertRootInputs {
    traversal: ResolvedRootProgramTraversal<CompilerAssertBoundary>,
    assertions: Vec<ReachableCompilerAssertInput>,
}

impl CompilerAssertRootInputs {
    /// Returns the opaque identity of the exact workspace used to prepare
    /// these root inputs.
    #[must_use]
    pub(in crate::analysis::facts) const fn workspace_identity(&self) -> &Arc<WorkspaceIdentity> {
        self.traversal.workspace_identity()
    }

    #[must_use]
    pub(crate) fn belongs_to(&self, workspace: &WorkspaceFactView<'_>) -> bool {
        self.traversal.belongs_to(workspace)
    }

    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        self.traversal.root()
    }

    #[must_use]
    pub(crate) fn traversal(&self) -> &ResolvedRootProgramTraversal<CompilerAssertBoundary> {
        &self.traversal
    }

    #[must_use]
    pub(crate) fn assertions(&self) -> &[ReachableCompilerAssertInput] {
        &self.assertions
    }

    #[cfg(test)]
    pub(super) fn test_assertion_mut(
        &mut self,
        index: usize,
    ) -> Option<&mut ReachableCompilerAssertInput> {
        self.assertions.get_mut(index)
    }
}

/// All roots prepared atomically before any caller-owned composition mutation.
#[derive(Debug)]
pub(crate) struct PreparedCompilerAssertRootBatch {
    roots: Vec<PreparedCompilerAssertRoot>,
}

impl PreparedCompilerAssertRootBatch {
    /// Prepares local report roots from the verified closure root generation.
    ///
    /// Requests intentionally carry no scope: dependency bodies may be
    /// reached, but report roots must resolve in `closure.root_scope()`.
    pub(crate) fn prepare(
        workspace: &WorkspaceFactView<'_>,
        closure: &VerifiedWorkspaceClosure,
        panic: &PanicConfig,
        overrides: &ContractDocOverrides,
        requests: impl IntoIterator<Item = CompilerAssertRootRequest>,
    ) -> Result<Self, CompilerAssertInputError> {
        let requests = requests.into_iter().collect::<Vec<_>>();
        if requests.is_empty() {
            return Ok(Self { roots: Vec::new() });
        }
        let program = closure.program().clone();
        let defining_scopes = closure.defining_scopes_handle();
        let panic_contracts = Arc::new(
            WorkspaceEffectivePanicContracts::open(workspace, &program, overrides)
                .map_err(|source| CompilerAssertInputError::PanicContracts(Box::new(source)))?,
        );
        let safety_contracts = Arc::new(
            WorkspaceEffectiveSafetyContracts::open(workspace, &program, overrides)
                .map_err(|source| CompilerAssertInputError::SafetyContracts(Box::new(source)))?,
        );
        let assertions = Arc::new(
            WorkspaceMirAssertIndex::open(workspace, &program)
                .map_err(|source| CompilerAssertInputError::Assertions(Box::new(source)))?,
        );
        let mut roots = Vec::new();
        for request in requests {
            let traversal_request = request.traversal_request(closure.root_scope().clone());
            let mut policy =
                CompilerAssertTraversalPolicy::new(workspace, panic, panic_contracts.as_ref());
            let traversal = PreparedRootProgramTraversal::prepare(
                workspace,
                &program,
                defining_scopes.as_ref(),
                &traversal_request,
                &mut policy,
            )
            .map_err(|source| CompilerAssertInputError::Traversal(Box::new(source)))?;
            roots.push(PreparedCompilerAssertRoot {
                traversal,
                program: program.clone(),
                defining_scopes: Arc::clone(&defining_scopes),
                panic_contracts: Arc::clone(&panic_contracts),
                safety_contracts: Arc::clone(&safety_contracts),
                assertions: Arc::clone(&assertions),
            });
        }
        Ok(Self { roots })
    }

    #[must_use]
    pub(crate) fn into_roots(self) -> Vec<PreparedCompilerAssertRoot> {
        self.roots
    }
}

/// One symbolic root, ready to append only its program edges to a shared builder.
#[derive(Debug)]
pub(crate) struct PreparedCompilerAssertRoot {
    traversal: PreparedRootProgramTraversal<CompilerAssertBoundary, CompilerAssertPolicyError>,
    program: WorkspaceProgramIndex,
    defining_scopes: Arc<VerifiedDefiningScopeMap>,
    panic_contracts: Arc<WorkspaceEffectivePanicContracts>,
    safety_contracts: Arc<WorkspaceEffectiveSafetyContracts>,
    assertions: Arc<WorkspaceMirAssertIndex>,
}

impl PreparedCompilerAssertRoot {
    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        self.traversal.root()
    }

    pub(crate) fn emit(
        self,
        builder: &mut CompositionRelationBuilder<'_, '_>,
    ) -> Result<EmittedCompilerAssertRoot, CompilerAssertInputError> {
        let traversal = self
            .traversal
            .emit(builder)
            .map_err(|source| CompilerAssertInputError::Traversal(Box::new(source)))?;
        Ok(EmittedCompilerAssertRoot {
            traversal,
            program: self.program,
            defining_scopes: self.defining_scopes,
            panic_contracts: self.panic_contracts,
            safety_contracts: self.safety_contracts,
            assertions: self.assertions,
        })
    }
}

/// Emitted root awaiting exact graph-path resolution by the caller lifecycle.
#[derive(Debug)]
pub(crate) struct EmittedCompilerAssertRoot {
    traversal: EmittedRootProgramTraversal<CompilerAssertBoundary, CompilerAssertPolicyError>,
    program: WorkspaceProgramIndex,
    defining_scopes: Arc<VerifiedDefiningScopeMap>,
    panic_contracts: Arc<WorkspaceEffectivePanicContracts>,
    safety_contracts: Arc<WorkspaceEffectiveSafetyContracts>,
    assertions: Arc<WorkspaceMirAssertIndex>,
}

impl EmittedCompilerAssertRoot {
    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        self.traversal.root()
    }

    pub(crate) fn resolve(
        self,
        workspace: &WorkspaceFactView<'_>,
        graph: &WorkspaceRelationGraph,
        registry: &CompositionRelationRegistry,
    ) -> Result<CompilerAssertRootInputs, CompilerAssertInputError> {
        self.resolve_inner(workspace, graph, registry)
            .map(|(inputs, _, _)| inputs)
    }

    fn resolve_inner(
        self,
        workspace: &WorkspaceFactView<'_>,
        graph: &WorkspaceRelationGraph,
        registry: &CompositionRelationRegistry,
    ) -> Result<
        (
            CompilerAssertRootInputs,
            WorkspaceProgramIndex,
            Arc<VerifiedDefiningScopeMap>,
        ),
        CompilerAssertInputError,
    > {
        self.assertions
            .validate_workspace(workspace)
            .map_err(|source| CompilerAssertInputError::Assertions(Box::new(source)))?;
        self.safety_contracts
            .validate_workspace(workspace)
            .map_err(|source| CompilerAssertInputError::SafetyContracts(Box::new(source)))?;
        self.panic_contracts
            .validate_workspace(workspace)
            .map_err(|source| CompilerAssertInputError::PanicContracts(Box::new(source)))?;
        let traversal = self
            .traversal
            .resolve(graph, registry)
            .map_err(|source| CompilerAssertInputError::Traversal(Box::new(source)))?;
        let mut assertions = Vec::new();
        for visit in traversal.effect_visits() {
            let Some(assertion) = self
                .assertions
                .assertion_for_effect(workspace, visit.effect())
                .map_err(|source| CompilerAssertInputError::Assertions(Box::new(source)))?
            else {
                continue;
            };
            let scope = visit.effect().scope();
            let callable = self
                .program
                .exact_callable(scope, visit.site().function())
                .ok_or_else(|| CompilerAssertInputError::InvalidResolvedInput {
                    reason: format!(
                        "effect {:?} has no exact owning callable for {:?}",
                        visit.effect(),
                        visit.site().function()
                    ),
                })?;
            let function = self
                .program
                .exact_function(scope, visit.site().function())
                .ok_or_else(|| CompilerAssertInputError::InvalidResolvedInput {
                    reason: format!(
                        "effect {:?} has no exact owning function for {:?}",
                        visit.effect(),
                        visit.site().function()
                    ),
                })?;
            if assertion.owner() != visit.effect() || assertion.provenance() != &function.id() {
                return Err(CompilerAssertInputError::InvalidResolvedInput {
                    reason: format!(
                        "MIR assertion {:?} disagrees with resolved effect ownership",
                        assertion.source()
                    ),
                });
            }
            let kind = assertion.data().kind();
            if suppresses_safety_precondition(
                workspace,
                self.safety_contracts.as_ref(),
                callable,
                kind,
            )? {
                continue;
            }
            let order = u64::try_from(assertions.len())
                .map_err(|_| CompilerAssertInputError::WitnessOrderOverflow)?;
            let markers = visit
                .active_markers()
                .iter()
                .filter(|marker| {
                    matches!(marker.data().selector(), EvidenceClaimSelector::Unnamed)
                        && !marker.data().rationale().trim().is_empty()
                })
                .map(|marker| CompilerAssertMarkerInput {
                    claim: marker.claim().clone(),
                    data: marker.data().clone(),
                    trace: marker.trace().clone(),
                })
                .collect();
            assertions.push(ReachableCompilerAssertInput {
                id: CompilerAssertInputId(assertions.len()),
                order,
                visit_order: visit.order(),
                source: assertion.source().clone(),
                owner: assertion.owner().clone(),
                provenance: assertion.provenance().clone(),
                kind,
                requirements: assertion.requirements().to_vec(),
                source_anchors: visit.source_anchors().to_vec(),
                macro_frames: visit.macro_frames().to_vec(),
                markers,
                trace: visit.trace().clone(),
            });
        }
        Ok((
            CompilerAssertRootInputs {
                traversal,
                assertions,
            },
            self.program,
            self.defining_scopes,
        ))
    }

    pub(crate) fn resolve_panic(
        self,
        workspace: &WorkspaceFactView<'_>,
        graph: &WorkspaceRelationGraph,
        registry: &CompositionRelationRegistry,
    ) -> Result<PanicRootInputs, CompilerAssertInputError> {
        let (compiler_asserts, program, defining_scopes) =
            self.resolve_inner(workspace, graph, registry)?;
        let presentation_scopes = defining_scopes
            .presentation_function_scopes(workspace, &program)
            .map_err(|source| invalid_presentation_scope_authority(&source))?;
        let reconciliation_groups = expected_reconciliation_groups(&compiler_asserts);
        let mut boundaries = compiler_asserts
            .traversal()
            .call_boundaries()
            .iter()
            .enumerate()
            .collect::<Vec<_>>();
        boundaries.sort_unstable_by_key(|(_, boundary)| boundary.order());
        let mut calls = Vec::new();
        for (boundary_index, boundary) in boundaries {
            let Some(kind) = retained_obligation_kind(boundary)? else {
                continue;
            };
            validate_call_boundary(
                &program,
                compiler_asserts.root(),
                boundary,
                reconciliation_groups.get(boundary.occurrence()),
            )?;
            let id = PanicCallInputId(calls.len());
            let presentation_function = resolve_panic_call_presentation_function(
                id,
                &program,
                &presentation_scopes,
                boundary,
            )?;
            calls.push(PanicCallInput {
                id,
                boundary_index,
                traversal_order: boundary.order(),
                kind,
                presentation_function,
                #[cfg(test)]
                clear_metadata_target_data: false,
                #[cfg(test)]
                markers_override: None,
                #[cfg(test)]
                trace_override: None,
            });
        }
        let mut ranked = compiler_asserts
            .assertions()
            .iter()
            .map(|assertion| {
                (
                    assertion.visit_order(),
                    PanicWitnessId::CompilerAssert(assertion.id()),
                )
            })
            .collect::<Vec<_>>();
        ranked.extend(
            calls
                .iter()
                .map(|call| (call.traversal_order, PanicWitnessId::Call(call.id))),
        );
        ranked.sort_unstable_by_key(|(order, witness)| (*order, *witness));
        for pair in ranked.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(CompilerAssertInputError::DuplicateTraversalOrder { order: pair[0].0 });
            }
        }
        let evidence_order = ranked
            .into_iter()
            .enumerate()
            .map(|(rank, (traversal_order, witness))| RankedPanicWitness {
                rank: PanicEvidenceRank(rank),
                traversal_order,
                witness,
            })
            .collect();
        Ok(PanicRootInputs {
            compiler_asserts,
            calls,
            evidence_order,
        })
    }
}

fn validate_contract_boundary(
    boundary: &PanicContractCallBoundary,
) -> Result<(), CompilerAssertInputError> {
    if boundary.contract().queried_callable() != boundary.contract_target().callable() {
        return Err(CompilerAssertInputError::InvalidResolvedInput {
            reason: String::from(
                "panic contract queried callable disagrees with its selected call target",
            ),
        });
    }
    Ok(())
}

fn boundary_evidence_group(boundary: &CompilerAssertBoundary) -> Option<&PanicEvidenceGroup> {
    match boundary {
        CompilerAssertBoundary::PanicContract(PanicContractBoundary::Call(payload)) => {
            Some(&payload.evidence_group)
        }
        CompilerAssertBoundary::PanicSink(context)
        | CompilerAssertBoundary::BodylessDeclaration(context)
        | CompilerAssertBoundary::OpaqueCall(context) => Some(&context.evidence_group),
        CompilerAssertBoundary::PanicContract(PanicContractBoundary::Root { .. })
        | CompilerAssertBoundary::TrustedNamespace
        | CompilerAssertBoundary::ForeignDeclaration => None,
    }
}

fn validate_call_metadata_target(
    program: &WorkspaceProgramIndex,
    target: Option<&CallTargetSelection>,
    data: Option<&CallableEntity>,
) -> Result<(), CompilerAssertInputError> {
    match (target, data) {
        (Some(target), Some(data)) => {
            let indexed = program
                .exact_callable(target.callable().scope(), data.key())
                .ok_or_else(|| CompilerAssertInputError::InvalidResolvedInput {
                    reason: String::from("panic call metadata target is not indexed"),
                })?;
            if indexed.id() != *target.callable() || indexed.data() != data {
                return Err(CompilerAssertInputError::InvalidResolvedInput {
                    reason: String::from(
                        "panic call metadata target identity disagrees with its data",
                    ),
                });
            }
            Ok(())
        }
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => Err(CompilerAssertInputError::InvalidResolvedInput {
            reason: String::from("panic call metadata target identity and data are not paired"),
        }),
    }
}

fn validate_call_boundary(
    program: &WorkspaceProgramIndex,
    root: &EvaluationRoot,
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        CompilerAssertBoundary,
    >,
    reconciled_group: Option<&Option<PanicEvidenceGroup>>,
) -> Result<(), CompilerAssertInputError> {
    if boundary.trace().root() != &root.entity {
        return Err(CompilerAssertInputError::InvalidResolvedInput {
            reason: String::from("panic call trace belongs to a different root"),
        });
    }
    if boundary.occurrence().scope() != boundary.call_site().scope() {
        return Err(CompilerAssertInputError::InvalidResolvedInput {
            reason: String::from("panic call occurrence and consumer call site cross scopes"),
        });
    }
    validate_call_metadata_target(program, boundary.target(), boundary.target_data())?;
    let expected_trace_target = boundary.target().map_or_else(
        || boundary.occurrence().erase(),
        |target| target.callable().erase(),
    );
    if boundary.trace().target() != &expected_trace_target {
        return Err(CompilerAssertInputError::InvalidResolvedInput {
            reason: String::from(
                "panic call trace target disagrees with its selected metadata target",
            ),
        });
    }
    let group = boundary_evidence_group(boundary.payload()).ok_or_else(|| {
        CompilerAssertInputError::InvalidResolvedInput {
            reason: String::from("panic call obligation lost its evidence group"),
        }
    })?;
    let indexed = program
        .exact_call_site(group.call_site.scope(), group.data.key())
        .ok_or_else(|| CompilerAssertInputError::InvalidResolvedInput {
            reason: String::from("panic evidence group call site is not indexed"),
        })?;
    if indexed.id() != group.call_site || indexed.data() != &group.data {
        return Err(CompilerAssertInputError::InvalidResolvedInput {
            reason: String::from("panic evidence group identity disagrees with its data"),
        });
    }
    if !evidence_group_matches_expected(
        group,
        boundary.call_site(),
        boundary.call_site_data(),
        reconciled_group,
    ) {
        return Err(CompilerAssertInputError::InvalidResolvedInput {
            reason: String::from("panic evidence group disagrees with call reconciliation"),
        });
    }
    Ok(())
}

fn evidence_group_matches_expected(
    retained: &PanicEvidenceGroup,
    consumer: &ScopedEntityId<CallSiteEntity>,
    consumer_data: &CallSiteEntity,
    reconciled: Option<&Option<PanicEvidenceGroup>>,
) -> bool {
    reconciled.and_then(Option::as_ref).map_or_else(
        || retained.call_site == *consumer && retained.data == *consumer_data,
        |expected| retained == expected,
    )
}

fn expected_reconciliation_groups(
    inputs: &CompilerAssertRootInputs,
) -> BTreeMap<ScopedEntityId<CallOccurrenceEntity>, Option<PanicEvidenceGroup>> {
    let mut grouped = BTreeMap::<
        ScopedEntityId<CallOccurrenceEntity>,
        Vec<(&ScopedEntityId<CallSiteEntity>, &CallSiteEntity)>,
    >::new();
    for reconciliation in inputs.traversal().consumer_reconciliations() {
        grouped
            .entry(reconciliation.consumer().clone())
            .or_default()
            .push((
                reconciliation.defining_call_site(),
                reconciliation.defining_call_site_data(),
            ));
    }
    grouped
        .into_iter()
        .map(|(consumer, candidates)| (consumer, shared_call_site(candidates.into_iter())))
        .collect()
}

fn suppresses_safety_precondition(
    workspace: &WorkspaceFactView<'_>,
    safety_contracts: &WorkspaceEffectiveSafetyContracts,
    callable: &ScopedProgramEntity<CallableEntity>,
    kind: MirAssertKind,
) -> Result<bool, CompilerAssertInputError> {
    if !callable.data().is_unsafe()
        || !matches!(
            kind,
            MirAssertKind::NullPointerDereference
                | MirAssertKind::MisalignedPointerDereference
                | MirAssertKind::InvalidEnumConstruction
        )
    {
        return Ok(false);
    }
    safety_contracts
        .has_effective_safety_contract(workspace, &callable.id())
        .map_err(|source| CompilerAssertInputError::SafetyContracts(Box::new(source)))
}

/// Fatal integrity failure before immutable compiler-assert inputs exist.
#[derive(Debug)]
pub(crate) enum CompilerAssertInputError {
    PanicContracts(Box<WorkspaceEffectivePanicContractsError>),
    SafetyContracts(Box<WorkspaceEffectiveSafetyContractsError>),
    Assertions(Box<WorkspaceMirAssertIndexError>),
    Traversal(Box<RootProgramTraversalError<CompilerAssertPolicyError>>),
    InvalidResolvedInput { reason: String },
    DuplicateTraversalOrder { order: u64 },
    WitnessOrderOverflow,
}

impl Display for CompilerAssertInputError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PanicContracts(source) => Display::fmt(source, formatter),
            Self::SafetyContracts(source) => Display::fmt(source, formatter),
            Self::Assertions(source) => Display::fmt(source, formatter),
            Self::Traversal(source) => Display::fmt(source, formatter),
            Self::InvalidResolvedInput { reason } => {
                write!(
                    formatter,
                    "invalid resolved compiler-assert input: {reason}"
                )
            }
            Self::DuplicateTraversalOrder { order } => {
                write!(formatter, "panic witnesses repeat traversal order {order}")
            }
            Self::WitnessOrderOverflow => {
                formatter.write_str("compiler-assert witness order exceeds u64")
            }
        }
    }
}

impl Error for CompilerAssertInputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PanicContracts(source) => Some(source),
            Self::SafetyContracts(source) => Some(source),
            Self::Assertions(source) => Some(source),
            Self::Traversal(source) => Some(source),
            Self::InvalidResolvedInput { .. }
            | Self::DuplicateTraversalOrder { .. }
            | Self::WitnessOrderOverflow => None,
        }
    }
}

/// Exact callable selected from one policy authority lane.
struct EffectiveTarget<'a> {
    callable: &'a ScopedProgramEntity<CallableEntity>,
    selection: CallTargetSelection,
}

struct EffectivePanicContractTarget {
    contract: Arc<EffectivePanicContract>,
    selection: CallTargetSelection,
}

/// Panic reachability policy shared by raw and evidence-resolved calls.
pub(crate) struct CompilerAssertTraversalPolicy<'workspace, 'facts> {
    workspace: &'workspace WorkspaceFactView<'facts>,
    panic: &'workspace PanicConfig,
    contracts: &'workspace WorkspaceEffectivePanicContracts,
}

impl<'workspace, 'facts> CompilerAssertTraversalPolicy<'workspace, 'facts> {
    #[must_use]
    pub(crate) const fn new(
        workspace: &'workspace WorkspaceFactView<'facts>,
        panic: &'workspace PanicConfig,
        contracts: &'workspace WorkspaceEffectivePanicContracts,
    ) -> Self {
        Self {
            workspace,
            panic,
            contracts,
        }
    }

    fn effective_contract(
        &self,
        callable: &ScopedProgramEntity<CallableEntity>,
    ) -> Result<Option<Arc<EffectivePanicContract>>, CompilerAssertPolicyError> {
        self.contracts
            .effective_panic_contract(self.workspace, &callable.id())
            .map_err(CompilerAssertPolicyError::PanicContracts)
    }

    fn call_contract_target(
        &self,
        context: &CallPolicyContext<'_>,
    ) -> Result<Option<EffectivePanicContractTarget>, CompilerAssertPolicyError> {
        if let Some(reconciliation) = &context.reconciliation {
            for target in &reconciliation.contract_targets {
                if let Some(contract) = self.effective_contract(target.callable)? {
                    return Ok(Some(EffectivePanicContractTarget {
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
            return Ok(Some(EffectivePanicContractTarget {
                contract,
                selection: source.selection(),
            }));
        }
        let raw = effective_raw_target(context.targets);
        if let Some(raw) = &raw
            && let Some(contract) = self.effective_contract(raw.callable)?
        {
            return Ok(Some(EffectivePanicContractTarget {
                contract,
                selection: raw.selection.clone(),
            }));
        }
        Ok(None)
    }

    fn decide_targeted_call(
        &self,
        context: &CallPolicyContext<'_>,
        metadata: EffectiveTarget<'_>,
    ) -> Result<CallTraversalDecision<CompilerAssertBoundary>, CompilerAssertPolicyError> {
        let attributes = metadata.callable.data();
        if self
            .panic
            .ignores_candidates(attributes.namespace_candidates())
        {
            return Ok(CallTraversalDecision::Ignore);
        }

        let namespace_policy = self
            .panic
            .panic_boundary_policy_candidates(attributes.namespace_candidates());
        if namespace_policy == PanicBoundaryPolicy::PanicSink {
            return Ok(call_boundary(
                metadata.selection,
                CompilerAssertBoundary::PanicSink(panic_call_context(context, None)),
            ));
        }
        if let Some(contract_target) = self.call_contract_target(context)? {
            return Ok(call_boundary(
                metadata.selection,
                CompilerAssertBoundary::PanicContract(PanicContractBoundary::Call(
                    PanicContractCallBoundary {
                        contract: contract_target.contract,
                        contract_target: contract_target.selection,
                        evidence_group: reconciled_panic_evidence_group(context),
                        trusted: namespace_policy == PanicBoundaryPolicy::TrustedBoundary,
                    },
                )),
            ));
        }
        if namespace_policy == PanicBoundaryPolicy::TrustedBoundary {
            return Ok(call_boundary(
                metadata.selection,
                CompilerAssertBoundary::TrustedNamespace,
            ));
        }
        if attributes.is_foreign() {
            return Ok(call_boundary(
                metadata.selection,
                CompilerAssertBoundary::ForeignDeclaration,
            ));
        }
        if !attributes.has_rust_body() {
            return Ok(call_boundary(
                metadata.selection,
                CompilerAssertBoundary::BodylessDeclaration(panic_call_context(
                    context,
                    Some(PanicOpaqueBoundary {
                        kind: PanicOpaqueBoundaryKind::BodylessDeclaration,
                        description: format!(
                            "indirect call to undocumented trait method `{}`",
                            attributes.display_path()
                        ),
                    }),
                )),
            ));
        }
        if matches!(&context.resolution, ProgramCallResolution::Persisted)
            && let Some(description) = context.occurrence.data().opaque_target_description()
        {
            return Ok(call_boundary(
                metadata.selection,
                CompilerAssertBoundary::OpaqueCall(panic_call_context(
                    context,
                    Some(PanicOpaqueBoundary {
                        kind: PanicOpaqueBoundaryKind::ExplicitOpaque,
                        description: description.to_owned(),
                    }),
                )),
            ));
        }
        Ok(CallTraversalDecision::Follow(metadata.selection))
    }
}

impl RootProgramTraversalPolicy for CompilerAssertTraversalPolicy<'_, '_> {
    type Error = CompilerAssertPolicyError;
    type Boundary = CompilerAssertBoundary;

    fn decide_call(
        &mut self,
        context: &CallPolicyContext<'_>,
    ) -> Result<CallTraversalDecision<Self::Boundary>, Self::Error> {
        effective_metadata_target(context).map_or_else(
            || Ok(targetless_call_decision(context)),
            |metadata| self.decide_targeted_call(context, metadata),
        )
    }

    fn decide_body(
        &mut self,
        context: &BodyPolicyContext<'_>,
    ) -> Result<BodyTraversalDecision<Self::Boundary>, Self::Error> {
        let attributes = context.callable.data();
        if self
            .panic
            .ignores_candidates(attributes.namespace_candidates())
        {
            return Ok(BodyTraversalDecision::Ignore);
        }
        if context.is_root {
            if let Some(contract) = self.effective_contract(context.callable)? {
                return Ok(BodyTraversalDecision::Boundary(
                    CompilerAssertBoundary::PanicContract(PanicContractBoundary::Root { contract }),
                ));
            }
            if self
                .panic
                .panic_boundary_policy_candidates(attributes.namespace_candidates())
                == PanicBoundaryPolicy::TrustedBoundary
            {
                return Ok(BodyTraversalDecision::Boundary(
                    CompilerAssertBoundary::TrustedNamespace,
                ));
            }
        }
        Ok(BodyTraversalDecision::Expand)
    }

    fn defining_markers(
        &mut self,
        context: &DefiningMarkerPolicyContext<'_>,
    ) -> Result<DefiningMarkerDecision, Self::Error> {
        Ok(if shared_defining_call_site(context.candidates).is_some() {
            DefiningMarkerDecision::UseCompleteSet
        } else {
            DefiningMarkerDecision::RejectCompleteSet
        })
    }
}

fn panic_call_context(
    context: &CallPolicyContext<'_>,
    opaque: Option<PanicOpaqueBoundary>,
) -> PanicCallBoundaryContext {
    PanicCallBoundaryContext {
        evidence_group: reconciled_panic_evidence_group(context),
        opaque,
    }
}

fn targetless_call_decision(
    context: &CallPolicyContext<'_>,
) -> CallTraversalDecision<CompilerAssertBoundary> {
    let Some(description) = context.occurrence.data().opaque_target_description() else {
        return CallTraversalDecision::Ignore;
    };
    if !is_actual_call(context.effective_kind) {
        return CallTraversalDecision::Ignore;
    }
    CallTraversalDecision::Boundary {
        target: None,
        payload: CompilerAssertBoundary::OpaqueCall(panic_call_context(
            context,
            Some(PanicOpaqueBoundary {
                kind: PanicOpaqueBoundaryKind::ExplicitOpaque,
                description: description.to_owned(),
            }),
        )),
    }
}

fn reconciled_panic_evidence_group(context: &CallPolicyContext<'_>) -> PanicEvidenceGroup {
    context
        .reconciliation
        .as_ref()
        .and_then(|reconciliation| shared_defining_call_site(reconciliation.candidates))
        .unwrap_or_else(|| PanicEvidenceGroup {
            call_site: context.call_site.id(),
            data: context.call_site.data().clone(),
        })
}

fn shared_defining_call_site(candidates: &[DefiningMarkerCandidate]) -> Option<PanicEvidenceGroup> {
    shared_call_site(
        candidates
            .iter()
            .map(|candidate| (&candidate.call_site, &candidate.call_site_data)),
    )
}

#[cfg(test)]
fn test_shared_defining_call_site(
    candidates: &[(ScopedEntityId<CallSiteEntity>, CallSiteEntity)],
) -> Option<PanicEvidenceGroup> {
    shared_call_site(candidates.iter().map(|(id, data)| (id, data)))
}

fn shared_call_site<'a>(
    mut candidates: impl Iterator<Item = (&'a ScopedEntityId<CallSiteEntity>, &'a CallSiteEntity)>,
) -> Option<PanicEvidenceGroup> {
    let (first_id, first_data) = candidates.next()?;
    candidates
        .all(|(call_site, data)| call_site == first_id && data == first_data)
        .then(|| PanicEvidenceGroup {
            call_site: first_id.clone(),
            data: first_data.clone(),
        })
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
    match kind {
        CallKind::DirectCall
        | CallKind::TailCall
        | CallKind::FnPointerCallTarget
        | CallKind::DynDispatchVTableEntry
        | CallKind::IndirectCall => true,
        CallKind::FnPointerReify
        | CallKind::ClosureFnPointerReify
        | CallKind::DynObjectCast
        | CallKind::VTableEntry
        | CallKind::MacroExpansion
        | CallKind::ConstBody
        | CallKind::CoroutineBody
        | CallKind::Assert => false,
    }
}

const fn call_boundary(
    target: CallTargetSelection,
    payload: CompilerAssertBoundary,
) -> CallTraversalDecision<CompilerAssertBoundary> {
    CallTraversalDecision::Boundary {
        target: Some(target),
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CompilerAssertBoundary, CompilerAssertInputError, CompilerAssertRootRequest,
        PanicCallInputId, PanicContractBoundary, PreparedCompilerAssertRootBatch,
        effective_persisted_metadata_target, is_actual_call,
        project_panic_call_presentation_function, raw_role_precedence,
        resolve_panic_call_presentation_target, test_shared_defining_call_site,
    };
    use crate::analysis::cache::RustcArtifactId;
    use crate::analysis::facts::builder::{ArtifactDbBuilder, FactMeta};
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::composition::{CompositionRelationBuilder, WorkspaceRelationGraph};
    use crate::analysis::facts::evaluation::DomainId;
    use crate::analysis::facts::human::EvidenceClaimSelector;
    use crate::analysis::facts::human::markers::{
        CallOccurrenceHasMarkerClaimCandidate, EffectSiteHasMarkerClaimCandidate,
        MarkerClaimEntity, MarkerClaimKey, MarkerOccurrenceEntity, MarkerOccurrenceHasClaim,
        MarkerOccurrenceHasSourceAnchor, MarkerOccurrenceKey,
    };
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::panic::contracts::{PanicContractFact, PanicRequirement};
    use crate::analysis::facts::panic::model::{
        InBoundsRequirement, MirAssertFact, MirAssertKind, NonNullPointerRequirement,
    };
    use crate::analysis::facts::program::root_traversal::{
        CallPolicyContext, CallTargetPolicyCandidate, CallTraversalDecision,
        DefiningScopeAuthority, MarkerProbe, ProgramCallResolution, ReconciledCallTargetAuthority,
        ReconciledCallTargetPolicyCandidate, RootProgramTraversalPolicy, StableCrateResolution,
        VerifiedDefiningScopeMap,
    };
    use crate::analysis::facts::program::topology::{
        CallAttributionRole, CallOccurrenceEntity, CallOccurrenceHasCallableKey,
        CallOccurrenceHasSourceAnchor, CallOccurrenceInSafetyEffectGroup, CallOccurrenceKey,
        CallOccurrenceTargetsCallable, CallSiteEntity, CallSiteHasOccurrence, CallSiteKey,
        CallSourceAnchorRole, CallableEntity, CallableKey, CallableKeyEntity,
        FunctionDefinesCallable, FunctionOwnsCallSite, FunctionOwnsSafetyEffectGroup,
        SafetyEffectGroupEntity, SafetyEffectGroupKey,
    };
    use crate::analysis::facts::program::topology::{CallKind, CallTargetRole};
    use crate::analysis::facts::program::workspace_index::{
        CallableResolutionKind, ScopedProgramEntity, VerifiedArtifactOwner, WorkspaceProgramIndex,
    };
    use crate::analysis::facts::program::{
        EffectSiteEntity, EffectSiteKey, FunctionBodyProvenance, FunctionEntity, FunctionKey,
        FunctionOwnsEffectSite, SourceAnchorEntity, SourceAnchorInFile, SourceAnchorKey,
        SourceFileEntity,
    };
    use crate::analysis::facts::safety::{SafetyContractFact, SafetyRequirement};
    use crate::analysis::facts::schema::{EntityHandle, EntityId, PassId, RowSchema};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::analysis::facts::workspace::{ArtifactScopeId, ScopedEntityId, WorkspaceFactView};
    use crate::analysis::workspace_closure::{
        ManagedArtifactGeneration, ManagedArtifactManifest, VerifiedWorkspaceClosure,
    };
    use crate::config::PanicConfig;
    use crate::contracts::ContractDocOverrides;
    use crate::namespace::{StableDefPathHash, StableInstanceHash, StableTypeHash};
    use crate::path_patterns::PathPatterns;
    use reachability::MirBodyLocation;

    #[test]
    fn only_runtime_invocations_are_actual_calls() {
        assert!(is_actual_call(CallKind::DirectCall));
        assert!(is_actual_call(CallKind::TailCall));
        assert!(is_actual_call(CallKind::IndirectCall));
        assert!(is_actual_call(CallKind::FnPointerCallTarget));
        assert!(is_actual_call(CallKind::DynDispatchVTableEntry));
        assert!(!is_actual_call(CallKind::FnPointerReify));
        assert!(!is_actual_call(CallKind::ClosureFnPointerReify));
        assert!(!is_actual_call(CallKind::DynObjectCast));
        assert!(!is_actual_call(CallKind::VTableEntry));
        assert!(!is_actual_call(CallKind::MacroExpansion));
        assert!(!is_actual_call(CallKind::ConstBody));
        assert!(!is_actual_call(CallKind::CoroutineBody));
        assert!(!is_actual_call(CallKind::Assert));
    }

    #[test]
    fn runtime_metadata_precedes_every_opaque_lane() {
        assert!(
            raw_role_precedence(CallTargetRole::Runtime)
                < raw_role_precedence(CallTargetRole::OpaqueTrait)
        );
        assert!(
            raw_role_precedence(CallTargetRole::OpaqueTrait)
                < raw_role_precedence(CallTargetRole::OpaqueFunction)
        );
    }

    #[test]
    fn source_only_persisted_target_is_effective_metadata() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let definition =
            serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000001\"")
                .unwrap();
        let callable_key = FunctionKey::new(definition, None);
        builder
            .insert_entity(&CallableEntity::new(
                callable_key,
                "crate::source_only",
                false,
                false,
                true,
                false,
                vec![String::from("crate::source_only")],
            ))
            .unwrap();
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
                .unwrap();
        let callable = program.exact_callable(&scope, &callable_key).unwrap();
        let targets = [CallTargetPolicyCandidate {
            role: CallTargetRole::SourceContract,
            callable,
        }];

        let effective = effective_persisted_metadata_target(&targets).unwrap();

        assert_eq!(effective.callable.id(), callable.id());
        assert_eq!(effective.selection.role(), CallTargetRole::SourceContract);
    }

    fn with_presentation_targets(
        test: impl FnOnce(
            &WorkspaceProgramIndex,
            &ScopedProgramEntity<CallableEntity>,
            &ScopedProgramEntity<CallableEntity>,
            &ScopedProgramEntity<CallableEntity>,
            ScopedEntityId<CallOccurrenceEntity>,
        ),
    ) {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let runtime_key = FunctionKey::new(matrix_definition(4), Some(matrix_instance(4)));
        let other_runtime_key = FunctionKey::new(matrix_definition(5), Some(matrix_instance(5)));
        let declaration_key = FunctionKey::new(matrix_definition(6), None);
        for (key, path) in [
            (runtime_key, "crate::runtime"),
            (other_runtime_key, "crate::other_runtime"),
            (declaration_key, "crate::declaration"),
        ] {
            builder
                .insert_entity(&CallableEntity::new(
                    key,
                    path,
                    false,
                    false,
                    true,
                    false,
                    vec![path.to_owned()],
                ))
                .unwrap();
        }
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
                .unwrap();
        let runtime = program.exact_callable(&scope, &runtime_key).unwrap();
        let other_runtime = program.exact_callable(&scope, &other_runtime_key).unwrap();
        let declaration = program.exact_callable(&scope, &declaration_key).unwrap();
        let evidence = ScopedEntityId::new(scope, EntityId::new(999));
        test(&program, runtime, other_runtime, declaration, evidence);
    }

    fn presentation_occurrence(description: Option<&str>) -> CallOccurrenceEntity {
        CallOccurrenceEntity::new(
            CallOccurrenceKey::new(FunctionKey::new(matrix_definition(11), None), 0),
            CallKind::IndirectCall,
            vec![CallAttributionRole::CallSite],
            false,
            false,
            description.map(str::to_owned),
        )
    }

    fn assert_presentation_target(
        resolution: &ProgramCallResolution,
        description: Option<&str>,
        selection: Option<&crate::analysis::facts::program::root_traversal::CallTargetSelection>,
        data: Option<&CallableEntity>,
        expected_callable: Option<&ScopedEntityId<CallableEntity>>,
        expected_description: Option<&str>,
    ) {
        let occurrence = presentation_occurrence(description);
        let target = super::resolve_panic_call_presentation_target(
            super::PanicCallInputId(0),
            resolution,
            &occurrence,
            selection,
            data,
        )
        .unwrap();
        assert_eq!(
            target
                .callable()
                .map(|callable| callable.selection().callable()),
            expected_callable
        );
        assert_eq!(target.opaque_description(), expected_description);
    }

    #[test]
    fn presentation_target_preserves_legacy_variants_and_fallback_rules() {
        with_presentation_targets(|_program, runtime, _other, declaration, evidence| {
            let persisted = ProgramCallResolution::Persisted;
            let callable_evidence = ProgramCallResolution::CallableEvidence {
                evidence,
                key: CallableKey::FnPointer(matrix_type(1)),
                kind: CallableResolutionKind::FunctionPointerEvidence,
            };
            let runtime_selection = CallTargetPolicyCandidate {
                role: CallTargetRole::Runtime,
                callable: runtime,
            }
            .selection();
            let opaque_selection = CallTargetPolicyCandidate {
                role: CallTargetRole::OpaqueTrait,
                callable: declaration,
            }
            .selection();
            let source_selection = CallTargetPolicyCandidate {
                role: CallTargetRole::SourceContract,
                callable: declaration,
            }
            .selection();
            let defining_selection = ReconciledCallTargetPolicyCandidate {
                authority: ReconciledCallTargetAuthority::DefiningTarget,
                role: CallTargetRole::Runtime,
                callable: runtime,
            }
            .selection();
            let runtime_id = runtime.id();
            let declaration_id = declaration.id();

            assert_presentation_target(
                &persisted,
                None,
                Some(&runtime_selection),
                Some(runtime.data()),
                Some(&runtime_id),
                None,
            );
            assert_presentation_target(
                &persisted,
                Some("raw opaque description"),
                Some(&opaque_selection),
                Some(declaration.data()),
                Some(&declaration_id),
                Some("raw opaque description"),
            );
            assert_presentation_target(
                &persisted,
                Some("source fallback"),
                Some(&source_selection),
                Some(declaration.data()),
                None,
                Some("source fallback"),
            );
            assert_presentation_target(
                &persisted,
                Some("defining fallback"),
                Some(&defining_selection),
                Some(runtime.data()),
                None,
                Some("defining fallback"),
            );
            assert_presentation_target(
                &callable_evidence,
                Some("raw function pointer"),
                Some(&runtime_selection),
                Some(runtime.data()),
                Some(&runtime_id),
                None,
            );
            assert_presentation_target(
                &persisted,
                Some("targetless opaque call"),
                None,
                None,
                None,
                Some("targetless opaque call"),
            );
        });
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the two-artifact fixture proves endpoint and semantic scope are independent"
    )]
    fn presentation_function_keeps_the_raw_endpoint_and_managed_generic_scope() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let definition = |stable_crate_id: u64, local: u64| {
            serde_json::from_str::<StableDefPathHash>(&format!(
                "\"{stable_crate_id:016x}{local:016x}\""
            ))
            .unwrap()
        };
        let caller = FunctionKey::new(definition(40, 1), None);
        let requested = FunctionKey::new(definition(41, 2), Some(matrix_instance(41)));
        let generic = FunctionKey::new(requested.definition(), None);

        let mut consumer = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            consumer.declare_table(descriptor).unwrap();
        }
        let caller_body = consumer
            .insert_entity(&FunctionEntity::new(
                caller,
                "crate::caller",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let caller_callable = consumer
            .insert_entity(&CallableEntity::new(
                caller,
                "crate::caller",
                false,
                false,
                true,
                false,
                vec![String::from("crate::caller")],
            ))
            .unwrap();
        consumer
            .relate(
                &caller_body,
                &caller_callable,
                &FunctionDefinesCallable::new(),
            )
            .unwrap();
        consumer
            .insert_entity(&CallableEntity::new(
                requested,
                "dependency::requested",
                false,
                false,
                false,
                false,
                vec![String::from("dependency::requested")],
            ))
            .unwrap();
        let consumer = consumer.finalize(registry.schemas()).unwrap();

        let mut defining = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            defining.declare_table(descriptor).unwrap();
        }
        let generic_body = defining
            .insert_entity(&FunctionEntity::new(
                generic,
                "dependency::generic",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let generic_callable = defining
            .insert_entity(&CallableEntity::new(
                generic,
                "dependency::generic",
                false,
                false,
                true,
                false,
                vec![String::from("dependency::generic")],
            ))
            .unwrap();
        defining
            .relate(
                &generic_body,
                &generic_callable,
                &FunctionDefinesCallable::new(),
            )
            .unwrap();
        let defining = defining.finalize(registry.schemas()).unwrap();

        let caller_scope = ArtifactScopeId::for_in_memory(40, 0);
        let defining_scope = ArtifactScopeId::for_in_memory(41, 0);
        let workspace = WorkspaceFactView::compose([
            (
                caller_scope.clone(),
                ArtifactDbView::open(&consumer, registry.schemas()).unwrap(),
            ),
            (
                defining_scope.clone(),
                ArtifactDbView::open(&defining, registry.schemas()).unwrap(),
            ),
        ])
        .unwrap();
        let program = WorkspaceProgramIndex::open(
            &workspace,
            [
                VerifiedArtifactOwner::new(caller_scope.clone(), 40),
                VerifiedArtifactOwner::new(defining_scope.clone(), 41),
            ],
        )
        .unwrap();
        let authority = VerifiedDefiningScopeMap::new(
            &workspace,
            &program,
            [DefiningScopeAuthority::new(
                caller_scope.clone(),
                41,
                StableCrateResolution::Managed(defining_scope.clone()),
            )],
        )
        .unwrap();
        let scopes = authority
            .presentation_function_scopes(&workspace, &program)
            .unwrap();
        let target = program.exact_callable(&caller_scope, &requested).unwrap();
        let selection = CallTargetPolicyCandidate {
            role: CallTargetRole::Runtime,
            callable: target,
        }
        .selection();
        let occurrence = CallOccurrenceEntity::new(
            CallOccurrenceKey::new(caller, 0),
            CallKind::IndirectCall,
            vec![CallAttributionRole::CallSite],
            false,
            false,
            None,
        );
        let call = PanicCallInputId(0);
        let presentation = resolve_panic_call_presentation_target(
            call,
            &ProgramCallResolution::Persisted,
            &occurrence,
            Some(&selection),
            Some(target.data()),
        )
        .unwrap();
        let projected = project_panic_call_presentation_function(
            call,
            &program,
            &scopes,
            &caller_scope,
            caller,
            presentation,
        )
        .unwrap();

        assert_eq!(projected.endpoint(), &target.id().erase());
        assert_eq!(projected.endpoint().scope(), &caller_scope);
        assert_eq!(projected.scope(), &defining_scope);
        assert_eq!(projected.function(), &requested);
        assert_ne!(projected.endpoint().scope(), projected.scope());

        let targetless_occurrence = CallOccurrenceEntity::new(
            CallOccurrenceKey::new(caller, 1),
            CallKind::IndirectCall,
            vec![CallAttributionRole::CallSite],
            false,
            false,
            Some(String::from("targetless opaque call")),
        );
        let targetless = resolve_panic_call_presentation_target(
            call,
            &ProgramCallResolution::Persisted,
            &targetless_occurrence,
            None,
            None,
        )
        .unwrap();
        let caller_projection = project_panic_call_presentation_function(
            call,
            &program,
            &scopes,
            &caller_scope,
            caller,
            targetless,
        )
        .unwrap();
        assert_eq!(
            caller_projection.endpoint(),
            &program
                .exact_function(&caller_scope, &caller)
                .unwrap()
                .id()
                .erase()
        );
        assert_eq!(caller_projection.scope(), &caller_scope);
        assert_eq!(caller_projection.function(), &caller);
    }

    #[test]
    fn presentation_target_rejects_malformed_selection_data_and_description() {
        with_presentation_targets(|program, runtime, other, declaration, _evidence| {
            let occurrence = presentation_occurrence(None);
            let runtime_selection = CallTargetPolicyCandidate {
                role: CallTargetRole::Runtime,
                callable: runtime,
            }
            .selection();
            let source_selection = CallTargetPolicyCandidate {
                role: CallTargetRole::SourceContract,
                callable: declaration,
            }
            .selection();
            for (selection, data) in [
                (Some(&runtime_selection), None),
                (Some(&runtime_selection), Some(declaration.data())),
                (Some(&source_selection), Some(declaration.data())),
            ] {
                assert!(matches!(
                    super::resolve_panic_call_presentation_target(
                        super::PanicCallInputId(0),
                        &ProgramCallResolution::Persisted,
                        &occurrence,
                        selection,
                        data,
                    ),
                    Err(CompilerAssertInputError::InvalidResolvedInput { .. })
                ));
            }
            assert!(matches!(
                super::validate_call_metadata_target(
                    program,
                    Some(&runtime_selection),
                    Some(other.data()),
                ),
                Err(CompilerAssertInputError::InvalidResolvedInput { .. })
            ));
        });
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the policy fixture keeps the synthetic target and targetless raw call distinct"
    )]
    fn callable_evidence_does_not_reapply_the_raw_opaque_boundary() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(matrix_definition(7), None);
        let target_key = FunctionKey::new(matrix_definition(8), Some(matrix_instance(8)));
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let root_body = builder
            .insert_entity(&FunctionEntity::new(
                root,
                "crate::root",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let root_callable = builder
            .insert_entity(&CallableEntity::new(
                root,
                "crate::root",
                false,
                false,
                true,
                false,
                vec![String::from("crate::root")],
            ))
            .unwrap();
        builder
            .relate(&root_body, &root_callable, &FunctionDefinesCallable::new())
            .unwrap();
        builder
            .insert_entity(&CallableEntity::new(
                target_key,
                "crate::resolved",
                false,
                false,
                true,
                false,
                vec![String::from("crate::resolved")],
            ))
            .unwrap();
        let call_site = builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(root, 0)))
            .unwrap();
        builder
            .relate(&root_body, &call_site, &FunctionOwnsCallSite::new())
            .unwrap();
        let occurrence = builder
            .insert_entity(&CallOccurrenceEntity::new(
                CallOccurrenceKey::new(root, 0),
                CallKind::IndirectCall,
                vec![CallAttributionRole::CallSite],
                false,
                false,
                Some(String::from("raw unresolved function pointer")),
            ))
            .unwrap();
        builder
            .relate(&call_site, &occurrence, &CallSiteHasOccurrence::new())
            .unwrap();
        let group = builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                root, 0,
            )))
            .unwrap();
        builder
            .relate(&root_body, &group, &FunctionOwnsSafetyEffectGroup::new())
            .unwrap();
        builder
            .relate(
                &occurrence,
                &group,
                &CallOccurrenceInSafetyEffectGroup::new(),
            )
            .unwrap();
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
                .unwrap();
        let target = program.exact_callable(&scope, &target_key).unwrap();
        let call_site = program
            .exact_call_site(&scope, &CallSiteKey::new(root, 0))
            .unwrap();
        let occurrence = program
            .exact_call_occurrence(&scope, &CallOccurrenceKey::new(root, 0))
            .unwrap();
        let group = program
            .exact_safety_group(&scope, &SafetyEffectGroupKey::new(root, 0))
            .unwrap();
        let contracts = super::WorkspaceEffectivePanicContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();
        let targets = [CallTargetPolicyCandidate {
            role: CallTargetRole::Runtime,
            callable: target,
        }];
        let panic = PanicConfig::default();
        let mut policy = super::CompilerAssertTraversalPolicy::new(&workspace, &panic, &contracts);

        let decision = policy
            .decide_call(&CallPolicyContext {
                call_site,
                occurrence,
                safety_group: group,
                effective_kind: CallKind::FnPointerCallTarget,
                targets: &targets,
                resolution: ProgramCallResolution::CallableEvidence {
                    evidence: occurrence.id(),
                    key: CallableKey::FnPointer(matrix_type(2)),
                    kind: CallableResolutionKind::FunctionPointerEvidence,
                },
                reconciliation: None,
                inherited_marker_claims: &[],
                attached_marker_candidates: &[],
                active_marker_claims: &[],
            })
            .unwrap();

        let CallTraversalDecision::Follow(selected) = decision else {
            panic!("callable evidence must replace, not reapply, the raw opaque boundary")
        };
        assert_eq!(selected.role(), CallTargetRole::Runtime);
        assert_eq!(
            selected.authority(),
            ReconciledCallTargetAuthority::ConsumerRaw
        );
        assert_eq!(selected.callable(), &target.id());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture separates metadata, contract, group, and requirement identities"
    )]
    fn source_contract_boundary_keeps_contract_target_separate_from_runtime_metadata() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(matrix_definition(1), None);
        let runtime_key = FunctionKey::new(matrix_definition(2), Some(matrix_instance(2)));
        let source_key = FunctionKey::new(matrix_definition(3), None);
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let root_body = builder
            .insert_entity(&FunctionEntity::new(
                root,
                "crate::root",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let root_callable = builder
            .insert_entity(&CallableEntity::new(
                root,
                "crate::root",
                false,
                false,
                true,
                false,
                vec![String::from("crate::root")],
            ))
            .unwrap();
        builder
            .relate(&root_body, &root_callable, &FunctionDefinesCallable::new())
            .unwrap();
        let runtime = builder
            .insert_entity(&CallableEntity::new(
                runtime_key,
                "crate::runtime",
                false,
                false,
                true,
                false,
                vec![String::from("crate::runtime")],
            ))
            .unwrap();
        let source = builder
            .insert_entity(&CallableEntity::new(
                source_key,
                "crate::source",
                false,
                false,
                true,
                false,
                vec![String::from("crate::source")],
            ))
            .unwrap();
        let source_requirement = builder
            .insert_requirement(&PanicRequirement::new(
                source_key,
                0,
                "source condition",
                "selected from the source contract",
                None,
            ))
            .unwrap();
        builder
            .insert_fact(
                &PanicContractFact::new(),
                FactMeta::new(PassId::new("test.panic-contract-boundary").unwrap())
                    .with_owner(&source)
                    .unwrap()
                    .with_requirement(&source_requirement)
                    .unwrap(),
            )
            .unwrap();
        let call_site = builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(root, 0)))
            .unwrap();
        builder
            .relate(&root_body, &call_site, &FunctionOwnsCallSite::new())
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
            .relate(&call_site, &occurrence, &CallSiteHasOccurrence::new())
            .unwrap();
        builder
            .relate(
                &occurrence,
                &runtime,
                &CallOccurrenceTargetsCallable::new(CallTargetRole::Runtime),
            )
            .unwrap();
        builder
            .relate(
                &occurrence,
                &source,
                &CallOccurrenceTargetsCallable::new(CallTargetRole::SourceContract),
            )
            .unwrap();
        let group = builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                root, 0,
            )))
            .unwrap();
        builder
            .relate(&root_body, &group, &FunctionOwnsSafetyEffectGroup::new())
            .unwrap();
        builder
            .relate(
                &occurrence,
                &group,
                &CallOccurrenceInSafetyEffectGroup::new(),
            )
            .unwrap();
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 1)])
                .unwrap();
        let runtime = program.exact_callable(&scope, &runtime_key).unwrap();
        let source = program.exact_callable(&scope, &source_key).unwrap();
        let call_site = program
            .exact_call_site(&scope, &CallSiteKey::new(root, 0))
            .unwrap();
        let occurrence = program
            .exact_call_occurrence(&scope, &CallOccurrenceKey::new(root, 0))
            .unwrap();
        let group = program
            .exact_safety_group(&scope, &SafetyEffectGroupKey::new(root, 0))
            .unwrap();
        let contracts = super::WorkspaceEffectivePanicContracts::open(
            &workspace,
            &program,
            &ContractDocOverrides::default(),
        )
        .unwrap();
        let targets = [
            CallTargetPolicyCandidate {
                role: CallTargetRole::Runtime,
                callable: runtime,
            },
            CallTargetPolicyCandidate {
                role: CallTargetRole::SourceContract,
                callable: source,
            },
        ];
        let panic = PanicConfig::default();
        let mut policy = super::CompilerAssertTraversalPolicy::new(&workspace, &panic, &contracts);
        let decision = policy
            .decide_call(&CallPolicyContext {
                call_site,
                occurrence,
                safety_group: group,
                effective_kind: CallKind::DirectCall,
                targets: &targets,
                resolution: ProgramCallResolution::Persisted,
                reconciliation: None,
                inherited_marker_claims: &[],
                attached_marker_candidates: &[],
                active_marker_claims: &[],
            })
            .unwrap();

        let CallTraversalDecision::Boundary {
            target: Some(metadata_target),
            payload: CompilerAssertBoundary::PanicContract(PanicContractBoundary::Call(boundary)),
        } = decision
        else {
            panic!("source contract must stop the runtime call")
        };
        assert_eq!(metadata_target.callable(), &runtime.id());
        assert_eq!(boundary.contract_target().callable(), &source.id());
        assert_eq!(boundary.contract().queried_callable(), &source.id());
        assert_eq!(boundary.evidence_group(), &call_site.id());
        assert_eq!(boundary.evidence_group_data(), call_site.data());
        let atoms = super::PanicCallRequirements::new(
            super::PanicCallInputId(0),
            boundary.contract().requirements(),
        )
        .collect::<Vec<_>>();
        assert_eq!(atoms.len(), 1);
        assert_eq!(
            atoms[0].id(),
            super::PanicCallRequirementId::Named {
                call: super::PanicCallInputId(0),
                ordinal: 0,
            }
        );
        assert_eq!(atoms[0].call(), super::PanicCallInputId(0));
        assert_eq!(atoms[0].value().unwrap().name(), "source condition");
        assert_eq!(
            atoms[0].value().unwrap().raw_requirement(),
            boundary.contract().requirements()[0].raw_requirement()
        );
    }

    #[test]
    fn defining_callsite_consensus_and_disagreement_choose_the_same_group_as_markers() {
        use crate::analysis::facts::schema::EntityId;
        use crate::analysis::facts::workspace::ScopedEntityId;

        let scope = ArtifactScopeId::for_in_memory(7, 0);
        let owner = FunctionKey::new(matrix_definition(70), None);
        let first_data = CallSiteEntity::new(CallSiteKey::new(owner, 1));
        let second_data = CallSiteEntity::new(CallSiteKey::new(owner, 2));
        let first = ScopedEntityId::new(scope.clone(), EntityId::new(1));
        let second = ScopedEntityId::new(scope.clone(), EntityId::new(2));

        let shared = test_shared_defining_call_site(&[
            (first.clone(), first_data.clone()),
            (first.clone(), first_data.clone()),
        ])
        .unwrap();
        assert_eq!(shared.call_site, first);
        assert_eq!(shared.data, first_data);
        let consumer = super::PanicEvidenceGroup {
            call_site: second.clone(),
            data: second_data.clone(),
        };
        let agreed = Some(shared.clone());
        assert!(super::evidence_group_matches_expected(
            &shared,
            &consumer.call_site,
            &consumer.data,
            Some(&agreed),
        ));
        assert!(!super::evidence_group_matches_expected(
            &consumer,
            &consumer.call_site,
            &consumer.data,
            Some(&agreed),
        ));
        let disagreed = None;
        assert!(super::evidence_group_matches_expected(
            &consumer,
            &consumer.call_site,
            &consumer.data,
            Some(&disagreed),
        ));
        let tampered = super::PanicEvidenceGroup {
            call_site: consumer.call_site.clone(),
            data: first_data.clone(),
        };
        assert!(!super::evidence_group_matches_expected(
            &tampered,
            &consumer.call_site,
            &consumer.data,
            Some(&disagreed),
        ));
        assert!(
            test_shared_defining_call_site(&[
                (first.clone(), first_data.clone()),
                (first.clone(), second_data.clone()),
            ])
            .is_none()
        );
        assert!(
            test_shared_defining_call_site(&[
                (shared.call_site, shared.data),
                (second, second_data),
            ])
            .is_none()
        );
    }

    #[test]
    fn empty_batch_does_not_open_missing_producer_tables() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000004\"")
                .unwrap(),
            None,
        );
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
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
                false,
                false,
                true,
                false,
                vec![String::from("crate::root")],
            ))
            .unwrap();
        builder
            .relate(&body, &callable, &FunctionDefinesCallable::new())
            .unwrap();
        let mut artifact = builder.finalize(registry.schemas()).unwrap();
        let omitted = [
            PanicContractFact::ID,
            PanicRequirement::ID,
            SafetyContractFact::ID,
            SafetyRequirement::ID,
            MirAssertFact::ID,
        ];
        artifact
            .tables
            .retain(|table| !omitted.contains(&table.schema.as_str()));
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

        let batch = PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &PanicConfig::default(),
            &ContractDocOverrides::default(),
            [],
        )
        .unwrap();

        assert!(batch.into_roots().is_empty());
    }

    #[test]
    fn batch_preparation_is_all_or_none_when_any_local_root_is_unknown() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000005\"")
                .unwrap(),
            None,
        );
        let unknown = FunctionKey::new(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000006\"")
                .unwrap(),
            None,
        );
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
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
                false,
                false,
                true,
                false,
                vec![String::from("crate::root")],
            ))
            .unwrap();
        builder
            .relate(&body, &callable, &FunctionDefinesCallable::new())
            .unwrap();
        let artifact = builder.finalize(registry.schemas()).unwrap();
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

        let result = PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &PanicConfig::default(),
            &ContractDocOverrides::default(),
            [root, unknown].map(|root| {
                CompilerAssertRootRequest::new(
                    root,
                    CallAttributionRole::CallSite,
                    MarkerProbe::SourceCallsite,
                    16,
                )
            }),
        );

        assert!(matches!(
            result,
            Err(CompilerAssertInputError::Traversal(source))
                if matches!(*source, crate::analysis::facts::program::root_traversal::RootProgramTraversalError::UnknownRoot { .. })
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the end-to-end fixture proves the caller-owned composition lifecycle"
    )]
    fn prepares_one_direct_assertion_without_owning_the_composition_builder() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000001\"")
                .unwrap(),
            None,
        );
        let site = EffectSiteKey::from_mir(
            root,
            MirBodyLocation {
                basic_block: 2,
                statement_index: 3,
            },
        )
        .unwrap();
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
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
                false,
                false,
                true,
                false,
                vec![String::from("crate::root")],
            ))
            .unwrap();
        builder
            .relate(&body, &callable, &FunctionDefinesCallable::new())
            .unwrap();
        let effect = builder.insert_entity(&EffectSiteEntity::new(site)).unwrap();
        builder
            .relate(&body, &effect, &FunctionOwnsEffectSite::new())
            .unwrap();
        let requirement = builder
            .insert_requirement(&InBoundsRequirement::new())
            .unwrap();
        builder
            .insert_fact(
                &MirAssertFact::new(MirAssertKind::BoundsCheck),
                FactMeta::new(PassId::new("test.compiler-assert-inputs").unwrap())
                    .with_owner(&effect)
                    .unwrap()
                    .with_provenance_root(&body)
                    .unwrap()
                    .with_requirement(&requirement)
                    .unwrap(),
            )
            .unwrap();
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
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
        let expected_effect = closure
            .program()
            .exact_effect_site(&scope, &site)
            .unwrap()
            .id();
        let request = CompilerAssertRootRequest::new(
            root,
            CallAttributionRole::CallSite,
            MarkerProbe::SourceCallsite,
            16,
        );
        let batch = PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &PanicConfig::default(),
            &ContractDocOverrides::default(),
            [request.clone(), request],
        )
        .unwrap();
        let mut roots = batch.into_roots();
        let prepared = roots.pop().unwrap();
        let replacement_prepared = roots.pop().unwrap();
        assert!(roots.is_empty());
        let mut replacement_relation_builder = CompositionRelationBuilder::new(
            replacement_prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let replacement_emitted = replacement_prepared
            .emit(&mut replacement_relation_builder)
            .unwrap();
        let replacement_composition = replacement_relation_builder.finalize().unwrap();
        let replacement_graph = WorkspaceRelationGraph::new(
            replacement_emitted.root(),
            &workspace,
            &replacement_composition,
        )
        .unwrap();
        let replacement = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        assert!(matches!(
            replacement_emitted.resolve_panic(
                &replacement,
                &replacement_graph,
                registry.composition_relations()
            ),
            Err(CompilerAssertInputError::Assertions(source))
                if matches!(*source, super::WorkspaceMirAssertIndexError::WorkspaceMismatch)
        ));
        let mut relation_builder = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut relation_builder).unwrap();
        let composition = relation_builder.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &composition).unwrap();

        let inputs = emitted
            .resolve_panic(&workspace, &graph, registry.composition_relations())
            .unwrap();

        assert!(inputs.belongs_to(&workspace));
        assert!(!inputs.belongs_to(&replacement));
        assert_eq!(inputs.compiler_asserts().assertions().len(), 1);
        let assertion = &inputs.compiler_asserts().assertions()[0];
        assert_eq!(assertion.id().index(), 0);
        assert_eq!(inputs.evidence_order().len(), 1);
        assert_eq!(inputs.evidence_order()[0].rank().index(), 0);
        assert_eq!(
            inputs.evidence_order()[0].witness(),
            super::PanicWitnessId::CompilerAssert(assertion.id())
        );
        assert_eq!(assertion.order(), 0);
        assert_eq!(assertion.kind(), MirAssertKind::BoundsCheck);
        assert_eq!(assertion.owner(), &expected_effect);
        assert_eq!(
            assertion.visit_order(),
            inputs
                .compiler_asserts()
                .traversal()
                .effect_visits()
                .iter()
                .find(|visit| visit.effect() == assertion.owner())
                .unwrap()
                .order()
        );
        assert_eq!(assertion.requirements().len(), 1);
        assert!(assertion.markers().is_empty());
        assert!(!assertion.trace().relations().is_empty());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the typed fixture proves suppression and dense ordering together"
    )]
    fn exact_safety_contract_suppresses_only_precondition_asserts_and_renumbers_dense() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000002\"")
                .unwrap(),
            None,
        );
        let null_site = EffectSiteKey::from_mir(
            root,
            MirBodyLocation {
                basic_block: 1,
                statement_index: 0,
            },
        )
        .unwrap();
        let bounds_site = EffectSiteKey::from_mir(
            root,
            MirBodyLocation {
                basic_block: 2,
                statement_index: 0,
            },
        )
        .unwrap();
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let body = builder
            .insert_entity(&FunctionEntity::new(
                root,
                "crate::unsafe_root",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let callable = builder
            .insert_entity(&CallableEntity::new(
                root,
                "crate::unsafe_root",
                true,
                false,
                true,
                false,
                vec![String::from("crate::unsafe_root")],
            ))
            .unwrap();
        builder
            .relate(&body, &callable, &FunctionDefinesCallable::new())
            .unwrap();
        builder
            .insert_fact(
                &SafetyContractFact::new(),
                FactMeta::new(PassId::new("test.compiler-assert-safety").unwrap())
                    .with_owner(&callable)
                    .unwrap(),
            )
            .unwrap();
        let null_effect = builder
            .insert_entity(&EffectSiteEntity::new(null_site))
            .unwrap();
        let bounds_effect = builder
            .insert_entity(&EffectSiteEntity::new(bounds_site))
            .unwrap();
        builder
            .relate(&body, &null_effect, &FunctionOwnsEffectSite::new())
            .unwrap();
        builder
            .relate(&body, &bounds_effect, &FunctionOwnsEffectSite::new())
            .unwrap();
        let null_requirement = builder
            .insert_requirement(&NonNullPointerRequirement::new())
            .unwrap();
        let bounds_requirement = builder
            .insert_requirement(&InBoundsRequirement::new())
            .unwrap();
        builder
            .insert_fact(
                &MirAssertFact::new(MirAssertKind::NullPointerDereference),
                FactMeta::new(PassId::new("test.compiler-assert-inputs").unwrap())
                    .with_owner(&null_effect)
                    .unwrap()
                    .with_provenance_root(&body)
                    .unwrap()
                    .with_requirement(&null_requirement)
                    .unwrap(),
            )
            .unwrap();
        builder
            .insert_fact(
                &MirAssertFact::new(MirAssertKind::BoundsCheck),
                FactMeta::new(PassId::new("test.compiler-assert-inputs").unwrap())
                    .with_owner(&bounds_effect)
                    .unwrap()
                    .with_provenance_root(&body)
                    .unwrap()
                    .with_requirement(&bounds_requirement)
                    .unwrap(),
            )
            .unwrap();
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
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
        let batch = PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &PanicConfig::default(),
            &ContractDocOverrides::default(),
            [CompilerAssertRootRequest::new(
                root,
                CallAttributionRole::CallSite,
                MarkerProbe::SourceCallsite,
                16,
            )],
        )
        .unwrap();
        let prepared = batch.into_roots().pop().unwrap();
        let mut relation_builder = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut relation_builder).unwrap();
        let composition = relation_builder.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &composition).unwrap();

        let inputs = emitted
            .resolve(&workspace, &graph, registry.composition_relations())
            .unwrap();

        assert_eq!(inputs.assertions().len(), 1);
        assert_eq!(inputs.assertions()[0].kind(), MirAssertKind::BoundsCheck);
        assert_eq!(inputs.assertions()[0].order(), 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture proves probe, domain, and selector filtering on exact marker traces"
    )]
    fn retains_only_active_unnamed_panic_markers() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(
            serde_json::from_str::<StableDefPathHash>("\"00000000000000010000000000000003\"")
                .unwrap(),
            None,
        );
        let site = EffectSiteKey::from_mir(
            root,
            MirBodyLocation {
                basic_block: 1,
                statement_index: 0,
            },
        )
        .unwrap();
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let file = builder
            .insert_entity(&SourceFileEntity::new(
                "src/lib.rs",
                "src/lib.rs",
                "hash",
                100,
            ))
            .unwrap();
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
                false,
                false,
                true,
                false,
                vec![String::from("crate::root")],
            ))
            .unwrap();
        builder
            .relate(&body, &callable, &FunctionDefinesCallable::new())
            .unwrap();
        let effect = builder.insert_entity(&EffectSiteEntity::new(site)).unwrap();
        builder
            .relate(&body, &effect, &FunctionOwnsEffectSite::new())
            .unwrap();
        let requirement = builder
            .insert_requirement(&InBoundsRequirement::new())
            .unwrap();
        builder
            .insert_fact(
                &MirAssertFact::new(MirAssertKind::BoundsCheck),
                FactMeta::new(PassId::new("test.compiler-assert-inputs").unwrap())
                    .with_owner(&effect)
                    .unwrap()
                    .with_provenance_root(&body)
                    .unwrap()
                    .with_requirement(&requirement)
                    .unwrap(),
            )
            .unwrap();
        for (ordinal, domain, selector, source_probe, macro_probe) in [
            (
                0_u32,
                "sniff-test.panic",
                EvidenceClaimSelector::Unnamed,
                true,
                false,
            ),
            (
                1,
                "sniff-test.panic",
                EvidenceClaimSelector::Named(String::from("condition")),
                true,
                false,
            ),
            (
                2,
                "sniff-test.safety",
                EvidenceClaimSelector::Unnamed,
                true,
                false,
            ),
            (
                3,
                "sniff-test.panic",
                EvidenceClaimSelector::Unnamed,
                false,
                true,
            ),
        ] {
            let start = u64::from(ordinal * 10);
            let anchor_key = SourceAnchorKey::new("src/lib.rs", start, start + 5);
            let anchor = builder
                .insert_entity(&SourceAnchorEntity::new(anchor_key.clone()))
                .unwrap();
            builder
                .relate(&anchor, &file, &SourceAnchorInFile::new())
                .unwrap();
            let occurrence_key = MarkerOccurrenceKey::new(anchor_key, None);
            let occurrence = builder
                .insert_entity(&MarkerOccurrenceEntity::new(occurrence_key.clone(), vec![]))
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
                    MarkerClaimKey::new(occurrence_key, DomainId::new(domain).unwrap(), 0),
                    selector,
                    format!("marker {ordinal}"),
                ))
                .unwrap();
            builder
                .relate(&occurrence, &claim, &MarkerOccurrenceHasClaim::new())
                .unwrap();
            builder
                .relate(
                    &effect,
                    &claim,
                    &EffectSiteHasMarkerClaimCandidate::new(source_probe, macro_probe),
                )
                .unwrap();
        }
        let artifact = builder.finalize(registry.schemas()).unwrap();
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
        let batch = PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &PanicConfig::default(),
            &ContractDocOverrides::default(),
            [CompilerAssertRootRequest::new(
                root,
                CallAttributionRole::CallSite,
                MarkerProbe::SourceCallsite,
                16,
            )],
        )
        .unwrap();
        let prepared = batch.into_roots().pop().unwrap();
        let mut relation_builder = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut relation_builder).unwrap();
        let composition = relation_builder.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &composition).unwrap();
        let inputs = emitted
            .resolve(&workspace, &graph, registry.composition_relations())
            .unwrap();

        let markers = inputs.assertions()[0].markers();
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].data().rationale(), "marker 0");
        assert_eq!(markers[0].claim().scope(), closure.root_scope());
        assert_eq!(markers[0].trace().target(), &markers[0].claim().erase());
    }

    #[derive(Clone, Copy)]
    enum PolicyMatrixCase {
        Sink,
        Normal,
        Ignored,
        StructuralSink,
        Contract,
        StructuralContract,
        TrustedContract,
        Trusted,
        Foreign,
        Bodyless,
        StructuralBodyless,
        Opaque,
        StructuralOpaque,
        TargetlessOpaque,
    }

    impl PolicyMatrixCase {
        fn path(self) -> &'static str {
            match self {
                Self::Sink | Self::StructuralSink => "crate::sink",
                Self::Normal => "crate::normal",
                Self::Ignored => "crate::ignored",
                Self::Contract => "crate::contract",
                Self::StructuralContract => "crate::override",
                Self::TrustedContract | Self::Trusted => "crate::trusted",
                Self::Foreign => "crate::foreign",
                Self::Bodyless => "crate::bodyless",
                Self::StructuralBodyless => "crate::structural_bodyless",
                Self::Opaque => "crate::opaque",
                Self::StructuralOpaque => "crate::structural_opaque",
                Self::TargetlessOpaque => "crate::targetless_opaque",
            }
        }

        fn has_body(self) -> bool {
            !matches!(
                self,
                Self::Foreign
                    | Self::Bodyless
                    | Self::StructuralBodyless
                    | Self::Opaque
                    | Self::StructuralOpaque
                    | Self::TargetlessOpaque
            )
        }

        fn has_rust_body(self) -> bool {
            !matches!(self, Self::Bodyless | Self::StructuralBodyless)
        }

        fn is_foreign(self) -> bool {
            matches!(self, Self::Foreign)
        }

        fn is_opaque(self) -> bool {
            matches!(
                self,
                Self::Opaque | Self::StructuralOpaque | Self::TargetlessOpaque
            )
        }

        fn has_contract(self) -> bool {
            matches!(
                self,
                Self::Contract | Self::StructuralContract | Self::TrustedContract
            )
        }

        fn has_target(self) -> bool {
            !matches!(self, Self::TargetlessOpaque)
        }

        fn call_kind(self) -> CallKind {
            match self {
                Self::StructuralSink | Self::StructuralBodyless => CallKind::ConstBody,
                Self::StructuralContract | Self::StructuralOpaque => CallKind::CoroutineBody,
                _ => CallKind::DirectCall,
            }
        }
    }

    fn matrix_definition(local: u64) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{:016x}{local:016x}\"", 1_u64)).unwrap()
    }

    fn matrix_instance(local: u64) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{local:032x}\"")).unwrap()
    }

    fn matrix_type(local: u64) -> StableTypeHash {
        serde_json::from_str(&format!("\"{local:032x}\"")).unwrap()
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the fixture helper preserves every keyed call facet explicitly"
    )]
    fn insert_keyed_call(
        builder: &mut ArtifactDbBuilder,
        root_body: &EntityHandle<FunctionEntity>,
        root: FunctionKey,
        local_id: u32,
        kind: CallKind,
        attribution: Vec<CallAttributionRole>,
        key: &EntityHandle<CallableKeyEntity>,
        target: &EntityHandle<CallableEntity>,
    ) -> EntityHandle<CallOccurrenceEntity> {
        let call_site = builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(root, local_id)))
            .unwrap();
        builder
            .relate(root_body, &call_site, &FunctionOwnsCallSite::new())
            .unwrap();
        let occurrence = builder
            .insert_entity(&CallOccurrenceEntity::new(
                CallOccurrenceKey::new(root, local_id),
                kind,
                attribution,
                false,
                false,
                None,
            ))
            .unwrap();
        builder
            .relate(&call_site, &occurrence, &CallSiteHasOccurrence::new())
            .unwrap();
        builder
            .relate(&occurrence, key, &CallOccurrenceHasCallableKey::new())
            .unwrap();
        builder
            .relate(
                &occurrence,
                target,
                &CallOccurrenceTargetsCallable::new(CallTargetRole::Runtime),
            )
            .unwrap();
        let group = builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                root, local_id,
            )))
            .unwrap();
        builder
            .relate(root_body, &group, &FunctionOwnsSafetyEffectGroup::new())
            .unwrap();
        builder
            .relate(
                &occurrence,
                &group,
                &CallOccurrenceInSafetyEffectGroup::new(),
            )
            .unwrap();
        occurrence
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the fixture varies domain, selector, and probe independently"
    )]
    fn attach_call_marker(
        builder: &mut ArtifactDbBuilder,
        occurrence: &EntityHandle<CallOccurrenceEntity>,
        ordinal: u32,
        domain: &str,
        selector: EvidenceClaimSelector,
        source_probe: bool,
        macro_probe: bool,
    ) {
        let file_id = format!("call-marker-{ordinal}");
        let file = builder
            .insert_entity(&SourceFileEntity::new(
                file_id.clone(),
                format!("src/{file_id}.rs"),
                format!("hash-{ordinal}"),
                100,
            ))
            .unwrap();
        let start = u64::from(ordinal) * 10;
        let anchor_key = SourceAnchorKey::new(file_id, start, start + 5);
        let anchor = builder
            .insert_entity(&SourceAnchorEntity::new(anchor_key.clone()))
            .unwrap();
        builder
            .relate(&anchor, &file, &SourceAnchorInFile::new())
            .unwrap();
        let marker_key = MarkerOccurrenceKey::new(anchor_key, None);
        let marker = builder
            .insert_entity(&MarkerOccurrenceEntity::new(marker_key.clone(), vec![]))
            .unwrap();
        builder
            .relate(&marker, &anchor, &MarkerOccurrenceHasSourceAnchor::new())
            .unwrap();
        let claim = builder
            .insert_entity(&MarkerClaimEntity::new(
                MarkerClaimKey::new(marker_key, DomainId::new(domain).unwrap(), 0),
                selector,
                format!("call marker {ordinal}"),
            ))
            .unwrap();
        builder
            .relate(&marker, &claim, &MarkerOccurrenceHasClaim::new())
            .unwrap();
        builder
            .relate(
                occurrence,
                &claim,
                &CallOccurrenceHasMarkerClaimCandidate::new(source_probe, macro_probe),
            )
            .unwrap();
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one fixture proves repeated call state, marker retention, and reconciliation"
    )]
    fn panic_calls_retain_callable_evidence_states_and_raw_marker_selectors() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(matrix_definition(80), None);
        let raw_key = FunctionKey::new(matrix_definition(81), Some(matrix_instance(81)));
        let evidence_key = FunctionKey::new(matrix_definition(82), Some(matrix_instance(82)));
        let callable_key = CallableKey::FnPointer(matrix_type(80));
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let root_body = builder
            .insert_entity(&FunctionEntity::new(
                root,
                "crate::root",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let root_callable = builder
            .insert_entity(&CallableEntity::new(
                root,
                "crate::root",
                false,
                false,
                true,
                false,
                vec![String::from("crate::root")],
            ))
            .unwrap();
        builder
            .relate(&root_body, &root_callable, &FunctionDefinesCallable::new())
            .unwrap();
        let raw = builder
            .insert_entity(&CallableEntity::new(
                raw_key,
                "crate::sink::raw",
                false,
                false,
                false,
                false,
                vec![String::from("crate::sink::raw")],
            ))
            .unwrap();
        let evidence_target = builder
            .insert_entity(&CallableEntity::new(
                evidence_key,
                "crate::sink::evidence",
                false,
                false,
                false,
                false,
                vec![String::from("crate::sink::evidence")],
            ))
            .unwrap();
        let key = builder
            .insert_entity(&CallableKeyEntity::new(callable_key))
            .unwrap();
        let evidence = insert_keyed_call(
            &mut builder,
            &root_body,
            root,
            0,
            CallKind::FnPointerReify,
            vec![CallAttributionRole::ErasureSite],
            &key,
            &evidence_target,
        );
        let invocation = insert_keyed_call(
            &mut builder,
            &root_body,
            root,
            1,
            CallKind::IndirectCall,
            vec![CallAttributionRole::CallSite],
            &key,
            &raw,
        );
        for (ordinal, domain, selector, source_probe, macro_probe) in [
            (
                0,
                "sniff-test.panic",
                EvidenceClaimSelector::Unnamed,
                true,
                false,
            ),
            (
                1,
                "sniff-test.panic",
                EvidenceClaimSelector::Named(String::from("Index_In-Bounds")),
                true,
                false,
            ),
            (
                2,
                "sniff-test.panic",
                EvidenceClaimSelector::Explicit(vec![String::from("compiler.bounds")]),
                true,
                false,
            ),
            (
                3,
                "sniff-test.safety",
                EvidenceClaimSelector::Unnamed,
                true,
                false,
            ),
            (
                4,
                "sniff-test.panic",
                EvidenceClaimSelector::Unnamed,
                false,
                true,
            ),
        ] {
            attach_call_marker(
                &mut builder,
                &invocation,
                ordinal,
                domain,
                selector,
                source_probe,
                macro_probe,
            );
        }
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let scope = ArtifactScopeId::for_in_memory(1, 80);
        let workspace = WorkspaceFactView::compose([(
            scope,
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(ManagedArtifactGeneration::in_memory(1, 80), vec![]),
            [],
            Vec::<RustcArtifactId>::new(),
        )
        .unwrap();
        let panic = PanicConfig {
            panic_sink_namespaces: PathPatterns::new(vec![String::from("crate::sink::**")])
                .unwrap(),
            ..PanicConfig::default()
        };
        let prepared = PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &panic,
            &ContractDocOverrides::default(),
            [CompilerAssertRootRequest::new(
                root,
                CallAttributionRole::CallSite,
                MarkerProbe::SourceCallsite,
                32,
            )],
        )
        .unwrap()
        .into_roots()
        .pop()
        .unwrap();
        let mut relation_builder = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut relation_builder).unwrap();
        let composition = relation_builder.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &composition).unwrap();
        let inputs = emitted
            .resolve_panic(&workspace, &graph, registry.composition_relations())
            .unwrap();

        assert_eq!(inputs.call_count(), 2);
        assert!(inputs.compiler_asserts().assertions().is_empty());
        assert_eq!(inputs.root(), inputs.compiler_asserts().root());
        assert!(std::ptr::eq(
            inputs.traversal(),
            inputs.compiler_asserts().traversal()
        ));
        assert!(std::ptr::eq(
            inputs.workspace_identity().as_ref(),
            inputs.compiler_asserts().workspace_identity().as_ref()
        ));
        let calls = inputs.calls().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(
            calls
                .iter()
                .map(|call| call.id().index())
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        let persisted = calls
            .iter()
            .find(|call| matches!(call.resolution(), ProgramCallResolution::Persisted))
            .unwrap();
        let resolved = calls
            .iter()
            .find(|call| {
                matches!(
                    call.resolution(),
                    ProgramCallResolution::CallableEvidence { .. }
                )
            })
            .unwrap();
        assert_eq!(persisted.occurrence_data().key(), invocation.key());
        assert_eq!(resolved.occurrence_data().key(), invocation.key());
        assert_eq!(persisted.effective_kind(), CallKind::IndirectCall);
        assert_eq!(resolved.effective_kind(), CallKind::FnPointerCallTarget);
        assert_eq!(persisted.kind(), super::PanicCallInputKind::PanicSink);
        assert_eq!(resolved.kind(), super::PanicCallInputKind::PanicSink);
        let persisted_atom = persisted.requirements().next().unwrap();
        let resolved_atom = resolved.requirements().next().unwrap();
        assert_eq!(persisted_atom.call(), persisted.id());
        assert_eq!(resolved_atom.call(), resolved.id());
        assert_ne!(persisted_atom.id(), resolved_atom.id());
        assert!(persisted_atom.value().is_none());
        assert!(resolved_atom.value().is_none());
        let evidence_visit = inputs
            .traversal()
            .occurrence_visits()
            .iter()
            .find(|visit| visit.data().key() == evidence.key())
            .unwrap();
        let invocation_visit = inputs
            .traversal()
            .occurrence_visits()
            .iter()
            .find(|visit| visit.data().key() == invocation.key())
            .unwrap();
        assert!(matches!(
            resolved.resolution(),
            ProgramCallResolution::CallableEvidence {
                evidence: selected,
                key: selected_key,
                kind: CallableResolutionKind::FunctionPointerEvidence,
            } if selected == evidence_visit.occurrence() && *selected_key == callable_key
        ));
        assert_eq!(persisted.metadata_target_data().unwrap().key(), &raw_key);
        assert_eq!(
            resolved.metadata_target_data().unwrap().key(),
            &evidence_key
        );
        let resolved_presentation = resolved.presentation_target().unwrap();
        assert_eq!(
            resolved_presentation
                .callable()
                .unwrap()
                .selection()
                .callable(),
            resolved.metadata_target().unwrap().callable()
        );
        assert!(std::ptr::eq(
            resolved_presentation.callable().unwrap().data(),
            resolved.metadata_target_data().unwrap()
        ));
        assert_eq!(resolved_presentation.opaque_description(), None);
        assert_eq!(persisted.evidence_group(), persisted.consumer_call_site());
        assert_eq!(
            persisted.evidence_group_data(),
            persisted.consumer_call_site_data()
        );
        assert!(inputs.traversal().consumer_reconciliations().is_empty());
        assert_eq!(resolved.evidence_group(), resolved.consumer_call_site());
        assert_eq!(
            resolved.evidence_group_data(),
            resolved.consumer_call_site_data()
        );

        assert_eq!(persisted.markers(), resolved.markers());
        assert_eq!(persisted.markers(), invocation_visit.active_markers());
        assert_eq!(persisted.markers().len(), 3);
        assert!(persisted.markers().iter().any(|marker| {
            marker.data().rationale() == "call marker 0"
                && marker.data().selector() == &EvidenceClaimSelector::Unnamed
        }));
        assert!(persisted.markers().iter().any(|marker| {
            marker.data().rationale() == "call marker 1"
                && marker.data().selector()
                    == &EvidenceClaimSelector::Named(String::from("Index_In-Bounds"))
        }));
        assert!(persisted.markers().iter().any(|marker| {
            marker.data().rationale() == "call marker 2"
                && marker.data().selector()
                    == &EvidenceClaimSelector::Explicit(vec![String::from("compiler.bounds")])
        }));
        assert!(persisted.markers().iter().all(|marker| {
            marker.claim().scope() == closure.root_scope()
                && marker.trace().target() == &marker.claim().erase()
        }));
        assert_eq!(inputs.evidence_order().len(), 2);
        for (index, ranked) in inputs.evidence_order().iter().enumerate() {
            assert_eq!(ranked.rank().index(), index);
            assert_eq!(
                ranked.witness(),
                super::PanicWitnessId::Call(calls[index].id())
            );
            assert_eq!(ranked.traversal_order(), calls[index].order());
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the two-artifact fixture proves the complete reconciled group path"
    )]
    fn panic_call_uses_the_exact_shared_defining_call_site_group() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let consumer = FunctionKey::new(matrix_definition(90), Some(matrix_instance(90)));
        let defining = FunctionKey::new(consumer.definition(), None);
        let make_artifact = |owner: FunctionKey, provenance: FunctionBodyProvenance, path: &str| {
            let mut builder = ArtifactDbBuilder::new();
            for descriptor in registry.schemas().descriptors() {
                builder.declare_table(descriptor).unwrap();
            }
            let body = builder
                .insert_entity(&FunctionEntity::new(owner, path, provenance))
                .unwrap();
            let callable = builder
                .insert_entity(&CallableEntity::new(
                    owner,
                    path,
                    false,
                    false,
                    true,
                    false,
                    vec![path.to_owned()],
                ))
                .unwrap();
            builder
                .relate(&body, &callable, &FunctionDefinesCallable::new())
                .unwrap();
            let call_site = builder
                .insert_entity(&CallSiteEntity::new(CallSiteKey::new(owner, 0)))
                .unwrap();
            builder
                .relate(&body, &call_site, &FunctionOwnsCallSite::new())
                .unwrap();
            let occurrence = builder
                .insert_entity(&CallOccurrenceEntity::new(
                    CallOccurrenceKey::new(owner, 0),
                    CallKind::DirectCall,
                    vec![CallAttributionRole::CallSite],
                    false,
                    false,
                    Some(String::from("reconciled opaque call")),
                ))
                .unwrap();
            builder
                .relate(&call_site, &occurrence, &CallSiteHasOccurrence::new())
                .unwrap();
            let group = builder
                .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                    owner, 0,
                )))
                .unwrap();
            builder
                .relate(&body, &group, &FunctionOwnsSafetyEffectGroup::new())
                .unwrap();
            builder
                .relate(
                    &occurrence,
                    &group,
                    &CallOccurrenceInSafetyEffectGroup::new(),
                )
                .unwrap();
            let file = builder
                .insert_entity(&SourceFileEntity::new(
                    "shared-call.rs",
                    "src/shared-call.rs",
                    format!("hash-{path}"),
                    100,
                ))
                .unwrap();
            let anchor = builder
                .insert_entity(&SourceAnchorEntity::new(SourceAnchorKey::new(
                    "shared-call.rs",
                    10,
                    20,
                )))
                .unwrap();
            builder
                .relate(&anchor, &file, &SourceAnchorInFile::new())
                .unwrap();
            builder
                .relate(
                    &occurrence,
                    &anchor,
                    &CallOccurrenceHasSourceAnchor::new(CallSourceAnchorRole::Expanded),
                )
                .unwrap();
            builder.finalize(registry.schemas()).unwrap()
        };
        let consumer_artifact = make_artifact(
            consumer,
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 90,
            },
            "crate::consumer",
        );
        let defining_artifact = make_artifact(
            defining,
            FunctionBodyProvenance::DefiningArtifact,
            "dependency::generic",
        );
        let dependency = RustcArtifactId::new(1, "9".repeat(32));
        let root_generation = ManagedArtifactGeneration::in_memory(90, 0);
        let dependency_generation = ManagedArtifactGeneration::persisted(dependency.clone());
        let consumer_scope = root_generation.scope().unwrap();
        let defining_scope = dependency_generation.scope().unwrap();
        let workspace = WorkspaceFactView::compose([
            (
                consumer_scope.clone(),
                ArtifactDbView::open(&consumer_artifact, registry.schemas()).unwrap(),
            ),
            (
                defining_scope.clone(),
                ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
            ),
        ])
        .unwrap();
        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root_generation, vec![dependency.clone()]),
            [ManagedArtifactManifest::new(
                dependency_generation,
                Vec::new(),
            )],
            [],
        )
        .unwrap();
        let prepared = PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &PanicConfig::default(),
            &ContractDocOverrides::default(),
            [CompilerAssertRootRequest::new(
                consumer,
                CallAttributionRole::CallSite,
                MarkerProbe::SourceCallsite,
                16,
            )],
        )
        .unwrap()
        .into_roots()
        .pop()
        .unwrap();
        let mut relation_builder = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut relation_builder).unwrap();
        let composition = relation_builder.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &composition).unwrap();
        let inputs = emitted
            .resolve_panic(&workspace, &graph, registry.composition_relations())
            .unwrap();

        assert_eq!(inputs.call_count(), 1);
        let call = inputs.calls().next().unwrap().unwrap();
        let [reconciliation] = inputs.traversal().consumer_reconciliations() else {
            panic!("one consumer/defining reconciliation must resolve")
        };
        assert_eq!(reconciliation.consumer().scope(), &consumer_scope);
        assert_eq!(reconciliation.defining().scope(), &defining_scope);
        assert_eq!(call.occurrence(), reconciliation.consumer());
        assert_eq!(
            call.consumer_call_site(),
            reconciliation.consumer_call_site()
        );
        assert_eq!(call.evidence_group(), reconciliation.defining_call_site());
        assert_eq!(
            call.evidence_group_data(),
            reconciliation.defining_call_site_data()
        );
        assert_ne!(call.evidence_group(), call.consumer_call_site());
        assert_eq!(
            call.kind(),
            super::PanicCallInputKind::Opaque {
                kind: super::PanicOpaqueBoundaryKind::ExplicitOpaque,
            }
        );
        assert_eq!(call.metadata_target(), None);
        let caller = closure
            .program()
            .exact_function(&consumer_scope, &consumer)
            .unwrap();
        assert_eq!(
            call.presentation_function().endpoint(),
            &caller.id().erase()
        );
        assert_eq!(call.presentation_function().scope(), &consumer_scope);
        assert_eq!(call.presentation_function().function(), &consumer);
        assert_eq!(call.endpoint(), call.occurrence().erase());
        assert_eq!(call.trace_target(), &call.endpoint());
        assert_eq!(
            call.requirements().next().unwrap().id(),
            super::PanicCallRequirementId::Unnamed { call: call.id() }
        );
        assert_eq!(inputs.evidence_order().len(), 1);
        assert_eq!(inputs.evidence_order()[0].rank().index(), 0);
        assert_eq!(
            inputs.evidence_order()[0].witness(),
            super::PanicWitnessId::Call(call.id())
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one artifact exercises the complete ordered panic call-boundary matrix"
    )]
    fn call_policy_follows_only_normal_rust_bodies_and_retains_every_boundary_kind() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(matrix_definition(1), None);
        let cases = [
            PolicyMatrixCase::Sink,
            PolicyMatrixCase::Normal,
            PolicyMatrixCase::Ignored,
            PolicyMatrixCase::StructuralSink,
            PolicyMatrixCase::Contract,
            PolicyMatrixCase::StructuralContract,
            PolicyMatrixCase::TrustedContract,
            PolicyMatrixCase::Trusted,
            PolicyMatrixCase::Foreign,
            PolicyMatrixCase::Bodyless,
            PolicyMatrixCase::StructuralBodyless,
            PolicyMatrixCase::Opaque,
            PolicyMatrixCase::StructuralOpaque,
            PolicyMatrixCase::TargetlessOpaque,
        ];
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let root_body = builder
            .insert_entity(&FunctionEntity::new(
                root,
                "crate::root",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let root_callable = builder
            .insert_entity(&CallableEntity::new(
                root,
                "crate::root",
                false,
                false,
                true,
                false,
                vec![String::from("crate::root")],
            ))
            .unwrap();
        builder
            .relate(&root_body, &root_callable, &FunctionDefinesCallable::new())
            .unwrap();
        let requirement = builder
            .insert_requirement(&InBoundsRequirement::new())
            .unwrap();
        for (index, case) in cases.iter().enumerate() {
            let local_id = u32::try_from(index).unwrap();
            let target = FunctionKey::new(
                matrix_definition(u64::from(local_id) + 10),
                (!case.is_opaque()).then(|| matrix_instance(u64::from(local_id) + 1)),
            );
            let callable = builder
                .insert_entity(&CallableEntity::new(
                    target,
                    case.path(),
                    false,
                    false,
                    case.has_rust_body(),
                    case.is_foreign(),
                    vec![case.path().to_owned()],
                ))
                .unwrap();
            if case.has_contract() {
                let mut metadata =
                    FactMeta::new(PassId::new("test.compiler-assert-contract").unwrap())
                        .with_owner(&callable)
                        .unwrap();
                if matches!(case, PolicyMatrixCase::Contract) {
                    for (ordinal, name, condition) in [
                        (0, "Index_In-Bounds", "first"),
                        (1, "ready", "second"),
                        (2, "index in bounds", "third"),
                    ] {
                        let requirement = builder
                            .insert_requirement(&PanicRequirement::new(
                                target, ordinal, name, condition, None,
                            ))
                            .unwrap();
                        metadata = metadata.with_requirement(&requirement).unwrap();
                    }
                }
                builder
                    .insert_fact(&PanicContractFact::new(), metadata)
                    .unwrap();
            }
            if case.has_body() {
                let body = builder
                    .insert_entity(&FunctionEntity::new(
                        target,
                        case.path(),
                        FunctionBodyProvenance::DefiningArtifact,
                    ))
                    .unwrap();
                builder
                    .relate(&body, &callable, &FunctionDefinesCallable::new())
                    .unwrap();
                let site = EffectSiteKey::from_mir(
                    target,
                    MirBodyLocation {
                        basic_block: 0,
                        statement_index: index,
                    },
                )
                .unwrap();
                let effect = builder.insert_entity(&EffectSiteEntity::new(site)).unwrap();
                builder
                    .relate(&body, &effect, &FunctionOwnsEffectSite::new())
                    .unwrap();
                builder
                    .insert_fact(
                        &MirAssertFact::new(MirAssertKind::BoundsCheck),
                        FactMeta::new(PassId::new("test.compiler-assert-inputs").unwrap())
                            .with_owner(&effect)
                            .unwrap()
                            .with_provenance_root(&body)
                            .unwrap()
                            .with_requirement(&requirement)
                            .unwrap(),
                    )
                    .unwrap();
            }
            let call_site = builder
                .insert_entity(&CallSiteEntity::new(CallSiteKey::new(root, local_id)))
                .unwrap();
            builder
                .relate(&root_body, &call_site, &FunctionOwnsCallSite::new())
                .unwrap();
            let occurrence = builder
                .insert_entity(&CallOccurrenceEntity::new(
                    CallOccurrenceKey::new(root, local_id),
                    case.call_kind(),
                    vec![CallAttributionRole::CallSite],
                    false,
                    false,
                    case.is_opaque().then(|| String::from("opaque call")),
                ))
                .unwrap();
            builder
                .relate(&call_site, &occurrence, &CallSiteHasOccurrence::new())
                .unwrap();
            if case.has_target() {
                builder
                    .relate(
                        &occurrence,
                        &callable,
                        &CallOccurrenceTargetsCallable::new(if case.is_opaque() {
                            CallTargetRole::OpaqueFunction
                        } else {
                            CallTargetRole::Runtime
                        }),
                    )
                    .unwrap();
            }
            let group = builder
                .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                    root, local_id,
                )))
                .unwrap();
            builder
                .relate(&root_body, &group, &FunctionOwnsSafetyEffectGroup::new())
                .unwrap();
            builder
                .relate(
                    &occurrence,
                    &group,
                    &CallOccurrenceInSafetyEffectGroup::new(),
                )
                .unwrap();
        }
        let artifact = builder.finalize(registry.schemas()).unwrap();
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
        let panic = PanicConfig {
            ignored_namespaces: PathPatterns::new(vec![String::from("crate::ignored")]).unwrap(),
            panic_sink_namespaces: PathPatterns::new(vec![String::from("crate::sink")]).unwrap(),
            trusted_panic_boundary_namespaces: PathPatterns::new(vec![String::from(
                "crate::trusted",
            )])
            .unwrap(),
            ..PanicConfig::default()
        };
        let overrides = ContractDocOverrides::new(vec![(
            String::from("crate::override"),
            String::from("# Panics\n- zeta: first\n- alpha: second\n- zeta: third"),
        )])
        .unwrap();
        let prepared = PreparedCompilerAssertRootBatch::prepare(
            &workspace,
            &closure,
            &panic,
            &overrides,
            [CompilerAssertRootRequest::new(
                root,
                CallAttributionRole::CallSite,
                MarkerProbe::SourceCallsite,
                32,
            )],
        )
        .unwrap()
        .into_roots()
        .pop()
        .unwrap();
        let mut relation_builder = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut relation_builder).unwrap();
        let composition = relation_builder.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &composition).unwrap();
        let inputs = emitted
            .resolve_panic(&workspace, &graph, registry.composition_relations())
            .unwrap();

        assert_eq!(inputs.compiler_asserts().assertions().len(), 1);
        assert_eq!(inputs.call_count(), 8);
        let calls = inputs.calls().collect::<Result<Vec<_>, _>>().unwrap();
        let runtime_presentation = calls[0].presentation_target().unwrap();
        assert_eq!(
            runtime_presentation.callable().unwrap().selection().role(),
            CallTargetRole::Runtime
        );
        assert_eq!(runtime_presentation.opaque_description(), None);
        let opaque_presentation = calls[6].presentation_target().unwrap();
        assert_eq!(
            opaque_presentation.callable().unwrap().selection().role(),
            CallTargetRole::OpaqueFunction
        );
        assert_eq!(
            opaque_presentation.opaque_description(),
            Some("opaque call")
        );
        let targetless_presentation = calls[7].presentation_target().unwrap();
        assert!(targetless_presentation.callable().is_none());
        assert_eq!(
            targetless_presentation.opaque_description(),
            Some("opaque call")
        );
        assert_eq!(calls[0].kind(), super::PanicCallInputKind::PanicSink);
        assert_eq!(calls[0].effective_kind(), CallKind::DirectCall);
        assert_eq!(calls[1].kind(), super::PanicCallInputKind::PanicSink);
        assert_eq!(calls[1].effective_kind(), CallKind::ConstBody);
        assert_eq!(
            calls[2].kind(),
            super::PanicCallInputKind::Documented { trusted: false }
        );
        assert_eq!(calls[2].effective_kind(), CallKind::DirectCall);
        assert_eq!(
            calls[3].kind(),
            super::PanicCallInputKind::Documented { trusted: false }
        );
        assert_eq!(calls[3].effective_kind(), CallKind::CoroutineBody);
        assert_eq!(
            calls[4].kind(),
            super::PanicCallInputKind::Documented { trusted: true }
        );
        for call in [
            &calls[0], &calls[1], &calls[4], &calls[5], &calls[6], &calls[7],
        ] {
            let mut requirements = call.requirements();
            assert_eq!(requirements.len(), 1);
            let requirement = requirements.next().unwrap();
            assert_eq!(
                requirement.id(),
                super::PanicCallRequirementId::Unnamed { call: call.id() }
            );
            assert!(requirement.value().is_none());
            assert!(requirements.next().is_none());
        }
        let raw_requirements = calls[2].requirements().collect::<Vec<_>>();
        assert_eq!(
            raw_requirements
                .iter()
                .map(super::PanicCallRequirementView::id)
                .collect::<Vec<_>>(),
            vec![
                super::PanicCallRequirementId::Named {
                    call: calls[2].id(),
                    ordinal: 0,
                },
                super::PanicCallRequirementId::Named {
                    call: calls[2].id(),
                    ordinal: 1,
                },
                super::PanicCallRequirementId::Named {
                    call: calls[2].id(),
                    ordinal: 2,
                },
            ]
        );
        assert_eq!(
            raw_requirements
                .iter()
                .map(|requirement| requirement.value().unwrap().name())
                .collect::<Vec<_>>(),
            vec!["Index_In-Bounds", "ready", "index in bounds"]
        );
        assert_eq!(
            raw_requirements[0].value().unwrap().normalized_name(),
            raw_requirements[2].value().unwrap().normalized_name()
        );
        let retained_requirements = calls[2].contract().unwrap().requirements();
        assert!(
            raw_requirements
                .iter()
                .zip(retained_requirements)
                .all(|(view, retained)| std::ptr::eq(view.value().unwrap(), retained))
        );
        assert!(
            raw_requirements
                .iter()
                .all(|requirement| { requirement.value().unwrap().raw_requirement().is_some() })
        );
        let override_requirements = calls[3].requirements().collect::<Vec<_>>();
        assert_eq!(
            override_requirements
                .iter()
                .map(|requirement| requirement.value().unwrap().name())
                .collect::<Vec<_>>(),
            vec!["zeta", "alpha", "zeta"]
        );
        assert!(override_requirements.iter().all(|requirement| {
            let requirement = requirement.value().unwrap();
            requirement.raw_requirement().is_none() && requirement.source_anchor().is_none()
        }));
        assert_eq!(
            calls[5].kind(),
            super::PanicCallInputKind::Opaque {
                kind: super::PanicOpaqueBoundaryKind::BodylessDeclaration,
            }
        );
        assert_eq!(
            calls[5].opaque_description(),
            Some("indirect call to undocumented trait method `crate::bodyless`")
        );
        assert_eq!(
            calls[6].kind(),
            super::PanicCallInputKind::Opaque {
                kind: super::PanicOpaqueBoundaryKind::ExplicitOpaque,
            }
        );
        assert_eq!(calls[6].opaque_description(), Some("opaque call"));
        assert_eq!(
            calls[7].kind(),
            super::PanicCallInputKind::Opaque {
                kind: super::PanicOpaqueBoundaryKind::ExplicitOpaque,
            }
        );
        assert_eq!(calls[7].opaque_description(), Some("opaque call"));
        assert!(calls.iter().all(|call| {
            call.metadata_target_data().is_none_or(|target| {
                !matches!(
                    target.display_path(),
                    "crate::structural_bodyless" | "crate::structural_opaque"
                )
            })
        }));
        assert!(calls.iter().enumerate().all(|(index, call)| {
            call.id().index() == index
                && call.evidence_group().scope() == call.occurrence().scope()
                && call.evidence_group_data().key() == call.consumer_call_site_data().key()
        }));
        assert!(calls[..7].iter().all(|call| {
            call.source() == call.occurrence().erase().as_row()
                && call.endpoint() == call.occurrence().erase()
                && call.trace_target() != &call.endpoint()
        }));
        assert_eq!(calls[7].source(), calls[7].occurrence().erase().as_row());
        assert_eq!(calls[7].endpoint(), calls[7].occurrence().erase());
        assert_eq!(calls[7].trace_target(), &calls[7].endpoint());

        assert_eq!(inputs.evidence_order().len(), 9);
        assert!(
            inputs
                .evidence_order()
                .windows(2)
                .all(|pair| pair[0].traversal_order() < pair[1].traversal_order())
        );
        let assertion = &inputs.compiler_asserts().assertions()[0];
        assert_eq!(assertion.id().index(), calls[0].id().index());
        let assertion_rank = inputs
            .evidence_order()
            .iter()
            .find(|ranked| {
                ranked.witness() == super::PanicWitnessId::CompilerAssert(assertion.id())
            })
            .unwrap()
            .rank();
        let first_call_rank = inputs
            .evidence_order()
            .iter()
            .find(|ranked| ranked.witness() == super::PanicWitnessId::Call(calls[0].id()))
            .unwrap()
            .rank();
        assert_ne!(assertion_rank, first_call_rank);
        assert!(first_call_rank < assertion_rank);
        assert!(calls.iter().all(|call| {
            inputs
                .evidence_order()
                .iter()
                .filter(|ranked| ranked.witness() == super::PanicWitnessId::Call(call.id()))
                .count()
                == 1
        }));
        let mut missing_target_data = inputs.clone();
        assert!(missing_target_data.test_clear_call_metadata_target_data(0));
        let malformed_call = missing_target_data.calls().next().unwrap().unwrap();
        assert!(matches!(
            malformed_call.presentation_target(),
            Err(super::CompilerAssertInputError::InvalidResolvedInput { .. })
        ));
        let mut tampered = inputs.clone();
        tampered.calls[0].boundary_index = usize::MAX;
        assert_eq!(tampered.call_count(), inputs.call_count());
        assert!(matches!(
            tampered.calls().next(),
            Some(Err(
                super::CompilerAssertInputError::InvalidResolvedInput { .. }
            ))
        ));
        let compiler_asserts = inputs.compiler_asserts();
        let inputs = compiler_asserts;
        let boundaries = inputs
            .traversal()
            .call_boundaries()
            .iter()
            .map(crate::analysis::facts::program::root_traversal::ResolvedCallBoundary::payload)
            .collect::<Vec<_>>();
        assert!(boundaries.iter().any(|boundary| matches!(
            boundary,
            super::CompilerAssertBoundary::PanicContract(super::PanicContractBoundary::Call(_))
        )));
        assert!(
            boundaries
                .iter()
                .any(|boundary| matches!(boundary, super::CompilerAssertBoundary::PanicSink(_)))
        );
        assert!(boundaries.contains(&&super::CompilerAssertBoundary::TrustedNamespace));
        assert!(boundaries.contains(&&super::CompilerAssertBoundary::ForeignDeclaration));
        assert!(boundaries.iter().any(|boundary| matches!(
            boundary,
            super::CompilerAssertBoundary::BodylessDeclaration(_)
        )));
        assert!(
            boundaries
                .iter()
                .any(|boundary| matches!(boundary, super::CompilerAssertBoundary::OpaqueCall(_)))
        );
        assert_eq!(
            boundaries
                .iter()
                .filter(|boundary| matches!(
                    boundary,
                    super::CompilerAssertBoundary::BodylessDeclaration(_)
                ))
                .count(),
            2
        );
        assert_eq!(
            boundaries
                .iter()
                .filter(|boundary| matches!(boundary, super::CompilerAssertBoundary::OpaqueCall(_)))
                .count(),
            3
        );
        assert_eq!(boundaries.len(), 12);
    }
}
