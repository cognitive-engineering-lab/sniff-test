//! Projection of retained panic-call boundaries into owned semantic traces.

#[cfg(test)]
use std::cell::Cell;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use super::compiler_assert_inputs::{
    CompilerAssertInputError, PanicCallInputId, PanicCallInputKind, PanicCallInputView,
    PanicOpaqueBoundaryKind, PanicRootInputs,
};
use super::trace_route::{
    SelectedTraceRoute, TraceRouteEndpoint, TraceRouteError, TraceRouteSelector,
};
use crate::analysis::facts::evaluation::RelationTrace;
use crate::analysis::facts::program::root_traversal::{
    CallTargetSelection, ProgramCallResolution, ResolvedBodyVisit, ResolvedCallMacroFrame,
    ResolvedCallSourceAnchor, ResolvedFollowedCall,
};
use crate::analysis::facts::program::topology::{
    CallKind, CallMacroExpansionEntity, CallOccurrenceEntity, CallSiteEntity, CallSourceAnchorRole,
    CallableEntity, SafetyEffectGroupEntity,
};
use crate::analysis::facts::program::{FunctionEntity, SourceAnchorEntity, SourceAnchorKey};
use crate::analysis::facts::workspace::{
    ScopedEntityId, ScopedEntityRef, ScopedRelationRef, ScopedRowRef,
};

/// Exact body identity retained by every semantic step it owns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PanicCallTraceBody {
    body: ScopedEntityId<FunctionEntity>,
    data: FunctionEntity,
}

impl PanicCallTraceBody {
    #[must_use]
    pub(crate) const fn body(&self) -> &ScopedEntityId<FunctionEntity> {
        &self.body
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &FunctionEntity {
        &self.data
    }
}

/// One exact callable selection and its owned display data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PanicCallTraceCallable {
    selection: CallTargetSelection,
    data: CallableEntity,
}

impl PanicCallTraceCallable {
    #[must_use]
    pub(crate) const fn selection(&self) -> &CallTargetSelection {
        &self.selection
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &CallableEntity {
        &self.data
    }
}

/// How the exact presentation target is rendered before report conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PanicCallTracePresentation {
    MetadataCallable {
        raw_opaque_description: Option<String>,
        semantic_opaque_description: Option<String>,
    },
    Description {
        raw_opaque_description: String,
        semantic_description: String,
    },
}

impl PanicCallTracePresentation {
    #[must_use]
    pub(crate) const fn uses_metadata_callable(&self) -> bool {
        matches!(self, Self::MetadataCallable { .. })
    }

    #[must_use]
    pub(crate) fn raw_opaque_description(&self) -> Option<&str> {
        match self {
            Self::MetadataCallable {
                raw_opaque_description,
                ..
            } => raw_opaque_description.as_deref(),
            Self::Description {
                raw_opaque_description,
                ..
            } => Some(raw_opaque_description),
        }
    }

    #[must_use]
    pub(crate) fn semantic_description(&self) -> Option<&str> {
        match self {
            Self::MetadataCallable {
                semantic_opaque_description,
                ..
            } => semantic_opaque_description.as_deref(),
            Self::Description {
                semantic_description,
                ..
            } => Some(semantic_description),
        }
    }
}

/// An owned semantic endpoint; descriptions intentionally remain functionless.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PanicCallTraceNode {
    Function {
        body: ScopedEntityId<FunctionEntity>,
        data: FunctionEntity,
    },
    Macro {
        frame: ScopedEntityId<CallMacroExpansionEntity>,
        data: CallMacroExpansionEntity,
    },
    Callable(PanicCallTraceCallable),
    Description(String),
}

impl PanicCallTraceNode {
    #[must_use]
    pub(crate) fn display_path(&self) -> &str {
        match self {
            Self::Function { data, .. } => data.display_path(),
            Self::Macro { data, .. } => data.display_path(),
            Self::Callable(target) => target.data().display_path(),
            Self::Description(description) => description,
        }
    }
}

/// Why a source anchor was selected for a semantic step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PanicCallTraceSourceRole {
    Call(CallSourceAnchorRole),
    MacroCallsite,
}

/// Exact source identity and the relation proving its role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PanicCallTraceSource {
    anchor: ScopedEntityId<SourceAnchorEntity>,
    key: SourceAnchorKey,
    role: PanicCallTraceSourceRole,
    relation: ScopedRelationRef,
}

impl PanicCallTraceSource {
    #[must_use]
    pub(crate) const fn anchor(&self) -> &ScopedEntityId<SourceAnchorEntity> {
        &self.anchor
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &SourceAnchorKey {
        &self.key
    }

    #[must_use]
    pub(crate) const fn role(&self) -> PanicCallTraceSourceRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// Complete owned semantic data for one followed call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PanicCallFollowedTrace {
    occurrence: ScopedEntityId<CallOccurrenceEntity>,
    occurrence_data: CallOccurrenceEntity,
    call_site: ScopedEntityId<CallSiteEntity>,
    call_site_data: CallSiteEntity,
    safety_group: ScopedEntityId<SafetyEffectGroupEntity>,
    safety_group_data: SafetyEffectGroupEntity,
    effective_kind: CallKind,
    resolution: ProgramCallResolution,
    target: CallTargetSelection,
}

impl PanicCallFollowedTrace {
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
    pub(crate) const fn effective_kind(&self) -> CallKind {
        self.effective_kind
    }

    #[must_use]
    pub(crate) const fn resolution(&self) -> &ProgramCallResolution {
        &self.resolution
    }

    #[must_use]
    pub(crate) const fn target(&self) -> &CallTargetSelection {
        &self.target
    }
}

/// Exact terminal-call provenance retained independently from policy metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PanicCallTerminalTrace {
    call_id: PanicCallInputId,
    traversal_order: u64,
    consumer_call_site: ScopedEntityId<CallSiteEntity>,
    consumer_call_site_data: CallSiteEntity,
    evidence_group: ScopedEntityId<CallSiteEntity>,
    evidence_group_data: CallSiteEntity,
    effective_kind: CallKind,
    resolution: ProgramCallResolution,
    boundary: PanicCallInputKind,
    metadata_target: Option<PanicCallTraceCallable>,
    contract_target: Option<CallTargetSelection>,
    presentation: PanicCallTracePresentation,
    boundary_description: Option<String>,
    source_anchors: Vec<ResolvedCallSourceAnchor>,
}

impl PanicCallTerminalTrace {
    #[must_use]
    pub(crate) const fn call_id(&self) -> PanicCallInputId {
        self.call_id
    }

    #[must_use]
    pub(crate) const fn traversal_order(&self) -> u64 {
        self.traversal_order
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
    pub(crate) const fn evidence_group(&self) -> &ScopedEntityId<CallSiteEntity> {
        &self.evidence_group
    }

    #[must_use]
    pub(crate) const fn evidence_group_data(&self) -> &CallSiteEntity {
        &self.evidence_group_data
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
    pub(crate) const fn boundary(&self) -> PanicCallInputKind {
        self.boundary
    }

    #[must_use]
    pub(crate) const fn metadata_target(&self) -> Option<&PanicCallTraceCallable> {
        self.metadata_target.as_ref()
    }

    #[must_use]
    pub(crate) const fn contract_target(&self) -> Option<&CallTargetSelection> {
        self.contract_target.as_ref()
    }

    #[must_use]
    pub(crate) const fn presentation(&self) -> &PanicCallTracePresentation {
        &self.presentation
    }

    #[must_use]
    pub(crate) const fn presentation_callable(&self) -> Option<&PanicCallTraceCallable> {
        if self.presentation.uses_metadata_callable() {
            self.metadata_target.as_ref()
        } else {
            None
        }
    }

    #[must_use]
    pub(crate) fn boundary_description(&self) -> Option<&str> {
        self.boundary_description.as_deref()
    }

    #[must_use]
    pub(crate) fn source_anchors(&self) -> &[ResolvedCallSourceAnchor] {
        &self.source_anchors
    }
}

/// Exact provenance carried by one semantic edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PanicCallSemanticTraceStepKind {
    Macro {
        occurrence: ScopedEntityId<CallOccurrenceEntity>,
        occurrence_data: CallOccurrenceEntity,
        frame: ScopedEntityId<CallMacroExpansionEntity>,
    },
    FollowedCall(Box<PanicCallFollowedTrace>),
    TerminalCall,
}

/// Report-facing semantic edge without exposing projector-owned provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PanicCallSemanticEdge {
    MacroExpansion,
    Call(CallKind),
}

/// One dense owned semantic trace step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PanicCallSemanticTraceStep {
    position: u32,
    owner: PanicCallTraceBody,
    caller: PanicCallTraceNode,
    source: Option<PanicCallTraceSource>,
    target: PanicCallTraceNode,
    kind: PanicCallSemanticTraceStepKind,
    edge: PanicCallSemanticEdge,
}

impl PanicCallSemanticTraceStep {
    #[must_use]
    pub(crate) const fn position(&self) -> u32 {
        self.position
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> &PanicCallTraceBody {
        &self.owner
    }

    #[must_use]
    pub(crate) const fn caller(&self) -> &PanicCallTraceNode {
        &self.caller
    }

    #[must_use]
    pub(crate) fn caller_display_path(&self) -> &str {
        self.caller.display_path()
    }

    #[must_use]
    pub(crate) const fn source(&self) -> Option<&PanicCallTraceSource> {
        self.source.as_ref()
    }

    #[must_use]
    pub(crate) fn source_key(&self) -> Option<&SourceAnchorKey> {
        self.source.as_ref().map(PanicCallTraceSource::key)
    }

    #[must_use]
    pub(crate) const fn target(&self) -> &PanicCallTraceNode {
        &self.target
    }

    #[must_use]
    pub(crate) fn target_display_path(&self) -> &str {
        self.target.display_path()
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> &PanicCallSemanticTraceStepKind {
        &self.kind
    }

    #[must_use]
    pub(crate) const fn edge(&self) -> PanicCallSemanticEdge {
        self.edge
    }
}

/// Complete semantic projection selected for one dense retained call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PanicCallSemanticTrace {
    witness_order: u64,
    source: ScopedRowRef,
    endpoint: ScopedEntityId<CallOccurrenceEntity>,
    endpoint_data: CallOccurrenceEntity,
    trace_target: ScopedEntityRef,
    relation_trace: RelationTrace,
    terminal: PanicCallTerminalTrace,
    steps: Vec<PanicCallSemanticTraceStep>,
}

impl PanicCallSemanticTrace {
    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) const fn source(&self) -> &ScopedRowRef {
        &self.source
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityId<CallOccurrenceEntity> {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn endpoint_data(&self) -> &CallOccurrenceEntity {
        &self.endpoint_data
    }

    #[must_use]
    pub(crate) const fn trace_target(&self) -> &ScopedEntityRef {
        &self.trace_target
    }

    #[must_use]
    pub(crate) const fn relation_trace(&self) -> &RelationTrace {
        &self.relation_trace
    }

    #[must_use]
    pub(crate) const fn terminal(&self) -> &PanicCallTerminalTrace {
        &self.terminal
    }

    #[must_use]
    pub(crate) fn steps(&self) -> &[PanicCallSemanticTraceStep] {
        &self.steps
    }
}

/// Integrity failure while projecting already-resolved call selections.
#[derive(Debug)]
pub(crate) enum PanicCallTraceError {
    Input(Box<CompilerAssertInputError>),
    NonDenseCallId { expected: u64, found: u64 },
    UnknownCallId { call_id: u64 },
    InvalidRootTrace { call_id: u64 },
    InvalidPresentationTarget { call_id: u64 },
    InvalidTracePrefix,
    MissingCallerBody { occurrence: ScopedEntityRef },
    AmbiguousCallerBody { occurrence: ScopedEntityRef },
    MissingEnteredBody { callable: ScopedEntityRef },
    AmbiguousEnteredBody { callable: ScopedEntityRef },
    TargetBodyMismatch { callable: ScopedEntityRef },
    NonMonotonicTraversalOrder,
    MarkerRegression,
    DuplicateSelectedCall { occurrence: ScopedEntityRef },
    PositionOverflow,
}

impl Display for PanicCallTraceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid panic-call semantic trace: {self:?}")
    }
}

impl Error for PanicCallTraceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Input(source) => Some(source),
            _ => None,
        }
    }
}

impl From<CompilerAssertInputError> for PanicCallTraceError {
    fn from(error: CompilerAssertInputError) -> Self {
        Self::Input(Box::new(error))
    }
}

impl From<TraceRouteError> for PanicCallTraceError {
    fn from(error: TraceRouteError) -> Self {
        match error {
            TraceRouteError::MissingCallerBody { occurrence } => {
                Self::MissingCallerBody { occurrence }
            }
            TraceRouteError::AmbiguousCallerBody { occurrence } => {
                Self::AmbiguousCallerBody { occurrence }
            }
            TraceRouteError::MissingEnteredBody { callable } => {
                Self::MissingEnteredBody { callable }
            }
            TraceRouteError::AmbiguousEnteredBody { callable } => {
                Self::AmbiguousEnteredBody { callable }
            }
            TraceRouteError::TargetBodyMismatch { callable } => {
                Self::TargetBodyMismatch { callable }
            }
            TraceRouteError::InvalidTracePrefix => Self::InvalidTracePrefix,
            TraceRouteError::NonMonotonicTraversalOrder => Self::NonMonotonicTraversalOrder,
            TraceRouteError::MarkerRegression => Self::MarkerRegression,
            TraceRouteError::DuplicateSelectedCall { occurrence } => {
                Self::DuplicateSelectedCall { occurrence }
            }
        }
    }
}

struct PreparedPanicCallProjection<'a> {
    call: PanicCallInputView<'a>,
    caller: &'a ResolvedBodyVisit,
    route: usize,
}

#[cfg(test)]
thread_local! {
    static REJECTED_PRESENTATION_CALL_ID: Cell<Option<u64>> = const { Cell::new(None) };
}

#[cfg(test)]
pub(super) struct PanicCallPresentationRejectionGuard {
    previous: Option<u64>,
}

#[cfg(test)]
impl Drop for PanicCallPresentationRejectionGuard {
    fn drop(&mut self) {
        REJECTED_PRESENTATION_CALL_ID.set(self.previous);
    }
}

#[cfg(test)]
#[must_use]
pub(super) fn reject_call_presentation_for_test(
    call_id: u64,
) -> PanicCallPresentationRejectionGuard {
    let previous = REJECTED_PRESENTATION_CALL_ID.replace(Some(call_id));
    PanicCallPresentationRejectionGuard { previous }
}

#[cfg(test)]
fn presentation_rejected_for_test(call_id: u64) -> bool {
    REJECTED_PRESENTATION_CALL_ID.get() == Some(call_id)
}

/// Validated root-local projection index for retained panic calls.
pub(crate) struct PanicCallTraceProjector<'a> {
    projections: Vec<PreparedPanicCallProjection<'a>>,
    routes: Vec<SelectedTraceRoute<'a>>,
}

impl<'a> PanicCallTraceProjector<'a> {
    pub(crate) fn prepare(inputs: &'a PanicRootInputs) -> Result<Self, PanicCallTraceError> {
        inputs.validate_retained_call_invariants()?;
        let mut route_selector = TraceRouteSelector::prepare(inputs.traversal());
        let mut route_by_caller = HashMap::<*const ResolvedBodyVisit, usize>::new();
        let mut routes = Vec::<SelectedTraceRoute<'a>>::new();
        let mut projections = Vec::with_capacity(inputs.call_count());
        for (expected, call) in inputs.calls().enumerate() {
            let call = call?;
            let expected =
                u64::try_from(expected).map_err(|_| PanicCallTraceError::PositionOverflow)?;
            let found = u64::try_from(call.id().index())
                .map_err(|_| PanicCallTraceError::PositionOverflow)?;
            if found != expected {
                return Err(PanicCallTraceError::NonDenseCallId { expected, found });
            }
            let expected_trace_target = call.metadata_target().map_or_else(
                || call.occurrence().erase(),
                |target| target.callable().erase(),
            );
            if call.trace().root() != &inputs.root().entity
                || call.trace().target() != &expected_trace_target
                || call.trace_target() != &expected_trace_target
            {
                return Err(PanicCallTraceError::InvalidRootTrace { call_id: found });
            }
            let occurrence = call.occurrence().erase();
            let caller = route_selector.select_terminal_caller(
                &occurrence,
                *call.occurrence_data().key().owner(),
                call.inherited_markers(),
                call.trace(),
            )?;
            let endpoint =
                TraceRouteEndpoint::new(call.order(), call.trace(), call.inherited_markers());
            let caller_identity = std::ptr::from_ref(caller);
            let route = if let Some(route) = route_by_caller.get(&caller_identity).copied() {
                routes[route].validate_reuse(endpoint)?;
                route
            } else {
                let selected = route_selector.select_route(endpoint)?;
                let route = routes.len();
                routes.push(selected);
                route_by_caller.insert(caller_identity, route);
                route
            };
            call.presentation_target()?;
            projections.push(PreparedPanicCallProjection {
                call,
                caller,
                route,
            });
        }
        Ok(Self {
            projections,
            routes,
        })
    }

    pub(crate) fn call(&self, call_id: u64) -> Result<PanicCallInputView<'a>, PanicCallTraceError> {
        Ok(self.prepared(call_id)?.call)
    }

    pub(crate) fn project(
        &self,
        call_id: u64,
    ) -> Result<PanicCallSemanticTrace, PanicCallTraceError> {
        let prepared = self.prepared(call_id)?;
        #[cfg(test)]
        if presentation_rejected_for_test(call_id) {
            return Err(PanicCallTraceError::InvalidPresentationTarget { call_id });
        }
        let mut steps = Vec::new();
        for selected in self.routes[prepared.route].calls() {
            append_followed_call_steps(&mut steps, selected.caller(), selected.call())?;
        }
        let terminal = terminal_trace(prepared.call)?;
        append_terminal_call_steps(&mut steps, prepared.caller, prepared.call, &terminal)?;
        Ok(PanicCallSemanticTrace {
            witness_order: call_id,
            source: prepared.call.source(),
            endpoint: prepared.call.occurrence().clone(),
            endpoint_data: prepared.call.occurrence_data().clone(),
            trace_target: prepared.call.trace_target().clone(),
            relation_trace: prepared.call.trace().clone(),
            terminal,
            steps,
        })
    }

    fn prepared(
        &self,
        call_id: u64,
    ) -> Result<&PreparedPanicCallProjection<'a>, PanicCallTraceError> {
        let index =
            usize::try_from(call_id).map_err(|_| PanicCallTraceError::UnknownCallId { call_id })?;
        self.projections
            .get(index)
            .ok_or(PanicCallTraceError::UnknownCallId { call_id })
    }
}

fn terminal_trace(
    call: PanicCallInputView<'_>,
) -> Result<PanicCallTerminalTrace, PanicCallTraceError> {
    let call_id =
        u64::try_from(call.id().index()).map_err(|_| PanicCallTraceError::PositionOverflow)?;
    let target = call.presentation_target()?;
    let raw_opaque_description = target.opaque_description().map(str::to_owned);
    let semantic_description = target.opaque_description().map(|description| {
        normalized_opaque_description(
            call.effective_kind(),
            call.occurrence_data().requires_unsafe(),
            description,
        )
    });
    let metadata_target =
        call.metadata_target()
            .zip(call.metadata_target_data())
            .map(|(selection, data)| PanicCallTraceCallable {
                selection: selection.clone(),
                data: data.clone(),
            });
    let presentation = if let Some(callable) = target.callable() {
        let Some(metadata) = metadata_target.as_ref() else {
            return Err(PanicCallTraceError::InvalidPresentationTarget { call_id });
        };
        if metadata.selection() != callable.selection() || metadata.data() != callable.data() {
            return Err(PanicCallTraceError::InvalidPresentationTarget { call_id });
        }
        PanicCallTracePresentation::MetadataCallable {
            raw_opaque_description,
            semantic_opaque_description: semantic_description,
        }
    } else {
        let Some(raw_opaque_description) = raw_opaque_description else {
            return Err(PanicCallTraceError::InvalidPresentationTarget { call_id });
        };
        let Some(semantic_description) = semantic_description else {
            return Err(PanicCallTraceError::InvalidPresentationTarget { call_id });
        };
        PanicCallTracePresentation::Description {
            raw_opaque_description,
            semantic_description,
        }
    };
    Ok(PanicCallTerminalTrace {
        call_id: call.id(),
        traversal_order: call.order(),
        consumer_call_site: call.consumer_call_site().clone(),
        consumer_call_site_data: call.consumer_call_site_data().clone(),
        evidence_group: call.evidence_group().clone(),
        evidence_group_data: call.evidence_group_data().clone(),
        effective_kind: call.effective_kind(),
        resolution: call.resolution().clone(),
        boundary: call.kind(),
        metadata_target,
        contract_target: call.contract_target().cloned(),
        presentation,
        boundary_description: call.opaque_description().map(|description| {
            if matches!(
                call.kind(),
                PanicCallInputKind::Opaque {
                    kind: PanicOpaqueBoundaryKind::ExplicitOpaque
                }
            ) {
                normalized_opaque_description(
                    call.effective_kind(),
                    call.occurrence_data().requires_unsafe(),
                    description,
                )
            } else {
                description.to_owned()
            }
        }),
        source_anchors: call.source_anchors().to_vec(),
    })
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

fn append_followed_call_steps(
    steps: &mut Vec<PanicCallSemanticTraceStep>,
    owner: &ResolvedBodyVisit,
    call: &ResolvedFollowedCall,
) -> Result<(), PanicCallTraceError> {
    let trace_owner = trace_body(owner);
    let mut caller = function_node(owner);
    for frame in call.macro_frames() {
        let target = macro_node(frame);
        push_step(
            steps,
            trace_owner.clone(),
            caller,
            frame.callsite().map(macro_source),
            target.clone(),
            PanicCallSemanticTraceStepKind::Macro {
                occurrence: call.occurrence().clone(),
                occurrence_data: call.occurrence_data().clone(),
                frame: frame.frame().clone(),
            },
            PanicCallSemanticEdge::MacroExpansion,
        )?;
        caller = target;
    }
    push_step(
        steps,
        trace_owner,
        caller,
        selected_call_source(call.source_anchors()),
        PanicCallTraceNode::Callable(PanicCallTraceCallable {
            selection: call.target().clone(),
            data: call.target_data().clone(),
        }),
        PanicCallSemanticTraceStepKind::FollowedCall(Box::new(PanicCallFollowedTrace {
            occurrence: call.occurrence().clone(),
            occurrence_data: call.occurrence_data().clone(),
            call_site: call.call_site().clone(),
            call_site_data: call.call_site_data().clone(),
            safety_group: call.safety_group().clone(),
            safety_group_data: call.safety_group_data().clone(),
            effective_kind: call.effective_kind(),
            resolution: call.resolution().clone(),
            target: call.target().clone(),
        })),
        PanicCallSemanticEdge::Call(call.effective_kind()),
    )
}

fn append_terminal_call_steps(
    steps: &mut Vec<PanicCallSemanticTraceStep>,
    owner: &ResolvedBodyVisit,
    call: PanicCallInputView<'_>,
    terminal: &PanicCallTerminalTrace,
) -> Result<(), PanicCallTraceError> {
    let trace_owner = trace_body(owner);
    let mut caller = function_node(owner);
    for frame in call.macro_frames() {
        let target = macro_node(frame);
        push_step(
            steps,
            trace_owner.clone(),
            caller,
            frame.callsite().map(macro_source),
            target.clone(),
            PanicCallSemanticTraceStepKind::Macro {
                occurrence: call.occurrence().clone(),
                occurrence_data: call.occurrence_data().clone(),
                frame: frame.frame().clone(),
            },
            PanicCallSemanticEdge::MacroExpansion,
        )?;
        caller = target;
    }
    let target = if let Some(callable) = terminal.presentation_callable() {
        PanicCallTraceNode::Callable(callable.clone())
    } else {
        PanicCallTraceNode::Description(
            terminal
                .presentation()
                .semantic_description()
                .ok_or(PanicCallTraceError::InvalidTracePrefix)?
                .to_owned(),
        )
    };
    push_step(
        steps,
        trace_owner,
        caller,
        selected_call_source(call.source_anchors()),
        target,
        PanicCallSemanticTraceStepKind::TerminalCall,
        PanicCallSemanticEdge::Call(call.effective_kind()),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "semantic steps retain each independently meaningful provenance facet"
)]
fn push_step(
    steps: &mut Vec<PanicCallSemanticTraceStep>,
    owner: PanicCallTraceBody,
    caller: PanicCallTraceNode,
    source: Option<PanicCallTraceSource>,
    target: PanicCallTraceNode,
    kind: PanicCallSemanticTraceStepKind,
    edge: PanicCallSemanticEdge,
) -> Result<(), PanicCallTraceError> {
    let position = u32::try_from(steps.len()).map_err(|_| PanicCallTraceError::PositionOverflow)?;
    steps.push(PanicCallSemanticTraceStep {
        position,
        owner,
        caller,
        source,
        target,
        kind,
        edge,
    });
    Ok(())
}

fn trace_body(visit: &ResolvedBodyVisit) -> PanicCallTraceBody {
    PanicCallTraceBody {
        body: visit.body().clone(),
        data: visit.data().clone(),
    }
}

fn function_node(visit: &ResolvedBodyVisit) -> PanicCallTraceNode {
    PanicCallTraceNode::Function {
        body: visit.body().clone(),
        data: visit.data().clone(),
    }
}

fn macro_node(frame: &ResolvedCallMacroFrame) -> PanicCallTraceNode {
    PanicCallTraceNode::Macro {
        frame: frame.frame().clone(),
        data: frame.data().clone(),
    }
}

fn macro_source(
    source: &crate::analysis::facts::program::root_traversal::ResolvedCallMacroCallsite,
) -> PanicCallTraceSource {
    PanicCallTraceSource {
        anchor: source.anchor().clone(),
        key: source.key().clone(),
        role: PanicCallTraceSourceRole::MacroCallsite,
        relation: source.relation().clone(),
    }
}

fn selected_call_source(anchors: &[ResolvedCallSourceAnchor]) -> Option<PanicCallTraceSource> {
    [
        CallSourceAnchorRole::Expanded,
        CallSourceAnchorRole::Presentation,
    ]
    .into_iter()
    .find_map(|role| {
        anchors
            .iter()
            .find(|anchor| anchor.role() == role)
            .map(|anchor| PanicCallTraceSource {
                anchor: anchor.anchor().clone(),
                key: anchor.key().clone(),
                role: PanicCallTraceSourceRole::Call(role),
                relation: anchor.relation().clone(),
            })
    })
}

#[cfg(test)]
mod tests {
    use super::{
        PanicCallSemanticEdge, PanicCallSemanticTraceStepKind, PanicCallTraceNode,
        PanicCallTraceProjector,
    };
    use crate::analysis::facts::builder::FactMeta;
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::evaluation::RelationTrace;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::panic::compiler_assert_inputs::{
        PanicCallInputKind, PanicOpaqueBoundaryKind, PanicRootInputs,
    };
    use crate::analysis::facts::panic::compiler_assert_trace::tests::{
        attach_named_call_macros_and_sources, attach_panic_marker_to_call, declared_builder,
        definition, insert_configured_call, insert_direct_call, insert_function, instance,
        resolve_single_panic_artifact, type_hash,
    };
    use crate::analysis::facts::panic::contracts::PanicContractFact;
    use crate::analysis::facts::panic::trace_route::{reset_trace_route_work, trace_route_work};
    use crate::analysis::facts::program::FunctionKey;
    use crate::analysis::facts::program::root_traversal::ProgramCallResolution;
    use crate::analysis::facts::program::topology::{
        CallAttributionRole, CallKind, CallOccurrenceTargetsCallable, CallTargetRole,
        CallableEntity, CallableKey, CallableKeyEntity,
    };
    use crate::analysis::facts::program::workspace_index::CallableResolutionKind;
    use crate::analysis::facts::schema::PassId;

    fn opaque_inputs(targetful: bool, requires_unsafe: bool) -> PanicRootInputs {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let ordinal = if targetful { 50 } else { 60 };
        let root = FunctionKey::new(definition(ordinal), None);
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let occurrence = insert_configured_call(
            &mut builder,
            &root_body,
            root,
            0,
            CallKind::IndirectCall,
            vec![CallAttributionRole::CallSite],
            None,
            None,
            requires_unsafe,
            Some(String::from("raw opaque description")),
        );
        if targetful {
            let target = FunctionKey::new(definition(ordinal + 1), None);
            let callable = builder
                .insert_entity(&CallableEntity::new(
                    target,
                    "crate::opaque_target",
                    false,
                    false,
                    true,
                    false,
                    vec![String::from("crate::opaque_target")],
                ))
                .unwrap();
            builder
                .relate(
                    &occurrence,
                    &callable,
                    &CallOccurrenceTargetsCallable::new(CallTargetRole::OpaqueFunction),
                )
                .unwrap();
        }
        resolve_single_panic_artifact(&registry, builder, root, 8)
    }

    #[test]
    fn direct_terminal_call_projects_one_owned_step() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(1), None);
        let target = FunctionKey::new(definition(2), Some(instance(2)));
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let target_callable = builder
            .insert_entity(&CallableEntity::new(
                target,
                "crate::bodyless",
                false,
                false,
                false,
                false,
                vec![String::from("crate::bodyless")],
            ))
            .unwrap();
        insert_direct_call(&mut builder, &root_body, root, 0, &target_callable);
        let inputs = resolve_single_panic_artifact(&registry, builder, root, 8);

        let projector = PanicCallTraceProjector::prepare(&inputs).unwrap();
        let call = projector.call(0).unwrap();
        let trace = projector.project(0).unwrap();

        assert_eq!(call.id().index(), 0);
        assert_eq!(trace.witness_order(), 0);
        assert_eq!(trace.source(), &call.source());
        assert_eq!(trace.endpoint(), call.occurrence());
        assert_eq!(trace.endpoint_data(), call.occurrence_data());
        assert_eq!(trace.trace_target(), call.trace_target());
        assert_eq!(trace.relation_trace(), call.trace());
        let [step] = trace.steps() else {
            panic!("a direct terminal call must project exactly one semantic step")
        };
        assert_eq!(step.position(), 0);
        assert_eq!(step.caller_display_path(), "crate::root");
        assert_eq!(step.target_display_path(), "crate::bodyless");
        assert_eq!(
            step.edge(),
            PanicCallSemanticEdge::Call(CallKind::DirectCall)
        );
    }

    #[test]
    fn exact_callable_may_enter_its_same_definition_generic_body() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(3), None);
        let target_definition = definition(4);
        let exact_target = FunctionKey::new(target_definition, Some(instance(4)));
        let generic_target = FunctionKey::new(target_definition, None);
        let terminal = FunctionKey::new(definition(5), Some(instance(5)));
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let (target_body, _) =
            insert_function(&mut builder, generic_target, "crate::generic_target");
        let exact_target_callable = builder
            .insert_entity(&CallableEntity::new(
                exact_target,
                "crate::generic_target::<u8>",
                false,
                false,
                true,
                false,
                vec![String::from("crate::generic_target::<u8>")],
            ))
            .unwrap();
        let terminal_callable = builder
            .insert_entity(&CallableEntity::new(
                terminal,
                "crate::terminal",
                false,
                false,
                false,
                false,
                vec![String::from("crate::terminal")],
            ))
            .unwrap();
        insert_direct_call(&mut builder, &root_body, root, 0, &exact_target_callable);
        insert_direct_call(
            &mut builder,
            &target_body,
            generic_target,
            0,
            &terminal_callable,
        );
        let inputs = resolve_single_panic_artifact(&registry, builder, root, 8);

        let projector = PanicCallTraceProjector::prepare(&inputs)
            .expect("the explicit exact-to-generic body selection is a valid trace route");
        let trace = projector.project(0).unwrap();

        assert_eq!(trace.steps().len(), 2);
        assert_eq!(
            trace.steps()[0].target_display_path(),
            "crate::generic_target::<u8>"
        );
        assert_eq!(
            trace.steps()[1].caller_display_path(),
            "crate::generic_target"
        );
        assert_eq!(trace.steps()[1].target_display_path(), "crate::terminal");
    }

    #[test]
    fn policy_trace_callable_can_have_a_description_only_presentation() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(10), None);
        let source = FunctionKey::new(definition(11), None);
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let source_callable = builder
            .insert_entity(&CallableEntity::new(
                source,
                "crate::source_contract",
                false,
                false,
                false,
                false,
                vec![String::from("crate::source_contract")],
            ))
            .unwrap();
        let occurrence = insert_configured_call(
            &mut builder,
            &root_body,
            root,
            0,
            CallKind::DirectCall,
            vec![CallAttributionRole::CallSite],
            None,
            None,
            false,
            Some(String::from("source-level opaque call")),
        );
        builder
            .relate(
                &occurrence,
                &source_callable,
                &CallOccurrenceTargetsCallable::new(CallTargetRole::SourceContract),
            )
            .unwrap();
        let inputs = resolve_single_panic_artifact(&registry, builder, root, 8);

        let projector = PanicCallTraceProjector::prepare(&inputs).unwrap();
        let call = projector.call(0).unwrap();
        let trace = projector.project(0).unwrap();

        assert_ne!(trace.trace_target(), &call.occurrence().erase());
        assert_eq!(
            trace.trace_target(),
            &call.metadata_target().unwrap().callable().erase()
        );
        assert!(trace.terminal().metadata_target().is_some());
        assert!(trace.terminal().presentation_callable().is_none());
        assert_eq!(
            trace.terminal().presentation().semantic_description(),
            Some("source-level opaque call")
        );
        let [step] = trace.steps() else {
            panic!("the description-only terminal has one semantic step")
        };
        assert!(matches!(
            step.target(),
            PanicCallTraceNode::Description(description)
                if description == "source-level opaque call"
        ));
    }

    #[test]
    fn callable_presentation_remains_distinct_from_source_contract_authority() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(20), None);
        let target_definition = definition(21);
        let runtime = FunctionKey::new(target_definition, Some(instance(21)));
        let source = FunctionKey::new(target_definition, None);
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let runtime_callable = builder
            .insert_entity(&CallableEntity::new(
                runtime,
                "crate::runtime",
                false,
                false,
                true,
                false,
                vec![String::from("crate::runtime")],
            ))
            .unwrap();
        let source_callable = builder
            .insert_entity(&CallableEntity::new(
                source,
                "crate::source",
                false,
                false,
                true,
                false,
                vec![String::from("crate::source")],
            ))
            .unwrap();
        let occurrence = insert_direct_call(&mut builder, &root_body, root, 0, &runtime_callable);
        builder
            .relate(
                &occurrence,
                &source_callable,
                &CallOccurrenceTargetsCallable::new(CallTargetRole::SourceContract),
            )
            .unwrap();
        builder
            .insert_fact(
                &PanicContractFact::new(),
                FactMeta::new(PassId::new("test.call-trace-contract").unwrap())
                    .with_owner(&source_callable)
                    .unwrap(),
            )
            .unwrap();
        let inputs = resolve_single_panic_artifact(&registry, builder, root, 8);

        let trace = PanicCallTraceProjector::prepare(&inputs)
            .unwrap()
            .project(0)
            .unwrap();
        let terminal = trace.terminal();

        assert_eq!(terminal.metadata_target().unwrap().data().key(), &runtime);
        assert_eq!(
            terminal.presentation_callable().unwrap().data().key(),
            &runtime
        );
        assert_eq!(
            terminal.contract_target().unwrap().role(),
            CallTargetRole::SourceContract
        );
        assert_ne!(
            terminal.presentation_callable().unwrap().selection(),
            terminal.contract_target().unwrap()
        );
        let [step] = trace.steps() else {
            panic!("the documented terminal has one semantic step")
        };
        assert_eq!(step.target_display_path(), "crate::runtime");
    }

    #[test]
    fn terminal_attached_marker_does_not_select_the_caller_route() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(30), None);
        let target = FunctionKey::new(definition(31), Some(instance(31)));
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let target_callable = builder
            .insert_entity(&CallableEntity::new(
                target,
                "crate::bodyless",
                false,
                false,
                false,
                false,
                vec![String::from("crate::bodyless")],
            ))
            .unwrap();
        let occurrence = insert_direct_call(&mut builder, &root_body, root, 0, &target_callable);
        attach_panic_marker_to_call(&mut builder, &occurrence, 30);
        let inputs = resolve_single_panic_artifact(&registry, builder, root, 8);

        let projector = PanicCallTraceProjector::prepare(&inputs).unwrap();
        let call = projector.call(0).unwrap();

        assert!(call.inherited_markers().is_empty());
        assert_eq!(call.attached_marker_candidates().len(), 1);
        assert_eq!(call.markers(), call.attached_marker_candidates());
        assert_eq!(projector.project(0).unwrap().steps().len(), 1);
    }

    #[test]
    fn nested_followed_route_ends_at_the_selected_terminal_caller() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(40), None);
        let middle = FunctionKey::new(definition(41), Some(instance(41)));
        let terminal = FunctionKey::new(definition(42), Some(instance(42)));
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let (middle_body, middle_callable) = insert_function(&mut builder, middle, "crate::middle");
        let terminal_callable = builder
            .insert_entity(&CallableEntity::new(
                terminal,
                "crate::terminal",
                false,
                false,
                false,
                false,
                vec![String::from("crate::terminal")],
            ))
            .unwrap();
        insert_direct_call(&mut builder, &root_body, root, 0, &middle_callable);
        insert_direct_call(&mut builder, &middle_body, middle, 0, &terminal_callable);
        let inputs = resolve_single_panic_artifact(&registry, builder, root, 16);

        let trace = PanicCallTraceProjector::prepare(&inputs)
            .unwrap()
            .project(0)
            .unwrap();
        let [followed, terminal_step] = trace.steps() else {
            panic!("one followed call must precede the terminal call")
        };

        assert!(matches!(
            followed.kind(),
            PanicCallSemanticTraceStepKind::FollowedCall(_)
        ));
        assert_eq!(followed.owner().data().key(), &root);
        assert_eq!(followed.caller_display_path(), "crate::root");
        assert_eq!(followed.target_display_path(), "crate::middle");
        assert!(matches!(
            terminal_step.kind(),
            PanicCallSemanticTraceStepKind::TerminalCall
        ));
        assert_eq!(terminal_step.owner().data().key(), &middle);
        assert_eq!(terminal_step.caller_display_path(), "crate::middle");
        assert_eq!(terminal_step.target_display_path(), "crate::terminal");
    }

    #[test]
    fn targetful_and_targetless_opaque_calls_keep_exact_presentation_provenance() {
        let targetful_inputs = opaque_inputs(true, true);
        let targetful_projector = PanicCallTraceProjector::prepare(&targetful_inputs).unwrap();
        let targetful_call = targetful_projector.call(0).unwrap();
        let targetful = targetful_projector.project(0).unwrap();
        let terminal = targetful.terminal();

        assert_eq!(
            terminal.consumer_call_site(),
            targetful_call.consumer_call_site()
        );
        assert_eq!(
            terminal.consumer_call_site_data(),
            targetful_call.consumer_call_site_data()
        );
        assert_eq!(terminal.evidence_group(), targetful_call.evidence_group());
        assert_eq!(
            terminal.evidence_group_data(),
            targetful_call.evidence_group_data()
        );
        assert_eq!(
            terminal.presentation().raw_opaque_description(),
            Some("raw opaque description")
        );
        assert_eq!(
            terminal.presentation().semantic_description(),
            Some("indirect call through an unsafe function pointer")
        );
        assert_eq!(
            terminal.boundary_description(),
            Some("indirect call through an unsafe function pointer")
        );
        assert_eq!(
            targetful.steps().last().unwrap().target_display_path(),
            "crate::opaque_target"
        );

        let targetless_inputs = opaque_inputs(false, false);
        let targetless_projector = PanicCallTraceProjector::prepare(&targetless_inputs).unwrap();
        let targetless = targetless_projector.project(0).unwrap();
        let terminal = targetless.terminal();
        assert!(terminal.metadata_target().is_none());
        assert!(terminal.presentation_callable().is_none());
        assert_eq!(
            terminal.presentation().raw_opaque_description(),
            Some("raw opaque description")
        );
        assert_eq!(
            terminal.presentation().semantic_description(),
            Some("indirect call through a function pointer")
        );
        assert_eq!(
            terminal.boundary_description(),
            Some("indirect call through a function pointer")
        );
        assert_eq!(
            targetless.steps().last().unwrap().target_display_path(),
            "indirect call through a function pointer"
        );
    }

    #[test]
    fn terminal_macros_keep_raw_labels_and_exact_source_precedence() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(70), None);
        let target = FunctionKey::new(definition(71), Some(instance(71)));
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let target_callable = builder
            .insert_entity(&CallableEntity::new(
                target,
                "crate::terminal",
                false,
                false,
                false,
                false,
                vec![String::from("crate::terminal")],
            ))
            .unwrap();
        let occurrence = insert_direct_call(&mut builder, &root_body, root, 1, &target_callable);
        let (presentation_key, expanded_key, macro_key) = attach_named_call_macros_and_sources(
            &mut builder,
            &root_body,
            root,
            &occurrence,
            "macro already_prefixed!",
            "inner!",
        );
        let inputs = resolve_single_panic_artifact(&registry, builder, root, 8);

        let trace = PanicCallTraceProjector::prepare(&inputs)
            .unwrap()
            .project(0)
            .unwrap();
        let [outer, inner, terminal] = trace.steps() else {
            panic!("two terminal macro frames must precede the call")
        };

        assert_eq!(outer.target_display_path(), "macro already_prefixed!");
        assert_eq!(inner.caller_display_path(), "macro already_prefixed!");
        assert_eq!(inner.target_display_path(), "inner!");
        assert_eq!(outer.source_key(), Some(&macro_key));
        assert_eq!(inner.source_key(), None);
        assert_eq!(terminal.source_key(), Some(&expanded_key));
        assert_ne!(terminal.source_key(), Some(&presentation_key));
        assert_eq!(trace.terminal().source_anchors().len(), 2);
    }

    #[test]
    fn callable_evidence_terminal_presents_the_synthetic_callable() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(80), None);
        let raw = FunctionKey::new(definition(81), Some(instance(81)));
        let evidence_target = FunctionKey::new(definition(82), Some(instance(82)));
        let callable_key = CallableKey::FnPointer(type_hash(80));
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let raw_callable = builder
            .insert_entity(&CallableEntity::new(
                raw,
                "crate::raw_target",
                false,
                false,
                false,
                false,
                vec![String::from("crate::raw_target")],
            ))
            .unwrap();
        let evidence_callable = builder
            .insert_entity(&CallableEntity::new(
                evidence_target,
                "crate::evidence_target",
                false,
                false,
                false,
                false,
                vec![String::from("crate::evidence_target")],
            ))
            .unwrap();
        let key = builder
            .insert_entity(&CallableKeyEntity::new(callable_key))
            .unwrap();
        let evidence = insert_configured_call(
            &mut builder,
            &root_body,
            root,
            0,
            CallKind::FnPointerReify,
            vec![CallAttributionRole::ErasureSite],
            Some(&key),
            Some(&evidence_callable),
            false,
            None,
        );
        insert_configured_call(
            &mut builder,
            &root_body,
            root,
            1,
            CallKind::IndirectCall,
            vec![CallAttributionRole::CallSite],
            Some(&key),
            Some(&raw_callable),
            false,
            None,
        );
        let inputs = resolve_single_panic_artifact(&registry, builder, root, 16);
        let evidence_visit = inputs
            .traversal()
            .occurrence_visits()
            .iter()
            .find(|visit| visit.data().key() == evidence.key())
            .unwrap();
        let projector = PanicCallTraceProjector::prepare(&inputs).unwrap();
        let resolved_id = (0..u64::try_from(inputs.call_count()).unwrap())
            .find(|call_id| {
                matches!(
                    projector.call(*call_id).unwrap().resolution(),
                    ProgramCallResolution::CallableEvidence { .. }
                )
            })
            .unwrap();

        let trace = projector.project(resolved_id).unwrap();
        let terminal = trace.terminal();
        assert_eq!(terminal.effective_kind(), CallKind::FnPointerCallTarget);
        assert!(matches!(
            terminal.resolution(),
            ProgramCallResolution::CallableEvidence {
                evidence: selected,
                key: selected_key,
                kind: CallableResolutionKind::FunctionPointerEvidence,
            } if selected == evidence_visit.occurrence() && *selected_key == callable_key
        ));
        assert_eq!(
            terminal.presentation_callable().unwrap().data().key(),
            &evidence_target
        );
        assert_eq!(
            trace.steps().last().unwrap().target_display_path(),
            "crate::evidence_target"
        );
    }

    #[test]
    fn invalid_root_or_target_and_unknown_ids_fail_closed() {
        let mut wrong_target = opaque_inputs(true, false);
        let call = wrong_target.calls().next().unwrap().unwrap();
        let target_mismatch = RelationTrace::new(
            call.trace().root().clone(),
            call.occurrence().erase(),
            call.trace().relations().to_vec(),
        );
        assert!(wrong_target.test_set_call_trace(0, target_mismatch));
        assert!(matches!(
            PanicCallTraceProjector::prepare(&wrong_target),
            Err(super::PanicCallTraceError::InvalidRootTrace { call_id: 0 })
        ));

        let mut wrong_root = opaque_inputs(true, false);
        let call = wrong_root.calls().next().unwrap().unwrap();
        let root_mismatch = RelationTrace::new(
            call.occurrence().erase(),
            call.trace().target().clone(),
            call.trace().relations().to_vec(),
        );
        assert!(wrong_root.test_set_call_trace(0, root_mismatch));
        assert!(matches!(
            PanicCallTraceProjector::prepare(&wrong_root),
            Err(super::PanicCallTraceError::InvalidRootTrace { call_id: 0 })
        ));

        let valid = opaque_inputs(true, false);
        let projector = PanicCallTraceProjector::prepare(&valid).unwrap();
        assert!(matches!(
            projector.call(u64::MAX),
            Err(super::PanicCallTraceError::UnknownCallId { call_id: u64::MAX })
        ));
        assert!(matches!(
            projector.project(u64::MAX),
            Err(super::PanicCallTraceError::UnknownCallId { call_id: u64::MAX })
        ));
    }

    #[test]
    fn projector_indexes_the_root_once_and_projection_performs_no_route_scans() {
        const TERMINAL_COUNT: usize = 16;

        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(90), None);
        let middle = FunctionKey::new(definition(91), Some(instance(91)));
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let (middle_body, middle_callable) = insert_function(&mut builder, middle, "crate::middle");
        insert_direct_call(&mut builder, &root_body, root, 0, &middle_callable);
        for ordinal in 0..TERMINAL_COUNT {
            let local_id = u32::try_from(ordinal).unwrap();
            let key = FunctionKey::new(
                definition(100 + u64::from(local_id)),
                Some(instance(100 + u128::from(local_id))),
            );
            let path = format!("crate::terminal_{ordinal}");
            let callable = builder
                .insert_entity(&CallableEntity::new(
                    key,
                    path.clone(),
                    false,
                    false,
                    false,
                    false,
                    vec![path],
                ))
                .unwrap();
            insert_direct_call(&mut builder, &middle_body, middle, local_id, &callable);
        }
        let inputs = resolve_single_panic_artifact(&registry, builder, root, 64);
        assert_eq!(inputs.call_count(), TERMINAL_COUNT);

        reset_trace_route_work();
        let projector = PanicCallTraceProjector::prepare(&inputs).unwrap();
        let prepared_work = trace_route_work();
        assert_eq!(
            prepared_work.body_visits,
            inputs.traversal().body_visits().len()
        );
        assert_eq!(
            prepared_work.followed_calls,
            inputs.traversal().followed_calls().len()
        );

        for call_id in 0..u64::try_from(inputs.call_count()).unwrap() {
            assert_eq!(projector.project(call_id).unwrap().steps().len(), 2);
        }
        assert_eq!(trace_route_work(), prepared_work);
    }

    #[test]
    fn indirect_bodyless_boundary_keeps_the_synthesized_description() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(200), None);
        let target = FunctionKey::new(definition(201), Some(instance(201)));
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let target_callable = builder
            .insert_entity(&CallableEntity::new(
                target,
                "crate::bodyless",
                false,
                false,
                false,
                false,
                vec![String::from("crate::bodyless")],
            ))
            .unwrap();
        insert_configured_call(
            &mut builder,
            &root_body,
            root,
            0,
            CallKind::IndirectCall,
            vec![CallAttributionRole::CallSite],
            None,
            Some(&target_callable),
            false,
            None,
        );
        let inputs = resolve_single_panic_artifact(&registry, builder, root, 8);

        let trace = PanicCallTraceProjector::prepare(&inputs)
            .unwrap()
            .project(0)
            .unwrap();
        assert_eq!(
            trace.terminal().boundary(),
            PanicCallInputKind::Opaque {
                kind: PanicOpaqueBoundaryKind::BodylessDeclaration
            }
        );
        assert_eq!(
            trace.terminal().boundary_description(),
            Some("indirect call to undocumented trait method `crate::bodyless`")
        );
        assert_eq!(
            trace.steps().last().unwrap().target_display_path(),
            "crate::bodyless"
        );
    }
}
