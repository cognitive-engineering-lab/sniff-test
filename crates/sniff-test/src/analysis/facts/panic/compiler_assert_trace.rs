//! Projection of exact compiler-assert traversal selections into semantic steps.

use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[cfg(test)]
use std::cell::Cell;

use super::compiler_assert_inputs::{CompilerAssertRootInputs, ReachableCompilerAssertInput};
use super::model::MirAssertKind;
use super::trace_route::{
    SelectedTraceRoute, TraceBodySelectionError, TraceRouteEndpoint, TraceRouteError,
    TraceRouteSelector,
};
use crate::analysis::facts::program::root_traversal::{
    CallTargetSelection, ProgramCallResolution, ResolvedBodyVisit, ResolvedCallMacroFrame,
    ResolvedCallSourceAnchor, ResolvedEffectMacroFrame, ResolvedEffectSourceAnchor,
    ResolvedEffectVisit, ResolvedFollowedCall,
};
use crate::analysis::facts::program::topology::{
    CallKind, CallMacroExpansionEntity, CallOccurrenceEntity, CallSiteEntity, CallSourceAnchorRole,
    CallableEntity, SafetyEffectGroupEntity,
};
use crate::analysis::facts::program::{
    EffectSiteEntity, EffectSourceAnchorRole, FunctionEntity, FunctionKey, MacroExpansionEntity,
    SourceAnchorEntity, SourceAnchorKey,
};
use crate::analysis::facts::workspace::{
    ScopedEntityId, ScopedEntityRef, ScopedRelationRef, ScopedRowRef,
};

/// One exact body identity retained by every semantic step it owns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompilerAssertTraceBody {
    body: ScopedEntityId<FunctionEntity>,
    data: FunctionEntity,
}

impl CompilerAssertTraceBody {
    #[must_use]
    pub(crate) const fn body(&self) -> &ScopedEntityId<FunctionEntity> {
        &self.body
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &FunctionEntity {
        &self.data
    }
}

/// The two permanent macro entity families represented without erasure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CompilerAssertTraceMacro {
    Call {
        frame: ScopedEntityId<CallMacroExpansionEntity>,
        data: CallMacroExpansionEntity,
    },
    Effect {
        frame: ScopedEntityId<MacroExpansionEntity>,
        data: MacroExpansionEntity,
    },
}

impl CompilerAssertTraceMacro {
    #[must_use]
    pub(crate) fn semantic_function(&self) -> FunctionKey {
        let definition = match self {
            Self::Call { data, .. } => data.macro_definition(),
            Self::Effect { data, .. } => data.macro_definition(),
        };
        FunctionKey::new(definition, None)
    }

    #[must_use]
    pub(crate) fn display_path(&self) -> &str {
        match self {
            Self::Call { data, .. } => data.display_path(),
            Self::Effect { data, .. } => data.display_path(),
        }
    }
}

/// An owned semantic endpoint; no later workspace lookup can change identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CompilerAssertTraceNode {
    Function {
        body: ScopedEntityId<FunctionEntity>,
        data: FunctionEntity,
    },
    Macro(CompilerAssertTraceMacro),
    Callable {
        callable: ScopedEntityId<CallableEntity>,
        data: CallableEntity,
    },
    CompilerAssert {
        source: ScopedRowRef,
        effect: ScopedEntityId<EffectSiteEntity>,
        effect_data: EffectSiteEntity,
        kind: MirAssertKind,
    },
}

/// Report-facing semantic role without exposing the projector's exact IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompilerAssertSemanticNodeRole {
    Function,
    Macro,
    Callable,
    CompilerAssert(MirAssertKind),
}

impl CompilerAssertTraceNode {
    const fn semantic_role(&self) -> CompilerAssertSemanticNodeRole {
        match self {
            Self::Function { .. } => CompilerAssertSemanticNodeRole::Function,
            Self::Macro(_) => CompilerAssertSemanticNodeRole::Macro,
            Self::Callable { .. } => CompilerAssertSemanticNodeRole::Callable,
            Self::CompilerAssert { kind, .. } => {
                CompilerAssertSemanticNodeRole::CompilerAssert(*kind)
            }
        }
    }

    fn display_path(&self) -> Option<&str> {
        match self {
            Self::Function { data, .. } => Some(data.display_path()),
            Self::Macro(data) => Some(data.display_path()),
            Self::Callable { data, .. } => Some(data.display_path()),
            Self::CompilerAssert { .. } => None,
        }
    }

    fn semantic_function(&self) -> Option<FunctionKey> {
        match self {
            Self::Function { data, .. } => Some(*data.key()),
            Self::Macro(data) => Some(data.semantic_function()),
            Self::Callable { data, .. } => Some(*data.key()),
            Self::CompilerAssert { .. } => None,
        }
    }
}

/// Semantic role of the exact source anchor selected for presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompilerAssertTraceSourceRole {
    Call(CallSourceAnchorRole),
    Effect(EffectSourceAnchorRole),
    MacroCallsite,
}

/// Exact source identity and the relation proving its role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompilerAssertTraceSource {
    anchor: ScopedEntityId<SourceAnchorEntity>,
    key: SourceAnchorKey,
    role: CompilerAssertTraceSourceRole,
    relation: ScopedRelationRef,
}

impl CompilerAssertTraceSource {
    #[must_use]
    pub(crate) const fn anchor(&self) -> &ScopedEntityId<SourceAnchorEntity> {
        &self.anchor
    }

    #[must_use]
    pub(crate) const fn key(&self) -> &SourceAnchorKey {
        &self.key
    }

    #[must_use]
    pub(crate) const fn role(&self) -> CompilerAssertTraceSourceRole {
        self.role
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }
}

/// Complete owned semantic data for one followed call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompilerAssertCallTrace {
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

impl CompilerAssertCallTrace {
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

/// Why one semantic edge appears in a compiler-assert explanation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CompilerAssertSemanticTraceStepKind {
    CallMacro {
        occurrence: ScopedEntityId<CallOccurrenceEntity>,
        occurrence_data: CallOccurrenceEntity,
        frame: ScopedEntityId<CallMacroExpansionEntity>,
    },
    Call(Box<CompilerAssertCallTrace>),
    EffectMacro {
        effect: ScopedEntityId<EffectSiteEntity>,
        effect_data: EffectSiteEntity,
        frame: ScopedEntityId<MacroExpansionEntity>,
    },
    Assert {
        source: ScopedRowRef,
        effect: ScopedEntityId<EffectSiteEntity>,
        effect_data: EffectSiteEntity,
        kind: MirAssertKind,
    },
}

/// Report-facing semantic edge without exposing projector-owned provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompilerAssertSemanticEdge {
    MacroExpansion,
    Call(CallKind),
    Assert(MirAssertKind),
}

/// One dense semantic trace step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompilerAssertSemanticTraceStep {
    position: u32,
    owner: CompilerAssertTraceBody,
    caller: CompilerAssertTraceNode,
    source: Option<CompilerAssertTraceSource>,
    target: CompilerAssertTraceNode,
    kind: CompilerAssertSemanticTraceStepKind,
}

impl CompilerAssertSemanticTraceStep {
    #[must_use]
    pub(crate) const fn position(&self) -> u32 {
        self.position
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> &CompilerAssertTraceBody {
        &self.owner
    }

    #[must_use]
    pub(crate) const fn caller(&self) -> &CompilerAssertTraceNode {
        &self.caller
    }

    #[must_use]
    pub(crate) const fn source(&self) -> Option<&CompilerAssertTraceSource> {
        self.source.as_ref()
    }

    #[must_use]
    pub(crate) fn source_key(&self) -> Option<&SourceAnchorKey> {
        self.source.as_ref().map(CompilerAssertTraceSource::key)
    }

    #[must_use]
    pub(crate) const fn caller_role(&self) -> CompilerAssertSemanticNodeRole {
        self.caller.semantic_role()
    }

    #[must_use]
    pub(crate) fn caller_display_path(&self) -> Option<&str> {
        self.caller.display_path()
    }

    #[must_use]
    pub(crate) fn caller_function(&self) -> Option<FunctionKey> {
        self.caller.semantic_function()
    }

    #[must_use]
    pub(crate) const fn target(&self) -> &CompilerAssertTraceNode {
        &self.target
    }

    #[must_use]
    pub(crate) const fn target_role(&self) -> CompilerAssertSemanticNodeRole {
        self.target.semantic_role()
    }

    #[must_use]
    pub(crate) fn target_display_path(&self) -> Option<&str> {
        self.target.display_path()
    }

    #[must_use]
    pub(crate) fn target_function(&self) -> Option<FunctionKey> {
        self.target.semantic_function()
    }

    #[must_use]
    pub(crate) fn call_local_id(&self) -> Option<u32> {
        match &self.kind {
            CompilerAssertSemanticTraceStepKind::CallMacro {
                occurrence_data, ..
            } => Some(occurrence_data.key().local_id()),
            CompilerAssertSemanticTraceStepKind::Call(call) => {
                Some(call.occurrence_data().key().local_id())
            }
            CompilerAssertSemanticTraceStepKind::EffectMacro { .. }
            | CompilerAssertSemanticTraceStepKind::Assert { .. } => None,
        }
    }

    #[must_use]
    pub(crate) fn effect(&self) -> Option<&ScopedEntityId<EffectSiteEntity>> {
        match &self.kind {
            CompilerAssertSemanticTraceStepKind::EffectMacro { effect, .. }
            | CompilerAssertSemanticTraceStepKind::Assert { effect, .. } => Some(effect),
            CompilerAssertSemanticTraceStepKind::CallMacro { .. }
            | CompilerAssertSemanticTraceStepKind::Call(_) => None,
        }
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> &CompilerAssertSemanticTraceStepKind {
        &self.kind
    }

    #[must_use]
    pub(crate) fn edge(&self) -> CompilerAssertSemanticEdge {
        match &self.kind {
            CompilerAssertSemanticTraceStepKind::CallMacro { .. }
            | CompilerAssertSemanticTraceStepKind::EffectMacro { .. } => {
                CompilerAssertSemanticEdge::MacroExpansion
            }
            CompilerAssertSemanticTraceStepKind::Call(call) => {
                CompilerAssertSemanticEdge::Call(call.effective_kind())
            }
            CompilerAssertSemanticTraceStepKind::Assert { kind, .. } => {
                CompilerAssertSemanticEdge::Assert(*kind)
            }
        }
    }
}

/// Exact semantic projection selected for one dense compiler-assert witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompilerAssertSemanticTrace {
    witness_order: u64,
    assertion: ScopedRowRef,
    endpoint: ScopedEntityId<EffectSiteEntity>,
    endpoint_data: EffectSiteEntity,
    steps: Vec<CompilerAssertSemanticTraceStep>,
}

impl CompilerAssertSemanticTrace {
    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) const fn assertion(&self) -> &ScopedRowRef {
        &self.assertion
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityId<EffectSiteEntity> {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn endpoint_data(&self) -> &EffectSiteEntity {
        &self.endpoint_data
    }

    #[must_use]
    pub(crate) fn steps(&self) -> &[CompilerAssertSemanticTraceStep] {
        &self.steps
    }
}

/// Integrity failure while projecting already-resolved traversal selections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CompilerAssertTraceError {
    NonDenseWitnessOrder { expected: u64, found: u64 },
    UnknownWitnessOrder { order: u64 },
    MissingEffectVisit { visit_order: u64 },
    DuplicateEffectVisit { visit_order: u64 },
    AssertionEffectMismatch,
    AssertionProvenanceMismatch,
    AssertionTraceMismatch,
    InvalidRootTrace,
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

impl Display for CompilerAssertTraceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid compiler-assert semantic trace: {self:?}"
        )
    }
}

impl Error for CompilerAssertTraceError {}

impl From<TraceRouteError> for CompilerAssertTraceError {
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProjectionWork {
    assertions: usize,
    effect_visits: usize,
    body_visits: usize,
    followed_calls: usize,
    trie_edges: usize,
    body_candidates: usize,
    marker_claims: usize,
}

#[cfg(test)]
thread_local! {
    static PROJECTION_WORK: Cell<ProjectionWork> = const {
        Cell::new(ProjectionWork {
            assertions: 0,
            effect_visits: 0,
            body_visits: 0,
            followed_calls: 0,
            trie_edges: 0,
            body_candidates: 0,
            marker_claims: 0,
        })
    };
}

#[cfg(test)]
fn reset_projection_work() {
    PROJECTION_WORK.set(ProjectionWork::default());
    super::trace_route::reset_trace_route_work();
}

#[cfg(test)]
fn projection_work() -> ProjectionWork {
    let mut work = PROJECTION_WORK.get();
    let route_work = super::trace_route::trace_route_work();
    work.body_visits = route_work.body_visits;
    work.followed_calls = route_work.followed_calls;
    work.trie_edges = route_work.trie_edges;
    work.body_candidates = route_work.body_candidates;
    work.marker_claims = route_work.marker_claims;
    work
}

#[cfg(test)]
fn record_assertion_indexed() {
    PROJECTION_WORK.with(|counter| {
        let mut work = counter.get();
        work.assertions += 1;
        counter.set(work);
    });
}

#[cfg(not(test))]
fn record_assertion_indexed() {}

#[cfg(test)]
fn record_effect_visit_indexed() {
    PROJECTION_WORK.with(|counter| {
        let mut work = counter.get();
        work.effect_visits += 1;
        counter.set(work);
    });
}

#[cfg(not(test))]
fn record_effect_visit_indexed() {}

/// A validated, root-local compiler-assert projection index.
///
/// Preparation is atomic: every witness and its exact traversal route is
/// validated before the projector can be used. Projection then touches only
/// the selected route, never the root input collections.
pub(crate) struct CompilerAssertTraceProjector<'a> {
    projections: Vec<PreparedCompilerAssertProjection<'a>>,
    routes: Vec<SelectedTraceRoute<'a>>,
}

impl<'a> CompilerAssertTraceProjector<'a> {
    pub(crate) fn prepare(
        inputs: &'a CompilerAssertRootInputs,
    ) -> Result<Self, CompilerAssertTraceError> {
        for (expected, assertion) in inputs.assertions().iter().enumerate() {
            record_assertion_indexed();
            let expected =
                u64::try_from(expected).map_err(|_| CompilerAssertTraceError::PositionOverflow)?;
            if assertion.order() != expected {
                return Err(CompilerAssertTraceError::NonDenseWitnessOrder {
                    expected,
                    found: assertion.order(),
                });
            }
        }

        let effects = CompilerAssertEffectIndex::new(inputs)?;
        let mut route_selector = TraceRouteSelector::prepare(inputs.traversal());
        let mut route_by_owner = HashMap::<*const ResolvedBodyVisit, usize>::new();
        let mut routes = Vec::<SelectedTraceRoute<'a>>::new();
        let mut projections = Vec::with_capacity(inputs.assertions().len());
        for assertion in inputs.assertions() {
            let effect = effects.exact_effect_visit(inputs, assertion)?;
            let effect_owner = exact_effect_owner(&route_selector, assertion, effect)?;
            let owner_identity = std::ptr::from_ref(effect_owner);
            let endpoint =
                TraceRouteEndpoint::new(effect.order(), effect.trace(), effect.inherited_markers());
            let route = if let Some(route) = route_by_owner.get(&owner_identity).copied() {
                routes[route].validate_reuse(endpoint)?;
                route
            } else {
                let selected = route_selector.select_route(endpoint)?;
                let route = routes.len();
                routes.push(selected);
                route_by_owner.insert(owner_identity, route);
                route
            };
            projections.push(PreparedCompilerAssertProjection {
                assertion,
                effect,
                effect_owner,
                route,
            });
        }
        Ok(Self {
            projections,
            routes,
        })
    }

    pub(crate) fn assertion(
        &self,
        witness_order: u64,
    ) -> Result<&'a ReachableCompilerAssertInput, CompilerAssertTraceError> {
        Ok(self.prepared(witness_order)?.assertion)
    }

    pub(crate) fn project(
        &self,
        witness_order: u64,
    ) -> Result<CompilerAssertSemanticTrace, CompilerAssertTraceError> {
        let prepared = self.prepared(witness_order)?;
        let mut steps = Vec::new();
        for selected in self.routes[prepared.route].calls() {
            append_call_steps(&mut steps, selected.caller(), selected.call())?;
        }
        append_effect_steps(
            &mut steps,
            prepared.effect_owner,
            prepared.assertion,
            prepared.effect,
        )?;
        Ok(CompilerAssertSemanticTrace {
            witness_order,
            assertion: prepared.assertion.source().clone(),
            endpoint: prepared.assertion.owner().clone(),
            endpoint_data: prepared.effect.data().clone(),
            steps,
        })
    }

    fn prepared(
        &self,
        witness_order: u64,
    ) -> Result<&PreparedCompilerAssertProjection<'a>, CompilerAssertTraceError> {
        let index = usize::try_from(witness_order).map_err(|_| {
            CompilerAssertTraceError::UnknownWitnessOrder {
                order: witness_order,
            }
        })?;
        self.projections
            .get(index)
            .ok_or(CompilerAssertTraceError::UnknownWitnessOrder {
                order: witness_order,
            })
    }
}

/// Compatibility wrapper for callers that project only one assertion.
pub(crate) fn project_compiler_assert_semantic_trace(
    inputs: &CompilerAssertRootInputs,
    witness_order: u64,
) -> Result<CompilerAssertSemanticTrace, CompilerAssertTraceError> {
    CompilerAssertTraceProjector::prepare(inputs)?.project(witness_order)
}

struct PreparedCompilerAssertProjection<'a> {
    assertion: &'a ReachableCompilerAssertInput,
    effect: &'a ResolvedEffectVisit,
    effect_owner: &'a ResolvedBodyVisit,
    route: usize,
}

struct CompilerAssertEffectIndex<'a> {
    effects_by_order: HashMap<u64, &'a ResolvedEffectVisit>,
}

impl<'a> CompilerAssertEffectIndex<'a> {
    fn new(inputs: &'a CompilerAssertRootInputs) -> Result<Self, CompilerAssertTraceError> {
        let mut effects_by_order = HashMap::new();
        for effect in inputs.traversal().effect_visits() {
            record_effect_visit_indexed();
            if effects_by_order.insert(effect.order(), effect).is_some() {
                return Err(CompilerAssertTraceError::DuplicateEffectVisit {
                    visit_order: effect.order(),
                });
            }
        }
        Ok(Self { effects_by_order })
    }

    fn exact_effect_visit(
        &self,
        inputs: &CompilerAssertRootInputs,
        assertion: &ReachableCompilerAssertInput,
    ) -> Result<&'a ResolvedEffectVisit, CompilerAssertTraceError> {
        let effect = self
            .effects_by_order
            .get(&assertion.visit_order())
            .copied()
            .ok_or(CompilerAssertTraceError::MissingEffectVisit {
                visit_order: assertion.visit_order(),
            })?;
        if effect.effect() != assertion.owner() {
            return Err(CompilerAssertTraceError::AssertionEffectMismatch);
        }
        if effect.source_anchors() != assertion.source_anchors()
            || effect.macro_frames() != assertion.macro_frames()
        {
            return Err(CompilerAssertTraceError::AssertionEffectMismatch);
        }
        if effect.trace() != assertion.trace() {
            return Err(CompilerAssertTraceError::AssertionTraceMismatch);
        }
        if assertion.trace().root() != &inputs.root().entity
            || assertion.trace().target() != &assertion.owner().erase()
        {
            return Err(CompilerAssertTraceError::InvalidRootTrace);
        }
        Ok(effect)
    }
}

fn exact_effect_owner<'a>(
    route_selector: &TraceRouteSelector<'a>,
    assertion: &ReachableCompilerAssertInput,
    effect: &ResolvedEffectVisit,
) -> Result<&'a ResolvedBodyVisit, CompilerAssertTraceError> {
    let owner = route_selector
        .select_owner_body(
            assertion.provenance().erase(),
            effect.inherited_markers(),
            assertion.trace(),
        )
        .map_err(|error| match error {
            TraceBodySelectionError::Missing | TraceBodySelectionError::Ambiguous => {
                CompilerAssertTraceError::AssertionProvenanceMismatch
            }
        })?;
    if effect.site().function() != owner.data().key() {
        return Err(CompilerAssertTraceError::AssertionProvenanceMismatch);
    }
    Ok(owner)
}

#[cfg(test)]
fn validate_call_route(
    route: &SelectedTraceRoute<'_>,
    effect: &ResolvedEffectVisit,
) -> Result<(), CompilerAssertTraceError> {
    route
        .validate_for_test(TraceRouteEndpoint::new(
            effect.order(),
            effect.trace(),
            effect.inherited_markers(),
        ))
        .map_err(CompilerAssertTraceError::from)
}
fn append_call_steps(
    steps: &mut Vec<CompilerAssertSemanticTraceStep>,
    owner: &ResolvedBodyVisit,
    call: &ResolvedFollowedCall,
) -> Result<(), CompilerAssertTraceError> {
    let trace_owner = trace_body(owner);
    let mut caller = function_node(owner);
    for frame in call.macro_frames() {
        let target = call_macro_node(frame);
        push_step(
            steps,
            trace_owner.clone(),
            caller,
            frame.callsite().map(call_macro_source),
            target.clone(),
            CompilerAssertSemanticTraceStepKind::CallMacro {
                occurrence: call.occurrence().clone(),
                occurrence_data: call.occurrence_data().clone(),
                frame: frame.frame().clone(),
            },
        )?;
        caller = target;
    }
    push_step(
        steps,
        trace_owner,
        caller,
        selected_call_source(call.source_anchors()),
        CompilerAssertTraceNode::Callable {
            callable: call.target().callable().clone(),
            data: call.target_data().clone(),
        },
        CompilerAssertSemanticTraceStepKind::Call(Box::new(CompilerAssertCallTrace {
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
    )
}

fn append_effect_steps(
    steps: &mut Vec<CompilerAssertSemanticTraceStep>,
    owner: &ResolvedBodyVisit,
    assertion: &ReachableCompilerAssertInput,
    effect: &ResolvedEffectVisit,
) -> Result<(), CompilerAssertTraceError> {
    let trace_owner = trace_body(owner);
    let mut caller = function_node(owner);
    for frame in assertion.macro_frames() {
        let target = effect_macro_node(frame);
        push_step(
            steps,
            trace_owner.clone(),
            caller,
            frame.callsite().map(effect_macro_source),
            target.clone(),
            CompilerAssertSemanticTraceStepKind::EffectMacro {
                effect: assertion.owner().clone(),
                effect_data: effect.data().clone(),
                frame: frame.frame().clone(),
            },
        )?;
        caller = target;
    }
    push_step(
        steps,
        trace_owner,
        caller,
        selected_effect_source(effect.source_anchors()),
        CompilerAssertTraceNode::CompilerAssert {
            source: assertion.source().clone(),
            effect: assertion.owner().clone(),
            effect_data: effect.data().clone(),
            kind: assertion.kind(),
        },
        CompilerAssertSemanticTraceStepKind::Assert {
            source: assertion.source().clone(),
            effect: assertion.owner().clone(),
            effect_data: effect.data().clone(),
            kind: assertion.kind(),
        },
    )
}

fn push_step(
    steps: &mut Vec<CompilerAssertSemanticTraceStep>,
    owner: CompilerAssertTraceBody,
    caller: CompilerAssertTraceNode,
    source: Option<CompilerAssertTraceSource>,
    target: CompilerAssertTraceNode,
    kind: CompilerAssertSemanticTraceStepKind,
) -> Result<(), CompilerAssertTraceError> {
    let position =
        u32::try_from(steps.len()).map_err(|_| CompilerAssertTraceError::PositionOverflow)?;
    steps.push(CompilerAssertSemanticTraceStep {
        position,
        owner,
        caller,
        source,
        target,
        kind,
    });
    Ok(())
}

fn trace_body(visit: &ResolvedBodyVisit) -> CompilerAssertTraceBody {
    CompilerAssertTraceBody {
        body: visit.body().clone(),
        data: visit.data().clone(),
    }
}

fn function_node(visit: &ResolvedBodyVisit) -> CompilerAssertTraceNode {
    CompilerAssertTraceNode::Function {
        body: visit.body().clone(),
        data: visit.data().clone(),
    }
}

fn call_macro_node(frame: &ResolvedCallMacroFrame) -> CompilerAssertTraceNode {
    CompilerAssertTraceNode::Macro(CompilerAssertTraceMacro::Call {
        frame: frame.frame().clone(),
        data: frame.data().clone(),
    })
}

fn effect_macro_node(frame: &ResolvedEffectMacroFrame) -> CompilerAssertTraceNode {
    CompilerAssertTraceNode::Macro(CompilerAssertTraceMacro::Effect {
        frame: frame.frame().clone(),
        data: frame.data().clone(),
    })
}

fn call_macro_source(
    source: &crate::analysis::facts::program::root_traversal::ResolvedCallMacroCallsite,
) -> CompilerAssertTraceSource {
    CompilerAssertTraceSource {
        anchor: source.anchor().clone(),
        key: source.key().clone(),
        role: CompilerAssertTraceSourceRole::MacroCallsite,
        relation: source.relation().clone(),
    }
}

fn effect_macro_source(
    source: &crate::analysis::facts::program::root_traversal::ResolvedEffectMacroCallsite,
) -> CompilerAssertTraceSource {
    CompilerAssertTraceSource {
        anchor: source.anchor().clone(),
        key: source.key().clone(),
        role: CompilerAssertTraceSourceRole::MacroCallsite,
        relation: source.relation().clone(),
    }
}

fn selected_call_source(anchors: &[ResolvedCallSourceAnchor]) -> Option<CompilerAssertTraceSource> {
    [
        CallSourceAnchorRole::Expanded,
        CallSourceAnchorRole::Presentation,
    ]
    .into_iter()
    .find_map(|role| {
        anchors
            .iter()
            .find(|anchor| anchor.role() == role)
            .map(|anchor| CompilerAssertTraceSource {
                anchor: anchor.anchor().clone(),
                key: anchor.key().clone(),
                role: CompilerAssertTraceSourceRole::Call(role),
                relation: anchor.relation().clone(),
            })
    })
}

fn selected_effect_source(
    anchors: &[ResolvedEffectSourceAnchor],
) -> Option<CompilerAssertTraceSource> {
    [
        EffectSourceAnchorRole::Expanded,
        EffectSourceAnchorRole::Presentation,
    ]
    .into_iter()
    .find_map(|role| {
        anchors
            .iter()
            .find(|anchor| anchor.role() == role)
            .map(|anchor| CompilerAssertTraceSource {
                anchor: anchor.anchor().clone(),
                key: anchor.key().clone(),
                role: CompilerAssertTraceSourceRole::Effect(role),
                relation: anchor.relation().clone(),
            })
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::{
        CompilerAssertSemanticEdge, CompilerAssertSemanticNodeRole, CompilerAssertSemanticTrace,
        CompilerAssertSemanticTraceStepKind, CompilerAssertTraceError, CompilerAssertTraceNode,
        CompilerAssertTraceProjector, CompilerAssertTraceSourceRole,
        project_compiler_assert_semantic_trace, projection_work, reset_projection_work,
    };
    use crate::analysis::cache::RustcArtifactId;
    use crate::analysis::facts::builder::{ArtifactDbBuilder, FactMeta};
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::composition::{CompositionRelationBuilder, WorkspaceRelationGraph};
    use crate::analysis::facts::evaluation::DomainId;
    use crate::analysis::facts::evidence::EvidenceSemanticEdgeOrder;
    use crate::analysis::facts::human::EvidenceClaimSelector;
    use crate::analysis::facts::human::markers::{
        CallOccurrenceHasMarkerClaimCandidate, MarkerClaimEntity, MarkerClaimKey,
        MarkerOccurrenceEntity, MarkerOccurrenceHasClaim, MarkerOccurrenceHasSourceAnchor,
        MarkerOccurrenceKey,
    };
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::panic::compiler_assert_ingress::semantic_order_for_trace;
    use crate::analysis::facts::panic::compiler_assert_inputs::{
        CompilerAssertRootInputs, CompilerAssertRootRequest, PreparedCompilerAssertRootBatch,
    };
    use crate::analysis::facts::panic::model::{InBoundsRequirement, MirAssertFact, MirAssertKind};
    use crate::analysis::facts::program::root_traversal::MarkerProbe;
    use crate::analysis::facts::program::root_traversal::{
        ProgramCallResolution, ReconciledCallTargetAuthority,
    };
    use crate::analysis::facts::program::topology::{
        CallAttributionRole, CallKind, CallMacroExpansionEntersCallMacroExpansion,
        CallMacroExpansionEntity, CallMacroExpansionHasCallsite, CallMacroExpansionKey,
        CallMacroExpansionProducesCallOccurrence, CallOccurrenceEntity,
        CallOccurrenceHasCallableKey, CallOccurrenceHasSourceAnchor,
        CallOccurrenceInSafetyEffectGroup, CallOccurrenceKey, CallOccurrenceTargetsCallable,
        CallSiteEntity, CallSiteHasOccurrence, CallSiteKey, CallSourceAnchorRole, CallTargetRole,
        CallableEntity, CallableKey, CallableKeyEntity, FunctionDefinesCallable,
        FunctionEntersCallMacroExpansion, FunctionOwnsCallSite, FunctionOwnsSafetyEffectGroup,
        SafetyEffectGroupEntity, SafetyEffectGroupKey,
    };
    use crate::analysis::facts::program::workspace_index::{
        CallableInvocationTargetsCallable, CallableResolutionKind, ConsumerOccurrenceReconcilesWith,
    };
    use crate::analysis::facts::program::{
        EffectSiteEntity, EffectSiteHasSourceAnchor, EffectSiteKey, EffectSourceAnchorRole,
        FunctionBodyProvenance, FunctionEntersMacroExpansion, FunctionEntity, FunctionKey,
        FunctionOwnsEffectSite, MacroExpansionEntersMacroExpansion, MacroExpansionEntity,
        MacroExpansionHasCallsite, MacroExpansionKey, MacroExpansionProducesEffectSite,
        SourceAnchorEntity, SourceAnchorInFile, SourceAnchorKey, SourceFileEntity,
    };
    use crate::analysis::facts::schema::{EntityHandle, PassId, RowSchema};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::analysis::facts::workspace::{ArtifactScopeId, WorkspaceFactView};
    use crate::analysis::workspace_closure::{
        ManagedArtifactGeneration, ManagedArtifactManifest, VerifiedWorkspaceClosure,
    };
    use crate::config::PanicConfig;
    use crate::contracts::ContractDocOverrides;
    use crate::namespace::{
        StableDefPathHash, StableExpansionHash, StableInstanceHash, StableTypeHash,
    };
    use reachability::MirBodyLocation;

    pub(in crate::analysis::facts::panic) fn definition(local: u64) -> StableDefPathHash {
        serde_json::from_str(&format!("\"0000000000000001{local:016x}\"")).unwrap()
    }

    fn definition_in(stable_crate_id: u64, local: u64) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{stable_crate_id:016x}{local:016x}\"")).unwrap()
    }

    pub(in crate::analysis::facts::panic) fn instance(local: u128) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{local:032x}\"")).unwrap()
    }

    fn expansion(local: u128) -> StableExpansionHash {
        serde_json::from_str(&format!("\"{local:032x}\"")).unwrap()
    }

    pub(in crate::analysis::facts::panic) fn type_hash(local: u128) -> StableTypeHash {
        serde_json::from_str(&format!("\"{local:032x}\"")).unwrap()
    }

    fn resolve_inputs(
        registry: &AnalysisRegistry<()>,
        workspace: &WorkspaceFactView<'_>,
        closure: &VerifiedWorkspaceClosure,
        root: FunctionKey,
        node_budget: usize,
    ) -> CompilerAssertRootInputs {
        let batch = PreparedCompilerAssertRootBatch::prepare(
            workspace,
            closure,
            &PanicConfig::default(),
            &ContractDocOverrides::default(),
            [CompilerAssertRootRequest::new(
                root,
                CallAttributionRole::CallSite,
                MarkerProbe::SourceCallsite,
                node_budget,
            )],
        )
        .unwrap();
        let prepared = batch.into_roots().pop().unwrap();
        let mut composition_builder = CompositionRelationBuilder::new(
            prepared.root(),
            workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut composition_builder).unwrap();
        let composition = composition_builder.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), workspace, &composition).unwrap();
        emitted
            .resolve(workspace, &graph, registry.composition_relations())
            .unwrap()
    }

    pub(in crate::analysis::facts::panic) fn declared_builder(
        registry: &AnalysisRegistry<()>,
    ) -> ArtifactDbBuilder {
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        builder
    }

    pub(in crate::analysis::facts::panic) fn insert_callable(
        builder: &mut ArtifactDbBuilder,
        key: FunctionKey,
        path: &str,
    ) -> EntityHandle<CallableEntity> {
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
            .unwrap()
    }

    pub(in crate::analysis::facts::panic) fn insert_function(
        builder: &mut ArtifactDbBuilder,
        key: FunctionKey,
        path: &str,
    ) -> (EntityHandle<FunctionEntity>, EntityHandle<CallableEntity>) {
        insert_function_with_provenance(
            builder,
            key,
            path,
            FunctionBodyProvenance::DefiningArtifact,
        )
    }

    fn insert_function_with_provenance(
        builder: &mut ArtifactDbBuilder,
        key: FunctionKey,
        path: &str,
        provenance: FunctionBodyProvenance,
    ) -> (EntityHandle<FunctionEntity>, EntityHandle<CallableEntity>) {
        let body = builder
            .insert_entity(&FunctionEntity::new(key, path, provenance))
            .unwrap();
        let callable = insert_callable(builder, key, path);
        builder
            .relate(&body, &callable, &FunctionDefinesCallable::new())
            .unwrap();
        (body, callable)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the fixture exposes every persisted call facet under test"
    )]
    pub(in crate::analysis::facts::panic) fn insert_configured_call(
        builder: &mut ArtifactDbBuilder,
        owner_body: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        local_id: u32,
        kind: CallKind,
        attribution: Vec<CallAttributionRole>,
        callable_key: Option<&EntityHandle<CallableKeyEntity>>,
        target: Option<&EntityHandle<CallableEntity>>,
        requires_unsafe: bool,
        opaque_target: Option<String>,
    ) -> EntityHandle<CallOccurrenceEntity> {
        let call_site = builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(owner, local_id)))
            .unwrap();
        let occurrence = builder
            .insert_entity(&CallOccurrenceEntity::new(
                CallOccurrenceKey::new(owner, local_id),
                kind,
                attribution,
                requires_unsafe,
                false,
                opaque_target,
            ))
            .unwrap();
        let safety_group = builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                owner, local_id,
            )))
            .unwrap();
        builder
            .relate(owner_body, &call_site, &FunctionOwnsCallSite::new())
            .unwrap();
        builder
            .relate(&call_site, &occurrence, &CallSiteHasOccurrence::new())
            .unwrap();
        builder
            .relate(
                owner_body,
                &safety_group,
                &FunctionOwnsSafetyEffectGroup::new(),
            )
            .unwrap();
        builder
            .relate(
                &occurrence,
                &safety_group,
                &CallOccurrenceInSafetyEffectGroup::new(),
            )
            .unwrap();
        if let Some(callable_key) = callable_key {
            builder
                .relate(
                    &occurrence,
                    callable_key,
                    &CallOccurrenceHasCallableKey::new(),
                )
                .unwrap();
        }
        if let Some(target) = target {
            builder
                .relate(
                    &occurrence,
                    target,
                    &CallOccurrenceTargetsCallable::new(CallTargetRole::Runtime),
                )
                .unwrap();
        }
        occurrence
    }

    pub(in crate::analysis::facts::panic) fn insert_direct_call(
        builder: &mut ArtifactDbBuilder,
        owner_body: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        local_id: u32,
        target: &EntityHandle<CallableEntity>,
    ) -> EntityHandle<CallOccurrenceEntity> {
        let call_site = builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(owner, local_id)))
            .unwrap();
        let occurrence = builder
            .insert_entity(&CallOccurrenceEntity::new(
                CallOccurrenceKey::new(owner, local_id),
                CallKind::DirectCall,
                vec![CallAttributionRole::CallSite],
                false,
                false,
                None,
            ))
            .unwrap();
        let safety_group = builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                owner, local_id,
            )))
            .unwrap();
        builder
            .relate(owner_body, &call_site, &FunctionOwnsCallSite::new())
            .unwrap();
        builder
            .relate(&call_site, &occurrence, &CallSiteHasOccurrence::new())
            .unwrap();
        builder
            .relate(
                owner_body,
                &safety_group,
                &FunctionOwnsSafetyEffectGroup::new(),
            )
            .unwrap();
        builder
            .relate(
                &occurrence,
                &safety_group,
                &CallOccurrenceInSafetyEffectGroup::new(),
            )
            .unwrap();
        builder
            .relate(
                &occurrence,
                target,
                &CallOccurrenceTargetsCallable::new(CallTargetRole::Runtime),
            )
            .unwrap();
        occurrence
    }

    fn insert_assertion(
        builder: &mut ArtifactDbBuilder,
        body: &EntityHandle<FunctionEntity>,
        site: EffectSiteKey,
    ) -> EntityHandle<EffectSiteEntity> {
        let effect = builder.insert_entity(&EffectSiteEntity::new(site)).unwrap();
        builder
            .relate(body, &effect, &FunctionOwnsEffectSite::new())
            .unwrap();
        let requirement = builder
            .insert_requirement(&InBoundsRequirement::new())
            .unwrap();
        builder
            .insert_fact(
                &MirAssertFact::new(MirAssertKind::BoundsCheck),
                FactMeta::new(PassId::new("test.compiler-assert-trace").unwrap())
                    .with_owner(&effect)
                    .unwrap()
                    .with_provenance_root(body)
                    .unwrap()
                    .with_requirement(&requirement)
                    .unwrap(),
            )
            .unwrap();
        effect
    }

    pub(in crate::analysis::facts::panic) fn attach_panic_marker_to_call(
        builder: &mut ArtifactDbBuilder,
        occurrence: &EntityHandle<CallOccurrenceEntity>,
        ordinal: u32,
    ) -> EntityHandle<MarkerClaimEntity> {
        let file_id = format!("marker-{ordinal}");
        let file = builder
            .insert_entity(&SourceFileEntity::new(
                file_id.clone(),
                format!("src/{file_id}.rs"),
                format!("marker-hash-{ordinal}"),
                10,
            ))
            .unwrap();
        let (anchor_key, anchor) = insert_anchor(builder, &file, &file_id, 0, 5);
        let occurrence_key = MarkerOccurrenceKey::new(anchor_key, None);
        let marker = builder
            .insert_entity(&MarkerOccurrenceEntity::new(occurrence_key.clone(), vec![]))
            .unwrap();
        builder
            .relate(&marker, &anchor, &MarkerOccurrenceHasSourceAnchor::new())
            .unwrap();
        let claim = builder
            .insert_entity(&MarkerClaimEntity::new(
                MarkerClaimKey::new(
                    occurrence_key,
                    DomainId::new("sniff-test.panic").unwrap(),
                    0,
                ),
                EvidenceClaimSelector::Unnamed,
                format!("marker {ordinal}"),
            ))
            .unwrap();
        builder
            .relate(&marker, &claim, &MarkerOccurrenceHasClaim::new())
            .unwrap();
        builder
            .relate(
                occurrence,
                &claim,
                &CallOccurrenceHasMarkerClaimCandidate::new(true, false),
            )
            .unwrap();
        claim
    }

    fn insert_anchor(
        builder: &mut ArtifactDbBuilder,
        file: &EntityHandle<SourceFileEntity>,
        file_id: &str,
        byte_start: u64,
        byte_end: u64,
    ) -> (SourceAnchorKey, EntityHandle<SourceAnchorEntity>) {
        let key = SourceAnchorKey::new(file_id, byte_start, byte_end);
        let anchor = builder
            .insert_entity(&SourceAnchorEntity::new(key.clone()))
            .unwrap();
        builder
            .relate(&anchor, file, &SourceAnchorInFile::new())
            .unwrap();
        (key, anchor)
    }

    fn attach_shared_call_source(
        builder: &mut ArtifactDbBuilder,
        occurrence: &EntityHandle<CallOccurrenceEntity>,
        file_id: &str,
    ) -> SourceAnchorKey {
        let file = builder
            .insert_entity(&SourceFileEntity::new(
                file_id,
                "src/shared.rs",
                "shared-source-hash",
                100,
            ))
            .unwrap();
        let (key, anchor) = insert_anchor(builder, &file, file_id, 10, 20);
        builder
            .relate(
                occurrence,
                &anchor,
                &CallOccurrenceHasSourceAnchor::new(CallSourceAnchorRole::Expanded),
            )
            .unwrap();
        key
    }

    fn attach_call_macros_and_sources(
        builder: &mut ArtifactDbBuilder,
        owner_body: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        occurrence: &EntityHandle<CallOccurrenceEntity>,
    ) -> (SourceAnchorKey, SourceAnchorKey, SourceAnchorKey) {
        attach_named_call_macros_and_sources(
            builder,
            owner_body,
            owner,
            occurrence,
            "call_outer!",
            "call_inner!",
        )
    }

    pub(in crate::analysis::facts::panic) fn attach_named_call_macros_and_sources(
        builder: &mut ArtifactDbBuilder,
        owner_body: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        occurrence: &EntityHandle<CallOccurrenceEntity>,
        outer_path: &str,
        inner_path: &str,
    ) -> (SourceAnchorKey, SourceAnchorKey, SourceAnchorKey) {
        let file = builder
            .insert_entity(&SourceFileEntity::new(
                "nested-file",
                "src/nested.rs",
                "nested-hash",
                100,
            ))
            .unwrap();
        let (presentation_key, presentation) = insert_anchor(builder, &file, "nested-file", 10, 20);
        let (expanded_key, expanded) = insert_anchor(builder, &file, "nested-file", 30, 40);
        let (macro_key, macro_anchor) = insert_anchor(builder, &file, "nested-file", 50, 60);
        builder
            .relate(
                occurrence,
                &presentation,
                &CallOccurrenceHasSourceAnchor::new(CallSourceAnchorRole::Presentation),
            )
            .unwrap();
        builder
            .relate(
                occurrence,
                &expanded,
                &CallOccurrenceHasSourceAnchor::new(CallSourceAnchorRole::Expanded),
            )
            .unwrap();
        let occurrence_key = CallOccurrenceKey::new(owner, 1);
        let outer = builder
            .insert_entity(&CallMacroExpansionEntity::new(
                CallMacroExpansionKey::new(occurrence_key, 0),
                expansion(10),
                definition(13),
                outer_path,
            ))
            .unwrap();
        let inner = builder
            .insert_entity(&CallMacroExpansionEntity::new(
                CallMacroExpansionKey::new(occurrence_key, 1),
                expansion(11),
                definition(14),
                inner_path,
            ))
            .unwrap();
        builder
            .relate(owner_body, &outer, &FunctionEntersCallMacroExpansion::new())
            .unwrap();
        builder
            .relate(
                &outer,
                &inner,
                &CallMacroExpansionEntersCallMacroExpansion::new(),
            )
            .unwrap();
        builder
            .relate(
                &inner,
                occurrence,
                &CallMacroExpansionProducesCallOccurrence::new(),
            )
            .unwrap();
        builder
            .relate(&outer, &macro_anchor, &CallMacroExpansionHasCallsite::new())
            .unwrap();
        (presentation_key, expanded_key, macro_key)
    }

    fn attach_effect_macros_and_sources(
        builder: &mut ArtifactDbBuilder,
        owner_body: &EntityHandle<FunctionEntity>,
        effect: &EntityHandle<EffectSiteEntity>,
        site: EffectSiteKey,
    ) -> (SourceAnchorKey, SourceAnchorKey, SourceAnchorKey) {
        let file = builder
            .insert_entity(&SourceFileEntity::new(
                "file-1",
                "src/lib.rs",
                "fixture-hash",
                100,
            ))
            .unwrap();
        let (presentation_key, presentation) = insert_anchor(builder, &file, "file-1", 10, 20);
        let (expanded_key, expanded) = insert_anchor(builder, &file, "file-1", 30, 40);
        let (callsite_key, callsite) = insert_anchor(builder, &file, "file-1", 50, 60);
        builder
            .relate(
                effect,
                &presentation,
                &EffectSiteHasSourceAnchor::new(EffectSourceAnchorRole::Presentation),
            )
            .unwrap();
        builder
            .relate(
                effect,
                &expanded,
                &EffectSiteHasSourceAnchor::new(EffectSourceAnchorRole::Expanded),
            )
            .unwrap();
        let outer = builder
            .insert_entity(&MacroExpansionEntity::new(
                MacroExpansionKey::new(site, 0),
                expansion(20),
                definition(21),
                "outer!",
            ))
            .unwrap();
        let inner = builder
            .insert_entity(&MacroExpansionEntity::new(
                MacroExpansionKey::new(site, 1),
                expansion(21),
                definition(22),
                "inner!",
            ))
            .unwrap();
        builder
            .relate(owner_body, &outer, &FunctionEntersMacroExpansion::new())
            .unwrap();
        builder
            .relate(&outer, &inner, &MacroExpansionEntersMacroExpansion::new())
            .unwrap();
        builder
            .relate(&inner, effect, &MacroExpansionProducesEffectSite::new())
            .unwrap();
        builder
            .relate(&outer, &callsite, &MacroExpansionHasCallsite::new())
            .unwrap();
        (presentation_key, expanded_key, callsite_key)
    }

    fn resolve_single_artifact(
        registry: &AnalysisRegistry<()>,
        builder: ArtifactDbBuilder,
        root: FunctionKey,
        node_budget: usize,
    ) -> CompilerAssertRootInputs {
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let workspace = WorkspaceFactView::compose([(
            ArtifactScopeId::for_in_memory(1, 0),
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
        resolve_inputs(registry, &workspace, &closure, root, node_budget)
    }

    pub(in crate::analysis::facts::panic) fn resolve_single_panic_artifact(
        registry: &AnalysisRegistry<()>,
        builder: ArtifactDbBuilder,
        root: FunctionKey,
        node_budget: usize,
    ) -> crate::analysis::facts::panic::compiler_assert_inputs::PanicRootInputs {
        let artifact = builder.finalize(registry.schemas()).unwrap();
        let workspace = WorkspaceFactView::compose([(
            ArtifactScopeId::for_in_memory(1, 0),
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
                node_budget,
            )],
        )
        .unwrap();
        let prepared = batch.into_roots().pop().unwrap();
        let mut composition_builder = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut composition_builder).unwrap();
        let composition = composition_builder.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &composition).unwrap();
        emitted
            .resolve_panic(&workspace, &graph, registry.composition_relations())
            .unwrap()
    }

    fn resolve_deep_assertion_fixture(
        depth: usize,
        witness_count: usize,
    ) -> CompilerAssertRootInputs {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let functions = (0..=depth)
            .map(|level| {
                let ordinal = u64::try_from(level).unwrap() + 100;
                FunctionKey::new(
                    definition(ordinal),
                    (level != 0).then(|| instance(u128::from(ordinal))),
                )
            })
            .collect::<Vec<_>>();
        let mut builder = declared_builder(&registry);
        let mut bodies = Vec::with_capacity(functions.len());
        let mut callables = Vec::with_capacity(functions.len());
        for (level, function) in functions.iter().copied().enumerate() {
            let (body, callable) =
                insert_function(&mut builder, function, &format!("crate::level_{level}"));
            bodies.push(body);
            callables.push(callable);
        }
        for level in 0..depth {
            let occurrence = insert_direct_call(
                &mut builder,
                &bodies[level],
                functions[level],
                0,
                &callables[level + 1],
            );
            attach_panic_marker_to_call(&mut builder, &occurrence, u32::try_from(level).unwrap());
        }
        for statement_index in 0..witness_count {
            let site = EffectSiteKey::from_mir(
                functions[depth],
                MirBodyLocation {
                    basic_block: 1,
                    statement_index,
                },
            )
            .unwrap();
            insert_assertion(&mut builder, &bodies[depth], site);
        }
        resolve_single_artifact(&registry, builder, functions[0], 2_048)
    }

    #[test]
    fn direct_assertion_projects_one_owned_terminal_step() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(1), None);
        let site = EffectSiteKey::from_mir(
            root,
            MirBodyLocation {
                basic_block: 1,
                statement_index: 2,
            },
        )
        .unwrap();
        let mut builder = declared_builder(&registry);
        let (body, _) = insert_function(&mut builder, root, "crate::root");
        insert_assertion(&mut builder, &body, site);
        let inputs = resolve_single_artifact(&registry, builder, root, 16);

        let trace = project_compiler_assert_semantic_trace(&inputs, 0).unwrap();

        assert_eq!(trace.witness_order(), 0);
        assert_eq!(trace.assertion(), inputs.assertions()[0].source());
        assert_eq!(
            trace.endpoint_data(),
            inputs
                .traversal()
                .effect_visits()
                .iter()
                .find(|visit| visit.effect() == trace.endpoint())
                .unwrap()
                .data()
        );
        let [step] = trace.steps() else {
            panic!("a direct assertion has exactly one semantic step")
        };
        assert_eq!(step.position(), 0);
        assert_eq!(step.caller_role(), CompilerAssertSemanticNodeRole::Function);
        assert_eq!(step.caller_display_path(), Some("crate::root"));
        assert_eq!(
            step.target_role(),
            CompilerAssertSemanticNodeRole::CompilerAssert(MirAssertKind::BoundsCheck)
        );
        assert_eq!(step.target_display_path(), None);
        assert_eq!(
            step.edge(),
            CompilerAssertSemanticEdge::Assert(MirAssertKind::BoundsCheck)
        );
        assert_eq!(step.source_key(), None);
        assert!(matches!(
            step.caller(),
            CompilerAssertTraceNode::Function { .. }
        ));
        assert!(matches!(
            step.target(),
            CompilerAssertTraceNode::CompilerAssert { effect_data, .. }
                if effect_data == trace.endpoint_data()
        ));
        assert!(matches!(
            step.kind(),
            CompilerAssertSemanticTraceStepKind::Assert {
                kind: MirAssertKind::BoundsCheck,
                ..
            }
        ));
        assert!(matches!(
            project_compiler_assert_semantic_trace(&inputs, 1),
            Err(CompilerAssertTraceError::UnknownWitnessOrder { order: 1 })
        ));
    }

    #[test]
    fn prepared_projector_indexes_root_once_for_many_assertions() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(1), None);
        let mut builder = declared_builder(&registry);
        let (body, _) = insert_function(&mut builder, root, "crate::root");
        for statement_index in 0..64 {
            let site = EffectSiteKey::from_mir(
                root,
                MirBodyLocation {
                    basic_block: 1,
                    statement_index,
                },
            )
            .unwrap();
            insert_assertion(&mut builder, &body, site);
        }
        let inputs = resolve_single_artifact(&registry, builder, root, 128);

        reset_projection_work();
        let projector = CompilerAssertTraceProjector::prepare(&inputs).unwrap();
        let preparation_work = projection_work();
        assert_eq!(preparation_work.assertions, inputs.assertions().len());
        assert_eq!(
            preparation_work.effect_visits,
            inputs.traversal().effect_visits().len()
        );
        assert_eq!(
            preparation_work.body_visits,
            inputs.traversal().body_visits().len()
        );
        assert_eq!(
            preparation_work.followed_calls,
            inputs.traversal().followed_calls().len()
        );

        for assertion in inputs.assertions() {
            projector.project(assertion.order()).unwrap();
        }

        assert_eq!(projection_work(), preparation_work);
    }

    #[test]
    fn deep_shared_route_selection_work_scales_with_input_not_witnesses_times_depth() {
        const DEPTH: usize = 12;
        const WITNESS_COUNT: usize = 64;
        let inputs = resolve_deep_assertion_fixture(DEPTH, WITNESS_COUNT);
        assert_eq!(inputs.assertions().len(), WITNESS_COUNT);
        assert_eq!(inputs.traversal().followed_calls().len(), DEPTH);

        let body_trace_edges = inputs
            .traversal()
            .body_visits()
            .iter()
            .map(|visit| visit.trace().relations().len())
            .sum::<usize>();
        let call_trace_edges = inputs
            .traversal()
            .followed_calls()
            .iter()
            .map(|call| call.trace().relations().len())
            .sum::<usize>();
        let effect_trace_edges = inputs
            .traversal()
            .effect_visits()
            .iter()
            .map(|effect| effect.trace().relations().len())
            .sum::<usize>();
        let longest_effect_trace = inputs
            .traversal()
            .effect_visits()
            .iter()
            .map(|effect| effect.trace().relations().len())
            .max()
            .unwrap();
        let body_marker_refs = inputs
            .traversal()
            .body_visits()
            .iter()
            .map(|visit| visit.active_markers().len())
            .sum::<usize>();
        let call_active_marker_refs = inputs
            .traversal()
            .followed_calls()
            .iter()
            .map(|call| call.active_markers().len())
            .sum::<usize>();
        let call_inherited_marker_refs = inputs
            .traversal()
            .followed_calls()
            .iter()
            .map(|call| call.inherited_markers().len())
            .sum::<usize>();
        let effect_marker_refs = inputs
            .traversal()
            .effect_visits()
            .iter()
            .map(|effect| effect.inherited_markers().len())
            .sum::<usize>();
        let longest_effect_markers = inputs
            .traversal()
            .effect_visits()
            .iter()
            .map(|effect| effect.inherited_markers().len())
            .max()
            .unwrap();

        reset_projection_work();
        let projector = CompilerAssertTraceProjector::prepare(&inputs).unwrap();
        for assertion in inputs.assertions() {
            let trace = projector.project(assertion.order()).unwrap();
            assert_eq!(trace.steps().len(), DEPTH + 1);
        }
        let work = projection_work();
        let max_trie_edges = 2 * (body_trace_edges + call_trace_edges + effect_trace_edges)
            + 2 * call_trace_edges
            + DEPTH
            + longest_effect_trace;

        assert!(
            work.trie_edges <= max_trie_edges,
            "trie-edge work was {work:?}, maximum {max_trie_edges}"
        );
        assert!(
            work.body_candidates <= WITNESS_COUNT + 2 * DEPTH,
            "body-candidate work was {work:?}"
        );
        assert!(
            work.marker_claims
                <= body_marker_refs
                    + effect_marker_refs
                    + call_inherited_marker_refs
                    + 4 * call_active_marker_refs
                    + 2 * longest_effect_markers,
            "marker work was {work:?}"
        );
    }

    #[test]
    fn nested_assertion_uses_only_the_exact_followed_call_route() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(10), None);
        let callee = FunctionKey::new(definition(11), Some(instance(11)));
        let decoy = FunctionKey::new(definition(12), Some(instance(12)));
        let site = EffectSiteKey::from_mir(
            callee,
            MirBodyLocation {
                basic_block: 2,
                statement_index: 3,
            },
        )
        .unwrap();
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let (callee_body, callee_callable) = insert_function(&mut builder, callee, "crate::callee");
        let (_, decoy_callable) = insert_function(&mut builder, decoy, "crate::decoy");
        let occurrence = insert_direct_call(&mut builder, &root_body, root, 1, &callee_callable);
        let (_call_presentation_key, call_expanded_key, call_macro_key) =
            attach_call_macros_and_sources(&mut builder, &root_body, root, &occurrence);
        insert_direct_call(&mut builder, &root_body, root, 2, &decoy_callable);
        insert_assertion(&mut builder, &callee_body, site);
        let inputs = resolve_single_artifact(&registry, builder, root, 32);

        let trace = project_compiler_assert_semantic_trace(&inputs, 0).unwrap();

        let [outer, inner, call, assertion] = trace.steps() else {
            panic!("the exact nested route has two call macros, one call, and one assertion")
        };
        let followed = inputs
            .traversal()
            .followed_calls()
            .iter()
            .find(|followed| followed.target_data().key() == &callee)
            .unwrap();
        assert!(matches!(
            outer.kind(),
            CompilerAssertSemanticTraceStepKind::CallMacro { .. }
        ));
        assert_eq!(
            outer.caller_role(),
            CompilerAssertSemanticNodeRole::Function
        );
        assert_eq!(outer.caller_display_path(), Some("crate::root"));
        assert_eq!(outer.target_role(), CompilerAssertSemanticNodeRole::Macro);
        assert_eq!(outer.target_display_path(), Some("call_outer!"));
        assert_eq!(outer.edge(), CompilerAssertSemanticEdge::MacroExpansion);
        assert!(matches!(
            outer.target(),
            CompilerAssertTraceNode::Macro(value) if value.display_path() == "call_outer!"
        ));
        assert_eq!(outer.source().unwrap().key(), &call_macro_key);
        assert!(matches!(
            inner.target(),
            CompilerAssertTraceNode::Macro(value) if value.display_path() == "call_inner!"
        ));
        assert!(matches!(
            call.kind(),
            CompilerAssertSemanticTraceStepKind::Call(value)
                if value.effective_kind() == CallKind::DirectCall
                    && value.occurrence() == followed.occurrence()
                    && value.occurrence_data() == followed.occurrence_data()
                    && value.call_site() == followed.call_site()
                    && value.call_site_data() == followed.call_site_data()
                    && value.safety_group() == followed.safety_group()
                    && value.safety_group_data() == followed.safety_group_data()
                    && value.resolution() == followed.resolution()
                    && value.target() == followed.target()
        ));
        assert!(matches!(
            call.target(),
            CompilerAssertTraceNode::Callable { data, .. } if data.key() == &callee
        ));
        assert_eq!(call.source().unwrap().key(), &call_expanded_key);
        assert_eq!(call.source_key(), Some(&call_expanded_key));
        assert_eq!(call.caller_role(), CompilerAssertSemanticNodeRole::Macro);
        assert_eq!(call.caller_display_path(), Some("call_inner!"));
        assert_eq!(call.target_role(), CompilerAssertSemanticNodeRole::Callable);
        assert_eq!(call.target_display_path(), Some("crate::callee"));
        assert_eq!(
            call.edge(),
            CompilerAssertSemanticEdge::Call(CallKind::DirectCall)
        );
        assert_eq!(
            call.source().unwrap().role(),
            CompilerAssertTraceSourceRole::Call(CallSourceAnchorRole::Expanded)
        );
        assert_eq!(call.owner().data().key(), &root);
        assert_eq!(assertion.owner().data().key(), &callee);
        assert!(matches!(
            assertion.kind(),
            CompilerAssertSemanticTraceStepKind::Assert { .. }
        ));
        assert_eq!(
            assertion.target_role(),
            CompilerAssertSemanticNodeRole::CompilerAssert(MirAssertKind::BoundsCheck)
        );
        assert_eq!(
            assertion.edge(),
            CompilerAssertSemanticEdge::Assert(MirAssertKind::BoundsCheck)
        );

        assert_nested_semantic_order(&trace);
    }

    fn assert_nested_semantic_order(trace: &CompilerAssertSemanticTrace) {
        let order = semantic_order_for_trace(trace, 77).unwrap();
        let [outer_order, inner_order, call_order, assertion_order] = order.steps() else {
            panic!("semantic evidence ordering must retain every projected step")
        };
        assert_eq!(order.traversal_order(), 77);
        assert_eq!(outer_order.caller(), "crate::root");
        assert_eq!(outer_order.target(), Some("macro call_outer!"));
        assert_eq!(inner_order.caller(), "macro call_outer!");
        assert_eq!(inner_order.target(), Some("macro call_inner!"));
        assert_eq!(call_order.caller(), "macro call_inner!");
        assert_eq!(call_order.target(), Some("crate::callee"));
        assert_eq!(assertion_order.caller(), "crate::callee");
        assert_eq!(
            assertion_order.target(),
            Some("compiler assert index out of bounds")
        );
        assert_eq!(
            outer_order.kind(),
            EvidenceSemanticEdgeOrder::Reachability(CallKind::MacroExpansion)
        );
        assert_eq!(inner_order.kind(), outer_order.kind());
        assert_eq!(
            call_order.kind(),
            EvidenceSemanticEdgeOrder::Reachability(CallKind::DirectCall)
        );
        assert_eq!(
            assertion_order.kind(),
            EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert)
        );
        assert_eq!(outer_order.source().unwrap().byte_start(), 50);
        assert_eq!(outer_order.source().unwrap().byte_end(), 60);
        assert_eq!(inner_order.source(), None);
        assert_eq!(call_order.source().unwrap().byte_start(), 30);
        assert_eq!(call_order.source().unwrap().byte_end(), 40);
    }

    #[test]
    fn repeated_body_marker_states_keep_their_exact_selected_call_routes() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(40), None);
        let callee = FunctionKey::new(definition(41), Some(instance(41)));
        let site = EffectSiteKey::from_mir(
            callee,
            MirBodyLocation {
                basic_block: 5,
                statement_index: 6,
            },
        )
        .unwrap();
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let (callee_body, callee_callable) = insert_function(&mut builder, callee, "crate::callee");
        let unmarked = insert_direct_call(&mut builder, &root_body, root, 1, &callee_callable);
        let marked = insert_direct_call(&mut builder, &root_body, root, 2, &callee_callable);
        attach_panic_marker_to_call(&mut builder, &marked, 1);
        insert_assertion(&mut builder, &callee_body, site);
        let inputs = resolve_single_artifact(&registry, builder, root, 32);

        assert_eq!(inputs.assertions().len(), 2);
        assert_eq!(inputs.assertions()[0].markers().len(), 0);
        assert_eq!(inputs.assertions()[1].markers().len(), 1);
        let unmarked_trace = project_compiler_assert_semantic_trace(&inputs, 0).unwrap();
        let marked_trace = project_compiler_assert_semantic_trace(&inputs, 1).unwrap();

        let unmarked_call = unmarked_trace
            .steps()
            .iter()
            .find_map(|step| match step.kind() {
                CompilerAssertSemanticTraceStepKind::Call(call) => Some(call),
                _ => None,
            })
            .unwrap();
        let marked_call = marked_trace
            .steps()
            .iter()
            .find_map(|step| match step.kind() {
                CompilerAssertSemanticTraceStepKind::Call(call) => Some(call),
                _ => None,
            })
            .unwrap();
        assert_eq!(unmarked_call.occurrence_data().key(), unmarked.key());
        assert_eq!(marked_call.occurrence_data().key(), marked.key());
    }

    #[test]
    fn cross_scope_call_keeps_consumer_callable_and_dependency_body_generations() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(30), None);
        let callee_definition =
            serde_json::from_str::<StableDefPathHash>("\"0000000000000002000000000000001f\"")
                .unwrap();
        let callee = FunctionKey::new(callee_definition, Some(instance(31)));
        let site = EffectSiteKey::from_mir(
            callee,
            MirBodyLocation {
                basic_block: 4,
                statement_index: 5,
            },
        )
        .unwrap();

        let mut root_builder = declared_builder(&registry);
        let mut dependency_builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut root_builder, root, "root::entry");
        let consumer_target = insert_callable(&mut root_builder, callee, "dependency::callee");
        insert_direct_call(&mut root_builder, &root_body, root, 1, &consumer_target);
        let (dependency_body, _) =
            insert_function(&mut dependency_builder, callee, "dependency::callee");
        insert_assertion(&mut dependency_builder, &dependency_body, site);

        let root_artifact = root_builder.finalize(registry.schemas()).unwrap();
        let dependency_artifact = dependency_builder.finalize(registry.schemas()).unwrap();
        let root_scope = ArtifactScopeId::for_in_memory(1, 0);
        let dependency_id = RustcArtifactId::new(2, "2".repeat(32));
        let dependency_scope =
            ArtifactScopeId::for_persisted(2, dependency_id.svh.clone()).unwrap();
        let workspace = WorkspaceFactView::compose([
            (
                root_scope.clone(),
                ArtifactDbView::open(&root_artifact, registry.schemas()).unwrap(),
            ),
            (
                dependency_scope.clone(),
                ArtifactDbView::open(&dependency_artifact, registry.schemas()).unwrap(),
            ),
        ])
        .unwrap();
        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(
                ManagedArtifactGeneration::in_memory(1, 0),
                vec![dependency_id.clone()],
            ),
            [ManagedArtifactManifest::new(
                ManagedArtifactGeneration::persisted(dependency_id),
                vec![],
            )],
            Vec::<RustcArtifactId>::new(),
        )
        .unwrap();
        let inputs = resolve_inputs(&registry, &workspace, &closure, root, 32);

        let trace = project_compiler_assert_semantic_trace(&inputs, 0).unwrap();

        let [call, assertion] = trace.steps() else {
            panic!("the cross-scope route retains one call and one assertion")
        };
        assert!(matches!(
            call.target(),
            CompilerAssertTraceNode::Callable { callable, .. }
                if callable.scope() == &root_scope
        ));
        assert_eq!(assertion.owner().body().scope(), &dependency_scope);
        assert_eq!(assertion.owner().data().key(), &callee);
    }

    #[test]
    fn effect_macros_preserve_outer_to_inner_frames_and_source_precedence() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(20), None);
        let site = EffectSiteKey::from_mir(
            root,
            MirBodyLocation {
                basic_block: 3,
                statement_index: 4,
            },
        )
        .unwrap();
        let mut builder = declared_builder(&registry);
        let (body, _) = insert_function(&mut builder, root, "crate::root");
        let effect = insert_assertion(&mut builder, &body, site);
        let (_presentation_key, expanded_key, callsite_key) =
            attach_effect_macros_and_sources(&mut builder, &body, &effect, site);
        let inputs = resolve_single_artifact(&registry, builder, root, 16);

        let trace = project_compiler_assert_semantic_trace(&inputs, 0).unwrap();

        let [outer_step, inner_step, assertion] = trace.steps() else {
            panic!("two macro frames precede the terminal assertion")
        };
        assert!(matches!(
            outer_step.kind(),
            CompilerAssertSemanticTraceStepKind::EffectMacro { .. }
        ));
        assert!(matches!(
            inner_step.kind(),
            CompilerAssertSemanticTraceStepKind::EffectMacro { .. }
        ));
        assert!(matches!(
            outer_step.target(),
            CompilerAssertTraceNode::Macro(value) if value.display_path() == "outer!"
        ));
        assert!(matches!(
            inner_step.target(),
            CompilerAssertTraceNode::Macro(value) if value.display_path() == "inner!"
        ));
        let macro_source = outer_step.source().unwrap();
        assert_eq!(macro_source.key(), &callsite_key);
        assert_eq!(outer_step.source_key(), Some(&callsite_key));
        assert_eq!(
            macro_source.relation().relation().schema.as_str(),
            MacroExpansionHasCallsite::ID
        );
        let assertion_source = assertion.source().unwrap();
        assert_eq!(assertion_source.key(), &expanded_key);
        assert_eq!(
            assertion_source.role(),
            CompilerAssertTraceSourceRole::Effect(EffectSourceAnchorRole::Expanded)
        );
        assert_eq!(
            assertion_source.relation().relation().schema.as_str(),
            EffectSiteHasSourceAnchor::ID
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the end-to-end fixture proves every callable-evidence identity facet"
    )]
    fn callable_evidence_follow_projects_exact_resolution_kind_and_target() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(70), None);
        let callee = FunctionKey::new(definition(71), Some(instance(71)));
        let callable_key = CallableKey::FnPointer(type_hash(71));
        let site = EffectSiteKey::from_mir(
            callee,
            MirBodyLocation {
                basic_block: 7,
                statement_index: 1,
            },
        )
        .unwrap();
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let (callee_body, callee_callable) =
            insert_function(&mut builder, callee, "crate::resolved");
        let raw = FunctionKey::new(definition(72), Some(instance(72)));
        let raw_callable = builder
            .insert_entity(&CallableEntity::new(
                raw,
                "crate::unresolved",
                false,
                false,
                false,
                false,
                vec![String::from("crate::unresolved")],
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
            Some(&callee_callable),
            false,
            None,
        );
        let invocation = insert_configured_call(
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
        insert_assertion(&mut builder, &callee_body, site);
        let inputs = resolve_single_artifact(&registry, builder, root, 32);

        let trace = project_compiler_assert_semantic_trace(&inputs, 0).unwrap();
        let evidence_visit = inputs
            .traversal()
            .occurrence_visits()
            .iter()
            .find(|visit| visit.data().key() == evidence.key())
            .unwrap();
        let projected = trace
            .steps()
            .iter()
            .find_map(|step| match step.kind() {
                CompilerAssertSemanticTraceStepKind::Call(call) => Some(call),
                _ => None,
            })
            .expect("the reached callable-evidence route is projected");

        assert_eq!(projected.occurrence_data().key(), invocation.key());
        assert_eq!(projected.effective_kind(), CallKind::FnPointerCallTarget);
        assert!(matches!(
            projected.resolution(),
            ProgramCallResolution::CallableEvidence {
                evidence: selected_evidence,
                key: selected_key,
                kind: CallableResolutionKind::FunctionPointerEvidence,
            } if selected_evidence == evidence_visit.occurrence()
                && *selected_key == callable_key
        ));
        assert_eq!(projected.target().role(), CallTargetRole::Runtime);
        assert_eq!(
            projected.target().authority(),
            ReconciledCallTargetAuthority::ConsumerRaw
        );
        let followed = inputs
            .traversal()
            .followed_calls()
            .iter()
            .find(|call| call.occurrence_data().key() == invocation.key())
            .unwrap();
        assert_eq!(projected.resolution(), followed.resolution());
        assert_eq!(projected.target(), followed.target());
        assert_eq!(followed.target_data().key(), &callee);
        assert_eq!(
            followed
                .trace()
                .relations()
                .last()
                .map(|relation| relation.schema().as_str()),
            Some(CallableInvocationTargetsCallable::ID)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the two-artifact fixture keeps reconciliation and marker transport explicit"
    )]
    fn reconciled_consumer_call_projects_transported_marker_and_defining_target_authority() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let consumer = FunctionKey::new(definition_in(2, 80), Some(instance(80)));
        let defining = FunctionKey::new(consumer.definition(), None);
        let callee = FunctionKey::new(definition_in(2, 81), Some(instance(81)));
        let site = EffectSiteKey::from_mir(
            callee,
            MirBodyLocation {
                basic_block: 8,
                statement_index: 1,
            },
        )
        .unwrap();

        let mut consumer_builder = declared_builder(&registry);
        let (consumer_body, _) = insert_function_with_provenance(
            &mut consumer_builder,
            consumer,
            "consumer::entry",
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 1,
            },
        );
        let consumer_target = insert_callable(&mut consumer_builder, callee, "dependency::callee");
        let consumer_call = insert_configured_call(
            &mut consumer_builder,
            &consumer_body,
            consumer,
            0,
            CallKind::DirectCall,
            vec![CallAttributionRole::CallSite],
            None,
            Some(&consumer_target),
            false,
            None,
        );
        let shared_key =
            attach_shared_call_source(&mut consumer_builder, &consumer_call, "shared-call");

        let mut defining_builder = declared_builder(&registry);
        let (defining_body, _) =
            insert_function(&mut defining_builder, defining, "dependency::generic");
        let (callee_body, callee_callable) =
            insert_function(&mut defining_builder, callee, "dependency::callee");
        let defining_call = insert_direct_call(
            &mut defining_builder,
            &defining_body,
            defining,
            0,
            &callee_callable,
        );
        assert_eq!(
            attach_shared_call_source(&mut defining_builder, &defining_call, "shared-call"),
            shared_key
        );
        let marker = attach_panic_marker_to_call(&mut defining_builder, &defining_call, 80);
        insert_assertion(&mut defining_builder, &callee_body, site);

        let root_artifact = consumer_builder.finalize(registry.schemas()).unwrap();
        let defining_artifact = defining_builder.finalize(registry.schemas()).unwrap();
        let root_scope = ArtifactScopeId::for_in_memory(1, 0);
        let dependency_id = RustcArtifactId::new(2, "8".repeat(32));
        let dependency_scope =
            ArtifactScopeId::for_persisted(2, dependency_id.svh.clone()).unwrap();
        let workspace = WorkspaceFactView::compose([
            (
                root_scope.clone(),
                ArtifactDbView::open(&root_artifact, registry.schemas()).unwrap(),
            ),
            (
                dependency_scope.clone(),
                ArtifactDbView::open(&defining_artifact, registry.schemas()).unwrap(),
            ),
        ])
        .unwrap();
        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(
                ManagedArtifactGeneration::in_memory(1, 0),
                vec![dependency_id.clone()],
            ),
            [ManagedArtifactManifest::new(
                ManagedArtifactGeneration::persisted(dependency_id),
                vec![],
            )],
            Vec::<RustcArtifactId>::new(),
        )
        .unwrap();
        let inputs = resolve_inputs(&registry, &workspace, &closure, consumer, 32);

        let trace = project_compiler_assert_semantic_trace(&inputs, 0).unwrap();
        let projected = trace
            .steps()
            .iter()
            .find_map(|step| match step.kind() {
                CompilerAssertSemanticTraceStepKind::Call(call) => Some(call),
                _ => None,
            })
            .expect("the reconciled consumer call is projected");
        let followed = inputs.traversal().followed_calls().first().unwrap();

        assert_eq!(projected.occurrence_data().key(), consumer_call.key());
        assert_eq!(projected.resolution(), &ProgramCallResolution::Persisted);
        assert_eq!(
            projected.target().authority(),
            ReconciledCallTargetAuthority::ConsumerRaw
        );
        assert_eq!(projected.target().callable().scope(), &root_scope);
        assert_eq!(projected.target(), followed.target());
        assert_eq!(followed.target_data().key(), &callee);
        assert!(
            followed
                .active_markers()
                .iter()
                .any(|active| active.data().key() == marker.key())
        );
        assert!(
            inputs.assertions()[0]
                .markers()
                .iter()
                .any(|active| active.data().key() == marker.key())
        );
        assert!(followed.active_markers().iter().any(|active| {
            active
                .trace()
                .relations()
                .iter()
                .any(|relation| relation.schema().as_str() == ConsumerOccurrenceReconcilesWith::ID)
        }));
    }

    #[test]
    fn tampered_non_monotonic_selected_route_fails_closed() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let root = FunctionKey::new(definition(90), None);
        let middle = FunctionKey::new(definition(91), Some(instance(91)));
        let callee = FunctionKey::new(definition(92), Some(instance(92)));
        let site = EffectSiteKey::from_mir(
            callee,
            MirBodyLocation {
                basic_block: 9,
                statement_index: 1,
            },
        )
        .unwrap();
        let mut builder = declared_builder(&registry);
        let (root_body, _) = insert_function(&mut builder, root, "crate::root");
        let (middle_body, middle_callable) = insert_function(&mut builder, middle, "crate::middle");
        let (callee_body, callee_callable) = insert_function(&mut builder, callee, "crate::callee");
        insert_direct_call(&mut builder, &root_body, root, 0, &middle_callable);
        insert_direct_call(&mut builder, &middle_body, middle, 0, &callee_callable);
        insert_assertion(&mut builder, &callee_body, site);
        let inputs = resolve_single_artifact(&registry, builder, root, 32);
        let projector = CompilerAssertTraceProjector::prepare(&inputs).unwrap();
        let prepared = projector.prepared(0).unwrap();
        let effect = prepared.effect;
        let mut route = projector.routes[prepared.route].clone();
        assert_eq!(route.len(), 2);
        super::validate_call_route(&route, effect).unwrap();

        route.swap_for_test(0, 1);
        assert_eq!(
            super::validate_call_route(&route, effect),
            Err(CompilerAssertTraceError::NonMonotonicTraversalOrder)
        );
    }
}
