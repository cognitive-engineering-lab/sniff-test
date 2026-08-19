//! Safety-domain human-evidence use projection.

use std::collections::BTreeSet;

use super::operations::UnsafeOperationSourceAnchorRole;
use super::{SafetyBoundary, SafetyRootInputs, safety_domain};
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationInput, EvaluationOutput, EvaluationRule, RuleDescriptor, RuleError,
};
use crate::analysis::facts::evidence::{
    EvidenceSemanticEdgeOrder, EvidenceSemanticOrder, EvidenceSemanticSourceOrder,
    EvidenceSemanticStepOrder, EvidenceUseRecord,
};
use crate::analysis::facts::human::EvidenceClaimSelector;
use crate::analysis::facts::human::markers::MarkerClaimEntity;
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::panic::trace_route::{
    SelectedTraceRoute, TraceRouteEndpoint, TraceRouteSelector,
};
use crate::analysis::facts::program::SourceAnchorKey;
use crate::analysis::facts::program::root_traversal::{
    ResolvedBodyVisit, ResolvedCallBoundary, ResolvedCallMacroCallsite, ResolvedCallSourceAnchor,
    ResolvedFollowedCall, ResolvedMarkerClaim, ResolvedUnsafeOperationMacroCallsite,
    ResolvedUnsafeOperationSourceAnchor, ResolvedUnsafeOperationVisit,
};
use crate::analysis::facts::program::topology::{CallKind, CallSourceAnchorRole};
use crate::analysis::facts::schema::PassId;
use crate::contracts::normalize_requirement_name;

const EMIT_SAFETY_EVIDENCE_USES_RULE: &str = "sniff-test.safety.emit-evidence-uses";

pub(crate) struct SafetyEvidenceUsePack;

impl AnalysisPack<SafetyRootInputs> for SafetyEvidenceUsePack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<SafetyRootInputs>,
    ) -> Result<(), PackRegistrationError> {
        registry.register_derived::<EvidenceUseRecord>()?;
        registry.register_evaluation_rule(EmitSafetyEvidenceUses)
    }
}

struct EmitSafetyEvidenceUses;

impl EvaluationRule<SafetyRootInputs> for EmitSafetyEvidenceUses {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new(EMIT_SAFETY_EVIDENCE_USES_RULE).unwrap())
            .read::<MarkerClaimEntity>()
            .write_derived::<EvidenceUseRecord>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, SafetyRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        if cx.root().domain != safety_domain()
            || cx.services().root() != cx.root()
            || !input.has_workspace_identity(cx.services().workspace_identity())
        {
            return Err(RuleError::failed(
                "safety evidence inputs belong to a different workspace, domain, or root",
            ));
        }
        let mut selector = TraceRouteSelector::prepare(cx.services().traversal());
        let mut uses = Vec::new();
        for visit in cx.services().traversal().unsafe_operation_visits() {
            let route = selector
                .select_route(TraceRouteEndpoint::new(
                    visit.order(),
                    visit.trace(),
                    visit.inherited_markers(),
                ))
                .map_err(trace_error)?;
            let owner = selector
                .select_owner_body(
                    visit.owner().erase(),
                    visit.inherited_markers(),
                    visit.trace(),
                )
                .map_err(|error| {
                    RuleError::failed(format!("invalid safety owner body: {error:?}"))
                })?;
            let semantic_order = operation_semantic_order(&route, owner, visit);
            collect_uses(
                cx,
                input,
                visit.active_markers(),
                |marker| matches!(marker.data().selector(), EvidenceClaimSelector::Unnamed),
                &visit.operation().erase(),
                &visit.safety_group().erase(),
                &visit.operation().erase().as_row(),
                visit.trace(),
                visit.order(),
                &semantic_order,
                &mut uses,
            )?;
        }
        for boundary in cx.services().traversal().call_boundaries() {
            let contributing = call_contributing_claims(boundary);
            if contributing.is_empty() {
                continue;
            }
            let route = selector
                .select_route(TraceRouteEndpoint::new(
                    boundary.order(),
                    boundary.trace(),
                    boundary.inherited_markers(),
                ))
                .map_err(trace_error)?;
            let owner = selector
                .select_terminal_caller(
                    &boundary.occurrence().erase(),
                    *boundary.occurrence_data().key().owner(),
                    boundary.inherited_markers(),
                    boundary.trace(),
                )
                .map_err(trace_error)?;
            let semantic_order = call_semantic_order(&route, owner, boundary);
            collect_uses(
                cx,
                input,
                boundary.active_markers(),
                |marker| contributing.contains(&marker.claim().erase()),
                &boundary.occurrence().erase(),
                &boundary.safety_group().erase(),
                &boundary.occurrence().erase().as_row(),
                boundary.trace(),
                boundary.order(),
                &semantic_order,
                &mut uses,
            )?;
        }
        for usage in uses {
            output.emit_derived(&usage)?;
        }
        Ok(())
    }
}

fn trace_error(error: impl std::fmt::Debug) -> RuleError {
    RuleError::failed(format!("invalid safety evidence route: {error:?}"))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the strict evidence row's witness identity is intentionally explicit"
)]
fn collect_uses(
    cx: &EvaluationCx<'_, SafetyRootInputs>,
    input: &EvaluationInput<'_>,
    markers: &[ResolvedMarkerClaim],
    contributes: impl Fn(&ResolvedMarkerClaim) -> bool,
    endpoint: &crate::analysis::facts::workspace::ScopedEntityRef,
    group: &crate::analysis::facts::workspace::ScopedEntityRef,
    source: &crate::analysis::facts::workspace::ScopedRowRef,
    trace: &crate::analysis::facts::evaluation::RelationTrace,
    witness_order: u64,
    semantic_order: &EvidenceSemanticOrder,
    uses: &mut Vec<EvidenceUseRecord>,
) -> Result<(), RuleError> {
    for marker in markers {
        let claim = input.artifact_entity_at::<MarkerClaimEntity>(&marker.claim().erase())?;
        if claim != *marker.data() {
            return Err(RuleError::failed(
                "safety evidence claim changed after traversal preparation",
            ));
        }
        if claim.key().domain() == &cx.root().domain
            && !claim.rationale().trim().is_empty()
            && contributes(marker)
        {
            uses.push(EvidenceUseRecord::new(
                cx.root().domain.clone(),
                marker.claim().erase(),
                endpoint.clone(),
                group.clone(),
                source.clone(),
                trace.clone(),
                witness_order,
                semantic_order.clone(),
            ));
        }
    }
    Ok(())
}

fn call_contributing_claims(
    boundary: &ResolvedCallBoundary<SafetyBoundary>,
) -> BTreeSet<crate::analysis::facts::workspace::ScopedEntityRef> {
    let Some(requirements) = call_requirements(boundary) else {
        return BTreeSet::new();
    };
    let normalized = requirements
        .iter()
        .map(super::contract_index::EffectiveSafetyRequirement::normalized_name)
        .collect::<BTreeSet<_>>();
    boundary
        .active_markers()
        .iter()
        .filter_map(|marker| {
            let selector_matches = if requirements.is_empty() {
                matches!(marker.data().selector(), EvidenceClaimSelector::Unnamed)
            } else {
                matches!(
                    marker.data().selector(),
                    EvidenceClaimSelector::Named(name)
                        if normalized.contains(normalize_requirement_name(name).as_str())
                )
            };
            selector_matches.then(|| marker.claim().erase())
        })
        .collect()
}

fn call_requirements(
    boundary: &ResolvedCallBoundary<SafetyBoundary>,
) -> Option<&[super::contract_index::EffectiveSafetyRequirement]> {
    match boundary.payload() {
        SafetyBoundary::CallContract(contract) if call_is_obligation(boundary) => {
            Some(contract.contract().requirements())
        }
        SafetyBoundary::ForeignDeclaration
        | SafetyBoundary::BodylessDeclaration
        | SafetyBoundary::OpaqueCall { .. }
            if boundary.occurrence_data().requires_unsafe()
                && is_actual_call(boundary.effective_kind()) =>
        {
            Some(&[])
        }
        SafetyBoundary::RootContract(_)
        | SafetyBoundary::CallContract(_)
        | SafetyBoundary::TrustedNamespace
        | SafetyBoundary::ForeignDeclaration
        | SafetyBoundary::BodylessDeclaration
        | SafetyBoundary::OpaqueCall { .. }
        | SafetyBoundary::BuiltinUnsafe => None,
    }
}

fn call_is_obligation(boundary: &ResolvedCallBoundary<SafetyBoundary>) -> bool {
    (boundary.occurrence_data().requires_unsafe() && is_actual_call(boundary.effective_kind()))
        || boundary
            .target_data()
            .is_some_and(|target| !target.is_unsafe())
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

fn operation_semantic_order(
    route: &SelectedTraceRoute<'_>,
    owner: &ResolvedBodyVisit,
    visit: &ResolvedUnsafeOperationVisit,
) -> EvidenceSemanticOrder {
    let mut steps = route_semantic_steps(route);
    let mut caller = owner.data().display_path().to_owned();
    for frame in visit.macro_frames() {
        let target = frame.data().display_path().to_owned();
        steps.push(semantic_step(
            caller,
            EvidenceSemanticEdgeOrder::Reachability(CallKind::MacroExpansion),
            Some(target.clone()),
            frame
                .callsite()
                .map(ResolvedUnsafeOperationMacroCallsite::key),
        ));
        caller = target;
    }
    steps.push(semantic_step(
        caller,
        EvidenceSemanticEdgeOrder::UnsafeOperation(visit.data().kind()),
        None,
        selected_operation_source(visit.source_anchors()),
    ));
    EvidenceSemanticOrder::new(steps, visit.order())
}

fn call_semantic_order(
    route: &SelectedTraceRoute<'_>,
    owner: &ResolvedBodyVisit,
    boundary: &ResolvedCallBoundary<SafetyBoundary>,
) -> EvidenceSemanticOrder {
    let mut steps = route_semantic_steps(route);
    let mut caller = owner.data().display_path().to_owned();
    for frame in boundary.macro_frames() {
        let target = frame.data().display_path().to_owned();
        steps.push(semantic_step(
            caller,
            EvidenceSemanticEdgeOrder::Reachability(CallKind::MacroExpansion),
            Some(target.clone()),
            frame.callsite().map(ResolvedCallMacroCallsite::key),
        ));
        caller = target;
    }
    let target = boundary.target_data().map_or_else(
        || match boundary.payload() {
            SafetyBoundary::OpaqueCall { description } => Some(description.clone()),
            SafetyBoundary::RootContract(_)
            | SafetyBoundary::CallContract(_)
            | SafetyBoundary::TrustedNamespace
            | SafetyBoundary::ForeignDeclaration
            | SafetyBoundary::BodylessDeclaration
            | SafetyBoundary::BuiltinUnsafe => None,
        },
        |target| Some(target.display_path().to_owned()),
    );
    steps.push(semantic_step(
        caller,
        EvidenceSemanticEdgeOrder::Reachability(boundary.effective_kind()),
        target,
        selected_call_source(boundary.source_anchors()),
    ));
    EvidenceSemanticOrder::new(steps, boundary.order())
}

fn route_semantic_steps(route: &SelectedTraceRoute<'_>) -> Vec<EvidenceSemanticStepOrder> {
    let mut steps = Vec::new();
    for selected in route.calls() {
        append_followed_call_steps(&mut steps, selected.caller(), selected.call());
    }
    steps
}

fn append_followed_call_steps(
    steps: &mut Vec<EvidenceSemanticStepOrder>,
    owner: &ResolvedBodyVisit,
    call: &ResolvedFollowedCall,
) {
    let mut caller = owner.data().display_path().to_owned();
    for frame in call.macro_frames() {
        let target = frame.data().display_path().to_owned();
        steps.push(semantic_step(
            caller,
            EvidenceSemanticEdgeOrder::Reachability(CallKind::MacroExpansion),
            Some(target.clone()),
            frame.callsite().map(ResolvedCallMacroCallsite::key),
        ));
        caller = target;
    }
    steps.push(semantic_step(
        caller,
        EvidenceSemanticEdgeOrder::Reachability(call.effective_kind()),
        Some(call.target_data().display_path().to_owned()),
        selected_call_source(call.source_anchors()),
    ));
}

fn semantic_step(
    caller: String,
    kind: EvidenceSemanticEdgeOrder,
    target: Option<String>,
    source: Option<&SourceAnchorKey>,
) -> EvidenceSemanticStepOrder {
    EvidenceSemanticStepOrder::new(caller, kind, target, source.map(semantic_source))
}

fn semantic_source(source: &SourceAnchorKey) -> EvidenceSemanticSourceOrder {
    EvidenceSemanticSourceOrder::new(source.byte_start(), source.byte_end())
}

fn selected_call_source(anchors: &[ResolvedCallSourceAnchor]) -> Option<&SourceAnchorKey> {
    [
        CallSourceAnchorRole::Expanded,
        CallSourceAnchorRole::Presentation,
    ]
    .into_iter()
    .find_map(|role| {
        anchors
            .iter()
            .find(|anchor| anchor.role() == role)
            .map(ResolvedCallSourceAnchor::key)
    })
}

fn selected_operation_source(
    anchors: &[ResolvedUnsafeOperationSourceAnchor],
) -> Option<&SourceAnchorKey> {
    [
        UnsafeOperationSourceAnchorRole::Expanded,
        UnsafeOperationSourceAnchorRole::Presentation,
    ]
    .into_iter()
    .find_map(|role| {
        anchors
            .iter()
            .find(|anchor| anchor.role() == role)
            .map(ResolvedUnsafeOperationSourceAnchor::key)
    })
}
