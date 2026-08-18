//! Validated evaluation ingress for retained panic-call obligations.

use std::collections::{BTreeMap, BTreeSet};

use super::call_issues::{ReportDuplicatePanicCallRequirements, ReportUnsatisfiedPanicCalls};
use super::call_matching::MatchPanicCallEvidence;
use super::call_model::{
    DuplicatePanicCallRequirementIssue, PanicCallAnchorProvenance, PanicCallBoundaryKind,
    PanicCallContractOrigin, PanicCallContractProvenance, PanicCallEvidenceMatch, PanicCallMarker,
    PanicCallMetadataTarget, PanicCallObligation, PanicCallOpaqueKind, PanicCallRequirementValue,
    PanicCallResolution, PanicCallTarget, UnsatisfiedPanicCallIssue,
};
use super::call_trace::{
    PanicCallSemanticEdge, PanicCallSemanticTrace, PanicCallSemanticTraceStepKind,
    PanicCallTraceNode, PanicCallTraceProjector,
};
use super::compiler_assert_inputs::{
    PanicCallInputKind, PanicOpaqueBoundaryKind, PanicRootInputs, PanicWitnessId,
};
use super::contract_index::EffectivePanicContract;
use super::contract_index::EffectivePanicContractOrigin;
use super::contracts::{PanicContractFact, PanicRequirement};
use super::model::PanicEvidenceOrdering;
use super::rules::panic_domain;
use crate::analysis::facts::encoded::TableKind;
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationInput, EvaluationOutput, EvaluationRule, RuleDescriptor, RuleError,
};
use crate::analysis::facts::evidence::{
    EvidenceSemanticEdgeOrder, EvidenceSemanticOrder, EvidenceSemanticSourceOrder,
    EvidenceSemanticStepOrder, EvidenceUseRecord, register_derived_once,
};
use crate::analysis::facts::human::EvidenceClaimSelector;
use crate::analysis::facts::human::markers::MarkerClaimEntity;
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::program::SourceAnchorEntity;
use crate::analysis::facts::program::root_traversal::{
    CallTargetSelection, ProgramCallResolution, ReconciledCallTargetAuthority,
    ResolvedCallableResolution,
};
use crate::analysis::facts::program::topology::{
    CallKind, CallOccurrenceEntity, CallSiteEntity, CallableEntity, CallableKey,
};
use crate::analysis::facts::program::workspace_index::CallableResolutionKind;
use crate::analysis::facts::schema::PassId;
use crate::analysis::facts::workspace::ScopedRowRef;

const EMIT_PANIC_CALL_INPUTS_RULE: &str = "sniff-test.panic.emit-call-inputs";

pub(crate) struct PanicCallInputPack;

impl AnalysisPack<PanicRootInputs> for PanicCallInputPack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<PanicRootInputs>,
    ) -> Result<(), PackRegistrationError> {
        registry.register_derived::<PanicCallObligation>()?;
        register_derived_once::<PanicEvidenceOrdering, PanicRootInputs>(registry)?;
        registry.register_derived::<PanicCallEvidenceMatch>()?;
        register_derived_once::<EvidenceUseRecord, PanicRootInputs>(registry)?;
        registry.register_issue::<UnsatisfiedPanicCallIssue>()?;
        registry.register_issue::<DuplicatePanicCallRequirementIssue>()?;
        registry.register_evaluation_rule(EmitPanicCallInputs)?;
        registry.register_evaluation_rule(MatchPanicCallEvidence)?;
        registry.register_evaluation_rule(ReportUnsatisfiedPanicCalls)?;
        registry.register_evaluation_rule(ReportDuplicatePanicCallRequirements)
    }
}

struct EmitPanicCallInputs;

impl EvaluationRule<PanicRootInputs> for EmitPanicCallInputs {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new(EMIT_PANIC_CALL_INPUTS_RULE).unwrap())
            .read::<CallOccurrenceEntity>()
            .read::<CallSiteEntity>()
            .read::<CallableEntity>()
            .read::<SourceAnchorEntity>()
            .read::<MarkerClaimEntity>()
            .read::<PanicContractFact>()
            .read::<PanicRequirement>()
            .write_derived::<PanicCallObligation>()
            .write_derived::<PanicEvidenceOrdering>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, PanicRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        validate_context(cx, input)?;
        if cx.root().domain != panic_domain() {
            return Ok(());
        }
        let batch = validate_batch(cx.services(), input, output)?;
        for call in &batch.obligations {
            output.emit_derived(call)?;
        }
        for ordering in &batch.orderings {
            output.emit_derived(ordering)?;
        }
        Ok(())
    }
}

pub(super) fn validate_context(
    cx: &EvaluationCx<'_, PanicRootInputs>,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    if !input.has_workspace_identity(cx.services().workspace_identity()) {
        return Err(RuleError::failed(
            "panic-call inputs belong to a replacement workspace fact view",
        ));
    }
    if cx.services().root() != cx.root() {
        return Err(RuleError::failed(
            "panic-call inputs belong to a different evaluation root",
        ));
    }
    Ok(())
}

pub(super) struct ValidatedBatch {
    obligations: Vec<PanicCallObligation>,
    orderings: Vec<PanicEvidenceOrdering>,
}

pub(super) fn validate_batch(
    services: &PanicRootInputs,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<ValidatedBatch, RuleError> {
    let obligations = validate_obligations(services, input, output)?;
    let orderings = validate_orderings(services, &obligations)?;
    Ok(ValidatedBatch {
        obligations,
        orderings,
    })
}

impl ValidatedBatch {
    pub(super) fn obligations(&self) -> &[PanicCallObligation] {
        &self.obligations
    }

    pub(super) fn orderings(&self) -> &[PanicEvidenceOrdering] {
        &self.orderings
    }
}

fn validate_obligations(
    services: &PanicRootInputs,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<Vec<PanicCallObligation>, RuleError> {
    services
        .validate_retained_call_invariants()
        .map_err(|error| RuleError::failed(error.to_string()))?;
    let call_count = services.call_count();
    let call_ranks = validate_evidence_order(services)?;
    let callable_resolutions = index_callable_resolutions(services)?;

    let mut batch = Vec::with_capacity(call_count);
    let mut callable_keys = BTreeMap::new();
    for (expected_id, call) in services.calls().enumerate() {
        let call = call.map_err(|error| RuleError::failed(error.to_string()))?;
        if call.id().index() != expected_id {
            return Err(RuleError::failed(format!(
                "panic call ID {} is not dense at position {expected_id}",
                call.id().index()
            )));
        }
        let (rank, ranked_order) = call_ranks.get(&expected_id).copied().ok_or_else(|| {
            RuleError::failed(format!("panic call {expected_id} has no evidence rank"))
        })?;
        if call.order() != ranked_order {
            return Err(invalid_call(
                expected_id,
                "traversal order disagrees with its evidence-order entry",
            ));
        }
        batch.push(project_call(
            call,
            rank,
            services.root(),
            &callable_resolutions,
            &mut callable_keys,
            input,
            output,
        )?);
    }
    if batch.len() != call_count {
        return Err(RuleError::failed(
            "panic call iterator length disagrees with its declared count",
        ));
    }
    Ok(batch)
}

fn validate_orderings(
    services: &PanicRootInputs,
    obligations: &[PanicCallObligation],
) -> Result<Vec<PanicEvidenceOrdering>, RuleError> {
    let projector = PanicCallTraceProjector::prepare(services)
        .map_err(|error| RuleError::failed(error.to_string()))?;
    let mut orderings = Vec::with_capacity(obligations.len());
    for obligation in obligations {
        let projected = projector
            .project(obligation.call_id())
            .map_err(|error| RuleError::failed(error.to_string()))?;
        validate_projected_identity(obligation, &projected)?;
        let semantic_order =
            semantic_order_for_call_trace(&projected, obligation.traversal_order())?;
        orderings.push(PanicEvidenceOrdering::new(
            obligation.source().clone(),
            obligation.endpoint().clone(),
            obligation.trace_target().clone(),
            obligation.trace().clone(),
            obligation.call_id(),
            semantic_order,
        ));
    }
    Ok(orderings)
}

fn validate_projected_identity(
    obligation: &PanicCallObligation,
    projected: &PanicCallSemanticTrace,
) -> Result<(), RuleError> {
    validate_presentation_function_identity(obligation, projected)?;
    let terminal_call_id = u64::try_from(projected.terminal().call_id().index())
        .map_err(|_| RuleError::failed("panic-call semantic terminal ID exceeds u64"))?;
    if projected.source() != obligation.source()
        || &projected.endpoint().erase() != obligation.endpoint()
        || projected.endpoint_data() != obligation.occurrence_data()
        || projected.trace_target() != obligation.trace_target()
        || projected.relation_trace() != obligation.trace()
        || projected.witness_order() != obligation.call_id()
        || terminal_call_id != obligation.call_id()
        || projected.terminal().traversal_order() != obligation.traversal_order()
        || projected.terminal().effective_kind() != obligation.effective_kind()
    {
        return Err(RuleError::failed(format!(
            "panic call input {} semantic ordering projection changed its witness identity",
            obligation.call_id()
        )));
    }
    Ok(())
}

fn validate_presentation_function_identity(
    obligation: &PanicCallObligation,
    projected: &PanicCallSemanticTrace,
) -> Result<(), RuleError> {
    let presentation = obligation.presentation_function();
    let matches = if let Some(callable) = projected.terminal().presentation_callable() {
        presentation.endpoint() == &callable.selection().callable().erase()
            && presentation.function() == callable.data().key()
    } else {
        projected.steps().last().is_some_and(|terminal| {
            matches!(
                terminal.kind(),
                PanicCallSemanticTraceStepKind::TerminalCall
            ) && presentation.endpoint() == &terminal.owner().body().erase()
                && presentation.scope() == terminal.owner().body().scope()
                && presentation.function() == terminal.owner().data().key()
        })
    };
    if matches {
        Ok(())
    } else {
        Err(RuleError::failed(format!(
            "panic call input {} presentation function changed its endpoint, semantic scope, or requested key",
            obligation.call_id()
        )))
    }
}

fn semantic_order_for_call_trace(
    trace: &PanicCallSemanticTrace,
    traversal_order: u64,
) -> Result<EvidenceSemanticOrder, RuleError> {
    let steps = trace
        .steps()
        .iter()
        .map(|step| {
            let caller = semantic_call_node_label(step.caller());
            let target = Some(semantic_call_node_label(step.target()));
            let kind = match step.edge() {
                PanicCallSemanticEdge::MacroExpansion => {
                    EvidenceSemanticEdgeOrder::Reachability(CallKind::MacroExpansion)
                }
                PanicCallSemanticEdge::Call(kind) => EvidenceSemanticEdgeOrder::Reachability(kind),
            };
            let source = step.source_key().map(|source| {
                EvidenceSemanticSourceOrder::new(source.byte_start(), source.byte_end())
            });
            EvidenceSemanticStepOrder::new(caller, kind, target, source)
        })
        .collect();
    let order = EvidenceSemanticOrder::new(steps, traversal_order);
    order.validate().map_err(RuleError::failed)?;
    Ok(order)
}

impl PanicCallSemanticTrace {
    pub(crate) fn evidence_order_for_report(
        &self,
        traversal_order: u64,
    ) -> Result<EvidenceSemanticOrder, RuleError> {
        semantic_order_for_call_trace(self, traversal_order)
    }
}

fn semantic_call_node_label(node: &PanicCallTraceNode) -> String {
    match node {
        PanicCallTraceNode::Macro { data, .. } => format!("macro {}", data.display_path()),
        PanicCallTraceNode::Function { data, .. } => data.display_path().to_owned(),
        PanicCallTraceNode::Callable(target) => target.data().display_path().to_owned(),
        PanicCallTraceNode::Description(description) => description.clone(),
    }
}

fn validate_evidence_order(
    services: &PanicRootInputs,
) -> Result<BTreeMap<usize, (usize, u64)>, RuleError> {
    let call_count = services.call_count();
    let assertion_count = services.compiler_asserts().assertions().len();
    let expected_witness_count = call_count
        .checked_add(assertion_count)
        .ok_or_else(|| RuleError::failed("panic witness count overflow"))?;
    if services.evidence_order().len() != expected_witness_count {
        return Err(RuleError::failed(
            "panic evidence order does not cover every retained witness",
        ));
    }
    let effect_visits = index_effect_visits(services)?;
    let mut call_ranks = BTreeMap::new();
    let mut assertion_ids = BTreeSet::new();
    let mut traversal_orders = BTreeSet::new();
    let mut previous_traversal_order = None;
    for (index, ranked) in services.evidence_order().iter().enumerate() {
        if ranked.rank().index() != index {
            return Err(RuleError::failed("panic evidence ranks are not dense"));
        }
        if !traversal_orders.insert(ranked.traversal_order()) {
            return Err(RuleError::failed(
                "panic evidence order repeats a traversal order",
            ));
        }
        if previous_traversal_order.is_some_and(|previous| previous >= ranked.traversal_order()) {
            return Err(RuleError::failed(
                "panic evidence order is not strictly traversal ordered",
            ));
        }
        previous_traversal_order = Some(ranked.traversal_order());
        match ranked.witness() {
            PanicWitnessId::CompilerAssert(id) => validate_assertion_witness(
                services,
                id,
                ranked.traversal_order(),
                assertion_count,
                &effect_visits,
                &mut assertion_ids,
            )?,
            PanicWitnessId::Call(id) => {
                if id.index() >= call_count
                    || call_ranks
                        .insert(id.index(), (index, ranked.traversal_order()))
                        .is_some()
                {
                    return Err(RuleError::failed(
                        "panic evidence order has an invalid call witness",
                    ));
                }
            }
        }
    }
    if call_ranks.len() != call_count || assertion_ids.len() != assertion_count {
        return Err(RuleError::failed(
            "panic evidence order is not a witness bijection",
        ));
    }
    Ok(call_ranks)
}

fn index_effect_visits(
    services: &PanicRootInputs,
) -> Result<
    BTreeMap<u64, &crate::analysis::facts::program::root_traversal::ResolvedEffectVisit>,
    RuleError,
> {
    let mut effect_visits = BTreeMap::new();
    for visit in services.traversal().effect_visits() {
        if effect_visits.insert(visit.order(), visit).is_some() {
            return Err(RuleError::failed(
                "resolved traversal repeats an effect-visit order",
            ));
        }
    }
    Ok(effect_visits)
}

fn validate_assertion_witness(
    services: &PanicRootInputs,
    id: super::compiler_assert_inputs::CompilerAssertInputId,
    traversal_order: u64,
    assertion_count: usize,
    effect_visits: &BTreeMap<
        u64,
        &crate::analysis::facts::program::root_traversal::ResolvedEffectVisit,
    >,
    assertion_ids: &mut BTreeSet<usize>,
) -> Result<(), RuleError> {
    if id.index() >= assertion_count || !assertion_ids.insert(id.index()) {
        return Err(RuleError::failed(
            "panic evidence order has an invalid compiler-assert witness",
        ));
    }
    let assertion = services
        .compiler_asserts()
        .assertions()
        .get(id.index())
        .ok_or_else(|| {
            RuleError::failed("panic evidence order references a missing compiler assertion")
        })?;
    if assertion.id() != id || assertion.visit_order() != traversal_order {
        return Err(RuleError::failed(
            "panic evidence order disagrees with its compiler-assert visit",
        ));
    }
    let visit = effect_visits.get(&assertion.visit_order()).ok_or_else(|| {
        RuleError::failed("compiler-assert witness has no exact resolved effect visit")
    })?;
    if visit.effect() != assertion.owner() || visit.trace() != assertion.trace() {
        return Err(RuleError::failed(
            "compiler-assert witness disagrees with its resolved effect visit",
        ));
    }
    Ok(())
}

fn index_callable_resolutions(
    services: &PanicRootInputs,
) -> Result<BTreeMap<CallableResolutionKey, &ResolvedCallableResolution>, RuleError> {
    let mut resolutions = BTreeMap::new();
    for resolution in services.traversal().callable_resolutions() {
        if resolutions
            .insert(callable_resolution_key(resolution), resolution)
            .is_some()
        {
            return Err(RuleError::failed(
                "resolved callable evidence repeats an exact resolution identity",
            ));
        }
    }
    Ok(resolutions)
}

fn project_call(
    call: super::compiler_assert_inputs::PanicCallInputView<'_>,
    rank: usize,
    root: &crate::analysis::facts::evaluation::EvaluationRoot,
    callable_resolutions: &BTreeMap<CallableResolutionKey, &ResolvedCallableResolution>,
    callable_keys: &mut BTreeMap<
        crate::analysis::facts::workspace::ScopedEntityRef,
        crate::analysis::facts::program::FunctionKey,
    >,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<PanicCallObligation, RuleError> {
    let (occurrence, evidence_group, metadata_target) =
        project_call_identity(&call, root, input, output)?;
    let resolution = project_resolution(&call, callable_resolutions, input, output)?;
    let declaration_key = if let Some(contract) = call.contract() {
        let reference = contract.declaration_owner().erase();
        Some(cached_callable_key(&reference, callable_keys, input)?)
    } else {
        None
    };
    let contract = project_contract(
        &call,
        declaration_key.as_ref(),
        callable_keys,
        input,
        output,
    )?;
    let requirements = call
        .requirements()
        .map(|requirement| {
            project_requirement(
                requirement.value(),
                call.contract(),
                declaration_key.as_ref(),
                input,
                output,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_requirements(call.id().index(), &requirements)?;
    let active_markers = project_markers(&call, input, output)?;

    Ok(PanicCallObligation {
        call_id: u64::try_from(call.id().index())
            .map_err(|_| RuleError::failed("panic call ID exceeds u64"))?,
        evidence_rank: u64::try_from(rank)
            .map_err(|_| RuleError::failed("panic evidence rank exceeds u64"))?,
        traversal_order: call.order(),
        source: call.source(),
        occurrence,
        occurrence_data: call.occurrence_data().clone(),
        endpoint: call.endpoint(),
        presentation_function: call.presentation_function().clone(),
        evidence_group,
        evidence_group_data: call.evidence_group_data().clone(),
        trace_target: call.trace_target().clone(),
        trace: call.trace().clone(),
        effective_kind: call.effective_kind(),
        resolution,
        boundary: project_boundary(&call)?,
        metadata_target,
        contract,
        requirements,
        active_markers,
    })
}

fn project_call_identity(
    call: &super::compiler_assert_inputs::PanicCallInputView<'_>,
    root: &crate::analysis::facts::evaluation::EvaluationRoot,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<
    (
        crate::analysis::facts::workspace::ScopedEntityRef,
        crate::analysis::facts::workspace::ScopedEntityRef,
        Option<PanicCallMetadataTarget>,
    ),
    RuleError,
> {
    let occurrence = call.occurrence().erase();
    let persisted_occurrence = input.artifact_entity_at::<CallOccurrenceEntity>(&occurrence)?;
    if &persisted_occurrence != call.occurrence_data() {
        return Err(invalid_call(
            call.id().index(),
            "occurrence data was altered",
        ));
    }
    let evidence_group = call.evidence_group().erase();
    let persisted_group = input.artifact_entity_at::<CallSiteEntity>(&evidence_group)?;
    if &persisted_group != call.evidence_group_data() {
        return Err(invalid_call(
            call.id().index(),
            "evidence-group data was altered",
        ));
    }
    if call.source() != occurrence.as_row() || call.endpoint() != occurrence {
        return Err(invalid_call(
            call.id().index(),
            "source or endpoint disagrees with its occurrence",
        ));
    }
    if call.trace().root() != &root.entity {
        return Err(invalid_call(call.id().index(), "invalid call trace root"));
    }
    if call.trace().target() != call.trace_target() {
        return Err(invalid_call(
            call.id().index(),
            "trace target disagrees with its relation trace",
        ));
    }
    output.validate_entity_reference(&occurrence)?;
    output.validate_entity_reference(&evidence_group)?;
    output.validate_entity_reference(call.trace_target())?;
    output.validate_relation_trace(call.trace())?;

    let metadata_target = project_metadata_pair(
        call.id().index(),
        call.metadata_target(),
        call.metadata_target_data(),
        input,
    )?;
    let expected_trace_target = call
        .metadata_target()
        .map_or_else(|| occurrence.clone(), |target| target.callable().erase());
    if call.trace_target() != &expected_trace_target {
        return Err(invalid_call(
            call.id().index(),
            "trace target disagrees with metadata target or occurrence fallback",
        ));
    }
    Ok((occurrence, evidence_group, metadata_target))
}

fn project_markers(
    call: &super::compiler_assert_inputs::PanicCallInputView<'_>,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<Vec<PanicCallMarker>, RuleError> {
    let mut marker_claims = BTreeSet::new();
    let mut previous_marker = None;
    call.markers()
        .iter()
        .map(|marker| {
            let claim = marker.claim().erase();
            let persisted = input.artifact_entity_at::<MarkerClaimEntity>(&claim)?;
            if &persisted != marker.data() {
                return Err(invalid_call(call.id().index(), "marker data was altered"));
            }
            if marker.data().key().domain() != &panic_domain()
                || marker.data().rationale().trim().is_empty()
            {
                return Err(invalid_call(
                    call.id().index(),
                    "active marker is not nonblank panic evidence",
                ));
            }
            validate_marker_selector(call.id().index(), marker.data().selector())?;
            if !marker_claims.insert(claim.clone()) {
                return Err(invalid_call(
                    call.id().index(),
                    "active marker set repeats a claim",
                ));
            }
            if previous_marker
                .as_ref()
                .is_some_and(|previous| previous >= &claim)
            {
                return Err(invalid_call(
                    call.id().index(),
                    "active markers are not in canonical claim order",
                ));
            }
            previous_marker = Some(claim.clone());
            if marker.trace().root() != call.trace().root() || marker.trace().target() != &claim {
                return Err(invalid_call(
                    call.id().index(),
                    "marker activation trace is malformed",
                ));
            }
            output.validate_relation_trace(marker.trace())?;
            Ok(PanicCallMarker {
                claim,
                data: marker.data().clone(),
                trace: marker.trace().clone(),
            })
        })
        .collect()
}

type CallableResolutionKey = (
    crate::analysis::facts::workspace::ScopedEntityRef,
    crate::analysis::facts::workspace::ScopedEntityRef,
    CallableKey,
    CallableResolutionKind,
    crate::analysis::facts::workspace::ScopedEntityRef,
    u64,
);

fn callable_resolution_key(resolution: &ResolvedCallableResolution) -> CallableResolutionKey {
    (
        resolution.invocation().erase(),
        resolution.evidence().erase(),
        resolution.key(),
        resolution.kind(),
        resolution.callable().erase(),
        resolution.order(),
    )
}

fn project_resolution(
    call: &super::compiler_assert_inputs::PanicCallInputView<'_>,
    resolutions: &BTreeMap<CallableResolutionKey, &ResolvedCallableResolution>,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<PanicCallResolution, RuleError> {
    let ProgramCallResolution::CallableEvidence {
        evidence,
        key,
        kind,
    } = call.resolution()
    else {
        if call.effective_kind() != call.occurrence_data().kind() {
            return Err(invalid_call(
                call.id().index(),
                "persisted effective kind disagrees with its occurrence",
            ));
        }
        return Ok(PanicCallResolution::Persisted);
    };
    let (Some(target), Some(target_data)) = (call.metadata_target(), call.metadata_target_data())
    else {
        return Err(invalid_call(
            call.id().index(),
            "callable evidence has no exact metadata target",
        ));
    };
    if target.role() != crate::analysis::facts::program::topology::CallTargetRole::Runtime
        || target.authority() != ReconciledCallTargetAuthority::ConsumerRaw
    {
        return Err(invalid_call(
            call.id().index(),
            "callable evidence does not use its exact synthetic runtime target authority",
        ));
    }
    let lookup = (
        call.occurrence().erase(),
        evidence.erase(),
        *key,
        *kind,
        target.callable().erase(),
        call.order().checked_sub(1).ok_or_else(|| {
            invalid_call(
                call.id().index(),
                "callable-evidence boundary has no preceding resolution step",
            )
        })?,
    );
    let resolved = resolutions.get(&lookup).copied().ok_or_else(|| {
        invalid_call(
            call.id().index(),
            "callable-evidence identity is not in the resolved traversal",
        )
    })?;
    if resolved.invocation_data() != call.occurrence_data()
        || resolved.callable_data() != target_data
    {
        return Err(invalid_call(
            call.id().index(),
            "callable-evidence data disagrees with the call boundary",
        ));
    }
    let persisted_evidence =
        input.artifact_entity_at::<CallOccurrenceEntity>(&resolved.evidence().erase())?;
    if &persisted_evidence != resolved.evidence_data() {
        return Err(invalid_call(
            call.id().index(),
            "callable-evidence occurrence data was altered",
        ));
    }
    validate_callable_resolution_semantics(call, resolved, evidence, key, *kind, target, output)?;
    Ok(PanicCallResolution::CallableEvidence {
        evidence: evidence.erase(),
        key: *key,
        resolution_kind: (*kind).into(),
    })
}

fn validate_callable_resolution_semantics(
    call: &super::compiler_assert_inputs::PanicCallInputView<'_>,
    resolved: &ResolvedCallableResolution,
    evidence: &crate::analysis::facts::workspace::ScopedEntityId<CallOccurrenceEntity>,
    key: &CallableKey,
    kind: CallableResolutionKind,
    target: &CallTargetSelection,
    output: &EvaluationOutput<'_>,
) -> Result<(), RuleError> {
    let expected_kind = match kind {
        CallableResolutionKind::FunctionPointerEvidence => CallKind::FnPointerCallTarget,
        CallableResolutionKind::DynamicDispatchEvidence => CallKind::DynDispatchVTableEntry,
    };
    let compatible_evidence = matches!(
        (kind, key, resolved.evidence_data().kind()),
        (
            CallableResolutionKind::FunctionPointerEvidence,
            CallableKey::FnPointer(_),
            CallKind::FnPointerReify | CallKind::ClosureFnPointerReify,
        ) | (
            CallableResolutionKind::DynamicDispatchEvidence,
            CallableKey::DynDispatch(_),
            CallKind::VTableEntry,
        )
    );
    if !compatible_evidence {
        return Err(invalid_call(
            call.id().index(),
            "callable-evidence kind, key, and occurrence are incompatible",
        ));
    }
    if call.effective_kind() != expected_kind {
        return Err(invalid_call(
            call.id().index(),
            "callable-evidence kind disagrees with the effective call kind",
        ));
    }
    if resolved.resolution_trace() != call.trace()
        || resolved.resolution_trace().target() != &target.callable().erase()
        || resolved.evidence_trace().root() != call.trace().root()
        || resolved.evidence_trace().target() != &evidence.erase()
    {
        return Err(invalid_call(
            call.id().index(),
            "callable-evidence traces disagree with the selected route",
        ));
    }
    output.validate_relation_trace(resolved.resolution_trace())?;
    output.validate_relation_trace(resolved.evidence_trace())?;
    Ok(())
}

fn project_boundary(
    call: &super::compiler_assert_inputs::PanicCallInputView<'_>,
) -> Result<PanicCallBoundaryKind, RuleError> {
    Ok(match call.kind() {
        PanicCallInputKind::Documented { trusted } => PanicCallBoundaryKind::Documented { trusted },
        PanicCallInputKind::PanicSink => PanicCallBoundaryKind::PanicSink,
        PanicCallInputKind::Opaque { kind } => PanicCallBoundaryKind::Opaque {
            opaque_kind: match kind {
                PanicOpaqueBoundaryKind::BodylessDeclaration => {
                    PanicCallOpaqueKind::BodylessDeclaration
                }
                PanicOpaqueBoundaryKind::ExplicitOpaque => PanicCallOpaqueKind::ExplicitOpaque,
            },
            description: call
                .opaque_description()
                .ok_or_else(|| invalid_call(call.id().index(), "opaque description is missing"))?
                .to_owned(),
        },
    })
}

fn project_metadata_target(
    selection: &CallTargetSelection,
    data: &CallableEntity,
    input: &EvaluationInput<'_>,
) -> Result<PanicCallMetadataTarget, RuleError> {
    let callable = selection.callable().erase();
    let persisted = input.artifact_entity_at::<CallableEntity>(&callable)?;
    if &persisted != data {
        return Err(RuleError::failed("panic metadata-target data was altered"));
    }
    Ok(PanicCallMetadataTarget {
        selection: project_target(selection),
        data: data.clone(),
    })
}

fn project_metadata_pair(
    call_id: usize,
    selection: Option<&CallTargetSelection>,
    data: Option<&CallableEntity>,
    input: &EvaluationInput<'_>,
) -> Result<Option<PanicCallMetadataTarget>, RuleError> {
    validate_metadata_pair_presence(call_id, selection.is_some(), data.is_some())?;
    match (selection, data) {
        (Some(selection), Some(data)) => project_metadata_target(selection, data, input).map(Some),
        (None, None) => Ok(None),
        _ => Err(invalid_call(
            call_id,
            "metadata target identity and data have different presence",
        )),
    }
}

fn validate_metadata_pair_presence(
    call_id: usize,
    has_selection: bool,
    has_data: bool,
) -> Result<(), RuleError> {
    if has_selection == has_data {
        Ok(())
    } else {
        Err(invalid_call(
            call_id,
            "metadata target identity and data have different presence",
        ))
    }
}

fn project_contract(
    call: &super::compiler_assert_inputs::PanicCallInputView<'_>,
    declaration_key: Option<&crate::analysis::facts::program::FunctionKey>,
    callable_keys: &mut BTreeMap<
        crate::analysis::facts::workspace::ScopedEntityRef,
        crate::analysis::facts::program::FunctionKey,
    >,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<Option<PanicCallContractProvenance>, RuleError> {
    let Some(contract) = call.contract() else {
        if matches!(call.kind(), PanicCallInputKind::Documented { .. }) {
            return Err(invalid_call(
                call.id().index(),
                "documented boundary has no effective contract",
            ));
        }
        if call.contract_target().is_some() {
            return Err(invalid_call(
                call.id().index(),
                "contract target exists without an effective contract",
            ));
        }
        return Ok(None);
    };
    if !matches!(call.kind(), PanicCallInputKind::Documented { .. }) {
        return Err(invalid_call(
            call.id().index(),
            "non-documented boundary carries an effective contract",
        ));
    }
    let target = call.contract_target().ok_or_else(|| {
        invalid_call(
            call.id().index(),
            "effective contract has no selected target",
        )
    })?;
    if contract.queried_callable() != target.callable() {
        return Err(invalid_call(
            call.id().index(),
            "effective contract queried callable disagrees with target",
        ));
    }
    let queried_reference = contract.queried_callable().erase();
    let queried_key = cached_callable_key(&queried_reference, callable_keys, input)?;
    let declaration_key = declaration_key.ok_or_else(|| {
        invalid_call(
            call.id().index(),
            "effective contract has no validated declaration owner",
        )
    })?;
    validate_contract_origin(call.id().index(), contract, &queried_key, declaration_key)?;
    if let Some(raw) = contract.raw_contract() {
        validate_raw_contract(call.id().index(), contract, raw, input, output)?;
    }
    let source_anchor = contract
        .source_anchor()
        .map(|anchor| project_anchor(anchor.id(), anchor.reference(), anchor.data(), input))
        .transpose()?;
    Ok(Some(PanicCallContractProvenance {
        target: project_target(target),
        queried_callable: contract.queried_callable().erase(),
        declaration_owner: contract.declaration_owner().erase(),
        raw_contract: contract.raw_contract().cloned(),
        origin: match contract.origin() {
            EffectivePanicContractOrigin::Override => PanicCallContractOrigin::Override,
            EffectivePanicContractOrigin::RawExact => PanicCallContractOrigin::RawExact,
            EffectivePanicContractOrigin::RawGeneric => PanicCallContractOrigin::RawGeneric,
        },
        source_anchor,
    }))
}

fn validate_raw_contract(
    call_id: usize,
    contract: &EffectivePanicContract,
    raw: &ScopedRowRef,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<(), RuleError> {
    let persisted = input.artifact_fact_at::<PanicContractFact>(raw)?;
    if raw.scope() != contract.declaration_owner().scope()
        || persisted.metadata.owner.as_ref() != Some(&contract.declaration_owner().entity().erase())
    {
        return Err(invalid_call(
            call_id,
            "raw contract owner disagrees with effective provenance",
        ));
    }
    let expected_anchor = contract
        .source_anchor()
        .map(|anchor| {
            if anchor.reference().scope() != raw.scope() {
                return Err(invalid_call(
                    call_id,
                    "raw contract anchor crosses artifact scopes",
                ));
            }
            Ok(anchor.reference().entity().clone())
        })
        .transpose()?;
    if persisted.metadata.anchor != expected_anchor {
        return Err(invalid_call(
            call_id,
            "raw contract anchor disagrees with effective provenance",
        ));
    }
    let mut requirement_refs = BTreeSet::new();
    let expected_requirements = contract
        .requirements()
        .iter()
        .map(|requirement| {
            let reference = requirement.raw_requirement().ok_or_else(|| {
                invalid_call(call_id, "raw contract requirement lost its permanent row")
            })?;
            if reference.scope() != raw.scope() || !requirement_refs.insert(reference.clone()) {
                return Err(invalid_call(
                    call_id,
                    "raw contract requirement references are malformed",
                ));
            }
            Ok(reference.clone())
        })
        .collect::<Result<BTreeSet<_>, RuleError>>()?;
    let persisted_requirements = persisted
        .metadata
        .requirements
        .iter()
        .cloned()
        .map(|reference| ScopedRowRef::new(raw.scope().clone(), reference))
        .collect::<BTreeSet<_>>();
    if persisted.metadata.requirements.len() != persisted_requirements.len()
        || persisted_requirements != expected_requirements
    {
        return Err(invalid_call(
            call_id,
            "raw contract requirements disagree with effective provenance",
        ));
    }
    output.validate_row_reference(raw, Some(TableKind::Fact))?;
    Ok(())
}

fn cached_callable_key(
    reference: &crate::analysis::facts::workspace::ScopedEntityRef,
    callable_keys: &mut BTreeMap<
        crate::analysis::facts::workspace::ScopedEntityRef,
        crate::analysis::facts::program::FunctionKey,
    >,
    input: &EvaluationInput<'_>,
) -> Result<crate::analysis::facts::program::FunctionKey, RuleError> {
    if let Some(key) = callable_keys.get(reference).copied() {
        return Ok(key);
    }
    let callable = input.artifact_entity_at::<CallableEntity>(reference)?;
    let key = *callable.key();
    callable_keys.insert(reference.clone(), key);
    Ok(key)
}

fn project_requirement(
    value: Option<&super::contract_index::EffectivePanicRequirement>,
    contract: Option<&std::sync::Arc<EffectivePanicContract>>,
    declaration_key: Option<&crate::analysis::facts::program::FunctionKey>,
    input: &EvaluationInput<'_>,
    output: &EvaluationOutput<'_>,
) -> Result<PanicCallRequirementValue, RuleError> {
    let Some(value) = value else {
        return Ok(PanicCallRequirementValue::unnamed());
    };
    if let Some(raw) = value.raw_requirement() {
        let contract = contract.ok_or_else(|| {
            RuleError::failed("named panic requirement exists without an effective contract")
        })?;
        let declaration_key = declaration_key.ok_or_else(|| {
            RuleError::failed("named raw requirement has no validated declaration owner")
        })?;
        let persisted = input.artifact_requirement_at::<PanicRequirement>(raw)?;
        let expected_anchor = value
            .source_anchor()
            .map(|anchor| {
                if anchor.reference().scope() != raw.scope() {
                    return Err(RuleError::failed(
                        "raw panic requirement anchor crosses artifact scopes",
                    ));
                }
                Ok(anchor.data().anchor())
            })
            .transpose()?;
        if raw.scope() != contract.declaration_owner().scope()
            || persisted.owner() != declaration_key
            || persisted.ordinal() != value.ordinal()
            || persisted.name() != value.name()
            || persisted.normalized_name() != value.normalized_name()
            || persisted.condition() != value.condition()
            || persisted.source_anchor() != expected_anchor
        {
            return Err(RuleError::failed(
                "raw panic requirement disagrees with effective requirement value",
            ));
        }
        output.validate_row_reference(raw, Some(TableKind::Requirement))?;
    }
    let source_anchor = value
        .source_anchor()
        .map(|anchor| project_anchor(anchor.id(), anchor.reference(), anchor.data(), input))
        .transpose()?;
    Ok(PanicCallRequirementValue::named(
        value.ordinal(),
        value.name(),
        value.normalized_name(),
        value.condition(),
        value.raw_requirement().cloned(),
        source_anchor,
    ))
}

fn project_anchor(
    id: &crate::analysis::facts::workspace::ScopedEntityId<SourceAnchorEntity>,
    reference: &crate::analysis::facts::workspace::ScopedEntityRef,
    data: &SourceAnchorEntity,
    input: &EvaluationInput<'_>,
) -> Result<PanicCallAnchorProvenance, RuleError> {
    if &id.erase() != reference {
        return Err(RuleError::failed(
            "panic source-anchor identity disagrees with its reference",
        ));
    }
    let persisted = input.artifact_entity_at::<SourceAnchorEntity>(reference)?;
    if &persisted != data {
        return Err(RuleError::failed("panic source-anchor data was altered"));
    }
    Ok(PanicCallAnchorProvenance {
        reference: reference.clone(),
        data: data.clone(),
    })
}

fn validate_contract_origin(
    call_id: usize,
    contract: &EffectivePanicContract,
    queried_key: &crate::analysis::facts::program::FunctionKey,
    declaration_key: &crate::analysis::facts::program::FunctionKey,
) -> Result<(), RuleError> {
    match contract.origin() {
        EffectivePanicContractOrigin::Override => {
            if contract.raw_contract().is_some()
                || contract.source_anchor().is_some()
                || contract.declaration_owner() != contract.queried_callable()
                || contract.requirements().iter().any(|requirement| {
                    requirement.raw_requirement().is_some() || requirement.source_anchor().is_some()
                })
            {
                return Err(invalid_call(
                    call_id,
                    "override contract contains fabricated raw provenance",
                ));
            }
        }
        EffectivePanicContractOrigin::RawExact => {
            if contract.raw_contract().is_none()
                || contract.declaration_owner() != contract.queried_callable()
            {
                return Err(invalid_call(
                    call_id,
                    "raw-exact contract provenance is malformed",
                ));
            }
        }
        EffectivePanicContractOrigin::RawGeneric => {
            if contract.raw_contract().is_none()
                || contract.declaration_owner() == contract.queried_callable()
                || queried_key.instance().is_none()
                || declaration_key.instance().is_some()
                || queried_key.definition() != declaration_key.definition()
            {
                return Err(invalid_call(
                    call_id,
                    "raw-generic contract provenance is malformed",
                ));
            }
        }
    }
    Ok(())
}

fn validate_marker_selector(
    call_id: usize,
    selector: &EvidenceClaimSelector,
) -> Result<(), RuleError> {
    match selector {
        EvidenceClaimSelector::Unnamed => Ok(()),
        EvidenceClaimSelector::Named(name) if !name.trim().is_empty() => Ok(()),
        EvidenceClaimSelector::Explicit(references)
            if !references.is_empty()
                && references
                    .iter()
                    .all(|reference| !reference.trim().is_empty())
                && references.iter().collect::<BTreeSet<_>>().len() == references.len() =>
        {
            Ok(())
        }
        EvidenceClaimSelector::Named(_) | EvidenceClaimSelector::Explicit(_) => {
            Err(invalid_call(call_id, "active marker selector is malformed"))
        }
    }
}

fn validate_requirements(
    call_id: usize,
    requirements: &[PanicCallRequirementValue],
) -> Result<(), RuleError> {
    if requirements.is_empty() {
        return Err(invalid_call(call_id, "has no requirement values"));
    }
    if requirements.len() == 1 && requirements[0].ordinal().is_none() {
        return Ok(());
    }
    for (expected, requirement) in requirements.iter().enumerate() {
        let expected = u32::try_from(expected)
            .map_err(|_| invalid_call(call_id, "requirement ordinal exceeds u32"))?;
        if requirement.ordinal() != Some(expected) {
            return Err(invalid_call(
                call_id,
                "named requirement ordinals are not dense",
            ));
        }
    }
    Ok(())
}

fn project_target(selection: &CallTargetSelection) -> PanicCallTarget {
    PanicCallTarget {
        role: selection.role(),
        callable: selection.callable().erase(),
        authority: selection.authority().into(),
    }
}

fn invalid_call(call_id: usize, reason: &str) -> RuleError {
    RuleError::failed(format!("panic call input {call_id} {reason}"))
}

#[cfg(test)]
mod tests {
    use super::super::call_issues::{
        ReportDuplicatePanicCallRequirements, ReportUnsatisfiedPanicCalls,
        reject_call_issue_for_test, reject_duplicate_call_issue_for_test,
    };
    use super::super::call_matching::{
        MatchPanicCallEvidence, expected_matches, reject_call_match_for_test,
    };
    use super::super::call_model::{
        DuplicatePanicCallRequirementIssue, PanicCallBoundaryKind, PanicCallContractOrigin,
        PanicCallEvidenceMatch, PanicCallObligation, PanicCallOpaqueKind,
        PanicCallRequirementMatchId, PanicCallResolution, PanicCallableResolutionKind,
        UnsatisfiedPanicCallIssue,
    };
    use super::super::call_trace::reject_call_presentation_for_test;
    use super::super::compiler_assert_ingress::CompilerAssertInputPack;
    use super::super::compiler_assert_inputs::{
        CompilerAssertRootRequest, PanicRootInputs, PanicWitnessId, PreparedCompilerAssertRootBatch,
    };
    use super::super::compiler_assert_trace::tests::{
        attach_named_call_macros_and_sources,
        insert_configured_call as insert_trace_configured_call,
    };
    use super::super::rules::PanicPack;
    use super::{
        PanicCallInputPack, validate_batch, validate_context, validate_metadata_pair_presence,
    };
    use crate::analysis::cache::RustcArtifactId;
    use crate::analysis::facts::builder::{ArtifactDbBuilder, FactMeta};
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::composition::{
        CompositionRelationBuilder, WorkspaceEvaluationView, WorkspaceRelationGraph,
    };
    use crate::analysis::facts::encoded::TableKind;
    use crate::analysis::facts::evaluation::{
        DomainId, EvaluationCx, EvaluationDb, EvaluationInput, EvaluationOutput, EvaluationRule,
        RuleDescriptor, RuleError,
    };
    use crate::analysis::facts::evidence::{
        AmbiguousEvidenceReuseIssue, EvidenceCoordinatorPack, EvidenceSemanticEdgeOrder,
        EvidenceSemanticOrder, EvidenceUseRecord,
    };
    use crate::analysis::facts::human::markers::{
        CallOccurrenceHasMarkerClaimCandidate, EffectSiteHasMarkerClaimCandidate,
        MarkerClaimEntity, MarkerClaimKey, MarkerOccurrenceEntity, MarkerOccurrenceHasClaim,
        MarkerOccurrenceHasSourceAnchor, MarkerOccurrenceKey,
    };
    use crate::analysis::facts::human::{EvidenceClaimSelector, HumanEvidencePack};
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::panic::contracts::{PanicContractFact, PanicRequirement};
    use crate::analysis::facts::panic::model::{
        InBoundsRequirement, MirAssertFact, MirAssertKind, PanicEvidenceOrdering,
    };
    use crate::analysis::facts::program::root_traversal::MarkerProbe;
    use crate::analysis::facts::program::topology::{
        CallAttributionRole, CallKind, CallOccurrenceEntity, CallOccurrenceHasCallableKey,
        CallOccurrenceHasSourceAnchor, CallOccurrenceInSafetyEffectGroup, CallOccurrenceKey,
        CallOccurrenceTargetsCallable, CallSiteEntity, CallSiteHasOccurrence, CallSiteKey,
        CallSourceAnchorRole, CallTargetRole, CallableEntity, CallableKey, CallableKeyEntity,
        FunctionDefinesCallable, FunctionOwnsCallSite, FunctionOwnsSafetyEffectGroup,
        SafetyEffectGroupEntity, SafetyEffectGroupKey,
    };
    use crate::analysis::facts::program::{
        EffectSiteEntity, EffectSiteKey, FunctionBodyProvenance, FunctionEntity, FunctionKey,
        FunctionOwnsEffectSite, SourceAnchorEntity, SourceAnchorInFile, SourceAnchorKey,
        SourceFileEntity,
    };
    use crate::analysis::facts::schema::{EntityHandle, PassId, RowSchema, SchemaId};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::analysis::facts::workspace::{ArtifactScopeId, WorkspaceFactView};
    use crate::analysis::workspace_closure::{
        ManagedArtifactGeneration, ManagedArtifactManifest, VerifiedWorkspaceClosure,
    };
    use crate::config::PanicConfig;
    use crate::contracts::ContractDocOverrides;
    use crate::namespace::{StableDefPathHash, StableInstanceHash, StableTypeHash};
    use crate::path_patterns::PathPatterns;
    use reachability::MirBodyLocation;

    fn definition(local: u64) -> StableDefPathHash {
        serde_json::from_str(&format!("\"0000000000000001{local:016x}\"")).unwrap()
    }

    fn instance(local: u64) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{local:032x}\"")).unwrap()
    }

    fn type_hash(local: u64) -> StableTypeHash {
        serde_json::from_str(&format!("\"{local:032x}\"")).unwrap()
    }

    fn registry() -> AnalysisRegistry<PanicRootInputs> {
        let mut registry = AnalysisRegistry::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        registry.install(&PanicCallInputPack).unwrap();
        registry
    }

    fn combined_registry() -> AnalysisRegistry<PanicRootInputs> {
        let mut registry = AnalysisRegistry::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        registry.install(&HumanEvidencePack).unwrap();
        registry.install(&PanicPack).unwrap();
        registry.install(&PanicCallInputPack).unwrap();
        registry.install(&CompilerAssertInputPack).unwrap();
        registry.install(&EvidenceCoordinatorPack).unwrap();
        registry
    }

    #[derive(Clone, Copy)]
    enum MatchSeedCorruption {
        MissingObligation,
        DuplicateObligation,
        AlteredObligation,
        MissingOrdering,
        DuplicateOrdering,
        OrphanOrdering,
        AlteredOrdering,
    }

    struct SeedCallMatchInputs(MatchSeedCorruption);

    impl EvaluationRule<PanicRootInputs> for SeedCallMatchInputs {
        fn descriptor(&self) -> RuleDescriptor {
            RuleDescriptor::new(PassId::new("test.panic.seed-call-match-inputs").unwrap())
                .read::<CallOccurrenceEntity>()
                .read::<CallSiteEntity>()
                .read::<CallableEntity>()
                .read::<SourceAnchorEntity>()
                .read::<MarkerClaimEntity>()
                .read::<PanicContractFact>()
                .read::<PanicRequirement>()
                .write_derived::<PanicCallObligation>()
                .write_derived::<PanicEvidenceOrdering>()
        }

        fn evaluate(
            &self,
            cx: &EvaluationCx<'_, PanicRootInputs>,
            input: &EvaluationInput<'_>,
            output: &mut EvaluationOutput<'_>,
        ) -> Result<(), RuleError> {
            validate_context(cx, input)?;
            let batch = validate_batch(cx.services(), input, output)?;
            let mut obligations = batch.obligations().to_vec();
            let mut orderings = batch.orderings().to_vec();
            match self.0 {
                MatchSeedCorruption::MissingObligation => {
                    obligations.pop();
                }
                MatchSeedCorruption::DuplicateObligation => {
                    obligations.push(obligations[0].clone());
                }
                MatchSeedCorruption::AlteredObligation => {
                    obligations[1].evidence_rank = obligations[1]
                        .evidence_rank
                        .checked_add(100)
                        .ok_or_else(|| RuleError::failed("fixture evidence rank overflow"))?;
                }
                MatchSeedCorruption::MissingOrdering => {
                    orderings.pop();
                }
                MatchSeedCorruption::DuplicateOrdering => {
                    orderings.push(orderings[0].clone());
                }
                MatchSeedCorruption::OrphanOrdering => {
                    let first = &orderings[0];
                    orderings.push(PanicEvidenceOrdering::new(
                        first.obligation_source().clone(),
                        first.endpoint().clone(),
                        first.trace_target().clone(),
                        first.trace().clone(),
                        100,
                        first.semantic_order().clone(),
                    ));
                }
                MatchSeedCorruption::AlteredOrdering => {
                    let altered = &orderings[1];
                    orderings[1] = PanicEvidenceOrdering::new(
                        altered.obligation_source().clone(),
                        altered.endpoint().clone(),
                        altered.trace_target().clone(),
                        altered.trace().clone(),
                        altered.witness_order(),
                        EvidenceSemanticOrder::new(
                            altered.semantic_order().steps().to_vec(),
                            altered
                                .semantic_order()
                                .traversal_order()
                                .checked_add(100)
                                .ok_or_else(|| {
                                    RuleError::failed("fixture traversal order overflow")
                                })?,
                        ),
                    );
                }
            }
            for obligation in &obligations {
                output.emit_derived(obligation)?;
            }
            for ordering in &orderings {
                output.emit_derived(ordering)?;
            }
            Ok(())
        }
    }

    fn matching_registry(corruption: MatchSeedCorruption) -> AnalysisRegistry<PanicRootInputs> {
        let mut registry = AnalysisRegistry::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        registry.install(&HumanEvidencePack).unwrap();
        registry.register_derived::<PanicCallObligation>().unwrap();
        registry
            .register_derived::<PanicEvidenceOrdering>()
            .unwrap();
        registry
            .register_derived::<PanicCallEvidenceMatch>()
            .unwrap();
        registry.register_derived::<EvidenceUseRecord>().unwrap();
        registry
            .register_evaluation_rule(SeedCallMatchInputs(corruption))
            .unwrap();
        registry
            .register_evaluation_rule(MatchPanicCallEvidence)
            .unwrap();
        registry
    }

    fn duplicate_issue_registry(
        corruption: MatchSeedCorruption,
    ) -> AnalysisRegistry<PanicRootInputs> {
        let mut registry = AnalysisRegistry::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        registry.install(&HumanEvidencePack).unwrap();
        registry.register_derived::<PanicCallObligation>().unwrap();
        registry
            .register_derived::<PanicEvidenceOrdering>()
            .unwrap();
        registry
            .register_issue::<DuplicatePanicCallRequirementIssue>()
            .unwrap();
        registry
            .register_evaluation_rule(SeedCallMatchInputs(corruption))
            .unwrap();
        registry
            .register_evaluation_rule(ReportDuplicatePanicCallRequirements)
            .unwrap();
        registry
    }

    #[derive(Clone, Copy)]
    enum IssueMatchSeedCorruption {
        Missing,
        Duplicate,
        AlteredRequirements,
        AlteredEnvelope,
        Orphan,
    }

    struct SeedCallIssueInputs(IssueMatchSeedCorruption);

    impl EvaluationRule<PanicRootInputs> for SeedCallIssueInputs {
        fn descriptor(&self) -> RuleDescriptor {
            RuleDescriptor::new(PassId::new("test.panic.seed-call-issue-inputs").unwrap())
                .read::<CallOccurrenceEntity>()
                .read::<CallSiteEntity>()
                .read::<CallableEntity>()
                .read::<SourceAnchorEntity>()
                .read::<MarkerClaimEntity>()
                .read::<PanicContractFact>()
                .read::<PanicRequirement>()
                .write_derived::<PanicCallObligation>()
                .write_derived::<PanicEvidenceOrdering>()
                .write_derived::<PanicCallEvidenceMatch>()
        }

        fn evaluate(
            &self,
            cx: &EvaluationCx<'_, PanicRootInputs>,
            input: &EvaluationInput<'_>,
            output: &mut EvaluationOutput<'_>,
        ) -> Result<(), RuleError> {
            validate_context(cx, input)?;
            let batch = validate_batch(cx.services(), input, output)?;
            let mut matches = expected_matches(&batch)?;
            match self.0 {
                IssueMatchSeedCorruption::Missing => {
                    matches.pop();
                }
                IssueMatchSeedCorruption::Duplicate => {
                    matches.push(matches[0].clone());
                }
                IssueMatchSeedCorruption::AlteredRequirements => {
                    let altered = &matches[0];
                    matches[0] = PanicCallEvidenceMatch::new(
                        altered.claim().clone(),
                        altered.obligation_source().clone(),
                        altered.endpoint().clone(),
                        altered.group().clone(),
                        altered.trace_target().clone(),
                        altered.trace().clone(),
                        altered.witness_order(),
                        Vec::new(),
                    );
                }
                IssueMatchSeedCorruption::AlteredEnvelope => {
                    let altered = &matches[0];
                    matches[0] = PanicCallEvidenceMatch::new(
                        altered.claim().clone(),
                        altered.obligation_source().clone(),
                        altered.endpoint().clone(),
                        altered.endpoint().clone(),
                        altered.trace_target().clone(),
                        altered.trace().clone(),
                        altered.witness_order(),
                        altered.satisfied_requirements().to_vec(),
                    );
                }
                IssueMatchSeedCorruption::Orphan => {
                    let first = &matches[0];
                    matches.push(PanicCallEvidenceMatch::new(
                        first.claim().clone(),
                        first.obligation_source().clone(),
                        first.endpoint().clone(),
                        first.group().clone(),
                        first.trace_target().clone(),
                        first.trace().clone(),
                        100,
                        first.satisfied_requirements().to_vec(),
                    ));
                }
            }
            for obligation in batch.obligations() {
                output.emit_derived(obligation)?;
            }
            for ordering in batch.orderings() {
                output.emit_derived(ordering)?;
            }
            for matched in &matches {
                output.emit_derived(matched)?;
            }
            Ok(())
        }
    }

    fn issue_matching_registry(
        corruption: IssueMatchSeedCorruption,
    ) -> AnalysisRegistry<PanicRootInputs> {
        let mut registry = AnalysisRegistry::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        registry.install(&HumanEvidencePack).unwrap();
        registry.register_derived::<PanicCallObligation>().unwrap();
        registry
            .register_derived::<PanicEvidenceOrdering>()
            .unwrap();
        registry
            .register_derived::<PanicCallEvidenceMatch>()
            .unwrap();
        registry
            .register_issue::<UnsatisfiedPanicCallIssue>()
            .unwrap();
        registry
            .register_evaluation_rule(SeedCallIssueInputs(corruption))
            .unwrap();
        registry
            .register_evaluation_rule(ReportUnsatisfiedPanicCalls)
            .unwrap();
        registry
    }

    fn insert_direct_call(
        builder: &mut ArtifactDbBuilder,
        root_body: &EntityHandle<FunctionEntity>,
        root: FunctionKey,
        local: u32,
        target_key: FunctionKey,
        path: &str,
    ) -> EntityHandle<CallableEntity> {
        let target = builder
            .insert_entity(&CallableEntity::new(
                target_key,
                path,
                false,
                false,
                true,
                false,
                vec![path.to_owned()],
            ))
            .unwrap();
        let call_site = builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(root, local)))
            .unwrap();
        builder
            .relate(root_body, &call_site, &FunctionOwnsCallSite::new())
            .unwrap();
        let occurrence = builder
            .insert_entity(&CallOccurrenceEntity::new(
                CallOccurrenceKey::new(root, local),
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
                &target,
                &CallOccurrenceTargetsCallable::new(CallTargetRole::Runtime),
            )
            .unwrap();
        let group = builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                root, local,
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
        target
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the fixture preserves the complete persisted call topology"
    )]
    fn insert_call_to_target(
        builder: &mut ArtifactDbBuilder,
        owner_body: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        local: u32,
        kind: CallKind,
        attribution: Vec<CallAttributionRole>,
        key: Option<&EntityHandle<CallableKeyEntity>>,
        target: &EntityHandle<CallableEntity>,
    ) -> EntityHandle<CallOccurrenceEntity> {
        let call_site = builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(owner, local)))
            .unwrap();
        builder
            .relate(owner_body, &call_site, &FunctionOwnsCallSite::new())
            .unwrap();
        let occurrence = builder
            .insert_entity(&CallOccurrenceEntity::new(
                CallOccurrenceKey::new(owner, local),
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
        if let Some(key) = key {
            builder
                .relate(&occurrence, key, &CallOccurrenceHasCallableKey::new())
                .unwrap();
        }
        builder
            .relate(
                &occurrence,
                target,
                &CallOccurrenceTargetsCallable::new(CallTargetRole::Runtime),
            )
            .unwrap();
        let group = builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                owner, local,
            )))
            .unwrap();
        builder
            .relate(owner_body, &group, &FunctionOwnsSafetyEffectGroup::new())
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

    fn insert_structural_opaque_call(
        builder: &mut ArtifactDbBuilder,
        owner_body: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        local: u32,
        kind: CallKind,
        target_key: FunctionKey,
        description: &str,
    ) {
        let call_site = builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(owner, local)))
            .unwrap();
        builder
            .relate(owner_body, &call_site, &FunctionOwnsCallSite::new())
            .unwrap();
        let occurrence = builder
            .insert_entity(&CallOccurrenceEntity::new(
                CallOccurrenceKey::new(owner, local),
                kind,
                vec![CallAttributionRole::CallSite],
                false,
                false,
                Some(description.to_owned()),
            ))
            .unwrap();
        builder
            .relate(&call_site, &occurrence, &CallSiteHasOccurrence::new())
            .unwrap();
        let target = builder
            .insert_entity(&CallableEntity::new(
                target_key,
                "crate::structural_opaque",
                false,
                false,
                true,
                false,
                vec![String::from("crate::structural_opaque")],
            ))
            .unwrap();
        builder
            .relate(
                &occurrence,
                &target,
                &CallOccurrenceTargetsCallable::new(CallTargetRole::OpaqueFunction),
            )
            .unwrap();
        let group = builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                owner, local,
            )))
            .unwrap();
        builder
            .relate(owner_body, &group, &FunctionOwnsSafetyEffectGroup::new())
            .unwrap();
        builder
            .relate(
                &occurrence,
                &group,
                &CallOccurrenceInSafetyEffectGroup::new(),
            )
            .unwrap();
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
    ) -> EntityHandle<MarkerClaimEntity> {
        attach_call_marker_claims(
            builder,
            occurrence,
            ordinal,
            domain,
            [(0, selector)],
            source_probe,
            macro_probe,
        )
        .pop()
        .expect("the single-claim marker fixture emits one claim")
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the fixture varies domain, claims, and probe independently"
    )]
    fn attach_call_marker_claims(
        builder: &mut ArtifactDbBuilder,
        occurrence: &EntityHandle<CallOccurrenceEntity>,
        ordinal: u32,
        domain: &str,
        claims: impl IntoIterator<Item = (u32, EvidenceClaimSelector)>,
        source_probe: bool,
        macro_probe: bool,
    ) -> Vec<EntityHandle<MarkerClaimEntity>> {
        let file_id = format!("ingress-marker-{ordinal}");
        let file = builder
            .insert_entity(&SourceFileEntity::new(
                file_id.clone(),
                format!("src/{file_id}.rs"),
                format!("hash-{ordinal}"),
                1_000,
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
        let mut emitted = Vec::new();
        for (source_ordinal, selector) in claims {
            let rationale = if source_ordinal == 0 {
                format!("ingress marker {ordinal}")
            } else {
                format!("ingress marker {ordinal} claim {source_ordinal}")
            };
            let claim = builder
                .insert_entity(&MarkerClaimEntity::new(
                    MarkerClaimKey::new(
                        marker_key.clone(),
                        DomainId::new(domain).unwrap(),
                        source_ordinal,
                    ),
                    selector,
                    rationale,
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
            emitted.push(claim);
        }
        emitted
    }

    fn with_inputs(
        test: impl FnOnce(
            &AnalysisRegistry<PanicRootInputs>,
            &WorkspaceFactView<'_>,
            PanicRootInputs,
            WorkspaceRelationGraph,
        ),
    ) {
        let registry = registry();
        with_registry_inputs(&registry, test);
    }

    fn assert_mixed_evidence_schedule(schedule: &[PassId]) {
        let unique_position = |rule_id: &str| {
            assert_eq!(
                schedule
                    .iter()
                    .filter(|rule| rule.as_str() == rule_id)
                    .count(),
                1,
                "{rule_id} must be scheduled exactly once"
            );
            schedule
                .iter()
                .position(|rule| rule.as_str() == rule_id)
                .unwrap()
        };
        let call_ingress = unique_position(super::EMIT_PANIC_CALL_INPUTS_RULE);
        let assert_ingress = unique_position("sniff-test.panic.emit-compiler-assert-inputs");
        let call_match = unique_position("sniff-test.panic.match-call-evidence");
        let assert_match = unique_position("sniff-test.panic.match-assert-evidence");
        let coordinator = unique_position("sniff-test.evidence.detect-reuse");
        assert!(call_ingress < call_match);
        assert!(assert_ingress < assert_match);
        assert!(call_match < coordinator);
        assert!(assert_match < coordinator);
    }

    fn assert_mixed_evidence_registration_surface(registry: &AnalysisRegistry<PanicRootInputs>) {
        registry
            .schemas()
            .descriptor_for::<PanicEvidenceOrdering>()
            .unwrap();
        registry
            .schemas()
            .descriptor_for::<EvidenceUseRecord>()
            .unwrap();
        registry
            .schemas()
            .descriptor_for::<UnsatisfiedPanicCallIssue>()
            .unwrap();
        registry
            .schemas()
            .descriptor_for::<DuplicatePanicCallRequirementIssue>()
            .unwrap();
        for schema in [
            PanicEvidenceOrdering::ID,
            EvidenceUseRecord::ID,
            UnsatisfiedPanicCallIssue::ID,
            DuplicatePanicCallRequirementIssue::ID,
        ] {
            let schema = SchemaId::new(schema).unwrap();
            assert_eq!(
                registry
                    .schemas()
                    .descriptors()
                    .filter(|descriptor| descriptor.id() == &schema)
                    .count(),
                1
            );
        }
        for rule in [
            super::EMIT_PANIC_CALL_INPUTS_RULE,
            "sniff-test.panic.match-call-evidence",
            "sniff-test.panic.report-unsatisfied-call-obligations",
            "sniff-test.panic.report-duplicate-call-requirements",
            "sniff-test.panic.emit-compiler-assert-inputs",
            "sniff-test.panic.create-assert-obligations",
            "sniff-test.panic.match-assert-evidence",
            "sniff-test.panic.report-unsatisfied-asserts",
            "sniff-test.evidence.detect-reuse",
        ] {
            assert!(
                registry
                    .evaluation_rules()
                    .descriptor(&PassId::new(rule).unwrap())
                    .is_some()
            );
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the shared fixture builds the complete cross-schema panic-call workspace"
    )]
    fn with_registry_inputs(
        registry: &AnalysisRegistry<PanicRootInputs>,
        test: impl FnOnce(
            &AnalysisRegistry<PanicRootInputs>,
            &WorkspaceFactView<'_>,
            PanicRootInputs,
            WorkspaceRelationGraph,
        ),
    ) {
        let root = FunctionKey::new(definition(1), None);
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors().filter(|descriptor| {
            !matches!(descriptor.kind(), TableKind::Derived | TableKind::Issue)
        }) {
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
        let sink = builder
            .insert_entity(&CallableEntity::new(
                FunctionKey::new(definition(10), None),
                "crate::sink",
                false,
                false,
                false,
                false,
                vec![String::from("crate::sink")],
            ))
            .unwrap();
        let sink_occurrence = insert_trace_configured_call(
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
                &sink_occurrence,
                &sink,
                &CallOccurrenceTargetsCallable::new(CallTargetRole::SourceContract),
            )
            .unwrap();
        let mut shared_assert_claim = None;
        for (ordinal, selector) in [
            (60, EvidenceClaimSelector::Unnamed),
            (61, EvidenceClaimSelector::Unnamed),
            (
                62,
                EvidenceClaimSelector::Named(String::from("Index_In-Bounds")),
            ),
            (
                63,
                EvidenceClaimSelector::Explicit(vec![String::from("panic.index-in-bounds")]),
            ),
        ] {
            let claim = attach_call_marker(
                &mut builder,
                &sink_occurrence,
                ordinal,
                "sniff-test.panic",
                selector,
                true,
                false,
            );
            if ordinal == 60 {
                shared_assert_claim = Some(claim);
            }
        }
        let override_target = builder
            .insert_entity(&CallableEntity::new(
                FunctionKey::new(definition(11), Some(instance(2))),
                "crate::override",
                false,
                false,
                true,
                false,
                vec![String::from("crate::override")],
            ))
            .unwrap();
        let override_occurrence = insert_call_to_target(
            &mut builder,
            &root_body,
            root,
            1,
            CallKind::DirectCall,
            vec![CallAttributionRole::CallSite],
            None,
            &override_target,
        );
        attach_named_call_macros_and_sources(
            &mut builder,
            &root_body,
            root,
            &override_occurrence,
            "macro already_prefixed!",
            "inner!",
        );
        attach_call_marker_claims(
            &mut builder,
            &override_occurrence,
            70,
            "sniff-test.panic",
            [
                (
                    0,
                    EvidenceClaimSelector::Named(String::from("  INDEX_in-bounds ")),
                ),
                (
                    1,
                    EvidenceClaimSelector::Named(String::from("index-in_bounds")),
                ),
            ],
            true,
            false,
        );
        for (ordinal, selector) in [
            (72, EvidenceClaimSelector::Unnamed),
            (
                73,
                EvidenceClaimSelector::Explicit(vec![String::from("panic.index-in-bounds")]),
            ),
        ] {
            attach_call_marker(
                &mut builder,
                &override_occurrence,
                ordinal,
                "sniff-test.panic",
                selector,
                true,
                false,
            );
        }
        let raw_exact_key = FunctionKey::new(definition(20), Some(instance(3)));
        let raw_exact = insert_direct_call(
            &mut builder,
            &root_body,
            root,
            2,
            raw_exact_key,
            "crate::raw_exact",
        );
        let generic_key = FunctionKey::new(definition(30), None);
        let generic_exact_key = FunctionKey::new(definition(30), Some(instance(4)));
        let generic = builder
            .insert_entity(&CallableEntity::new(
                generic_key,
                "crate::generic",
                false,
                false,
                true,
                false,
                vec![String::from("crate::generic")],
            ))
            .unwrap();
        insert_direct_call(
            &mut builder,
            &root_body,
            root,
            3,
            generic_exact_key,
            "crate::generic::<u8>",
        );
        insert_direct_call(
            &mut builder,
            &root_body,
            root,
            4,
            FunctionKey::new(definition(40), Some(instance(5))),
            "crate::trusted",
        );
        let bodyless = builder
            .insert_entity(&CallableEntity::new(
                FunctionKey::new(definition(41), Some(instance(6))),
                "crate::bodyless",
                false,
                false,
                false,
                false,
                vec![String::from("crate::bodyless")],
            ))
            .unwrap();
        let bodyless_occurrence = insert_call_to_target(
            &mut builder,
            &root_body,
            root,
            5,
            CallKind::DirectCall,
            vec![CallAttributionRole::CallSite],
            None,
            &bodyless,
        );
        attach_call_marker(
            &mut builder,
            &bodyless_occurrence,
            80,
            "sniff-test.panic",
            EvidenceClaimSelector::Explicit(vec![String::from("panic.opaque-boundary")]),
            true,
            false,
        );
        insert_structural_opaque_call(
            &mut builder,
            &root_body,
            root,
            6,
            CallKind::CoroutineBody,
            FunctionKey::new(definition(42), None),
            "structural opaque must not become an obligation",
        );

        let effect = builder
            .insert_entity(&EffectSiteEntity::new(
                EffectSiteKey::from_mir(
                    root,
                    MirBodyLocation {
                        basic_block: 0,
                        statement_index: 0,
                    },
                )
                .unwrap(),
            ))
            .unwrap();
        builder
            .relate(&root_body, &effect, &FunctionOwnsEffectSite::new())
            .unwrap();
        let assert_requirement = builder
            .insert_requirement(&InBoundsRequirement::new())
            .unwrap();
        builder
            .insert_fact(
                &MirAssertFact::new(MirAssertKind::BoundsCheck),
                FactMeta::new(PassId::new("test.panic.call-ingress").unwrap())
                    .with_owner(&effect)
                    .unwrap()
                    .with_provenance_root(&root_body)
                    .unwrap()
                    .with_requirement(&assert_requirement)
                    .unwrap(),
            )
            .unwrap();
        builder
            .relate(
                &effect,
                shared_assert_claim
                    .as_ref()
                    .expect("the sink fixture retains its shared unnamed claim"),
                &EffectSiteHasMarkerClaimCandidate::new(true, false),
            )
            .unwrap();

        let file = builder
            .insert_entity(&SourceFileEntity::new(
                "call-contracts.rs",
                "src/call-contracts.rs",
                "verified",
                200,
            ))
            .unwrap();
        let mut make_anchor = |start: u64| {
            let key = SourceAnchorKey::new("call-contracts.rs", start, start + 5);
            let anchor = builder
                .insert_entity(&SourceAnchorEntity::new(key.clone()))
                .unwrap();
            builder
                .relate(&anchor, &file, &SourceAnchorInFile::new())
                .unwrap();
            (key, anchor)
        };
        let (_, exact_contract_anchor) = make_anchor(10);
        let (exact_requirement_one_key, _) = make_anchor(30);
        let (exact_requirement_zero_key, _) = make_anchor(20);
        let (_, generic_contract_anchor) = make_anchor(40);
        let (generic_requirement_key, _) = make_anchor(50);

        let exact_requirement_one = builder
            .insert_requirement(&PanicRequirement::new(
                raw_exact_key,
                1,
                "index-in_bounds",
                "aaa value is ready",
                Some(exact_requirement_one_key),
            ))
            .unwrap();
        let exact_requirement_zero = builder
            .insert_requirement(&PanicRequirement::new(
                raw_exact_key,
                0,
                "Index_In-Bounds",
                "zzz index is valid",
                Some(exact_requirement_zero_key),
            ))
            .unwrap();
        let exact_metadata = FactMeta::new(PassId::new("test.panic.call-ingress").unwrap())
            .with_owner(&raw_exact)
            .unwrap()
            .with_anchor(&exact_contract_anchor)
            .unwrap()
            .with_requirement(&exact_requirement_one)
            .unwrap()
            .with_requirement(&exact_requirement_zero)
            .unwrap();
        builder
            .insert_fact(&PanicContractFact::new(), exact_metadata)
            .unwrap();

        let generic_requirement = builder
            .insert_requirement(&PanicRequirement::new(
                generic_key,
                0,
                "Initialized",
                "the value was initialized",
                Some(generic_requirement_key),
            ))
            .unwrap();
        let generic_metadata = FactMeta::new(PassId::new("test.panic.call-ingress").unwrap())
            .with_owner(&generic)
            .unwrap()
            .with_anchor(&generic_contract_anchor)
            .unwrap()
            .with_requirement(&generic_requirement)
            .unwrap();
        builder
            .insert_fact(&PanicContractFact::new(), generic_metadata)
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
        let panic = PanicConfig {
            panic_sink_namespaces: PathPatterns::new(vec![String::from("crate::sink")]).unwrap(),
            trusted_panic_boundary_namespaces: PathPatterns::new(vec![String::from(
                "crate::trusted",
            )])
            .unwrap(),
            ..PanicConfig::default()
        };
        let overrides = ContractDocOverrides::new(vec![
            (
                String::from("crate::sink"),
                String::from(
                    "# Panics\n- ready: the sink is ready\n- READY: the sink remains ready",
                ),
            ),
            (
                String::from("crate::override"),
                String::from(
                    "# Panics\n- Index_In-Bounds: the index is valid\n- index-in_bounds: the index remains valid",
                ),
            ),
            (
                String::from("crate::trusted"),
                String::from("# Panics\n- ready: the value is ready"),
            ),
        ])
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
        let mut composition = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut composition).unwrap();
        let relations = composition.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &relations).unwrap();
        let inputs = emitted
            .resolve_panic(&workspace, &graph, registry.composition_relations())
            .unwrap();
        test(registry, &workspace, inputs, graph);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one registry contract test freezes every call-pack schema and rule surface"
    )]
    fn exposes_the_production_panic_call_ingress_surface() {
        fn assert_types(
            _: PanicCallInputPack,
            _: Option<PanicCallObligation>,
            _: Option<PanicCallEvidenceMatch>,
            _: Option<DuplicatePanicCallRequirementIssue>,
        ) {
        }

        assert_types(PanicCallInputPack, None, None, None);
        let registry = registry();
        let descriptor = registry
            .evaluation_rules()
            .descriptor(&PassId::new(super::EMIT_PANIC_CALL_INPUTS_RULE).unwrap())
            .unwrap();
        assert_eq!(
            descriptor.reads().map(SchemaId::as_str).collect::<Vec<_>>(),
            [
                CallOccurrenceEntity::ID,
                CallSiteEntity::ID,
                CallableEntity::ID,
                SourceAnchorEntity::ID,
                MarkerClaimEntity::ID,
                PanicContractFact::ID,
                PanicRequirement::ID,
            ]
        );
        assert_eq!(
            descriptor
                .writes()
                .map(SchemaId::as_str)
                .collect::<Vec<_>>(),
            [PanicCallObligation::ID, PanicEvidenceOrdering::ID]
        );
        registry
            .schemas()
            .descriptor_for::<PanicCallEvidenceMatch>()
            .unwrap();
        let issue_schema = registry
            .schemas()
            .descriptor_for::<UnsatisfiedPanicCallIssue>()
            .unwrap();
        assert_eq!(issue_schema.kind(), TableKind::Issue);
        let duplicate_schema = registry
            .schemas()
            .descriptor_for::<DuplicatePanicCallRequirementIssue>()
            .unwrap();
        assert_eq!(duplicate_schema.kind(), TableKind::Issue);
        let matcher = registry
            .evaluation_rules()
            .descriptor(&PassId::new("sniff-test.panic.match-call-evidence").unwrap())
            .unwrap();
        assert_eq!(
            matcher.reads().map(SchemaId::as_str).collect::<Vec<_>>(),
            [
                CallOccurrenceEntity::ID,
                CallSiteEntity::ID,
                CallableEntity::ID,
                SourceAnchorEntity::ID,
                MarkerClaimEntity::ID,
                PanicContractFact::ID,
                PanicRequirement::ID,
                PanicCallObligation::ID,
                PanicEvidenceOrdering::ID,
            ]
        );
        assert_eq!(
            matcher.writes().map(SchemaId::as_str).collect::<Vec<_>>(),
            [PanicCallEvidenceMatch::ID, EvidenceUseRecord::ID]
        );
        let reporter = registry
            .evaluation_rules()
            .descriptor(
                &PassId::new("sniff-test.panic.report-unsatisfied-call-obligations").unwrap(),
            )
            .unwrap();
        assert_eq!(
            reporter.reads().map(SchemaId::as_str).collect::<Vec<_>>(),
            [
                CallOccurrenceEntity::ID,
                CallSiteEntity::ID,
                CallableEntity::ID,
                SourceAnchorEntity::ID,
                MarkerClaimEntity::ID,
                PanicContractFact::ID,
                PanicRequirement::ID,
                PanicCallObligation::ID,
                PanicEvidenceOrdering::ID,
                PanicCallEvidenceMatch::ID,
            ]
        );
        assert_eq!(
            reporter.writes().map(SchemaId::as_str).collect::<Vec<_>>(),
            [UnsatisfiedPanicCallIssue::ID]
        );
        let duplicate_reporter = registry
            .evaluation_rules()
            .descriptor(
                &PassId::new("sniff-test.panic.report-duplicate-call-requirements").unwrap(),
            )
            .unwrap();
        assert_eq!(
            duplicate_reporter
                .reads()
                .map(SchemaId::as_str)
                .collect::<Vec<_>>(),
            [
                CallOccurrenceEntity::ID,
                CallSiteEntity::ID,
                CallableEntity::ID,
                SourceAnchorEntity::ID,
                MarkerClaimEntity::ID,
                PanicContractFact::ID,
                PanicRequirement::ID,
                PanicCallObligation::ID,
                PanicEvidenceOrdering::ID,
            ]
        );
        assert!(
            !duplicate_reporter
                .reads()
                .any(|schema| schema.as_str() == PanicCallEvidenceMatch::ID)
        );
        assert_eq!(
            duplicate_reporter
                .writes()
                .map(SchemaId::as_str)
                .collect::<Vec<_>>(),
            [DuplicatePanicCallRequirementIssue::ID]
        );
    }

    #[test]
    fn shared_call_schemas_are_install_order_composable() {
        for permutation in 0..6 {
            let mut registry = AnalysisRegistry::<PanicRootInputs>::new();
            registry.install(&CollectedArtifactSchemaPack).unwrap();
            registry.install(&HumanEvidencePack).unwrap();
            match permutation {
                0 => {
                    registry.install(&PanicCallInputPack).unwrap();
                    registry.install(&PanicPack).unwrap();
                    registry.install(&EvidenceCoordinatorPack).unwrap();
                }
                1 => {
                    registry.install(&PanicCallInputPack).unwrap();
                    registry.install(&EvidenceCoordinatorPack).unwrap();
                    registry.install(&PanicPack).unwrap();
                }
                2 => {
                    registry.install(&PanicPack).unwrap();
                    registry.install(&PanicCallInputPack).unwrap();
                    registry.install(&EvidenceCoordinatorPack).unwrap();
                }
                3 => {
                    registry.install(&PanicPack).unwrap();
                    registry.install(&EvidenceCoordinatorPack).unwrap();
                    registry.install(&PanicCallInputPack).unwrap();
                }
                4 => {
                    registry.install(&EvidenceCoordinatorPack).unwrap();
                    registry.install(&PanicCallInputPack).unwrap();
                    registry.install(&PanicPack).unwrap();
                }
                5 => {
                    registry.install(&EvidenceCoordinatorPack).unwrap();
                    registry.install(&PanicPack).unwrap();
                    registry.install(&PanicCallInputPack).unwrap();
                }
                _ => unreachable!(),
            }
            registry.install(&CompilerAssertInputPack).unwrap();
            assert_mixed_evidence_registration_surface(&registry);
            let schedule = registry.evaluation_rules().schedule().unwrap();
            assert_mixed_evidence_schedule(&schedule);
            let duplicate = registry
                .register_evaluation_rule(ReportUnsatisfiedPanicCalls)
                .unwrap_err();
            assert!(duplicate.to_string().contains(
                "duplicate evaluation rule sniff-test.panic.report-unsatisfied-call-obligations"
            ));
            let duplicate = registry
                .register_evaluation_rule(ReportDuplicatePanicCallRequirements)
                .unwrap_err();
            assert!(duplicate.to_string().contains(
                "duplicate evaluation rule sniff-test.panic.report-duplicate-call-requirements"
            ));
        }
    }

    #[test]
    fn one_physical_marker_reused_by_real_call_and_assert_matchers_is_ambiguous() {
        let registry = combined_registry();
        with_registry_inputs(&registry, |registry, workspace, inputs, graph| {
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();
            registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap();
            let results = evaluated.finish().unwrap();
            let [issue] = results
                .issues::<AmbiguousEvidenceReuseIssue>(registry.schemas())
                .unwrap()
                .try_into()
                .expect("the shared physical marker emits one ambiguity issue");
            let marker = workspace
                .entity::<MarkerOccurrenceEntity>(issue.data.marker())
                .unwrap();
            let mut uses = results
                .derived_rows::<EvidenceUseRecord>(registry.schemas())
                .unwrap()
                .into_iter()
                .filter(|usage| {
                    workspace
                        .entity::<MarkerClaimEntity>(usage.data.claim())
                        .is_ok_and(|claim| claim.key().occurrence() == marker.key())
                })
                .collect::<Vec<_>>();
            uses.sort_by(|left, right| {
                left.data
                    .semantic_order()
                    .cmp(right.data.semantic_order())
                    .then_with(|| left.data.trace().cmp(right.data.trace()))
                    .then_with(|| left.data.source().cmp(right.data.source()))
                    .then_with(|| left.data.endpoint().cmp(right.data.endpoint()))
                    .then_with(|| left.data.witness_order().cmp(&right.data.witness_order()))
                    .then_with(|| left.data.claim().cmp(right.data.claim()))
            });

            assert_eq!(uses.len(), 2);
            assert_eq!(
                uses.iter()
                    .map(|usage| usage.producer.as_str())
                    .collect::<std::collections::BTreeSet<_>>(),
                [
                    "sniff-test.panic.match-assert-evidence",
                    "sniff-test.panic.match-call-evidence",
                ]
                .into_iter()
                .collect()
            );
            assert_eq!(issue.data.groups().len(), 2);
            assert_eq!(
                issue.data.marker().entity().schema.as_str(),
                MarkerOccurrenceEntity::ID
            );
            assert_eq!(issue.data.witness_source(), uses[0].data.source());
            assert_eq!(issue.data.witness_endpoint(), uses[0].data.endpoint());
            assert_eq!(issue.data.witness_order(), uses[0].data.witness_order());
            assert_eq!(
                issue.context.source.as_ref(),
                Some(&issue.data.marker().as_row())
            );
            assert_eq!(
                issue.context.endpoint.as_ref(),
                Some(uses[0].data.endpoint())
            );
            assert_eq!(issue.context.trace.as_ref(), Some(uses[0].data.trace()));

            let call_use = uses
                .iter()
                .find(|usage| usage.producer.as_str() == "sniff-test.panic.match-call-evidence")
                .unwrap();
            assert_ne!(call_use.data.trace().target(), call_use.data.endpoint());
        });
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one projection test verifies every field of the strict obligation schema"
    )]
    fn emits_unnamed_sink_and_value_only_named_override() {
        with_inputs(|registry, workspace, inputs, graph| {
            assert_eq!(inputs.call_count(), 6);
            assert_eq!(inputs.compiler_asserts().assertions().len(), 1);
            assert_eq!(inputs.evidence_order().len(), 7);
            assert!(inputs.evidence_order().iter().any(|ranked| {
                matches!(ranked.witness(), PanicWitnessId::CompilerAssert(id) if id.index() == 0)
            }));
            assert!(inputs.traversal().call_boundaries().len() > inputs.call_count());
            let traversal_orders = inputs
                .calls()
                .map(|call| call.unwrap().order())
                .collect::<Vec<_>>();
            let expected_ranks = inputs
                .evidence_order()
                .iter()
                .filter_map(|ranked| match ranked.witness() {
                    PanicWitnessId::Call(id) => Some((
                        u64::try_from(id.index()).unwrap(),
                        (
                            u64::try_from(ranked.rank().index()).unwrap(),
                            ranked.traversal_order(),
                        ),
                    )),
                    PanicWitnessId::CompilerAssert(_) => None,
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();
            registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap();
            let results = evaluated.finish().unwrap();
            let mut calls = results
                .derived_rows::<PanicCallObligation>(registry.schemas())
                .unwrap();
            calls.sort_by_key(|call| call.data.call_id());
            let mut orderings = results
                .derived_rows::<PanicEvidenceOrdering>(registry.schemas())
                .unwrap();
            orderings.sort_by_key(|ordering| ordering.data.witness_order());
            let mut matches = results
                .derived_rows::<PanicCallEvidenceMatch>(registry.schemas())
                .unwrap();
            matches.sort_by(|left, right| {
                (left.data.witness_order(), left.data.claim())
                    .cmp(&(right.data.witness_order(), right.data.claim()))
            });
            let mut uses = results
                .derived_rows::<EvidenceUseRecord>(registry.schemas())
                .unwrap();
            uses.sort_by(|left, right| {
                (left.data.witness_order(), left.data.claim())
                    .cmp(&(right.data.witness_order(), right.data.claim()))
            });

            assert_eq!(calls.len(), 6);
            assert_eq!(orderings.len(), calls.len());
            assert_eq!(matches.len(), 4);
            assert_eq!(uses.len(), matches.len());
            for (call, ordering) in calls.iter().zip(&orderings) {
                assert_eq!(ordering.data.obligation_source(), call.data.source());
                assert_eq!(ordering.data.endpoint(), call.data.endpoint());
                assert_eq!(ordering.data.trace_target(), call.data.trace_target());
                assert_eq!(ordering.data.trace(), call.data.trace());
                assert_eq!(ordering.data.witness_order(), call.data.call_id());
                assert_eq!(
                    ordering.data.semantic_order().traversal_order(),
                    call.data.traversal_order()
                );
            }
            for (matched, usage) in matches.iter().zip(&uses) {
                let call = &calls[usize::try_from(matched.data.witness_order()).unwrap()].data;
                let ordering =
                    &orderings[usize::try_from(matched.data.witness_order()).unwrap()].data;
                assert_eq!(matched.data.obligation_source(), call.source());
                assert_eq!(matched.data.endpoint(), call.endpoint());
                assert_eq!(matched.data.group(), call.evidence_group());
                assert_eq!(matched.data.trace_target(), call.trace_target());
                assert_eq!(matched.data.trace(), call.trace());
                assert_eq!(matched.data.trace().target(), matched.data.trace_target());
                assert_eq!(usage.data.claim(), matched.data.claim());
                assert_eq!(usage.data.source(), matched.data.obligation_source());
                assert_eq!(usage.data.endpoint(), matched.data.endpoint());
                assert_eq!(usage.data.group(), matched.data.group());
                assert_eq!(usage.data.trace(), matched.data.trace());
                assert_eq!(usage.data.witness_order(), matched.data.witness_order());
                assert_eq!(usage.data.semantic_order(), ordering.semantic_order());
                assert_eq!(usage.data.domain(), &super::super::rules::panic_domain());
                let marker = call
                    .active_markers()
                    .iter()
                    .find(|marker| marker.claim() == matched.data.claim())
                    .unwrap();
                assert_eq!(marker.trace().target(), marker.claim());
                assert_eq!(usage.data.trace(), call.trace());
                assert_ne!(usage.data.trace(), marker.trace());
            }
            assert!(matches[..2].iter().all(|matched| {
                matched.data.witness_order() == 0
                    && matched.data.satisfied_requirements()
                        == [PanicCallRequirementMatchId::unnamed()]
            }));
            assert!(matches[2..].iter().all(|matched| {
                matched.data.witness_order() == 1
                    && matched.data.satisfied_requirements()
                        == [
                            PanicCallRequirementMatchId::named(0),
                            PanicCallRequirementMatchId::named(1),
                        ]
            }));
            assert_ne!(matches[0].data.claim(), matches[1].data.claim());
            assert_ne!(matches[2].data.claim(), matches[3].data.claim());
            let mut named_claim_keys = matches[2..]
                .iter()
                .map(|matched| {
                    calls[1]
                        .data
                        .active_markers()
                        .iter()
                        .find(|marker| marker.claim() == matched.data.claim())
                        .unwrap()
                        .data()
                        .key()
                })
                .collect::<Vec<_>>();
            named_claim_keys.sort_by_key(|key| key.source_ordinal());
            assert_eq!(
                named_claim_keys[0].occurrence(),
                named_claim_keys[1].occurrence()
            );
            assert_eq!(
                named_claim_keys
                    .iter()
                    .map(|key| key.source_ordinal())
                    .collect::<Vec<_>>(),
                [0, 1]
            );
            assert!(calls.iter().zip(&orderings).any(|(call, ordering)| {
                call.data.call_id() != call.data.evidence_rank()
                    && call.data.call_id() != call.data.traversal_order()
                    && ordering.data.semantic_order().traversal_order() != call.data.evidence_rank()
            }));
            assert_eq!(calls[0].data.call_id(), 0);
            assert_eq!(calls[0].data.traversal_order(), traversal_orders[0]);
            assert_ne!(calls[0].data.trace_target(), calls[0].data.endpoint());
            assert_eq!(
                calls[0].data.trace_target(),
                calls[0]
                    .data
                    .metadata_target()
                    .unwrap()
                    .selection()
                    .callable()
            );
            assert_eq!(
                calls[0].data.metadata_target().unwrap().selection().role(),
                CallTargetRole::SourceContract
            );
            let [sink_step] = orderings[0].data.semantic_order().steps() else {
                panic!("the description-only sink has one semantic step")
            };
            assert_eq!(sink_step.caller(), "crate::root");
            assert_eq!(sink_step.target(), Some("source-level opaque call"));
            assert_eq!(
                sink_step.kind(),
                EvidenceSemanticEdgeOrder::Reachability(CallKind::DirectCall)
            );
            assert_eq!(sink_step.source(), None);
            assert_eq!(
                calls[0].data.boundary_kind(),
                &PanicCallBoundaryKind::PanicSink
            );
            assert_eq!(calls[0].data.requirements().len(), 1);
            assert_eq!(calls[0].data.requirements()[0].ordinal(), None);
            assert_eq!(calls[1].data.call_id(), 1);
            assert_eq!(calls[1].data.traversal_order(), traversal_orders[1]);
            assert_eq!(calls[1].data.requirements().len(), 2);
            for (ordinal, named) in calls[1].data.requirements().iter().enumerate() {
                assert_eq!(named.ordinal(), Some(u32::try_from(ordinal).unwrap()));
                assert_eq!(named.raw_requirement(), None);
                assert_eq!(named.source_anchor(), None);
            }
            let [outer, inner, terminal] = orderings[1].data.semantic_order().steps() else {
                panic!("the macro-wrapped override has two macro steps and one terminal call")
            };
            assert_eq!(outer.caller(), "crate::root");
            assert_eq!(outer.target(), Some("macro macro already_prefixed!"));
            assert_eq!(
                outer.kind(),
                EvidenceSemanticEdgeOrder::Reachability(CallKind::MacroExpansion)
            );
            assert_eq!(outer.source().unwrap().byte_start(), 50);
            assert_eq!(outer.source().unwrap().byte_end(), 60);
            assert_eq!(inner.caller(), "macro macro already_prefixed!");
            assert_eq!(inner.target(), Some("macro inner!"));
            assert_eq!(inner.source(), None);
            assert_eq!(terminal.caller(), "macro inner!");
            assert_eq!(terminal.target(), Some("crate::override"));
            assert_eq!(terminal.source().unwrap().byte_start(), 30);
            assert_eq!(terminal.source().unwrap().byte_end(), 40);

            let raw_exact = calls[2].data.contract().unwrap();
            assert_eq!(raw_exact.origin(), PanicCallContractOrigin::RawExact);
            assert!(raw_exact.raw_contract().is_some());
            assert!(raw_exact.source_anchor().is_some());
            assert_eq!(calls[2].data.requirements().len(), 2);
            let exact_zero = &calls[2].data.requirements()[0];
            let exact_one = &calls[2].data.requirements()[1];
            assert_eq!(exact_zero.ordinal(), Some(0));
            assert_eq!(exact_one.ordinal(), Some(1));
            assert!(exact_zero.raw_requirement().is_some());
            assert!(exact_one.raw_requirement().is_some());
            assert!(exact_zero.source_anchor().is_some());
            assert!(exact_one.source_anchor().is_some());
            assert!(
                exact_zero.raw_requirement().unwrap().row().row
                    > exact_one.raw_requirement().unwrap().row().row
            );

            let raw_generic = calls[3].data.contract().unwrap();
            assert_eq!(raw_generic.origin(), PanicCallContractOrigin::RawGeneric);
            assert_ne!(
                raw_generic.queried_callable(),
                raw_generic.declaration_owner()
            );
            assert!(raw_generic.raw_contract().is_some());
            assert!(raw_generic.source_anchor().is_some());
            let generic_requirement = &calls[3].data.requirements()[0];
            assert_eq!(generic_requirement.ordinal(), Some(0));
            assert!(generic_requirement.raw_requirement().is_some());
            assert!(generic_requirement.source_anchor().is_some());

            assert_eq!(
                calls[4].data.boundary_kind(),
                &PanicCallBoundaryKind::Documented { trusted: true }
            );
            assert_eq!(
                calls[4].data.contract().unwrap().origin(),
                PanicCallContractOrigin::Override
            );
            assert_eq!(
                calls[5].data.boundary_kind(),
                &PanicCallBoundaryKind::Opaque {
                    opaque_kind: PanicCallOpaqueKind::BodylessDeclaration,
                    description: String::from(
                        "indirect call to undocumented trait method `crate::bodyless`"
                    ),
                }
            );
            for call in &calls {
                let (rank, order) = expected_ranks[&call.data.call_id()];
                assert_eq!(call.data.evidence_rank(), rank);
                assert_eq!(call.data.traversal_order(), order);
            }

            assert_eq!(PanicCallObligation::VERSION, 2);
            let encoded = serde_json::to_value(&calls[0].data).unwrap();
            let mut missing_presentation = encoded.clone();
            missing_presentation
                .as_object_mut()
                .unwrap()
                .remove("presentation-function");
            let mut unknown_presentation = encoded.clone();
            unknown_presentation["presentation-function"]["unexpected"] = serde_json::json!(true);
            let mut unknown_trace = encoded;
            unknown_trace["trace"]["unexpected"] = serde_json::json!(true);
            for hostile in [missing_presentation, unknown_presentation, unknown_trace] {
                assert!(serde_json::from_value::<PanicCallObligation>(hostile).is_err());
            }
        });
    }

    #[test]
    fn reports_only_unsatisfied_call_atoms_with_exact_witness_context() {
        with_inputs(|registry, workspace, inputs, graph| {
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();
            registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap();
            let results = evaluated.finish().unwrap();
            let mut calls = results
                .derived_rows::<PanicCallObligation>(registry.schemas())
                .unwrap();
            calls.sort_by_key(|call| call.data.call_id());
            let mut issues = results
                .issues::<UnsatisfiedPanicCallIssue>(registry.schemas())
                .unwrap();
            issues.sort_by_key(|issue| issue.data.witness_order());

            assert_eq!(
                issues
                    .iter()
                    .map(|issue| issue.data.witness_order())
                    .collect::<Vec<_>>(),
                [2, 3, 4, 5]
            );
            assert_eq!(
                issues[0].data.missing_requirements(),
                [
                    PanicCallRequirementMatchId::named(0),
                    PanicCallRequirementMatchId::named(1),
                ]
            );
            assert_eq!(
                issues[1].data.missing_requirements(),
                [PanicCallRequirementMatchId::named(0)]
            );
            assert_eq!(
                issues[2].data.missing_requirements(),
                [PanicCallRequirementMatchId::named(0)]
            );
            assert_eq!(
                issues[3].data.missing_requirements(),
                [PanicCallRequirementMatchId::unnamed()]
            );
            assert!(calls[0].data.requirements()[0].ordinal().is_none());
            assert!(
                calls[1].data.requirements().iter().all(|requirement| {
                    requirement.normalized_name() == Some("index in bounds")
                })
            );
            assert!(calls[5].data.active_markers().iter().any(|marker| {
                matches!(marker.data().selector(), EvidenceClaimSelector::Explicit(_))
            }));
            for issue in &issues {
                let call = &calls[usize::try_from(issue.data.witness_order()).unwrap()].data;
                assert_eq!(issue.data.source(), call.source());
                assert_eq!(issue.data.endpoint(), call.endpoint());
                assert_eq!(issue.data.boundary_kind(), call.boundary_kind());
                assert_eq!(issue.context.root, root);
                assert_eq!(issue.context.source.as_ref(), Some(call.source()));
                assert_eq!(issue.context.endpoint.as_ref(), Some(call.endpoint()));
                assert_eq!(issue.context.trace.as_ref(), Some(call.trace()));
            }
            assert_ne!(calls[2].data.trace().target(), calls[2].data.endpoint());
            assert_eq!(
                issues[0].context.trace.as_ref().unwrap().target(),
                calls[2].data.trace_target()
            );
        });
    }

    #[test]
    fn reports_duplicate_call_requirements_even_when_evidence_satisfies_them() {
        with_inputs(|registry, workspace, inputs, graph| {
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();
            registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap();
            let results = evaluated.finish().unwrap();
            let mut calls = results
                .derived_rows::<PanicCallObligation>(registry.schemas())
                .unwrap();
            calls.sort_by_key(|call| call.data.call_id());
            let issues = results
                .issues::<DuplicatePanicCallRequirementIssue>(registry.schemas())
                .unwrap();

            assert_eq!(
                calls[0].data.boundary_kind(),
                &PanicCallBoundaryKind::PanicSink
            );
            assert!(calls[0].data.contract().is_none());
            assert_eq!(
                calls[0].data.requirements(),
                [super::super::call_model::PanicCallRequirementValue::unnamed()]
            );
            assert!(matches!(
                calls[2].data.boundary_kind(),
                PanicCallBoundaryKind::Documented { trusted: false }
            ));
            assert_eq!(
                issues
                    .iter()
                    .map(|issue| issue.data.witness_order())
                    .collect::<Vec<_>>(),
                [1, 2]
            );
            for issue in &issues {
                let call = &calls[usize::try_from(issue.data.witness_order()).unwrap()].data;
                assert_eq!(issue.data.normalized_name(), "index in bounds");
                assert_eq!(
                    issue.data.requirements(),
                    [
                        PanicCallRequirementMatchId::named(0),
                        PanicCallRequirementMatchId::named(1),
                    ]
                );
                assert_eq!(issue.data.source(), call.source());
                assert_eq!(
                    issue.data.presentation_function(),
                    call.presentation_function()
                );
                assert_eq!(issue.context.root, root);
                assert_eq!(issue.context.source.as_ref(), Some(call.source()));
                assert_eq!(
                    issue.context.endpoint.as_ref(),
                    Some(call.presentation_function().endpoint())
                );
                assert_ne!(issue.context.endpoint.as_ref(), Some(call.endpoint()));
                assert_eq!(issue.context.trace.as_ref(), Some(call.trace()));
            }
            let fully_satisfied = results
                .derived_rows::<PanicCallEvidenceMatch>(registry.schemas())
                .unwrap()
                .into_iter()
                .filter(|matched| matched.data.witness_order() == 1)
                .collect::<Vec<_>>();
            assert!(!fully_satisfied.is_empty());
            assert!(fully_satisfied.iter().all(|matched| {
                matched.data.satisfied_requirements()
                    == [
                        PanicCallRequirementMatchId::named(0),
                        PanicCallRequirementMatchId::named(1),
                    ]
            }));
        });
    }

    #[test]
    fn hostile_committed_call_inputs_fail_without_partial_match_or_use_rows() {
        for (corruption, expected_error) in [
            (
                MatchSeedCorruption::MissingObligation,
                "panic-call obligation is missing an expected witness",
            ),
            (
                MatchSeedCorruption::DuplicateObligation,
                "panic-call obligations repeat an exact witness identity",
            ),
            (
                MatchSeedCorruption::AlteredObligation,
                "panic-call obligation changed after validated ingress",
            ),
            (
                MatchSeedCorruption::MissingOrdering,
                "panic-call evidence ordering is missing an expected witness",
            ),
            (
                MatchSeedCorruption::DuplicateOrdering,
                "panic-call evidence orderings repeat an exact witness identity",
            ),
            (
                MatchSeedCorruption::OrphanOrdering,
                "panic-call evidence ordering has an orphan witness",
            ),
            (
                MatchSeedCorruption::AlteredOrdering,
                "panic-call evidence ordering changed after validated ingress",
            ),
        ] {
            let registry = matching_registry(corruption);
            with_registry_inputs(&registry, |registry, workspace, inputs, graph| {
                let root = inputs.root().clone();
                let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
                let mut evaluated = EvaluationDb::new();

                let error = registry
                    .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                    .unwrap_err();

                assert!(error.to_string().contains(expected_error), "{error}");
                let results = evaluated.finish().unwrap();
                assert!(
                    !results
                        .derived_rows::<PanicCallObligation>(registry.schemas())
                        .unwrap()
                        .is_empty()
                );
                assert!(
                    !results
                        .derived_rows::<PanicEvidenceOrdering>(registry.schemas())
                        .unwrap()
                        .is_empty()
                );
                assert!(
                    results
                        .derived_rows::<PanicCallEvidenceMatch>(registry.schemas())
                        .unwrap()
                        .is_empty()
                );
                assert!(
                    results
                        .derived_rows::<EvidenceUseRecord>(registry.schemas())
                        .unwrap()
                        .is_empty()
                );
            });
        }
    }

    #[test]
    fn hostile_committed_call_inputs_fail_without_any_duplicate_issue() {
        for (corruption, expected_error) in [
            (
                MatchSeedCorruption::MissingObligation,
                "panic-call obligation is missing an expected witness",
            ),
            (
                MatchSeedCorruption::DuplicateObligation,
                "panic-call obligations repeat an exact witness identity",
            ),
            (
                MatchSeedCorruption::AlteredObligation,
                "panic-call obligation changed after validated ingress",
            ),
            (
                MatchSeedCorruption::MissingOrdering,
                "panic-call evidence ordering is missing an expected witness",
            ),
            (
                MatchSeedCorruption::DuplicateOrdering,
                "panic-call evidence orderings repeat an exact witness identity",
            ),
            (
                MatchSeedCorruption::OrphanOrdering,
                "panic-call evidence ordering has an orphan witness",
            ),
            (
                MatchSeedCorruption::AlteredOrdering,
                "panic-call evidence ordering changed after validated ingress",
            ),
        ] {
            let registry = duplicate_issue_registry(corruption);
            with_registry_inputs(&registry, |registry, workspace, inputs, graph| {
                let root = inputs.root().clone();
                let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
                let mut evaluated = EvaluationDb::new();

                let error = registry
                    .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                    .unwrap_err();

                assert!(error.to_string().contains(expected_error), "{error}");
                let results = evaluated.finish().unwrap();
                assert!(
                    results
                        .issues::<DuplicatePanicCallRequirementIssue>(registry.schemas())
                        .unwrap()
                        .is_empty()
                );
            });
        }
    }

    #[test]
    fn late_duplicate_call_issue_failure_commits_no_partial_issue_batch() {
        with_inputs(|registry, workspace, inputs, graph| {
            let _rejection = reject_duplicate_call_issue_for_test(2);
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap_err();

            assert!(error.to_string().contains(
                "panic-call duplicate requirement projection rejected call 2 for atomicity testing"
            ));
            let results = evaluated.finish().unwrap();
            assert!(
                results
                    .issues::<DuplicatePanicCallRequirementIssue>(registry.schemas())
                    .unwrap()
                    .is_empty()
            );
        });
    }

    #[test]
    fn late_second_call_matching_failure_commits_no_partial_match_or_use_batch() {
        with_inputs(|registry, workspace, inputs, graph| {
            let _rejection = reject_call_match_for_test(1);
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("panic-call matching rejected call 1 for atomicity testing")
            );
            let results = evaluated.finish().unwrap();
            assert_eq!(
                results
                    .derived_rows::<PanicCallObligation>(registry.schemas())
                    .unwrap()
                    .len(),
                6
            );
            assert_eq!(
                results
                    .derived_rows::<PanicEvidenceOrdering>(registry.schemas())
                    .unwrap()
                    .len(),
                6
            );
            assert!(
                results
                    .derived_rows::<PanicCallEvidenceMatch>(registry.schemas())
                    .unwrap()
                    .is_empty()
            );
            assert!(
                results
                    .derived_rows::<EvidenceUseRecord>(registry.schemas())
                    .unwrap()
                    .is_empty()
            );
        });
    }

    #[test]
    fn hostile_committed_matches_fail_without_any_call_issue() {
        for (corruption, expected_error) in [
            (
                IssueMatchSeedCorruption::Missing,
                "panic-call evidence match is missing an expected witness",
            ),
            (
                IssueMatchSeedCorruption::Duplicate,
                "panic-call evidence matches repeat an exact witness identity",
            ),
            (
                IssueMatchSeedCorruption::AlteredRequirements,
                "panic-call evidence match changed after validated ingress",
            ),
            (
                IssueMatchSeedCorruption::AlteredEnvelope,
                "panic-call evidence match changed after validated ingress",
            ),
            (
                IssueMatchSeedCorruption::Orphan,
                "panic-call evidence match has an orphan witness",
            ),
        ] {
            let registry = issue_matching_registry(corruption);
            with_registry_inputs(&registry, |registry, workspace, inputs, graph| {
                let root = inputs.root().clone();
                let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
                let mut evaluated = EvaluationDb::new();

                let error = registry
                    .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                    .unwrap_err();

                assert!(error.to_string().contains(expected_error), "{error}");
                let results = evaluated.finish().unwrap();
                assert_eq!(
                    results
                        .derived_rows::<PanicCallObligation>(registry.schemas())
                        .unwrap()
                        .len(),
                    6
                );
                assert!(
                    results
                        .issues::<UnsatisfiedPanicCallIssue>(registry.schemas())
                        .unwrap()
                        .is_empty()
                );
            });
        }
    }

    #[test]
    fn late_call_issue_failure_commits_no_partial_issue_batch() {
        with_inputs(|registry, workspace, inputs, graph| {
            let _rejection = reject_call_issue_for_test(3);
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("panic-call issue projection rejected call 3 for atomicity testing")
            );
            let results = evaluated.finish().unwrap();
            assert_eq!(
                results
                    .derived_rows::<PanicCallEvidenceMatch>(registry.schemas())
                    .unwrap()
                    .len(),
                4
            );
            assert!(
                results
                    .issues::<UnsatisfiedPanicCallIssue>(registry.schemas())
                    .unwrap()
                    .is_empty()
            );
        });
    }

    #[test]
    fn rejects_both_metadata_option_mismatches_before_projection() {
        assert!(validate_metadata_pair_presence(3, true, false).is_err());
        assert!(validate_metadata_pair_presence(3, false, true).is_err());
        assert!(validate_metadata_pair_presence(3, true, true).is_ok());
        assert!(validate_metadata_pair_presence(3, false, false).is_ok());
    }

    #[test]
    fn rejects_wrong_actual_traversal_order_without_committing_any_call() {
        with_inputs(|registry, workspace, mut inputs, graph| {
            let final_rank = inputs.evidence_order().len() - 1;
            let wrong_order = inputs.evidence_order()[final_rank]
                .traversal_order()
                .checked_add(1)
                .unwrap();
            assert!(inputs.test_set_evidence_traversal_order(final_rank, wrong_order));
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("traversal order disagrees with its evidence-order entry")
            );
            assert_eq!(evaluated.derived_count(), 0);
            let results = evaluated.finish().unwrap();
            assert!(
                results
                    .derived_rows::<PanicCallObligation>(registry.schemas())
                    .unwrap()
                    .is_empty()
            );
            assert!(
                results
                    .derived_rows::<PanicEvidenceOrdering>(registry.schemas())
                    .unwrap()
                    .is_empty()
            );
        });

        with_inputs(|registry, workspace, mut inputs, graph| {
            let call_trace = inputs.calls().next().unwrap().unwrap().trace().clone();
            assert!(inputs.test_set_assertion_trace(0, call_trace));
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap_err();

            assert!(error.to_string().contains("resolved effect visit"));
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn duplicate_call_and_assert_traversal_order_commits_no_rows() {
        with_inputs(|registry, workspace, mut inputs, graph| {
            let assertion_rank = inputs
                .evidence_order()
                .iter()
                .position(|ranked| matches!(ranked.witness(), PanicWitnessId::CompilerAssert(_)))
                .unwrap();
            let assertion_order = inputs.evidence_order()[assertion_rank].traversal_order();
            let call_rank = inputs
                .evidence_order()
                .iter()
                .enumerate()
                .skip(assertion_rank + 1)
                .find_map(|(rank, ranked)| {
                    matches!(ranked.witness(), PanicWitnessId::Call(_)).then_some(rank)
                })
                .unwrap();
            assert!(inputs.test_set_evidence_traversal_order(call_rank, assertion_order));
            assert_eq!(
                inputs.evidence_order()[call_rank].traversal_order(),
                assertion_order
            );
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap_err();

            assert!(
                error.to_string().contains("repeats a traversal order"),
                "{error}"
            );
            assert_eq!(evaluated.derived_count(), 0);
            let results = evaluated.finish().unwrap();
            assert!(
                results
                    .derived_rows::<PanicCallObligation>(registry.schemas())
                    .unwrap()
                    .is_empty()
            );
            assert!(
                results
                    .derived_rows::<PanicEvidenceOrdering>(registry.schemas())
                    .unwrap()
                    .is_empty()
            );
        });
    }

    #[test]
    fn rejects_call_kind_that_disagrees_with_retained_boundary() {
        with_inputs(|registry, workspace, mut inputs, graph| {
            assert!(inputs.test_set_call_kind(
                1,
                super::super::compiler_assert_inputs::PanicCallInputKind::PanicSink,
            ));
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap_err();

            assert!(error.to_string().contains("kind disagrees"));
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn rejects_an_omitted_or_substituted_retained_boundary() {
        with_inputs(|registry, workspace, mut inputs, graph| {
            assert!(inputs.test_drop_last_call_and_witness());
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap_err();

            assert!(error.to_string().contains("bijection"));
            assert_eq!(evaluated.derived_count(), 0);
        });

        with_inputs(|registry, workspace, mut inputs, graph| {
            let structural = inputs
                .traversal()
                .call_boundaries()
                .iter()
                .position(|boundary| boundary.effective_kind() == CallKind::CoroutineBody)
                .unwrap();
            assert!(inputs.test_set_call_boundary_index(1, structural));
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap_err();

            assert!(error.to_string().contains("boundary bijection"));
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn late_second_call_projection_failure_commits_no_partial_batch() {
        with_inputs(|registry, workspace, mut inputs, graph| {
            assert!(inputs.test_clear_call_metadata_target_data(1));
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("metadata target identity and data have different presence")
            );
            assert_eq!(evaluated.derived_count(), 0);
        });
    }

    #[test]
    fn late_semantic_projection_failure_commits_no_obligations_or_orderings() {
        with_inputs(|registry, workspace, inputs, graph| {
            let _rejection = reject_call_presentation_for_test(1);
            let root = inputs.root().clone();
            let evaluation = WorkspaceEvaluationView::from_graph(workspace, graph).unwrap();
            let mut evaluated = EvaluationDb::new();

            let error = registry
                .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
                .unwrap_err();

            assert!(error.to_string().contains("InvalidPresentationTarget"));
            assert_eq!(evaluated.derived_count(), 0);
            let results = evaluated.finish().unwrap();
            assert!(
                results
                    .derived_rows::<PanicCallObligation>(registry.schemas())
                    .unwrap()
                    .is_empty()
            );
            assert!(
                results
                    .derived_rows::<PanicEvidenceOrdering>(registry.schemas())
                    .unwrap()
                    .is_empty()
            );
        });
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one fixture proves route-specific callable evidence and raw marker retention"
    )]
    fn callable_evidence_repeated_marker_states_keep_exact_routes_and_markers() {
        let registry = registry();
        let root = FunctionKey::new(definition(100), None);
        let target_key = FunctionKey::new(definition(101), Some(instance(101)));
        let raw_key = FunctionKey::new(definition(102), Some(instance(102)));
        let evidence_key = FunctionKey::new(definition(103), Some(instance(103)));
        let callable_key = CallableKey::FnPointer(type_hash(100));
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors().filter(|descriptor| {
            !matches!(descriptor.kind(), TableKind::Derived | TableKind::Issue)
        }) {
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
        let target_body = builder
            .insert_entity(&FunctionEntity::new(
                target_key,
                "crate::target",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let target = builder
            .insert_entity(&CallableEntity::new(
                target_key,
                "crate::target",
                false,
                false,
                true,
                false,
                vec![String::from("crate::target")],
            ))
            .unwrap();
        builder
            .relate(&target_body, &target, &FunctionDefinesCallable::new())
            .unwrap();
        let first_route = insert_call_to_target(
            &mut builder,
            &root_body,
            root,
            0,
            CallKind::DirectCall,
            vec![CallAttributionRole::CallSite],
            None,
            &target,
        );
        insert_call_to_target(
            &mut builder,
            &root_body,
            root,
            1,
            CallKind::DirectCall,
            vec![CallAttributionRole::CallSite],
            None,
            &target,
        );
        attach_call_marker(
            &mut builder,
            &first_route,
            10,
            "sniff-test.panic",
            EvidenceClaimSelector::Unnamed,
            true,
            false,
        );

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
        insert_call_to_target(
            &mut builder,
            &target_body,
            target_key,
            0,
            CallKind::FnPointerReify,
            vec![CallAttributionRole::ErasureSite],
            Some(&key),
            &evidence_target,
        );
        let invocation = insert_call_to_target(
            &mut builder,
            &target_body,
            target_key,
            1,
            CallKind::IndirectCall,
            vec![CallAttributionRole::CallSite],
            Some(&key),
            &raw,
        );
        for (ordinal, domain, selector, source_probe, macro_probe) in [
            (
                20,
                "sniff-test.panic",
                EvidenceClaimSelector::Unnamed,
                true,
                false,
            ),
            (
                21,
                "sniff-test.panic",
                EvidenceClaimSelector::Named(String::from("Index_In-Bounds")),
                true,
                false,
            ),
            (
                22,
                "sniff-test.panic",
                EvidenceClaimSelector::Explicit(vec![String::from("compiler.bounds")]),
                true,
                false,
            ),
            (
                23,
                "sniff-test.safety",
                EvidenceClaimSelector::Unnamed,
                true,
                false,
            ),
            (
                24,
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
        let scope = ArtifactScopeId::for_in_memory(1, 100);
        let workspace = WorkspaceFactView::compose([(
            scope,
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(ManagedArtifactGeneration::in_memory(1, 100), vec![]),
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
                64,
            )],
        )
        .unwrap()
        .into_roots()
        .pop()
        .unwrap();
        let mut composition = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut composition).unwrap();
        let relations = composition.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &relations).unwrap();
        let inputs = emitted
            .resolve_panic(&workspace, &graph, registry.composition_relations())
            .unwrap();
        assert_eq!(inputs.traversal().callable_resolutions().len(), 2);
        assert_eq!(inputs.call_count(), 4);
        let root = inputs.root().clone();
        let evaluation = WorkspaceEvaluationView::from_graph(&workspace, graph).unwrap();
        let mut reversed = inputs.clone();
        assert!(reversed.test_reverse_call_markers(0));
        let mut rejected = EvaluationDb::new();
        let error = registry
            .run_workspace_evaluation(&reversed, &root, &evaluation, &mut rejected)
            .unwrap_err();
        assert!(error.to_string().contains("canonical claim order"));
        assert_eq!(rejected.derived_count(), 0);

        let mut duplicated = inputs.clone();
        assert!(duplicated.test_duplicate_call_marker(0));
        let mut rejected = EvaluationDb::new();
        let error = registry
            .run_workspace_evaluation(&duplicated, &root, &evaluation, &mut rejected)
            .unwrap_err();
        assert!(error.to_string().contains("repeats a claim"));
        assert_eq!(rejected.derived_count(), 0);

        let mut evaluated = EvaluationDb::new();
        registry
            .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
            .unwrap();
        let results = evaluated.finish().unwrap();
        let mut calls = results
            .derived_rows::<PanicCallObligation>(registry.schemas())
            .unwrap();
        calls.sort_by_key(|call| call.data.call_id());
        let matches = results
            .derived_rows::<PanicCallEvidenceMatch>(registry.schemas())
            .unwrap();
        let uses = results
            .derived_rows::<EvidenceUseRecord>(registry.schemas())
            .unwrap();

        assert_eq!(calls.len(), 4);
        assert_eq!(
            calls
                .iter()
                .map(|call| call.data.active_markers().len())
                .collect::<Vec<_>>(),
            vec![4, 4, 3, 3]
        );
        assert_eq!(matches.len(), 6);
        assert_eq!(uses.len(), matches.len());
        let mut match_counts = vec![0_u32; calls.len()];
        for matched in &matches {
            let call_index = usize::try_from(matched.data.witness_order()).unwrap();
            let call = &calls[call_index].data;
            match_counts[call_index] += 1;
            assert!(
                call.active_markers()
                    .iter()
                    .any(|marker| marker.claim() == matched.data.claim())
            );
        }
        assert_eq!(match_counts, [2, 2, 1, 1]);
        for usage in &uses {
            let call_index = usize::try_from(usage.data.witness_order()).unwrap();
            assert!(
                calls[call_index]
                    .data
                    .active_markers()
                    .iter()
                    .any(|marker| {
                        marker.claim() == usage.data.claim()
                            && usage.data.source() == calls[call_index].data.source()
                    })
            );
        }
        let synthetic = calls
            .iter()
            .filter(|call| {
                matches!(
                    call.data.resolution(),
                    PanicCallResolution::CallableEvidence { .. }
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(synthetic.len(), 2);
        for call in &calls {
            assert_eq!(call.data.source(), &call.data.occurrence().as_row());
            assert_eq!(call.data.endpoint(), call.data.occurrence());
            assert_eq!(call.data.evidence_group_data().key().owner(), &target_key);
            assert_eq!(call.data.boundary_kind(), &PanicCallBoundaryKind::PanicSink);
            assert_eq!(call.data.call_id(), call.data.evidence_rank());
            assert!(
                call.data
                    .active_markers()
                    .windows(2)
                    .all(|pair| pair[0].claim() < pair[1].claim())
            );
            assert!(call.data.active_markers().iter().all(|marker| {
                marker.trace().target() == marker.claim()
                    && marker.data().key().domain() == &DomainId::new("sniff-test.panic").unwrap()
                    && !matches!(
                        marker.data().rationale(),
                        "ingress marker 23" | "ingress marker 24"
                    )
            }));
        }
        for call in synthetic {
            let Some((key, resolution_kind)) = (match call.data.resolution() {
                PanicCallResolution::CallableEvidence {
                    key,
                    resolution_kind,
                    ..
                } => Some((key, resolution_kind)),
                PanicCallResolution::Persisted => None,
            }) else {
                panic!("filtered callable evidence must retain its resolution")
            };
            assert_eq!(*key, callable_key);
            assert_eq!(
                *resolution_kind,
                PanicCallableResolutionKind::FunctionPointerEvidence
            );
            let metadata = call.data.metadata_target().unwrap();
            assert_eq!(metadata.selection().role(), CallTargetRole::Runtime);
            assert_eq!(
                metadata.selection().authority(),
                super::super::call_model::PanicCallTargetAuthority::ConsumerRaw
            );
            assert_eq!(metadata.data().key(), &evidence_key);
            assert_eq!(call.data.trace_target(), metadata.selection().callable());
        }
        assert!(calls.iter().any(|call| {
            call.data
                .active_markers()
                .iter()
                .any(|marker| marker.data().selector() == &EvidenceClaimSelector::Unnamed)
                && call.data.active_markers().iter().any(|marker| {
                    marker.data().selector()
                        == &EvidenceClaimSelector::Named(String::from("Index_In-Bounds"))
                })
                && call.data.active_markers().iter().any(|marker| {
                    marker.data().selector()
                        == &EvidenceClaimSelector::Explicit(vec![String::from("compiler.bounds")])
                })
        }));
        assert!(
            inputs
                .traversal()
                .callable_resolutions()
                .windows(2)
                .all(|pair| {
                    pair[0].invocation() == pair[1].invocation()
                        && pair[0].evidence() == pair[1].evidence()
                        && pair[0].callable() == pair[1].callable()
                        && pair[0].key() == pair[1].key()
                        && pair[0].kind() == pair[1].kind()
                        && pair[0].order() != pair[1].order()
                })
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the two-artifact fixture proves the exact reconciled evidence group"
    )]
    fn reconciled_call_projects_the_exact_defining_evidence_group() {
        let registry = registry();
        let consumer = FunctionKey::new(definition(120), Some(instance(120)));
        let defining = FunctionKey::new(consumer.definition(), None);
        let make_artifact = |owner: FunctionKey, provenance: FunctionBodyProvenance, path: &str| {
            let mut builder = ArtifactDbBuilder::new();
            for descriptor in registry.schemas().descriptors().filter(|descriptor| {
                !matches!(descriptor.kind(), TableKind::Derived | TableKind::Issue)
            }) {
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
            if path == "crate::consumer" {
                attach_call_marker(
                    &mut builder,
                    &occurrence,
                    30,
                    "sniff-test.panic",
                    EvidenceClaimSelector::Unnamed,
                    true,
                    false,
                );
            }
            builder.finalize(registry.schemas()).unwrap()
        };
        let consumer_artifact = make_artifact(
            consumer,
            FunctionBodyProvenance::ConsumerInstantiation {
                consumer_stable_crate_id: 120,
            },
            "crate::consumer",
        );
        let defining_artifact = make_artifact(
            defining,
            FunctionBodyProvenance::DefiningArtifact,
            "dependency::generic",
        );
        let dependency = RustcArtifactId::new(1, "a".repeat(32));
        let root_generation = ManagedArtifactGeneration::in_memory(120, 0);
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
        let mut composition = CompositionRelationBuilder::new(
            prepared.root(),
            &workspace,
            registry.composition_relations(),
        )
        .unwrap();
        let emitted = prepared.emit(&mut composition).unwrap();
        let relations = composition.finalize().unwrap();
        let graph = WorkspaceRelationGraph::new(emitted.root(), &workspace, &relations).unwrap();
        let inputs = emitted
            .resolve_panic(&workspace, &graph, registry.composition_relations())
            .unwrap();
        let [reconciliation] = inputs.traversal().consumer_reconciliations() else {
            panic!("one consumer/defining reconciliation must resolve")
        };
        let root = inputs.root().clone();
        let evaluation = WorkspaceEvaluationView::from_graph(&workspace, graph).unwrap();
        let mut evaluated = EvaluationDb::new();
        registry
            .run_workspace_evaluation(&inputs, &root, &evaluation, &mut evaluated)
            .unwrap();
        let results = evaluated.finish().unwrap();
        let [call] = results
            .derived_rows::<PanicCallObligation>(registry.schemas())
            .unwrap()
            .try_into()
            .unwrap();
        let [matched] = results
            .derived_rows::<PanicCallEvidenceMatch>(registry.schemas())
            .unwrap()
            .try_into()
            .unwrap();
        let [usage] = results
            .derived_rows::<EvidenceUseRecord>(registry.schemas())
            .unwrap()
            .try_into()
            .unwrap();

        assert_eq!(call.data.occurrence().scope(), &consumer_scope);
        assert_eq!(call.data.evidence_group().scope(), &defining_scope);
        assert_eq!(
            call.data.evidence_group(),
            &reconciliation.defining_call_site().erase()
        );
        assert_eq!(
            call.data.evidence_group_data(),
            reconciliation.defining_call_site_data()
        );
        assert_ne!(
            call.data.evidence_group().scope(),
            call.data.occurrence().scope()
        );
        assert_eq!(call.data.trace_target(), call.data.occurrence());
        assert_eq!(matched.data.claim().scope(), &consumer_scope);
        assert_eq!(matched.data.obligation_source(), call.data.source());
        assert_eq!(matched.data.obligation_source().scope(), &consumer_scope);
        assert_eq!(matched.data.endpoint(), call.data.endpoint());
        assert_eq!(matched.data.endpoint().scope(), &consumer_scope);
        assert_eq!(matched.data.group(), call.data.evidence_group());
        assert_eq!(matched.data.group().scope(), &defining_scope);
        assert_eq!(matched.data.trace_target(), call.data.trace_target());
        assert_eq!(matched.data.trace(), call.data.trace());
        assert_eq!(matched.data.witness_order(), call.data.call_id());
        assert_eq!(
            matched.data.satisfied_requirements(),
            [PanicCallRequirementMatchId::unnamed()]
        );
        assert_eq!(usage.data.claim(), matched.data.claim());
        assert_eq!(usage.data.source(), call.data.source());
        assert_eq!(usage.data.source().scope(), &consumer_scope);
        assert_eq!(usage.data.endpoint(), call.data.endpoint());
        assert_eq!(usage.data.endpoint().scope(), &consumer_scope);
        assert_eq!(usage.data.group(), call.data.evidence_group());
        assert_eq!(usage.data.group().scope(), &defining_scope);
        assert_eq!(usage.data.trace(), call.data.trace());
        assert_eq!(usage.data.witness_order(), call.data.call_id());
        assert_eq!(
            call.data.boundary_kind(),
            &PanicCallBoundaryKind::Opaque {
                opaque_kind: PanicCallOpaqueKind::ExplicitOpaque,
                description: String::from("reconciled opaque call"),
            }
        );
    }
}
