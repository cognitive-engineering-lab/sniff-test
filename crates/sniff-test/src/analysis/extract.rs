//! Policy-neutral extraction of rustc bodies into artifact analysis IR.
//!
//! Extraction deliberately enumerates local bodies without consulting report
//! roots, namespace policy, lint levels, or documentation overrides. Callable
//! erasure and invocation facts retain stable join keys; the workspace
//! interpreter derives configured call-site edges only within each selected
//! root's reachable graph.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use reachability::{
    ArtifactScope, CallableEdgeInfo, DynDispatchVTableEdges, FnPointerEdges, MirBodyLocation,
    NoopReachabilityHooks, ReachabilityEdge, ReachabilityEdgeKind, ReachabilityGraph,
    ReachabilityHalt, ReachabilityIndex, ReachabilityNodeExpansion, ReachabilityNodeKind,
    ReachabilityOptions, ReachabilityRoot, ReachedEdge,
};
use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LOCAL_CRATE, LocalDefId};
use rustc_middle::mir::{AssertKind, BinOp};
use rustc_middle::ty::{AssocContainer, GenericArgs, Instance, InstanceKind, TyCtxt, TyKind};
use rustc_span::{ExpnId, ExpnKind, Pos, Span};

use super::collected::{
    CollectedArtifact, CollectedArtifactInput, CollectedCallMacroFrame, CollectedCallOccurrence,
    CollectedCallSite, CollectedCallSourceAnchor, CollectedCallTarget, CollectedEffectMacroFrame,
    CollectedEffectMarkerCandidate, CollectedEffectSite, CollectedEffectSourceAnchor,
    CollectedFunctionBody, CollectedMarkerCallCandidate, CollectedMarkerOccurrence,
    CollectedMirAssert, CollectedPanicContract, CollectedProgram, CollectedSafetyContract,
    CollectedUnsafeOperation, CollectedUnsafeOperationMacroFrame,
    CollectedUnsafeOperationMarkerCandidate, CollectedUnsafeOperationSourceAnchor,
};
use super::facts::collection::collect_artifact_facts;
use super::facts::encoded::ArtifactFactIr;
use super::facts::evaluation::DomainId;
use super::facts::human::EvidenceClaimSelector;
use super::facts::human::markers::{
    CallOccurrenceHasMarkerClaimCandidate, EffectSiteHasMarkerClaimCandidate, MarkerClaimEntity,
    MarkerClaimKey, MarkerOccurrenceEntity, MarkerOccurrenceKey,
    UnsafeOperationHasMarkerClaimCandidate,
};
use super::facts::panic::contracts::PanicRequirement;
use super::facts::panic::model::{BinaryOverflowOperation, MirAssertKind};
use super::facts::program::topology::{
    CallAttributionRole, CallKind, CallMacroExpansionEntity, CallMacroExpansionKey,
    CallOccurrenceEntity, CallOccurrenceKey, CallSiteEntity, CallSiteKey, CallSourceAnchorRole,
    CallTargetRole, CallableEntity, CallableKey, SafetyEffectGroupEntity, SafetyEffectGroupKey,
};
use super::facts::program::{
    EffectSiteEntity, EffectSiteKey, EffectSourceAnchorRole, FunctionBodyProvenance,
    FunctionEntity, FunctionKey, MacroExpansionEntity, MacroExpansionKey, SourceAnchorEntity,
    SourceAnchorKey, SourceFileEntity,
};
use super::facts::safety::SafetyRequirement;
use super::facts::safety::operations::{
    UnsafeOperationEntity, UnsafeOperationKey, UnsafeOperationMacroExpansionEntity,
    UnsafeOperationMacroExpansionKey, UnsafeOperationSourceAnchorRole,
};
use super::ir::{
    ArtifactAnalysisIr, CallEdgeIr, CallEdgeKindIr, CallId, CallSiteId, CallTargetIr,
    CallableAttributionIr, CallableKeyIr, ContractRequirementIr, EffectFactIr, EffectId,
    EffectKindIr, FunctionAttributesIr, FunctionBodyIr, FunctionBodyProvenanceIr,
    FunctionContractsIr, FunctionId, FunctionTargetIr, MacroExpansionFrameIr, MarkerId, MarkerIr,
    MarkerKindIr, MarkerProbingIr, MarkerSatisfactionIr, MarkerTargetIr, OpaqueTargetIr,
    RawContractIr, SafetyEffectGroupId, SourceFileId, SourceFileIr, SourceRangeIr,
    StableDefPathHash, StableInstanceHash, StableTypeHash,
};
use super::source::{source_filename, stable_source_file_id};
use crate::config::MarkerProbing;
use crate::contracts::{
    ContractDocSummary, panic_contract_doc_summary_from_attrs,
    safety_contract_doc_summary_from_attrs,
};
use crate::namespace::{StableExpansionHash, canonical_namespace, namespace_candidates};
use crate::panics::CompilerAssertKind;
use crate::safety::{
    RawSafetyFacts, RawSafetyOpFact, call_identity_def_id, collect_raw_safety_facts,
    fn_def_is_unsafe,
};
use crate::source_markers::{
    EffectMarkerBlock, MarkerOrigin, panic_effect_edge_marker_block,
    safety_effect_edge_marker_block, safety_span_marker_block,
};

/// Failure to produce complete, structurally valid IR for a required body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtractError {
    message: String,
}

impl ExtractError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ExtractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ExtractError {}

/// Atomic result of one policy-neutral compiler extraction.
///
/// Both halves are structurally validated before this value is returned.
pub(crate) struct ExtractedArtifactBundle {
    pub(crate) legacy_ir: ArtifactAnalysisIr,
    pub(crate) facts: ArtifactFactIr,
}

/// Extracts and validates legacy and typed policy-neutral facts atomically.
///
/// Failure to collect or finalize typed facts fails the production extraction
/// rather than silently returning only the legacy half of the artifact.
pub(crate) fn extract_artifact_bundle(
    tcx: TyCtxt<'_>,
) -> Result<ExtractedArtifactBundle, ExtractError> {
    let parts = extract_artifact_parts(tcx)?;
    let facts = collect_artifact_facts(&parts.collected).map_err(|error| {
        ExtractError::new(format!(
            "failed to collect permanent typed artifact facts: {error}"
        ))
    })?;
    Ok(ExtractedArtifactBundle {
        legacy_ir: parts.legacy,
        facts,
    })
}

struct ExtractedArtifactParts {
    collected: CollectedArtifact,
    legacy: ArtifactAnalysisIr,
}

#[derive(Clone)]
struct PendingTypedMirAssert {
    function: FunctionId,
    location: MirBodyLocation,
    legacy_effect_key: String,
    kind: MirAssertKind,
    presentation_anchor: Option<SourceAnchorKey>,
    expanded_anchor: Option<SourceAnchorKey>,
    macro_expansions: Vec<ExtractedMacroExpansionFrame>,
}

/// Compiler-owned identity and presentation data for one real macro frame.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExtractedMacroExpansionFrame {
    expansion_hash: StableExpansionHash,
    macro_definition: StableDefPathHash,
    display_path: String,
    source_range: Option<SourceRangeIr>,
}

impl ExtractedMacroExpansionFrame {
    fn new(
        expansion_hash: StableExpansionHash,
        macro_definition: StableDefPathHash,
        display_path: impl Into<String>,
        source_range: Option<SourceRangeIr>,
    ) -> Self {
        Self {
            expansion_hash,
            macro_definition,
            display_path: display_path.into(),
            source_range,
        }
    }

    const fn expansion_hash(&self) -> StableExpansionHash {
        self.expansion_hash
    }

    const fn macro_definition(&self) -> StableDefPathHash {
        self.macro_definition
    }

    fn display_path(&self) -> &str {
        &self.display_path
    }

    const fn source_range(&self) -> Option<&SourceRangeIr> {
        self.source_range.as_ref()
    }
}

#[derive(Clone)]
struct PendingTypedUnsafeOperation {
    operation: UnsafeOperationEntity,
    safety_effect_group: SafetyEffectGroupKey,
    presentation_anchor: Option<SourceAnchorKey>,
    expanded_anchor: Option<SourceAnchorKey>,
    macro_expansions: Vec<ExtractedMacroExpansionFrame>,
}

fn extract_artifact_parts(tcx: TyCtxt<'_>) -> Result<ExtractedArtifactParts, ExtractError> {
    let required_owners = analyzable_local_fn_defs(tcx).collect::<Vec<_>>();
    ensure_required_thir_is_available(tcx, &required_owners)?;

    let mut sources = ExtractionSources::default();
    let mut bodies = BTreeMap::<FunctionId, PendingBody>::new();
    let raw_safety_facts = collect_raw_safety_facts(tcx);
    let mut safety_groups = RawSafetyGroupResolver::new(&raw_safety_facts);
    let mut pending_typed_assertions = Vec::new();
    let mut pending_typed_unsafe_operations = Vec::new();
    let mut next_typed_unsafe_operation = BTreeMap::new();

    for owner in &required_owners {
        let function = FunctionId::generic(StableDefPathHash::from_def_id(tcx, owner.to_def_id()));
        ensure_body(
            tcx,
            &mut sources.legacy,
            &mut bodies,
            function,
            owner.to_def_id(),
            FunctionBodyProvenanceIr::DefiningArtifact,
        )?;
    }

    collect_reachability_mode(
        tcx,
        &required_owners,
        extraction_options(),
        &mut sources,
        &mut bodies,
        &mut safety_groups,
        &mut pending_typed_assertions,
    )?;

    attach_raw_unsafe_operations(
        tcx,
        raw_safety_facts.operations,
        &mut sources,
        &mut bodies,
        &mut pending_typed_unsafe_operations,
        &mut next_typed_unsafe_operation,
    )?;

    let collected = build_collected_artifact(
        &sources,
        &bodies,
        &pending_typed_assertions,
        pending_typed_unsafe_operations,
    )?;

    let finished_bodies = bodies
        .into_values()
        .filter(|body| body.projects_to_legacy)
        .map(PendingBody::finish)
        .collect::<Result<Vec<_>, _>>()?;
    let mut functions = Vec::with_capacity(finished_bodies.len());
    for finished in finished_bodies {
        functions.push(finished.body);
    }
    let legacy = ArtifactAnalysisIr::new(functions, sources.legacy.into_files())
        .map_err(|error| ExtractError::new(format!("extracted artifact IR is invalid: {error}")))?;
    Ok(ExtractedArtifactParts { collected, legacy })
}

fn analyzable_local_fn_defs(tcx: TyCtxt<'_>) -> impl Iterator<Item = LocalDefId> + '_ {
    tcx.hir_body_owners()
        .filter(move |owner| matches!(tcx.def_kind(*owner), DefKind::Fn | DefKind::AssocFn))
}

fn ensure_required_thir_is_available(
    tcx: TyCtxt<'_>,
    owners: &[LocalDefId],
) -> Result<(), ExtractError> {
    for owner in owners {
        if tcx.hir_maybe_body_owned_by(*owner).is_none() {
            return Err(ExtractError::new(format!(
                "required body `{}` is not available",
                canonical_namespace(tcx, owner.to_def_id())
            )));
        }
        if tcx.thir_body(*owner).is_err() {
            return Err(ExtractError::new(format!(
                "failed to obtain THIR for required body `{}`",
                canonical_namespace(tcx, owner.to_def_id())
            )));
        }
    }
    Ok(())
}

fn extraction_options() -> ReachabilityOptions {
    ReachabilityOptions {
        node_limit: None,
        artifact_scope: ArtifactScope::AllArtifacts,
        dyn_dispatch_vtable_edges: DynDispatchVTableEdges::CastSites,
        fn_pointer_edges: FnPointerEdges::ReifySites,
    }
}

fn reachability_halt_description(halt: &ReachabilityHalt) -> String {
    match halt {
        ReachabilityHalt::NodeLimitReached { limit } => {
            format!("artifact reachability analysis reached the configured node limit ({limit})")
        }
    }
}

const fn reachability_edge_description(kind: ReachabilityEdgeKind) -> &'static str {
    match kind {
        ReachabilityEdgeKind::DirectCall => "direct call",
        ReachabilityEdgeKind::TailCall => "tail call",
        ReachabilityEdgeKind::FnPointerReify => "function-to-pointer conversion",
        ReachabilityEdgeKind::ClosureFnPointerReify => "closure-to-pointer conversion",
        ReachabilityEdgeKind::FnPointerCallTarget => "function-pointer call target",
        ReachabilityEdgeKind::DynObjectCast => "trait-object conversion",
        ReachabilityEdgeKind::VTableEntry => "dynamic-dispatch method",
        ReachabilityEdgeKind::DynDispatchVTableEntry => "dynamic call target",
        ReachabilityEdgeKind::MacroExpansion => "macro expansion",
        ReachabilityEdgeKind::ConstBody => "constant body",
        ReachabilityEdgeKind::CoroutineBody => "async or coroutine body",
        ReachabilityEdgeKind::Assert => "compiler check",
        ReachabilityEdgeKind::IndirectCall => "indirect call",
    }
}

fn collect_reachability_mode(
    tcx: TyCtxt<'_>,
    roots: &[LocalDefId],
    options: ReachabilityOptions,
    sources: &mut ExtractionSources,
    bodies: &mut BTreeMap<FunctionId, PendingBody>,
    safety_groups: &mut RawSafetyGroupResolver,
    typed_assertions: &mut Vec<PendingTypedMirAssert>,
) -> Result<(), ExtractError> {
    let mut reachability = ReachabilityIndex::new(tcx);
    let hooks = NoopReachabilityHooks;
    let Some(snapshot) = reachability.query_many(
        roots.iter().copied().map(ReachabilityRoot::from),
        &hooks,
        options,
    ) else {
        return Ok(());
    };
    let view = reachability.graph().view(&snapshot);

    for (root, reached_root) in roots.iter().zip(view.roots()) {
        if reached_root.expansion() != Some(ReachabilityNodeExpansion::Expanded) {
            return Err(ExtractError::new(format!(
                "required body `{}` could not be expanded",
                canonical_namespace(tcx, root.to_def_id())
            )));
        }
    }
    if let Some(halt) = view.halt() {
        return Err(ExtractError::new(reachability_halt_description(halt)));
    }

    for node in view.nodes() {
        let Some(instance) = node.instance() else {
            continue;
        };
        if node.expansion() != Some(ReachabilityNodeExpansion::Expanded) {
            continue;
        }
        let function = body_id_for_instance(tcx, instance);
        let def_id = instance.def_id();
        ensure_body(
            tcx,
            &mut sources.legacy,
            bodies,
            function,
            def_id,
            body_provenance(tcx, def_id),
        )?;
    }

    for reached in view.edges() {
        if reached.kind() == ReachabilityEdgeKind::MacroExpansion {
            continue;
        }
        collect_edge(
            tcx,
            view.graph(),
            reached,
            sources,
            bodies,
            safety_groups,
            typed_assertions,
        )?;
    }
    Ok(())
}

fn body_id_for_instance<'tcx>(tcx: TyCtxt<'tcx>, instance: Instance<'tcx>) -> FunctionId {
    let def_id = instance.def_id();
    if def_id.is_local()
        && matches!(instance.def, InstanceKind::Item(_))
        && matches!(tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn)
        && instance == Instance::new_raw(def_id, GenericArgs::identity_for_item(tcx, def_id))
    {
        FunctionId::generic(StableDefPathHash::from_def_id(tcx, def_id))
    } else {
        FunctionId::exact(
            StableDefPathHash::from_def_id(tcx, def_id),
            StableInstanceHash::from_instance(tcx, instance),
        )
    }
}

fn body_provenance(tcx: TyCtxt<'_>, def_id: DefId) -> FunctionBodyProvenanceIr {
    if def_id.is_local() {
        FunctionBodyProvenanceIr::DefiningArtifact
    } else {
        FunctionBodyProvenanceIr::ConsumerInstantiation {
            consumer_stable_crate_id: tcx.stable_crate_id(LOCAL_CRATE).as_u64(),
        }
    }
}

fn edge_origin<'tcx>(
    graph: &ReachabilityGraph<'tcx>,
    edge: &ReachabilityEdge,
) -> Result<Instance<'tcx>, ExtractError> {
    graph
        .node_instance(edge.origin)
        .ok_or_else(|| ExtractError::new("reachability edge has no function-instance origin"))
}

fn collect_edge<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    reached: ReachedEdge<'_, 'tcx>,
    sources: &mut ExtractionSources,
    bodies: &mut BTreeMap<FunctionId, PendingBody>,
    safety_groups: &mut RawSafetyGroupResolver,
    typed_assertions: &mut Vec<PendingTypedMirAssert>,
) -> Result<(), ExtractError> {
    let edge = reached.edge();
    let origin = edge_origin(graph, edge)?;
    let origin_def_id = origin.def_id();
    let body_id = body_id_for_instance(tcx, origin);
    ensure_body(
        tcx,
        &mut sources.legacy,
        bodies,
        body_id,
        origin_def_id,
        body_provenance(tcx, origin_def_id),
    )?;
    let (key, provenance, pending_call) =
        pending_call_for_edge(tcx, graph, reached, origin, sources, safety_groups)?;
    let body = bodies
        .get_mut(&body_id)
        .expect("origin body was inserted before edge collection");
    let call_index = insert_or_merge_call(body, pending_call)?;
    let panic_requirements = body.calls[call_index].panic_requirements.clone();
    let safety_requirements = body.calls[call_index].safety_requirements.clone();

    let effect_key = collect_compiler_assert_effect(
        graph,
        edge,
        body,
        &key,
        provenance.source_range.as_ref(),
        provenance.expanded_range.as_ref(),
        &provenance.macro_expansions,
    );
    if let Some(effect_key) = effect_key.as_deref() {
        capture_typed_compiler_assert(
            graph,
            edge,
            body_id,
            effect_key,
            &provenance,
            typed_assertions,
        );
    }

    collect_edge_markers(
        tcx,
        graph,
        edge,
        &mut sources.legacy,
        body,
        &key,
        effect_key.as_deref(),
        &panic_requirements,
        &safety_requirements,
    )
}

fn pending_call_for_edge<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    reached: ReachedEdge<'_, 'tcx>,
    origin: Instance<'tcx>,
    sources: &mut ExtractionSources,
    safety_groups: &mut RawSafetyGroupResolver,
) -> Result<(String, EdgeSourceProvenance, PendingCall), ExtractError> {
    let edge = reached.edge();
    let provenance = edge_source_provenance(tcx, reached, &mut sources.legacy, &mut sources.typed)?;
    let callee_range = edge
        .callee_span
        .map(|span| sources.legacy.range(tcx, span))
        .transpose()?
        .flatten();
    let target = call_target(tcx, graph, edge, &mut sources.legacy)?;
    let groups = if is_reachability_call(edge.kind) {
        safety_groups.group_for_call(
            origin.def_id(),
            edge.span,
            reachability_call_identity(tcx, reached),
        )
    } else {
        safety_groups.group_for_structural_edge(origin.def_id(), edge.span)
    }
    .map_err(|error| edge_grouping_error(tcx, origin.def_id(), edge, &error))?;
    let source_target = source_call_target(tcx, groups.source_callee, &mut sources.legacy)?;
    let signature_requires_unsafe =
        target_function(&target).is_some_and(|target| target.attributes.is_unsafe);
    let callable_declarations = pending_callable_declarations(&target, source_target.as_ref())?;
    let panic_requirements = panic_requirements(source_target.as_ref(), &target);
    let safety_requirements = safety_requirements(source_target.as_ref(), &target);
    let key = edge_key(
        tcx,
        graph,
        edge,
        provenance.expanded_range.as_ref(),
        callee_range.as_ref(),
        &target,
    );
    let kind = call_edge_kind(edge.kind);
    let presentation_anchor = provenance
        .source_range
        .as_ref()
        .map(SourceTable::anchor_from_range);
    let expanded_anchor = provenance
        .expanded_range
        .as_ref()
        .map(SourceTable::anchor_from_range);
    let callee_anchor = callee_range.as_ref().map(SourceTable::anchor_from_range);
    let applicable_attribution = callable_attribution_for_edge(edge.kind);
    let callable_keys = callable_keys(tcx, graph, reached);
    let targets = collected_call_targets(&target, source_target.as_ref());
    let requires_unsafe = edge_requires_unsafe(tcx, graph, reached, signature_requires_unsafe);
    let stable_sort_key = PendingCallSortKey {
        kind,
        presentation_anchor: presentation_anchor.clone(),
        expanded_anchor: expanded_anchor.clone(),
        callee_anchor: callee_anchor.clone(),
        macro_expansions: provenance
            .typed_macro_expansions
            .iter()
            .map(ExtractedMacroExpansionFrame::expansion_hash)
            .collect(),
        targets: targets
            .iter()
            .map(|target| (target.role(), *target.callable()))
            .collect(),
        compiler_assert_site: match &graph.node(edge.target).kind {
            ReachabilityNodeKind::CompilerAssert { site, .. } => Some(*site),
            ReachabilityNodeKind::Instance(_)
            | ReachabilityNodeKind::IndirectCall { .. }
            | ReachabilityNodeKind::DynObjectCast { .. }
            | ReachabilityNodeKind::MacroExpansion { .. } => None,
        },
        call_site: groups.call_site.index(),
        safety_effect_group: groups.safety_effect_group.index(),
        requires_unsafe,
        inside_builtin_unsafe: groups.inside_builtin_unsafe,
    };
    let pending = PendingCall {
        key: key.clone(),
        stable_sort_key,
        call_site: groups.call_site.index(),
        kind,
        safety_effect_group: groups.safety_effect_group.index(),
        requires_unsafe,
        inside_builtin_unsafe: groups.inside_builtin_unsafe,
        presentation_anchor,
        expanded_anchor,
        callee_anchor,
        applicable_attribution,
        callable_keys,
        targets,
        callable_declarations,
        opaque_target_description: opaque_target_description(&target),
        panic_requirements,
        safety_requirements,
        typed_macro_expansions: provenance.typed_macro_expansions.clone(),
        legacy: PendingLegacyCallProjection {
            macro_expansions: provenance.macro_expansions.clone(),
            source_target,
            target,
        },
    };
    Ok((key, provenance, pending))
}

struct EdgeSourceProvenance {
    source_range: Option<SourceRangeIr>,
    expanded_range: Option<SourceRangeIr>,
    macro_expansions: Vec<MacroExpansionFrameIr>,
    typed_macro_expansions: Vec<ExtractedMacroExpansionFrame>,
}

fn edge_source_provenance(
    tcx: TyCtxt<'_>,
    reached: ReachedEdge<'_, '_>,
    sources: &mut SourceTable,
    typed_sources: &mut SourceTable,
) -> Result<EdgeSourceProvenance, ExtractError> {
    let edge = reached.edge();
    let expanded = sources.range(tcx, edge.span)?;
    let source = sources
        .range(tcx, edge.span.source_callsite())?
        .or_else(|| expanded.clone());
    let expansions = edge_macro_expansions(tcx, reached, sources)?;
    let typed_expansions = typed_macro_expansions(tcx, edge.span, typed_sources)?;
    Ok(EdgeSourceProvenance {
        source_range: source,
        expanded_range: expanded,
        macro_expansions: expansions,
        typed_macro_expansions: typed_expansions,
    })
}

fn capture_typed_compiler_assert(
    graph: &ReachabilityGraph<'_>,
    edge: &ReachabilityEdge,
    function: FunctionId,
    legacy_effect_key: &str,
    provenance: &EdgeSourceProvenance,
    assertions: &mut Vec<PendingTypedMirAssert>,
) {
    let ReachabilityNodeKind::CompilerAssert { message, site, .. } = &graph.node(edge.target).kind
    else {
        return;
    };
    let kind = classify_mir_assert(message.as_ref());
    assertions.push(PendingTypedMirAssert {
        function,
        location: *site,
        legacy_effect_key: legacy_effect_key.to_owned(),
        kind,
        presentation_anchor: provenance
            .source_range
            .as_ref()
            .map(SourceTable::anchor_from_range),
        expanded_anchor: provenance
            .expanded_range
            .as_ref()
            .map(SourceTable::anchor_from_range),
        macro_expansions: provenance.typed_macro_expansions.clone(),
    });
}

fn classify_mir_assert<O>(assertion: &AssertKind<O>) -> MirAssertKind {
    match assertion {
        AssertKind::BoundsCheck { .. } => MirAssertKind::BoundsCheck,
        AssertKind::Overflow(operation, ..) => classify_overflow_operation(*operation),
        AssertKind::OverflowNeg(..) => MirAssertKind::OverflowNegation,
        AssertKind::DivisionByZero(..) => MirAssertKind::DivisionByZero,
        AssertKind::RemainderByZero(..) => MirAssertKind::RemainderByZero,
        AssertKind::ResumedAfterReturn(..) => MirAssertKind::ResumedAfterReturn,
        AssertKind::ResumedAfterPanic(..) => MirAssertKind::ResumedAfterPanic,
        AssertKind::ResumedAfterDrop(..) => MirAssertKind::ResumedAfterDrop,
        AssertKind::MisalignedPointerDereference { .. } => {
            MirAssertKind::MisalignedPointerDereference
        }
        AssertKind::NullPointerDereference => MirAssertKind::NullPointerDereference,
        AssertKind::InvalidEnumConstruction(..) => MirAssertKind::InvalidEnumConstruction,
    }
}

const fn classify_overflow_operation(operation: BinOp) -> MirAssertKind {
    match operation {
        BinOp::Add => MirAssertKind::Overflow(BinaryOverflowOperation::Addition),
        BinOp::Sub => MirAssertKind::Overflow(BinaryOverflowOperation::Subtraction),
        BinOp::Mul => MirAssertKind::Overflow(BinaryOverflowOperation::Multiplication),
        BinOp::Div => MirAssertKind::Overflow(BinaryOverflowOperation::Division),
        BinOp::Rem => MirAssertKind::Overflow(BinaryOverflowOperation::Remainder),
        BinOp::Shl => MirAssertKind::Overflow(BinaryOverflowOperation::LeftShift),
        BinOp::Shr => MirAssertKind::Overflow(BinaryOverflowOperation::RightShift),
        _ => MirAssertKind::OpaqueOverflow,
    }
}

fn source_call_target(
    tcx: TyCtxt<'_>,
    source_callee: Option<DefId>,
    sources: &mut SourceTable,
) -> Result<Option<PendingFunctionTarget>, ExtractError> {
    source_callee
        .map(|def_id| function_target_for_def(tcx, def_id, sources))
        .transpose()
}

fn reachability_call_identity(tcx: TyCtxt<'_>, reached: ReachedEdge<'_, '_>) -> Option<DefId> {
    let def_id = match reached.target().kind() {
        ReachabilityNodeKind::Instance(instance) => Some(instance.def_id()),
        ReachabilityNodeKind::IndirectCall { callee_ty } => match callee_ty.kind() {
            TyKind::FnDef(def_id, _) => Some(*def_id),
            _ => None,
        },
        ReachabilityNodeKind::CompilerAssert { .. }
        | ReachabilityNodeKind::DynObjectCast { .. }
        | ReachabilityNodeKind::MacroExpansion { .. } => None,
    }?;
    Some(call_identity_def_id(tcx, def_id))
}

fn is_reachability_call(kind: ReachabilityEdgeKind) -> bool {
    matches!(
        kind,
        ReachabilityEdgeKind::DirectCall
            | ReachabilityEdgeKind::TailCall
            | ReachabilityEdgeKind::FnPointerCallTarget
            | ReachabilityEdgeKind::DynDispatchVTableEntry
            | ReachabilityEdgeKind::IndirectCall
    )
}

fn insert_or_merge_call(
    body: &mut PendingBody,
    mut call: PendingCall,
) -> Result<usize, ExtractError> {
    let Some(index) = body
        .calls
        .iter()
        .position(|pending| pending.key == call.key)
    else {
        body.calls.push(call);
        return Ok(body.calls.len() - 1);
    };
    let existing = &mut body.calls[index];
    if existing.stable_sort_key != call.stable_sort_key
        || existing.call_site != call.call_site
        || existing.safety_effect_group != call.safety_effect_group
        || existing.presentation_anchor != call.presentation_anchor
        || existing.expanded_anchor != call.expanded_anchor
        || existing.callee_anchor != call.callee_anchor
        || existing.typed_macro_expansions != call.typed_macro_expansions
        || existing.legacy.macro_expansions != call.legacy.macro_expansions
        || existing.requires_unsafe != call.requires_unsafe
        || existing.inside_builtin_unsafe != call.inside_builtin_unsafe
        || existing.kind != call.kind
        || existing.targets != call.targets
        || existing.callable_declarations != call.callable_declarations
        || existing.opaque_target_description != call.opaque_target_description
        || existing.panic_requirements != call.panic_requirements
        || existing.safety_requirements != call.safety_requirements
        || existing.legacy.source_target != call.legacy.source_target
        || existing.legacy.target != call.legacy.target
    {
        return Err(ExtractError::new(
            "one call edge resolved to inconsistent raw call facts",
        ));
    }
    for applicability in call.applicable_attribution.drain(..) {
        push_unique(&mut existing.applicable_attribution, applicability);
    }
    for callable in call.callable_keys.drain(..) {
        push_unique(&mut existing.callable_keys, callable);
    }
    Ok(index)
}

fn collect_compiler_assert_effect(
    graph: &ReachabilityGraph<'_>,
    edge: &ReachabilityEdge,
    body: &mut PendingBody,
    call_key: &str,
    source_range: Option<&SourceRangeIr>,
    expanded_range: Option<&SourceRangeIr>,
    macro_expansions: &[MacroExpansionFrameIr],
) -> Option<String> {
    let ReachabilityNodeKind::CompilerAssert { message, .. } = &graph.node(edge.target).kind else {
        return None;
    };
    let effect_key = format!("compiler-assert:{call_key}");
    if !body.effects.iter().any(|effect| effect.key == effect_key) {
        body.effects.push(PendingEffect {
            key: effect_key.clone(),
            effect: EffectFactIr {
                id: EffectId::new(0),
                safety_effect_group: None,
                source_range: source_range.cloned(),
                expanded_range: expanded_range.cloned(),
                macro_expansions: macro_expansions.to_vec(),
                kind: EffectKindIr::CompilerAssert {
                    kind: CompilerAssertKind::from(message.as_ref()),
                },
            },
        });
    }
    Some(effect_key)
}

fn edge_macro_expansions(
    tcx: TyCtxt<'_>,
    reached: ReachedEdge<'_, '_>,
    sources: &mut SourceTable,
) -> Result<Vec<MacroExpansionFrameIr>, ExtractError> {
    let provenance_edge = reached.parent_edge().unwrap_or(reached);
    let mut source = provenance_edge.source();
    let mut frames = Vec::new();
    while let ReachabilityNodeKind::MacroExpansion { def_id } = source.kind() {
        let Some(predecessor) = source.predecessor_edge() else {
            return Err(ExtractError::new(
                "macro-expansion node has no reached predecessor edge",
            ));
        };
        if predecessor.kind() != ReachabilityEdgeKind::MacroExpansion {
            return Err(ExtractError::new(
                "macro-expansion node was reached by a non-expansion edge",
            ));
        }
        frames.push(MacroExpansionFrameIr {
            macro_def: StableDefPathHash::from_def_id(tcx, *def_id),
            display_path: canonical_namespace(tcx, *def_id),
            source_range: sources.range(tcx, predecessor.span())?,
        });
        source = predecessor.source();
    }
    frames.reverse();
    Ok(frames)
}

fn span_macro_expansions(
    tcx: TyCtxt<'_>,
    span: Span,
    sources: &mut SourceTable,
) -> Result<Vec<MacroExpansionFrameIr>, ExtractError> {
    let mut raw_frames = span
        .macro_backtrace()
        .filter_map(|expansion| {
            expansion
                .macro_def_id
                .map(|def_id| (def_id, expansion.call_site))
        })
        .collect::<Vec<_>>();
    raw_frames.reverse();
    raw_frames.dedup_by(|left, right| left.0 == right.0 && left.1.source_equal(right.1));
    raw_frames
        .into_iter()
        .map(|(def_id, call_site)| {
            Ok(MacroExpansionFrameIr {
                macro_def: StableDefPathHash::from_def_id(tcx, def_id),
                display_path: canonical_namespace(tcx, def_id),
                source_range: sources.range(tcx, call_site)?,
            })
        })
        .collect()
}

/// Returns real macro marks in rustc's outer-to-inner syntax-context order.
///
/// Compiler desugarings and AST passes are deliberately absent. Every retained
/// frame carries rustc's stable expansion hash, so downstream typed rows never
/// infer invocation identity from a span, display string, or session-local id.
/// In particular, equal definition/call-site pairs are not deduplicated:
/// rustc's expansion disambiguator is the identity of repeated invocations.
fn typed_macro_expansions(
    tcx: TyCtxt<'_>,
    span: Span,
    sources: &mut SourceTable,
) -> Result<Vec<ExtractedMacroExpansionFrame>, ExtractError> {
    real_macro_expansion_chain(span)
        .into_iter()
        .map(|expansion| (expansion, expansion.expn_data()))
        .map(|(expansion, data)| {
            let macro_definition = data.macro_def_id.ok_or_else(|| {
                ExtractError::new(format!(
                    "real macro expansion {} has no macro definition identity",
                    StableExpansionHash::from_expn_id(expansion)
                ))
            })?;
            Ok(ExtractedMacroExpansionFrame::new(
                StableExpansionHash::from_expn_id(expansion),
                StableDefPathHash::from_def_id(tcx, macro_definition),
                canonical_namespace(tcx, macro_definition),
                sources.range(tcx, data.call_site)?,
            ))
        })
        .collect()
}

/// Returns every real macro ancestor of the innermost syntax-context mark.
///
/// `SyntaxContext::marks` can omit an outer expansion when the inner macro was
/// invoked by tokens produced in that outer macro. The expansion-parent chain
/// remains authoritative for that nesting and is also the identity used by
/// marker occurrences, so use the same chain for endpoint topology.
fn real_macro_expansion_chain(span: Span) -> Vec<ExpnId> {
    let Some(mut expansion) = span
        .ctxt()
        .marks()
        .into_iter()
        .rev()
        .find_map(|(expansion, _)| {
            matches!(expansion.expn_data().kind, ExpnKind::Macro(..)).then_some(expansion)
        })
    else {
        return Vec::new();
    };
    let mut path = Vec::new();
    while expansion != ExpnId::root() {
        let data = expansion.expn_data();
        if matches!(data.kind, ExpnKind::Macro(..)) {
            path.push(expansion);
        }
        expansion = data.parent;
    }
    path.reverse();
    path
}

#[allow(clippy::too_many_arguments)]
fn collect_edge_markers(
    tcx: TyCtxt<'_>,
    graph: &ReachabilityGraph<'_>,
    edge: &ReachabilityEdge,
    sources: &mut SourceTable,
    body: &mut PendingBody,
    call_key: &str,
    effect_key: Option<&str>,
    panic_requirements: &[ContractRequirementIr],
    safety_requirements: &[ContractRequirementIr],
) -> Result<(), ExtractError> {
    for (probing, applicable_probing) in probing_modes() {
        if let Some(marker) = panic_effect_edge_marker_block(tcx, graph, edge, probing) {
            let (target, requirements) = if let Some(effect_key) = effect_key {
                (
                    PendingMarkerTarget::Effect(effect_key.to_owned()),
                    Vec::new(),
                )
            } else {
                (
                    PendingMarkerTarget::Call(call_key.to_owned()),
                    panic_requirements.to_vec(),
                )
            };
            push_effect_marker(
                tcx,
                sources,
                body,
                MarkerKindIr::PanicJustification,
                target.clone(),
                Some(match target {
                    PendingMarkerTarget::Call(key) => PendingTypedMarkerTarget::Call(key),
                    PendingMarkerTarget::Effect(key) => PendingTypedMarkerTarget::Effect(key),
                    PendingMarkerTarget::Function => {
                        return Err(ExtractError::new(
                            "effect marker unexpectedly targeted a function declaration",
                        ));
                    }
                }),
                marker,
                applicable_probing,
                requirements,
            )?;
        }
        if let Some(marker) = safety_effect_edge_marker_block(tcx, graph, edge, probing) {
            push_effect_marker(
                tcx,
                sources,
                body,
                MarkerKindIr::SafetyJustification,
                PendingMarkerTarget::Call(call_key.to_owned()),
                Some(PendingTypedMarkerTarget::Call(call_key.to_owned())),
                marker,
                applicable_probing,
                safety_requirements.to_vec(),
            )?;
        }
    }
    Ok(())
}

fn edge_grouping_error(
    tcx: TyCtxt<'_>,
    origin: DefId,
    edge: &ReachabilityEdge,
    error: &ExtractError,
) -> ExtractError {
    let source_map = tcx.sess.source_map();
    let location = source_map.span_to_diagnostic_string(edge.span);
    let callee_location = edge.callee_span.map_or_else(String::new, |span| {
        format!(", callee at {}", source_map.span_to_diagnostic_string(span))
    });
    ExtractError::new(format!(
        "failed to associate the {} in `{}` at {location}{callee_location} with its source-level safety scope: {error}",
        reachability_edge_description(edge.kind),
        canonical_namespace(tcx, origin),
    ))
}

fn edge_requires_unsafe<'view, 'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &'view ReachabilityGraph<'tcx>,
    reached: ReachedEdge<'view, 'tcx>,
    signature_requires_unsafe: bool,
) -> bool {
    let caller = reached.origin().instance();
    let target_requires_unsafe = if edge_uses_target_unsafe_requirement(reached.kind()) {
        reached
            .target()
            .instance()
            .map_or(signature_requires_unsafe, |callee| {
                fn_def_call_requires_unsafe(tcx, callee.def_id(), signature_requires_unsafe, caller)
            })
    } else {
        false
    };
    let callable_requires_unsafe = if edge_uses_callable_unsafe_requirement(reached.kind()) {
        match graph.edge_callable(reached.id()) {
            Some(CallableEdgeInfo::FnPointer { fn_ptr_ty }) => {
                callable_ty_requires_unsafe(tcx, fn_ptr_ty, caller)
            }
            Some(CallableEdgeInfo::DynDispatch { .. }) | None => match reached.target().kind() {
                ReachabilityNodeKind::IndirectCall { callee_ty } => {
                    callable_ty_requires_unsafe(tcx, *callee_ty, caller)
                }
                ReachabilityNodeKind::Instance(_)
                | ReachabilityNodeKind::CompilerAssert { .. }
                | ReachabilityNodeKind::MacroExpansion { .. }
                | ReachabilityNodeKind::DynObjectCast { .. } => false,
            },
        }
    } else {
        false
    };
    unsafe_requirement_for_edge(
        reached.kind(),
        target_requires_unsafe,
        callable_requires_unsafe,
    )
}

const fn edge_uses_target_unsafe_requirement(kind: ReachabilityEdgeKind) -> bool {
    matches!(
        kind,
        ReachabilityEdgeKind::DirectCall
            | ReachabilityEdgeKind::TailCall
            | ReachabilityEdgeKind::DynDispatchVTableEntry
    )
}

const fn edge_uses_callable_unsafe_requirement(kind: ReachabilityEdgeKind) -> bool {
    matches!(
        kind,
        ReachabilityEdgeKind::IndirectCall | ReachabilityEdgeKind::FnPointerCallTarget
    )
}

const fn compiler_call_requires_unsafe(
    signature_requires_unsafe: bool,
    safe_target_features: bool,
    target_features_are_safe: bool,
) -> bool {
    (signature_requires_unsafe && !safe_target_features) || !target_features_are_safe
}

fn fn_def_call_requires_unsafe<'tcx>(
    tcx: TyCtxt<'tcx>,
    callee_def_id: DefId,
    signature_requires_unsafe: bool,
    caller_instance: Option<Instance<'tcx>>,
) -> bool {
    let Some(caller_instance) = caller_instance else {
        return signature_requires_unsafe;
    };
    let callee_attributes = tcx.codegen_fn_attrs(callee_def_id);
    // rustc unsafe-checks closures, coroutines, and inline consts with their
    // enclosing type-check root's target features.
    let caller_body = tcx.typeck_root_def_id(caller_instance.def_id());
    let caller_features = &tcx.body_codegen_attrs(caller_body).target_features;
    let target_features_are_safe =
        tcx.is_target_feature_call_safe(&callee_attributes.target_features, caller_features);
    compiler_call_requires_unsafe(
        signature_requires_unsafe,
        callee_attributes.safe_target_features,
        target_features_are_safe,
    )
}

fn callable_ty_requires_unsafe<'tcx>(
    tcx: TyCtxt<'tcx>,
    ty: rustc_middle::ty::Ty<'tcx>,
    caller: Option<Instance<'tcx>>,
) -> bool {
    let signature_requires_unsafe = matches!(ty.kind(), TyKind::FnDef(..) | TyKind::FnPtr(..))
        && ty.fn_sig(tcx).skip_binder().safety().is_unsafe();
    match ty.kind() {
        TyKind::FnDef(def_id, _) => {
            fn_def_call_requires_unsafe(tcx, *def_id, signature_requires_unsafe, caller)
        }
        TyKind::FnPtr(..) => signature_requires_unsafe,
        _ => false,
    }
}

const fn unsafe_requirement_for_edge(
    kind: ReachabilityEdgeKind,
    target_requires_unsafe: bool,
    callable_requires_unsafe: bool,
) -> bool {
    match kind {
        ReachabilityEdgeKind::DirectCall
        | ReachabilityEdgeKind::TailCall
        | ReachabilityEdgeKind::DynDispatchVTableEntry => target_requires_unsafe,
        ReachabilityEdgeKind::IndirectCall | ReachabilityEdgeKind::FnPointerCallTarget => {
            callable_requires_unsafe
        }
        ReachabilityEdgeKind::FnPointerReify
        | ReachabilityEdgeKind::ClosureFnPointerReify
        | ReachabilityEdgeKind::DynObjectCast
        | ReachabilityEdgeKind::VTableEntry
        | ReachabilityEdgeKind::MacroExpansion
        | ReachabilityEdgeKind::ConstBody
        | ReachabilityEdgeKind::CoroutineBody
        | ReachabilityEdgeKind::Assert => false,
    }
}

fn compiler_assert_description(
    message: &rustc_middle::mir::AssertMessage<'_>,
    locals: &[reachability::CompilerAssertLocal],
) -> String {
    // The semantic assertion subtype is stored separately. This session-rendered
    // text identifies the corresponding opaque target, and cache loading requires
    // the rustc version that produced it.
    if locals.is_empty() {
        format!("{message:?}")
    } else {
        format!("{message:?} with locals {locals:?}")
    }
}

fn edge_key<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge: &ReachabilityEdge,
    expanded_range: Option<&SourceRangeIr>,
    callee_range: Option<&SourceRangeIr>,
    target: &PendingCallTarget,
) -> String {
    let origin = graph
        .node_instance(edge.origin)
        .map(|instance| StableInstanceHash::from_instance(tcx, instance).to_string())
        .unwrap_or_default();
    let structural = format!(
        "{origin}|{:?}|{expanded_range:?}|{callee_range:?}|{target:?}|{:?}",
        edge.kind,
        edge.span.ctxt()
    );
    let ReachabilityNodeKind::CompilerAssert { site, .. } = &graph.node(edge.target).kind else {
        return structural;
    };
    // MIR can contain distinct assertions with identical kind, span, target,
    // and hygiene. Coordinates intentionally participate in the legacy
    // pending-call/effect identity so those assertions cannot coalesce before
    // each typed site is linked to its finalized legacy effect.
    format!(
        "{structural}|mir-site:{}:{}",
        site.basic_block, site.statement_index
    )
}

fn callable_attribution_for_edge(kind: ReachabilityEdgeKind) -> Vec<CallAttributionRole> {
    match kind {
        ReachabilityEdgeKind::FnPointerReify
        | ReachabilityEdgeKind::ClosureFnPointerReify
        | ReachabilityEdgeKind::VTableEntry => vec![CallAttributionRole::ErasureSite],
        ReachabilityEdgeKind::FnPointerCallTarget
        | ReachabilityEdgeKind::DynDispatchVTableEntry => vec![CallAttributionRole::CallSite],
        ReachabilityEdgeKind::DirectCall
        | ReachabilityEdgeKind::TailCall
        | ReachabilityEdgeKind::DynObjectCast
        | ReachabilityEdgeKind::MacroExpansion
        | ReachabilityEdgeKind::ConstBody
        | ReachabilityEdgeKind::CoroutineBody
        | ReachabilityEdgeKind::Assert
        | ReachabilityEdgeKind::IndirectCall => vec![
            CallAttributionRole::ErasureSite,
            CallAttributionRole::CallSite,
        ],
    }
}

fn callable_keys<'view, 'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &'view ReachabilityGraph<'tcx>,
    reached: ReachedEdge<'view, 'tcx>,
) -> Vec<CallableKey> {
    match graph.edge_callable(reached.id()) {
        Some(CallableEdgeInfo::FnPointer { fn_ptr_ty }) => {
            vec![CallableKey::FnPointer(StableTypeHash::from_ty(
                tcx, fn_ptr_ty,
            ))]
        }
        Some(CallableEdgeInfo::DynDispatch { trait_def_id })
            if reached.kind() == ReachabilityEdgeKind::VTableEntry =>
        {
            rustc_middle::ty::elaborate::supertrait_def_ids(tcx, trait_def_id)
                .map(|trait_def_id| {
                    CallableKey::DynDispatch(StableDefPathHash::from_def_id(tcx, trait_def_id))
                })
                .collect()
        }
        Some(CallableEdgeInfo::DynDispatch { trait_def_id }) => vec![CallableKey::DynDispatch(
            StableDefPathHash::from_def_id(tcx, trait_def_id),
        )],
        None => Vec::new(),
    }
}

fn call_edge_kind(kind: ReachabilityEdgeKind) -> CallKind {
    match kind {
        ReachabilityEdgeKind::DirectCall => CallKind::DirectCall,
        ReachabilityEdgeKind::TailCall => CallKind::TailCall,
        ReachabilityEdgeKind::FnPointerReify => CallKind::FnPointerReify,
        ReachabilityEdgeKind::ClosureFnPointerReify => CallKind::ClosureFnPointerReify,
        ReachabilityEdgeKind::FnPointerCallTarget => CallKind::FnPointerCallTarget,
        ReachabilityEdgeKind::DynObjectCast => CallKind::DynObjectCast,
        ReachabilityEdgeKind::VTableEntry => CallKind::VTableEntry,
        ReachabilityEdgeKind::DynDispatchVTableEntry => CallKind::DynDispatchVTableEntry,
        ReachabilityEdgeKind::MacroExpansion => CallKind::MacroExpansion,
        ReachabilityEdgeKind::ConstBody => CallKind::ConstBody,
        ReachabilityEdgeKind::CoroutineBody => CallKind::CoroutineBody,
        ReachabilityEdgeKind::Assert => CallKind::Assert,
        ReachabilityEdgeKind::IndirectCall => CallKind::IndirectCall,
    }
}

fn call_target<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge: &ReachabilityEdge,
    sources: &mut SourceTable,
) -> Result<PendingCallTarget, ExtractError> {
    match &graph.node(edge.target).kind {
        ReachabilityNodeKind::Instance(instance) => Ok(PendingCallTarget::Function(
            function_target_for_instance(tcx, *instance, sources)?,
        )),
        ReachabilityNodeKind::CompilerAssert {
            message, locals, ..
        } => Ok(PendingCallTarget::OpaqueBoundary {
            description: format!(
                "compiler assertion {}",
                compiler_assert_description(message, locals)
            ),
            target: None,
        }),
        ReachabilityNodeKind::MacroExpansion { def_id } => Ok(PendingCallTarget::OpaqueBoundary {
            description: format!("macro expansion {}", canonical_namespace(tcx, *def_id)),
            target: Some(PendingOpaqueTarget::Function(function_target_for_def(
                tcx, *def_id, sources,
            )?)),
        }),
        ReachabilityNodeKind::IndirectCall { callee_ty } => {
            let target = indirect_target_def_id(tcx, *callee_ty).map(|(def_id, is_trait)| {
                function_target_for_def(tcx, def_id, sources).map(|target| {
                    if is_trait {
                        PendingOpaqueTarget::Trait(target)
                    } else {
                        PendingOpaqueTarget::Function(target)
                    }
                })
            });
            Ok(PendingCallTarget::OpaqueBoundary {
                description: format!("indirect call {callee_ty:?}"),
                target: target.transpose()?,
            })
        }
        ReachabilityNodeKind::DynObjectCast {
            source_ty,
            target_ty,
        } => {
            let target = match target_ty.kind() {
                TyKind::Dynamic(predicates, _) => predicates
                    .principal_def_id()
                    .map(|def_id| {
                        function_target_for_def(tcx, def_id, sources)
                            .map(PendingOpaqueTarget::Trait)
                    })
                    .transpose()?,
                _ => None,
            };
            Ok(PendingCallTarget::OpaqueBoundary {
                description: format!("dynamic object cast {source_ty:?} as {target_ty:?}"),
                target,
            })
        }
    }
}

fn collected_call_targets(
    target: &PendingCallTarget,
    source_target: Option<&PendingFunctionTarget>,
) -> Vec<CollectedCallTarget> {
    let mut targets = match target {
        PendingCallTarget::Function(target) => vec![CollectedCallTarget::new(
            CallTargetRole::Runtime,
            function_key(target.function),
        )],
        PendingCallTarget::OpaqueBoundary { target, .. } => target
            .as_ref()
            .map(|target| match target {
                PendingOpaqueTarget::Trait(target) => CollectedCallTarget::new(
                    CallTargetRole::OpaqueTrait,
                    function_key(target.function),
                ),
                PendingOpaqueTarget::Function(target) => CollectedCallTarget::new(
                    CallTargetRole::OpaqueFunction,
                    function_key(target.function),
                ),
            })
            .into_iter()
            .collect(),
    };
    if let Some(source_target) = source_target {
        targets.push(CollectedCallTarget::new(
            CallTargetRole::SourceContract,
            function_key(source_target.function),
        ));
    }
    targets
}

fn target_function(target: &PendingCallTarget) -> Option<&PendingFunctionTarget> {
    match target {
        PendingCallTarget::Function(target)
        | PendingCallTarget::OpaqueBoundary {
            target: Some(PendingOpaqueTarget::Trait(target) | PendingOpaqueTarget::Function(target)),
            ..
        } => Some(target),
        PendingCallTarget::OpaqueBoundary { target: None, .. } => None,
    }
}

fn opaque_target_description(target: &PendingCallTarget) -> Option<String> {
    match target {
        PendingCallTarget::Function(_) => None,
        PendingCallTarget::OpaqueBoundary { description, .. } => Some(description.clone()),
    }
}

fn pending_callable_declarations(
    target: &PendingCallTarget,
    source_target: Option<&PendingFunctionTarget>,
) -> Result<Vec<PendingCallableDeclaration>, ExtractError> {
    let mut declarations = Vec::new();
    if let Some(target) = target_function(target) {
        declarations.extend(pending_function_declarations(target)?);
    }
    if let Some(source_target) = source_target {
        declarations.extend(pending_function_declarations(source_target)?);
    }
    Ok(declarations)
}

fn pending_function_declarations(
    target: &PendingFunctionTarget,
) -> Result<Vec<PendingCallableDeclaration>, ExtractError> {
    let runtime_key = function_key(target.function);
    let defining_key = FunctionKey::new(runtime_key.definition(), None);
    let callable = |key| {
        CallableEntity::new(
            key,
            &target.display_path,
            target.attributes.is_unsafe,
            target.attributes.is_exported,
            target.attributes.has_rust_body,
            target.attributes.is_foreign,
            target.attributes.namespace_candidates.clone(),
        )
    };
    let mut declarations = Vec::new();
    if runtime_key != defining_key {
        declarations.push(PendingCallableDeclaration {
            callable: callable(runtime_key),
            panic_contract: None,
            safety_contract: None,
        });
    }
    let mut panic_contracts = BTreeMap::new();
    let mut safety_contracts = BTreeMap::new();
    register_collected_contracts(
        defining_key,
        &target.contracts,
        &mut panic_contracts,
        &mut safety_contracts,
    )?;
    declarations.push(PendingCallableDeclaration {
        callable: callable(defining_key),
        panic_contract: panic_contracts.remove(&defining_key),
        safety_contract: safety_contracts.remove(&defining_key),
    });
    Ok(declarations)
}

fn indirect_target_def_id<'tcx>(
    tcx: TyCtxt<'tcx>,
    callee_ty: rustc_middle::ty::Ty<'tcx>,
) -> Option<(DefId, bool)> {
    match *callee_ty.kind() {
        TyKind::FnDef(def_id, _) => Some((def_id, tcx.trait_of_assoc(def_id).is_some())),
        TyKind::Dynamic(predicates, _) => {
            predicates.principal_def_id().map(|def_id| (def_id, true))
        }
        _ => None,
    }
}

fn function_target_for_instance<'tcx>(
    tcx: TyCtxt<'tcx>,
    instance: Instance<'tcx>,
    sources: &mut SourceTable,
) -> Result<PendingFunctionTarget, ExtractError> {
    let def_id = instance.def_id();
    Ok(PendingFunctionTarget {
        function: FunctionId::exact(
            StableDefPathHash::from_def_id(tcx, def_id),
            StableInstanceHash::from_instance(tcx, instance),
        ),
        display_path: canonical_namespace(tcx, def_id),
        attributes: function_attributes(tcx, def_id),
        contracts: function_contracts(tcx, def_id, sources)?,
    })
}

fn function_target_for_def(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    sources: &mut SourceTable,
) -> Result<PendingFunctionTarget, ExtractError> {
    Ok(PendingFunctionTarget {
        function: FunctionId::generic(StableDefPathHash::from_def_id(tcx, def_id)),
        display_path: canonical_namespace(tcx, def_id),
        attributes: function_attributes(tcx, def_id),
        contracts: function_contracts(tcx, def_id, sources)?,
    })
}

fn function_attributes(tcx: TyCtxt<'_>, def_id: DefId) -> FunctionAttributesIr {
    let candidates = namespace_candidates(tcx, def_id);
    let is_foreign = tcx.is_foreign_item(def_id);
    let def_kind = tcx.def_kind(def_id);
    let has_rust_body = !is_foreign
        && match def_kind {
            DefKind::Fn | DefKind::Closure | DefKind::SyntheticCoroutineBody => true,
            DefKind::AssocFn => match tcx.associated_item(def_id).container {
                AssocContainer::InherentImpl | AssocContainer::TraitImpl(_) => true,
                AssocContainer::Trait => tcx.associated_item(def_id).defaultness(tcx).has_value(),
            },
            _ => false,
        };
    // Nested closure and coroutine bodies do not have standalone visibility
    // metadata. Their enclosing item determines whether callers can reach
    // them, and only functions/associated functions can be report roots.
    let is_exported = matches!(def_kind, DefKind::Fn | DefKind::AssocFn)
        && def_id.as_local().map_or_else(
            || tcx.visibility(def_id).is_public(),
            |local| tcx.effective_visibilities(()).is_exported(local),
        );
    FunctionAttributesIr {
        is_unsafe: fn_def_is_unsafe(tcx, def_id),
        is_exported,
        has_rust_body,
        is_foreign,
        namespace_candidates: candidates.iter().map(str::to_owned).collect(),
    }
}

fn function_contracts(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    sources: &mut SourceTable,
) -> Result<FunctionContractsIr, ExtractError> {
    if !matches!(tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn) {
        return Ok(FunctionContractsIr::default());
    }
    Ok(FunctionContractsIr {
        panic: raw_contract(
            tcx,
            def_id,
            panic_contract_doc_summary_from_attrs(tcx, def_id),
            sources,
        )?,
        safety: raw_contract(
            tcx,
            def_id,
            safety_contract_doc_summary_from_attrs(tcx, def_id),
            sources,
        )?,
    })
}

fn raw_contract(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    summary: ContractDocSummary,
    sources: &mut SourceTable,
) -> Result<Option<RawContractIr>, ExtractError> {
    if !summary.has_docs {
        return Ok(None);
    }
    Ok(Some(RawContractIr {
        source_range: sources.range(tcx, tcx.def_span(def_id))?,
        requirements: contract_requirements(tcx, summary.requirements, sources)?,
    }))
}

fn contract_requirements(
    tcx: TyCtxt<'_>,
    requirements: Vec<crate::contracts::ContractRequirement>,
    sources: &mut SourceTable,
) -> Result<Vec<ContractRequirementIr>, ExtractError> {
    requirements
        .into_iter()
        .map(|requirement| {
            Ok(ContractRequirementIr {
                name: requirement.name,
                condition: requirement.condition,
                source_range: sources.range(tcx, requirement.span)?,
            })
        })
        .collect()
}

fn ensure_body(
    tcx: TyCtxt<'_>,
    sources: &mut SourceTable,
    bodies: &mut BTreeMap<FunctionId, PendingBody>,
    function: FunctionId,
    def_id: DefId,
    provenance: FunctionBodyProvenanceIr,
) -> Result<(), ExtractError> {
    ensure_body_with_projection(tcx, sources, bodies, function, def_id, provenance, true)
}

fn ensure_body_with_projection(
    tcx: TyCtxt<'_>,
    sources: &mut SourceTable,
    bodies: &mut BTreeMap<FunctionId, PendingBody>,
    function: FunctionId,
    def_id: DefId,
    provenance: FunctionBodyProvenanceIr,
    projects_to_legacy: bool,
) -> Result<(), ExtractError> {
    if let Some(body) = bodies.get_mut(&function) {
        return if body.provenance == provenance {
            body.projects_to_legacy |= projects_to_legacy;
            Ok(())
        } else {
            Err(ExtractError::new(format!(
                "function `{}` was extracted with conflicting provenance",
                canonical_namespace(tcx, def_id)
            )))
        };
    }
    let contracts = function_contracts(tcx, def_id, sources)?;
    let declaration_attributes = function_attributes(tcx, def_id);
    let mut attributes = declaration_attributes.clone();
    // `ensure_body` is used only for required HIR bodies and expanded rustc
    // instances. That proves this IR entry has a body even when its defining
    // `DefId` is an abstract callable trait method backed by a compiler-
    // generated shim (for example `FnOnce::call_once`).
    attributes.has_rust_body = true;
    let mut body = PendingBody {
        function,
        provenance,
        display_path: canonical_namespace(tcx, def_id),
        attributes,
        declaration_attributes,
        contracts: contracts.clone(),
        source_range: sources.range(tcx, tcx.def_span(def_id))?,
        calls: Vec::new(),
        effects: Vec::new(),
        markers: Vec::new(),
        typed_markers: Vec::new(),
        typed_safety_groups: BTreeSet::new(),
        projects_to_legacy,
    };
    if let Some(contract) = contracts.panic {
        body.push_contract_marker(MarkerKindIr::PanicContract, contract);
    }
    if let Some(contract) = contracts.safety {
        body.push_contract_marker(MarkerKindIr::SafetyContract, contract);
    }
    bodies.insert(function, body);
    Ok(())
}

fn build_collected_artifact(
    sources: &ExtractionSources,
    bodies: &BTreeMap<FunctionId, PendingBody>,
    assertions: &[PendingTypedMirAssert],
    unsafe_operations: Vec<PendingTypedUnsafeOperation>,
) -> Result<CollectedArtifact, ExtractError> {
    let mut callable_entities = BTreeMap::new();
    let mut panic_contracts = BTreeMap::new();
    let mut safety_contracts = BTreeMap::new();
    for body in bodies.values() {
        let owner = function_key(body.function);
        register_collected_callable(
            &mut callable_entities,
            owner,
            &body.display_path,
            &body.attributes,
        )?;
        let defining_owner = FunctionKey::new(owner.definition(), None);
        register_collected_callable(
            &mut callable_entities,
            defining_owner,
            &body.display_path,
            &body.declaration_attributes,
        )?;
        register_collected_contracts(
            defining_owner,
            &body.contracts,
            &mut panic_contracts,
            &mut safety_contracts,
        )?;
        for call in &body.calls {
            for declaration in &call.callable_declarations {
                register_collected_callable_entity(
                    &mut callable_entities,
                    declaration.callable.clone(),
                )?;
                if let Some(contract) = declaration.panic_contract.clone() {
                    insert_contract(&mut panic_contracts, *contract.owner(), contract, "panic")?;
                }
                if let Some(contract) = declaration.safety_contract.clone() {
                    insert_contract(&mut safety_contracts, *contract.owner(), contract, "safety")?;
                }
            }
        }
    }

    let collection_index = PermanentCollectionIndex::new(bodies, assertions)?;
    let marker_occurrences = collect_marker_occurrences(bodies, &collection_index)?;
    let collected_bodies = bodies
        .values()
        .map(|body| {
            collected_function_body(
                body,
                collection_index.calls(body.function),
                collection_index.assertions(body.function),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut source_files = sources.legacy.source_files();
    source_files.extend(sources.typed.source_files());
    let mut source_anchors = sources.legacy.source_anchors();
    source_anchors.extend(sources.typed.source_anchors());
    let program = CollectedProgram::try_new(
        source_files,
        source_anchors,
        callable_entities.into_values().collect(),
        collected_bodies,
    )
    .map_err(|error| ExtractError::new(error.to_string()))?;

    let unsafe_operations = unsafe_operations
        .into_iter()
        .map(collected_unsafe_operation)
        .collect::<Result<Vec<_>, _>>()?;
    CollectedArtifact::try_new(CollectedArtifactInput {
        program,
        unsafe_operations,
        panic_contracts: panic_contracts.into_values().collect(),
        safety_contracts: safety_contracts.into_values().collect(),
        mir_asserts: collection_index.mir_asserts,
        marker_occurrences,
    })
    .map_err(|error| ExtractError::new(error.to_string()))
}

struct PreparedTypedAssertion<'a> {
    assertion: &'a PendingTypedMirAssert,
    site: EffectSiteKey,
}

/// Validated, reusable ordering and ownership indexes for permanent collection.
///
/// Assertion sites are derived and partitioned once instead of rescanning the
/// complete artifact for every body. Typed calls are likewise sorted once and
/// shared by body materialization and marker target resolution.
struct PermanentCollectionIndex<'a> {
    assertions_by_function: BTreeMap<FunctionId, Vec<PreparedTypedAssertion<'a>>>,
    calls_by_function: BTreeMap<FunctionId, Vec<&'a PendingCall>>,
    marker_effect_sites: BTreeMap<(FunctionId, String), EffectSiteKey>,
    mir_asserts: Vec<CollectedMirAssert>,
}

impl<'a> PermanentCollectionIndex<'a> {
    fn new(
        bodies: &'a BTreeMap<FunctionId, PendingBody>,
        assertions: &'a [PendingTypedMirAssert],
    ) -> Result<Self, ExtractError> {
        let mut assertions_by_function = BTreeMap::<_, Vec<_>>::new();
        let mut marker_effect_sites = BTreeMap::new();
        let mut mir_asserts = Vec::with_capacity(assertions.len());
        for assertion in assertions {
            let function = assertion.function;
            let site = effect_site_key(assertion)?;
            assertions_by_function
                .entry(function)
                .or_default()
                .push(PreparedTypedAssertion { assertion, site });
            marker_effect_sites.insert((function, assertion.legacy_effect_key.clone()), site);
            mir_asserts.push(CollectedMirAssert::new(site, assertion.kind));
        }
        let calls_by_function = bodies
            .iter()
            .map(|(function, body)| Ok((*function, sorted_typed_calls(body)?)))
            .collect::<Result<_, ExtractError>>()?;
        Ok(Self {
            assertions_by_function,
            calls_by_function,
            marker_effect_sites,
            mir_asserts,
        })
    }

    fn assertions(&self, function: FunctionId) -> &[PreparedTypedAssertion<'a>] {
        self.assertions_by_function
            .get(&function)
            .map_or(&[], Vec::as_slice)
    }

    fn calls(&self, function: FunctionId) -> &[&'a PendingCall] {
        self.calls_by_function
            .get(&function)
            .expect("every pending body has one validated typed call order")
    }
}

fn function_key(function: FunctionId) -> FunctionKey {
    FunctionKey::new(function.def_path_hash, function.instance_hash)
}

fn register_collected_callable(
    callables: &mut BTreeMap<FunctionKey, CallableEntity>,
    key: FunctionKey,
    display_path: &str,
    attributes: &FunctionAttributesIr,
) -> Result<(), ExtractError> {
    let candidate = CallableEntity::new(
        key,
        display_path,
        attributes.is_unsafe,
        attributes.is_exported,
        attributes.has_rust_body,
        attributes.is_foreign,
        attributes.namespace_candidates.clone(),
    );
    register_collected_callable_entity(callables, candidate)
}

fn register_collected_callable_entity(
    callables: &mut BTreeMap<FunctionKey, CallableEntity>,
    candidate: CallableEntity,
) -> Result<(), ExtractError> {
    let key = *candidate.key();
    let Some(existing) = callables.get(&key) else {
        callables.insert(key, candidate);
        return Ok(());
    };
    if existing == &candidate {
        return Ok(());
    }
    if existing.display_path() != candidate.display_path()
        || existing.is_unsafe() != candidate.is_unsafe()
        || existing.is_exported() != candidate.is_exported()
        || existing.is_foreign() != candidate.is_foreign()
        || existing.namespace_candidates() != candidate.namespace_candidates()
    {
        return Err(ExtractError::new(format!(
            "callable `{}` was extracted with conflicting metadata",
            candidate.display_path()
        )));
    }
    callables.insert(
        key,
        CallableEntity::new(
            key,
            candidate.display_path(),
            candidate.is_unsafe(),
            candidate.is_exported(),
            existing.has_rust_body() || candidate.has_rust_body(),
            candidate.is_foreign(),
            candidate.namespace_candidates().to_vec(),
        ),
    );
    Ok(())
}

fn register_collected_contracts(
    owner: FunctionKey,
    contracts: &FunctionContractsIr,
    panic_contracts: &mut BTreeMap<FunctionKey, CollectedPanicContract>,
    safety_contracts: &mut BTreeMap<FunctionKey, CollectedSafetyContract>,
) -> Result<(), ExtractError> {
    if let Some(contract) = contracts.panic.as_ref() {
        let collected = CollectedPanicContract::new(
            owner,
            contract
                .source_range
                .as_ref()
                .map(SourceTable::anchor_from_range),
            contract
                .requirements
                .iter()
                .enumerate()
                .map(|(ordinal, requirement)| {
                    Ok(PanicRequirement::new(
                        owner,
                        local_id(ordinal, "panic contract requirement")?,
                        &requirement.name,
                        &requirement.condition,
                        requirement
                            .source_range
                            .as_ref()
                            .map(SourceTable::anchor_from_range),
                    ))
                })
                .collect::<Result<Vec<_>, ExtractError>>()?,
        );
        insert_contract(panic_contracts, owner, collected, "panic")?;
    }
    if let Some(contract) = contracts.safety.as_ref() {
        let collected = CollectedSafetyContract::new(
            owner,
            contract
                .source_range
                .as_ref()
                .map(SourceTable::anchor_from_range),
            contract
                .requirements
                .iter()
                .enumerate()
                .map(|(ordinal, requirement)| {
                    Ok(SafetyRequirement::new(
                        owner,
                        local_id(ordinal, "safety contract requirement")?,
                        &requirement.name,
                        &requirement.condition,
                        requirement
                            .source_range
                            .as_ref()
                            .map(SourceTable::anchor_from_range),
                    ))
                })
                .collect::<Result<Vec<_>, ExtractError>>()?,
        );
        insert_contract(safety_contracts, owner, collected, "safety")?;
    }
    Ok(())
}

fn insert_contract<C: Eq>(
    contracts: &mut BTreeMap<FunctionKey, C>,
    owner: FunctionKey,
    contract: C,
    domain: &str,
) -> Result<(), ExtractError> {
    if let Some(existing) = contracts.get(&owner) {
        if existing != &contract {
            return Err(ExtractError::new(format!(
                "callable {owner:?} was extracted with conflicting {domain} contracts"
            )));
        }
    } else {
        contracts.insert(owner, contract);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ResolvedMarkerTarget {
    Call(CallOccurrenceKey),
    Effect(EffectSiteKey),
    UnsafeOperation(UnsafeOperationKey),
}

struct MarkerAggregate {
    entity: MarkerOccurrenceEntity,
    claims: BTreeMap<DomainId, Vec<(EvidenceClaimSelector, String)>>,
    candidates: BTreeMap<(ResolvedMarkerTarget, MarkerClaimKey), (bool, bool)>,
}

fn collect_marker_occurrences(
    bodies: &BTreeMap<FunctionId, PendingBody>,
    collection_index: &PermanentCollectionIndex<'_>,
) -> Result<Vec<CollectedMarkerOccurrence>, ExtractError> {
    let mut aggregates = BTreeMap::<MarkerOccurrenceKey, MarkerAggregate>::new();
    for body in bodies.values() {
        let calls = marker_call_targets(body, collection_index.calls(body.function))?;
        for marker in &body.typed_markers {
            let target = resolve_marker_target(
                body.function,
                marker,
                &calls,
                &collection_index.marker_effect_sites,
            )?;
            merge_marker_aggregate(&mut aggregates, marker, target)?;
        }
    }
    aggregates
        .into_values()
        .map(finish_marker_aggregate)
        .collect()
}

fn marker_call_targets(
    body: &PendingBody,
    calls: &[&PendingCall],
) -> Result<BTreeMap<String, CallOccurrenceKey>, ExtractError> {
    let owner = function_key(body.function);
    calls
        .iter()
        .copied()
        .enumerate()
        .map(|(ordinal, call)| {
            Ok((
                call.key.clone(),
                CallOccurrenceKey::new(owner, local_id(ordinal, "marker call target")?),
            ))
        })
        .collect()
}

fn resolve_marker_target(
    function: FunctionId,
    marker: &PendingTypedMarker,
    calls: &BTreeMap<String, CallOccurrenceKey>,
    effect_sites: &BTreeMap<(FunctionId, String), EffectSiteKey>,
) -> Result<ResolvedMarkerTarget, ExtractError> {
    if marker.satisfactions.is_empty() {
        return Err(ExtractError::new(
            "a typed human marker has no justification claims",
        ));
    }
    match &marker.target {
        PendingTypedMarkerTarget::Call(key) => calls
            .get(key)
            .copied()
            .map(ResolvedMarkerTarget::Call)
            .ok_or_else(|| ExtractError::new("typed marker refers to an unknown extracted call")),
        PendingTypedMarkerTarget::Effect(key) => effect_sites
            .get(&(function, key.clone()))
            .copied()
            .map(ResolvedMarkerTarget::Effect)
            .ok_or_else(|| {
                ExtractError::new("typed marker refers to an unknown compiler effect site")
            }),
        PendingTypedMarkerTarget::UnsafeOperation(key) => {
            Ok(ResolvedMarkerTarget::UnsafeOperation(*key))
        }
    }
}

fn merge_marker_aggregate(
    aggregates: &mut BTreeMap<MarkerOccurrenceKey, MarkerAggregate>,
    marker: &PendingTypedMarker,
    target: ResolvedMarkerTarget,
) -> Result<(), ExtractError> {
    let occurrence_key = marker.occurrence.key().clone();
    let claims = marker
        .satisfactions
        .iter()
        .map(|satisfaction| {
            (
                satisfaction
                    .requirement
                    .as_ref()
                    .map_or(EvidenceClaimSelector::Unnamed, |requirement| {
                        EvidenceClaimSelector::Named(requirement.clone())
                    }),
                satisfaction.reason.clone(),
            )
        })
        .collect::<Vec<_>>();
    let aggregate = aggregates
        .entry(occurrence_key.clone())
        .or_insert_with(|| MarkerAggregate {
            entity: marker.occurrence.clone(),
            claims: BTreeMap::new(),
            candidates: BTreeMap::new(),
        });
    if aggregate.entity != marker.occurrence {
        return Err(ExtractError::new(
            "one marker occurrence resolved to conflicting expansion paths",
        ));
    }
    if let Some(existing) = aggregate.claims.get(&marker.domain) {
        if existing != &claims {
            return Err(ExtractError::new(
                "one marker occurrence resolved to conflicting human claims",
            ));
        }
    } else {
        aggregate.claims.insert(marker.domain.clone(), claims);
    }
    for ordinal in &marker.applicable_satisfactions {
        if usize::try_from(*ordinal)
            .ok()
            .is_none_or(|ordinal| ordinal >= marker.satisfactions.len())
        {
            return Err(ExtractError::new(
                "a typed human marker selected an unknown physical claim ordinal",
            ));
        }
        let claim = MarkerClaimKey::new(occurrence_key.clone(), marker.domain.clone(), *ordinal);
        let applicability = aggregate.candidates.entry((target, claim)).or_default();
        applicability.0 |= marker.source_callsite;
        applicability.1 |= marker.macro_definition_first;
    }
    Ok(())
}

fn finish_marker_aggregate(
    aggregate: MarkerAggregate,
) -> Result<CollectedMarkerOccurrence, ExtractError> {
    let occurrence = aggregate.entity.key().clone();
    let claims = aggregate
        .claims
        .into_iter()
        .flat_map(|(domain, claims)| {
            let occurrence = occurrence.clone();
            claims
                .into_iter()
                .enumerate()
                .map(move |(ordinal, (selector, rationale))| {
                    Ok(MarkerClaimEntity::new(
                        MarkerClaimKey::new(
                            occurrence.clone(),
                            domain.clone(),
                            local_id(ordinal, "marker claim")?,
                        ),
                        selector,
                        rationale,
                    ))
                })
        })
        .collect::<Result<Vec<_>, ExtractError>>()?;
    let mut call_candidates = Vec::new();
    let mut effect_candidates = Vec::new();
    let mut unsafe_operation_candidates = Vec::new();
    for ((target, claim), (source_callsite, macro_definition_first)) in aggregate.candidates {
        match target {
            ResolvedMarkerTarget::Call(call) => {
                call_candidates.push(CollectedMarkerCallCandidate::new(
                    call,
                    claim,
                    CallOccurrenceHasMarkerClaimCandidate::new(
                        source_callsite,
                        macro_definition_first,
                    ),
                ));
            }
            ResolvedMarkerTarget::Effect(effect) => {
                effect_candidates.push(CollectedEffectMarkerCandidate::new(
                    effect,
                    claim,
                    EffectSiteHasMarkerClaimCandidate::new(source_callsite, macro_definition_first),
                ));
            }
            ResolvedMarkerTarget::UnsafeOperation(operation) => {
                unsafe_operation_candidates.push(CollectedUnsafeOperationMarkerCandidate::new(
                    operation,
                    claim,
                    UnsafeOperationHasMarkerClaimCandidate::new(
                        source_callsite,
                        macro_definition_first,
                    ),
                ));
            }
        }
    }
    Ok(CollectedMarkerOccurrence::new(
        aggregate.entity,
        claims,
        Vec::new(),
        call_candidates,
        effect_candidates,
        unsafe_operation_candidates,
    ))
}

fn collected_function_body(
    body: &PendingBody,
    calls: &[&PendingCall],
    assertions: &[PreparedTypedAssertion<'_>],
) -> Result<CollectedFunctionBody, ExtractError> {
    let owner = function_key(body.function);
    let mut sites = BTreeMap::<CallSiteKey, Vec<CollectedCallOccurrence>>::new();
    let mut safety_groups = body.typed_safety_groups.clone();
    for (ordinal, pending) in calls.iter().copied().enumerate() {
        let occurrence_key = CallOccurrenceKey::new(owner, local_id(ordinal, "call")?);
        safety_groups.insert(pending.safety_effect_group);
        let site_key = CallSiteKey::new(owner, pending.call_site);
        sites
            .entry(site_key)
            .or_default()
            .push(collected_call_occurrence(occurrence_key, pending)?);
    }
    let call_sites = sites
        .into_iter()
        .map(|(key, occurrences)| CollectedCallSite::new(CallSiteEntity::new(key), occurrences))
        .collect();
    let safety_effect_groups = safety_groups
        .into_iter()
        .map(|local_id| SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(owner, local_id)))
        .collect();
    let effect_sites = assertions
        .iter()
        .map(|assertion| collected_effect_site(assertion.assertion, assertion.site))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CollectedFunctionBody::new(
        FunctionEntity::new(
            owner,
            &body.display_path,
            match body.provenance {
                FunctionBodyProvenanceIr::DefiningArtifact => {
                    FunctionBodyProvenance::DefiningArtifact
                }
                FunctionBodyProvenanceIr::ConsumerInstantiation {
                    consumer_stable_crate_id,
                } => FunctionBodyProvenance::ConsumerInstantiation {
                    consumer_stable_crate_id,
                },
            },
        ),
        body.source_range
            .as_ref()
            .map(SourceTable::anchor_from_range),
        call_sites,
        safety_effect_groups,
        effect_sites,
    ))
}

fn sorted_typed_calls(body: &PendingBody) -> Result<Vec<&PendingCall>, ExtractError> {
    let mut calls = body.calls.iter().collect::<Vec<_>>();
    calls.sort_by(|left, right| left.stable_sort_key.cmp(&right.stable_sort_key));
    if calls
        .windows(2)
        .any(|pair| pair[0].stable_sort_key == pair[1].stable_sort_key)
    {
        return Err(ExtractError::new(
            "two extracted call occurrences have the same stable typed identity",
        ));
    }
    Ok(calls)
}

fn collected_call_occurrence(
    key: CallOccurrenceKey,
    pending: &PendingCall,
) -> Result<CollectedCallOccurrence, ExtractError> {
    Ok(CollectedCallOccurrence::new(
        CallOccurrenceEntity::new(
            key,
            pending.kind,
            pending.applicable_attribution.clone(),
            pending.requires_unsafe,
            pending.inside_builtin_unsafe,
            pending.opaque_target_description.clone(),
        ),
        pending.targets.clone(),
        pending.callable_keys.clone(),
        vec![SafetyEffectGroupKey::new(
            *key.owner(),
            pending.safety_effect_group,
        )],
        call_source_anchors(pending),
        collected_call_macro_frames(key, &pending.typed_macro_expansions)?,
    ))
}

fn legacy_call_kind(kind: CallKind) -> CallEdgeKindIr {
    match kind {
        CallKind::DirectCall => CallEdgeKindIr::DirectCall,
        CallKind::TailCall => CallEdgeKindIr::TailCall,
        CallKind::FnPointerReify => CallEdgeKindIr::FnPointerReify,
        CallKind::ClosureFnPointerReify => CallEdgeKindIr::ClosureFnPointerReify,
        CallKind::FnPointerCallTarget => CallEdgeKindIr::FnPointerCallTarget,
        CallKind::DynObjectCast => CallEdgeKindIr::DynObjectCast,
        CallKind::VTableEntry => CallEdgeKindIr::VTableEntry,
        CallKind::DynDispatchVTableEntry => CallEdgeKindIr::DynDispatchVTableEntry,
        CallKind::MacroExpansion => CallEdgeKindIr::MacroExpansion,
        CallKind::ConstBody => CallEdgeKindIr::ConstBody,
        CallKind::CoroutineBody => CallEdgeKindIr::CoroutineBody,
        CallKind::Assert => CallEdgeKindIr::Assert,
        CallKind::IndirectCall => CallEdgeKindIr::IndirectCall,
    }
}

fn call_source_anchors(call: &PendingCall) -> Vec<CollectedCallSourceAnchor> {
    [
        (
            CallSourceAnchorRole::Presentation,
            call.presentation_anchor.as_ref(),
        ),
        (
            CallSourceAnchorRole::Expanded,
            call.expanded_anchor.as_ref(),
        ),
        (CallSourceAnchorRole::Callee, call.callee_anchor.as_ref()),
    ]
    .into_iter()
    .filter_map(|(role, anchor)| {
        anchor.map(|anchor| CollectedCallSourceAnchor::new(role, anchor.clone()))
    })
    .collect()
}

fn collected_call_macro_frames(
    occurrence: CallOccurrenceKey,
    frames: &[ExtractedMacroExpansionFrame],
) -> Result<Vec<CollectedCallMacroFrame>, ExtractError> {
    frames
        .iter()
        .enumerate()
        .map(|(depth, frame)| {
            Ok(CollectedCallMacroFrame::new(
                CallMacroExpansionEntity::new(
                    CallMacroExpansionKey::new(
                        occurrence,
                        local_id(depth, "call macro expansion")?,
                    ),
                    frame.expansion_hash(),
                    frame.macro_definition(),
                    frame.display_path(),
                ),
                frame.source_range().map(SourceTable::anchor_from_range),
            ))
        })
        .collect()
}

fn effect_site_key(assertion: &PendingTypedMirAssert) -> Result<EffectSiteKey, ExtractError> {
    EffectSiteKey::from_mir(function_key(assertion.function), assertion.location)
        .map_err(|error| ExtractError::new(error.to_string()))
}

fn collected_effect_site(
    assertion: &PendingTypedMirAssert,
    site: EffectSiteKey,
) -> Result<CollectedEffectSite, ExtractError> {
    let source_anchors = [
        (
            EffectSourceAnchorRole::Presentation,
            assertion.presentation_anchor.as_ref(),
        ),
        (
            EffectSourceAnchorRole::Expanded,
            assertion.expanded_anchor.as_ref(),
        ),
    ]
    .into_iter()
    .filter_map(|(role, anchor)| {
        anchor
            .cloned()
            .map(|anchor| CollectedEffectSourceAnchor::new(role, anchor))
    })
    .collect();
    let macro_frames = assertion
        .macro_expansions
        .iter()
        .enumerate()
        .map(|(depth, frame)| {
            Ok(CollectedEffectMacroFrame::new(
                MacroExpansionEntity::new(
                    MacroExpansionKey::new(site, local_id(depth, "effect macro expansion")?),
                    frame.expansion_hash(),
                    frame.macro_definition(),
                    frame.display_path(),
                ),
                frame.source_range().map(SourceTable::anchor_from_range),
            ))
        })
        .collect::<Result<Vec<_>, ExtractError>>()?;
    Ok(CollectedEffectSite::new(
        EffectSiteEntity::new(site),
        source_anchors,
        macro_frames,
    ))
}

fn collected_unsafe_operation(
    operation: PendingTypedUnsafeOperation,
) -> Result<CollectedUnsafeOperation, ExtractError> {
    let key = *operation.operation.key();
    let source_anchors = [
        (
            UnsafeOperationSourceAnchorRole::Presentation,
            operation.presentation_anchor,
        ),
        (
            UnsafeOperationSourceAnchorRole::Expanded,
            operation.expanded_anchor,
        ),
    ]
    .into_iter()
    .filter_map(|(role, anchor)| {
        anchor.map(|anchor| CollectedUnsafeOperationSourceAnchor::new(role, anchor))
    })
    .collect();
    let macro_frames = operation
        .macro_expansions
        .iter()
        .enumerate()
        .map(|(depth, frame)| {
            Ok(CollectedUnsafeOperationMacroFrame::new(
                UnsafeOperationMacroExpansionEntity::new(
                    UnsafeOperationMacroExpansionKey::new(
                        key,
                        local_id(depth, "unsafe operation macro expansion")?,
                    ),
                    frame.expansion_hash(),
                    frame.macro_definition(),
                    frame.display_path(),
                ),
                frame.source_range().map(SourceTable::anchor_from_range),
            ))
        })
        .collect::<Result<Vec<_>, ExtractError>>()?;
    Ok(CollectedUnsafeOperation::new(
        operation.operation,
        operation.safety_effect_group,
        source_anchors,
        macro_frames,
    ))
}

#[derive(Debug, Clone, Copy)]
struct RawSafetyGroupSite {
    span: Span,
    group: usize,
}

#[derive(Debug, Clone, Copy)]
struct RawCallSite {
    callee: Option<DefId>,
    source_callee: Option<DefId>,
    safety_group: usize,
    call_site: usize,
    inside_builtin_unsafe: bool,
}

#[derive(Debug, Clone, Copy)]
struct RawStandaloneSite {
    safety_group: usize,
    call_site: usize,
}

#[derive(Debug, Clone, Copy)]
enum StandaloneSiteKind {
    Call,
    StructuralEdge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedCallGroups {
    safety_effect_group: SafetyEffectGroupId,
    call_site: CallSiteId,
    inside_builtin_unsafe: bool,
    source_callee: Option<DefId>,
}

/// Replays the policy-neutral grouping performed by the THIR unsafety walk.
///
/// Operations and calls inside one explicit unsafe block share that block's
/// group. A reachability-only callable edge inside the same block inherits the
/// innermost containing group. Edges with no THIR scope receive one stable
/// standalone group per source site.
struct RawSafetyGroupResolver {
    calls_by_span: HashMap<(DefId, Span), Vec<RawCallSite>>,
    scopes_by_owner: HashMap<DefId, Vec<RawSafetyGroupSite>>,
    standalone_calls: HashMap<(DefId, Span), RawStandaloneSite>,
    standalone_structural_edges: HashMap<(DefId, Span), RawStandaloneSite>,
    next_group: Option<usize>,
    next_call_site: Option<usize>,
}

impl RawSafetyGroupResolver {
    fn new(facts: &RawSafetyFacts) -> Self {
        let mut calls_by_span = HashMap::<(DefId, Span), Vec<RawCallSite>>::new();
        for fact in &facts.calls {
            calls_by_span
                .entry((fact.owner, fact.span))
                .or_default()
                .push(RawCallSite {
                    callee: fact.callee,
                    source_callee: fact.source_callee,
                    safety_group: fact.effect_group.id,
                    call_site: fact.call_site,
                    inside_builtin_unsafe: fact.inside_builtin_unsafe,
                });
        }
        let mut scopes_by_owner = HashMap::<DefId, Vec<RawSafetyGroupSite>>::new();
        for fact in &facts.groups {
            scopes_by_owner
                .entry(fact.owner)
                .or_default()
                .push(RawSafetyGroupSite {
                    span: fact.effect_group.span,
                    group: fact.effect_group.id,
                });
        }
        let next_group = facts
            .groups
            .iter()
            .map(|fact| fact.effect_group.id)
            .chain(facts.calls.iter().map(|fact| fact.effect_group.id))
            .chain(facts.operations.iter().map(|fact| fact.effect_group.id))
            .max()
            .map_or(Some(0), |group| group.checked_add(1));
        let next_call_site = facts
            .calls
            .iter()
            .map(|fact| fact.call_site)
            .max()
            .map_or(Some(0), |site| site.checked_add(1));
        Self {
            calls_by_span,
            scopes_by_owner,
            standalone_calls: HashMap::new(),
            standalone_structural_edges: HashMap::new(),
            next_group,
            next_call_site,
        }
    }

    fn group_for_call(
        &mut self,
        owner: DefId,
        span: Span,
        callee: Option<DefId>,
    ) -> Result<ResolvedCallGroups, ExtractError> {
        // Preserve macro-instance identity before falling back to
        // source-callsite containment. Multiple expansions may normalize to
        // the same byte range while still representing distinct unsafe
        // scopes and therefore distinct proof obligations.
        let exact_calls = self
            .calls_by_span
            .get(&(owner, span))
            .map_or(&[][..], Vec::as_slice);
        if let Some(site) =
            unique_raw_call_groups(exact_calls.iter().filter(|site| site.callee == callee))
        {
            return resolved_call_groups(
                site.safety_group,
                site.call_site,
                site.inside_builtin_unsafe,
                site.source_callee,
            );
        }
        if let Some(site) = unique_raw_call_groups(
            exact_calls
                .iter()
                .filter(|site| callee.is_none() || site.callee.is_none()),
        ) {
            return resolved_call_groups(
                site.safety_group,
                site.call_site,
                site.inside_builtin_unsafe,
                site.source_callee,
            );
        }
        // Coroutine lowering can add a direct runtime-body edge at the same
        // span as several desugared `.await` calls without a corresponding
        // THIR call expression. When no candidate identity is unique, keep a
        // conservative standalone site instead of borrowing an unrelated
        // user or compiler-provided unsafe context.
        self.group_for_standalone_site(owner, span, StandaloneSiteKind::Call)
    }

    fn group_for_structural_edge(
        &mut self,
        owner: DefId,
        span: Span,
    ) -> Result<ResolvedCallGroups, ExtractError> {
        self.group_for_standalone_site(owner, span, StandaloneSiteKind::StructuralEdge)
    }

    fn group_for_standalone_site(
        &mut self,
        owner: DefId,
        span: Span,
        kind: StandaloneSiteKind,
    ) -> Result<ResolvedCallGroups, ExtractError> {
        let existing = match kind {
            StandaloneSiteKind::Call => &self.standalone_calls,
            StandaloneSiteKind::StructuralEdge => &self.standalone_structural_edges,
        }
        .get(&(owner, span));
        if let Some(site) = existing {
            return resolved_call_groups(site.safety_group, site.call_site, false, None);
        }
        let safety_group =
            if let Some(group) = containing_scope_group(&self.scopes_by_owner, owner, span) {
                group
            } else {
                let group = self.next_group.ok_or_else(|| {
                    ExtractError::new("too many raw safety effect groups in one artifact")
                })?;
                self.next_group = group.checked_add(1);
                group
            };
        let call_site = self
            .next_call_site
            .ok_or_else(|| ExtractError::new("too many raw call sites in one artifact"))?;
        self.next_call_site = call_site.checked_add(1);
        let site = RawStandaloneSite {
            safety_group,
            call_site,
        };
        match kind {
            StandaloneSiteKind::Call => {
                self.standalone_calls.insert((owner, span), site);
            }
            StandaloneSiteKind::StructuralEdge => {
                self.standalone_structural_edges.insert((owner, span), site);
            }
        }
        resolved_call_groups(safety_group, call_site, false, None)
    }
}

#[derive(Debug, Clone, Copy)]
struct RawCallConsensus {
    safety_group: usize,
    call_site: usize,
    inside_builtin_unsafe: bool,
    source_callee: Option<DefId>,
}

fn unique_raw_call_groups<'a>(
    mut calls: impl Iterator<Item = &'a RawCallSite>,
) -> Option<RawCallConsensus> {
    let first = *calls.next()?;
    let mut source_callee = first.source_callee;
    for candidate in calls {
        if candidate.safety_group != first.safety_group
            || candidate.call_site != first.call_site
            || candidate.inside_builtin_unsafe != first.inside_builtin_unsafe
        {
            return None;
        }
        if candidate.source_callee != source_callee {
            source_callee = None;
        }
    }
    Some(RawCallConsensus {
        safety_group: first.safety_group,
        call_site: first.call_site,
        inside_builtin_unsafe: first.inside_builtin_unsafe,
        source_callee,
    })
}

fn containing_scope_group(
    scopes_by_owner: &HashMap<DefId, Vec<RawSafetyGroupSite>>,
    owner: DefId,
    span: Span,
) -> Option<usize> {
    let scopes = scopes_by_owner.get(&owner).map_or(&[][..], Vec::as_slice);
    let exact = innermost_scope_group(
        scopes.iter().filter(|site| {
            !site.span.is_dummy()
                && !span.is_dummy()
                && site.span.ctxt() == span.ctxt()
                && site.span.lo() <= span.lo()
                && span.hi() <= site.span.hi()
        }),
        false,
    );
    match exact {
        InnermostScopeGroup::Unique(group) => Some(group),
        InnermostScopeGroup::Ambiguous => None,
        InnermostScopeGroup::Absent => match innermost_scope_group(
            scopes
                .iter()
                .filter(|site| crate::source_markers::span_contains(site.span, span)),
            true,
        ) {
            InnermostScopeGroup::Unique(group) => Some(group),
            InnermostScopeGroup::Absent | InnermostScopeGroup::Ambiguous => None,
        },
    }
}

enum InnermostScopeGroup {
    Absent,
    Unique(usize),
    Ambiguous,
}

fn innermost_scope_group<'a>(
    scopes: impl Iterator<Item = &'a RawSafetyGroupSite>,
    source_callsite: bool,
) -> InnermostScopeGroup {
    let mut selected = None;
    let mut ambiguous = false;
    for site in scopes {
        let span = if source_callsite {
            site.span.source_callsite()
        } else {
            site.span
        };
        let length = span.hi().to_u32().saturating_sub(span.lo().to_u32());
        match selected {
            None => {
                selected = Some((length, site.group));
            }
            Some((current_length, _)) if length < current_length => {
                selected = Some((length, site.group));
                ambiguous = false;
            }
            Some((current_length, group)) if length == current_length && group != site.group => {
                ambiguous = true;
            }
            Some(_) => {}
        }
    }
    match selected {
        None => InnermostScopeGroup::Absent,
        Some(_) if ambiguous => InnermostScopeGroup::Ambiguous,
        Some((_, group)) => InnermostScopeGroup::Unique(group),
    }
}

fn resolved_call_groups(
    safety_group: usize,
    call_site: usize,
    inside_builtin_unsafe: bool,
    source_callee: Option<DefId>,
) -> Result<ResolvedCallGroups, ExtractError> {
    Ok(ResolvedCallGroups {
        safety_effect_group: raw_safety_group_id(safety_group)?,
        call_site: u32::try_from(call_site)
            .map(CallSiteId::new)
            .map_err(|_| ExtractError::new("too many raw call sites in one artifact"))?,
        inside_builtin_unsafe,
        source_callee,
    })
}

fn raw_safety_group_id(group: usize) -> Result<SafetyEffectGroupId, ExtractError> {
    u32::try_from(group)
        .map(SafetyEffectGroupId::new)
        .map_err(|_| ExtractError::new("too many raw safety effect groups in one artifact"))
}

fn attach_raw_unsafe_operations(
    tcx: TyCtxt<'_>,
    facts: Vec<RawSafetyOpFact>,
    sources: &mut ExtractionSources,
    bodies: &mut BTreeMap<FunctionId, PendingBody>,
    typed_operations: &mut Vec<PendingTypedUnsafeOperation>,
    next_typed_operation: &mut BTreeMap<FunctionKey, u32>,
) -> Result<(), ExtractError> {
    for (ordinal, fact) in facts.into_iter().enumerate() {
        let prepared = prepare_permanent_unsafe_operation(
            tcx,
            &fact,
            sources,
            bodies,
            typed_operations,
            next_typed_operation,
        )?;
        attach_legacy_unsafe_operation(
            tcx,
            ordinal,
            &fact,
            &prepared,
            &mut sources.legacy,
            bodies,
        )?;
    }
    Ok(())
}

struct PreparedUnsafeOperation {
    generic_function: FunctionId,
    body_ids: Vec<FunctionId>,
    operation_key: UnsafeOperationKey,
    source_range: Option<SourceRangeIr>,
    expanded_range: Option<SourceRangeIr>,
    legacy_macro_expansions: Vec<MacroExpansionFrameIr>,
}

fn prepare_permanent_unsafe_operation(
    tcx: TyCtxt<'_>,
    fact: &RawSafetyOpFact,
    sources: &mut ExtractionSources,
    bodies: &mut BTreeMap<FunctionId, PendingBody>,
    typed_operations: &mut Vec<PendingTypedUnsafeOperation>,
    next_typed_operation: &mut BTreeMap<FunctionKey, u32>,
) -> Result<PreparedUnsafeOperation, ExtractError> {
    let Some(local) = fact.owner.as_local() else {
        return Err(ExtractError::new(
            "raw unsafe operation is not owned by the local artifact",
        ));
    };
    let definition = StableDefPathHash::from_def_id(tcx, fact.owner);
    let generic_function = FunctionId::generic(definition);
    let mut body_ids = bodies
        .iter()
        .filter_map(|(function, body)| {
            (body.projects_to_legacy && function.def_path_hash == definition).then_some(*function)
        })
        .collect::<Vec<_>>();
    let generic_projects_to_legacy = body_ids.is_empty();
    ensure_body_with_projection(
        tcx,
        &mut sources.legacy,
        bodies,
        generic_function,
        local.to_def_id(),
        FunctionBodyProvenanceIr::DefiningArtifact,
        generic_projects_to_legacy,
    )?;
    if generic_projects_to_legacy {
        body_ids.push(generic_function);
    }
    let expanded_range = sources.legacy.range(tcx, fact.span)?;
    let legacy_macro_expansions = span_macro_expansions(tcx, fact.span, &mut sources.legacy)?;
    let source_range = sources
        .legacy
        .range(tcx, fact.span.source_callsite())?
        .or_else(|| expanded_range.clone());
    let typed_owner = function_key(generic_function);
    let local_id = next_typed_operation.entry(typed_owner).or_default();
    let operation_key = UnsafeOperationKey::new(typed_owner, *local_id);
    *local_id = local_id
        .checked_add(1)
        .ok_or_else(|| ExtractError::new("too many unsafe operations in one function"))?;
    let group = SafetyEffectGroupKey::new(
        typed_owner,
        u32::try_from(fact.effect_group.id)
            .map_err(|_| ExtractError::new("too many raw safety effect groups"))?,
    );
    bodies
        .get_mut(&generic_function)
        .expect("generic unsafe-operation body was inserted")
        .typed_safety_groups
        .insert(group.local_id());
    typed_operations.push(PendingTypedUnsafeOperation {
        operation: UnsafeOperationEntity::new(operation_key, fact.op),
        safety_effect_group: group,
        presentation_anchor: source_range.as_ref().map(SourceTable::anchor_from_range),
        expanded_anchor: expanded_range.as_ref().map(SourceTable::anchor_from_range),
        macro_expansions: typed_macro_expansions(tcx, fact.span, &mut sources.typed)?,
    });
    Ok(PreparedUnsafeOperation {
        generic_function,
        body_ids,
        operation_key,
        source_range,
        expanded_range,
        legacy_macro_expansions,
    })
}

fn attach_legacy_unsafe_operation(
    tcx: TyCtxt<'_>,
    ordinal: usize,
    fact: &RawSafetyOpFact,
    prepared: &PreparedUnsafeOperation,
    sources: &mut SourceTable,
    bodies: &mut BTreeMap<FunctionId, PendingBody>,
) -> Result<(), ExtractError> {
    let key = format!(
        "unsafe:{ordinal}:{:?}:{:?}:{}",
        fact.op, prepared.source_range, fact.effect_group.id
    );
    for body_id in prepared.body_ids.iter().copied() {
        let body = bodies
            .get_mut(&body_id)
            .expect("unsafe-operation body was inserted");
        body.effects.push(PendingEffect {
            key: key.clone(),
            effect: EffectFactIr {
                id: EffectId::new(0),
                safety_effect_group: Some(raw_safety_group_id(fact.effect_group.id)?),
                source_range: prepared.source_range.clone(),
                expanded_range: prepared.expanded_range.clone(),
                macro_expansions: prepared.legacy_macro_expansions.clone(),
                kind: EffectKindIr::UnsafeOperation { kind: fact.op },
            },
        });
        for (probing, applicable_probing) in probing_modes() {
            let marker = fact
                .marker_anchor_spans
                .iter()
                .find_map(|span| safety_span_marker_block(tcx, *span, probing));
            if let Some(marker) = marker {
                push_effect_marker(
                    tcx,
                    sources,
                    body,
                    MarkerKindIr::SafetyJustification,
                    PendingMarkerTarget::Effect(key.clone()),
                    (body_id == prepared.generic_function).then_some(
                        PendingTypedMarkerTarget::UnsafeOperation(prepared.operation_key),
                    ),
                    marker,
                    applicable_probing,
                    Vec::new(),
                )?;
            }
        }
    }
    if !prepared.body_ids.contains(&prepared.generic_function) {
        let body = bodies
            .get_mut(&prepared.generic_function)
            .expect("permanent generic unsafe-operation body was inserted");
        for (probing, applicable_probing) in probing_modes() {
            let marker = fact
                .marker_anchor_spans
                .iter()
                .find_map(|span| safety_span_marker_block(tcx, *span, probing));
            if let Some(marker) = marker {
                push_effect_marker(
                    tcx,
                    sources,
                    body,
                    MarkerKindIr::SafetyJustification,
                    PendingMarkerTarget::Effect(key.clone()),
                    Some(PendingTypedMarkerTarget::UnsafeOperation(
                        prepared.operation_key,
                    )),
                    marker,
                    applicable_probing,
                    Vec::new(),
                )?;
            }
        }
    }
    Ok(())
}

fn probing_modes() -> [(MarkerProbing, MarkerProbingIr); 2] {
    [
        (
            MarkerProbing::SourceCallsite,
            MarkerProbingIr::SourceCallsite,
        ),
        (
            MarkerProbing::MacroDefinitionFirst,
            MarkerProbingIr::MacroDefinitionFirst,
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn push_effect_marker(
    tcx: TyCtxt<'_>,
    sources: &mut SourceTable,
    body: &mut PendingBody,
    kind: MarkerKindIr,
    target: PendingMarkerTarget,
    typed_target: Option<PendingTypedMarkerTarget>,
    marker: EffectMarkerBlock,
    applicable_probing: MarkerProbingIr,
    requirements: Vec<ContractRequirementIr>,
) -> Result<(), ExtractError> {
    let source_range = sources.range(tcx, marker.span)?;
    let satisfactions = marker
        .satisfactions
        .iter()
        .map(|satisfaction| MarkerSatisfactionIr {
            requirement: satisfaction.requirement.clone(),
            reason: satisfaction.reason.clone(),
        })
        .collect::<Vec<_>>();
    let applicable_satisfactions = marker
        .applicable_satisfactions
        .iter()
        .map(|ordinal| local_id(*ordinal, "marker claim"))
        .collect::<Result<Vec<_>, _>>()?;
    if marker
        .applicable_satisfactions
        .iter()
        .any(|ordinal| *ordinal >= satisfactions.len())
    {
        return Err(ExtractError::new(
            "a human marker selected a claim outside its physical source inventory",
        ));
    }
    if let Some(target) = typed_target {
        let anchor = source_range
            .as_ref()
            .map(SourceTable::anchor_from_range)
            .ok_or_else(|| {
                ExtractError::new("a human marker did not resolve to a physical source anchor")
            })?;
        let (origin, expansion_path) = marker_expansion_identity(marker.key.origin);
        let domain = match kind {
            MarkerKindIr::PanicJustification => DomainId::new("sniff-test.panic"),
            MarkerKindIr::SafetyJustification => DomainId::new("sniff-test.safety"),
            MarkerKindIr::PanicContract | MarkerKindIr::SafetyContract => {
                return Err(ExtractError::new(
                    "a declaration contract entered human marker collection",
                ));
            }
        }
        .expect("built-in marker domain IDs are valid");
        body.typed_markers.push(PendingTypedMarker {
            occurrence: MarkerOccurrenceEntity::new(
                MarkerOccurrenceKey::new(anchor, origin),
                expansion_path,
            ),
            domain,
            satisfactions: satisfactions.clone(),
            applicable_satisfactions: applicable_satisfactions.clone(),
            target,
            source_callsite: applicable_probing == MarkerProbingIr::SourceCallsite,
            macro_definition_first: applicable_probing == MarkerProbingIr::MacroDefinitionFirst,
        });
    }
    let legacy_satisfactions = marker
        .applicable_satisfactions
        .into_iter()
        .map(|ordinal| satisfactions[ordinal].clone())
        .collect::<Vec<_>>();
    let identity = format!("{kind:?}|{:?}", marker.key);
    let key =
        format!("{identity}|{target:?}|{source_range:?}|{legacy_satisfactions:?}|{requirements:?}");
    if let Some(existing) = body.markers.iter_mut().find(|pending| pending.key == key) {
        push_unique(&mut existing.applicable_probing, applicable_probing);
    } else {
        body.markers.push(PendingMarker {
            key,
            identity,
            kind,
            source_range,
            target,
            applicable_probing: vec![applicable_probing],
            satisfactions: legacy_satisfactions,
            requirements,
        });
    }
    Ok(())
}

fn marker_expansion_identity(
    origin: MarkerOrigin,
) -> (Option<StableExpansionHash>, Vec<StableExpansionHash>) {
    let MarkerOrigin::Macro(origin) = origin else {
        return (None, Vec::new());
    };
    let mut expansion = origin;
    let mut path = Vec::new();
    while expansion != ExpnId::root() {
        let data = expansion.expn_data();
        if matches!(data.kind, ExpnKind::Macro(..)) {
            path.push(StableExpansionHash::from_expn_id(expansion));
        }
        expansion = data.parent;
    }
    path.reverse();
    (Some(StableExpansionHash::from_expn_id(origin)), path)
}

fn panic_requirements(
    source_target: Option<&PendingFunctionTarget>,
    runtime_target: &PendingCallTarget,
) -> Vec<ContractRequirementIr> {
    source_target
        .and_then(|target| target.contracts.panic.as_ref())
        .or_else(|| target_contracts(runtime_target).and_then(|contracts| contracts.panic.as_ref()))
        .map_or_else(Vec::new, |contract| contract.requirements.clone())
}

fn safety_requirements(
    source_target: Option<&PendingFunctionTarget>,
    runtime_target: &PendingCallTarget,
) -> Vec<ContractRequirementIr> {
    source_target
        .and_then(|target| target.contracts.safety.as_ref())
        .or_else(|| {
            target_contracts(runtime_target).and_then(|contracts| contracts.safety.as_ref())
        })
        .map_or_else(Vec::new, |contract| contract.requirements.clone())
}

fn target_contracts(target: &PendingCallTarget) -> Option<&FunctionContractsIr> {
    target_function(target).map(|target| &target.contracts)
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

struct PendingBody {
    function: FunctionId,
    provenance: FunctionBodyProvenanceIr,
    display_path: String,
    attributes: FunctionAttributesIr,
    declaration_attributes: FunctionAttributesIr,
    contracts: FunctionContractsIr,
    source_range: Option<SourceRangeIr>,
    calls: Vec<PendingCall>,
    effects: Vec<PendingEffect>,
    markers: Vec<PendingMarker>,
    typed_markers: Vec<PendingTypedMarker>,
    typed_safety_groups: BTreeSet<u32>,
    projects_to_legacy: bool,
}

impl PendingBody {
    fn push_contract_marker(&mut self, kind: MarkerKindIr, contract: RawContractIr) {
        self.markers.push(PendingMarker {
            key: format!("{kind:?}|function|{:?}", contract.source_range),
            identity: format!("{kind:?}|function|{:?}", contract.source_range),
            kind,
            source_range: contract.source_range,
            target: PendingMarkerTarget::Function,
            applicable_probing: vec![
                MarkerProbingIr::SourceCallsite,
                MarkerProbingIr::MacroDefinitionFirst,
            ],
            satisfactions: Vec::new(),
            requirements: contract.requirements,
        });
    }

    fn finish(mut self) -> Result<FinishedBody, ExtractError> {
        self.calls.sort_by(|left, right| left.key.cmp(&right.key));
        self.effects.sort_by(|left, right| left.key.cmp(&right.key));
        self.markers.sort_by(|left, right| left.key.cmp(&right.key));

        let mut call_ids = BTreeMap::new();
        let calls = self
            .calls
            .into_iter()
            .enumerate()
            .map(|(index, pending)| {
                let id = local_id(index, "call")?;
                let key = pending.key.clone();
                let call = pending.into_legacy(CallId::new(id));
                call_ids.insert(key, call.id);
                Ok(call)
            })
            .collect::<Result<Vec<_>, ExtractError>>()?;
        let mut effect_ids = BTreeMap::new();
        let effects = self
            .effects
            .into_iter()
            .enumerate()
            .map(|(index, mut pending)| {
                let id = local_id(index, "effect")?;
                pending.effect.id = EffectId::new(id);
                effect_ids.insert(pending.key, pending.effect.id);
                Ok(pending.effect)
            })
            .collect::<Result<Vec<_>, ExtractError>>()?;
        let markers = self
            .markers
            .into_iter()
            .enumerate()
            .map(|(index, pending)| {
                let target = match pending.target {
                    PendingMarkerTarget::Function => MarkerTargetIr::Function(self.function),
                    PendingMarkerTarget::Call(key) => {
                        MarkerTargetIr::Call(*call_ids.get(&key).ok_or_else(|| {
                            ExtractError::new("marker refers to an unknown extracted call")
                        })?)
                    }
                    PendingMarkerTarget::Effect(key) => {
                        MarkerTargetIr::Effect(*effect_ids.get(&key).ok_or_else(|| {
                            ExtractError::new("marker refers to an unknown extracted effect")
                        })?)
                    }
                };
                Ok(MarkerIr {
                    id: MarkerId::new(local_id(index, "marker")?),
                    identity: pending.identity,
                    kind: pending.kind,
                    source_range: pending.source_range,
                    target,
                    applicable_probing: pending.applicable_probing,
                    satisfactions: pending.satisfactions,
                    requirements: pending.requirements,
                })
            })
            .collect::<Result<Vec<_>, ExtractError>>()?;

        Ok(FinishedBody {
            body: FunctionBodyIr {
                function: self.function,
                provenance: self.provenance,
                display_path: self.display_path,
                attributes: self.attributes,
                source_range: self.source_range,
                calls,
                effects,
                markers,
            },
        })
    }
}

struct FinishedBody {
    body: FunctionBodyIr,
}

fn local_id(index: usize, label: &str) -> Result<u32, ExtractError> {
    u32::try_from(index)
        .map_err(|_| ExtractError::new(format!("too many {label} facts in one function body")))
}

struct PendingCall {
    key: String,
    stable_sort_key: PendingCallSortKey,
    call_site: u32,
    kind: CallKind,
    safety_effect_group: u32,
    requires_unsafe: bool,
    inside_builtin_unsafe: bool,
    presentation_anchor: Option<SourceAnchorKey>,
    expanded_anchor: Option<SourceAnchorKey>,
    callee_anchor: Option<SourceAnchorKey>,
    applicable_attribution: Vec<CallAttributionRole>,
    callable_keys: Vec<CallableKey>,
    targets: Vec<CollectedCallTarget>,
    callable_declarations: Vec<PendingCallableDeclaration>,
    opaque_target_description: Option<String>,
    panic_requirements: Vec<ContractRequirementIr>,
    safety_requirements: Vec<ContractRequirementIr>,
    typed_macro_expansions: Vec<ExtractedMacroExpansionFrame>,
    legacy: PendingLegacyCallProjection,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PendingCallSortKey {
    kind: CallKind,
    presentation_anchor: Option<SourceAnchorKey>,
    expanded_anchor: Option<SourceAnchorKey>,
    callee_anchor: Option<SourceAnchorKey>,
    macro_expansions: Vec<StableExpansionHash>,
    targets: Vec<(CallTargetRole, FunctionKey)>,
    compiler_assert_site: Option<reachability::MirBodyLocation>,
    call_site: u32,
    safety_effect_group: u32,
    requires_unsafe: bool,
    inside_builtin_unsafe: bool,
}

impl PendingCall {
    fn into_legacy(self, id: CallId) -> CallEdgeIr {
        CallEdgeIr {
            id,
            call_site: CallSiteId::new(self.call_site),
            kind: legacy_call_kind(self.kind),
            safety_effect_group: Some(SafetyEffectGroupId::new(self.safety_effect_group)),
            requires_unsafe: self.requires_unsafe,
            inside_builtin_unsafe: self.inside_builtin_unsafe,
            source_range: self
                .presentation_anchor
                .as_ref()
                .map(SourceTable::project_anchor),
            expanded_range: self
                .expanded_anchor
                .as_ref()
                .map(SourceTable::project_anchor),
            macro_expansions: self.legacy.macro_expansions,
            callee_range: self.callee_anchor.as_ref().map(SourceTable::project_anchor),
            applicable_attribution: self
                .applicable_attribution
                .into_iter()
                .map(|role| match role {
                    CallAttributionRole::ErasureSite => CallableAttributionIr::ErasureSites,
                    CallAttributionRole::CallSite => CallableAttributionIr::CallSites,
                })
                .collect(),
            callable_keys: self
                .callable_keys
                .into_iter()
                .map(|key| match key {
                    CallableKey::FnPointer(identity) => CallableKeyIr::FnPointer(identity),
                    CallableKey::DynDispatch(identity) => CallableKeyIr::DynDispatch(identity),
                })
                .collect(),
            source_target: self
                .legacy
                .source_target
                .map(PendingFunctionTarget::into_legacy),
            target: self.legacy.target.into_legacy(),
        }
    }
}

struct PendingLegacyCallProjection {
    macro_expansions: Vec<MacroExpansionFrameIr>,
    source_target: Option<PendingFunctionTarget>,
    target: PendingCallTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingFunctionTarget {
    function: FunctionId,
    display_path: String,
    attributes: FunctionAttributesIr,
    contracts: FunctionContractsIr,
}

impl PendingFunctionTarget {
    fn into_legacy(self) -> FunctionTargetIr {
        FunctionTargetIr {
            function: self.function,
            display_path: self.display_path,
            attributes: self.attributes,
            contracts: self.contracts,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingOpaqueTarget {
    Trait(PendingFunctionTarget),
    Function(PendingFunctionTarget),
}

impl PendingOpaqueTarget {
    fn into_legacy(self) -> OpaqueTargetIr {
        match self {
            Self::Trait(target) => OpaqueTargetIr::Trait(target.into_legacy()),
            Self::Function(target) => OpaqueTargetIr::Function(target.into_legacy()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingCallTarget {
    Function(PendingFunctionTarget),
    OpaqueBoundary {
        description: String,
        target: Option<PendingOpaqueTarget>,
    },
}

impl PendingCallTarget {
    fn into_legacy(self) -> CallTargetIr {
        match self {
            Self::Function(target) => CallTargetIr::Function(target.into_legacy()),
            Self::OpaqueBoundary {
                description,
                target,
            } => CallTargetIr::OpaqueBoundary {
                description,
                target: target.map(PendingOpaqueTarget::into_legacy),
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingCallableDeclaration {
    callable: CallableEntity,
    panic_contract: Option<CollectedPanicContract>,
    safety_contract: Option<CollectedSafetyContract>,
}

struct PendingEffect {
    key: String,
    effect: EffectFactIr,
}

struct PendingMarker {
    key: String,
    identity: String,
    kind: MarkerKindIr,
    source_range: Option<SourceRangeIr>,
    target: PendingMarkerTarget,
    applicable_probing: Vec<MarkerProbingIr>,
    satisfactions: Vec<MarkerSatisfactionIr>,
    requirements: Vec<ContractRequirementIr>,
}

#[derive(Clone, Debug)]
enum PendingMarkerTarget {
    Function,
    Call(String),
    Effect(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingTypedMarkerTarget {
    Call(String),
    Effect(String),
    UnsafeOperation(UnsafeOperationKey),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingTypedMarker {
    occurrence: MarkerOccurrenceEntity,
    domain: DomainId,
    satisfactions: Vec<MarkerSatisfactionIr>,
    applicable_satisfactions: Vec<u32>,
    target: PendingTypedMarkerTarget,
    source_callsite: bool,
    macro_definition_first: bool,
}

#[derive(Default)]
struct ExtractionSources {
    legacy: SourceTable,
    typed: SourceTable,
}

#[derive(Default)]
struct SourceTable {
    files: BTreeMap<String, SourceFileEntity>,
    anchors: BTreeSet<SourceAnchorKey>,
}

impl SourceTable {
    fn range(
        &mut self,
        tcx: TyCtxt<'_>,
        span: Span,
    ) -> Result<Option<SourceRangeIr>, ExtractError> {
        if span.is_dummy() {
            return Ok(None);
        }
        let file = tcx.sess.source_map().lookup_source_file(span.lo());
        if span.lo() < file.start_pos || span.hi() > file.end_position() {
            return Err(ExtractError::new(format!(
                "span {}..{} crosses source-file boundary `{}`",
                span.lo().0,
                span.hi().0,
                file.name.prefer_local_unconditionally()
            )));
        }
        let id = stable_source_file_id(&file);
        self.files.entry(id.as_str().to_owned()).or_insert_with(|| {
            SourceFileEntity::new(
                id.as_str(),
                source_filename(&file),
                file.src_hash.to_string(),
                u64::from(file.normalized_source_len.to_u32()),
            )
        });
        let anchor = SourceAnchorKey::new(
            id.as_str(),
            u64::from(span.lo().0 - file.start_pos.0),
            u64::from(span.hi().0 - file.start_pos.0),
        );
        self.anchors.insert(anchor.clone());
        Ok(Some(Self::project_anchor(&anchor)))
    }

    fn into_files(self) -> Vec<SourceFileIr> {
        self.files
            .into_values()
            .map(|file| SourceFileIr {
                id: SourceFileId::new(file.id()),
                filename: file.filename().to_owned(),
                content_hash: file.content_hash().to_owned(),
                byte_len: file.byte_len(),
            })
            .collect()
    }

    fn project_anchor(anchor: &SourceAnchorKey) -> SourceRangeIr {
        SourceRangeIr {
            file: SourceFileId::new(anchor.file()),
            byte_start: anchor.byte_start(),
            byte_end: anchor.byte_end(),
        }
    }

    fn anchor_from_range(range: &SourceRangeIr) -> SourceAnchorKey {
        SourceAnchorKey::new(range.file.as_str(), range.byte_start, range.byte_end)
    }

    fn source_files(&self) -> Vec<SourceFileEntity> {
        self.files.values().cloned().collect()
    }

    fn source_anchors(&self) -> Vec<SourceAnchorEntity> {
        self.anchors
            .iter()
            .cloned()
            .map(SourceAnchorEntity::new)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use reachability::{
        DynDispatchVTableEdges, FnPointerEdges, ReachabilityEdgeKind, ReachabilityHalt,
    };
    use rustc_driver::{Callbacks, Compilation};
    use rustc_hir::def_id::{CRATE_DEF_ID, DefId, DefIndex};
    use rustc_interface::interface;
    use rustc_middle::ty::TyCtxt;
    use rustc_span::{BytePos, Span};

    use super::{
        RawSafetyGroupResolver, extract_artifact_bundle, extraction_options, probing_modes,
        reachability_edge_description, reachability_halt_description,
    };
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::encoded::ArtifactFactIr;
    use crate::analysis::facts::human::{
        EvidenceClaimSelector,
        markers::{
            CallOccurrenceHasMarkerClaimCandidate, EffectSiteHasMarkerClaimCandidate,
            MarkerClaimEntity, MarkerOccurrenceEntity, UnsafeOperationHasMarkerClaimCandidate,
        },
    };
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::panic::contracts::PanicContractFact;
    use crate::analysis::facts::panic::model::{
        BinaryOverflowOperation, MirAssertFact, MirAssertKind,
    };
    use crate::analysis::facts::program::topology::{
        CallMacroExpansionEntity, CallMacroExpansionHasCallsite,
    };
    use crate::analysis::facts::program::{
        EffectSiteEntity, FunctionEntity, FunctionKey, MacroExpansionEntity,
        MacroExpansionHasCallsite,
    };
    use crate::analysis::facts::safety::SafetyContractFact;
    use crate::analysis::facts::safety::operations::{
        UnsafeOperationEntity, UnsafeOperationMacroExpansionEntity,
    };
    use crate::analysis::facts::schema::EntitySchema;
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::analysis::ir::{
        ArtifactAnalysisIr, CallEdgeKindIr, CallSiteId, EffectKindIr, MarkerProbingIr,
        SafetyEffectGroupId,
    };
    use crate::safety::{
        RawSafetyCallFact, RawSafetyEffectGroup, RawSafetyFacts, RawSafetyGroupFact,
        RawSafetyOpFact, SafetyOpKind,
    };

    fn span(start: u32, end: u32) -> Span {
        Span::with_root_ctxt(BytePos(start), BytePos(end))
    }

    const TYPED_ASSERT_SOURCE: &str = r"
macro_rules! checked_lookup {
    ($values:expr, $index:expr) => {{
        let first = $values[$index];
        let second = $values[$index];
        first + second
    }};
}

pub fn entry(values: &[u8], index: usize) -> u8 {
    checked_lookup!(values, index)
}
";

    const SAME_SPAN_ASSERT_SOURCE: &str = r"
macro_rules! duplicate {
    ($expression:expr) => {
        ($expression, $expression)
    };
}

#[inline(never)]
fn select(values: &[u8]) -> &[u8] {
    values
}

pub fn entry(values: &[u8], index: usize) -> (u8, u8) {
    duplicate!(select(values)[index])
}
";

    const EQUAL_CALLSITE_MACRO_ASSERT_SOURCE: &str = r"
macro_rules! repeated_check {
    ($values:expr, $index:expr) => {{
        select($values)[$index]
    }};
}

macro_rules! duplicate_tokens {
    ($expression:expr) => {
        ($expression, $expression)
    };
}

#[inline(never)]
fn select(values: &[u8]) -> &[u8] {
    values
}

pub fn entry(values: &[u8], index: usize) -> (u8, u8) {
    duplicate_tokens!(repeated_check!(values, index))
}
";

    const DIRECT_COLLECTION_SOURCE: &str = r"
macro_rules! read_pointer_inner {
    ($pointer:expr) => {{
        unsafe { &*$pointer }
    }};
}

macro_rules! read_pointer {
    ($pointer:expr) => {{
        // SAFETY: pointer-valid: guaranteed by the caller.
        read_pointer_inner!($pointer)
    }};
}

/// # Safety
/// - `pointer-valid`: `pointer` must be valid for reads.
///
/// # Panics
/// - `index-in-bounds`: `index` must be less than `values.len()`.
pub unsafe fn documented<T>(pointer: *const T, values: &[u8], index: usize) -> u8 {
    let _reference = read_pointer!(pointer);
    // PANIC: index-in-bounds: guaranteed by the caller.
    values[index]
}

pub fn entry(first: *const u8, second: *const u16, values: &[u8], index: usize) -> u8 {
    unsafe {
        documented::<u8>(first, values, index)
            + documented::<u16>(second, values, index)
    }
}
";

    const CLOSURE_UNSAFE_SOURCE: &str = r"
pub fn closure_owner(pointer: *const u8) -> u8 {
    let read = || {
        // SAFETY: pointer validity is guaranteed by the caller.
        unsafe { *pointer }
    };
    read()
}
";

    const MIXED_MARKER_SOURCE: &str = r"
struct Chain(u8);

impl Chain {
    fn first(self) -> Self { self }
    fn second(self) -> u8 { self.0 }
}

fn make(value: u8) -> Chain { Chain(value) }

pub fn entry(value: u8) -> u8 {
    // PANIC: the complete statement invariant was checked.
    // PANIC: nested-link: each nested link was checked.
    make(value)
        .first()
        .second()
}
";

    #[derive(Debug)]
    struct DirectCollectionCompilerResult {
        deterministic: bool,
        unsafe_operation_count: usize,
        exact_runtime_bodies_for_unsafe_definition: usize,
        panic_contract_count: usize,
        safety_contract_count: usize,
        marker_occurrence_count: usize,
        marker_claim_count: usize,
        effect_marker_candidate_count: usize,
        unsafe_marker_candidate_count: usize,
        unsafe_macro_frame_count: usize,
        macro_marker_occurrence_count: usize,
        legacy_generic_closure_bodies: usize,
        legacy_exact_closure_bodies: usize,
        legacy_exact_closure_unsafe_effects: usize,
        marker_claims: Vec<(u32, EvidenceClaimSelector)>,
        call_candidate_claim_ordinals: Vec<u32>,
        invariants: DirectCollectionInvariants,
    }

    #[derive(Debug)]
    struct DirectCollectionInvariants {
        unsafe_owners_are_generic: bool,
        contract_owners_are_generic: bool,
        unsafe_marker_path_is_endpoint_prefix: bool,
    }

    #[derive(Clone, Copy)]
    struct LegacyClosureObservation {
        generic_bodies: usize,
        exact_bodies: usize,
        exact_unsafe_effects: usize,
    }

    fn observe_legacy_closure(ir: &ArtifactAnalysisIr) -> LegacyClosureObservation {
        let closure_bodies = ir
            .functions
            .iter()
            .filter(|body| body.display_path.contains("::{closure"))
            .collect::<Vec<_>>();
        LegacyClosureObservation {
            generic_bodies: closure_bodies
                .iter()
                .filter(|body| body.function.instance_hash.is_none())
                .count(),
            exact_bodies: closure_bodies
                .iter()
                .filter(|body| body.function.instance_hash.is_some())
                .count(),
            exact_unsafe_effects: closure_bodies
                .into_iter()
                .filter(|body| body.function.instance_hash.is_some())
                .flat_map(|body| &body.effects)
                .filter(|effect| matches!(effect.kind, EffectKindIr::UnsafeOperation { .. }))
                .count(),
        }
    }

    #[derive(Default)]
    struct DirectCollectionCallbacks {
        result: Option<DirectCollectionCompilerResult>,
    }

    impl Callbacks for DirectCollectionCallbacks {
        fn after_analysis(
            &mut self,
            _compiler: &interface::Compiler,
            tcx: TyCtxt<'_>,
        ) -> Compilation {
            self.result = Some(observe_direct_collection(tcx));
            Compilation::Stop
        }
    }

    fn observe_direct_collection(tcx: TyCtxt<'_>) -> DirectCollectionCompilerResult {
        let first = extract_artifact_bundle(tcx).expect("first direct typed extraction");
        first
            .legacy_ir
            .validate()
            .expect("direct collection preserves valid legacy IR");
        let legacy_closure = observe_legacy_closure(&first.legacy_ir);
        let second = extract_artifact_bundle(tcx)
            .expect("second direct typed extraction")
            .facts;
        let deterministic = first.facts == second;
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let view = ArtifactDbView::open(&first.facts, registry.schemas()).unwrap();
        observe_direct_view(&view, deterministic, legacy_closure)
    }

    fn observe_direct_view(
        view: &ArtifactDbView<'_>,
        deterministic: bool,
        legacy_closure: LegacyClosureObservation,
    ) -> DirectCollectionCompilerResult {
        let operations = view.table::<UnsafeOperationEntity>().unwrap();
        let unsafe_definition = operations
            .iter()
            .next()
            .map(|operation| operation.key().owner().definition());
        let functions = view.table::<FunctionEntity>().unwrap();
        let exact_runtime_bodies_for_unsafe_definition = unsafe_definition.map_or(0, |hash| {
            functions
                .iter()
                .filter(|function| {
                    function.key().definition() == hash && function.key().instance().is_some()
                })
                .count()
        });
        let panic_contracts = view.facts::<PanicContractFact>().unwrap();
        let safety_contracts = view.facts::<SafetyContractFact>().unwrap();
        let callables = view
            .table::<crate::analysis::facts::program::topology::CallableEntity>()
            .unwrap();
        let owner_is_generic = |owner: Option<&crate::analysis::facts::encoded::EntityRef>| {
            owner.is_some_and(|owner| {
                callables
                    .get(owner.row)
                    .is_some_and(|callable| callable.key().instance().is_none())
            })
        };
        let contract_owners_are_generic = panic_contracts
            .iter()
            .all(|contract| owner_is_generic(contract.metadata.owner.as_ref()))
            && safety_contracts
                .iter()
                .all(|contract| owner_is_generic(contract.metadata.owner.as_ref()));
        let unsafe_macro_frames = view.table::<UnsafeOperationMacroExpansionEntity>().unwrap();
        DirectCollectionCompilerResult {
            deterministic,
            unsafe_operation_count: operations.len(),
            exact_runtime_bodies_for_unsafe_definition,
            panic_contract_count: panic_contracts.len(),
            safety_contract_count: safety_contracts.len(),
            marker_occurrence_count: view.table::<MarkerOccurrenceEntity>().unwrap().len(),
            marker_claim_count: view.table::<MarkerClaimEntity>().unwrap().len(),
            effect_marker_candidate_count: view
                .relations::<EffectSiteHasMarkerClaimCandidate>()
                .unwrap()
                .len(),
            unsafe_marker_candidate_count: view
                .relations::<UnsafeOperationHasMarkerClaimCandidate>()
                .unwrap()
                .len(),
            unsafe_macro_frame_count: unsafe_macro_frames.len(),
            macro_marker_occurrence_count: view
                .table::<MarkerOccurrenceEntity>()
                .unwrap()
                .iter()
                .filter(|occurrence| occurrence.key().origin().is_some())
                .count(),
            legacy_generic_closure_bodies: legacy_closure.generic_bodies,
            legacy_exact_closure_bodies: legacy_closure.exact_bodies,
            legacy_exact_closure_unsafe_effects: legacy_closure.exact_unsafe_effects,
            marker_claims: view
                .table::<MarkerClaimEntity>()
                .unwrap()
                .iter()
                .map(|claim| (claim.key().source_ordinal(), claim.selector().clone()))
                .collect(),
            call_candidate_claim_ordinals: view
                .relations::<CallOccurrenceHasMarkerClaimCandidate>()
                .unwrap()
                .into_iter()
                .map(|candidate| view.entity(candidate.to).unwrap().key().source_ordinal())
                .collect(),
            invariants: DirectCollectionInvariants {
                unsafe_owners_are_generic: operations
                    .iter()
                    .all(|operation| operation.key().owner().instance().is_none()),
                contract_owners_are_generic,
                unsafe_marker_path_is_endpoint_prefix: unsafe_marker_path_is_endpoint_prefix(
                    view,
                    &unsafe_macro_frames,
                ),
            },
        }
    }

    fn unsafe_marker_path_is_endpoint_prefix(
        view: &ArtifactDbView<'_>,
        frames: &crate::analysis::facts::view::TypedTable<UnsafeOperationMacroExpansionEntity>,
    ) -> bool {
        view.relations::<UnsafeOperationHasMarkerClaimCandidate>()
            .unwrap()
            .into_iter()
            .all(|candidate| {
                let operation = view.entity(candidate.from).unwrap();
                let claim = view.entity(candidate.to).unwrap();
                let occurrence = view
                    .entity_by_key::<MarkerOccurrenceEntity>(claim.key().occurrence())
                    .unwrap()
                    .unwrap();
                let mut path = frames
                    .iter()
                    .filter(|frame| frame.key().operation() == operation.key())
                    .collect::<Vec<_>>();
                path.sort_by_key(|frame| frame.key().depth());
                let path = path
                    .into_iter()
                    .map(UnsafeOperationMacroExpansionEntity::expansion_hash)
                    .collect::<Vec<_>>();
                path.starts_with(occurrence.1.expansion_path())
            })
    }

    #[derive(Debug)]
    struct TypedAssertCompilerResult {
        deterministic: bool,
        facts: ArtifactFactIr,
        kinds: Vec<MirAssertKind>,
        legacy_assert_calls: usize,
        legacy_effects: usize,
        effect_sites: usize,
        unique_effect_sites: usize,
        repeated_macros: RepeatedMacroObservation,
    }

    #[derive(Debug)]
    struct RepeatedMacroObservation {
        frame_count: usize,
        depths: Vec<u32>,
        unique_hash_count: usize,
        callsite_count: usize,
        unique_callsite_count: usize,
        call_frame_count: usize,
        unique_call_hash_count: usize,
        call_macro_callsite_count: usize,
        unique_call_macro_callsite_count: usize,
    }

    #[derive(Default)]
    struct TypedAssertCallbacks {
        result: Option<TypedAssertCompilerResult>,
    }

    fn observe_repeated_macros(view: &ArtifactDbView<'_>) -> RepeatedMacroObservation {
        let macro_expansions = view.table::<MacroExpansionEntity>().unwrap();
        let frames = macro_expansions
            .iter()
            .filter(|frame| frame.display_path().ends_with("::repeated_check"))
            .collect::<Vec<_>>();
        let unique_hash_count = frames
            .iter()
            .map(|frame| frame.expansion_hash())
            .collect::<BTreeSet<_>>()
            .len();
        let callsites = view
            .relations::<MacroExpansionHasCallsite>()
            .unwrap()
            .into_iter()
            .filter_map(|relation| {
                let frame = view.entity(relation.from).unwrap();
                frame
                    .display_path()
                    .ends_with("::repeated_check")
                    .then(|| view.entity(relation.to).unwrap().anchor().clone())
            })
            .collect::<Vec<_>>();
        let call_macro_expansions = view.table::<CallMacroExpansionEntity>().unwrap();
        let call_frames = call_macro_expansions
            .iter()
            .filter(|frame| frame.display_path().ends_with("::repeated_check"))
            .collect::<Vec<_>>();
        let call_macro_callsites = view
            .relations::<CallMacroExpansionHasCallsite>()
            .unwrap()
            .into_iter()
            .filter_map(|relation| {
                let frame = view.entity(relation.from).unwrap();
                frame
                    .display_path()
                    .ends_with("::repeated_check")
                    .then(|| view.entity(relation.to).unwrap().anchor().clone())
            })
            .collect::<Vec<_>>();
        RepeatedMacroObservation {
            frame_count: frames.len(),
            depths: frames
                .iter()
                .map(|frame| frame.expansion().depth())
                .collect(),
            unique_hash_count,
            callsite_count: callsites.len(),
            unique_callsite_count: callsites.into_iter().collect::<BTreeSet<_>>().len(),
            call_frame_count: call_frames.len(),
            unique_call_hash_count: call_frames
                .iter()
                .map(|frame| frame.expansion_hash())
                .collect::<BTreeSet<_>>()
                .len(),
            call_macro_callsite_count: call_macro_callsites.len(),
            unique_call_macro_callsite_count: call_macro_callsites
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len(),
        }
    }

    impl Callbacks for TypedAssertCallbacks {
        fn after_analysis(
            &mut self,
            _compiler: &interface::Compiler,
            tcx: TyCtxt<'_>,
        ) -> Compilation {
            let first_bundle = extract_artifact_bundle(tcx).expect("first typed extraction");
            first_bundle
                .legacy_ir
                .validate()
                .expect("typed fact collection preserves valid legacy IR");
            let legacy_effects = first_bundle
                .legacy_ir
                .functions
                .iter()
                .flat_map(|body| {
                    let function =
                        FunctionKey::new(body.function.def_path_hash, body.function.instance_hash);
                    body.effects.iter().filter_map(move |effect| {
                        matches!(effect.kind, EffectKindIr::CompilerAssert { .. })
                            .then_some((function, effect.id.index()))
                    })
                })
                .collect::<BTreeSet<_>>();
            let legacy_assert_calls = first_bundle
                .legacy_ir
                .functions
                .iter()
                .flat_map(|body| &body.calls)
                .filter(|call| call.kind == CallEdgeKindIr::Assert)
                .count();
            let first = first_bundle.facts;
            let second = extract_artifact_bundle(tcx)
                .expect("second typed extraction")
                .facts;
            let mut registry = AnalysisRegistry::<()>::new();
            registry.install(&CollectedArtifactSchemaPack).unwrap();
            let view = ArtifactDbView::open(&first, registry.schemas()).unwrap();
            let kinds = view
                .facts::<MirAssertFact>()
                .unwrap()
                .into_iter()
                .map(|fact| fact.fact.data.kind())
                .collect::<Vec<_>>();
            let effect_sites = view.table::<EffectSiteEntity>().unwrap();
            let unique_effect_sites = effect_sites
                .iter()
                .map(EntitySchema::key)
                .collect::<BTreeSet<_>>()
                .len();
            let repeated_macros = observe_repeated_macros(&view);
            self.result = Some(TypedAssertCompilerResult {
                deterministic: first == second,
                facts: first.clone(),
                kinds,
                legacy_assert_calls,
                legacy_effects: legacy_effects.len(),
                effect_sites: effect_sites.len(),
                unique_effect_sites,
                repeated_macros,
            });
            Compilation::Stop
        }
    }

    fn compile_typed_asserts(source_text: &str, crate_name: &str) -> TypedAssertCompilerResult {
        let directory = tempfile::tempdir().expect("temporary compiler fixture");
        let source = directory.path().join("lib.rs");
        fs::write(&source, source_text).expect("write compiler fixture");
        run_typed_assert_compiler(&source, crate_name)
    }

    fn run_typed_assert_compiler(source: &Path, crate_name: &str) -> TypedAssertCompilerResult {
        let sysroot = Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()
            .expect("query rustc sysroot");
        assert!(sysroot.status.success());
        let sysroot = String::from_utf8(sysroot.stdout)
            .expect("UTF-8 sysroot")
            .trim()
            .to_owned();
        let args = vec![
            String::from("rustc"),
            String::from("--crate-name"),
            String::from(crate_name),
            String::from("--crate-type"),
            String::from("lib"),
            String::from("--edition"),
            String::from("2024"),
            String::from("--sysroot"),
            sysroot,
            String::from("-Zno-steal-thir"),
            String::from("-Awarnings"),
            source.display().to_string(),
        ];
        let mut callbacks = TypedAssertCallbacks::default();
        rustc_driver::run_compiler(&args, &mut callbacks);
        callbacks.result.expect("compiler callback ran")
    }

    fn compile_direct_collection(
        source_text: &str,
        crate_name: &str,
    ) -> DirectCollectionCompilerResult {
        let directory = tempfile::tempdir().expect("temporary compiler fixture");
        let source = directory.path().join("lib.rs");
        fs::write(&source, source_text).expect("write compiler fixture");
        let sysroot = Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()
            .expect("query rustc sysroot");
        assert!(sysroot.status.success());
        let sysroot = String::from_utf8(sysroot.stdout)
            .expect("UTF-8 sysroot")
            .trim()
            .to_owned();
        let args = vec![
            String::from("rustc"),
            String::from("--crate-name"),
            String::from(crate_name),
            String::from("--crate-type"),
            String::from("lib"),
            String::from("--edition"),
            String::from("2024"),
            String::from("--sysroot"),
            sysroot,
            String::from("-Zno-steal-thir"),
            String::from("-Awarnings"),
            source.display().to_string(),
        ];
        let mut callbacks = DirectCollectionCallbacks::default();
        rustc_driver::run_compiler(&args, &mut callbacks);
        callbacks.result.expect("compiler callback ran")
    }

    #[test]
    fn compiler_extraction_emits_precise_deterministic_typed_assert_facts() {
        let result = compile_typed_asserts(TYPED_ASSERT_SOURCE, "typed_assert_fixture");

        assert!(result.deterministic);
        assert_eq!(result.effect_sites, result.unique_effect_sites);
        assert_eq!(result.effect_sites, result.kinds.len());
        assert!(result.kinds.contains(&MirAssertKind::BoundsCheck));
        assert!(
            result
                .kinds
                .contains(&MirAssertKind::Overflow(BinaryOverflowOperation::Addition))
        );
    }

    #[test]
    fn typed_call_occurrence_order_is_stable_across_compiler_sessions() {
        let directory = tempfile::tempdir().expect("temporary compiler fixture");
        let source = directory.path().join("lib.rs");
        fs::write(&source, EQUAL_CALLSITE_MACRO_ASSERT_SOURCE).expect("write compiler fixture");

        let first = run_typed_assert_compiler(&source, "cross_session_call_order_fixture");
        let second = run_typed_assert_compiler(&source, "cross_session_call_order_fixture");

        assert_eq!(first.facts, second.facts);
    }

    #[test]
    fn compiler_extraction_keeps_same_span_assertions_as_distinct_legacy_effects() {
        let result = compile_typed_asserts(SAME_SPAN_ASSERT_SOURCE, "same_span_assert_fixture");

        assert_eq!(result.kinds, [MirAssertKind::BoundsCheck; 2]);
        assert_eq!(result.legacy_assert_calls, 2);
        assert_eq!(result.legacy_effects, 2);
        assert_eq!(result.effect_sites, 2);
        assert_eq!(result.unique_effect_sites, 2);
    }

    #[test]
    fn repeated_macro_invocations_with_one_callsite_keep_distinct_stable_identity() {
        let result = compile_typed_asserts(
            EQUAL_CALLSITE_MACRO_ASSERT_SOURCE,
            "equal_callsite_macro_assert_fixture",
        );

        assert_eq!(result.kinds, [MirAssertKind::BoundsCheck; 2]);
        assert_eq!(result.repeated_macros.frame_count, 2);
        assert_eq!(result.repeated_macros.depths, [1, 1]);
        assert_eq!(result.repeated_macros.unique_hash_count, 2);
        assert_eq!(result.repeated_macros.callsite_count, 2);
        assert_eq!(result.repeated_macros.unique_callsite_count, 1);
        assert_eq!(result.repeated_macros.call_frame_count, 4);
        assert_eq!(result.repeated_macros.unique_call_hash_count, 2);
        assert_eq!(result.repeated_macros.call_macro_callsite_count, 4);
        assert_eq!(result.repeated_macros.unique_call_macro_callsite_count, 1);
    }

    #[test]
    fn direct_collection_keeps_source_owned_domains_generic_and_migrates_markers() {
        let result =
            compile_direct_collection(DIRECT_COLLECTION_SOURCE, "direct_collection_fixture");

        assert!(result.deterministic);
        assert_eq!(result.unsafe_operation_count, 1);
        assert!(result.invariants.unsafe_owners_are_generic);
        assert_eq!(result.exact_runtime_bodies_for_unsafe_definition, 2);
        assert_eq!(result.panic_contract_count, 1);
        assert_eq!(result.safety_contract_count, 1);
        assert!(result.invariants.contract_owners_are_generic);
        assert_eq!(result.marker_occurrence_count, 2);
        assert_eq!(result.marker_claim_count, 2);
        assert_eq!(result.effect_marker_candidate_count, 3);
        assert_eq!(result.unsafe_marker_candidate_count, 1);
        assert_eq!(result.unsafe_macro_frame_count, 2);
        assert!(result.invariants.unsafe_marker_path_is_endpoint_prefix);
        assert_eq!(result.macro_marker_occurrence_count, 1);
    }

    #[test]
    fn permanent_generic_unsafe_ownership_preserves_exact_legacy_closure_projection() {
        let result = compile_direct_collection(CLOSURE_UNSAFE_SOURCE, "closure_unsafe_fixture");

        assert_eq!(result.unsafe_operation_count, 1);
        assert!(result.invariants.unsafe_owners_are_generic);
        assert_eq!(result.legacy_generic_closure_bodies, 0);
        assert_eq!(result.legacy_exact_closure_bodies, 1);
        assert_eq!(result.legacy_exact_closure_unsafe_effects, 1);
        assert_eq!(result.unsafe_marker_candidate_count, 1);
    }

    #[test]
    fn mixed_statement_marker_preserves_full_claims_and_original_candidate_ordinals() {
        let result = compile_direct_collection(MIXED_MARKER_SOURCE, "mixed_marker_fixture");

        assert_eq!(
            result.marker_claims,
            [
                (0, EvidenceClaimSelector::Unnamed),
                (1, EvidenceClaimSelector::Named(String::from("nested-link")),),
            ]
        );
        assert!(result.call_candidate_claim_ordinals.contains(&0));
        assert!(
            result
                .call_candidate_claim_ordinals
                .iter()
                .filter(|ordinal| **ordinal == 1)
                .count()
                > 1
        );
    }

    fn safety_group_id(raw: usize) -> SafetyEffectGroupId {
        SafetyEffectGroupId::new(u32::try_from(raw).expect("test safety group fits in u32"))
    }

    fn call_site_id(raw: usize) -> CallSiteId {
        CallSiteId::new(u32::try_from(raw).expect("test call site fits in u32"))
    }

    #[test]
    fn extraction_retains_raw_callable_erasure_evidence() {
        let options = extraction_options();
        assert_eq!(
            options.dyn_dispatch_vtable_edges,
            DynDispatchVTableEdges::CastSites
        );
        assert_eq!(options.fn_pointer_edges, FnPointerEdges::ReifySites);
    }

    #[test]
    fn extraction_enumerates_both_marker_probing_modes() {
        assert_eq!(
            probing_modes().map(|(_, mode)| mode),
            [
                MarkerProbingIr::SourceCallsite,
                MarkerProbingIr::MacroDefinitionFirst
            ]
        );
    }

    #[test]
    fn reachability_failures_have_stable_human_descriptions() {
        assert_eq!(
            reachability_halt_description(&ReachabilityHalt::NodeLimitReached { limit: 42 }),
            "artifact reachability analysis reached the configured node limit (42)"
        );
        assert_eq!(
            reachability_edge_description(ReachabilityEdgeKind::DirectCall),
            "direct call"
        );
        assert_eq!(
            reachability_edge_description(ReachabilityEdgeKind::FnPointerReify),
            "function-to-pointer conversion"
        );
        assert_eq!(
            reachability_edge_description(ReachabilityEdgeKind::Assert),
            "compiler check"
        );
    }

    #[test]
    fn call_grouping_prefers_the_innermost_thir_scope_and_reuses_standalone_sites() {
        let owner = CRATE_DEF_ID.to_def_id();
        let outer = RawSafetyEffectGroup {
            id: 0,
            span: span(10, 50),
        };
        let inner = RawSafetyEffectGroup {
            id: 1,
            span: span(20, 40),
        };
        let facts = RawSafetyFacts {
            groups: vec![
                RawSafetyGroupFact {
                    owner,
                    effect_group: outer,
                },
                RawSafetyGroupFact {
                    owner,
                    effect_group: inner,
                },
            ],
            calls: Vec::new(),
            operations: vec![RawSafetyOpFact {
                owner,
                op: SafetyOpKind::DerefRawPointer,
                span: span(30, 31),
                marker_anchor_spans: vec![span(20, 40), span(30, 31)],
                effect_group: inner,
            }],
        };
        let mut resolver = RawSafetyGroupResolver::new(&facts);

        let outer_call = resolver
            .group_for_call(owner, span(15, 16), None)
            .expect("outer group");
        assert_eq!(outer_call.safety_effect_group, safety_group_id(outer.id));
        assert!(!outer_call.inside_builtin_unsafe);
        assert_eq!(outer_call.source_callee, None);

        let inner_call = resolver
            .group_for_call(owner, span(30, 31), None)
            .expect("inner group");
        assert_eq!(inner_call.safety_effect_group, safety_group_id(inner.id));
        assert_ne!(inner_call.call_site, outer_call.call_site);
        assert!(!inner_call.inside_builtin_unsafe);
        assert_eq!(inner_call.source_callee, None);

        let first = resolver
            .group_for_call(owner, span(60, 61), None)
            .expect("standalone group");
        let second = resolver
            .group_for_call(owner, span(60, 61), None)
            .expect("same standalone group");
        assert_ne!(first.safety_effect_group, outer_call.safety_effect_group);
        assert_ne!(first.safety_effect_group, inner_call.safety_effect_group);
        assert_ne!(first.call_site, outer_call.call_site);
        assert_ne!(first.call_site, inner_call.call_site);
        assert!(!first.inside_builtin_unsafe);
        assert_eq!(first.source_callee, None);
        assert_eq!(second, first);
    }

    #[test]
    fn call_grouping_disambiguates_desugared_calls_by_callee() {
        let owner = CRATE_DEF_ID.to_def_id();
        let first_callee = DefId::local(DefIndex::from_u32(1));
        let second_callee = DefId::local(DefIndex::from_u32(2));
        let unmatched_callee = DefId::local(DefIndex::from_u32(3));
        let second_source_callee = DefId::local(DefIndex::from_u32(4));
        let shared_span = span(10, 40);
        let facts = RawSafetyFacts {
            groups: Vec::new(),
            calls: vec![
                RawSafetyCallFact {
                    owner,
                    callee: Some(first_callee),
                    source_callee: Some(first_callee),
                    inside_builtin_unsafe: false,
                    call_site: 0,
                    span: shared_span,
                    effect_group: RawSafetyEffectGroup {
                        id: 0,
                        span: shared_span,
                    },
                },
                RawSafetyCallFact {
                    owner,
                    callee: Some(second_callee),
                    source_callee: Some(second_source_callee),
                    inside_builtin_unsafe: true,
                    call_site: 1,
                    span: shared_span,
                    effect_group: RawSafetyEffectGroup {
                        id: 1,
                        span: shared_span,
                    },
                },
            ],
            operations: Vec::new(),
        };
        let mut resolver = RawSafetyGroupResolver::new(&facts);

        let matched = resolver
            .group_for_call(owner, shared_span, Some(second_callee))
            .expect("callee identifies one desugared call");
        assert_eq!(
            matched.safety_effect_group,
            safety_group_id(facts.calls[1].effect_group.id)
        );
        assert_eq!(matched.call_site, call_site_id(facts.calls[1].call_site));
        assert!(matched.inside_builtin_unsafe);
        assert_eq!(matched.source_callee, Some(second_source_callee));

        let unmatched = resolver
            .group_for_call(owner, shared_span, Some(unmatched_callee))
            .expect("unmatched compiler edge gets a standalone identity");
        for call in &facts.calls {
            assert_ne!(
                unmatched.safety_effect_group,
                safety_group_id(call.effect_group.id)
            );
            assert_ne!(unmatched.call_site, call_site_id(call.call_site));
        }
        assert!(!unmatched.inside_builtin_unsafe);
        assert_eq!(unmatched.source_callee, None);
    }

    #[test]
    fn call_grouping_keeps_only_a_consensus_source_callee() {
        let owner = CRATE_DEF_ID.to_def_id();
        let first_callee = DefId::local(DefIndex::from_u32(1));
        let second_callee = DefId::local(DefIndex::from_u32(2));
        let shared_span = span(10, 40);
        let shared_group = RawSafetyEffectGroup {
            id: 0,
            span: shared_span,
        };
        let facts = RawSafetyFacts {
            groups: Vec::new(),
            calls: vec![
                RawSafetyCallFact {
                    owner,
                    callee: Some(first_callee),
                    source_callee: Some(first_callee),
                    inside_builtin_unsafe: false,
                    call_site: 0,
                    span: shared_span,
                    effect_group: shared_group,
                },
                RawSafetyCallFact {
                    owner,
                    callee: Some(second_callee),
                    source_callee: Some(second_callee),
                    inside_builtin_unsafe: false,
                    call_site: 0,
                    span: shared_span,
                    effect_group: shared_group,
                },
            ],
            operations: Vec::new(),
        };
        let mut resolver = RawSafetyGroupResolver::new(&facts);

        let call_groups = resolver
            .group_for_call(owner, shared_span, None)
            .expect("shared raw site remains a valid group");
        assert_eq!(
            call_groups.safety_effect_group,
            safety_group_id(shared_group.id)
        );
        assert_eq!(
            call_groups.call_site,
            call_site_id(facts.calls[0].call_site)
        );
        assert!(!call_groups.inside_builtin_unsafe);
        assert_eq!(call_groups.source_callee, None);
    }

    #[test]
    fn a_mismatched_callee_gets_an_independent_call_identity() {
        let owner = CRATE_DEF_ID.to_def_id();
        let source_callee = DefId::local(DefIndex::from_u32(1));
        let requested_callee = DefId::local(DefIndex::from_u32(2));
        let shared_span = span(10, 40);
        let facts = RawSafetyFacts {
            groups: Vec::new(),
            calls: vec![RawSafetyCallFact {
                owner,
                callee: Some(source_callee),
                source_callee: Some(source_callee),
                inside_builtin_unsafe: true,
                call_site: 0,
                span: shared_span,
                effect_group: RawSafetyEffectGroup {
                    id: 0,
                    span: shared_span,
                },
            }],
            operations: Vec::new(),
        };
        let mut resolver = RawSafetyGroupResolver::new(&facts);

        let call_groups = resolver
            .group_for_call(owner, shared_span, Some(requested_callee))
            .expect("a different known callee gets a standalone identity");
        assert_ne!(
            call_groups.safety_effect_group,
            safety_group_id(facts.calls[0].effect_group.id)
        );
        assert_ne!(
            call_groups.call_site,
            call_site_id(facts.calls[0].call_site)
        );
        assert!(!call_groups.inside_builtin_unsafe);
        assert_eq!(call_groups.source_callee, None);
    }

    #[test]
    fn structural_edges_get_a_stable_identity_distinct_from_thir_calls() {
        let owner = CRATE_DEF_ID.to_def_id();
        let first_callee = DefId::local(DefIndex::from_u32(1));
        let second_callee = DefId::local(DefIndex::from_u32(2));
        let shared_span = span(10, 40);
        let facts = RawSafetyFacts {
            groups: Vec::new(),
            calls: vec![
                RawSafetyCallFact {
                    owner,
                    callee: Some(first_callee),
                    source_callee: Some(first_callee),
                    inside_builtin_unsafe: false,
                    call_site: 0,
                    span: shared_span,
                    effect_group: RawSafetyEffectGroup {
                        id: 0,
                        span: shared_span,
                    },
                },
                RawSafetyCallFact {
                    owner,
                    callee: Some(second_callee),
                    source_callee: Some(second_callee),
                    inside_builtin_unsafe: false,
                    call_site: 1,
                    span: shared_span,
                    effect_group: RawSafetyEffectGroup {
                        id: 1,
                        span: shared_span,
                    },
                },
            ],
            operations: Vec::new(),
        };
        let mut resolver = RawSafetyGroupResolver::new(&facts);

        let first = resolver
            .group_for_structural_edge(owner, shared_span)
            .expect("structural edge gets its own source identity");
        let second = resolver
            .group_for_structural_edge(owner, shared_span)
            .expect("same structural edge reuses its identity");
        for call in &facts.calls {
            assert_ne!(
                first.safety_effect_group,
                safety_group_id(call.effect_group.id)
            );
            assert_ne!(first.call_site, call_site_id(call.call_site));
        }
        assert!(!first.inside_builtin_unsafe);
        assert_eq!(first.source_callee, None);
        assert_eq!(second, first);
    }

    #[test]
    fn standalone_operation_anchors_leave_structural_edges_independent() {
        let owner = CRATE_DEF_ID.to_def_id();
        let facts = RawSafetyFacts {
            groups: Vec::new(),
            calls: Vec::new(),
            operations: vec![RawSafetyOpFact {
                owner,
                op: SafetyOpKind::DerefRawPointer,
                span: span(10, 40),
                marker_anchor_spans: vec![span(10, 40)],
                effect_group: RawSafetyEffectGroup {
                    id: 0,
                    span: span(10, 40),
                },
            }],
        };
        let mut resolver = RawSafetyGroupResolver::new(&facts);

        let edge_groups = resolver
            .group_for_structural_edge(owner, span(20, 21))
            .expect("structural edge gets a standalone identity");
        assert_ne!(
            edge_groups.safety_effect_group,
            safety_group_id(facts.operations[0].effect_group.id)
        );
        assert!(!edge_groups.inside_builtin_unsafe);
        assert_eq!(edge_groups.source_callee, None);
    }

    #[test]
    fn ambiguous_containing_unsafe_scopes_use_a_fresh_group() {
        let owner = CRATE_DEF_ID.to_def_id();
        let shared_scope = span(10, 40);
        let facts = RawSafetyFacts {
            groups: vec![
                RawSafetyGroupFact {
                    owner,
                    effect_group: RawSafetyEffectGroup {
                        id: 0,
                        span: shared_scope,
                    },
                },
                RawSafetyGroupFact {
                    owner,
                    effect_group: RawSafetyEffectGroup {
                        id: 1,
                        span: shared_scope,
                    },
                },
            ],
            calls: Vec::new(),
            operations: Vec::new(),
        };
        let mut resolver = RawSafetyGroupResolver::new(&facts);

        let edge_groups = resolver
            .group_for_structural_edge(owner, span(20, 21))
            .expect("ambiguous containment degrades to a fresh group");
        for group in &facts.groups {
            assert_ne!(
                edge_groups.safety_effect_group,
                safety_group_id(group.effect_group.id)
            );
        }
        assert!(!edge_groups.inside_builtin_unsafe);
        assert_eq!(edge_groups.source_callee, None);
    }

    #[test]
    fn opaque_unsafe_function_pointer_call_retains_unsafe_requirement() {
        assert!(super::unsafe_requirement_for_edge(
            reachability::ReachabilityEdgeKind::IndirectCall,
            false,
            true,
        ));
    }

    #[test]
    fn unsafe_function_reification_is_safe_until_invoked() {
        assert!(!super::unsafe_requirement_for_edge(
            reachability::ReachabilityEdgeKind::FnPointerReify,
            true,
            true,
        ));
    }

    #[test]
    fn target_feature_safety_is_caller_relative() {
        assert!(super::compiler_call_requires_unsafe(false, false, false));
        assert!(!super::compiler_call_requires_unsafe(false, false, true));
        assert!(super::compiler_call_requires_unsafe(true, false, true));
        assert!(!super::compiler_call_requires_unsafe(true, true, true));
        assert!(super::compiler_call_requires_unsafe(true, true, false));
    }

    #[test]
    fn edge_kinds_select_their_unsafe_requirement_source() {
        use reachability::ReachabilityEdgeKind;

        assert!(!super::edge_uses_target_unsafe_requirement(
            ReachabilityEdgeKind::ConstBody
        ));
        assert!(!super::edge_uses_callable_unsafe_requirement(
            ReachabilityEdgeKind::ConstBody
        ));
        assert!(super::edge_uses_target_unsafe_requirement(
            ReachabilityEdgeKind::DirectCall
        ));
        assert!(super::edge_uses_callable_unsafe_requirement(
            ReachabilityEdgeKind::IndirectCall
        ));
    }
}
