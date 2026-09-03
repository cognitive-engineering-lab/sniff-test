//! Policy-neutral extraction of rustc bodies into artifact facts.
//!
//! Extraction deliberately enumerates local bodies without consulting report
//! roots, namespace policy, lint levels, or documentation overrides. Indirect
//! calls retain only invocation-local dispatch classification; compatible
//! callables observed elsewhere are never persisted as target evidence.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use reachability::{
    ArtifactScope, CallableEdgeInfo, DynDispatchVTableEdges, FnPointerEdges, NoopReachabilityHooks,
    ReachabilityEdge, ReachabilityEdgeKind, ReachabilityGraph, ReachabilityHalt, ReachabilityIndex,
    ReachabilityNodeExpansion, ReachabilityNodeKind, ReachabilityOptions, ReachabilityRoot,
    ReachedEdge,
};
use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LOCAL_CRATE, LocalDefId};
use rustc_middle::ty::{AssocContainer, GenericArgs, Instance, InstanceKind, TyCtxt, TyKind};
use rustc_span::{Pos, Span, StableSourceFileId};

use super::source::{source_filename, stable_source_file_id};
use crate::artifact::{
    AnnotationFact, AnnotationFactKind, AnnotationProbingFact, AnnotationSatisfactionFact,
    AnnotationTargetFact, ArtifactFacts, CallFact, CallId, CallKindFact, CallSiteId,
    CallTargetFact, CompilerAssertKind, ContractFact, ContractRequirementFact, EffectFact,
    EffectFactKind, EffectId, FunctionAttributesFact, FunctionContractsFact, FunctionFact,
    FunctionFactProvenance, FunctionId, FunctionTargetFact, IndirectCallKindFact,
    MacroExpansionFact, MarkerId, OpaqueTargetFact, SafetyEffectGroupId, SourceFileFact,
    SourceFileId, SourceRangeFact, StableDefPathHash, StableInstanceHash,
    UnverifiedMarkerProbeFact, UnverifiedMarkerProbeReason, same_macro_provenance,
};
use crate::compiler::safety::{
    RawSafetyFacts, RawSafetyOpFact, call_identity_def_id, collect_raw_safety_facts,
    fn_def_is_unsafe,
};
use crate::config::MarkerProbing;
use crate::contracts::{
    ContractDocSummary, panic_contract_doc_summary_from_attrs,
    safety_contract_doc_summary_from_attrs,
};
use crate::namespace::{canonical_namespace, namespace_candidates};
use crate::source_markers::{
    EffectMarkerBlock, MarkerProbe, panic_effect_edge_marker_block, probe_marker_candidates,
    safety_effect_edge_marker_block, safety_span_marker_block,
};

/// Failure to produce complete, structurally valid artifact facts for a required body.
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

/// Extracts every analyzable local function and associated-function body.
///
/// Reachable local closure, coroutine, and const bodies are retained as exact
/// instance bodies so facts owned by those nested bodies do not disappear.
/// No report-root or lint configuration participates in extraction.
pub(crate) fn extract_artifact_facts(tcx: TyCtxt<'_>) -> Result<ArtifactFacts, ExtractError> {
    let required_owners = analyzable_local_fn_defs(tcx).collect::<Vec<_>>();
    ensure_required_thir_is_available(tcx, &required_owners)?;

    let mut sources = SourceTable::default();
    let mut bodies = BTreeMap::<FunctionId, PendingBody>::new();
    let raw_safety_facts = collect_raw_safety_facts(tcx);
    let mut safety_groups = RawSafetyGroupResolver::new(&raw_safety_facts);

    for owner in &required_owners {
        let function = FunctionId::generic(StableDefPathHash::from_def_id(tcx, owner.to_def_id()));
        ensure_body(
            tcx,
            &mut sources,
            &mut bodies,
            function,
            owner.to_def_id(),
            FunctionFactProvenance::DefiningArtifact,
        )?;
    }

    collect_reachability_mode(
        tcx,
        &required_owners,
        extraction_options(),
        &mut sources,
        &mut bodies,
        &mut safety_groups,
    )?;

    attach_raw_unsafe_operations(tcx, raw_safety_facts.operations, &mut sources, &mut bodies)?;

    let functions = bodies
        .into_values()
        .map(PendingBody::finish)
        .collect::<Result<Vec<_>, _>>()?;
    ArtifactFacts::new(functions, sources.into_files())
        .map_err(|error| ExtractError::new(format!("extracted artifact facts is invalid: {error}")))
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
    sources: &mut SourceTable,
    bodies: &mut BTreeMap<FunctionId, PendingBody>,
    safety_groups: &mut RawSafetyGroupResolver,
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
            sources,
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
        collect_edge(tcx, view.graph(), reached, sources, bodies, safety_groups)?;
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

fn body_provenance(tcx: TyCtxt<'_>, def_id: DefId) -> FunctionFactProvenance {
    if def_id.is_local() {
        FunctionFactProvenance::DefiningArtifact
    } else {
        FunctionFactProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: tcx.stable_crate_id(LOCAL_CRATE).as_u64(),
        }
    }
}

fn collect_edge<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    reached: ReachedEdge<'_, 'tcx>,
    sources: &mut SourceTable,
    bodies: &mut BTreeMap<FunctionId, PendingBody>,
    safety_groups: &mut RawSafetyGroupResolver,
) -> Result<(), ExtractError> {
    let edge = reached.edge();
    let Some(call_kind) = call_edge_kind(reached) else {
        return Ok(());
    };
    let Some(origin) = graph.node_instance(edge.origin) else {
        return Err(ExtractError::new(
            "reachability edge has no function-instance origin",
        ));
    };
    let origin_def_id = origin.def_id();
    let body_id = body_id_for_instance(tcx, origin);
    ensure_body(
        tcx,
        sources,
        bodies,
        body_id,
        origin_def_id,
        body_provenance(tcx, origin_def_id),
    )?;

    let expanded_range = sources.range(tcx, edge.span)?;
    let macro_expansions = edge_macro_expansions(tcx, reached, sources)?;
    let source_range = sources
        .range(tcx, edge.span.source_callsite())?
        .or_else(|| expanded_range.clone());
    let callee_range = edge
        .callee_span
        .map(|span| sources.range(tcx, span))
        .transpose()?
        .flatten();
    let target = call_target(tcx, graph, edge, sources)?;
    let requires_unsafe = edge_requires_unsafe(tcx, graph, reached, &target);
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
    let declaration_target = declaration_call_target(tcx, groups.declaration_callee, sources)?;
    let key = edge_key(
        tcx,
        graph,
        edge,
        expanded_range.as_ref(),
        callee_range.as_ref(),
        &target,
    );

    let body = bodies
        .get_mut(&body_id)
        .expect("origin body was inserted before edge collection");
    let call_index = insert_or_merge_call(
        body,
        key.clone(),
        CallFact {
            id: CallId::new(0),
            call_site: groups.call_site,
            kind: call_kind,
            safety_effect_group: Some(groups.safety_effect_group),
            requires_unsafe,
            inside_builtin_unsafe: groups.inside_builtin_unsafe,
            source_range: source_range.clone(),
            expanded_range: expanded_range.clone(),
            macro_expansions: macro_expansions.clone(),
            callee_range,
            indirect_kind: indirect_call_kind(graph, reached, call_kind),
            declaration_target,
            target,
        },
    )?;
    let call_target = body.calls[call_index].call.target.clone();
    let declaration_target = body.calls[call_index].call.declaration_target.clone();

    let effect_key = collect_compiler_assert_effect(
        graph,
        edge,
        body,
        &key,
        source_range.as_ref(),
        expanded_range.as_ref(),
        &macro_expansions,
    );

    collect_edge_markers(
        tcx,
        graph,
        edge,
        groups.safety_scope_span,
        sources,
        body,
        &key,
        effect_key.as_deref(),
        declaration_target.as_ref(),
        &call_target,
    )
}

fn declaration_call_target(
    tcx: TyCtxt<'_>,
    declaration_callee: Option<DefId>,
    sources: &mut SourceTable,
) -> Result<Option<FunctionTargetFact>, ExtractError> {
    declaration_callee
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
    key: String,
    call: CallFact,
) -> Result<usize, ExtractError> {
    let Some(index) = body.calls.iter().position(|pending| pending.key == key) else {
        body.calls.push(PendingCall { key, call });
        return Ok(body.calls.len() - 1);
    };
    let existing = &mut body.calls[index].call;
    if existing.safety_effect_group != call.safety_effect_group
        || existing.call_site != call.call_site
        || existing.source_range != call.source_range
        || existing.expanded_range != call.expanded_range
        || !same_macro_provenance(&existing.macro_expansions, &call.macro_expansions)
        || existing.requires_unsafe != call.requires_unsafe
        || existing.inside_builtin_unsafe != call.inside_builtin_unsafe
        || existing.callee_range != call.callee_range
        || existing.indirect_kind != call.indirect_kind
        || existing.kind != call.kind
        || existing.declaration_target != call.declaration_target
        || existing.target != call.target
    {
        return Err(ExtractError::new(
            "one call edge resolved to inconsistent raw call facts",
        ));
    }
    Ok(index)
}

fn collect_compiler_assert_effect(
    graph: &ReachabilityGraph<'_>,
    edge: &ReachabilityEdge,
    body: &mut PendingBody,
    call_key: &str,
    source_range: Option<&SourceRangeFact>,
    expanded_range: Option<&SourceRangeFact>,
    macro_expansions: &[MacroExpansionFact],
) -> Option<String> {
    let ReachabilityNodeKind::CompilerAssert { message, .. } = &graph.node(edge.target).kind else {
        return None;
    };
    let effect_key = format!("compiler-assert:{call_key}");
    if !body.effects.iter().any(|effect| effect.key == effect_key) {
        body.effects.push(PendingEffect {
            key: effect_key.clone(),
            effect: EffectFact {
                id: EffectId::new(0),
                safety_effect_group: None,
                source_range: source_range.cloned(),
                expanded_range: expanded_range.cloned(),
                macro_expansions: macro_expansions.to_vec(),
                kind: EffectFactKind::CompilerAssert {
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
) -> Result<Vec<MacroExpansionFact>, ExtractError> {
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
        frames.push(MacroExpansionFact {
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
) -> Result<Vec<MacroExpansionFact>, ExtractError> {
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
            Ok(MacroExpansionFact {
                macro_def: StableDefPathHash::from_def_id(tcx, def_id),
                display_path: canonical_namespace(tcx, def_id),
                source_range: sources.range(tcx, call_site)?,
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn collect_edge_markers(
    tcx: TyCtxt<'_>,
    graph: &ReachabilityGraph<'_>,
    edge: &ReachabilityEdge,
    safety_scope_span: Option<Span>,
    sources: &mut SourceTable,
    body: &mut PendingBody,
    call_key: &str,
    effect_key: Option<&str>,
    declaration_target: Option<&FunctionTargetFact>,
    call_target: &CallTargetFact,
) -> Result<(), ExtractError> {
    for (probing, applicable_probing) in probing_modes() {
        let (panic_target, panic_requirements) = if let Some(effect_key) = effect_key {
            (
                PendingMarkerTarget::Effect(effect_key.to_owned()),
                Vec::new(),
            )
        } else {
            (
                PendingMarkerTarget::Call(call_key.to_owned()),
                panic_requirements(declaration_target, call_target),
            )
        };
        record_effect_marker_probe(
            tcx,
            sources,
            body,
            AnnotationFactKind::PanicJustification,
            panic_target,
            panic_effect_edge_marker_block(tcx, graph, edge, probing),
            applicable_probing,
            panic_requirements,
        )?;
        record_effect_marker_probe(
            tcx,
            sources,
            body,
            AnnotationFactKind::SafetyJustification,
            PendingMarkerTarget::Call(call_key.to_owned()),
            safety_effect_edge_marker_block(tcx, graph, edge, safety_scope_span, probing),
            applicable_probing,
            safety_requirements(declaration_target, call_target),
        )?;
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
    target: &CallTargetFact,
) -> bool {
    let signature_requires_unsafe = target
        .function_target()
        .is_some_and(|target| target.attributes.is_unsafe);
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
    expanded_range: Option<&SourceRangeFact>,
    callee_range: Option<&SourceRangeFact>,
    target: &CallTargetFact,
) -> String {
    let origin = graph
        .node_instance(edge.origin)
        .map(|instance| StableInstanceHash::from_instance(tcx, instance).to_string())
        .unwrap_or_default();
    format!(
        "{origin}|{:?}|{expanded_range:?}|{callee_range:?}|{target:?}|{:?}",
        edge.kind,
        edge.span.ctxt()
    )
}

fn indirect_call_kind<'view, 'tcx>(
    graph: &'view ReachabilityGraph<'tcx>,
    reached: ReachedEdge<'view, 'tcx>,
    call_kind: CallKindFact,
) -> Option<IndirectCallKindFact> {
    if call_kind != CallKindFact::IndirectCall {
        return None;
    }
    match graph.edge_callable(reached.id()) {
        Some(CallableEdgeInfo::FnPointer { .. }) => Some(IndirectCallKindFact::FunctionPointer),
        Some(CallableEdgeInfo::DynDispatch { .. }) => Some(IndirectCallKindFact::DynamicDispatch),
        None => None,
    }
}

fn call_edge_kind(reached: ReachedEdge<'_, '_>) -> Option<CallKindFact> {
    if matches!(
        reached.target().kind(),
        ReachabilityNodeKind::Instance(Instance {
            def: InstanceKind::Virtual(..),
            ..
        })
    ) {
        return Some(CallKindFact::IndirectCall);
    }
    match reached.kind() {
        ReachabilityEdgeKind::DirectCall => Some(CallKindFact::DirectCall),
        ReachabilityEdgeKind::TailCall => Some(CallKindFact::TailCall),
        ReachabilityEdgeKind::ConstBody => Some(CallKindFact::ConstBody),
        ReachabilityEdgeKind::CoroutineBody => Some(CallKindFact::CoroutineBody),
        ReachabilityEdgeKind::Assert => Some(CallKindFact::Assert),
        ReachabilityEdgeKind::IndirectCall => Some(CallKindFact::IndirectCall),
        ReachabilityEdgeKind::FnPointerReify
        | ReachabilityEdgeKind::ClosureFnPointerReify
        | ReachabilityEdgeKind::FnPointerCallTarget
        | ReachabilityEdgeKind::DynObjectCast
        | ReachabilityEdgeKind::VTableEntry
        | ReachabilityEdgeKind::DynDispatchVTableEntry
        | ReachabilityEdgeKind::MacroExpansion => None,
    }
}

fn call_target<'tcx>(
    tcx: TyCtxt<'tcx>,
    graph: &ReachabilityGraph<'tcx>,
    edge: &ReachabilityEdge,
    sources: &mut SourceTable,
) -> Result<CallTargetFact, ExtractError> {
    match &graph.node(edge.target).kind {
        ReachabilityNodeKind::Instance(instance) => {
            if matches!(instance.def, InstanceKind::Virtual(..)) {
                Ok(CallTargetFact::OpaqueBoundary {
                    description: format!("virtual dispatch {instance:?}"),
                    target: Some(OpaqueTargetFact::Trait(function_target_for_def(
                        tcx,
                        instance.def_id(),
                        sources,
                    )?)),
                })
            } else {
                Ok(CallTargetFact::Function(function_target_for_instance(
                    tcx, *instance, sources,
                )?))
            }
        }
        ReachabilityNodeKind::CompilerAssert {
            message, locals, ..
        } => Ok(CallTargetFact::OpaqueBoundary {
            description: format!(
                "compiler assertion {}",
                compiler_assert_description(message, locals)
            ),
            target: None,
        }),
        ReachabilityNodeKind::MacroExpansion { def_id } => Ok(CallTargetFact::OpaqueBoundary {
            description: format!("macro expansion {}", canonical_namespace(tcx, *def_id)),
            target: Some(OpaqueTargetFact::Function(function_target_for_def(
                tcx, *def_id, sources,
            )?)),
        }),
        ReachabilityNodeKind::IndirectCall { callee_ty } => {
            let target = indirect_target_def_id(tcx, *callee_ty).map(|(def_id, is_trait)| {
                function_target_for_def(tcx, def_id, sources).map(|target| {
                    if is_trait {
                        OpaqueTargetFact::Trait(target)
                    } else {
                        OpaqueTargetFact::Function(target)
                    }
                })
            });
            Ok(CallTargetFact::OpaqueBoundary {
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
                        function_target_for_def(tcx, def_id, sources).map(OpaqueTargetFact::Trait)
                    })
                    .transpose()?,
                _ => None,
            };
            Ok(CallTargetFact::OpaqueBoundary {
                description: format!("dynamic object cast {source_ty:?} as {target_ty:?}"),
                target,
            })
        }
    }
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
) -> Result<FunctionTargetFact, ExtractError> {
    let def_id = instance.def_id();
    Ok(FunctionTargetFact {
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
) -> Result<FunctionTargetFact, ExtractError> {
    Ok(FunctionTargetFact {
        function: FunctionId::generic(StableDefPathHash::from_def_id(tcx, def_id)),
        display_path: canonical_namespace(tcx, def_id),
        attributes: function_attributes(tcx, def_id),
        contracts: function_contracts(tcx, def_id, sources)?,
    })
}

fn contract_declaration_for_def(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    sources: &mut SourceTable,
) -> Result<Option<FunctionTargetFact>, ExtractError> {
    tcx.trait_item_of(def_id)
        .filter(|declaration| *declaration != def_id)
        .map(|declaration| function_target_for_def(tcx, declaration, sources))
        .transpose()
}

fn function_attributes(tcx: TyCtxt<'_>, def_id: DefId) -> FunctionAttributesFact {
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
    FunctionAttributesFact {
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
) -> Result<FunctionContractsFact, ExtractError> {
    if !matches!(tcx.def_kind(def_id), DefKind::Fn | DefKind::AssocFn) {
        return Ok(FunctionContractsFact::default());
    }
    Ok(FunctionContractsFact {
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
) -> Result<Option<ContractFact>, ExtractError> {
    if !summary.has_docs {
        return Ok(None);
    }
    Ok(Some(ContractFact {
        source_range: sources.range(tcx, tcx.def_span(def_id))?,
        requirements: contract_requirements(tcx, summary.requirements, sources)?,
    }))
}

fn contract_requirements(
    tcx: TyCtxt<'_>,
    requirements: Vec<crate::contracts::ContractRequirement>,
    sources: &mut SourceTable,
) -> Result<Vec<ContractRequirementFact>, ExtractError> {
    requirements
        .into_iter()
        .map(|requirement| {
            Ok(ContractRequirementFact {
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
    provenance: FunctionFactProvenance,
) -> Result<(), ExtractError> {
    if let Some(body) = bodies.get(&function) {
        return if body.provenance == provenance {
            Ok(())
        } else {
            Err(ExtractError::new(format!(
                "function `{}` was extracted with conflicting provenance",
                canonical_namespace(tcx, def_id)
            )))
        };
    }
    let contracts = function_contracts(tcx, def_id, sources)?;
    let contract_declaration = contract_declaration_for_def(tcx, def_id, sources)?;
    let mut attributes = function_attributes(tcx, def_id);
    // `ensure_body` is used only for required HIR bodies and expanded rustc
    // instances. That proves this facts entry has a body even when its defining
    // `DefId` is an abstract callable trait method backed by a compiler-
    // generated shim (for example `FnOnce::call_once`).
    attributes.has_rust_body = true;
    let mut body = PendingBody {
        function,
        provenance,
        display_path: canonical_namespace(tcx, def_id),
        attributes,
        contract_declaration,
        source_range: sources.range(tcx, tcx.def_span(def_id))?,
        calls: Vec::new(),
        effects: Vec::new(),
        markers: Vec::new(),
        unverified_marker_probes: Vec::new(),
    };
    if let Some(contract) = contracts.panic {
        body.push_contract_marker(AnnotationFactKind::PanicContract, contract);
    }
    if let Some(contract) = contracts.safety {
        body.push_contract_marker(AnnotationFactKind::SafetyContract, contract);
    }
    bodies.insert(function, body);
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct RawSafetyGroupSite {
    span: Span,
    group: usize,
}

#[derive(Debug, Clone, Copy)]
struct RawCallSite {
    callee: Option<DefId>,
    declaration_callee: Option<DefId>,
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
    declaration_callee: Option<DefId>,
    safety_scope_span: Option<Span>,
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
                    declaration_callee: fact.declaration_callee,
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
                site.declaration_callee,
                self.safety_scope_span(owner, site.safety_group),
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
                site.declaration_callee,
                self.safety_scope_span(owner, site.safety_group),
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
            return resolved_call_groups(
                site.safety_group,
                site.call_site,
                false,
                None,
                self.safety_scope_span(owner, site.safety_group),
            );
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
        resolved_call_groups(
            safety_group,
            call_site,
            false,
            None,
            self.safety_scope_span(owner, safety_group),
        )
    }

    fn safety_scope_span(&self, owner: DefId, group: usize) -> Option<Span> {
        let mut matches = self
            .scopes_by_owner
            .get(&owner)
            .into_iter()
            .flatten()
            .filter(|site| site.group == group)
            .map(|site| site.span);
        let first = matches.next()?;
        matches
            .all(|span| span.source_equal(first))
            .then_some(first)
    }
}

#[derive(Debug, Clone, Copy)]
struct RawCallConsensus {
    safety_group: usize,
    call_site: usize,
    inside_builtin_unsafe: bool,
    declaration_callee: Option<DefId>,
}

fn unique_raw_call_groups<'a>(
    mut calls: impl Iterator<Item = &'a RawCallSite>,
) -> Option<RawCallConsensus> {
    let first = *calls.next()?;
    let mut declaration_callee = first.declaration_callee;
    for candidate in calls {
        if candidate.safety_group != first.safety_group
            || candidate.call_site != first.call_site
            || candidate.inside_builtin_unsafe != first.inside_builtin_unsafe
        {
            return None;
        }
        if candidate.declaration_callee != declaration_callee {
            declaration_callee = None;
        }
    }
    Some(RawCallConsensus {
        safety_group: first.safety_group,
        call_site: first.call_site,
        inside_builtin_unsafe: first.inside_builtin_unsafe,
        declaration_callee,
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
    declaration_callee: Option<DefId>,
    safety_scope_span: Option<Span>,
) -> Result<ResolvedCallGroups, ExtractError> {
    Ok(ResolvedCallGroups {
        safety_effect_group: raw_safety_group_id(safety_group)?,
        call_site: u32::try_from(call_site)
            .map(CallSiteId::new)
            .map_err(|_| ExtractError::new("too many raw call sites in one artifact"))?,
        inside_builtin_unsafe,
        declaration_callee,
        safety_scope_span,
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
    sources: &mut SourceTable,
    bodies: &mut BTreeMap<FunctionId, PendingBody>,
) -> Result<(), ExtractError> {
    for (ordinal, fact) in facts.into_iter().enumerate() {
        let Some(local) = fact.owner.as_local() else {
            return Err(ExtractError::new(
                "raw unsafe operation is not owned by the local artifact",
            ));
        };
        let definition = StableDefPathHash::from_def_id(tcx, fact.owner);
        let mut body_ids = bodies
            .keys()
            .copied()
            .filter(|function| function.def_path_hash == definition)
            .collect::<Vec<_>>();
        if body_ids.is_empty() {
            let function = FunctionId::generic(definition);
            ensure_body(
                tcx,
                sources,
                bodies,
                function,
                local.to_def_id(),
                FunctionFactProvenance::DefiningArtifact,
            )?;
            body_ids.push(function);
        }

        let expanded_range = sources.range(tcx, fact.span)?;
        let macro_expansions = span_macro_expansions(tcx, fact.span, sources)?;
        let source_range = sources
            .range(tcx, fact.span.source_callsite())?
            .or_else(|| expanded_range.clone());
        for body_id in body_ids {
            let key = format!(
                "unsafe:{ordinal}:{:?}:{source_range:?}:{}",
                fact.op, fact.effect_group.id
            );
            let body = bodies
                .get_mut(&body_id)
                .expect("unsafe-operation body was inserted");
            body.effects.push(PendingEffect {
                key: key.clone(),
                effect: EffectFact {
                    id: EffectId::new(0),
                    safety_effect_group: Some(raw_safety_group_id(fact.effect_group.id)?),
                    source_range: source_range.clone(),
                    expanded_range: expanded_range.clone(),
                    macro_expansions: macro_expansions.clone(),
                    kind: EffectFactKind::UnsafeOperation { kind: fact.op },
                },
            });

            for (probing, applicable_probing) in probing_modes() {
                let probe =
                    probe_marker_candidates(fact.marker_anchor_spans.iter().copied(), |span| {
                        safety_span_marker_block(tcx, local, span, probing)
                    });
                record_effect_marker_probe(
                    tcx,
                    sources,
                    body,
                    AnnotationFactKind::SafetyJustification,
                    PendingMarkerTarget::Effect(key.clone()),
                    probe,
                    applicable_probing,
                    Vec::new(),
                )?;
            }
        }
    }
    Ok(())
}

fn probing_modes() -> [(MarkerProbing, AnnotationProbingFact); 2] {
    [
        (
            MarkerProbing::SourceCallsite,
            AnnotationProbingFact::SourceCallsite,
        ),
        (
            MarkerProbing::MacroDefinitionFirst,
            AnnotationProbingFact::MacroDefinitionFirst,
        ),
    ]
}

fn pending_unverified_marker_probe<T>(
    kind: AnnotationFactKind,
    target: PendingMarkerTarget,
    probing: AnnotationProbingFact,
    probe: &MarkerProbe<T>,
) -> Option<PendingUnverifiedMarkerProbe> {
    let MarkerProbe::Unverified(reason) = probe else {
        return None;
    };
    Some(PendingUnverifiedMarkerProbe {
        kind,
        target,
        probing,
        reason: *reason,
    })
}

fn push_unverified_marker_probe(body: &mut PendingBody, probe: PendingUnverifiedMarkerProbe) {
    let marker_is_present = body.markers.iter().any(|marker| {
        marker.kind == probe.kind
            && marker.target == probe.target
            && marker.applicable_probing.contains(&probe.probing)
    });
    if marker_is_present {
        return;
    }
    if let Some(existing) = body.unverified_marker_probes.iter_mut().find(|existing| {
        existing.kind == probe.kind
            && existing.target == probe.target
            && existing.probing == probe.probing
    }) {
        existing.reason = existing.reason.merge(probe.reason);
    } else {
        body.unverified_marker_probes.push(probe);
    }
}

#[allow(clippy::too_many_arguments)]
fn record_effect_marker_probe(
    tcx: TyCtxt<'_>,
    sources: &mut SourceTable,
    body: &mut PendingBody,
    kind: AnnotationFactKind,
    target: PendingMarkerTarget,
    probe: MarkerProbe<EffectMarkerBlock>,
    applicable_probing: AnnotationProbingFact,
    requirements: Vec<ContractRequirementFact>,
) -> Result<(), ExtractError> {
    if let Some(unverified) =
        pending_unverified_marker_probe(kind, target.clone(), applicable_probing, &probe)
    {
        push_unverified_marker_probe(body, unverified);
    }
    if let MarkerProbe::Present(marker) = probe {
        push_effect_marker(
            tcx,
            sources,
            body,
            kind,
            target,
            marker,
            applicable_probing,
            requirements,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_effect_marker(
    tcx: TyCtxt<'_>,
    sources: &mut SourceTable,
    body: &mut PendingBody,
    kind: AnnotationFactKind,
    target: PendingMarkerTarget,
    marker: EffectMarkerBlock,
    applicable_probing: AnnotationProbingFact,
    requirements: Vec<ContractRequirementFact>,
) -> Result<(), ExtractError> {
    body.unverified_marker_probes.retain(|probe| {
        probe.kind != kind || probe.target != target || probe.probing != applicable_probing
    });
    let source_range = sources.range(tcx, marker.span)?;
    let satisfactions = marker
        .satisfactions
        .into_iter()
        .map(|satisfaction| AnnotationSatisfactionFact {
            requirement: satisfaction.requirement,
            reason: satisfaction.reason,
        })
        .collect::<Vec<_>>();
    let identity = format!("{kind:?}|{:?}", marker.key);
    let key = format!("{identity}|{target:?}|{source_range:?}|{satisfactions:?}|{requirements:?}");
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
            satisfactions,
            requirements,
        });
    }
    Ok(())
}

fn panic_requirements(
    declaration_target: Option<&FunctionTargetFact>,
    runtime_target: &CallTargetFact,
) -> Vec<ContractRequirementFact> {
    runtime_target
        .function_target()
        .and_then(|target| target.contracts.panic.as_ref())
        .or_else(|| declaration_target.and_then(|target| target.contracts.panic.as_ref()))
        .map_or_else(Vec::new, |contract| contract.requirements.clone())
}

fn safety_requirements(
    declaration_target: Option<&FunctionTargetFact>,
    runtime_target: &CallTargetFact,
) -> Vec<ContractRequirementFact> {
    runtime_target
        .function_target()
        .and_then(|target| target.contracts.safety.as_ref())
        .or_else(|| declaration_target.and_then(|target| target.contracts.safety.as_ref()))
        .map_or_else(Vec::new, |contract| contract.requirements.clone())
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

struct PendingBody {
    function: FunctionId,
    provenance: FunctionFactProvenance,
    display_path: String,
    attributes: FunctionAttributesFact,
    contract_declaration: Option<FunctionTargetFact>,
    source_range: Option<SourceRangeFact>,
    calls: Vec<PendingCall>,
    effects: Vec<PendingEffect>,
    markers: Vec<PendingMarker>,
    unverified_marker_probes: Vec<PendingUnverifiedMarkerProbe>,
}

impl PendingBody {
    fn push_contract_marker(&mut self, kind: AnnotationFactKind, contract: ContractFact) {
        self.markers.push(PendingMarker {
            key: format!("{kind:?}|function|{:?}", contract.source_range),
            identity: format!("{kind:?}|function|{:?}", contract.source_range),
            kind,
            source_range: contract.source_range,
            target: PendingMarkerTarget::Function,
            applicable_probing: vec![
                AnnotationProbingFact::SourceCallsite,
                AnnotationProbingFact::MacroDefinitionFirst,
            ],
            satisfactions: Vec::new(),
            requirements: contract.requirements,
        });
    }

    fn finish(mut self) -> Result<FunctionFact, ExtractError> {
        self.calls.sort_by(|left, right| left.key.cmp(&right.key));
        self.effects.sort_by(|left, right| left.key.cmp(&right.key));
        self.markers.sort_by(|left, right| left.key.cmp(&right.key));

        let mut call_ids = BTreeMap::new();
        let calls = self
            .calls
            .into_iter()
            .enumerate()
            .map(|(index, mut pending)| {
                let id = local_id(index, "call")?;
                pending.call.id = CallId::new(id);
                call_ids.insert(pending.key, pending.call.id);
                Ok(pending.call)
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
                    PendingMarkerTarget::Function => AnnotationTargetFact::Function(self.function),
                    PendingMarkerTarget::Call(key) => {
                        AnnotationTargetFact::Call(*call_ids.get(&key).ok_or_else(|| {
                            ExtractError::new("marker refers to an unknown extracted call")
                        })?)
                    }
                    PendingMarkerTarget::Effect(key) => {
                        AnnotationTargetFact::Effect(*effect_ids.get(&key).ok_or_else(|| {
                            ExtractError::new("marker refers to an unknown extracted effect")
                        })?)
                    }
                };
                Ok(AnnotationFact {
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
        let unverified_marker_probes =
            finish_unverified_marker_probes(self.unverified_marker_probes, &call_ids, &effect_ids)?;

        Ok(FunctionFact {
            function: self.function,
            provenance: self.provenance,
            display_path: self.display_path,
            attributes: self.attributes,
            contract_declaration: self.contract_declaration,
            source_range: self.source_range,
            calls,
            effects,
            markers,
            unverified_marker_probes,
        })
    }
}

fn finish_unverified_marker_probes(
    mut probes: Vec<PendingUnverifiedMarkerProbe>,
    call_ids: &BTreeMap<String, CallId>,
    effect_ids: &BTreeMap<String, EffectId>,
) -> Result<Vec<UnverifiedMarkerProbeFact>, ExtractError> {
    probes.sort_by(|left, right| {
        (&left.kind, &left.target, &left.probing).cmp(&(&right.kind, &right.target, &right.probing))
    });
    probes
        .into_iter()
        .map(|pending| {
            let target = match pending.target {
                PendingMarkerTarget::Function => {
                    return Err(ExtractError::new(
                        "unverified marker probe has a function target",
                    ));
                }
                PendingMarkerTarget::Call(key) => {
                    AnnotationTargetFact::Call(*call_ids.get(&key).ok_or_else(|| {
                        ExtractError::new(
                            "unverified marker probe refers to an unknown extracted call",
                        )
                    })?)
                }
                PendingMarkerTarget::Effect(key) => {
                    AnnotationTargetFact::Effect(*effect_ids.get(&key).ok_or_else(|| {
                        ExtractError::new(
                            "unverified marker probe refers to an unknown extracted effect",
                        )
                    })?)
                }
            };
            Ok(UnverifiedMarkerProbeFact {
                kind: pending.kind,
                target,
                probing: pending.probing,
                reason: pending.reason,
            })
        })
        .collect()
}

fn local_id(index: usize, label: &str) -> Result<u32, ExtractError> {
    u32::try_from(index)
        .map_err(|_| ExtractError::new(format!("too many {label} facts in one function body")))
}

struct PendingCall {
    key: String,
    call: CallFact,
}

struct PendingEffect {
    key: String,
    effect: EffectFact,
}

struct PendingMarker {
    key: String,
    identity: String,
    kind: AnnotationFactKind,
    source_range: Option<SourceRangeFact>,
    target: PendingMarkerTarget,
    applicable_probing: Vec<AnnotationProbingFact>,
    satisfactions: Vec<AnnotationSatisfactionFact>,
    requirements: Vec<ContractRequirementFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PendingMarkerTarget {
    Function,
    Call(String),
    Effect(String),
}

struct PendingUnverifiedMarkerProbe {
    kind: AnnotationFactKind,
    target: PendingMarkerTarget,
    probing: AnnotationProbingFact,
    reason: UnverifiedMarkerProbeReason,
}

#[derive(Default)]
struct SourceTable {
    source_ids: BTreeMap<StableSourceFileId, SourceFileId>,
    files: BTreeMap<SourceFileId, SourceFileFact>,
}

impl SourceTable {
    fn range(
        &mut self,
        tcx: TyCtxt<'_>,
        span: Span,
    ) -> Result<Option<SourceRangeFact>, ExtractError> {
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
        let id = if let Some(id) = self.source_ids.get(&file.stable_id) {
            id.clone()
        } else {
            let id = stable_source_file_id(&file);
            self.files
                .entry(id.clone())
                .or_insert_with(|| SourceFileFact {
                    id: id.clone(),
                    filename: source_filename(&file),
                    content_hash: file.src_hash.to_string(),
                    byte_len: u64::from(file.normalized_source_len.to_u32()),
                });
            self.source_ids.insert(file.stable_id, id.clone());
            id
        };
        Ok(Some(SourceRangeFact {
            file: id,
            byte_start: u64::from(span.lo().0 - file.start_pos.0),
            byte_end: u64::from(span.hi().0 - file.start_pos.0),
        }))
    }

    fn into_files(self) -> Vec<SourceFileFact> {
        self.files.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use reachability::{
        DynDispatchVTableEdges, FnPointerEdges, ReachabilityEdgeKind, ReachabilityHalt,
    };
    use rustc_hir::def_id::{CRATE_DEF_ID, DefId, DefIndex};
    use rustc_span::{BytePos, Span};

    use super::{
        PendingMarkerTarget, RawSafetyGroupResolver, extraction_options, probing_modes,
        reachability_edge_description, reachability_halt_description,
    };
    use crate::artifact::UnverifiedMarkerProbeReason;
    use crate::artifact::{
        AnnotationFactKind, AnnotationProbingFact, CallSiteId, SafetyEffectGroupId, SafetyOpKind,
    };
    use crate::compiler::safety::{
        RawSafetyCallFact, RawSafetyEffectGroup, RawSafetyFacts, RawSafetyGroupFact,
        RawSafetyOpFact,
    };
    use crate::source_markers::MarkerProbe;

    fn span(start: u32, end: u32) -> Span {
        Span::with_root_ctxt(BytePos(start), BytePos(end))
    }

    fn safety_group_id(raw: usize) -> SafetyEffectGroupId {
        SafetyEffectGroupId::new(u32::try_from(raw).expect("test safety group fits in u32"))
    }

    fn call_site_id(raw: usize) -> CallSiteId {
        CallSiteId::new(u32::try_from(raw).expect("test call site fits in u32"))
    }

    #[test]
    fn extraction_never_attributes_callable_candidates_to_call_sites() {
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
                AnnotationProbingFact::SourceCallsite,
                AnnotationProbingFact::MacroDefinitionFirst
            ]
        );
    }

    #[test]
    fn extraction_only_materializes_unverified_marker_probe_gaps() {
        let target = PendingMarkerTarget::Effect(String::from("effect-0"));

        assert!(
            super::pending_unverified_marker_probe(
                AnnotationFactKind::PanicJustification,
                target.clone(),
                AnnotationProbingFact::SourceCallsite,
                &MarkerProbe::Present(()),
            )
            .is_none()
        );
        assert!(
            super::pending_unverified_marker_probe::<()>(
                AnnotationFactKind::PanicJustification,
                target.clone(),
                AnnotationProbingFact::SourceCallsite,
                &MarkerProbe::VerifiedAbsent,
            )
            .is_none()
        );
        let unverified = super::pending_unverified_marker_probe::<()>(
            AnnotationFactKind::PanicJustification,
            target,
            AnnotationProbingFact::SourceCallsite,
            &MarkerProbe::Unverified(UnverifiedMarkerProbeReason::SourceUnavailable),
        )
        .expect("unverified probes need one sparse artifact fact");

        assert_eq!(unverified.kind, AnnotationFactKind::PanicJustification);
        assert_eq!(unverified.probing, AnnotationProbingFact::SourceCallsite);
        assert_eq!(
            unverified.reason,
            UnverifiedMarkerProbeReason::SourceUnavailable
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
        assert_eq!(outer_call.declaration_callee, None);
        assert_eq!(outer_call.safety_scope_span, Some(outer.span));

        let inner_call = resolver
            .group_for_call(owner, span(30, 31), None)
            .expect("inner group");
        assert_eq!(inner_call.safety_effect_group, safety_group_id(inner.id));
        assert_ne!(inner_call.call_site, outer_call.call_site);
        assert!(!inner_call.inside_builtin_unsafe);
        assert_eq!(inner_call.declaration_callee, None);
        assert_eq!(inner_call.safety_scope_span, Some(inner.span));

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
        assert_eq!(first.declaration_callee, None);
        assert_eq!(first.safety_scope_span, None);
        assert_eq!(second, first);
    }

    #[test]
    fn call_grouping_disambiguates_desugared_calls_by_callee() {
        let owner = CRATE_DEF_ID.to_def_id();
        let first_callee = DefId::local(DefIndex::from_u32(1));
        let second_callee = DefId::local(DefIndex::from_u32(2));
        let unmatched_callee = DefId::local(DefIndex::from_u32(3));
        let second_declaration_callee = DefId::local(DefIndex::from_u32(4));
        let shared_span = span(10, 40);
        let facts = RawSafetyFacts {
            groups: Vec::new(),
            calls: vec![
                RawSafetyCallFact {
                    owner,
                    callee: Some(first_callee),
                    declaration_callee: Some(first_callee),
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
                    declaration_callee: Some(second_declaration_callee),
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
        assert_eq!(matched.declaration_callee, Some(second_declaration_callee));

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
        assert_eq!(unmatched.declaration_callee, None);
    }

    #[test]
    fn call_grouping_keeps_only_a_consensus_declaration_callee() {
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
                    declaration_callee: Some(first_callee),
                    inside_builtin_unsafe: false,
                    call_site: 0,
                    span: shared_span,
                    effect_group: shared_group,
                },
                RawSafetyCallFact {
                    owner,
                    callee: Some(second_callee),
                    declaration_callee: Some(second_callee),
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
        assert_eq!(call_groups.declaration_callee, None);
    }

    #[test]
    fn a_mismatched_callee_gets_an_independent_call_identity() {
        let owner = CRATE_DEF_ID.to_def_id();
        let declaration_callee = DefId::local(DefIndex::from_u32(1));
        let requested_callee = DefId::local(DefIndex::from_u32(2));
        let shared_span = span(10, 40);
        let facts = RawSafetyFacts {
            groups: Vec::new(),
            calls: vec![RawSafetyCallFact {
                owner,
                callee: Some(declaration_callee),
                declaration_callee: Some(declaration_callee),
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
        assert_eq!(call_groups.declaration_callee, None);
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
                    declaration_callee: Some(first_callee),
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
                    declaration_callee: Some(second_callee),
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
        assert_eq!(first.declaration_callee, None);
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
        assert_eq!(edge_groups.declaration_callee, None);
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
        assert_eq!(edge_groups.declaration_callee, None);
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
