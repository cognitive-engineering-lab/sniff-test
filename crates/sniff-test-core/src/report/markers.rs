//! Marker claim grouping and ambiguity projection.

use std::collections::BTreeMap;

use effect_tracing::{EffectTrace, FunctionId, TerminationSite, TraceNodeId};

use crate::annotations::{AnnotationId, AnnotationIndex};
use crate::artifact::{ArtifactFacts, EffectId, EffectKey, FunctionId as StableFunctionId};
use crate::compiler::invocations::InvocationGraph;
use crate::effects::EffectMetadata;
use crate::effects::InvocationSourceBranch;
use crate::effects::concrete::ConcreteSource;
use crate::effects::obligation::{
    ObligationTracker, TrackedEffect, TrackedOrigin, TrackedState, TrackedTermination,
};
use crate::effects::trust::TrustPath;
use crate::report_model::{InterpretedFinding, InterpretedFindingKind, InterpretedTrace};

use super::{
    ConcreteTrace, append_call_trace, append_effect_provenance, audited_path_from_root,
    display_path, effect_fact, path_from_root_until, trace_path,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SourceEffectGroup {
    Invocation(effect_tracing::InvocationId, crate::artifact::CallId),
    Operation(StableFunctionId, crate::artifact::EffectGroupId),
    StandaloneOperation(StableFunctionId, EffectId),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct MarkerEffectGroup {
    effect: EffectKey,
    source: SourceEffectGroup,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum MarkerWitness {
    Concrete {
        effect: EffectKey,
        origin: ConcreteSource,
        site: MarkerTraceSite,
    },
    Obligation {
        effect: EffectKey,
        invocation: effect_tracing::InvocationId,
        node: TraceNodeId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum MarkerTraceSite {
    Source,
    Invocation {
        invocation: effect_tracing::InvocationId,
        node: TraceNodeId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MarkerUse {
    annotation: AnnotationId,
    group: MarkerEffectGroup,
    witness: MarkerWitness,
}

pub(super) type MarkerClaims =
    BTreeMap<AnnotationId, BTreeMap<MarkerEffectGroup, Vec<MarkerWitness>>>;

struct MarkerProjection {
    function: StableFunctionId,
    function_path: String,
    trace: InterpretedTrace,
}

#[allow(clippy::too_many_arguments, reason = "report inputs remain explicit")]
pub(super) fn marker_ambiguities(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    annotations: &AnnotationIndex,
    concrete_effects: &BTreeMap<EffectKey, crate::effects::concrete::ConcreteEffect<'_>>,
    traces: &BTreeMap<EffectKey, ConcreteTrace>,
    tracked_effects: &BTreeMap<
        EffectKey,
        TrackedEffect<'_, '_, crate::effects::concrete::ConcreteEffect<'_>>,
    >,
    claims: &MarkerClaims,
    metadata: &[EffectMetadata],
    root_function: FunctionId,
) -> Vec<InterpretedFinding> {
    claims
        .iter()
        .filter_map(|(annotation, groups)| {
            if groups.len() < 2 {
                return None;
            }
            let projections = groups
                .values()
                .filter_map(|witnesses| {
                    witnesses
                        .iter()
                        .cloned()
                        .filter_map(|witness| {
                            marker_projection(
                                artifact,
                                graph,
                                concrete_effects,
                                tracked_effects,
                                traces,
                                root_function,
                                witness,
                            )
                        })
                        .min_by(marker_projection_order)
                })
                .collect::<Vec<_>>();
            if projections.len() < 2 {
                return None;
            }
            let effect_count = projections.len();
            let comment = annotations.site_comment(*annotation)?;
            let representative = projections.into_iter().min_by(marker_projection_order)?;
            Some(InterpretedFinding {
                effect: metadata
                    .iter()
                    .find(|metadata| metadata.key == *comment.effect())?
                    .clone(),
                kind: InterpretedFindingKind::AmbiguousMarker { effect_count },
                function: representative.function,
                function_path: representative.function_path,
                callee: None,
                source_range: comment.source_range().cloned(),
                contract_source_range: None,
                marker_evidence: None,
                trace: representative.trace,
                missing_requirements: Vec::new(),
                requirements: Vec::new(),
            })
        })
        .collect()
}

pub(super) fn collect_marker_claims(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    concrete_effects: &BTreeMap<EffectKey, crate::effects::concrete::ConcreteEffect<'_>>,
    traces: &BTreeMap<EffectKey, ConcreteTrace>,
    tracked_effects: &BTreeMap<
        EffectKey,
        TrackedEffect<'_, '_, crate::effects::concrete::ConcreteEffect<'_>>,
    >,
) -> MarkerClaims {
    let mut uses = Vec::new();
    for (effect, trace) in traces {
        let Some(concrete) = concrete_effects.get(effect) else {
            continue;
        };
        for handled in trace.handled() {
            let (
                TrackedOrigin::Concrete(origin),
                TrackedTermination::Concrete(
                    crate::effects::concrete::ConcreteTermination::Justification(annotation),
                ),
            ) = (handled.origin(), handled.termination())
            else {
                continue;
            };
            let origin = *origin;
            let Some(site) = marker_trace_site(handled.site(), handled.node()) else {
                continue;
            };
            uses.extend(
                effect_groups(artifact, graph, concrete, effect, origin)
                    .into_iter()
                    .map(|group| MarkerUse {
                        annotation: *annotation,
                        group: MarkerEffectGroup {
                            effect: effect.clone(),
                            source: group,
                        },
                        witness: MarkerWitness::Concrete {
                            effect: effect.clone(),
                            origin,
                            site,
                        },
                    }),
            );
        }
    }
    for (effect, tracked) in tracked_effects {
        let Some(trace) = traces.get(effect) else {
            continue;
        };
        for usage in tracked.obligation_marker_uses(trace) {
            let source_invocation = usage.source_invocation();
            let groups = obligation_effect_groups(
                graph,
                concrete_effects.get(effect),
                effect,
                source_invocation,
                usage.source_calls(),
            );
            let witness = MarkerWitness::Obligation {
                effect: effect.clone(),
                invocation: usage.invocation(),
                node: usage.node(),
            };
            uses.extend(groups.into_iter().map(|source| MarkerUse {
                annotation: usage.annotation(),
                group: MarkerEffectGroup {
                    effect: effect.clone(),
                    source,
                },
                witness: witness.clone(),
            }));
        }
    }

    let mut claims = MarkerClaims::new();
    for usage in uses {
        claims
            .entry(usage.annotation)
            .or_default()
            .entry(usage.group)
            .or_default()
            .push(usage.witness);
    }
    for groups in claims.values_mut() {
        for witnesses in groups.values_mut() {
            witnesses.sort();
            witnesses.dedup();
        }
    }
    claims
}

fn marker_projection_order(
    left: &MarkerProjection,
    right: &MarkerProjection,
) -> std::cmp::Ordering {
    left.trace
        .steps
        .len()
        .cmp(&right.trace.steps.len())
        .then_with(|| left.function_path.cmp(&right.function_path))
}

fn marker_projection(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    concrete_effects: &BTreeMap<EffectKey, crate::effects::concrete::ConcreteEffect<'_>>,
    tracked_effects: &BTreeMap<
        EffectKey,
        TrackedEffect<'_, '_, crate::effects::concrete::ConcreteEffect<'_>>,
    >,
    traces: &BTreeMap<EffectKey, ConcreteTrace>,
    root_function: FunctionId,
    witness: MarkerWitness,
) -> Option<MarkerProjection> {
    let (function, mut trace) = match &witness {
        MarkerWitness::Concrete {
            effect,
            origin,
            site,
        } => match site {
            MarkerTraceSite::Source => {
                let concrete = concrete_effects.get(effect)?;
                let endpoint = concrete_source_owner(graph, *origin)?;
                let trace = audited_path_from_root(
                    artifact,
                    graph,
                    root_function,
                    endpoint,
                    |function, path: &TrustPath| concrete.is_opaque_on_path(function, path),
                    |invocation| concrete.is_ignored_invocation(invocation),
                )?;
                (graph.stable_function(endpoint), trace)
            }
            MarkerTraceSite::Invocation { invocation, node } => {
                let concrete = concrete_effects.get(effect)?;
                let effect_trace = traces.get(effect)?;
                marker_invocation_projection(
                    artifact,
                    graph,
                    effect_trace,
                    root_function,
                    *invocation,
                    *node,
                    MarkerTraversalPolicy {
                        trust_path: match effect_trace.nodes().nth(node.index())?.state() {
                            TrackedState::Concrete(state) => state.trust_path().clone(),
                            TrackedState::Obligation(_) => return None,
                        },
                        is_opaque: |function, path: &TrustPath| {
                            concrete.is_opaque_on_path(function, path)
                        },
                        is_ignored_invocation: |candidate| {
                            concrete.is_ignored_invocation(candidate)
                        },
                    },
                )?
            }
        },
        MarkerWitness::Obligation {
            effect,
            invocation,
            node,
        } => {
            let tracked = tracked_effects.get(effect)?;
            obligation_marker_projection(
                artifact,
                graph,
                tracked.obligations(),
                traces.get(effect)?,
                root_function,
                *invocation,
                *node,
                effect,
            )?
        }
    };
    if let MarkerWitness::Concrete { effect, origin, .. } = witness
        && let Some(concrete) = concrete_effects.get(&effect)
    {
        append_concrete_origin(artifact, graph, concrete, origin, &mut trace);
    }
    Some(MarkerProjection {
        function,
        function_path: display_path(artifact, function),
        trace,
    })
}

fn marker_trace_site<O>(
    site: &TerminationSite<O>,
    node: Option<TraceNodeId>,
) -> Option<MarkerTraceSite> {
    match site {
        TerminationSite::Source(_) => Some(MarkerTraceSite::Source),
        TerminationSite::Invocation(invocation) => Some(MarkerTraceSite::Invocation {
            invocation: *invocation,
            node: node?,
        }),
        TerminationSite::Function(_) => None,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "marker projection inputs remain explicit"
)]
fn obligation_marker_projection<O: Clone, S, T>(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    obligations: &ObligationTracker<'_>,
    trace: &EffectTrace<TrackedOrigin<O>, TrackedState<S>, TrackedTermination<T>>,
    root_function: FunctionId,
    invocation: effect_tracing::InvocationId,
    node: TraceNodeId,
    effect: &EffectKey,
) -> Option<(StableFunctionId, InterpretedTrace)> {
    let trust_path = trace
        .nodes()
        .nth(node.index())?
        .state()
        .obligation()?
        .trust_path()
        .clone();
    marker_invocation_projection(
        artifact,
        graph,
        trace,
        root_function,
        invocation,
        node,
        MarkerTraversalPolicy {
            trust_path,
            is_opaque: |function, path: &TrustPath| {
                obligations.trusts_function(effect, function)
                    && path.allows_boundary(graph, function)
            },
            is_ignored_invocation: |candidate| obligations.is_ignored_invocation(effect, candidate),
        },
    )
}

fn marker_invocation_projection<O: Clone, S, T>(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    effect_trace: &EffectTrace<O, S, T>,
    root_function: FunctionId,
    invocation: effect_tracing::InvocationId,
    node: TraceNodeId,
    policy: MarkerTraversalPolicy<
        impl Fn(FunctionId, &TrustPath) -> bool,
        impl Fn(effect_tracing::InvocationId) -> bool,
    >,
) -> Option<(StableFunctionId, InterpretedTrace)> {
    let function = graph.invocation(invocation).caller();
    let mut trace = path_from_root_until(
        artifact,
        graph,
        root_function,
        function,
        policy.trust_path,
        policy.is_opaque,
        policy.is_ignored_invocation,
    )?;
    let target = effect_trace.nodes().nth(node.index())?.function();
    let edge = graph.source_edge(invocation, target)?;
    append_call_trace(artifact, graph.stable_function(function), edge, &mut trace);
    if let Some(last) = trace.steps.last_mut() {
        last.target = Some(graph.stable_function(target));
        last.target_path = Some(display_path(artifact, graph.stable_function(target)));
    }
    let mut suffix = trace_path(artifact, graph, effect_trace, node.index());
    trace.steps.append(&mut suffix.steps);
    Some((graph.stable_function(function), trace))
}

struct MarkerTraversalPolicy<Opaque, Ignored> {
    trust_path: TrustPath,
    is_opaque: Opaque,
    is_ignored_invocation: Ignored,
}

fn effect_groups(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    concrete: &crate::effects::concrete::ConcreteEffect<'_>,
    effect_key: &EffectKey,
    origin: ConcreteSource,
) -> Vec<SourceEffectGroup> {
    match origin {
        ConcreteSource::Invocation { invocation, call } => {
            let owner = graph.stable_function(graph.invocation(invocation).caller());
            let group = concrete
                .invocation_source(invocation, call)
                .and_then(|source| {
                    source
                        .edge()
                        .invocation_effects
                        .iter()
                        .find(|fact| &fact.effect == effect_key)
                        .and_then(|fact| fact.effect_group)
                })
                .map_or(SourceEffectGroup::Invocation(invocation, call), |group| {
                    SourceEffectGroup::Operation(owner, group)
                });
            vec![group]
        }
        ConcreteSource::Effect { owner, effect } => vec![
            effect_fact(artifact, owner, effect)
                .and_then(|(_, fact)| fact.effect_group)
                .map_or(
                    SourceEffectGroup::StandaloneOperation(owner, effect),
                    |group| SourceEffectGroup::Operation(owner, group),
                ),
        ],
    }
}

pub(super) fn obligation_effect_groups(
    graph: &InvocationGraph,
    concrete: Option<&crate::effects::concrete::ConcreteEffect<'_>>,
    effect_key: &EffectKey,
    invocation: effect_tracing::InvocationId,
    calls: impl IntoIterator<Item = crate::artifact::CallId>,
) -> Vec<SourceEffectGroup> {
    let owner = graph.stable_function(graph.invocation(invocation).caller());
    calls
        .into_iter()
        .filter_map(|call| {
            graph
                .source_edges(invocation)
                .iter()
                .find(|edge| edge.id == call)
        })
        .map(|edge| {
            let is_concrete = concrete
                .is_some_and(|concrete| concrete.invocation_source(invocation, edge.id).is_some());
            if !is_concrete {
                return SourceEffectGroup::Invocation(invocation, edge.id);
            }
            edge.invocation_effects
                .iter()
                .find(|fact| &fact.effect == effect_key)
                .and_then(|fact| fact.effect_group)
                .map_or(
                    SourceEffectGroup::Invocation(invocation, edge.id),
                    |group| SourceEffectGroup::Operation(owner, group),
                )
        })
        .collect()
}

fn concrete_source_owner(graph: &InvocationGraph, origin: ConcreteSource) -> Option<FunctionId> {
    match origin {
        ConcreteSource::Invocation { invocation, .. } => {
            Some(graph.invocation(invocation).caller())
        }
        ConcreteSource::Effect { owner, .. } => graph.function(owner),
    }
}

fn append_concrete_origin(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    concrete: &crate::effects::concrete::ConcreteEffect<'_>,
    origin: ConcreteSource,
    trace: &mut InterpretedTrace,
) {
    match origin {
        ConcreteSource::Invocation { invocation, call } => {
            if let Some(source) = concrete.invocation_source(invocation, call) {
                append_invocation_source(artifact, graph, invocation, source, trace);
            }
        }
        ConcreteSource::Effect { owner, effect } => {
            if let Some((body, fact)) = effect_fact(artifact, owner, effect) {
                append_effect_provenance(body, fact, trace);
            }
        }
    }
}

fn append_invocation_source(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    invocation: effect_tracing::InvocationId,
    source: &InvocationSourceBranch,
    trace: &mut InterpretedTrace,
) {
    append_call_trace(
        artifact,
        graph.stable_function(graph.invocation(invocation).caller()),
        source.edge(),
        trace,
    );
    if let Some((step, target)) = trace.steps.last_mut().zip(source.target()) {
        step.target = Some(target.function);
        step.target_path = Some(target.display_path.clone());
    }
}
