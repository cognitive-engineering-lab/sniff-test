//! Projection of compiler facts and effect traces into policy-neutral findings.
//!
//! It probes the three concrete effects, asks `effect-tracing` to trace them,
//! and projects trace outcomes for configured report roots. A narrow,
//! effect-provided boundary-aware path lookup associates ambiguous annotations
//! with audited roots; effect propagation itself is exclusively performed by
//! the shared engine.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use effect_tracing::{
    EffectEngine, EffectGraph, EffectTrace, FunctionId, PropagationEdge, TerminationSite,
    TraceNodeId, TraceOptions,
};

use crate::annotations::{AnnotationId, AnnotationIndex};
use crate::artifact::{
    AnnotationFactKind, AnnotationProbingFact, AnnotationRole, AnnotationTargetFact, ArtifactFacts,
    CallTargetFact, DefinitionNamespaceIndex, EffectFact, EffectId, EffectKey, FunctionFact,
    FunctionId as StableFunctionId, FunctionTargetFact, MarkerEvidenceState,
    UnverifiedMarkerProbeReason,
};
use crate::compiler::invocations::{
    InvocationGraph, InvocationResolution, UnresolvedCallTargetReason,
};
use crate::config::{MarkerProbing, SniffTestConfig};
use crate::contracts::normalize_requirement_name;
use crate::effects::InvocationSourceBranch;
use crate::effects::concrete::{ConcreteSource, probe_concrete_effect};
use crate::effects::obligation::{
    ObligationEffectPolicy, ObligationTracker, TrackedEffect, TrackedOrigin, TrackedState,
    TrackedTermination,
};
use crate::effects::{Effect, EffectConfig, EffectMetadata, EffectSpec, annotation_kind};
#[cfg(test)]
use crate::effects::{EffectSelection, selected_effect_objects};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ReportEffect {
    Panic,
    Safety,
}

impl ReportEffect {
    fn key(self) -> EffectKey {
        match self {
            Self::Panic => EffectKey::new(Panic::EFFECT_NAME),
            Self::Safety => EffectKey::new(Safety::EFFECT_NAME),
        }
    }

    fn try_from_key(effect: &EffectKey) -> Option<Self> {
        if effect.as_str() == Panic::EFFECT_NAME {
            Some(Self::Panic)
        } else if effect.as_str() == Safety::EFFECT_NAME {
            Some(Self::Safety)
        } else {
            None
        }
    }
}
use crate::effects::panic::Panic;
use crate::effects::safety::Safety;
use crate::effects::trust::TrustPath;
use crate::report_model::{
    DomainCompleteness, EffectCompleteness, IncompleteReason, IncompleteTraceKind,
    InterpretationRoot, InterpretedCallee, InterpretedFinding, InterpretedFindingKind,
    InterpretedTrace, InterpretedTraceStep, InterpretedTraceStepKind, RootInterpretation,
    TraceFrontier, UnresolvedCallCoverage, UnresolvedCallMechanism, UnresolvedCallSite,
};
use crate::workspace::ArtifactAnalysisGraph;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EffectReportError {
    message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SourceEffectGroup {
    Invocation(effect_tracing::InvocationId, crate::artifact::CallId),
    Operation(StableFunctionId, crate::artifact::EffectGroupId),
    StandaloneOperation(StableFunctionId, EffectId),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MarkerEffectGroup {
    effect: EffectKey,
    source: SourceEffectGroup,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum MarkerWitness {
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
enum MarkerTraceSite {
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

type MarkerClaims = BTreeMap<AnnotationId, BTreeMap<MarkerEffectGroup, Vec<MarkerWitness>>>;

type ConcreteTrace = EffectTrace<
    TrackedOrigin<ConcreteSource>,
    TrackedState<crate::effects::concrete::ConcreteEffectState>,
    TrackedTermination<crate::effects::concrete::ConcreteTermination>,
>;

struct MarkerProjection {
    function: StableFunctionId,
    function_path: String,
    trace: InterpretedTrace,
}

impl EffectReportError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for EffectReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for EffectReportError {}

#[cfg(test)]
pub(crate) fn trace_workspace(
    local: &ArtifactFacts,
    local_stable_crate_id: u64,
    dependencies: &ArtifactAnalysisGraph,
    roots: &[InterpretationRoot],
    config: &SniffTestConfig,
) -> Result<Vec<RootInterpretation>, EffectReportError> {
    let effects = EffectSelection::default();
    let selected_effects = selected_effect_objects(&effects, config);
    trace_selected_workspace(
        local,
        local_stable_crate_id,
        dependencies,
        &BTreeMap::new(),
        roots,
        config,
        &selected_effects,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the selected effect probes and traces stay visible in one production entry point"
)]
pub(crate) fn trace_selected_workspace(
    local: &ArtifactFacts,
    local_stable_crate_id: u64,
    dependencies: &ArtifactAnalysisGraph,
    rustc_dependencies: &BTreeMap<u64, BTreeSet<u64>>,
    roots: &[InterpretationRoot],
    config: &SniffTestConfig,
    effects: &[Box<dyn Effect + '_>],
) -> Result<Vec<RootInterpretation>, EffectReportError> {
    let artifact = compose_workspace_artifact(local, dependencies)?;
    let artifact = &artifact;
    let mut graph = InvocationGraph::from_artifact(artifact)
        .map_err(|error| EffectReportError::new(error.to_string()))?;
    let mut crate_dependencies = dependencies
        .artifacts()
        .map(|artifact| {
            (
                artifact.artifact.id.stable_crate_id,
                artifact
                    .dependencies
                    .iter()
                    .map(|id| id.stable_crate_id)
                    .collect(),
            )
        })
        .collect::<BTreeMap<_, BTreeSet<_>>>();
    crate_dependencies.insert(
        local_stable_crate_id,
        dependencies
            .direct_dependency_ids()
            .map(|id| id.stable_crate_id)
            .collect(),
    );
    crate_dependencies.extend(
        rustc_dependencies
            .iter()
            .map(|(&owner, children)| (owner, children.clone())),
    );
    graph.set_dependencies(&crate_dependencies);
    let namespaces = artifact.definition_namespace_index();
    let selected_metadata = effects
        .iter()
        .map(|effect| effect.metadata().clone())
        .collect::<Vec<_>>();
    let annotations = AnnotationIndex::from_artifact_with_overrides(
        artifact,
        &graph,
        &namespaces,
        &config.contracts.overrides,
        config.analysis.marker_probing,
        &selected_metadata,
    )
    .map_err(|error| EffectReportError::new(error.to_string()))?;
    let concrete_effects = effects
        .iter()
        .map(|effect| {
            let concrete =
                probe_concrete_effect(artifact, &graph, &annotations, &namespaces, effect.as_ref())
                    .map_err(|error| EffectReportError::new(error.to_string()))?;
            Ok((effect.key().clone(), concrete))
        })
        .collect::<Result<BTreeMap<_, _>, EffectReportError>>()?;
    let obligation_policies = concrete_effects.iter().map(|(effect, concrete)| {
        ObligationEffectPolicy::new(
            effect.clone(),
            concrete.trusted_functions(),
            concrete.ignored_invocations(),
        )
    });
    let obligations = ObligationTracker::probe(
        &graph,
        &annotations,
        config.analysis.effect_doc_matching,
        obligation_policies,
    );
    let trace_options = TraceOptions {
        max_depth: config.analysis.max_trace_depth,
        state_budget: config.analysis.trace_state_budget,
    };
    let obligation_graph = graph.obligation_graph();
    let engine = EffectEngine::with_options(&obligation_graph, trace_options);
    // Tracing is entirely effect-independent. Keep runs keyed by their stable
    // effect identity so registering another effect does not require another
    // typed local, trace alias, or engine invocation here.
    let tracked_effects = concrete_effects
        .iter()
        .map(|(effect, concrete)| {
            (
                effect.clone(),
                TrackedEffect::new(concrete, &obligations, effect.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let effect_traces = tracked_effects
        .iter()
        .map(|(effect, tracked)| (effect.clone(), engine.trace(tracked)))
        .collect::<BTreeMap<_, ConcreteTrace>>();
    let panic_key = ReportEffect::Panic.key();
    let safety_key = ReportEffect::Safety.key();
    let panic_trace = effect_traces.get(&panic_key);
    let safety_trace = effect_traces.get(&safety_key);
    let marker_claims = collect_marker_claims(
        artifact,
        &graph,
        &concrete_effects,
        &effect_traces,
        &tracked_effects,
    );
    let marker_probing = annotation_probing_fact(config.analysis.marker_probing);

    roots
        .iter()
        .cloned()
        .map(|root| {
            let root_functions = graph.function_aliases(root.function).collect::<Vec<_>>();
            if root_functions.is_empty() {
                return Err(EffectReportError::new(format!(
                    "report root `{}` is absent from the invocation graph",
                    root.path
                )));
            }
            let mut findings = Vec::new();
            for root_function in root_functions.iter().copied() {
                for (effect, concrete) in &concrete_effects {
                    if let Some(trace) = effect_traces.get(effect) {
                        let metadata = selected_metadata
                            .iter()
                            .find(|metadata| &metadata.key == effect)
                            .expect("every probed effect has selected metadata");
                        findings.extend(concrete_findings(
                            artifact,
                            &graph,
                            &annotations,
                            metadata,
                            concrete,
                            trace,
                            root_function,
                            marker_probing,
                        ));
                        findings.extend(justified_undocumented_invocation_findings(
                            artifact,
                            &graph,
                            &annotations,
                            metadata,
                            concrete,
                            trace,
                            root_function,
                        ));
                    }
                }
                for domain in effects {
                    let effect = domain.key();
                    let concrete = concrete_effects
                        .get(effect)
                        .expect("selected effect was probed");
                    if domain
                        .config()
                        .effective_coverage(&config.analysis.lints)
                        .unresolved_call_target
                        .is_allow()
                    {
                        continue;
                    }
                    let metadata = selected_metadata
                        .iter()
                        .find(|metadata| &metadata.key == effect)
                        .expect("selected effect metadata");
                    findings.extend(unresolved_call_target_findings(
                        artifact,
                        &graph,
                        &annotations,
                        root_function,
                        metadata,
                        domain.config(),
                        &namespaces,
                        |function, path: &TrustPath| concrete.is_opaque_on_path(function, path),
                        |invocation| concrete.is_ignored_invocation(invocation),
                    ));
                }
                findings.extend(marker_ambiguities(
                    artifact,
                    &graph,
                    &annotations,
                    &concrete_effects,
                    &effect_traces,
                    &tracked_effects,
                    &marker_claims,
                    &selected_metadata,
                    root_function,
                ));
                for (effect, tracked) in &tracked_effects {
                    if let Some(trace) = effect_traces.get(effect) {
                        findings.extend(obligation_findings(
                            artifact,
                            &graph,
                            &annotations,
                            tracked,
                            selected_metadata
                                .iter()
                                .find(|metadata| &metadata.key == effect)
                                .expect("every tracked effect has selected metadata"),
                            trace,
                            root_function,
                            &root,
                            marker_probing,
                        ));
                    }
                }
            }
            // A source definition can have both generic and monomorphized graph
            // identities. They are deliberately traced independently, but they
            // still describe one source-level finding when their projected path
            // and state are identical.
            let mut unique = Vec::with_capacity(findings.len());
            for finding in findings {
                if !unique
                    .iter()
                    .any(|existing| same_source_finding(existing, &finding))
                {
                    unique.push(finding);
                }
            }
            let mut panic_additional = AdditionalCompleteness {
                reasons: Vec::new(),
            };
            if effects
                .iter()
                .any(|effect| effect.key() == &ReportEffect::Panic.key())
            {
                panic_additional.reasons.extend(missing_body_reasons(
                    artifact,
                    &graph,
                    &namespaces,
                    dependencies,
                    local_stable_crate_id,
                    &root_functions,
                    ReportEffect::Panic,
                    config,
                ));
            }
            let mut safety_additional = AdditionalCompleteness {
                reasons: Vec::new(),
            };
            if effects
                .iter()
                .any(|effect| effect.key() == &ReportEffect::Safety.key())
            {
                safety_additional.reasons.extend(missing_body_reasons(
                    artifact,
                    &graph,
                    &namespaces,
                    dependencies,
                    local_stable_crate_id,
                    &root_functions,
                    ReportEffect::Safety,
                    config,
                ));
            }
            Ok(RootInterpretation {
                root,
                findings: unique,
                completeness: EffectCompleteness {
                    panic: panic_trace.as_ref().map_or(
                        DomainCompleteness {
                            complete: true,
                            reasons: Vec::new(),
                        },
                        |panic_trace| {
                            completeness(
                                artifact,
                                panic_trace,
                                &graph,
                                &root_functions,
                                trace_options,
                                IncompleteTraceKind::PanicEffect,
                                panic_additional,
                            )
                        },
                    ),
                    safety: safety_trace.as_ref().map_or(
                        DomainCompleteness {
                            complete: true,
                            reasons: Vec::new(),
                        },
                        |safety_trace| {
                            completeness(
                                artifact,
                                safety_trace,
                                &graph,
                                &root_functions,
                                trace_options,
                                IncompleteTraceKind::SafetyEffect,
                                safety_additional,
                            )
                        },
                    ),
                    effects: effect_traces
                        .iter()
                        .filter(|(effect, _)| ReportEffect::try_from_key(effect).is_none())
                        .map(|(effect, trace)| {
                            (
                                effect.clone(),
                                completeness(
                                    artifact,
                                    trace,
                                    &graph,
                                    &root_functions,
                                    trace_options,
                                    IncompleteTraceKind::Effect,
                                    AdditionalCompleteness {
                                        reasons: Vec::new(),
                                    },
                                ),
                            )
                        })
                        .collect(),
                },
            })
        })
        .collect()
}

fn marker_ambiguities(
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

fn collect_marker_claims(
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
    if let MarkerWitness::Concrete { effect, origin, .. } = witness {
        if let Some(concrete) = concrete_effects.get(&effect) {
            append_concrete_origin(artifact, graph, concrete, origin, &mut trace);
        }
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

fn obligation_effect_groups(
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

fn path_from_root(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    root: FunctionId,
    target: FunctionId,
) -> Option<InterpretedTrace> {
    path_from_root_until(
        artifact,
        graph,
        root,
        target,
        TrustPath::default(),
        |_, _| false,
        |_| false,
    )
}

fn audited_path_from_root(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    root: FunctionId,
    target: FunctionId,
    is_opaque: impl Fn(FunctionId, &TrustPath) -> bool,
    is_ignored_invocation: impl Fn(effect_tracing::InvocationId) -> bool,
) -> Option<InterpretedTrace> {
    path_from_root_until(
        artifact,
        graph,
        root,
        target,
        TrustPath::default(),
        is_opaque,
        is_ignored_invocation,
    )
}

fn path_from_root_until(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    root: FunctionId,
    target: FunctionId,
    mut trust_path: TrustPath,
    is_opaque: impl Fn(FunctionId, &TrustPath) -> bool,
    is_ignored_invocation: impl Fn(effect_tracing::InvocationId) -> bool,
) -> Option<InterpretedTrace> {
    if !is_opaque(target, &TrustPath::default()) {
        trust_path.enter(graph, target);
    }
    if is_opaque(target, &trust_path) {
        return None;
    }
    if root == target {
        return Some(InterpretedTrace { steps: Vec::new() });
    }
    let mut queue = std::collections::VecDeque::from([(target, Vec::new(), trust_path.clone())]);
    let mut visited = BTreeSet::from([(target, trust_path)]);
    while let Some((function, path, trust_path)) = queue.pop_front() {
        for invocation in graph.incoming_invocations(function) {
            if is_ignored_invocation(*invocation) {
                continue;
            }
            let parent = graph.caller(*invocation);
            let mut next_trust = trust_path.clone();
            if !is_opaque(parent, &TrustPath::default()) {
                next_trust.enter(graph, parent);
            }
            if is_opaque(parent, &next_trust) || !visited.insert((parent, next_trust.clone())) {
                continue;
            }
            let mut next = path.clone();
            next.push((PropagationEdge::Invocation(*invocation), function));
            if parent == root {
                return Some(project_reverse_path(artifact, graph, next));
            }
            queue.push_back((parent, next, next_trust));
        }
        for transparent in graph.transparent_parents(function) {
            let parent = graph.transparent_parent(*transparent);
            let mut next_trust = trust_path.clone();
            if !is_opaque(parent, &TrustPath::default()) {
                next_trust.enter(graph, parent);
            }
            if is_opaque(parent, &next_trust) || !visited.insert((parent, next_trust.clone())) {
                continue;
            }
            let mut next = path.clone();
            next.push((PropagationEdge::TransparentBody(*transparent), function));
            if parent == root {
                return Some(project_reverse_path(artifact, graph, next));
            }
            queue.push_back((parent, next, next_trust));
        }
    }
    None
}

fn project_reverse_path(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    path: Vec<(PropagationEdge, FunctionId)>,
) -> InterpretedTrace {
    let mut trace = InterpretedTrace { steps: Vec::new() };
    for (edge, child) in path.into_iter().rev() {
        match edge {
            PropagationEdge::Invocation(invocation) => {
                if let Some(source) = graph.source_edge(invocation, child) {
                    append_call_trace(
                        artifact,
                        graph.stable_function(graph.caller(invocation)),
                        source,
                        &mut trace,
                    );
                }
            }
            PropagationEdge::TransparentBody(transparent) => {
                let parent = graph.transparent_parent(transparent);
                let source = graph.transparent_source(transparent);
                trace.steps.push(InterpretedTraceStep {
                    caller: graph.stable_function(parent),
                    caller_path: display_path(artifact, graph.stable_function(parent)),
                    call: source.id,
                    marker_call: None,
                    kind: InterpretedTraceStepKind::Reachability(source.kind),
                    source_range: source.source_range.clone(),
                    target: Some(graph.stable_function(child)),
                    target_path: Some(display_path(artifact, graph.stable_function(child))),
                });
            }
            PropagationEdge::ContractHandoff => {}
        }
    }
    trace
}

fn same_source_finding(left: &InterpretedFinding, right: &InterpretedFinding) -> bool {
    left.effect == right.effect
        && left.kind == right.kind
        && left.function_path == right.function_path
        && left.callee.as_ref().map(|callee| &callee.path)
            == right.callee.as_ref().map(|callee| &callee.path)
        && left.source_range == right.source_range
        && left.marker_evidence == right.marker_evidence
        && left.missing_requirements == right.missing_requirements
        && left.requirements == right.requirements
        && left.trace.steps.len() == right.trace.steps.len()
        && left
            .trace
            .steps
            .iter()
            .zip(&right.trace.steps)
            .all(|(left, right)| {
                left.caller.def_path_hash == right.caller.def_path_hash
                    && (left.caller != right.caller || left.call == right.call)
                    && left.caller_path == right.caller_path
                    && left.kind == right.kind
                    && left.source_range == right.source_range
                    && left.target_path == right.target_path
            })
}

fn compose_workspace_artifact(
    local: &ArtifactFacts,
    dependencies: &ArtifactAnalysisGraph,
) -> Result<ArtifactFacts, EffectReportError> {
    let mut functions = std::collections::BTreeMap::new();
    let mut sources = std::collections::BTreeMap::new();
    for dependency in dependencies.artifacts() {
        for body in &dependency.facts.functions {
            functions
                .entry(body.function)
                .or_insert_with(|| body.clone());
        }
        for source in &dependency.facts.source_files {
            sources
                .entry(source.id.clone())
                .or_insert_with(|| source.clone());
        }
    }
    for body in &local.functions {
        functions.insert(body.function, body.clone());
    }
    for source in &local.source_files {
        sources.insert(source.id.clone(), source.clone());
    }
    ArtifactFacts::new(
        functions.into_values().collect(),
        sources.into_values().collect(),
    )
    .map_err(|error| EffectReportError::new(format!("invalid linked workspace facts: {error}")))
}

const fn annotation_probing_fact(probing: MarkerProbing) -> AnnotationProbingFact {
    match probing {
        MarkerProbing::SourceCallsite => AnnotationProbingFact::SourceCallsite,
        MarkerProbing::MacroDefinitionFirst => AnnotationProbingFact::MacroDefinitionFirst,
    }
}

const fn unavailable_marker_evidence() -> MarkerEvidenceState {
    MarkerEvidenceState::Unverified(UnverifiedMarkerProbeReason::NoUsableSourceSpan)
}

fn merge_marker_evidence(
    left: MarkerEvidenceState,
    right: MarkerEvidenceState,
) -> MarkerEvidenceState {
    match (left, right) {
        (MarkerEvidenceState::Present, _) | (_, MarkerEvidenceState::Present) => {
            MarkerEvidenceState::Present
        }
        (MarkerEvidenceState::Unverified(left), MarkerEvidenceState::Unverified(right)) => {
            MarkerEvidenceState::Unverified(left.merge(right))
        }
        (unverified @ MarkerEvidenceState::Unverified(_), MarkerEvidenceState::VerifiedAbsent)
        | (MarkerEvidenceState::VerifiedAbsent, unverified @ MarkerEvidenceState::Unverified(_)) => {
            unverified
        }
        (MarkerEvidenceState::VerifiedAbsent, MarkerEvidenceState::VerifiedAbsent) => {
            MarkerEvidenceState::VerifiedAbsent
        }
    }
}

fn effect_marker_evidence(
    artifact: &ArtifactFacts,
    owner: StableFunctionId,
    effect: EffectId,
    kind: AnnotationFactKind,
    probing: AnnotationProbingFact,
) -> MarkerEvidenceState {
    artifact
        .source_marker_evidence_state(owner, kind, AnnotationTargetFact::Effect(effect), probing)
        .unwrap_or_else(unavailable_marker_evidence)
}

fn raw_call_marker_evidence(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    invocation: effect_tracing::InvocationId,
    call: crate::artifact::CallId,
    kind: AnnotationFactKind,
    probing: AnnotationProbingFact,
) -> MarkerEvidenceState {
    let owner = graph.stable_function(graph.invocation(invocation).caller());
    artifact
        .source_marker_evidence_state(owner, kind, AnnotationTargetFact::Call(call), probing)
        .unwrap_or_else(unavailable_marker_evidence)
}

fn obligation_marker_evidence(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    source_invocation: Option<effect_tracing::InvocationId>,
    source_calls: impl IntoIterator<Item = crate::artifact::CallId>,
    kind: AnnotationFactKind,
    probing: AnnotationProbingFact,
) -> Option<MarkerEvidenceState> {
    let invocation = source_invocation?;
    Some(
        source_calls
            .into_iter()
            .map(|call| {
                raw_call_marker_evidence(artifact, graph, invocation, call, kind.clone(), probing)
            })
            .reduce(merge_marker_evidence)
            .unwrap_or_else(unavailable_marker_evidence),
    )
}

/// Projects every registered effect from the common fact vocabulary emitted
/// by its compiler passes; presentation compatibility is applied later.
fn concrete_findings(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    annotations: &AnnotationIndex,
    metadata: &EffectMetadata,
    concrete: &crate::effects::concrete::ConcreteEffect<'_>,
    trace: &ConcreteTrace,
    root_function: effect_tracing::FunctionId,
    marker_probing: AnnotationProbingFact,
) -> Vec<InterpretedFinding> {
    let effect_key = &metadata.key;
    active_root_nodes(trace, root_function)
        .filter_map(|node| {
            let mut trace_path = trace_path(artifact, graph, trace, node);
            let trace_node = trace.nodes().nth(node)?;
            let TrackedState::Concrete(_) = trace_node.state() else {
                return None;
            };
            let TrackedOrigin::Concrete(origin) = *trace_node.origin() else {
                return None;
            };
            match origin {
                ConcreteSource::Effect { owner, effect } => {
                    let (body, fact) = effect_fact(artifact, owner, effect)?;
                    if &fact.effect != effect_key {
                        return None;
                    }
                    append_effect_provenance(body, fact, &mut trace_path);
                    append_effect_operation(body, fact, &mut trace_path);
                    Some(InterpretedFinding {
                        effect: metadata.clone(),
                        kind: InterpretedFindingKind::Operation {
                            operation: fact.kind.clone(),
                        },
                        function: owner,
                        function_path: body.display_path.clone(),
                        callee: None,
                        source_range: fact.source_range.clone(),
                        contract_source_range: None,
                        marker_evidence: Some(effect_marker_evidence(
                            artifact,
                            owner,
                            effect,
                            AnnotationFactKind::new(
                                effect_key.clone(),
                                AnnotationRole::Justification,
                            ),
                            marker_probing,
                        )),
                        trace: trace_path,
                        missing_requirements: Vec::new(),
                        requirements: Vec::new(),
                    })
                }
                ConcreteSource::Invocation { invocation, call } => {
                    let source = concrete.invocation_source(invocation, call)?;
                    if invocation_source_has_contract(graph, annotations, &source, effect_key) {
                        return None;
                    }
                    let edge = source.edge();
                    let invocation_effect = edge
                        .invocation_effects
                        .iter()
                        .find(|fact| &fact.effect == effect_key)?;
                    let operation = invocation_effect.kind.clone();
                    let missing_required_documentation = invocation_effect
                        .requires_documented_obligation
                        && source.target().is_some();
                    let owner = graph.stable_function(graph.invocation(invocation).caller());
                    let body = artifact.function_body(owner)?;
                    append_call_trace(artifact, owner, edge, &mut trace_path);
                    if missing_required_documentation {
                        return undocumented_invocation_finding(
                            artifact, graph, metadata, source, invocation, trace_path,
                        );
                    }
                    Some(InterpretedFinding {
                        effect: metadata.clone(),
                        kind: InterpretedFindingKind::Invocation { operation },
                        function: owner,
                        function_path: body.display_path.clone(),
                        callee: source.target().map(interpreted_callee).or_else(|| {
                            (effect_key == &ReportEffect::Safety.key()
                                && edge.kind == crate::artifact::CallKindFact::IndirectCall)
                                .then(|| InterpretedCallee {
                                    function: None,
                                    path: String::from("unsafe function pointer"),
                                    requires_explicit_context: true,
                                })
                        }),
                        source_range: edge.source_range.clone(),
                        contract_source_range: None,
                        marker_evidence: Some(raw_call_marker_evidence(
                            artifact,
                            graph,
                            invocation,
                            call,
                            AnnotationFactKind::new(
                                effect_key.clone(),
                                AnnotationRole::Justification,
                            ),
                            marker_probing,
                        )),
                        trace: trace_path,
                        missing_requirements: Vec::new(),
                        requirements: Vec::new(),
                    })
                }
            }
        })
        .collect()
}

fn justified_undocumented_invocation_findings(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    annotations: &AnnotationIndex,
    metadata: &EffectMetadata,
    concrete: &crate::effects::concrete::ConcreteEffect<'_>,
    trace: &ConcreteTrace,
    root_function: effect_tracing::FunctionId,
) -> Vec<InterpretedFinding> {
    trace
        .handled()
        .filter_map(|handled| {
            let (
                TrackedOrigin::Concrete(ConcreteSource::Invocation { invocation, call }),
                TrackedTermination::Concrete(
                    crate::effects::concrete::ConcreteTermination::Justification(_),
                ),
            ) = (handled.origin(), handled.termination())
            else {
                return None;
            };
            let source = concrete.invocation_source(*invocation, *call)?;
            let invocation_effect = source
                .edge()
                .invocation_effects
                .iter()
                .find(|fact| fact.effect == metadata.key)?;
            if !invocation_effect.requires_documented_obligation
                || source.target().is_none()
                || invocation_source_has_contract(graph, annotations, source, &metadata.key)
            {
                return None;
            }
            let owner = graph.invocation(*invocation).caller();
            let mut path = audited_path_from_root(
                artifact,
                graph,
                root_function,
                owner,
                |function, trust_path| concrete.is_opaque_on_path(function, trust_path),
                |candidate| concrete.is_ignored_invocation(candidate),
            )?;
            append_call_trace(
                artifact,
                graph.stable_function(owner),
                source.edge(),
                &mut path,
            );
            undocumented_invocation_finding(artifact, graph, metadata, source, *invocation, path)
        })
        .collect()
}

fn undocumented_invocation_finding(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    metadata: &EffectMetadata,
    source: &InvocationSourceBranch,
    invocation: effect_tracing::InvocationId,
    trace: InterpretedTrace,
) -> Option<InterpretedFinding> {
    let edge = source.edge();
    let invocation_effect = edge
        .invocation_effects
        .iter()
        .find(|fact| fact.effect == metadata.key)?;
    let owner = graph.stable_function(graph.invocation(invocation).caller());
    let body = artifact.function_body(owner)?;
    Some(InterpretedFinding {
        effect: metadata.clone(),
        kind: InterpretedFindingKind::UndocumentedInvocation {
            operation: invocation_effect.kind.clone(),
        },
        function: owner,
        function_path: body.display_path.clone(),
        callee: source.target().map(interpreted_callee),
        source_range: edge.source_range.clone(),
        contract_source_range: None,
        marker_evidence: None,
        trace,
        missing_requirements: Vec::new(),
        requirements: Vec::new(),
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "root-scoped coverage reuses precomputed definition aliases with domain policy"
)]
fn unresolved_call_target_findings(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    annotations: &AnnotationIndex,
    root_function: effect_tracing::FunctionId,
    metadata: &EffectMetadata,
    config: &dyn EffectConfig,
    namespaces: &DefinitionNamespaceIndex,
    is_opaque: impl Fn(FunctionId, &TrustPath) -> bool + Copy,
    is_ignored_invocation: impl Fn(effect_tracing::InvocationId) -> bool + Copy,
) -> Vec<InterpretedFinding> {
    graph
        .invocations()
        .filter(|invocation| invocation.is_unresolved())
        .filter(|invocation| !is_ignored_invocation(invocation.id()))
        .flat_map(|invocation| {
            let resolution = invocation.resolution();
            let partially_resolved = match resolution {
                InvocationResolution::Resolved => return Vec::new(),
                InvocationResolution::PartiallyResolved { .. } => true,
                InvocationResolution::Unresolved { .. } => false,
            };
            let owner = graph.stable_function(invocation.caller());
            let Some(body) = artifact.function_body(owner) else {
                return Vec::new();
            };
            let ignored = config
                .ignored_namespaces()
                .best_candidates_match(namespaces.candidates(owner))
                .is_some();
            if ignored {
                return Vec::new();
            }
            let Some(base_trace) = audited_path_from_root(
                artifact,
                graph,
                root_function,
                invocation.caller(),
                is_opaque,
                is_ignored_invocation,
            ) else {
                return Vec::new();
            };
            let mut seen_surfaces = BTreeSet::new();
            graph
                .source_edges(invocation.id())
                .iter()
                .filter_map(|edge| unresolved_source_reason(edge).map(|reason| (edge, reason)))
                .filter_map(|(edge, reason)| {
                    if reason == UnresolvedCallTargetReason::UnavailableBody
                        || unresolved_source_is_covered(
                            edge,
                            annotations,
                            &metadata.key,
                            config,
                            namespaces,
                        )
                    {
                        return None;
                    }
                    let site = unresolved_call_site(partially_resolved, reason)?;
                    let surface = invocation_surface(edge);
                    let opaque_description = surface.is_none().then(|| match &edge.target {
                        CallTargetFact::OpaqueBoundary { description, .. } => description.clone(),
                        CallTargetFact::Function(_) => String::new(),
                    });
                    seen_surfaces
                        .insert((
                            site,
                            surface.map(|target| target.function),
                            opaque_description,
                        ))
                        .then_some((edge, site))
                })
                .map(|(edge, site)| {
                    let mut trace = base_trace.clone();
                    append_call_trace(artifact, owner, edge, &mut trace);
                    InterpretedFinding {
                        effect: metadata.clone(),
                        kind: InterpretedFindingKind::UnresolvedCallTarget { site },
                        function: owner,
                        function_path: body.display_path.clone(),
                        callee: invocation_surface(edge).map(interpreted_callee),
                        source_range: edge.source_range.clone(),
                        contract_source_range: None,
                        marker_evidence: None,
                        trace,
                        missing_requirements: Vec::new(),
                        requirements: Vec::new(),
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn unresolved_source_reason(
    edge: &crate::artifact::CallFact,
) -> Option<UnresolvedCallTargetReason> {
    if !matches!(edge.target, CallTargetFact::OpaqueBoundary { .. }) {
        return None;
    }
    if edge.indirect_kind == Some(crate::artifact::IndirectCallKindFact::DynamicDispatch) {
        return Some(UnresolvedCallTargetReason::DynamicDispatch);
    }
    if edge.indirect_kind == Some(crate::artifact::IndirectCallKindFact::FunctionPointer) {
        return Some(UnresolvedCallTargetReason::FunctionPointer);
    }
    if edge.declaration_target.is_some() {
        return Some(UnresolvedCallTargetReason::GenericDispatch);
    }
    if edge
        .target
        .function_target()
        .is_some_and(|target| !target.attributes.is_foreign && !target.attributes.has_rust_body)
    {
        return Some(UnresolvedCallTargetReason::UnavailableBody);
    }
    Some(UnresolvedCallTargetReason::Opaque)
}

fn unresolved_source_is_covered(
    edge: &crate::artifact::CallFact,
    annotations: &AnnotationIndex,
    effect: &EffectKey,
    config: &dyn EffectConfig,
    namespaces: &DefinitionNamespaceIndex,
) -> bool {
    let Some(declaration) = invocation_surface(edge) else {
        return false;
    };
    if annotations
        .function_contracts(declaration.function, effect)
        .next()
        .is_some()
    {
        return true;
    }

    let candidates = namespaces.candidates(declaration.function);
    config
        .ignored_namespaces()
        .best_candidates_match(candidates)
        .is_some()
        || config
            .trusted_boundary_namespaces()
            .best_candidates_match(candidates)
            .is_some()
}

fn invocation_surface(edge: &crate::artifact::CallFact) -> Option<&FunctionTargetFact> {
    edge.declaration_target
        .as_ref()
        .or_else(|| edge.target.function_target())
}

fn unresolved_call_site(
    partially_resolved: bool,
    reason: UnresolvedCallTargetReason,
) -> Option<UnresolvedCallSite> {
    let coverage = if partially_resolved {
        UnresolvedCallCoverage::Partial
    } else {
        UnresolvedCallCoverage::None
    };
    let mechanism = match reason {
        UnresolvedCallTargetReason::FunctionPointer => UnresolvedCallMechanism::FunctionPointer,
        UnresolvedCallTargetReason::DynamicDispatch => UnresolvedCallMechanism::DynamicDispatch,
        UnresolvedCallTargetReason::GenericDispatch => UnresolvedCallMechanism::GenericDispatch,
        UnresolvedCallTargetReason::Opaque => UnresolvedCallMechanism::Opaque,
        UnresolvedCallTargetReason::UnavailableBody => return None,
    };
    Some(UnresolvedCallSite {
        coverage,
        mechanism,
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(
    clippy::too_many_lines,
    reason = "obligation findings project one stateful domain from the unified effect trace"
)]
fn obligation_findings<C, O: Clone, S, T>(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    annotations: &AnnotationIndex,
    tracked: &TrackedEffect<'_, '_, C>,
    metadata: &EffectMetadata,
    trace: &EffectTrace<TrackedOrigin<O>, TrackedState<S>, TrackedTermination<T>>,
    root_function: effect_tracing::FunctionId,
    root: &InterpretationRoot,
    marker_probing: AnnotationProbingFact,
) -> Vec<InterpretedFinding> {
    active_root_nodes(trace, root_function)
        .filter_map(|node| {
            let trace_node = trace.nodes().nth(node)?;
            let state = trace_node.state().obligation()?;
            let contract = tracked.obligations().contract(state.contract())?;
            let annotation = annotations.contract(contract.id().annotation())?;
            if contract.applies_to(root_function) {
                return None;
            }
            let path = trace_path(artifact, graph, trace, node);
            let missing_requirements = trace_node
                .state()
                .obligation()?
                .remaining()
                .filter_map(|index| annotation.requirements().get(index).cloned())
                .collect::<Vec<_>>();
            let requirements = annotation.requirements().to_vec();
            let target_function = path
                .steps
                .last()
                .and_then(|step| step.target)
                .unwrap_or(annotation.owner());
            let target_path = path
                .steps
                .last()
                .and_then(|step| step.target_path.clone())
                .or_else(|| {
                    function_presentation(artifact, annotation.owner())
                        .map(|presentation| presentation.path.to_owned())
                })
                .unwrap_or_else(|| format!("{:?}", annotation.owner()));
            let target_is_unsafe = function_presentation(artifact, target_function)
                .is_some_and(|presentation| presentation.is_unsafe);
            let domain = ReportEffect::try_from_key(state.effect());
            let marker_evidence = obligation_marker_evidence(
                artifact,
                graph,
                state.source_invocation(),
                state.source_calls(),
                match domain {
                    Some(ReportEffect::Panic) => {
                        annotation_kind::<Panic>(AnnotationRole::Justification)
                    }
                    Some(ReportEffect::Safety) => {
                        annotation_kind::<Safety>(AnnotationRole::Justification)
                    }
                    None => AnnotationFactKind::new(
                        state.effect().clone(),
                        AnnotationRole::Justification,
                    ),
                },
                marker_probing,
            );
            let (function, function_path, source_range) =
                path.steps
                    .last()
                    .map_or((root.function, root.path.clone(), None), |step| {
                        (
                            step.caller,
                            step.caller_path.clone(),
                            step.source_range.clone(),
                        )
                    });
            let finding = InterpretedFinding {
                effect: metadata.clone(),
                kind: InterpretedFindingKind::DocumentedObligation,
                function,
                function_path,
                callee: Some(InterpretedCallee {
                    function: Some(target_function),
                    path: target_path,
                    requires_explicit_context: target_is_unsafe,
                }),
                source_range,
                contract_source_range: annotation.source_range().cloned(),
                marker_evidence,
                trace: path,
                missing_requirements,
                requirements,
            };
            let mut requirement_groups = std::collections::BTreeMap::<
                String,
                Vec<crate::artifact::ContractRequirementFact>,
            >::new();
            for requirement in annotation.requirements() {
                requirement_groups
                    .entry(normalize_requirement_name(&requirement.name))
                    .or_default()
                    .push(requirement.clone());
            }
            let ambiguous = requirement_groups
                .into_iter()
                .filter(|(name, requirements)| !name.is_empty() && requirements.len() > 1)
                .collect::<Vec<_>>();
            if ambiguous.is_empty() {
                return Some(vec![finding]);
            }
            Some(
                ambiguous
                    .into_iter()
                    .map(|(normalized_name, requirements)| InterpretedFinding {
                        kind: InterpretedFindingKind::AmbiguousRequirement { normalized_name },
                        function: annotation.owner(),
                        function_path: function_presentation(artifact, annotation.owner())
                            .map_or_else(
                                || format!("{:?}", annotation.owner()),
                                |presentation| presentation.path.to_owned(),
                            ),
                        source_range: annotation.source_range().cloned(),
                        marker_evidence: None,
                        missing_requirements: Vec::new(),
                        requirements,
                        ..finding.clone()
                    })
                    .collect(),
            )
        })
        .flatten()
        .collect()
}

struct FunctionPresentation<'artifact> {
    path: &'artifact str,
    is_unsafe: bool,
}

fn function_presentation(
    artifact: &ArtifactFacts,
    function: StableFunctionId,
) -> Option<FunctionPresentation<'_>> {
    if let Some(body) = artifact.function_body(function) {
        return Some(FunctionPresentation {
            path: &body.display_path,
            is_unsafe: body.attributes.is_unsafe,
        });
    }
    artifact
        .functions
        .iter()
        .flat_map(|body| {
            body.contract_declaration
                .iter()
                .chain(body.calls.iter().flat_map(|call| {
                    [
                        call.target.function_target(),
                        call.declaration_target.as_ref(),
                    ]
                    .into_iter()
                    .flatten()
                }))
        })
        .find(|target| target.function.def_path_hash == function.def_path_hash)
        .map(|target| FunctionPresentation {
            path: &target.display_path,
            is_unsafe: target.attributes.is_unsafe,
        })
}

fn invocation_source_has_contract(
    graph: &InvocationGraph,
    annotations: &AnnotationIndex,
    source: &InvocationSourceBranch,
    effect: &EffectKey,
) -> bool {
    let edge = source.edge();
    if let CallTargetFact::Function(target) = &edge.target {
        return graph.function(target.function).is_some_and(|function| {
            annotations
                .effective_contract(graph, function, effect)
                .is_some()
        });
    }

    invocation_surface(edge).is_some_and(|declaration| {
        annotations
            .function_contracts(declaration.function, effect)
            .next()
            .is_some()
    })
}

fn active_root_nodes<O: Clone, S, T>(
    trace: &EffectTrace<O, S, T>,
    root: effect_tracing::FunctionId,
) -> impl Iterator<Item = usize> + '_ {
    let handled_at_root = trace
        .handled()
        .filter_map(|handled| match (handled.site(), handled.node()) {
            (TerminationSite::Function(function), Some(node)) if *function == root => {
                Some(node.index())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let handed_off = trace
        .edges()
        .filter(|edge| edge.propagation() == PropagationEdge::ContractHandoff)
        .map(|edge| edge.from().index())
        .collect::<BTreeSet<_>>();
    trace
        .nodes()
        .enumerate()
        .filter(move |(index, node)| {
            node.function() == root
                && !handled_at_root.contains(index)
                && !handed_off.contains(index)
        })
        .map(|(index, _)| index)
}

struct AdditionalCompleteness {
    reasons: Vec<IncompleteReason>,
}

struct MissingBodyBoundary {
    function: StableFunctionId,
    path: String,
    source_range: Option<crate::artifact::SourceRangeFact>,
    trace: InterpretedTrace,
}

impl MissingBodyBoundary {
    fn into_reason(self) -> IncompleteReason {
        IncompleteReason::MissingBody {
            function: self.function,
            path: self.path,
            source_range: self.source_range,
            trace: self.trace,
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "managed-body completeness joins ownership, domain policy, and root projection"
)]
fn missing_body_reasons(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    namespaces: &DefinitionNamespaceIndex,
    dependencies: &ArtifactAnalysisGraph,
    local_stable_crate_id: u64,
    roots: &[FunctionId],
    domain: ReportEffect,
    config: &SniffTestConfig,
) -> Vec<IncompleteReason> {
    let is_trusted = |function: FunctionId, path: &TrustPath| {
        trusted_boundary(graph.stable_function(function), domain, namespaces, config)
            && path.allows_boundary(graph, function)
    };
    let mut boundaries = BTreeMap::<StableFunctionId, MissingBodyBoundary>::new();
    for body in &artifact.functions {
        let Some(caller) = graph.function(body.function) else {
            continue;
        };
        for call in &body.calls {
            if !call_reaches_function_body(call.kind) {
                continue;
            }
            let CallTargetFact::Function(target) = &call.target else {
                continue;
            };
            if target.attributes.is_foreign
                || !target.attributes.has_rust_body
                || !is_managed_function(target.function, local_stable_crate_id, dependencies)
                || trusted_boundary(target.function, domain, namespaces, config)
            {
                continue;
            }
            let body_is_available = match domain {
                ReportEffect::Panic => artifact.function_body(target.function).is_some(),
                ReportEffect::Safety => artifact.defining_function_body(target.function).is_some(),
            };
            if body_is_available {
                continue;
            }
            let Some(mut trace) = roots
                .iter()
                .copied()
                .filter_map(|root| {
                    let source = graph.function(target.function)?;
                    path_from_root_until(
                        artifact,
                        graph,
                        root,
                        caller,
                        TrustPath::new(graph, source),
                        is_trusted,
                        |_| false,
                    )
                })
                .min_by_key(|trace| trace.steps.len())
            else {
                continue;
            };
            append_call_trace(artifact, body.function, call, &mut trace);
            let candidate = MissingBodyBoundary {
                function: target.function,
                path: target.display_path.clone(),
                source_range: trace
                    .steps
                    .last()
                    .and_then(|step| step.source_range.clone()),
                trace,
            };
            match boundaries.entry(target.function) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(candidate);
                }
                std::collections::btree_map::Entry::Occupied(mut entry)
                    if missing_body_boundary_is_shorter(&candidate, entry.get()) =>
                {
                    entry.insert(candidate);
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
        }
    }
    boundaries
        .into_values()
        .map(MissingBodyBoundary::into_reason)
        .collect()
}

fn missing_body_boundary_is_shorter(
    candidate: &MissingBodyBoundary,
    current: &MissingBodyBoundary,
) -> bool {
    candidate
        .trace
        .steps
        .len()
        .cmp(&current.trace.steps.len())
        .then_with(|| candidate.path.cmp(&current.path))
        .is_lt()
}

fn trusted_boundary(
    function: StableFunctionId,
    domain: ReportEffect,
    namespaces: &DefinitionNamespaceIndex,
    config: &SniffTestConfig,
) -> bool {
    let candidates = namespaces.candidates(function);
    match domain {
        ReportEffect::Panic => config.panics.trusts_panic_boundary_candidates(candidates),
        ReportEffect::Safety => config.safety.trusts_safety_boundary_candidates(candidates),
    }
}

fn is_managed_function(
    function: StableFunctionId,
    local_stable_crate_id: u64,
    dependencies: &ArtifactAnalysisGraph,
) -> bool {
    let stable_crate_id = function.def_path_hash.stable_crate_id();
    stable_crate_id == local_stable_crate_id
        || dependencies
            .artifact_info_by_stable_crate_id(stable_crate_id)
            .is_some()
}

const fn call_reaches_function_body(kind: crate::artifact::CallKindFact) -> bool {
    matches!(
        kind,
        crate::artifact::CallKindFact::DirectCall
            | crate::artifact::CallKindFact::TailCall
            | crate::artifact::CallKindFact::IndirectCall
            | crate::artifact::CallKindFact::ConstBody
            | crate::artifact::CallKindFact::CoroutineBody
    )
}

fn completeness<O: Clone, S, T>(
    artifact: &ArtifactFacts,
    trace: &EffectTrace<O, S, T>,
    graph: &InvocationGraph,
    roots: &[FunctionId],
    options: TraceOptions,
    trace_kind: IncompleteTraceKind,
    additional: AdditionalCompleteness,
) -> DomainCompleteness {
    let mut reasons =
        trace_limit_reasons(artifact, trace, graph, roots, options, trace_kind, |_| true);
    reasons.extend(additional.reasons);
    DomainCompleteness {
        complete: reasons.is_empty(),
        reasons,
    }
}

fn trace_limit_reasons<O: Clone, S, T>(
    artifact: &ArtifactFacts,
    trace: &EffectTrace<O, S, T>,
    graph: &InvocationGraph,
    roots: &[FunctionId],
    options: TraceOptions,
    trace_kind: IncompleteTraceKind,
    includes_state: impl Fn(&S) -> bool,
) -> Vec<IncompleteReason> {
    [
        (
            effect_tracing::UnknownBoundaryKind::TraceDepth,
            TraceLimitValue::Depth(options.max_depth),
        ),
        (
            effect_tracing::UnknownBoundaryKind::TraceStateBudget,
            TraceLimitValue::StateBudget(options.state_budget),
        ),
    ]
    .into_iter()
    .filter_map(|(boundary_kind, limit)| {
        trace
            .unknown()
            .filter(|unknown| {
                unknown.boundary().kind() == boundary_kind && includes_state(unknown.state())
            })
            .filter_map(|unknown| {
                trace_frontier(
                    artifact,
                    graph,
                    trace,
                    roots,
                    unknown.node(),
                    unknown.function(),
                )
            })
            .min_by(|left, right| {
                left.trace
                    .steps
                    .len()
                    .cmp(&right.trace.steps.len())
                    .then_with(|| left.path.cmp(&right.path))
            })
            .map(|frontier| match limit {
                TraceLimitValue::Depth(max_depth) => IncompleteReason::TraceDepth {
                    max_depth,
                    trace_kind,
                    frontier,
                },
                TraceLimitValue::StateBudget(budget) => IncompleteReason::TraceStateBudget {
                    budget,
                    trace_kind,
                    frontier,
                },
            })
    })
    .collect()
}

#[derive(Clone, Copy)]
enum TraceLimitValue {
    Depth(usize),
    StateBudget(usize),
}

fn trace_frontier<O: Clone, S, T>(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    trace: &EffectTrace<O, S, T>,
    roots: &[FunctionId],
    node: Option<effect_tracing::TraceNodeId>,
    function: FunctionId,
) -> Option<TraceFrontier> {
    let mut path = roots
        .iter()
        .copied()
        .filter_map(|root| path_from_root(artifact, graph, root, function))
        .min_by_key(|path| path.steps.len())?;
    if let Some(node) = node {
        let mut traced = trace_path(artifact, graph, trace, node.index());
        path.steps.append(&mut traced.steps);
    }
    let function = graph.stable_function(function);
    Some(TraceFrontier {
        function,
        path: display_path(artifact, function),
        source_range: artifact
            .function_body(function)
            .and_then(|body| body.source_range.clone()),
        trace: path,
    })
}

fn trace_path<O: Clone, S, T>(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    trace: &EffectTrace<O, S, T>,
    mut node: usize,
) -> InterpretedTrace {
    let nodes = trace.nodes().collect::<Vec<_>>();
    let edges = trace.edges().collect::<Vec<_>>();
    let mut steps = Vec::new();
    let mut seen = BTreeSet::new();
    while seen.insert(node) {
        let Some(edge) = nodes[node]
            .predecessors()
            .min_by_key(|edge| edge.index())
            .map(|edge| edges[edge.index()])
        else {
            break;
        };
        if let PropagationEdge::Invocation(invocation) = edge.propagation() {
            let target = nodes[edge.from().index()].function();
            if let Some(source) = graph.source_edge(invocation, target) {
                let caller = graph.stable_function(nodes[edge.to().index()].function());
                let target = graph.stable_function(target);
                let mut call_trace = InterpretedTrace { steps: Vec::new() };
                append_call_trace(artifact, caller, source, &mut call_trace);
                if let Some(last) = call_trace.steps.last_mut() {
                    last.target = Some(target);
                }
                steps.extend(call_trace.steps);
            }
        } else if let PropagationEdge::TransparentBody(transparent) = edge.propagation() {
            let parent = graph.stable_function(nodes[edge.to().index()].function());
            let child = graph.stable_function(nodes[edge.from().index()].function());
            let source = graph.transparent_source(transparent);
            steps.push(InterpretedTraceStep {
                caller: parent,
                caller_path: display_path(artifact, parent),
                call: source.id,
                marker_call: None,
                kind: InterpretedTraceStepKind::Reachability(source.kind),
                source_range: source.source_range.clone(),
                target: Some(child),
                target_path: Some(display_path(artifact, child)),
            });
        } else if matches!(edge.propagation(), PropagationEdge::ContractHandoff) {
            // The contract at this boundary replaces the lower-level effect.
            // Keep the causal edge in the trace model, but present the
            // obligation from the point where its current carrier begins.
            break;
        }
        node = edge.from().index();
    }
    InterpretedTrace { steps }
}

fn append_call_trace(
    artifact: &ArtifactFacts,
    caller: StableFunctionId,
    edge: &crate::artifact::CallFact,
    trace: &mut InterpretedTrace,
) {
    let mut caller_path = display_path(artifact, caller);
    for frame in &edge.macro_expansions {
        let target_path = format!("macro {}", frame.display_path);
        trace.steps.push(InterpretedTraceStep {
            caller,
            caller_path,
            call: edge.id,
            marker_call: None,
            kind: InterpretedTraceStepKind::Reachability(
                crate::artifact::CallKindFact::MacroExpansion,
            ),
            source_range: frame
                .source_range
                .clone()
                .or_else(|| edge.source_range.clone()),
            target: None,
            target_path: Some(target_path.clone()),
        });
        caller_path = target_path;
    }
    trace.steps.push(InterpretedTraceStep {
        caller,
        caller_path,
        call: edge.id,
        marker_call: Some(edge.id),
        kind: InterpretedTraceStepKind::Reachability(edge.kind),
        source_range: if edge.macro_expansions.is_empty() {
            edge.source_range.clone()
        } else {
            edge.expanded_range
                .clone()
                .or_else(|| edge.source_range.clone())
        },
        target: edge.target.function_target().map(|target| target.function),
        target_path: edge
            .target
            .function_target()
            .map(|target| target.display_path.clone())
            .or_else(|| Some(boundary_description(edge))),
    });
}

fn append_effect_provenance(body: &FunctionFact, fact: &EffectFact, trace: &mut InterpretedTrace) {
    let mut caller_path = body.display_path.clone();
    for frame in &fact.macro_expansions {
        let target_path = format!("macro {}", frame.display_path);
        trace.steps.push(InterpretedTraceStep {
            caller: body.function,
            caller_path,
            call: crate::artifact::CallId::new(fact.id.index()),
            marker_call: None,
            kind: InterpretedTraceStepKind::Reachability(
                crate::artifact::CallKindFact::MacroExpansion,
            ),
            source_range: frame
                .source_range
                .clone()
                .or_else(|| fact.source_range.clone()),
            target: None,
            target_path: Some(target_path.clone()),
        });
        caller_path = target_path;
    }
}

fn effect_caller_path(body: &FunctionFact, fact: &EffectFact) -> String {
    fact.macro_expansions.last().map_or_else(
        || body.display_path.clone(),
        |frame| format!("macro {}", frame.display_path),
    )
}

fn append_effect_operation(body: &FunctionFact, fact: &EffectFact, trace: &mut InterpretedTrace) {
    trace.steps.push(InterpretedTraceStep {
        caller: body.function,
        caller_path: effect_caller_path(body, fact),
        call: crate::artifact::CallId::new(fact.id.index()),
        marker_call: None,
        kind: InterpretedTraceStepKind::EffectOperation,
        source_range: fact
            .expanded_range
            .clone()
            .or_else(|| fact.source_range.clone()),
        target: None,
        target_path: Some(fact.kind.as_str().replace('-', " ")),
    });
}

fn display_path(artifact: &ArtifactFacts, function: StableFunctionId) -> String {
    artifact
        .function_body(function)
        .map_or_else(|| format!("{function:?}"), |body| body.display_path.clone())
}

fn effect_fact(
    artifact: &ArtifactFacts,
    owner: StableFunctionId,
    effect: EffectId,
) -> Option<(&FunctionFact, &EffectFact)> {
    let body = artifact.function_body(owner)?;
    let fact = body.effects.iter().find(|fact| fact.id == effect)?;
    Some((body, fact))
}

fn boundary_description(edge: &crate::artifact::CallFact) -> String {
    if edge.kind == crate::artifact::CallKindFact::IndirectCall
        && edge.target.function_target().is_none()
    {
        if edge
            .invocation_effects
            .iter()
            .any(|source| source.effect == ReportEffect::Safety.key())
        {
            String::from("indirect call through an unsafe function pointer")
        } else {
            String::from("indirect call through a function pointer")
        }
    } else {
        match &edge.target {
            CallTargetFact::OpaqueBoundary { description, .. } => description.clone(),
            CallTargetFact::Function(target) => target.display_path.clone(),
        }
    }
}

fn interpreted_callee(target: &FunctionTargetFact) -> InterpretedCallee {
    InterpretedCallee {
        function: Some(target.function),
        path: target.display_path.clone(),
        requires_explicit_context: target.attributes.is_unsafe,
    }
}

#[cfg(test)]
mod tests {
    use super::ReportEffect;
    use super::{
        EffectEngine, Panic, Safety, annotation_probing_fact, append_call_trace,
        effect_marker_evidence, invocation_source_has_contract, obligation_marker_evidence,
        raw_call_marker_evidence, same_source_finding, trace_workspace,
    };
    use crate::annotations::AnnotationIndex;
    use crate::artifact::{
        AnnotationFact, AnnotationFactKind, AnnotationProbingFact, AnnotationRole,
        AnnotationSatisfactionFact, AnnotationTargetFact, ArtifactFacts, CallFact, CallId,
        CallKindFact, CallSiteId, CallTargetFact, CompilerAssertKind, ContractFact,
        EffectContractFact, EffectFact, EffectGroupId, EffectId, EffectKey, EffectKind,
        FunctionAttributesFact, FunctionContractsFact, FunctionFact, FunctionFactProvenance,
        FunctionId, FunctionTargetFact, IndirectCallKindFact, InvocationEffectFact,
        MacroExpansionFact, MarkerEvidenceState, MarkerId, OpaqueTargetFact, SafetyOpKind,
        SourceFileFact, SourceFileId, SourceRangeFact, StableDefPathHash, StableInstanceHash,
        UnverifiedMarkerProbeFact, UnverifiedMarkerProbeReason,
    };
    use crate::artifact_cache::{
        ArtifactAnalysisCache, ArtifactInfo, ArtifactScope, CacheExpectations, RustcArtifactId,
    };
    use crate::compiler::invocations::InvocationGraph;
    use crate::config::{MarkerProbing, PanicConfig, SniffTestConfig};
    use crate::effects::concrete::{probe_concrete_effect, probe_concrete_effect_for};
    use crate::effects::{EffectMetadata, EffectSpec, annotation_kind, effect};
    use crate::report_model::{
        DomainCompleteness, IncompleteReason, InterpretationRoot, InterpretedFinding,
        InterpretedFindingKind, InterpretedTrace, InterpretedTraceStep, InterpretedTraceStepKind,
        RootInterpretation,
    };
    use crate::report_roots::ReportRootKind;
    use crate::workspace::{ArtifactAnalysisGraph, ExternArtifactInput};

    struct Allocation;

    impl EffectSpec for Allocation {
        type Config = PanicConfig;

        const EFFECT_NAME: &'static str = "allocation";
        const OBLIGATION: &'static str = "Allocations";
        const JUSTIFICATION: &'static str = "ALLOCATION";

        fn register_passes(_: &mut crate::effects::visit::EffectPassRegistry) {}
    }

    fn stable_function(index: u64) -> FunctionId {
        let value = format!("{index:016x}{:016x}", index + 100);
        let hash = serde_json::from_str::<StableDefPathHash>(&format!("\"{value}\""))
            .expect("valid stable hash");
        FunctionId::generic(hash)
    }

    #[test]
    fn registered_effect_gets_default_concrete_reporting_without_an_adapter() {
        let root = stable_function(9_900);
        let artifact = ArtifactFacts::new(
            vec![body(
                root,
                "sample::allocates",
                Vec::new(),
                vec![EffectFact {
                    id: EffectId::new(0),
                    effect: EffectKey::new(Allocation::EFFECT_NAME),
                    effect_group: None,
                    source_range: None,
                    expanded_range: None,
                    macro_expansions: Vec::new(),
                    kind: EffectKind::new("heap-allocation"),
                }],
                Vec::new(),
                Vec::new(),
            )],
            Vec::new(),
        )
        .expect("custom effect artifact");
        let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
        let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
        let namespaces = artifact.definition_namespace_index();
        let allocation_config = PanicConfig::default();
        let allocation = effect::<Allocation>(&allocation_config);
        let concrete = probe_concrete_effect(
            &artifact,
            &graph,
            &annotations,
            &namespaces,
            allocation.as_ref(),
        )
        .expect("custom concrete effect");
        let config = SniffTestConfig::default();
        let obligations = super::ObligationTracker::probe(
            &graph,
            &annotations,
            config.analysis.effect_doc_matching,
            [super::ObligationEffectPolicy::new(
                EffectKey::new(Allocation::EFFECT_NAME),
                concrete.trusted_functions(),
                concrete.ignored_invocations(),
            )],
        );
        let tracked = super::TrackedEffect::new(
            &concrete,
            &obligations,
            EffectKey::new(Allocation::EFFECT_NAME),
        );
        let obligation_graph = graph.obligation_graph();
        let trace = EffectEngine::new(&obligation_graph).trace(&tracked);
        let findings = super::concrete_findings(
            &artifact,
            &graph,
            &annotations,
            &EffectMetadata::of::<Allocation>(),
            &concrete,
            &trace,
            graph.function(root).expect("root function"),
            AnnotationProbingFact::SourceCallsite,
        );

        assert!(matches!(
            findings.as_slice(),
            [InterpretedFinding {
                effect,
                kind: InterpretedFindingKind::Operation { operation },
                ..
            }] if effect.key.as_str() == "allocation" && operation.as_str() == "heap-allocation"
        ));
        assert!(matches!(
            findings[0].trace.steps.last(),
            Some(InterpretedTraceStep {
                kind: InterpretedTraceStepKind::EffectOperation,
                target_path: Some(target),
                ..
            }) if target == "heap allocation"
        ));
    }

    #[test]
    fn invocation_fact_controls_documentation_policy_for_a_registered_effect() {
        fn findings(requires_documented_obligation: bool) -> Vec<InterpretedFinding> {
            let root = stable_function(9_910);
            let callee = stable_function(9_911);
            let mut invocation = call(0, target(callee, "sample::allocator"));
            invocation.invocation_effects.push(InvocationEffectFact {
                effect: EffectKey::new(Allocation::EFFECT_NAME),
                kind: EffectKind::new("heap-allocation-call"),
                effect_group: invocation.effect_group,
                requires_documented_obligation,
            });
            let artifact = ArtifactFacts::new(
                vec![
                    body(
                        root,
                        "sample::root",
                        vec![invocation],
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    ),
                    body(
                        callee,
                        "sample::allocator",
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    ),
                ],
                Vec::new(),
            )
            .expect("custom invocation artifact");
            let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
            let annotations =
                AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
            let namespaces = artifact.definition_namespace_index();
            let allocation_config = PanicConfig::default();
            let allocation = effect::<Allocation>(&allocation_config);
            let concrete = probe_concrete_effect(
                &artifact,
                &graph,
                &annotations,
                &namespaces,
                allocation.as_ref(),
            )
            .expect("allocation effect");
            let config = SniffTestConfig::default();
            let obligations = super::ObligationTracker::probe(
                &graph,
                &annotations,
                config.analysis.effect_doc_matching,
                [super::ObligationEffectPolicy::new(
                    EffectKey::new(Allocation::EFFECT_NAME),
                    concrete.trusted_functions(),
                    concrete.ignored_invocations(),
                )],
            );
            let tracked = super::TrackedEffect::new(
                &concrete,
                &obligations,
                EffectKey::new(Allocation::EFFECT_NAME),
            );
            let obligation_graph = graph.obligation_graph();
            let trace = EffectEngine::new(&obligation_graph).trace(&tracked);
            super::concrete_findings(
                &artifact,
                &graph,
                &annotations,
                &EffectMetadata::of::<Allocation>(),
                &concrete,
                &trace,
                graph.function(root).expect("root function"),
                AnnotationProbingFact::SourceCallsite,
            )
        }

        assert!(matches!(
            findings(true).as_slice(),
            [InterpretedFinding {
                kind: InterpretedFindingKind::UndocumentedInvocation { operation },
                marker_evidence: None,
                ..
            }] if operation.as_str() == "heap-allocation-call"
        ));
        assert!(matches!(
            findings(false).as_slice(),
            [InterpretedFinding {
                kind: InterpretedFindingKind::Invocation { operation },
                marker_evidence: Some(_),
                ..
            }] if operation.as_str() == "heap-allocation-call"
        ));
    }

    #[test]
    fn local_justification_does_not_hide_required_invocation_documentation() {
        let root = stable_function(9_920);
        let callee = stable_function(9_921);
        let mut invocation = call(0, target(callee, "sample::unsafe_callee"));
        mark_safety_invocation(&mut invocation);
        let artifact = ArtifactFacts::new(
            vec![
                body(
                    root,
                    "sample::root",
                    vec![invocation],
                    Vec::new(),
                    vec![shared_justification_marker(
                        0,
                        "local-safety-justification",
                        annotation_kind::<Safety>(AnnotationRole::Justification),
                        AnnotationTargetFact::Call(CallId::new(0)),
                    )],
                    Vec::new(),
                ),
                body(
                    callee,
                    "sample::unsafe_callee",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("justified unsafe invocation artifact");
        let reports = trace_workspace(
            &artifact,
            root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &[InterpretationRoot {
                function: root,
                path: String::from("sample::root"),
                kind: ReportRootKind::Concrete,
            }],
            &SniffTestConfig::default(),
        )
        .expect("effect report");

        assert!(
            reports[0].findings.iter().any(|finding| matches!(
                finding.kind,
                InterpretedFindingKind::UndocumentedInvocation { .. }
            )),
            "findings: {:#?}",
            reports[0].findings
        );
    }

    fn function_in_crate(stable_crate_id: u64, index: u64) -> FunctionId {
        let value = format!("{stable_crate_id:016x}{index:016x}");
        let hash = serde_json::from_str::<StableDefPathHash>(&format!("\"{value}\""))
            .expect("valid stable hash");
        FunctionId::generic(hash)
    }

    fn exact_function(definition: FunctionId, index: u64) -> FunctionId {
        let value = format!("{index:016x}{:016x}", index + 200);
        let instance = serde_json::from_str::<StableInstanceHash>(&format!("\"{value}\""))
            .expect("valid stable instance hash");
        FunctionId::exact(definition.def_path_hash, instance)
    }

    fn source_finding_with_trace_call(caller: FunctionId, call: u32) -> InterpretedFinding {
        InterpretedFinding {
            effect: EffectMetadata::of::<Panic>(),
            kind: InterpretedFindingKind::Invocation {
                operation: EffectKind::new("configured-invocation"),
            },
            function: stable_function(90),
            function_path: String::from("sample::panic_source"),
            callee: None,
            source_range: None,
            contract_source_range: None,
            marker_evidence: None,
            trace: InterpretedTrace {
                steps: vec![InterpretedTraceStep {
                    caller,
                    caller_path: String::from("sample::caller"),
                    call: CallId::new(call),
                    marker_call: None,
                    kind: InterpretedTraceStepKind::Reachability(CallKindFact::DirectCall),
                    source_range: Some(SourceRangeFact {
                        file: SourceFileId::new("normalized-source"),
                        byte_start: 10,
                        byte_end: 20,
                    }),
                    target: Some(stable_function(90)),
                    target_path: Some(String::from("sample::panic_source")),
                }],
            },
            missing_requirements: Vec::new(),
            requirements: Vec::new(),
        }
    }

    #[test]
    fn source_finding_identity_distinguishes_calls_but_merges_instance_aliases() {
        let generic_caller = stable_function(91);
        let first = source_finding_with_trace_call(generic_caller, 1);
        let second = source_finding_with_trace_call(generic_caller, 2);
        assert!(
            !same_source_finding(&first, &second),
            "two calls in one body remain distinct even when their ranges normalize identically"
        );

        let first_instance = exact_function(generic_caller, 92);
        let second_instance = exact_function(generic_caller, 93);
        let first = source_finding_with_trace_call(first_instance, 1);
        let second = source_finding_with_trace_call(second_instance, 2);
        assert!(
            same_source_finding(&first, &second),
            "the same source call projected through two instances remains one finding"
        );
    }

    fn attributes(path: &str) -> FunctionAttributesFact {
        FunctionAttributesFact {
            is_unsafe: false,
            is_exported: true,
            has_rust_body: true,
            is_foreign: false,
            namespace_candidates: vec![path.to_owned()],
        }
    }

    fn target(function: FunctionId, path: &str) -> CallTargetFact {
        CallTargetFact::Function(FunctionTargetFact {
            function,
            display_path: path.to_owned(),
            attributes: attributes(path),
            contracts: FunctionContractsFact::default(),
        })
    }

    fn bodyless_declaration(
        function: FunctionId,
        path: &str,
        contracts: FunctionContractsFact,
    ) -> CallTargetFact {
        let mut declaration_attributes = attributes(path);
        declaration_attributes.has_rust_body = false;
        CallTargetFact::OpaqueBoundary {
            description: format!("unresolved implementation of `{path}`"),
            target: Some(OpaqueTargetFact::Trait(FunctionTargetFact {
                function,
                display_path: path.to_owned(),
                attributes: declaration_attributes,
                contracts,
            })),
        }
    }

    fn whole_contract() -> ContractFact {
        ContractFact {
            source_range: None,
            requirements: Vec::new(),
        }
    }

    fn effect_contracts(
        panic: Option<ContractFact>,
        safety: Option<ContractFact>,
    ) -> FunctionContractsFact {
        let mut effects = Vec::new();
        if let Some(contract) = panic {
            effects.push(EffectContractFact {
                effect: ReportEffect::Panic.key(),
                contract,
            });
        }
        if let Some(contract) = safety {
            effects.push(EffectContractFact {
                effect: ReportEffect::Safety.key(),
                contract,
            });
        }
        FunctionContractsFact { effects }
    }

    fn call(id: u32, target: CallTargetFact) -> CallFact {
        CallFact {
            id: CallId::new(id),
            call_site: CallSiteId::new(0),
            kind: CallKindFact::DirectCall,
            effect_group: Some(EffectGroupId::new(0)),
            invocation_effects: Vec::new(),
            suppressed_by_compiler_context: false,
            source_range: None,
            expanded_range: None,
            macro_expansions: Vec::new(),
            callee_range: None,
            indirect_kind: None,
            declaration_target: None,
            target,
        }
    }

    fn mark_safety_invocation(call: &mut CallFact) {
        call.invocation_effects.push(InvocationEffectFact {
            effect: ReportEffect::Safety.key(),
            kind: EffectKind::new("unsafe-call"),
            effect_group: call.effect_group,
            requires_documented_obligation: true,
        });
    }

    fn mark_panic_invocation(call: &mut CallFact) {
        call.invocation_effects.push(InvocationEffectFact {
            effect: ReportEffect::Panic.key(),
            kind: EffectKind::new("configured-invocation"),
            effect_group: call.effect_group,
            requires_documented_obligation: false,
        });
    }

    fn indirect_call(id: u32, site: u32, target: CallTargetFact) -> CallFact {
        let mut call = call(id, target);
        call.call_site = CallSiteId::new(site);
        call.kind = CallKindFact::IndirectCall;
        call.indirect_kind = Some(IndirectCallKindFact::DynamicDispatch);
        call
    }

    fn targetless_call(id: u32, site: u32, description: &str) -> CallFact {
        let mut call = indirect_call(
            id,
            site,
            CallTargetFact::OpaqueBoundary {
                description: description.to_owned(),
                target: None,
            },
        );
        call.indirect_kind = Some(IndirectCallKindFact::FunctionPointer);
        call
    }

    fn trusted_declaration_config() -> SniffTestConfig {
        toml::from_str(
            r#"
[panics]
trusted-boundary-namespaces = ["trusted::**"]
[panics.lints]
unresolved-call-target = "warn"
[safety]
trusted-boundary-namespaces = ["trusted::**"]
[safety.lints]
unresolved-call-target = "warn"
"#,
        )
        .expect("trusted declaration configuration")
    }

    fn assert_trusted_surface_findings(reports: &[RootInterpretation]) {
        let findings = reports
            .iter()
            .flat_map(|report| &report.findings)
            .collect::<Vec<_>>();
        assert!(
            findings.iter().all(|finding| !matches!(
                finding.kind,
                InterpretedFindingKind::UnresolvedCallTarget { .. }
            )),
            "trusted declaration surfaces should suppress unresolved coverage: {findings:#?}",
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| {
                    finding.effect.justification == "PANIC"
                        && matches!(finding.kind, InterpretedFindingKind::DocumentedObligation)
                })
                .count(),
            2,
            "the declaration's panic contract must remain a ObligationTracker source",
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| {
                    finding.effect.justification == "SAFETY"
                        && matches!(finding.kind, InterpretedFindingKind::DocumentedObligation)
                })
                .count(),
            2,
            "the declaration's safety contract must remain a ObligationTracker source",
        );
    }

    fn marker(id: u32, kind: AnnotationFactKind, target: AnnotationTargetFact) -> AnnotationFact {
        AnnotationFact {
            id: MarkerId::new(id),
            identity: format!("marker-{id}"),
            kind,
            source_range: None,
            target,
            applicable_probing: vec![AnnotationProbingFact::SourceCallsite],
            satisfactions: Vec::new(),
            requirements: Vec::new(),
        }
    }

    fn shared_justification_marker(
        id: u32,
        identity: &str,
        kind: AnnotationFactKind,
        target: AnnotationTargetFact,
    ) -> AnnotationFact {
        let mut marker = marker(id, kind, target);
        marker.identity = identity.to_owned();
        marker
            .applicable_probing
            .push(AnnotationProbingFact::MacroDefinitionFirst);
        marker.satisfactions.push(AnnotationSatisfactionFact {
            requirement: None,
            reason: String::from("audited reason"),
            structural_path: None,
        });
        marker
    }

    fn unsafe_operation_with_provenance(id: u32, group: u32, macro_index: u64) -> EffectFact {
        EffectFact {
            id: EffectId::new(id),
            effect: EffectKey::new("safety"),
            effect_group: Some(EffectGroupId::new(group)),
            source_range: None,
            expanded_range: None,
            macro_expansions: ["outer", "inner"]
                .into_iter()
                .zip(0_u64..)
                .map(|(layer, offset)| MacroExpansionFact {
                    macro_def: stable_function(macro_index + offset).def_path_hash,
                    display_path: format!("sample::{layer}_unsafe_{id}"),
                    source_range: None,
                })
                .collect(),
            kind: EffectKind::new(SafetyOpKind::DerefRawPointer.effect_kind_name()),
        }
    }

    fn body(
        function: FunctionId,
        path: &str,
        calls: Vec<CallFact>,
        effects: Vec<EffectFact>,
        markers: Vec<AnnotationFact>,
        unverified_marker_probes: Vec<UnverifiedMarkerProbeFact>,
    ) -> FunctionFact {
        FunctionFact {
            function,
            provenance: FunctionFactProvenance::DefiningArtifact,
            display_path: path.to_owned(),
            attributes: attributes(path),
            contract_declaration: None,
            source_range: None,
            calls,
            effects,
            markers,
            unverified_marker_probes,
        }
    }

    fn loaded_dependency(stable_crate_id: u64, facts: ArtifactFacts) -> ArtifactAnalysisGraph {
        const TOOL_VERSION: &str = "report-test-tool";
        const RUSTC_VERSION: &str = "report-test-rustc";
        let directory = tempfile::tempdir().expect("dependency cache directory");
        let artifact_id = RustcArtifactId::new(stable_crate_id, format!("{stable_crate_id:032x}"));
        let cache = ArtifactAnalysisCache::new(
            TOOL_VERSION,
            RUSTC_VERSION,
            ArtifactInfo {
                id: artifact_id.clone(),
                crate_name: format!("dependency-{stable_crate_id}"),
                scope: ArtifactScope::Dependency,
            },
            Vec::new(),
            facts,
        )
        .expect("valid dependency cache");
        cache
            .write(directory.path())
            .expect("written dependency cache");
        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[ExternArtifactInput {
                name: format!("dependency_{stable_crate_id}"),
                artifact_id,
            }],
            &CacheExpectations {
                tool_version: TOOL_VERSION,
                rustc_version: RUSTC_VERSION,
            },
        );
        assert!(
            graph.is_complete(),
            "dependency graph: {:#?}",
            graph.failures().collect::<Vec<_>>()
        );
        graph
    }

    fn missing_body_targets(completeness: &DomainCompleteness) -> Vec<FunctionId> {
        completeness
            .reasons
            .iter()
            .filter_map(|reason| match reason {
                IncompleteReason::MissingBody { function, .. } => Some(*function),
                IncompleteReason::TraceDepth { .. } | IncompleteReason::TraceStateBudget { .. } => {
                    None
                }
            })
            .collect()
    }

    fn desugared_declaration_body(
        base: u64,
        first_path: &str,
        first_has_contract: bool,
        second_path: &str,
    ) -> FunctionFact {
        let first_contracts = if first_has_contract {
            effect_contracts(Some(whole_contract()), None)
        } else {
            FunctionContractsFact::default()
        };
        body(
            stable_function(base),
            &format!("sample::root_{base}"),
            vec![
                indirect_call(
                    0,
                    0,
                    bodyless_declaration(stable_function(base + 1), first_path, first_contracts),
                ),
                indirect_call(
                    1,
                    0,
                    bodyless_declaration(
                        stable_function(base + 2),
                        second_path,
                        FunctionContractsFact::default(),
                    ),
                ),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    fn unresolved_panic_count(reports: &[RootInterpretation], root: FunctionId) -> usize {
        reports
            .iter()
            .find(|report| report.root.function == root)
            .expect("root report")
            .findings
            .iter()
            .filter(|finding| {
                finding.effect.key == ReportEffect::Panic.key()
                    && matches!(
                        finding.kind,
                        InterpretedFindingKind::UnresolvedCallTarget { .. }
                    )
            })
            .count()
    }

    fn marker_evidence_fixture() -> (ArtifactFacts, InvocationGraph, FunctionId) {
        let owner = stable_function(0);
        let first_target = stable_function(1);
        let second_target = stable_function(2);
        let artifact = ArtifactFacts::new(
            vec![
                body(
                    owner,
                    "sample::owner",
                    vec![
                        call(0, target(first_target, "sample::first_target")),
                        call(1, target(second_target, "sample::second_target")),
                    ],
                    vec![
                        EffectFact {
                            id: EffectId::new(0),
                            effect: EffectKey::new("panic"),
                            effect_group: None,
                            source_range: None,
                            expanded_range: None,
                            macro_expansions: Vec::new(),
                            kind: EffectKind::new(
                                CompilerAssertKind::BoundsCheck.effect_kind_name(),
                            ),
                        },
                        EffectFact {
                            id: EffectId::new(1),
                            effect: EffectKey::new("safety"),
                            effect_group: Some(EffectGroupId::new(1)),
                            source_range: None,
                            expanded_range: None,
                            macro_expansions: Vec::new(),
                            kind: EffectKind::new(SafetyOpKind::DerefRawPointer.effect_kind_name()),
                        },
                    ],
                    vec![
                        marker(
                            0,
                            annotation_kind::<Panic>(AnnotationRole::Justification),
                            AnnotationTargetFact::Call(CallId::new(1)),
                        ),
                        marker(
                            1,
                            annotation_kind::<Panic>(AnnotationRole::Justification),
                            AnnotationTargetFact::Effect(EffectId::new(0)),
                        ),
                        marker(
                            2,
                            annotation_kind::<Safety>(AnnotationRole::Justification),
                            AnnotationTargetFact::Effect(EffectId::new(1)),
                        ),
                    ],
                    vec![UnverifiedMarkerProbeFact {
                        kind: annotation_kind::<Safety>(AnnotationRole::Justification),
                        target: AnnotationTargetFact::Call(CallId::new(0)),
                        probing: AnnotationProbingFact::SourceCallsite,
                        reason: UnverifiedMarkerProbeReason::SourceUnavailable,
                    }],
                ),
                body(
                    first_target,
                    "sample::first_target",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    second_target,
                    "sample::second_target",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("valid marker evidence fixture");
        let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
        (artifact, graph, owner)
    }

    #[test]
    fn active_marker_probing_maps_to_the_persisted_probe_mode() {
        assert_eq!(
            annotation_probing_fact(MarkerProbing::SourceCallsite),
            AnnotationProbingFact::SourceCallsite
        );
        assert_eq!(
            annotation_probing_fact(MarkerProbing::MacroDefinitionFirst),
            AnnotationProbingFact::MacroDefinitionFirst
        );
    }

    #[test]
    fn only_real_invocation_trace_steps_retain_the_marker_call() {
        let owner = stable_function(0);
        let invoked = stable_function(1);
        let mut edge = call(7, target(invoked, "sample::invoked"));
        edge.macro_expansions.push(MacroExpansionFact {
            macro_def: stable_function(2).def_path_hash,
            display_path: String::from("sample::wrapper"),
            source_range: None,
        });
        let artifact = ArtifactFacts::new(
            vec![
                body(
                    owner,
                    "sample::owner",
                    vec![edge.clone()],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    invoked,
                    "sample::invoked",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("valid trace fixture");
        let mut trace = crate::report_model::InterpretedTrace { steps: Vec::new() };

        append_call_trace(&artifact, owner, &edge, &mut trace);

        assert_eq!(trace.steps.len(), 2);
        assert_eq!(trace.steps[0].marker_call, None);
        assert_eq!(trace.steps[1].marker_call, Some(CallId::new(7)));
    }

    #[test]
    fn source_findings_project_marker_evidence_by_exact_effect_or_raw_call() {
        let (artifact, graph, owner) = marker_evidence_fixture();
        let invocation = graph
            .invocation_for_raw_call(owner, CallId::new(0))
            .expect("source invocation");
        assert_eq!(graph.invocation(invocation).raw_calls().len(), 2);

        assert_eq!(
            effect_marker_evidence(
                &artifact,
                owner,
                EffectId::new(0),
                annotation_kind::<Panic>(AnnotationRole::Justification),
                AnnotationProbingFact::SourceCallsite,
            ),
            MarkerEvidenceState::Present,
            "compiler assertions use panic evidence on their effect site"
        );
        assert_eq!(
            effect_marker_evidence(
                &artifact,
                owner,
                EffectId::new(1),
                annotation_kind::<Safety>(AnnotationRole::Justification),
                AnnotationProbingFact::SourceCallsite,
            ),
            MarkerEvidenceState::Present,
            "unsafe operations use safety evidence on their effect site"
        );
        assert_eq!(
            raw_call_marker_evidence(
                &artifact,
                &graph,
                invocation,
                CallId::new(0),
                annotation_kind::<Panic>(AnnotationRole::Justification),
                AnnotationProbingFact::SourceCallsite,
            ),
            MarkerEvidenceState::VerifiedAbsent,
            "a sibling marker must not become evidence for this raw call"
        );
        assert_eq!(
            raw_call_marker_evidence(
                &artifact,
                &graph,
                invocation,
                CallId::new(1),
                annotation_kind::<Panic>(AnnotationRole::Justification),
                AnnotationProbingFact::SourceCallsite,
            ),
            MarkerEvidenceState::Present,
            "the marker remains attached to its exact raw call"
        );
        assert_eq!(
            raw_call_marker_evidence(
                &artifact,
                &graph,
                invocation,
                CallId::new(0),
                annotation_kind::<Safety>(AnnotationRole::Justification),
                AnnotationProbingFact::SourceCallsite,
            ),
            MarkerEvidenceState::Unverified(UnverifiedMarkerProbeReason::SourceUnavailable),
            "unverified evidence remains attached to its exact raw call"
        );
        assert_eq!(
            effect_marker_evidence(
                &artifact,
                owner,
                EffectId::new(99),
                annotation_kind::<Panic>(AnnotationRole::Justification),
                AnnotationProbingFact::SourceCallsite,
            ),
            MarkerEvidenceState::Unverified(UnverifiedMarkerProbeReason::NoUsableSourceSpan),
            "a missing source lookup is never reported as verified absence"
        );
    }

    #[test]
    fn obligation_marker_evidence_uses_only_contract_carrying_raw_calls() {
        let (artifact, graph, owner) = marker_evidence_fixture();
        let invocation = graph
            .invocation_for_raw_call(owner, CallId::new(0))
            .expect("recorded source invocation");

        assert_eq!(
            obligation_marker_evidence(
                &artifact,
                &graph,
                Some(invocation),
                [CallId::new(0)],
                annotation_kind::<Panic>(AnnotationRole::Justification),
                AnnotationProbingFact::SourceCallsite,
            ),
            Some(MarkerEvidenceState::VerifiedAbsent),
            "a marker on a grouped sibling must not become source evidence"
        );
        assert_eq!(
            obligation_marker_evidence(
                &artifact,
                &graph,
                Some(invocation),
                [CallId::new(1)],
                annotation_kind::<Panic>(AnnotationRole::Justification),
                AnnotationProbingFact::SourceCallsite,
            ),
            Some(MarkerEvidenceState::Present),
            "the raw branch carrying the marker retains its evidence"
        );
        assert_eq!(
            obligation_marker_evidence(
                &artifact,
                &graph,
                Some(invocation),
                [CallId::new(0)],
                annotation_kind::<Safety>(AnnotationRole::Justification),
                AnnotationProbingFact::SourceCallsite,
            ),
            Some(MarkerEvidenceState::Unverified(
                UnverifiedMarkerProbeReason::SourceUnavailable
            ))
        );
        assert_eq!(
            obligation_marker_evidence(
                &artifact,
                &graph,
                None,
                [],
                annotation_kind::<Panic>(AnnotationRole::Justification),
                AnnotationProbingFact::SourceCallsite,
            ),
            None,
            "comment states without a source invocation carry no marker evidence"
        );
    }

    #[test]
    fn one_exact_projection_contract_does_not_suppress_its_sibling() {
        let generic_caller = stable_function(0);
        let first_caller = exact_function(generic_caller, 1);
        let second_caller = exact_function(generic_caller, 2);
        let first_target = stable_function(3);
        let second_target = stable_function(4);
        let range = SourceRangeFact {
            file: SourceFileId::new("source-1"),
            byte_start: 10,
            byte_end: 20,
        };
        let mut first_call = call(0, target(first_target, "sample::First::run"));
        mark_safety_invocation(&mut first_call);
        first_call.source_range = Some(range.clone());
        first_call.expanded_range = Some(range.clone());
        let mut second_call = call(0, target(second_target, "sample::Second::run"));
        mark_safety_invocation(&mut second_call);
        second_call.source_range = Some(range.clone());
        second_call.expanded_range = Some(range);
        let artifact = ArtifactFacts::new(
            vec![
                body(
                    first_caller,
                    "sample::wrapper::<First>",
                    vec![first_call],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    second_caller,
                    "sample::wrapper::<Second>",
                    vec![second_call],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    first_target,
                    "sample::First::run",
                    Vec::new(),
                    Vec::new(),
                    vec![marker(
                        0,
                        annotation_kind::<Safety>(AnnotationRole::Contract),
                        AnnotationTargetFact::Function(first_target),
                    )],
                    Vec::new(),
                ),
                body(
                    second_target,
                    "sample::Second::run",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ],
            vec![SourceFileFact {
                id: SourceFileId::new("source-1"),
                filename: String::from("src/lib.rs"),
                content_hash: String::from("sha256:0123456789abcdef"),
                byte_len: 100,
            }],
        )
        .expect("valid exact projection fixture");
        let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
        let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
        let first = graph
            .invocation_for_raw_call(first_caller, CallId::new(0))
            .expect("first invocation");
        let second = graph
            .invocation_for_raw_call(second_caller, CallId::new(0))
            .expect("second invocation");
        let config = SniffTestConfig::default();
        let namespaces = artifact.definition_namespace_index();
        let safety = probe_concrete_effect_for::<Safety>(
            &artifact,
            &graph,
            &annotations,
            &namespaces,
            &config.safety,
        )
        .expect("safety effect");

        assert!(invocation_source_has_contract(
            &graph,
            &annotations,
            &safety.invocation_sources(first)[0],
            &ReportEffect::Safety.key(),
        ));
        assert!(!invocation_source_has_contract(
            &graph,
            &annotations,
            &safety.invocation_sources(second)[0],
            &ReportEffect::Safety.key(),
        ));
    }

    #[test]
    fn grouped_panic_sink_uses_its_matched_declaration_branch() {
        let root = stable_function(10);
        let contracted = stable_function(11);
        let sink = stable_function(12);
        let mut sink_call = indirect_call(
            1,
            0,
            bodyless_declaration(sink, "sink::panic", FunctionContractsFact::default()),
        );
        mark_panic_invocation(&mut sink_call);
        sink_call.call_site = CallSiteId::new(0);
        let artifact = ArtifactFacts::new(
            vec![
                body(
                    root,
                    "sample::root",
                    vec![call(0, target(contracted, "sample::contracted")), sink_call],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    contracted,
                    "sample::contracted",
                    Vec::new(),
                    Vec::new(),
                    vec![marker(
                        0,
                        annotation_kind::<Panic>(AnnotationRole::Contract),
                        AnnotationTargetFact::Function(contracted),
                    )],
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("grouped panic sink artifact");
        let config = SniffTestConfig::default();

        let reports = trace_workspace(
            &artifact,
            root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &[InterpretationRoot {
                function: root,
                path: String::from("sample::root"),
                kind: ReportRootKind::Concrete,
            }],
            &config,
        )
        .expect("effect report");
        let sinks = reports[0]
            .findings
            .iter()
            .filter(|finding| {
                finding.effect.justification == "PANIC"
                    && matches!(finding.kind, InterpretedFindingKind::Invocation { .. })
            })
            .collect::<Vec<_>>();

        assert_eq!(sinks.len(), 1);
        assert_eq!(
            sinks[0].callee.as_ref().map(|callee| callee.path.as_str()),
            Some("sink::panic")
        );
    }

    #[test]
    fn grouped_unsafe_call_uses_its_actual_unsafe_branch() {
        let root = stable_function(20);
        let contracted_safe = stable_function(21);
        let mut unsafe_pointer = call(
            1,
            CallTargetFact::OpaqueBoundary {
                description: String::from("unresolved unsafe function pointer"),
                target: None,
            },
        );
        unsafe_pointer.call_site = CallSiteId::new(0);
        unsafe_pointer.kind = CallKindFact::IndirectCall;
        unsafe_pointer.indirect_kind = Some(IndirectCallKindFact::FunctionPointer);
        mark_safety_invocation(&mut unsafe_pointer);
        let artifact = ArtifactFacts::new(
            vec![
                body(
                    root,
                    "sample::root",
                    vec![
                        call(0, target(contracted_safe, "sample::contracted_safe")),
                        unsafe_pointer,
                    ],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    contracted_safe,
                    "sample::contracted_safe",
                    Vec::new(),
                    Vec::new(),
                    vec![marker(
                        0,
                        annotation_kind::<Safety>(AnnotationRole::Contract),
                        AnnotationTargetFact::Function(contracted_safe),
                    )],
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("grouped unsafe call artifact");
        let config = SniffTestConfig::from_manifest_str(
            "[safety.coverage]\nunresolved-call-target = \"warn\"",
        )
        .expect("unresolved safety coverage configuration");

        let reports = trace_workspace(
            &artifact,
            root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &[InterpretationRoot {
                function: root,
                path: String::from("sample::root"),
                kind: ReportRootKind::Concrete,
            }],
            &config,
        )
        .expect("effect report");
        let unsafe_calls = reports[0]
            .findings
            .iter()
            .filter(|finding| {
                finding.effect.justification == "SAFETY"
                    && matches!(finding.kind, InterpretedFindingKind::Invocation { .. })
            })
            .collect::<Vec<_>>();

        assert_eq!(unsafe_calls.len(), 1);
        assert_eq!(
            unsafe_calls[0]
                .callee
                .as_ref()
                .map(|target| target.path.as_str()),
            Some("unsafe function pointer")
        );
        assert_eq!(
            reports[0]
                .findings
                .iter()
                .filter(|finding| matches!(
                    finding.kind,
                    InterpretedFindingKind::UnresolvedCallTarget { .. }
                ) && finding.effect.key == ReportEffect::Safety.key())
                .count(),
            1,
            "the unsafe signature is a local SafetyEffect source, but it does not make the unknown implementation complete"
        );
    }

    #[test]
    fn grouped_panic_marker_ambiguity_uses_the_actual_sink_branch() {
        let root = stable_function(30);
        let nonsink = stable_function(31);
        let sink = stable_function(32);
        let mut sink_call = indirect_call(
            1,
            0,
            bodyless_declaration(sink, "sink::panic", FunctionContractsFact::default()),
        );
        mark_panic_invocation(&mut sink_call);
        sink_call.call_site = CallSiteId::new(0);
        let compiler_assert = EffectFact {
            id: EffectId::new(0),
            effect: EffectKey::new("panic"),
            effect_group: None,
            source_range: None,
            expanded_range: None,
            macro_expansions: vec![
                MacroExpansionFact {
                    macro_def: stable_function(33).def_path_hash,
                    display_path: String::from("sample::outer_assert"),
                    source_range: None,
                },
                MacroExpansionFact {
                    macro_def: stable_function(34).def_path_hash,
                    display_path: String::from("sample::inner_assert"),
                    source_range: None,
                },
            ],
            kind: EffectKind::new(CompilerAssertKind::BoundsCheck.effect_kind_name()),
        };
        let artifact = ArtifactFacts::new(
            vec![
                body(
                    root,
                    "sample::root",
                    vec![call(0, target(nonsink, "sample::nonsink")), sink_call],
                    vec![compiler_assert],
                    vec![
                        shared_justification_marker(
                            0,
                            "shared-panic-marker",
                            annotation_kind::<Panic>(AnnotationRole::Justification),
                            AnnotationTargetFact::Call(CallId::new(1)),
                        ),
                        shared_justification_marker(
                            1,
                            "shared-panic-marker",
                            annotation_kind::<Panic>(AnnotationRole::Justification),
                            AnnotationTargetFact::Effect(EffectId::new(0)),
                        ),
                    ],
                    Vec::new(),
                ),
                body(
                    nonsink,
                    "sample::nonsink",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("grouped panic marker artifact");
        let config = SniffTestConfig::default();

        let reports = trace_workspace(
            &artifact,
            root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &[InterpretationRoot {
                function: root,
                path: String::from("sample::root"),
                kind: ReportRootKind::Concrete,
            }],
            &config,
        )
        .expect("effect report");
        let ambiguity = reports[0]
            .findings
            .iter()
            .find(|finding| matches!(finding.kind, InterpretedFindingKind::AmbiguousMarker { .. }))
            .unwrap_or_else(|| panic!("ambiguous panic marker: {:#?}", reports[0].findings));
        assert!(matches!(
            ambiguity.kind,
            InterpretedFindingKind::AmbiguousMarker { effect_count: 2 }
        ));
        let source = ambiguity.trace.steps.last().expect("source trace step");

        assert_eq!(source.call, CallId::new(1));
        assert_eq!(source.target_path.as_deref(), Some("sink::panic"));
    }

    #[test]
    fn grouped_safety_marker_uses_actual_branch_group_and_source_trace() {
        let root = stable_function(40);
        let safe = stable_function(41);
        let unsafe_target = stable_function(42);
        let mut unsafe_call = call(1, target(unsafe_target, "sample::unsafe_target"));
        unsafe_call.call_site = CallSiteId::new(0);
        unsafe_call.effect_group = Some(EffectGroupId::new(1));
        mark_safety_invocation(&mut unsafe_call);
        let artifact = ArtifactFacts::new(
            vec![
                body(
                    root,
                    "sample::root",
                    vec![call(0, target(safe, "sample::safe")), unsafe_call],
                    vec![
                        unsafe_operation_with_provenance(0, 1, 43),
                        unsafe_operation_with_provenance(1, 2, 45),
                    ],
                    vec![
                        shared_justification_marker(
                            0,
                            "shared-safety-marker",
                            annotation_kind::<Safety>(AnnotationRole::Justification),
                            AnnotationTargetFact::Call(CallId::new(1)),
                        ),
                        shared_justification_marker(
                            1,
                            "shared-safety-marker",
                            annotation_kind::<Safety>(AnnotationRole::Justification),
                            AnnotationTargetFact::Effect(EffectId::new(0)),
                        ),
                        shared_justification_marker(
                            2,
                            "shared-safety-marker",
                            annotation_kind::<Safety>(AnnotationRole::Justification),
                            AnnotationTargetFact::Effect(EffectId::new(1)),
                        ),
                    ],
                    Vec::new(),
                ),
                body(
                    safe,
                    "sample::safe",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    unsafe_target,
                    "sample::unsafe_target",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("grouped safety marker artifact");

        let reports = trace_workspace(
            &artifact,
            root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &[InterpretationRoot {
                function: root,
                path: String::from("sample::root"),
                kind: ReportRootKind::Concrete,
            }],
            &SniffTestConfig::default(),
        )
        .expect("effect report");
        let ambiguity = reports[0]
            .findings
            .iter()
            .find(|finding| matches!(finding.kind, InterpretedFindingKind::AmbiguousMarker { .. }))
            .unwrap_or_else(|| panic!("ambiguous safety marker: {:#?}", reports[0].findings));
        assert!(matches!(
            ambiguity.kind,
            InterpretedFindingKind::AmbiguousMarker { effect_count: 2 }
        ));
        let source = ambiguity.trace.steps.last().expect("source trace step");

        assert_eq!(source.call, CallId::new(1));
        assert_eq!(source.target_path.as_deref(), Some("sample::unsafe_target"));
    }

    fn grouped_comment_claim_artifact(root: FunctionId, obligation: FunctionId) -> ArtifactFacts {
        let mut first_call = call(0, target(obligation, "sample::safe_obligation"));
        first_call.effect_group = Some(EffectGroupId::new(1));
        let mut second_call = call(1, target(obligation, "sample::safe_obligation"));
        second_call.effect_group = Some(EffectGroupId::new(1));
        let mut first_marker = shared_justification_marker(
            0,
            "shared-contract-marker",
            annotation_kind::<Safety>(AnnotationRole::Justification),
            AnnotationTargetFact::Call(CallId::new(0)),
        );
        first_marker.satisfactions[0].requirement = Some(String::from("initialized"));
        let mut second_marker = shared_justification_marker(
            1,
            "shared-contract-marker",
            annotation_kind::<Safety>(AnnotationRole::Justification),
            AnnotationTargetFact::Call(CallId::new(1)),
        );
        second_marker.satisfactions[0].requirement = Some(String::from("initialized"));
        let mut contract = marker(
            2,
            annotation_kind::<Safety>(AnnotationRole::Contract),
            AnnotationTargetFact::Function(obligation),
        );
        contract.requirements = vec![
            crate::artifact::ContractRequirementFact {
                name: String::from("initialized"),
                condition: String::from("state must be initialized"),
                structural_path: vec![0],
                source_range: None,
            },
            crate::artifact::ContractRequirementFact {
                name: String::from("exclusive"),
                condition: String::from("access must be exclusive"),
                structural_path: vec![1],
                source_range: None,
            },
        ];
        ArtifactFacts::new(
            vec![
                body(
                    root,
                    "sample::root",
                    vec![first_call, second_call],
                    Vec::new(),
                    vec![first_marker, second_marker],
                    Vec::new(),
                ),
                body(
                    obligation,
                    "sample::safe_obligation",
                    Vec::new(),
                    Vec::new(),
                    vec![contract],
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("grouped safety contract artifact")
    }

    #[test]
    fn grouped_comment_marker_claims_each_relevant_contract_branch() {
        let root = stable_function(47);
        let artifact = grouped_comment_claim_artifact(root, stable_function(48));

        let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
        let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
        let config = SniffTestConfig::default();
        let namespaces = artifact.definition_namespace_index();
        let panic = probe_concrete_effect_for::<Panic>(
            &artifact,
            &graph,
            &annotations,
            &namespaces,
            &config.panics,
        )
        .expect("panic effect");
        let safety = probe_concrete_effect_for::<Safety>(
            &artifact,
            &graph,
            &annotations,
            &namespaces,
            &config.safety,
        )
        .expect("safety effect");
        let comments = super::ObligationTracker::probe(
            &graph,
            &annotations,
            config.analysis.effect_doc_matching,
            [
                super::ObligationEffectPolicy::new(
                    super::ReportEffect::Panic.key(),
                    panic.trusted_functions(),
                    panic.ignored_invocations(),
                ),
                super::ObligationEffectPolicy::new(
                    super::ReportEffect::Safety.key(),
                    safety.trusted_functions(),
                    safety.ignored_invocations(),
                ),
            ],
        );
        let panic_key = super::ReportEffect::Panic.key();
        let safety_key = super::ReportEffect::Safety.key();
        let concrete_effects = std::collections::BTreeMap::from([
            (panic_key.clone(), panic),
            (safety_key.clone(), safety),
        ]);
        let tracked_effects = concrete_effects
            .iter()
            .map(|(effect, concrete)| {
                (
                    effect.clone(),
                    super::TrackedEffect::new(concrete, &comments, effect.clone()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let obligation_graph = graph.obligation_graph();
        let engine = EffectEngine::new(&obligation_graph);
        let traces = tracked_effects
            .iter()
            .map(|(effect, tracked)| (effect.clone(), engine.trace(tracked)))
            .collect::<std::collections::BTreeMap<_, super::ConcreteTrace>>();
        let tracked_safety = tracked_effects.get(&safety_key).expect("tracked safety");
        let safety_trace = traces.get(&safety_key).expect("safety trace");
        let uses = tracked_safety.obligation_marker_uses(&safety_trace);
        assert_eq!(
            comments.contract_count(&super::ReportEffect::Safety.key()),
            1
        );
        assert_eq!(uses.len(), 1, "marker uses: {uses:#?}");
        assert_eq!(
            uses[0].source_calls().collect::<Vec<_>>(),
            vec![CallId::new(0), CallId::new(1)],
        );
        assert_eq!(
            super::obligation_effect_groups(
                &graph,
                concrete_effects.get(&safety_key),
                &safety_key,
                uses[0].source_invocation(),
                uses[0].source_calls(),
            ),
            vec![
                super::SourceEffectGroup::Invocation(uses[0].source_invocation(), CallId::new(0),),
                super::SourceEffectGroup::Invocation(uses[0].source_invocation(), CallId::new(1),),
            ],
        );
        let claims = super::collect_marker_claims(
            &artifact,
            &graph,
            &concrete_effects,
            &traces,
            &tracked_effects,
        );
        assert_eq!(
            claims.values().next().map(std::collections::BTreeMap::len),
            Some(2),
            "claims: {claims:#?}",
        );
        let root_function = graph.function(root).expect("root function");
        let ambiguities = super::marker_ambiguities(
            &artifact,
            &graph,
            &annotations,
            &concrete_effects,
            &traces,
            &tracked_effects,
            &claims,
            &[EffectMetadata::of::<Safety>()],
            root_function,
        );

        assert!(matches!(
            ambiguities.as_slice(),
            [InterpretedFinding {
                kind: InterpretedFindingKind::AmbiguousMarker { effect_count: 2 },
                ..
            }]
        ));
    }

    fn trusted_safety_marker_artifact(root: FunctionId, trusted: FunctionId) -> ArtifactFacts {
        let mut trusted_body = body(
            trusted,
            "trusted::api",
            Vec::new(),
            vec![
                unsafe_operation_with_provenance(0, 1, 52),
                unsafe_operation_with_provenance(1, 2, 54),
            ],
            vec![
                shared_justification_marker(
                    0,
                    "trusted-shared-safety-marker",
                    annotation_kind::<Safety>(AnnotationRole::Justification),
                    AnnotationTargetFact::Effect(EffectId::new(0)),
                ),
                shared_justification_marker(
                    1,
                    "trusted-shared-safety-marker",
                    annotation_kind::<Safety>(AnnotationRole::Justification),
                    AnnotationTargetFact::Effect(EffectId::new(1)),
                ),
                marker(
                    2,
                    annotation_kind::<Safety>(AnnotationRole::Contract),
                    AnnotationTargetFact::Function(trusted),
                ),
            ],
            Vec::new(),
        );
        trusted_body
            .attributes
            .namespace_candidates
            .push(String::from("trusted"));
        ArtifactFacts::new(
            vec![
                body(
                    root,
                    "sample::root",
                    vec![call(0, target(trusted, "trusted::api"))],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                trusted_body,
            ],
            Vec::new(),
        )
        .expect("trusted safety marker artifact")
    }

    #[test]
    fn trusted_safety_boundary_hides_internal_marker_ambiguity_but_exports_its_contract() {
        let root = stable_function(50);
        let trusted = stable_function(51);
        let artifact = trusted_safety_marker_artifact(root, trusted);
        let roots = [InterpretationRoot {
            function: root,
            path: String::from("sample::root"),
            kind: ReportRootKind::Concrete,
        }];
        let untrusted_config =
            SniffTestConfig::from_manifest_str("[analysis]\nmarker-probing = \"source-callsite\"")
                .expect("source-callsite marker configuration");
        let untrusted_reports = trace_workspace(
            &artifact,
            root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &roots,
            &untrusted_config,
        )
        .expect("untrusted effect report");
        assert!(untrusted_reports[0].findings.iter().any(|finding| {
            matches!(
                finding.kind,
                InterpretedFindingKind::AmbiguousMarker { effect_count: 2 }
            )
        }));

        let config = SniffTestConfig::from_manifest_str(
            r#"
                [analysis]
                marker-probing = "source-callsite"

                [safety]
                trusted-boundary-namespaces = ["trusted"]
            "#,
        )
        .expect("trusted safety boundary configuration");

        let reports = trace_workspace(
            &artifact,
            root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &roots,
            &config,
        )
        .expect("effect report");
        let findings = &reports[0].findings;

        assert!(
            findings.iter().all(|finding| !matches!(
                finding.kind,
                InterpretedFindingKind::AmbiguousMarker { .. }
            )),
            "trusted implementation details must not project marker ambiguity: {findings:#?}",
        );
        let surface = findings
            .iter()
            .filter(|finding| {
                finding.effect.justification == "SAFETY"
                    && matches!(finding.kind, InterpretedFindingKind::DocumentedObligation)
                    && finding
                        .callee
                        .as_ref()
                        .is_some_and(|target| target.path == "trusted::api")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            surface.len(),
            1,
            "the trusted API's own # Safety contract must remain visible: {findings:#?}",
        );
    }

    #[test]
    fn managed_callback_missing_body_crosses_trusted_boundary() {
        let root = function_in_crate(1, 1);
        let callback = function_in_crate(1, 2);
        let consumer = function_in_crate(2, 1);
        let declaration = function_in_crate(2, 2);
        let mut callback_call = call(0, target(callback, "app::callback"));
        let CallTargetFact::Function(surface) = target(declaration, "trusted::Callback::call")
        else {
            unreachable!();
        };
        callback_call.declaration_target = Some(surface);
        let local = ArtifactFacts::new(
            vec![body(
                root,
                "app::root",
                vec![call(0, target(consumer, "trusted::consume"))],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )],
            Vec::new(),
        )
        .expect("local callback fixture");
        let dependencies = loaded_dependency(
            2,
            ArtifactFacts::new(
                vec![body(
                    consumer,
                    "trusted::consume",
                    vec![callback_call],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )],
                Vec::new(),
            )
            .expect("trusted consumer fixture"),
        );
        let reports = trace_workspace(
            &local,
            1,
            &dependencies,
            &[InterpretationRoot {
                function: root,
                path: String::from("app::root"),
                kind: ReportRootKind::Concrete,
            }],
            &trusted_declaration_config(),
        )
        .expect("callback missing-body report");
        assert_eq!(
            missing_body_targets(&reports[0].completeness.panic),
            [callback]
        );
        assert_eq!(
            missing_body_targets(&reports[0].completeness.safety),
            [callback]
        );
    }

    #[test]
    fn managed_missing_bodies_are_report_root_scoped() {
        let local_stable_crate_id = 1;
        let dependency_stable_crate_id = 2;
        let root = function_in_crate(local_stable_crate_id, 1);
        let unrelated_root = function_in_crate(local_stable_crate_id, 2);
        let local_missing = function_in_crate(local_stable_crate_id, 3);
        let dependency_missing = function_in_crate(dependency_stable_crate_id, 1);
        let unmanaged_missing = function_in_crate(3, 1);
        let mut local_call = call(0, target(local_missing, "app::local_missing"));
        local_call.call_site = CallSiteId::new(0);
        let mut dependency_call = call(1, target(dependency_missing, "dependency::missing"));
        dependency_call.call_site = CallSiteId::new(1);
        let mut unmanaged_call = call(2, target(unmanaged_missing, "core::unmanaged"));
        unmanaged_call.call_site = CallSiteId::new(2);
        let local = ArtifactFacts::new(
            vec![
                body(
                    root,
                    "app::root",
                    vec![local_call, dependency_call, unmanaged_call],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    unrelated_root,
                    "app::unrelated_root",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("managed missing-body fixture");
        let dependencies = loaded_dependency(
            dependency_stable_crate_id,
            ArtifactFacts::new(Vec::new(), Vec::new()).expect("empty dependency facts"),
        );

        let reports = trace_workspace(
            &local,
            local_stable_crate_id,
            &dependencies,
            &[
                InterpretationRoot {
                    function: root,
                    path: String::from("app::root"),
                    kind: ReportRootKind::Concrete,
                },
                InterpretationRoot {
                    function: unrelated_root,
                    path: String::from("app::unrelated_root"),
                    kind: ReportRootKind::Concrete,
                },
            ],
            &SniffTestConfig::default(),
        )
        .expect("effect report");

        let root_report = &reports[0];
        assert_eq!(
            missing_body_targets(&root_report.completeness.panic),
            [local_missing, dependency_missing]
        );
        assert_eq!(
            missing_body_targets(&root_report.completeness.safety),
            [local_missing, dependency_missing]
        );
        for reason in root_report
            .completeness
            .panic
            .reasons
            .iter()
            .chain(&root_report.completeness.safety.reasons)
        {
            let IncompleteReason::MissingBody {
                function, trace, ..
            } = reason
            else {
                continue;
            };
            assert_eq!(
                trace.steps.last().and_then(|step| step.target),
                Some(*function)
            );
        }
        assert!(reports[1].completeness.panic.complete);
        assert!(reports[1].completeness.safety.complete);
    }

    #[test]
    fn consumer_overlay_is_complete_for_panic_but_not_definition_site_safety() {
        let local_stable_crate_id = 1;
        let dependency_stable_crate_id = 2;
        let root = function_in_crate(local_stable_crate_id, 1);
        let overlay_definition = function_in_crate(dependency_stable_crate_id, 1);
        let overlay = exact_function(overlay_definition, 10);
        let defining_generic = function_in_crate(dependency_stable_crate_id, 2);
        let exact_with_fallback = exact_function(defining_generic, 11);
        let mut overlay_body = body(
            overlay,
            "dependency::overlay::<App>",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        overlay_body.provenance = FunctionFactProvenance::ConsumerInstantiation {
            consumer_stable_crate_id: local_stable_crate_id,
        };
        let local = ArtifactFacts::new(
            vec![
                body(
                    root,
                    "app::root",
                    vec![
                        call(0, target(overlay, "dependency::overlay::<App>")),
                        call(1, target(exact_with_fallback, "dependency::generic::<App>")),
                    ],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                overlay_body,
            ],
            Vec::new(),
        )
        .expect("consumer overlay fixture");
        let dependencies = loaded_dependency(
            dependency_stable_crate_id,
            ArtifactFacts::new(
                vec![body(
                    defining_generic,
                    "dependency::generic",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )],
                Vec::new(),
            )
            .expect("defining dependency facts"),
        );

        let reports = trace_workspace(
            &local,
            local_stable_crate_id,
            &dependencies,
            &[InterpretationRoot {
                function: root,
                path: String::from("app::root"),
                kind: ReportRootKind::Concrete,
            }],
            &SniffTestConfig::default(),
        )
        .expect("effect report");

        assert!(reports[0].completeness.panic.complete);
        assert_eq!(
            missing_body_targets(&reports[0].completeness.safety),
            [overlay]
        );
    }

    #[test]
    fn trusted_boundary_filters_each_concrete_target_in_its_own_domain() {
        let local_stable_crate_id = 1;
        let dependency_stable_crate_id = 2;
        let root = function_in_crate(local_stable_crate_id, 1);
        let trusted_missing = function_in_crate(dependency_stable_crate_id, 1);
        let ignored_contracted_missing = function_in_crate(dependency_stable_crate_id, 2);
        let present = function_in_crate(dependency_stable_crate_id, 3);
        let mut contracted_target =
            match target(ignored_contracted_missing, "ignored::contracted_missing") {
                CallTargetFact::Function(target) => target,
                CallTargetFact::OpaqueBoundary { .. } => unreachable!("concrete target helper"),
            };
        contracted_target.contracts =
            effect_contracts(Some(whole_contract()), Some(whole_contract()));
        let local = ArtifactFacts::new(
            vec![body(
                root,
                "app::root",
                vec![
                    call(0, target(trusted_missing, "visible::trusted_missing")),
                    call(1, CallTargetFact::Function(contracted_target)),
                    call(2, target(present, "dependency::present")),
                ],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )],
            Vec::new(),
        )
        .expect("multi-target missing-body fixture");
        let dependencies = loaded_dependency(
            dependency_stable_crate_id,
            ArtifactFacts::new(
                vec![body(
                    present,
                    "dependency::present",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )],
                Vec::new(),
            )
            .expect("dependency with one available target"),
        );
        let config = SniffTestConfig::from_manifest_str(
            r#"
                [panics]
                trusted-boundary-namespaces = ["visible::**"]
                ignored-namespaces = ["ignored::**"]
                [safety]
                ignored-namespaces = ["ignored::**"]
            "#,
        )
        .expect("domain-local trusted-boundary config");

        let reports = trace_workspace(
            &local,
            local_stable_crate_id,
            &dependencies,
            &[InterpretationRoot {
                function: root,
                path: String::from("app::root"),
                kind: ReportRootKind::Concrete,
            }],
            &config,
        )
        .expect("effect report");

        assert_eq!(
            missing_body_targets(&reports[0].completeness.panic),
            [ignored_contracted_missing],
            "ignored namespaces and ordinary contracts are not completeness boundaries"
        );
        assert_eq!(
            missing_body_targets(&reports[0].completeness.safety),
            [trusted_missing, ignored_contracted_missing]
        );
    }

    #[test]
    fn report_root_does_not_owe_or_duplicate_effective_trait_contracts() {
        let implementation = stable_function(0);
        let declaration = stable_function(1);
        let mut implementation_body = body(
            implementation,
            "sample::Impl::run",
            Vec::new(),
            vec![EffectFact {
                id: EffectId::new(0),
                effect: EffectKey::new("panic"),
                effect_group: None,
                source_range: None,
                expanded_range: None,
                macro_expansions: Vec::new(),
                kind: EffectKind::new(CompilerAssertKind::BoundsCheck.effect_kind_name()),
            }],
            Vec::new(),
            Vec::new(),
        );
        implementation_body.attributes.is_unsafe = true;
        implementation_body.contract_declaration = Some(FunctionTargetFact {
            function: declaration,
            display_path: String::from("sample::Trait::run"),
            attributes: attributes("sample::Trait::run"),
            contracts: FunctionContractsFact::default(),
        });
        let artifact = ArtifactFacts::new(
            vec![
                implementation_body,
                body(
                    declaration,
                    "sample::Trait::run",
                    Vec::new(),
                    Vec::new(),
                    vec![
                        marker(
                            0,
                            annotation_kind::<Panic>(AnnotationRole::Contract),
                            AnnotationTargetFact::Function(declaration),
                        ),
                        marker(
                            1,
                            annotation_kind::<Safety>(AnnotationRole::Contract),
                            AnnotationTargetFact::Function(declaration),
                        ),
                    ],
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("effective trait contract artifact");
        let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
        let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
        let implementation_graph = graph.function(implementation).expect("implementation");
        assert_eq!(
            annotations
                .effective_contract(&graph, implementation_graph, &ReportEffect::Panic.key())
                .expect("effective panic contract")
                .owner(),
            declaration,
        );
        assert_eq!(
            annotations
                .effective_contract(&graph, implementation_graph, &ReportEffect::Safety.key())
                .expect("effective safety contract")
                .owner(),
            declaration,
        );
        let mut config = SniffTestConfig::default();
        config.analysis.marker_probing = MarkerProbing::SourceCallsite;

        let reports = trace_workspace(
            &artifact,
            implementation.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &[InterpretationRoot {
                function: implementation,
                path: String::from("sample::Impl::run"),
                kind: ReportRootKind::Concrete,
            }],
            &config,
        )
        .expect("effect report");

        assert!(
            reports[0].findings.is_empty(),
            "unexpected findings: {:#?}",
            reports[0].findings,
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one declaration-coverage matrix compares mixed contract, trust, ignore, sink, and duplicate raw-edge cases"
    )]
    fn every_desugared_declaration_requires_contract_or_boundary_coverage() {
        let cases = [
            (
                20,
                "other::Iterator::next",
                true,
                "other::IntoIterator::into_iter",
                1,
            ),
            (
                30,
                "other::Iterator::next",
                true,
                "trusted::IntoIterator::into_iter",
                0,
            ),
            (
                40,
                "other::Iterator::next",
                true,
                "ignored::IntoIterator::into_iter",
                0,
            ),
            (
                50,
                "other::Iterator::next",
                true,
                "sink::IntoIterator::into_iter",
                1,
            ),
            // A representative ignored edge must not hide its uncovered
            // sibling merely because rustc grouped them at one source site.
            (60, "ignored::Iterator::next", false, "other::uncovered", 1),
            // Each independently uncovered declaration needs its own action;
            // fixing one must not reveal a hidden sibling only on the next run.
            (70, "other::first", false, "other::second", 2),
        ];
        let mut bodies = cases
            .iter()
            .map(|(base, first_path, first_has_contract, second_path, _)| {
                desugared_declaration_body(*base, first_path, *first_has_contract, second_path)
            })
            .collect::<Vec<_>>();
        let repeated_body = bodies
            .iter_mut()
            .find(|body| body.function == stable_function(70))
            .expect("two-uncovered-declaration body");
        let mut repeated_first = repeated_body.calls[0].clone();
        repeated_first.id = CallId::new(2);
        repeated_body.calls.push(repeated_first);
        let artifact =
            ArtifactFacts::new(bodies, Vec::new()).expect("desugared declaration artifact");
        let config = SniffTestConfig::from_manifest_str(
            r#"
                [panics]
                trusted-boundary-namespaces = ["trusted::**"]
                ignored-namespaces = ["ignored::**"]
                [panics.coverage]
                unresolved-call-target = "warn"
            "#,
        )
        .expect("declaration coverage configuration");
        let roots = cases
            .iter()
            .map(|(base, _, _, _, _)| InterpretationRoot {
                function: stable_function(*base),
                path: format!("sample::root_{base}"),
                kind: ReportRootKind::Concrete,
            })
            .collect::<Vec<_>>();

        let reports = trace_workspace(
            &artifact,
            roots[0].function.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &roots,
            &config,
        )
        .expect("effect report");

        for (base, _, _, second_path, expected) in cases {
            assert_eq!(
                unresolved_panic_count(&reports, stable_function(base)),
                expected,
                "unexpected declaration coverage for {second_path}"
            );
        }

        let uncovered = reports
            .iter()
            .find(|report| report.root.function == stable_function(20))
            .expect("partially covered root report")
            .findings
            .iter()
            .find(|finding| {
                matches!(
                    finding.kind,
                    InterpretedFindingKind::UnresolvedCallTarget { .. }
                )
            })
            .expect("uncovered second declaration");
        assert_eq!(
            uncovered.callee.as_ref().map(|callee| callee.path.as_str()),
            Some("other::IntoIterator::into_iter")
        );
        assert_eq!(
            uncovered
                .trace
                .steps
                .last()
                .and_then(|step| step.target_path.as_deref()),
            Some("other::IntoIterator::into_iter")
        );
    }

    #[test]
    fn covered_declaration_does_not_hide_targetless_unknown_sibling() {
        let root = stable_function(70);
        let declaration = stable_function(71);
        let contracts = effect_contracts(Some(whole_contract()), Some(whole_contract()));
        let artifact = ArtifactFacts::new(
            vec![body(
                root,
                "sample::root_70",
                vec![
                    indirect_call(
                        0,
                        0,
                        bodyless_declaration(declaration, "other::covered", contracts),
                    ),
                    targetless_call(1, 0, "unresolved targetless sibling"),
                ],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )],
            Vec::new(),
        )
        .expect("covered declaration with targetless sibling artifact");
        let config = SniffTestConfig::from_manifest_str(
            r#"
                [panics.coverage]
                unresolved-call-target = "warn"
                [safety.lints]
                unresolved-call-target = "warn"
            "#,
        )
        .expect("unresolved coverage configuration");

        let reports = trace_workspace(
            &artifact,
            root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &[InterpretationRoot {
                function: root,
                path: String::from("sample::root_70"),
                kind: ReportRootKind::Concrete,
            }],
            &config,
        )
        .expect("effect report");
        let unresolved = reports[0]
            .findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.kind,
                    InterpretedFindingKind::UnresolvedCallTarget { .. }
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(unresolved.len(), 2, "one finding per effect domain");
        for finding in unresolved {
            assert_eq!(finding.callee, None);
            assert_eq!(
                finding.trace.steps.last().map(|step| step.call),
                Some(CallId::new(1))
            );
            assert_eq!(
                finding
                    .trace
                    .steps
                    .last()
                    .and_then(|step| step.target_path.as_deref()),
                Some("indirect call through a function pointer")
            );
        }
    }

    #[test]
    fn independent_declaration_surface_propagates_contracts_and_covers_targetless_call() {
        let root = stable_function(80);
        let declaration = stable_function(81);
        let mut declaration_attributes = attributes("sample::Callable::call");
        declaration_attributes.has_rust_body = false;
        let mut invocation = targetless_call(0, 0, "unresolved dynamic dispatch");
        invocation.declaration_target = Some(FunctionTargetFact {
            function: declaration,
            display_path: String::from("sample::Callable::call"),
            attributes: declaration_attributes,
            contracts: effect_contracts(Some(whole_contract()), Some(whole_contract())),
        });
        let artifact = ArtifactFacts::new(
            vec![body(
                root,
                "sample::root_80",
                vec![invocation],
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )],
            Vec::new(),
        )
        .expect("targetless call with independent declaration surface");
        let config = SniffTestConfig::from_manifest_str(
            r#"
                [panics.lints]
                unresolved-call-target = "warn"
                [safety.lints]
                unresolved-call-target = "warn"
            "#,
        )
        .expect("unresolved coverage configuration");

        let reports = trace_workspace(
            &artifact,
            root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &[InterpretationRoot {
                function: root,
                path: String::from("sample::root_80"),
                kind: ReportRootKind::Concrete,
            }],
            &config,
        )
        .expect("effect report");
        let findings = &reports[0].findings;

        assert!(findings.iter().all(|finding| !matches!(
            finding.kind,
            InterpretedFindingKind::UnresolvedCallTarget { .. }
        )));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| {
                    finding.effect.justification == "PANIC"
                        && matches!(finding.kind, InterpretedFindingKind::DocumentedObligation)
                })
                .count(),
            1,
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| {
                    finding.effect.justification == "SAFETY"
                        && matches!(finding.kind, InterpretedFindingKind::DocumentedObligation)
                })
                .count(),
            1,
        );
    }

    #[test]
    fn trusted_bodyless_declarations_suppress_only_coverage_not_surface_contracts() {
        let unrelated = stable_function(0);
        let root = stable_function(10);
        let panic_declaration = stable_function(11);
        let safety_declaration = stable_function(12);

        let unrelated_panic_call = indirect_call(
            0,
            0,
            bodyless_declaration(
                panic_declaration,
                "other::PanicSurface::call",
                FunctionContractsFact::default(),
            ),
        );
        let unrelated_safety_call = indirect_call(
            1,
            1,
            bodyless_declaration(
                safety_declaration,
                "other::SafetySurface::call",
                FunctionContractsFact::default(),
            ),
        );

        let panic_call = indirect_call(
            0,
            0,
            bodyless_declaration(
                panic_declaration,
                "trusted::PanicSurface::call",
                effect_contracts(Some(whole_contract()), None),
            ),
        );

        let safety_call = indirect_call(
            1,
            1,
            bodyless_declaration(
                safety_declaration,
                "trusted::SafetySurface::call",
                effect_contracts(None, Some(whole_contract())),
            ),
        );

        let artifact = ArtifactFacts::new(
            vec![
                body(
                    unrelated,
                    "sample::unrelated",
                    vec![unrelated_panic_call, unrelated_safety_call],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    root,
                    "sample::root",
                    vec![panic_call, safety_call],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("bodyless declaration artifact");
        let config = trusted_declaration_config();

        let reports = trace_workspace(
            &artifact,
            root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &[
                InterpretationRoot {
                    function: unrelated,
                    path: String::from("sample::unrelated"),
                    kind: ReportRootKind::Concrete,
                },
                InterpretationRoot {
                    function: root,
                    path: String::from("sample::root"),
                    kind: ReportRootKind::Concrete,
                },
            ],
            &config,
        )
        .expect("effect report");
        assert_trusted_surface_findings(&reports);
    }

    fn ignored_macro_call(target_function: FunctionId, macro_definition: FunctionId) -> CallFact {
        let mut helper_call = call(0, target(target_function, "sample::helper"));
        helper_call.macro_expansions = vec![MacroExpansionFact {
            macro_def: macro_definition.def_path_hash,
            display_path: String::from("core::ub_checks::assert_unsafe_precondition"),
            source_range: None,
        }];
        helper_call
    }

    #[test]
    fn ignored_macro_invocation_is_local_to_the_caller_report_root() {
        let boundary_root = stable_function(100);
        let helper_root = stable_function(101);
        let helper_call = ignored_macro_call(helper_root, stable_function(102));
        let compiler_assert = EffectFact {
            id: EffectId::new(0),
            effect: EffectKey::new("panic"),
            effect_group: None,
            source_range: None,
            expanded_range: None,
            macro_expansions: Vec::new(),
            kind: EffectKind::new(CompilerAssertKind::BoundsCheck.effect_kind_name()),
        };
        let artifact = ArtifactFacts::new(
            vec![
                body(
                    boundary_root,
                    "sample::boundary_root",
                    vec![helper_call],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    helper_root,
                    "sample::helper",
                    Vec::new(),
                    vec![compiler_assert],
                    Vec::new(),
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("path-local ignored-macro fixture");
        let config = SniffTestConfig::default();
        let graph = InvocationGraph::from_artifact(&artifact).expect("invocation graph");
        let namespaces = artifact.definition_namespace_index();
        let annotations = AnnotationIndex::from_artifact(&artifact, &graph).expect("annotations");
        let panic = probe_concrete_effect_for::<Panic>(
            &artifact,
            &graph,
            &annotations,
            &namespaces,
            &config.panics,
        )
        .expect("panic effect");
        let trace = EffectEngine::new(&graph).trace(&panic);

        assert_eq!(trace.handled().count(), 1);
        assert_eq!(trace.escaped().count(), 0);

        let reports = trace_workspace(
            &artifact,
            boundary_root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &[
                InterpretationRoot {
                    function: boundary_root,
                    path: String::from("sample::boundary_root"),
                    kind: ReportRootKind::Concrete,
                },
                InterpretationRoot {
                    function: helper_root,
                    path: String::from("sample::helper"),
                    kind: ReportRootKind::Concrete,
                },
            ],
            &config,
        )
        .expect("effect report");
        let compiler_assert_count = |report: &RootInterpretation| {
            report
                .findings
                .iter()
                .filter(|finding| matches!(finding.kind, InterpretedFindingKind::Operation { .. }))
                .count()
        };

        assert_eq!(compiler_assert_count(&reports[0]), 0);
        assert_eq!(compiler_assert_count(&reports[1]), 1);
    }

    #[test]
    fn ignored_macro_invocation_hides_nested_panic_marker_ambiguity_from_the_caller_root() {
        let boundary_root = stable_function(110);
        let helper_root = stable_function(111);
        let helper_call = ignored_macro_call(helper_root, stable_function(112));
        let compiler_assert = |id| EffectFact {
            id: EffectId::new(id),
            effect: EffectKey::new("panic"),
            effect_group: None,
            source_range: None,
            expanded_range: None,
            macro_expansions: Vec::new(),
            kind: EffectKind::new(CompilerAssertKind::BoundsCheck.effect_kind_name()),
        };
        let artifact = ArtifactFacts::new(
            vec![
                body(
                    boundary_root,
                    "sample::boundary_root",
                    vec![helper_call],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    helper_root,
                    "sample::helper",
                    Vec::new(),
                    vec![compiler_assert(0), compiler_assert(1)],
                    vec![
                        shared_justification_marker(
                            0,
                            "shared-panic-marker",
                            annotation_kind::<Panic>(AnnotationRole::Justification),
                            AnnotationTargetFact::Effect(EffectId::new(0)),
                        ),
                        shared_justification_marker(
                            1,
                            "shared-panic-marker",
                            annotation_kind::<Panic>(AnnotationRole::Justification),
                            AnnotationTargetFact::Effect(EffectId::new(1)),
                        ),
                    ],
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("ignored-macro marker-ambiguity fixture");

        let reports = trace_workspace(
            &artifact,
            boundary_root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &[
                InterpretationRoot {
                    function: boundary_root,
                    path: String::from("sample::boundary_root"),
                    kind: ReportRootKind::Concrete,
                },
                InterpretationRoot {
                    function: helper_root,
                    path: String::from("sample::helper"),
                    kind: ReportRootKind::Concrete,
                },
            ],
            &SniffTestConfig::default(),
        )
        .expect("effect report");
        let ambiguity_count = |root| {
            reports
                .iter()
                .find(|report| report.root.function == root)
                .expect("root report")
                .findings
                .iter()
                .filter(|finding| {
                    matches!(finding.kind, InterpretedFindingKind::AmbiguousMarker { .. })
                })
                .count()
        };

        assert_eq!(ambiguity_count(boundary_root), 0);
        assert_eq!(ambiguity_count(helper_root), 1);
    }

    #[test]
    fn ignored_macro_invocation_hides_nested_unresolved_panic_gap_from_the_caller_root() {
        let boundary_root = stable_function(120);
        let helper_root = stable_function(121);
        let helper_call = ignored_macro_call(helper_root, stable_function(122));
        let artifact = ArtifactFacts::new(
            vec![
                body(
                    boundary_root,
                    "sample::boundary_root",
                    vec![helper_call],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                body(
                    helper_root,
                    "sample::helper",
                    vec![targetless_call(0, 0, "unresolved function pointer")],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
            ],
            Vec::new(),
        )
        .expect("ignored-macro unresolved-call fixture");
        let config = SniffTestConfig::from_manifest_str(
            r#"
                [panics.lints]
                unresolved-call-target = "warn"
            "#,
        )
        .expect("unresolved-call configuration");

        let reports = trace_workspace(
            &artifact,
            boundary_root.def_path_hash.stable_crate_id(),
            &ArtifactAnalysisGraph::default(),
            &[
                InterpretationRoot {
                    function: boundary_root,
                    path: String::from("sample::boundary_root"),
                    kind: ReportRootKind::Concrete,
                },
                InterpretationRoot {
                    function: helper_root,
                    path: String::from("sample::helper"),
                    kind: ReportRootKind::Concrete,
                },
            ],
            &config,
        )
        .expect("effect report");

        assert_eq!(unresolved_panic_count(&reports, boundary_root), 0);
        assert_eq!(unresolved_panic_count(&reports, helper_root), 1);
    }
}
