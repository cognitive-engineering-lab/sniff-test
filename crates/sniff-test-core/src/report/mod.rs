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
    TraceOptions,
};

use crate::annotations::AnnotationIndex;
use crate::artifact::{
    AnnotationFactKind, AnnotationProbingFact, AnnotationRole, AnnotationTargetFact, ArtifactFacts,
    CallTargetFact, DefinitionNamespaceIndex, EffectFact, EffectId, EffectKey, FunctionFact,
    FunctionId as StableFunctionId, FunctionTargetFact, MarkerEvidenceState,
    UnverifiedMarkerProbeReason,
};
use crate::compiler::invocations::{
    InvocationGraph, InvocationResolution, UnresolvedCallTargetReason,
};
use crate::config::EffectConfig;
use crate::config::{MarkerProbing, SniffTestConfig};
use crate::contracts::normalize_requirement_name;
use crate::effects::InvocationSourceBranch;
use crate::effects::concrete::{ConcreteSource, probe_concrete_effect};
use crate::effects::obligation::{
    ObligationEffectPolicy, ObligationTracker, TrackedEffect, TrackedOrigin, TrackedState,
    TrackedTermination,
};
use crate::effects::visit::EffectPassRegistry;
use crate::effects::{Effect, EffectMetadata};
#[cfg(test)]
use crate::effects::{EffectSelection, EffectSpec, selected_effect_objects};

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ReportEffect {
    Panic,
    Safety,
}

#[cfg(test)]
impl ReportEffect {
    fn key(self) -> EffectKey {
        match self {
            Self::Panic => EffectKey::new(Panic::EFFECT_NAME),
            Self::Safety => EffectKey::new(Safety::EFFECT_NAME),
        }
    }
}
#[cfg(test)]
use crate::effects::panic::Panic;
#[cfg(test)]
use crate::effects::safety::Safety;
use crate::effects::trust::TrustPath;
use crate::report_model::{
    DomainCompleteness, EffectCompleteness, IncompleteReason, InterpretationRoot,
    InterpretedCallee, InterpretedFinding, InterpretedFindingKind, InterpretedTrace,
    InterpretedTraceStep, InterpretedTraceStepKind, RootInterpretation, TraceFrontier,
    UnresolvedCallCoverage, UnresolvedCallMechanism, UnresolvedCallSite,
};
use crate::workspace::ArtifactAnalysisGraph;

mod markers;
#[cfg(test)]
use markers::{SourceEffectGroup, obligation_effect_groups};
use markers::{collect_marker_claims, marker_ambiguities};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectReportError {
    message: String,
}

type ConcreteTrace = EffectTrace<
    TrackedOrigin<ConcreteSource>,
    TrackedState<crate::effects::concrete::ConcreteEffectState>,
    TrackedTermination<crate::effects::concrete::ConcreteTermination>,
>;

impl EffectReportError {
    pub fn new(message: impl Into<String>) -> Self {
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
pub fn trace_workspace(
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
pub fn trace_selected_workspace(
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
    let mut pass_registry = EffectPassRegistry::default();
    for effect in effects {
        effect.register_passes(&mut pass_registry);
    }
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
                        .effective_coverage()
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
            let completeness_by_effect = effects
                .iter()
                .map(|effect| {
                    let trace = effect_traces
                        .get(effect.key())
                        .expect("selected effect was traced");
                    let reasons = missing_body_reasons(
                        artifact,
                        &graph,
                        &namespaces,
                        dependencies,
                        local_stable_crate_id,
                        &root_functions,
                        pass_registry.requires_defining_body(effect.key()),
                        effect.config(),
                    );
                    (
                        effect.key().clone(),
                        completeness(
                            artifact,
                            trace,
                            &graph,
                            &root_functions,
                            trace_options,
                            AdditionalCompleteness { reasons },
                        ),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            Ok(RootInterpretation {
                root,
                findings: unique,
                completeness: EffectCompleteness {
                    effects: completeness_by_effect,
                },
            })
        })
        .collect()
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

#[allow(
    clippy::needless_pass_by_value,
    reason = "annotation kind is an owned fact key"
)]
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
#[allow(clippy::too_many_arguments, reason = "report inputs remain explicit")]
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
                    if invocation_source_has_contract(graph, annotations, source, effect_key) {
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
                            (edge.indirect_kind
                                == Some(crate::artifact::IndirectCallKindFact::FunctionPointer))
                            .then(|| InterpretedCallee {
                                function: None,
                                path: String::from("opaque function pointer"),
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
    config: &EffectConfig,
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
    config: &EffectConfig,
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
            let marker_evidence = obligation_marker_evidence(
                artifact,
                graph,
                state.source_invocation(),
                state.source_calls(),
                AnnotationFactKind::new(state.effect().clone(), AnnotationRole::Justification),
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
}

fn function_presentation(
    artifact: &ArtifactFacts,
    function: StableFunctionId,
) -> Option<FunctionPresentation<'_>> {
    if let Some(body) = artifact.function_body(function) {
        return Some(FunctionPresentation {
            path: &body.display_path,
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
    requires_defining_body: bool,
    effect_config: &EffectConfig,
) -> Vec<IncompleteReason> {
    let is_trusted = |function: FunctionId, path: &TrustPath| {
        trusted_boundary(graph.stable_function(function), namespaces, effect_config)
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
                || trusted_boundary(target.function, namespaces, effect_config)
            {
                continue;
            }
            let body_is_available = if requires_defining_body {
                artifact.defining_function_body(target.function).is_some()
            } else {
                artifact.function_body(target.function).is_some()
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
    namespaces: &DefinitionNamespaceIndex,
    effect_config: &EffectConfig,
) -> bool {
    let candidates = namespaces.candidates(function);
    effect_config
        .trusted_boundary_namespaces()
        .best_candidates_match(candidates)
        .is_some()
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
    additional: AdditionalCompleteness,
) -> DomainCompleteness {
    let mut reasons = trace_limit_reasons(artifact, trace, graph, roots, options, |_| true);
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
                    frontier,
                },
                TraceLimitValue::StateBudget(budget) => {
                    IncompleteReason::TraceStateBudget { budget, frontier }
                }
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
    if edge.indirect_kind == Some(crate::artifact::IndirectCallKindFact::FunctionPointer)
        && edge.target.function_target().is_none()
    {
        String::from("indirect call through a function pointer")
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
    }
}

#[cfg(test)]
mod tests;
