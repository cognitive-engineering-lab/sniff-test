//! Shared tracking for compiler-discovered concrete effect seeds.

use std::collections::{BTreeMap, BTreeSet};

use effect_tracing::{
    EffectSeed, FunctionId, InvocationId, Propagation, PropagationEdge, TraceCx, TracePolicy,
    TraceSite,
};

use crate::annotations::{AnnotationId, AnnotationIndex, SiteCommentAnnotation};
use crate::artifact::{
    ArtifactFacts, CallId, DefinitionNamespaceIndex, EffectFact, EffectId, EffectKey,
    FunctionId as StableFunctionId, MacroExpansionFact, same_macro_provenance,
};
use crate::compiler::invocations::InvocationGraph;
use crate::path_patterns::PathPatterns;

use super::obligation::ConcreteState;
use super::trust::TrustPath;
use super::{Effect, InvocationSourceBranch, ProbeError};
use crate::config::EffectConfig;

/// Stable location of one compiler-discovered effect source.
///
/// The active tracker supplies the effect domain. The source itself only
/// needs enough identity to keep traces distinct and resolve source evidence
/// and diagnostics back to compiler facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConcreteSource {
    Invocation {
        invocation: InvocationId,
        call: CallId,
    },
    Effect {
        owner: StableFunctionId,
        effect: EffectId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConcreteEffectSeed {
    source: ConcreteSource,
    owner: FunctionId,
}

impl ConcreteEffectSeed {
    #[must_use]
    pub const fn new(source: ConcreteSource, owner: FunctionId) -> Self {
        Self { source, owner }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyPolicy {
    Include,
    TrustedBoundary,
    Ignore,
}

/// Framework-derived view of the common effect configuration.
struct ConcreteProbePolicy<'config> {
    ignored: &'config PathPatterns,
    trusted: &'config PathPatterns,
}

impl<'config> ConcreteProbePolicy<'config> {
    fn from_config(config: &'config EffectConfig) -> Self {
        Self {
            ignored: config.ignored_namespaces(),
            trusted: config.trusted_boundary_namespaces(),
        }
    }

    fn body_policy(&self, candidates: &[String]) -> BodyPolicy {
        if self.ignored.best_candidates_match(candidates).is_some() {
            return BodyPolicy::Ignore;
        }
        if self.trusted.best_candidates_match(candidates).is_some() {
            BodyPolicy::TrustedBoundary
        } else {
            BodyPolicy::Include
        }
    }

    fn ignores_macro_path(&self, path: &str) -> bool {
        self.ignored.best_match(path).is_some()
    }
}

/// Resolves preliminary sources through shared function, macro, and boundary
/// policy before constructing a domain's concrete effect tracker.
struct ConcreteSeedCollector<'a, 'policy> {
    graph: &'a InvocationGraph,
    policy: ConcreteProbePolicy<'policy>,
    seeds: Vec<ConcreteEffectSeed>,
    trusted_functions: BTreeSet<FunctionId>,
    ignored_functions: BTreeSet<FunctionId>,
    macro_ignored_sources: BTreeSet<ConcreteSource>,
    ignored_invocations: BTreeSet<InvocationId>,
    invocation_sources: BTreeMap<InvocationId, Vec<InvocationSourceBranch>>,
}

impl<'a, 'policy> ConcreteSeedCollector<'a, 'policy> {
    fn new(graph: &'a InvocationGraph, config: &'policy EffectConfig) -> Self {
        let policy = ConcreteProbePolicy::from_config(config);
        let ignored_invocations = graph
            .invocations()
            .filter(|invocation| {
                invocation.is_suppressed_by_compiler_context()
                    || invocation
                        .macro_provenance()
                        .iter()
                        .any(|frame| policy.ignores_macro_path(&frame.display_path))
            })
            .map(crate::compiler::invocations::Invocation::id)
            .collect();
        Self {
            graph,
            policy,
            seeds: Vec::new(),
            trusted_functions: BTreeSet::new(),
            ignored_functions: BTreeSet::new(),
            macro_ignored_sources: BTreeSet::new(),
            ignored_invocations,
            invocation_sources: BTreeMap::new(),
        }
    }

    fn filter_owner(
        &mut self,
        function: StableFunctionId,
        candidates: &[String],
        domain_name: &str,
    ) -> Result<Option<FunctionId>, ProbeError> {
        let body_policy = self.policy.body_policy(candidates);
        if body_policy == BodyPolicy::Ignore {
            self.ignored_functions
                .extend(self.graph.function_aliases(function));
            return Ok(None);
        }
        let owner = self.graph.function(function).ok_or_else(|| {
            ProbeError::new(format!(
                "{domain_name} source owner {function:?} is missing from the invocation graph"
            ))
        })?;
        if body_policy == BodyPolicy::TrustedBoundary {
            self.trusted_functions
                .extend(self.graph.function_aliases(function));
        }
        Ok(Some(owner))
    }

    fn push_effect(
        &mut self,
        function: StableFunctionId,
        effect: EffectId,
        owner: FunctionId,
        macro_expansions: &[MacroExpansionFact],
    ) {
        let source = ConcreteSource::Effect {
            owner: function,
            effect,
        };
        self.push_source(source, owner, macro_expansions);
    }

    fn push_invocation(&mut self, invocation: InvocationId, branch: InvocationSourceBranch) {
        let source = ConcreteSource::Invocation {
            invocation,
            call: branch.edge().id,
        };
        self.push_source(
            source,
            self.graph.invocation(invocation).caller(),
            &branch.edge().macro_expansions,
        );
        self.invocation_sources
            .entry(invocation)
            .or_default()
            .push(branch);
    }

    fn push_source(
        &mut self,
        source: ConcreteSource,
        owner: FunctionId,
        macro_expansions: &[MacroExpansionFact],
    ) {
        if macro_expansions
            .iter()
            .any(|frame| self.policy.ignores_macro_path(&frame.display_path))
        {
            self.macro_ignored_sources.insert(source);
        }
        self.seeds.push(ConcreteEffectSeed::new(source, owner));
    }

    fn finish(self, annotations: &'a AnnotationIndex, effect: EffectKey) -> ConcreteEffect<'a> {
        ConcreteEffect::new(
            annotations,
            self.graph,
            effect,
            self.seeds,
            self.trusted_functions,
            self.ignored_functions,
            self.macro_ignored_sources,
            self.ignored_invocations,
            self.invocation_sources,
        )
    }
}

/// Discovers concrete sources for any effect using one framework-owned walk.
pub fn probe_concrete_effect<'annotations>(
    artifact: &ArtifactFacts,
    graph: &'annotations InvocationGraph,
    annotations: &'annotations AnnotationIndex,
    namespaces: &DefinitionNamespaceIndex,
    domain: &dyn Effect,
) -> Result<ConcreteEffect<'annotations>, ProbeError> {
    let mut seeds = ConcreteSeedCollector::new(graph, domain.config());
    for body in &artifact.functions {
        let Some(owner) = seeds.filter_owner(
            body.function,
            namespaces.candidates(body.function),
            domain.key().as_str(),
        )?
        else {
            continue;
        };

        for effect in &body.effects {
            if effect.effect != *domain.key() {
                continue;
            }
            for projected_owner in projected_owners(artifact, graph, body.function, owner, effect) {
                seeds.push_effect(
                    body.function,
                    effect.id,
                    projected_owner,
                    &effect.macro_expansions,
                );
            }
        }

        for call in &body.calls {
            if !call
                .invocation_effects
                .iter()
                .any(|source| source.effect == *domain.key())
            {
                continue;
            }
            if let Some(invocation) = graph.invocation_for_raw_call(body.function, call.id) {
                seeds.push_invocation(
                    invocation,
                    InvocationSourceBranch::new(
                        call.clone(),
                        call.target.function_target().cloned(),
                    ),
                );
            }
        }
    }
    Ok(seeds.finish(annotations, domain.key().clone()))
}

#[cfg(test)]
pub fn probe_concrete_effect_for<'annotations, E: super::EffectSpec>(
    artifact: &ArtifactFacts,
    graph: &'annotations InvocationGraph,
    annotations: &'annotations AnnotationIndex,
    namespaces: &DefinitionNamespaceIndex,
    config: &EffectConfig,
) -> Result<ConcreteEffect<'annotations>, ProbeError> {
    let effect = super::effect::<E>(config);
    probe_concrete_effect(artifact, graph, annotations, namespaces, effect.as_ref())
}

fn projected_owners(
    artifact: &ArtifactFacts,
    graph: &InvocationGraph,
    function: StableFunctionId,
    owner: FunctionId,
    effect: &EffectFact,
) -> Vec<FunctionId> {
    if function.instance_hash.is_some() {
        return vec![owner];
    }
    graph
        .function_aliases(function)
        .filter(|alias| {
            *alias == owner
                || !artifact
                    .function_body(graph.stable_function(*alias))
                    .is_some_and(|candidate| {
                        candidate
                            .effects
                            .iter()
                            .any(|candidate| same_materialized_effect(candidate, effect))
                    })
        })
        .collect()
}

fn same_materialized_effect(left: &EffectFact, right: &EffectFact) -> bool {
    left.effect == right.effect
        && left.kind == right.kind
        && left.effect_group == right.effect_group
        && left.source_range == right.source_range
        && left.expanded_range == right.expanded_range
        && same_macro_provenance(&left.macro_expansions, &right.macro_expansions)
}

#[cfg(test)]
mod probe_policy_tests {
    use crate::config::EffectConfig;
    use crate::path_patterns::PathPatterns;

    use super::{BodyPolicy, ConcreteProbePolicy};

    fn patterns(values: &[&str]) -> PathPatterns {
        PathPatterns::new(values.iter().map(|value| (*value).to_owned()).collect())
            .expect("test paths should be valid")
    }

    #[test]
    fn common_body_policy_is_derived_from_effect_config() {
        let safety = EffectConfig {
            ignored_namespaces: patterns(&["ignored::**"]),
            trusted_boundary_namespaces: patterns(&["trusted::**"]),
            ..crate::config::test_config().effect("safety").clone()
        };
        let policy = ConcreteProbePolicy::from_config(&safety);

        assert_eq!(
            policy.body_policy(&[String::from("ordinary::function")]),
            BodyPolicy::Include
        );
        assert_eq!(
            policy.body_policy(&[String::from("trusted::function")]),
            BodyPolicy::TrustedBoundary
        );
        assert_eq!(
            policy.body_policy(&[String::from("ignored::function")]),
            BodyPolicy::Ignore
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConcreteEffectState {
    current_function: FunctionId,
    invocation_justification: Option<AnnotationId>,
    trust_path: TrustPath,
}

impl ConcreteEffectState {
    #[must_use]
    pub fn new(owner: FunctionId, graph: &InvocationGraph) -> Self {
        Self {
            current_function: owner,
            invocation_justification: None,
            trust_path: TrustPath::new(graph, owner),
        }
    }

    #[must_use]
    pub fn trust_path(&self) -> &TrustPath {
        &self.trust_path
    }

    pub fn trust_from_boundary(&mut self) {
        self.trust_path = TrustPath::default();
    }
}

impl ConcreteState for ConcreteEffectState {
    fn current_function(&self) -> FunctionId {
        self.current_function
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConcreteTermination {
    Justification(AnnotationId),
    TrustedBoundary,
    IgnoredBoundary,
}

/// Framework-owned propagation policy for one concrete effect domain.
///
/// Effect definitions construct seeds and boundary sets. This type provides
/// the common graph propagation and justification termination semantics.
pub struct ConcreteEffect<'annotations> {
    annotations: &'annotations AnnotationIndex,
    graph: &'annotations InvocationGraph,
    effect: EffectKey,
    seeds: Vec<EffectSeed<ConcreteSource, ConcreteEffectState>>,
    trusted_functions: BTreeSet<FunctionId>,
    ignored_functions: BTreeSet<FunctionId>,
    macro_ignored_sources: BTreeSet<ConcreteSource>,
    ignored_invocations: BTreeSet<InvocationId>,
    invocation_sources: BTreeMap<InvocationId, Vec<InvocationSourceBranch>>,
}

impl<'annotations> ConcreteEffect<'annotations> {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        annotations: &'annotations AnnotationIndex,
        graph: &'annotations InvocationGraph,
        effect: EffectKey,
        seeds: Vec<ConcreteEffectSeed>,
        trusted_functions: BTreeSet<FunctionId>,
        ignored_functions: BTreeSet<FunctionId>,
        macro_ignored_sources: BTreeSet<ConcreteSource>,
        ignored_invocations: BTreeSet<InvocationId>,
        invocation_sources: BTreeMap<InvocationId, Vec<InvocationSourceBranch>>,
    ) -> Self {
        let seeds = seeds
            .into_iter()
            .map(|seed| {
                let mut state = ConcreteEffectState::new(seed.owner, graph);
                if trusted_functions.contains(&seed.owner) {
                    state.trust_from_boundary();
                }
                EffectSeed::new(seed.source, seed.owner, state)
            })
            .collect();
        Self {
            annotations,
            graph,
            effect,
            seeds,
            trusted_functions,
            ignored_functions,
            macro_ignored_sources,
            ignored_invocations,
            invocation_sources,
        }
    }

    #[must_use]
    #[cfg(test)]
    pub fn source_count(&self) -> usize {
        self.seeds.len()
    }

    #[must_use]
    pub fn is_opaque_on_path(&self, function: FunctionId, path: &TrustPath) -> bool {
        self.ignored_functions.contains(&function)
            || (self.is_trusted_function(function) && path.allows_boundary(self.graph, function))
    }

    #[must_use]
    pub fn is_trusted_function(&self, function: FunctionId) -> bool {
        self.trusted_functions.contains(&function)
    }

    pub fn trusted_functions(&self) -> impl Iterator<Item = FunctionId> + '_ {
        self.trusted_functions.iter().copied()
    }

    #[must_use]
    pub fn is_ignored_invocation(&self, invocation: InvocationId) -> bool {
        self.ignored_invocations.contains(&invocation)
    }

    pub fn ignored_invocations(&self) -> impl Iterator<Item = InvocationId> + '_ {
        self.ignored_invocations.iter().copied()
    }

    #[must_use]
    pub fn invocation_sources(&self, invocation: InvocationId) -> &[InvocationSourceBranch] {
        self.invocation_sources
            .get(&invocation)
            .map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub fn invocation_source(
        &self,
        invocation: InvocationId,
        call: CallId,
    ) -> Option<&InvocationSourceBranch> {
        self.invocation_sources(invocation)
            .iter()
            .find(|source| source.edge().id == call)
    }

    fn raw_call_justification(
        &self,
        invocation: InvocationId,
        call: CallId,
    ) -> Option<AnnotationId> {
        self.annotations
            .comments_at_raw_call(invocation, call, &self.effect)
            .find(|comment| comment.has_justification())
            .map(SiteCommentAnnotation::id)
    }

    fn invocation_justification(
        &self,
        invocation: InvocationId,
        target: FunctionId,
    ) -> Option<AnnotationId> {
        let mut calls = self.graph.raw_calls_reaching(invocation, target);
        let selected = self.raw_call_justification(invocation, calls.next()?)?;
        for call in calls {
            self.raw_call_justification(invocation, call)?;
        }
        Some(selected)
    }
}

impl ConcreteEffect<'_> {
    fn source_justification(&self, source: ConcreteSource) -> Option<AnnotationId> {
        match source {
            ConcreteSource::Invocation { invocation, call } => {
                self.raw_call_justification(invocation, call)
            }
            ConcreteSource::Effect { owner, effect } => self
                .annotations
                .comments_at_effect(owner, effect, &self.effect)
                .find(|comment| comment.has_justification())
                .map(SiteCommentAnnotation::id),
        }
    }
}

impl TracePolicy for ConcreteEffect<'_> {
    type Origin = ConcreteSource;
    type State = ConcreteEffectState;
    type Termination = ConcreteTermination;

    fn sources(&self) -> impl Iterator<Item = EffectSeed<Self::Origin, Self::State>> + '_ {
        self.seeds.iter().cloned()
    }

    fn propagate(
        &self,
        cx: &TraceCx<'_>,
        state: &Self::State,
        edge: PropagationEdge,
    ) -> Propagation<Self::State> {
        let mut next = state.clone();
        next.invocation_justification = None;
        next.current_function = match edge {
            PropagationEdge::Invocation(invocation) => {
                next.invocation_justification =
                    self.invocation_justification(invocation, state.current_function);
                self.graph.invocation(invocation).caller()
            }
            PropagationEdge::TransparentBody(edge) => cx.graph().transparent_parent(edge),
            PropagationEdge::ContractHandoff => {
                unreachable!("contract handoffs are created by the tracing engine")
            }
        };
        if !self.is_trusted_function(next.current_function) {
            next.trust_path.enter(self.graph, next.current_function);
        }
        Propagation::Follow(next)
    }

    fn terminate(
        &self,
        _cx: &TraceCx<'_>,
        state: &Self::State,
        site: TraceSite<'_, Self::Origin>,
    ) -> Option<Self::Termination> {
        match site {
            TraceSite::Source(origin) => {
                if self.macro_ignored_sources.contains(origin) {
                    Some(ConcreteTermination::IgnoredBoundary)
                } else {
                    self.source_justification(*origin)
                        .map(ConcreteTermination::Justification)
                }
            }
            TraceSite::Function(function) => {
                if self.ignored_functions.contains(&function) {
                    Some(ConcreteTermination::IgnoredBoundary)
                } else {
                    (self.trusted_functions.contains(&function)
                        && state.trust_path.allows_boundary(self.graph, function))
                    .then_some(ConcreteTermination::TrustedBoundary)
                }
            }
            TraceSite::Invocation(invocation) => {
                if self.ignored_invocations.contains(&invocation) {
                    Some(ConcreteTermination::IgnoredBoundary)
                } else {
                    state
                        .invocation_justification
                        .map(ConcreteTermination::Justification)
                }
            }
        }
    }
}
