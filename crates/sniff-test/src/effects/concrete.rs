//! Shared tracking for compiler-discovered concrete effect seeds.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use effect_tracing::{
    EffectSeed, FunctionId, InvocationId, Propagation, PropagationEdge, TraceCx, TracePolicy,
    TraceSite,
};

use crate::annotations::{AnnotationDomain, AnnotationId, AnnotationIndex, SiteCommentAnnotation};
use crate::artifact::{
    ArtifactFacts, CallId, DefinitionNamespaceIndex, EffectFact, EffectId,
    FunctionId as StableFunctionId, FunctionTargetFact, MacroExpansionFact, same_macro_provenance,
};
use crate::compiler::invocations::InvocationGraph;
use crate::path_patterns::PathPatterns;

use super::obligation::ConcreteState;
use super::trust::TrustPath;
use super::{Effect, EffectConfig, InvocationSourceBranch, ProbeError};

/// Stable location of one compiler-discovered effect source.
///
/// The active tracker supplies the effect domain. The source itself only
/// needs enough identity to keep traces distinct and resolve source evidence
/// and diagnostics back to compiler facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ConcreteSource {
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
pub(crate) struct ConcreteEffectSeed {
    source: ConcreteSource,
    owner: FunctionId,
}

impl ConcreteEffectSeed {
    #[must_use]
    pub(crate) const fn new(source: ConcreteSource, owner: FunctionId) -> Self {
        Self { source, owner }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyPolicy {
    Include,
    TrustedBoundary,
    Ignore,
}

pub(crate) struct InvocationSourceMatch {
    pub(crate) target: Option<FunctionTargetFact>,
}

/// Framework-derived view of the common effect configuration.
struct ConcreteProbePolicy<'config> {
    ignored: &'config PathPatterns,
    trusted: &'config PathPatterns,
    source_boundaries: Option<&'config PathPatterns>,
}

impl<'config> ConcreteProbePolicy<'config> {
    fn from_config(config: &'config impl EffectConfig) -> Self {
        Self {
            ignored: config.ignored_namespaces(),
            trusted: config.trusted_boundary_namespaces(),
            source_boundaries: config.source_boundary_namespaces(),
        }
    }

    fn body_policy(&self, candidates: &[String]) -> BodyPolicy {
        if self.ignored.best_candidates_match(candidates).is_some() {
            return BodyPolicy::Ignore;
        }
        let trusted = self.trusted.best_candidates_match(candidates);
        let source = self
            .source_boundaries
            .and_then(|patterns| patterns.best_candidates_match(candidates));
        match (trusted, source) {
            (Some(trusted), Some(source)) if trusted.precision > source.precision => {
                BodyPolicy::TrustedBoundary
            }
            (Some(_), None) => BodyPolicy::TrustedBoundary,
            _ => BodyPolicy::Include,
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
    macro_ignored_invocations: BTreeSet<InvocationId>,
    invocation_sources: BTreeMap<InvocationId, Vec<InvocationSourceBranch>>,
}

impl<'a, 'policy> ConcreteSeedCollector<'a, 'policy> {
    fn new(graph: &'a InvocationGraph, config: &'policy impl EffectConfig) -> Self {
        let policy = ConcreteProbePolicy::from_config(config);
        let macro_ignored_invocations = graph
            .invocations()
            .filter(|invocation| {
                invocation
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
            macro_ignored_invocations,
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

    fn finish<D>(
        self,
        annotations: &'a AnnotationIndex,
        domain: AnnotationDomain,
    ) -> ConcreteEffect<'a, D> {
        ConcreteEffect::new(
            annotations,
            self.graph,
            domain,
            self.seeds,
            self.trusted_functions,
            self.ignored_functions,
            self.macro_ignored_sources,
            self.macro_ignored_invocations,
            self.invocation_sources,
        )
    }
}

/// Discovers concrete sources for any effect using one framework-owned walk.
pub(crate) fn probe_concrete_effect<'annotations, E: Effect>(
    artifact: &ArtifactFacts,
    graph: &'annotations InvocationGraph,
    annotations: &'annotations AnnotationIndex,
    namespaces: &DefinitionNamespaceIndex,
    config: &E::Config,
) -> Result<ConcreteEffect<'annotations, E>, ProbeError> {
    let mut seeds = ConcreteSeedCollector::new(graph, config);
    for body in &artifact.functions {
        let Some(owner) = seeds.filter_owner(
            body.function,
            namespaces.candidates(body.function),
            E::EFFECT_NAME,
        )?
        else {
            continue;
        };

        for effect in &body.effects {
            if effect.effect.as_str() != E::EFFECT_NAME {
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
            let Some(source) = E::invocation_source(config, call, namespaces) else {
                continue;
            };
            if let Some(invocation) = graph.invocation_for_raw_call(body.function, call.id) {
                seeds.push_invocation(
                    invocation,
                    InvocationSourceBranch::new(call.clone(), source.target),
                );
            }
        }
    }
    Ok(seeds.finish(annotations, E::DOMAIN))
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
    use crate::config::{PanicConfig, SafetyConfig};
    use crate::path_patterns::PathPatterns;

    use super::{BodyPolicy, ConcreteProbePolicy};

    fn patterns(values: &[&str]) -> PathPatterns {
        PathPatterns::new(values.iter().map(|value| (*value).to_owned()).collect())
            .expect("test paths should be valid")
    }

    #[test]
    fn common_body_policy_is_derived_from_effect_config() {
        let safety = SafetyConfig {
            ignored_namespaces: patterns(&["ignored::**"]),
            trusted_boundary_namespaces: patterns(&["trusted::**"]),
            ..SafetyConfig::default()
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

    #[test]
    fn source_boundary_precision_is_resolved_by_the_framework() {
        let mut panic = PanicConfig::default();
        panic.trusted_boundary_namespaces = patterns(&["runtime::**", "runtime::trusted"]);
        panic.panic_sink_namespaces = patterns(&["runtime::**"]);
        let policy = ConcreteProbePolicy::from_config(&panic);

        assert_eq!(
            policy.body_policy(&[String::from("runtime::panic")]),
            BodyPolicy::Include,
            "equal-precision source rules win over trust"
        );
        assert_eq!(
            policy.body_policy(&[String::from("runtime::trusted")]),
            BodyPolicy::TrustedBoundary,
            "a more precise trusted rule wins"
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ConcreteEffectState {
    current_function: FunctionId,
    invocation_justification: Option<AnnotationId>,
    trust_path: TrustPath,
}

impl ConcreteEffectState {
    #[must_use]
    pub(crate) fn new(owner: FunctionId, graph: &InvocationGraph) -> Self {
        Self {
            current_function: owner,
            invocation_justification: None,
            trust_path: TrustPath::new(graph, owner),
        }
    }

    #[must_use]
    pub(crate) fn trust_path(&self) -> &TrustPath {
        &self.trust_path
    }

    pub(crate) fn trust_from_boundary(&mut self) {
        self.trust_path = TrustPath::default();
    }
}

impl ConcreteState for ConcreteEffectState {
    fn current_function(&self) -> FunctionId {
        self.current_function
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ConcreteTermination {
    Justification(AnnotationId),
    TrustedBoundary,
    IgnoredBoundary,
}

/// Framework-owned propagation policy for one concrete effect domain.
///
/// Effect definitions construct seeds and boundary sets. This type provides
/// the common graph propagation and justification termination semantics.
pub(crate) struct ConcreteEffect<'annotations, D> {
    annotations: &'annotations AnnotationIndex,
    graph: &'annotations InvocationGraph,
    domain: AnnotationDomain,
    seeds: Vec<EffectSeed<ConcreteSource, ConcreteEffectState>>,
    trusted_functions: BTreeSet<FunctionId>,
    ignored_functions: BTreeSet<FunctionId>,
    macro_ignored_sources: BTreeSet<ConcreteSource>,
    macro_ignored_invocations: BTreeSet<InvocationId>,
    invocation_sources: BTreeMap<InvocationId, Vec<InvocationSourceBranch>>,
    domain_marker: PhantomData<D>,
}

impl<'annotations, D> ConcreteEffect<'annotations, D> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        annotations: &'annotations AnnotationIndex,
        graph: &'annotations InvocationGraph,
        domain: AnnotationDomain,
        seeds: Vec<ConcreteEffectSeed>,
        trusted_functions: BTreeSet<FunctionId>,
        ignored_functions: BTreeSet<FunctionId>,
        macro_ignored_sources: BTreeSet<ConcreteSource>,
        macro_ignored_invocations: BTreeSet<InvocationId>,
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
            domain,
            seeds,
            trusted_functions,
            ignored_functions,
            macro_ignored_sources,
            macro_ignored_invocations,
            invocation_sources,
            domain_marker: PhantomData,
        }
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn source_count(&self) -> usize {
        self.seeds.len()
    }

    pub(crate) fn is_opaque_on_path(&self, function: FunctionId, path: &TrustPath) -> bool {
        self.ignored_functions.contains(&function)
            || (self.is_trusted_function(function) && path.allows_boundary(self.graph, function))
    }

    #[must_use]
    pub(crate) fn is_trusted_function(&self, function: FunctionId) -> bool {
        self.trusted_functions.contains(&function)
    }

    #[must_use]
    pub(crate) fn is_ignored_invocation(&self, invocation: InvocationId) -> bool {
        self.macro_ignored_invocations.contains(&invocation)
    }

    #[must_use]
    pub(crate) fn invocation_sources(&self, invocation: InvocationId) -> &[InvocationSourceBranch] {
        self.invocation_sources
            .get(&invocation)
            .map_or(&[], Vec::as_slice)
    }

    #[must_use]
    pub(crate) fn invocation_source(
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
            .comments_at_raw_call(invocation, call, self.domain)
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

impl<D> ConcreteEffect<'_, D> {
    fn source_justification(&self, source: ConcreteSource) -> Option<AnnotationId> {
        match source {
            ConcreteSource::Invocation { invocation, call } => {
                self.raw_call_justification(invocation, call)
            }
            ConcreteSource::Effect { owner, effect } => self
                .annotations
                .comments_at_effect(owner, effect, self.domain)
                .find(|comment| comment.has_justification())
                .map(SiteCommentAnnotation::id),
        }
    }
}

impl<D> TracePolicy for ConcreteEffect<'_, D> {
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
                if self.macro_ignored_invocations.contains(&invocation) {
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
