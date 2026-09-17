//! Shared tracking for compiler-discovered concrete effect seeds.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hash;

use effect_tracing::{
    EffectSeed, FunctionId, InvocationId, Propagation, PropagationEdge, TraceCx, TracePolicy,
    TraceSite,
};

use crate::annotations::{AnnotationDomain, AnnotationId, AnnotationIndex, SiteCommentAnnotation};
use crate::artifact::{CallId, EffectId, FunctionId as StableFunctionId};
use crate::compiler::invocations::InvocationGraph;

use super::InvocationSourceBranch;
use super::obligation::ConcreteState;
use super::trust::TrustPath;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JustificationSite {
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
pub(crate) struct ConcreteEffectSeed<O, K> {
    origin: O,
    owner: FunctionId,
    kind: K,
    justification_site: JustificationSite,
}

impl<O, K> ConcreteEffectSeed<O, K> {
    #[must_use]
    pub(crate) const fn new(
        origin: O,
        owner: FunctionId,
        kind: K,
        justification_site: JustificationSite,
    ) -> Self {
        Self {
            origin,
            owner,
            kind,
            justification_site,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ConcreteEffectState<K> {
    kind: K,
    current_function: FunctionId,
    invocation_justification: Option<AnnotationId>,
    trust_path: TrustPath,
}

impl<K> ConcreteEffectState<K> {
    #[must_use]
    pub(crate) fn new(kind: K, owner: FunctionId, graph: &InvocationGraph) -> Self {
        Self {
            kind,
            current_function: owner,
            invocation_justification: None,
            trust_path: TrustPath::new(graph, owner),
        }
    }

    #[must_use]
    pub(crate) fn trust_path(&self) -> &TrustPath {
        &self.trust_path
    }

    pub(crate) const fn kind(&self) -> K
    where
        K: Copy,
    {
        self.kind
    }

    pub(crate) fn trust_from_boundary(&mut self) {
        self.trust_path = TrustPath::default();
    }
}

impl<K> ConcreteState for ConcreteEffectState<K> {
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
pub(crate) struct ConcreteEffect<'annotations, O, K> {
    annotations: &'annotations AnnotationIndex,
    graph: &'annotations InvocationGraph,
    domain: AnnotationDomain,
    seeds: Vec<EffectSeed<O, ConcreteEffectState<K>>>,
    source_sites: BTreeMap<O, JustificationSite>,
    trusted_functions: BTreeSet<FunctionId>,
    ignored_functions: BTreeSet<FunctionId>,
    macro_ignored_sources: BTreeSet<O>,
    macro_ignored_invocations: BTreeSet<InvocationId>,
    invocation_sources: BTreeMap<InvocationId, Vec<InvocationSourceBranch>>,
}

impl<'annotations, O, K> ConcreteEffect<'annotations, O, K>
where
    O: Copy + Ord,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        annotations: &'annotations AnnotationIndex,
        graph: &'annotations InvocationGraph,
        domain: AnnotationDomain,
        seeds: Vec<ConcreteEffectSeed<O, K>>,
        trusted_functions: BTreeSet<FunctionId>,
        ignored_functions: BTreeSet<FunctionId>,
        macro_ignored_sources: BTreeSet<O>,
        macro_ignored_invocations: BTreeSet<InvocationId>,
        invocation_sources: BTreeMap<InvocationId, Vec<InvocationSourceBranch>>,
    ) -> Self {
        let source_sites = seeds
            .iter()
            .map(|seed| (seed.origin, seed.justification_site))
            .collect();
        let seeds = seeds
            .into_iter()
            .map(|seed| {
                let mut state = ConcreteEffectState::new(seed.kind, seed.owner, graph);
                if trusted_functions.contains(&seed.owner) {
                    state.trust_from_boundary();
                }
                EffectSeed::new(seed.origin, seed.owner, state)
            })
            .collect();
        Self {
            annotations,
            graph,
            domain,
            seeds,
            source_sites,
            trusted_functions,
            ignored_functions,
            macro_ignored_sources,
            macro_ignored_invocations,
            invocation_sources,
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

impl<O: Copy + Ord, K> ConcreteEffect<'_, O, K> {
    fn source_justification(&self, origin: O) -> Option<AnnotationId> {
        match *self.source_sites.get(&origin)? {
            JustificationSite::Invocation { invocation, call } => {
                self.raw_call_justification(invocation, call)
            }
            JustificationSite::Effect { owner, effect } => self
                .annotations
                .comments_at_effect(owner, effect, self.domain)
                .find(|comment| comment.has_justification())
                .map(SiteCommentAnnotation::id),
        }
    }
}

impl<O, K> TracePolicy for ConcreteEffect<'_, O, K>
where
    O: Copy + Eq + Ord + Hash,
    K: Copy + Eq + Hash,
{
    type Origin = O;
    type State = ConcreteEffectState<K>;
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
