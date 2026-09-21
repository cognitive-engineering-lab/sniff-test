//! Shared obligation tracking for every concrete effect domain.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hash;

use effect_tracing::{
    EffectSeed, EffectTrace, FunctionId, InvocationId, Propagation, PropagationEdge,
    TerminationSite, TraceCx, TraceNodeId, TracePolicy, TraceSite,
};

use crate::annotations::{AnnotationId, AnnotationIndex, FunctionContractAnnotation};
use crate::artifact::{ArtifactFacts, CallId, DefinitionNamespaceIndex, EffectKey};
use crate::compiler::invocations::InvocationGraph;
use crate::config::{EffectDocMatching, PanicConfig, SafetyConfig};
use crate::contracts::normalize_requirement_name;
use crate::effects::EffectSelection;
use crate::effects::EffectSpec;
use crate::effects::panic::Panic;
use crate::effects::safety::Safety;

use super::trust::TrustPath;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ContractId(AnnotationId);

impl ContractId {
    #[must_use]
    pub(crate) const fn annotation(self) -> AnnotationId {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ObligationId {
    contract: ContractId,
    index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ObligationState {
    effect: EffectKey,
    contract: ContractId,
    // One invocation may contain concrete and declaration targets. Retaining
    // the current target lets propagation gate only the declaration edge.
    current_function: FunctionId,
    source_invocation: Option<InvocationId>,
    source_calls: BTreeSet<CallId>,
    remaining: BTreeSet<ObligationId>,
    termination: Option<ObligationTermination>,
    trust_path: TrustPath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ObligationTermination {
    Satisfaction(AnnotationId),
    TrustedBoundary,
}

impl ObligationState {
    #[must_use]
    pub(crate) fn trust_path(&self) -> &TrustPath {
        &self.trust_path
    }

    pub(crate) fn remaining(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        self.remaining.iter().map(|obligation| obligation.index)
    }

    #[must_use]
    pub(crate) const fn effect(&self) -> &EffectKey {
        &self.effect
    }

    #[must_use]
    pub(crate) const fn contract(&self) -> ContractId {
        self.contract
    }

    #[must_use]
    pub(crate) const fn source_invocation(&self) -> Option<InvocationId> {
        self.source_invocation
    }

    #[must_use]
    pub(crate) fn source_calls(&self) -> impl ExactSizeIterator<Item = CallId> + '_ {
        self.source_calls.iter().copied()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ObligationMarkerUse {
    annotation: AnnotationId,
    effect: EffectKey,
    invocation: InvocationId,
    source_invocation: InvocationId,
    source_calls: BTreeSet<CallId>,
    node: TraceNodeId,
}

impl ObligationMarkerUse {
    #[must_use]
    pub(crate) const fn annotation(&self) -> AnnotationId {
        self.annotation
    }

    #[must_use]
    pub(crate) const fn invocation(&self) -> InvocationId {
        self.invocation
    }

    #[must_use]
    pub(crate) const fn source_invocation(&self) -> InvocationId {
        self.source_invocation
    }

    #[must_use]
    pub(crate) fn source_calls(&self) -> impl ExactSizeIterator<Item = CallId> + '_ {
        self.source_calls.iter().copied()
    }

    #[must_use]
    pub(crate) const fn node(&self) -> TraceNodeId {
        self.node
    }
}

struct ObligationInvocationTransition {
    state: ObligationState,
    marker_uses: Vec<ObligationMarkerUse>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObligationContract {
    id: ContractId,
    functions: BTreeSet<FunctionId>,
    effect: EffectKey,
    obligations: BTreeSet<ObligationId>,
}

impl ObligationContract {
    #[must_use]
    pub(crate) const fn id(&self) -> ContractId {
        self.id
    }

    #[must_use]
    pub(crate) fn applies_to(&self, function: FunctionId) -> bool {
        self.functions.contains(&function)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Obligation {
    Named(String),
    Structured(Vec<usize>),
    WholeContract,
}

pub(crate) struct ObligationTracker<'annotations> {
    annotations: &'annotations AnnotationIndex,
    graph: &'annotations InvocationGraph,
    contracts: Vec<ObligationContract>,
    obligations: BTreeMap<ObligationId, Obligation>,
    effect_doc_matching: EffectDocMatching,
    trusted_functions: BTreeMap<EffectKey, BTreeSet<FunctionId>>,
    ignored_invocations: BTreeMap<EffectKey, BTreeSet<InvocationId>>,
}

impl<'annotations> ObligationTracker<'annotations> {
    #[allow(
        clippy::too_many_arguments,
        reason = "comment probing joins both domain policies with the invocation selection"
    )]
    pub(crate) fn probe(
        artifact: &ArtifactFacts,
        graph: &'annotations InvocationGraph,
        annotations: &'annotations AnnotationIndex,
        namespaces: &DefinitionNamespaceIndex,
        effect_doc_matching: EffectDocMatching,
        panic_config: &PanicConfig,
        safety_config: &SafetyConfig,
        effects: EffectSelection,
    ) -> Self {
        let mut contracts = Vec::new();
        let mut obligations = BTreeMap::new();
        let panic_key = EffectKey::new(Panic::EFFECT_NAME);
        let safety_key = EffectKey::new(Safety::EFFECT_NAME);
        for annotation in annotations.contracts() {
            if (annotation.effect() == &panic_key && !effects.tracks_panic())
                || (annotation.effect() == &safety_key && !effects.tracks_safety())
            {
                continue;
            }
            let functions = graph
                .contract_targets(annotation.owner())
                .into_iter()
                .filter(|function| {
                    annotations
                        .effective_contract(graph, *function, annotation.effect())
                        .is_some_and(|selected| selected.id() == annotation.id())
                })
                .collect::<BTreeSet<_>>();
            if functions.is_empty() {
                continue;
            }
            let id = ContractId(annotation.id());
            let contract_obligations = collect_obligations(annotation, id, &mut obligations);
            contracts.push(ObligationContract {
                id,
                functions,
                effect: annotation.effect().clone(),
                obligations: contract_obligations,
            });
        }
        let mut trusted_functions = BTreeMap::<EffectKey, BTreeSet<FunctionId>>::new();
        for body in &artifact.functions {
            let candidates = namespaces.candidates(body.function);
            if effects.tracks_panic()
                && panic_config.panic_boundary_policy_candidates(candidates)
                    == crate::config::PanicBoundaryPolicy::TrustedBoundary
            {
                trusted_functions
                    .entry(panic_key.clone())
                    .or_default()
                    .extend(graph.function_aliases(body.function));
            }
            if effects.tracks_safety()
                && safety_config.trusts_safety_boundary_candidates(candidates)
            {
                trusted_functions
                    .entry(safety_key.clone())
                    .or_default()
                    .extend(graph.function_aliases(body.function));
            }
        }
        let ignored_panic_invocations = graph
            .invocations()
            .filter(|_| effects.tracks_panic())
            .filter(|invocation| {
                invocation
                    .macro_provenance()
                    .iter()
                    .any(|frame| panic_config.ignores_path(&frame.display_path))
            })
            .map(crate::compiler::invocations::Invocation::id)
            .collect();
        let ignored_safety_invocations = graph
            .invocations()
            .filter(|_| effects.tracks_safety())
            .filter(|invocation| {
                invocation
                    .macro_provenance()
                    .iter()
                    .any(|frame| safety_config.ignores_path(&frame.display_path))
            })
            .map(crate::compiler::invocations::Invocation::id)
            .collect();
        let mut ignored_invocations = BTreeMap::new();
        ignored_invocations.insert(panic_key, ignored_panic_invocations);
        ignored_invocations.insert(safety_key, ignored_safety_invocations);
        Self {
            annotations,
            graph,
            contracts,
            obligations,
            effect_doc_matching,
            trusted_functions,
            ignored_invocations,
        }
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn contracts(&self) -> &[ObligationContract] {
        &self.contracts
    }

    #[must_use]
    pub(crate) fn contract(&self, id: ContractId) -> Option<&ObligationContract> {
        self.contracts.iter().find(|contract| contract.id == id)
    }

    fn contract_state(
        &self,
        function: FunctionId,
        effect: &EffectKey,
        current: Option<&ObligationState>,
    ) -> Option<ObligationState> {
        let contract = self
            .contracts
            .iter()
            .find(|contract| &contract.effect == effect && contract.applies_to(function))?;
        if current
            .is_some_and(|state| state.contract == contract.id && state.source_invocation.is_none())
        {
            return None;
        }
        Some(ObligationState {
            effect: effect.clone(),
            contract: contract.id,
            current_function: function,
            source_invocation: None,
            source_calls: BTreeSet::new(),
            remaining: contract.obligations.clone(),
            termination: None,
            trust_path: if self.trusts_function(effect, function) {
                TrustPath::default()
            } else {
                TrustPath::new(self.graph, function)
            },
        })
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn contract_count(&self, effect: &EffectKey) -> usize {
        self.contracts
            .iter()
            .filter(|contract| &contract.effect == effect)
            .count()
    }

    fn apply_satisfaction(
        &self,
        state: &mut ObligationState,
        satisfaction: &crate::artifact::AnnotationSatisfactionFact,
    ) {
        if satisfaction.reason.trim().is_empty() {
            return;
        }
        if self.effect_doc_matching == EffectDocMatching::AnyJustification {
            state.remaining.clear();
            return;
        }
        let matching = if let Some(requirement) = satisfaction.requirement.as_deref() {
            let normalized = normalize_requirement_name(requirement);
            self.obligations
                .iter()
                .filter_map(|(id, obligation)| {
                    (id.contract == state.contract
                        && matches!(obligation, Obligation::Named(name) if name == &normalized))
                    .then_some(*id)
                })
                .collect::<Vec<_>>()
        } else {
            let expected = satisfaction
                .structural_path
                .as_ref()
                .map_or(Obligation::WholeContract, |path| {
                    Obligation::Structured(path.clone())
                });
            self.obligations
                .iter()
                .filter_map(|(id, obligation)| {
                    (id.contract == state.contract && obligation == &expected).then_some(*id)
                })
                .collect()
        };
        if let [obligation] = matching.as_slice() {
            state.remaining.remove(obligation);
        }
    }

    pub(crate) fn trusts_function(&self, effect: &EffectKey, function: FunctionId) -> bool {
        self.trusted_functions
            .get(effect)
            .is_some_and(|functions| functions.contains(&function))
    }

    #[must_use]
    pub(crate) fn is_ignored_invocation(
        &self,
        effect: &EffectKey,
        invocation: InvocationId,
    ) -> bool {
        self.ignored_invocations
            .get(effect)
            .is_some_and(|invocations| invocations.contains(&invocation))
    }

    fn invocation_transition(
        &self,
        state: &ObligationState,
        invocation: InvocationId,
        node: Option<TraceNodeId>,
    ) -> Option<ObligationInvocationTransition> {
        if self.is_ignored_invocation(&state.effect, invocation) {
            return None;
        }
        if state.effect.as_str() == Safety::EFFECT_NAME
            && self.graph.invocation(invocation).is_builtin_unsafe()
        {
            return None;
        }
        let mut next = state.clone();
        next.termination = None;
        let relevant_calls = self
            .graph
            .raw_calls_reaching(invocation, state.current_function)
            .collect::<Vec<_>>();
        if next.source_invocation.is_none() {
            next.source_invocation = Some(invocation);
            next.source_calls.extend(relevant_calls.iter().copied());
        }
        let source_invocation = next
            .source_invocation
            .expect("an invocation transition records its source invocation");
        let mut marker_uses = Vec::new();
        for call in relevant_calls {
            for comment in self
                .annotations
                .comments_at_raw_call(invocation, call, &state.effect)
            {
                let before = next.remaining.len();
                for satisfaction in comment.satisfactions() {
                    self.apply_satisfaction(&mut next, satisfaction);
                }
                if next.remaining.len() < before
                    && let Some(node) = node
                {
                    marker_uses.push(ObligationMarkerUse {
                        annotation: comment.id(),
                        effect: state.effect.clone(),
                        invocation,
                        source_invocation,
                        source_calls: next.source_calls.clone(),
                        node,
                    });
                }
                if before > 0 && next.remaining.is_empty() {
                    next.termination = Some(ObligationTermination::Satisfaction(comment.id()));
                }
            }
        }
        Some(ObligationInvocationTransition {
            state: next,
            marker_uses,
        })
    }

    fn crosses_non_applicable_declaration(
        &self,
        state: &ObligationState,
        invocation: InvocationId,
    ) -> bool {
        let invocation = self.graph.invocation(invocation);
        let current = state.current_function;
        let is_concrete_edge = invocation
            .function_targets()
            .any(|target| target == current);
        let is_declaration_edge = invocation
            .declaration_targets()
            .any(|target| target == current);

        !is_concrete_edge
            && is_declaration_edge
            && !self
                .contract(state.contract)
                .is_some_and(|contract| contract.applies_to(current))
    }

    #[cfg(test)]
    pub(crate) fn marker_uses(
        &self,
        trace: &EffectTrace<ContractId, ObligationState, ObligationTermination>,
    ) -> Vec<ObligationMarkerUse> {
        let nodes = trace.nodes().collect::<Vec<_>>();
        let mut uses = Vec::new();
        for edge in trace.edges() {
            let PropagationEdge::Invocation(invocation) = edge.propagation() else {
                continue;
            };
            if let Some(transition) = self.invocation_transition(
                nodes[edge.from().index()].state(),
                invocation,
                Some(edge.from()),
            ) {
                uses.extend(transition.marker_uses);
            }
        }
        for handled in trace.handled() {
            let (Some(node), TerminationSite::Invocation(invocation)) =
                (handled.node(), handled.site())
            else {
                continue;
            };
            if let Some(transition) =
                self.invocation_transition(nodes[node.index()].state(), *invocation, Some(node))
            {
                uses.extend(transition.marker_uses);
            }
        }
        uses.sort();
        uses.dedup();
        uses
    }
}

impl TracePolicy for ObligationTracker<'_> {
    type Origin = ContractId;
    type State = ObligationState;
    type Termination = ObligationTermination;

    fn sources(&self) -> impl Iterator<Item = EffectSeed<Self::Origin, Self::State>> + '_ {
        self.contracts.iter().flat_map(move |contract| {
            contract.functions.iter().copied().map(move |function| {
                EffectSeed::new(
                    contract.id,
                    function,
                    ObligationState {
                        effect: contract.effect.clone(),
                        contract: contract.id,
                        current_function: function,
                        source_invocation: None,
                        source_calls: BTreeSet::new(),
                        remaining: contract.obligations.clone(),
                        termination: None,
                        trust_path: if self.trusts_function(&contract.effect, function) {
                            TrustPath::default()
                        } else {
                            TrustPath::new(self.graph, function)
                        },
                    },
                )
            })
        })
    }

    fn handoff(
        &self,
        _cx: &TraceCx<'_>,
        state: &Self::State,
        function: FunctionId,
    ) -> Option<Self::State> {
        self.contract_state(function, &state.effect, Some(state))
    }

    fn propagate(
        &self,
        cx: &TraceCx<'_>,
        state: &Self::State,
        edge: PropagationEdge,
    ) -> Propagation<Self::State> {
        let mut next = state.clone();
        next.termination = None;
        if let PropagationEdge::Invocation(invocation) = edge {
            if self.crosses_non_applicable_declaration(state, invocation) {
                return Propagation::Ignore;
            }
            let Some(transition) = self.invocation_transition(state, invocation, None) else {
                return Propagation::Ignore;
            };
            next = transition.state;
            // The callsite belongs to the trusted implementation, so its
            // explicit evidence is interpreted before opacity stops any
            // remaining obligations at the parent function boundary.
            if matches!(
                next.termination,
                Some(ObligationTermination::Satisfaction(_))
            ) {
                return Propagation::Follow(next);
            }
        }
        let parent = match edge {
            PropagationEdge::Invocation(invocation) => self.graph.invocation(invocation).caller(),
            PropagationEdge::TransparentBody(edge) => cx.graph().transparent_parent(edge),
            PropagationEdge::ContractHandoff => {
                unreachable!("contract handoffs are created by the tracing engine")
            }
        };
        next.current_function = parent;
        if !self.trusts_function(&state.effect, parent) {
            next.trust_path.enter(self.graph, parent);
        }
        if self.trusts_function(&state.effect, parent)
            && next.trust_path.allows_boundary(self.graph, parent)
        {
            next.termination = Some(ObligationTermination::TrustedBoundary);
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
            TraceSite::Invocation(_)
                if matches!(
                    state.termination,
                    Some(ObligationTermination::Satisfaction(_))
                ) =>
            {
                state.termination
            }
            TraceSite::Function(_)
                if state.termination == Some(ObligationTermination::TrustedBoundary) =>
            {
                state.termination
            }
            TraceSite::Function(_) | TraceSite::Source(_) | TraceSite::Invocation(_) => None,
        }
    }
}

fn collect_obligations(
    annotation: &FunctionContractAnnotation,
    contract: ContractId,
    obligations: &mut BTreeMap<ObligationId, Obligation>,
) -> BTreeSet<ObligationId> {
    if annotation.requirements().is_empty() {
        let id = ObligationId { contract, index: 0 };
        obligations.insert(id, Obligation::WholeContract);
        return BTreeSet::from([id]);
    }
    annotation
        .requirements()
        .iter()
        .enumerate()
        .map(|(index, requirement)| {
            let id = ObligationId { contract, index };
            let obligation = if requirement.name.is_empty() {
                Obligation::Structured(requirement.structural_path.clone())
            } else {
                Obligation::Named(normalize_requirement_name(&requirement.name))
            };
            obligations.insert(id, obligation);
            id
        })
        .collect()
}

/// Concrete propagation state exposes only its current runtime target. This
/// lets the shared tracker reject declaration-only edges while contract
/// carriers deliberately traverse those edges.
pub(crate) trait ConcreteState {
    fn current_function(&self) -> FunctionId;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum TrackedOrigin<O> {
    Concrete(O),
    Contract(ContractId),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum TrackedState<S> {
    Concrete(S),
    Obligation(ObligationState),
}

impl<S> TrackedState<S> {
    #[must_use]
    pub(crate) const fn obligation(&self) -> Option<&ObligationState> {
        match self {
            Self::Concrete(_) => None,
            Self::Obligation(state) => Some(state),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrackedTermination<T> {
    Concrete(T),
    Obligation(ObligationTermination),
}

/// One effect-domain trace containing both compiler-discovered operations and
/// documentation-derived contract carriers. `ObligationTracker` supplies the
/// shared contract semantics; the concrete policy supplies only seed-specific
/// source handling.
pub(crate) struct TrackedEffect<'effect, 'annotations, C> {
    concrete: &'effect C,
    obligations: &'effect ObligationTracker<'annotations>,
    effect: EffectKey,
}

impl<'effect, 'annotations, C> TrackedEffect<'effect, 'annotations, C> {
    #[must_use]
    pub(crate) fn new(
        concrete: &'effect C,
        obligations: &'effect ObligationTracker<'annotations>,
        effect: EffectKey,
    ) -> Self {
        Self {
            concrete,
            obligations,
            effect,
        }
    }

    #[must_use]
    pub(crate) const fn obligations(&self) -> &ObligationTracker<'annotations> {
        self.obligations
    }

    /// Returns every justification that consumed at least one contract
    /// requirement in this domain's unified trace.
    pub(crate) fn obligation_marker_uses<O: Clone, S, T>(
        &self,
        trace: &EffectTrace<TrackedOrigin<O>, TrackedState<S>, TrackedTermination<T>>,
    ) -> Vec<ObligationMarkerUse> {
        let nodes = trace.nodes().collect::<Vec<_>>();
        let mut uses = Vec::new();
        for edge in trace.edges() {
            let PropagationEdge::Invocation(invocation) = edge.propagation() else {
                continue;
            };
            let TrackedState::Obligation(state) = nodes[edge.from().index()].state() else {
                continue;
            };
            if let Some(transition) =
                self.obligations
                    .invocation_transition(state, invocation, Some(edge.from()))
            {
                uses.extend(transition.marker_uses);
            }
        }
        for handled in trace.handled() {
            let (Some(node), TerminationSite::Invocation(invocation)) =
                (handled.node(), handled.site())
            else {
                continue;
            };
            let TrackedState::Obligation(state) = nodes[node.index()].state() else {
                continue;
            };
            if let Some(transition) =
                self.obligations
                    .invocation_transition(state, *invocation, Some(node))
            {
                uses.extend(transition.marker_uses);
            }
        }
        uses.sort();
        uses.dedup();
        uses
    }
}

impl<C> TracePolicy for TrackedEffect<'_, '_, C>
where
    C: TracePolicy,
    C::Origin: Clone + Eq + Hash,
    C::State: ConcreteState + Clone + Eq + Hash,
{
    type Origin = TrackedOrigin<C::Origin>;
    type State = TrackedState<C::State>;
    type Termination = TrackedTermination<C::Termination>;

    fn sources(&self) -> impl Iterator<Item = EffectSeed<Self::Origin, Self::State>> + '_ {
        self.concrete
            .sources()
            .map(|seed| {
                EffectSeed::new(
                    TrackedOrigin::Concrete(seed.origin),
                    seed.owner,
                    TrackedState::Concrete(seed.state),
                )
            })
            .chain(
                self.obligations
                    .sources()
                    .filter(|seed| seed.state.effect == self.effect)
                    .map(|seed| {
                        EffectSeed::new(
                            TrackedOrigin::Contract(seed.origin),
                            seed.owner,
                            TrackedState::Obligation(seed.state),
                        )
                    }),
            )
    }

    fn handoff(
        &self,
        _cx: &TraceCx<'_>,
        state: &Self::State,
        function: FunctionId,
    ) -> Option<Self::State> {
        match state {
            TrackedState::Concrete(_) => self
                .obligations
                .contract_state(function, &self.effect, None)
                .map(TrackedState::Obligation),
            TrackedState::Obligation(state) => self
                .obligations
                .contract_state(function, &self.effect, Some(state))
                .map(TrackedState::Obligation),
        }
    }

    fn propagate(
        &self,
        cx: &TraceCx<'_>,
        state: &Self::State,
        edge: PropagationEdge,
    ) -> Propagation<Self::State> {
        match state {
            TrackedState::Concrete(state) => {
                if let PropagationEdge::Invocation(invocation) = edge
                    && !self
                        .obligations
                        .graph
                        .invocation(invocation)
                        .function_targets()
                        .any(|target| target == state.current_function())
                {
                    return Propagation::Ignore;
                }
                match self.concrete.propagate(cx, state, edge) {
                    Propagation::Follow(next) => Propagation::Follow(TrackedState::Concrete(next)),
                    Propagation::Ignore => Propagation::Ignore,
                    Propagation::Unknown(boundary) => Propagation::Unknown(boundary),
                }
            }
            TrackedState::Obligation(state) => match self.obligations.propagate(cx, state, edge) {
                Propagation::Follow(next) => Propagation::Follow(TrackedState::Obligation(next)),
                Propagation::Ignore => Propagation::Ignore,
                Propagation::Unknown(boundary) => Propagation::Unknown(boundary),
            },
        }
    }

    fn terminate(
        &self,
        cx: &TraceCx<'_>,
        state: &Self::State,
        site: TraceSite<'_, Self::Origin>,
    ) -> Option<Self::Termination> {
        match (state, site) {
            (TrackedState::Concrete(state), TraceSite::Source(TrackedOrigin::Concrete(origin))) => {
                self.concrete
                    .terminate(cx, state, TraceSite::Source(origin))
                    .map(TrackedTermination::Concrete)
            }
            (TrackedState::Concrete(state), TraceSite::Function(function)) => self
                .concrete
                .terminate(cx, state, TraceSite::Function(function))
                .map(TrackedTermination::Concrete),
            (TrackedState::Concrete(state), TraceSite::Invocation(invocation)) => self
                .concrete
                .terminate(cx, state, TraceSite::Invocation(invocation))
                .map(TrackedTermination::Concrete),
            (
                TrackedState::Obligation(state),
                TraceSite::Source(TrackedOrigin::Contract(origin)),
            ) => self
                .obligations
                .terminate(cx, state, TraceSite::Source(origin))
                .map(TrackedTermination::Obligation),
            (TrackedState::Obligation(state), TraceSite::Function(function)) => self
                .obligations
                .terminate(cx, state, TraceSite::Function(function))
                .map(TrackedTermination::Obligation),
            (TrackedState::Obligation(state), TraceSite::Invocation(invocation)) => self
                .obligations
                .terminate(cx, state, TraceSite::Invocation(invocation))
                .map(TrackedTermination::Obligation),
            (TrackedState::Concrete(_), TraceSite::Source(TrackedOrigin::Contract(_)))
            | (TrackedState::Obligation(_), TraceSite::Source(TrackedOrigin::Concrete(_))) => None,
        }
    }
}
