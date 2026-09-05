use std::collections::{BTreeMap, BTreeSet};

use effect_tracing::{
    Effect, EffectSeed, EffectTrace, FunctionId, InvocationId, Propagation, PropagationEdge,
    TerminationSite, TraceCx, TraceNodeId, TraceSite,
};

use crate::annotations::{
    AnnotationDomain, AnnotationId, AnnotationIndex, FunctionContractAnnotation,
};
use crate::artifact::{ArtifactFacts, CallId, DefinitionNamespaceIndex};
use crate::compiler::invocations::InvocationGraph;
use crate::config::{EffectDocMatching, PanicConfig, SafetyConfig};
use crate::contracts::normalize_requirement_name;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum CommentDomain {
    Panic,
    Safety,
}

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
pub(crate) struct CommentState {
    domain: CommentDomain,
    contract: ContractId,
    // One invocation may contain concrete and declaration targets. Retaining
    // the current target lets propagation gate only the declaration edge.
    current_function: FunctionId,
    source_invocation: Option<InvocationId>,
    source_calls: BTreeSet<CallId>,
    remaining: BTreeSet<ObligationId>,
    termination: Option<CommentTermination>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum CommentTermination {
    Satisfaction(AnnotationId),
    TrustedBoundary,
}

impl CommentState {
    #[must_use]
    pub(crate) fn remaining(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        self.remaining.iter().map(|obligation| obligation.index)
    }

    #[must_use]
    pub(crate) const fn domain(&self) -> CommentDomain {
        self.domain
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
pub(crate) struct CommentMarkerUse {
    annotation: AnnotationId,
    domain: CommentDomain,
    invocation: InvocationId,
    source_invocation: InvocationId,
    source_calls: BTreeSet<CallId>,
    node: TraceNodeId,
}

impl CommentMarkerUse {
    #[must_use]
    pub(crate) const fn annotation(&self) -> AnnotationId {
        self.annotation
    }

    #[must_use]
    pub(crate) const fn domain(&self) -> CommentDomain {
        self.domain
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

struct CommentInvocationTransition {
    state: CommentState,
    marker_uses: Vec<CommentMarkerUse>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommentContract {
    id: ContractId,
    functions: BTreeSet<FunctionId>,
    domain: CommentDomain,
    obligations: BTreeSet<ObligationId>,
}

impl CommentContract {
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

pub(crate) struct CommentEffect<'annotations> {
    annotations: &'annotations AnnotationIndex,
    graph: &'annotations InvocationGraph,
    contracts: Vec<CommentContract>,
    obligations: BTreeMap<ObligationId, Obligation>,
    effect_doc_matching: EffectDocMatching,
    trusted_panic_functions: BTreeSet<FunctionId>,
    trusted_safety_functions: BTreeSet<FunctionId>,
    ignored_panic_invocations: BTreeSet<InvocationId>,
}

impl<'annotations> CommentEffect<'annotations> {
    pub(crate) fn probe(
        artifact: &ArtifactFacts,
        graph: &'annotations InvocationGraph,
        annotations: &'annotations AnnotationIndex,
        namespaces: &DefinitionNamespaceIndex,
        effect_doc_matching: EffectDocMatching,
        panic_config: &PanicConfig,
        safety_config: &SafetyConfig,
    ) -> Self {
        let mut contracts = Vec::new();
        let mut obligations = BTreeMap::new();
        for annotation in annotations.contracts() {
            let functions = graph
                .contract_targets(annotation.owner())
                .into_iter()
                .filter(|function| {
                    annotations
                        .effective_contract(graph, *function, annotation.domain())
                        .is_some_and(|selected| selected.id() == annotation.id())
                })
                .collect::<BTreeSet<_>>();
            if functions.is_empty() {
                continue;
            }
            let id = ContractId(annotation.id());
            let contract_obligations = collect_obligations(annotation, id, &mut obligations);
            contracts.push(CommentContract {
                id,
                functions,
                domain: annotation.domain().into(),
                obligations: contract_obligations,
            });
        }
        let mut trusted_panic_functions = BTreeSet::new();
        let mut trusted_safety_functions = BTreeSet::new();
        for body in &artifact.functions {
            let candidates = namespaces.candidates(body.function);
            if panic_config.panic_boundary_policy_candidates(candidates)
                == crate::config::PanicBoundaryPolicy::TrustedBoundary
            {
                trusted_panic_functions.extend(graph.function_aliases(body.function));
            }
            if safety_config.trusts_safety_boundary_candidates(candidates) {
                trusted_safety_functions.extend(graph.function_aliases(body.function));
            }
        }
        let ignored_panic_invocations = graph
            .invocations()
            .filter(|invocation| {
                invocation
                    .macro_provenance()
                    .iter()
                    .any(|frame| panic_config.ignores_path(&frame.display_path))
            })
            .map(crate::compiler::invocations::Invocation::id)
            .collect();
        Self {
            annotations,
            graph,
            contracts,
            obligations,
            effect_doc_matching,
            trusted_panic_functions,
            trusted_safety_functions,
            ignored_panic_invocations,
        }
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn contracts(&self) -> &[CommentContract] {
        &self.contracts
    }

    #[must_use]
    pub(crate) fn contract(&self, id: ContractId) -> Option<&CommentContract> {
        self.contracts.iter().find(|contract| contract.id == id)
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn contract_count(&self, domain: CommentDomain) -> usize {
        self.contracts
            .iter()
            .filter(|contract| contract.domain == domain)
            .count()
    }

    fn apply_satisfaction(
        &self,
        state: &mut CommentState,
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

    pub(crate) fn trusts_function(&self, domain: CommentDomain, function: FunctionId) -> bool {
        match domain {
            CommentDomain::Panic => &self.trusted_panic_functions,
            CommentDomain::Safety => &self.trusted_safety_functions,
        }
        .contains(&function)
    }

    fn invocation_transition(
        &self,
        state: &CommentState,
        invocation: InvocationId,
        node: Option<TraceNodeId>,
    ) -> Option<CommentInvocationTransition> {
        if state.domain == CommentDomain::Panic
            && self.ignored_panic_invocations.contains(&invocation)
        {
            return None;
        }
        if state.domain == CommentDomain::Safety
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
        let domain = AnnotationDomain::from(state.domain);
        let mut marker_uses = Vec::new();
        for call in relevant_calls {
            for comment in self
                .annotations
                .comments_at_raw_call(invocation, call, domain)
            {
                let before = next.remaining.len();
                for satisfaction in comment.satisfactions() {
                    self.apply_satisfaction(&mut next, satisfaction);
                }
                if next.remaining.len() < before
                    && let Some(node) = node
                {
                    marker_uses.push(CommentMarkerUse {
                        annotation: comment.id(),
                        domain: state.domain,
                        invocation,
                        source_invocation,
                        source_calls: next.source_calls.clone(),
                        node,
                    });
                }
                if before > 0 && next.remaining.is_empty() {
                    next.termination = Some(CommentTermination::Satisfaction(comment.id()));
                }
            }
        }
        Some(CommentInvocationTransition {
            state: next,
            marker_uses,
        })
    }

    fn crosses_non_applicable_declaration(
        &self,
        state: &CommentState,
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

    /// Returns every marker that actually removed at least one remaining
    /// obligation on a traced invocation transition. This includes partial
    /// satisfactions that do not terminate the comment effect.
    pub(crate) fn marker_uses(
        &self,
        trace: &EffectTrace<ContractId, CommentState, CommentTermination>,
    ) -> Vec<CommentMarkerUse> {
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

impl Effect for CommentEffect<'_> {
    type Origin = ContractId;
    type State = CommentState;
    type Termination = CommentTermination;

    fn sources(&self) -> impl Iterator<Item = EffectSeed<Self::Origin, Self::State>> + '_ {
        self.contracts.iter().flat_map(|contract| {
            contract.functions.iter().copied().map(move |function| {
                EffectSeed::new(
                    contract.id,
                    function,
                    CommentState {
                        domain: contract.domain,
                        contract: contract.id,
                        current_function: function,
                        source_invocation: None,
                        source_calls: BTreeSet::new(),
                        remaining: contract.obligations.clone(),
                        termination: None,
                    },
                )
            })
        })
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
            if matches!(next.termination, Some(CommentTermination::Satisfaction(_))) {
                return Propagation::Follow(next);
            }
        }
        let parent = match edge {
            PropagationEdge::Invocation(invocation) => self.graph.invocation(invocation).caller(),
            PropagationEdge::TransparentBody(edge) => cx.graph().transparent_parent(edge),
        };
        next.current_function = parent;
        if self.trusts_function(state.domain, parent) {
            next.termination = Some(CommentTermination::TrustedBoundary);
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
                if matches!(state.termination, Some(CommentTermination::Satisfaction(_))) =>
            {
                state.termination
            }
            TraceSite::Function(_)
                if state.termination == Some(CommentTermination::TrustedBoundary) =>
            {
                state.termination
            }
            TraceSite::Source(_) | TraceSite::Function(_) | TraceSite::Invocation(_) => None,
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

impl From<AnnotationDomain> for CommentDomain {
    fn from(value: AnnotationDomain) -> Self {
        match value {
            AnnotationDomain::Panic => Self::Panic,
            AnnotationDomain::Safety => Self::Safety,
        }
    }
}

impl From<CommentDomain> for AnnotationDomain {
    fn from(value: CommentDomain) -> Self {
        match value {
            CommentDomain::Panic => Self::Panic,
            CommentDomain::Safety => Self::Safety,
        }
    }
}
