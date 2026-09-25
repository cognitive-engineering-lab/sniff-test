use std::collections::BTreeSet;

use effect_tracing::{
    Effect, EffectSeed, EffectTrace, FunctionId, InvocationId, Propagation, PropagationEdge,
    TerminationSite, TraceCx, TraceNodeId, TraceSite,
};

use crate::annotations::{
    AnnotationDomain, AnnotationId, AnnotationIndex, FunctionContractAnnotation,
};
use crate::artifact::{
    ArtifactFacts, CallId, CallKindFact, DefinitionNamespaceIndex, FunctionId as StableFunctionId,
};
use crate::compiler::invocations::InvocationGraph;
use crate::config::{EffectDocMatching, PanicConfig, SafetyConfig};
use crate::contracts::normalize_requirement_name;
use crate::effects::EffectSelection;

use super::trust::TrustPath;

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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CommentState {
    domain: CommentDomain,
    contract: ContractId,
    // One invocation may contain concrete and declaration targets. Retaining
    // the current target lets propagation gate only the declaration edge.
    current_function: FunctionId,
    source_invocation: Option<InvocationId>,
    source_calls: BTreeSet<CallId>,
    remaining: BTreeSet<usize>,
    termination: Option<CommentTermination>,
    trust_path: TrustPath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum CommentTermination {
    Satisfaction(AnnotationId),
    Contract(AnnotationId),
    TrustedBoundary,
}

impl CommentState {
    #[must_use]
    pub(crate) fn trust_path(&self) -> &TrustPath {
        &self.trust_path
    }

    #[must_use]
    pub(crate) fn remaining(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        self.remaining.iter().copied()
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
    obligations: Vec<Obligation>,
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
    effect_doc_matching: EffectDocMatching,
    trusted_panic_functions: BTreeSet<FunctionId>,
    trusted_safety_functions: BTreeSet<FunctionId>,
    trusted_panic_invocations: BTreeSet<InvocationId>,
    trusted_safety_invocations: BTreeSet<InvocationId>,
    ignored_panic_invocations: BTreeSet<InvocationId>,
    ignored_safety_invocations: BTreeSet<InvocationId>,
}

impl<'annotations> CommentEffect<'annotations> {
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
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
        for annotation in annotations.contracts() {
            if (annotation.domain() == AnnotationDomain::Panic && !effects.tracks_panic())
                || (annotation.domain() == AnnotationDomain::Safety && !effects.tracks_safety())
            {
                continue;
            }
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
            contracts.push(CommentContract {
                id,
                functions,
                domain: annotation.domain().into(),
                obligations: collect_obligations(annotation),
            });
        }
        let mut trusted_panic_functions = BTreeSet::new();
        let mut trusted_safety_functions = BTreeSet::new();
        for body in &artifact.functions {
            let candidates = namespaces.candidates(body.function);
            if effects.tracks_panic()
                && panic_config.panic_boundary_policy_candidates(candidates)
                    == crate::config::PanicBoundaryPolicy::TrustedBoundary
            {
                trusted_panic_functions.extend(graph.function_aliases(body.function));
            }
            if effects.tracks_safety()
                && safety_config.trusts_safety_boundary_candidates(candidates)
            {
                trusted_safety_functions.extend(graph.function_aliases(body.function));
            }
        }
        let mut trusted_panic_invocations = BTreeSet::new();
        let mut trusted_safety_invocations = BTreeSet::new();
        for invocation in graph.invocations() {
            for edge in graph.source_edges(invocation.id()) {
                // A macro's own public contract remains visible. Only its
                // ancestors can make this invocation an implementation detail.
                let ancestor_count = edge
                    .macro_expansions
                    .len()
                    .saturating_sub(usize::from(edge.kind == CallKindFact::MacroExpansion));
                for frame in &edge.macro_expansions[..ancestor_count] {
                    let candidates =
                        namespaces.candidates(StableFunctionId::generic(frame.macro_def));
                    let candidates = if candidates.is_empty() {
                        std::slice::from_ref(&frame.display_path)
                    } else {
                        candidates
                    };
                    if panic_config.panic_boundary_policy_candidates(candidates)
                        == crate::config::PanicBoundaryPolicy::TrustedBoundary
                    {
                        trusted_panic_invocations.insert(invocation.id());
                    }
                    if safety_config.trusts_safety_boundary_candidates(candidates) {
                        trusted_safety_invocations.insert(invocation.id());
                    }
                }
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
        Self {
            annotations,
            graph,
            contracts,
            effect_doc_matching,
            trusted_panic_functions,
            trusted_safety_functions,
            trusted_panic_invocations,
            trusted_safety_invocations,
            ignored_panic_invocations,
            ignored_safety_invocations,
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
        let Some(contract) = self.contract(state.contract) else {
            return;
        };
        let required = match satisfaction.requirement.as_deref() {
            Some(requirement) => Obligation::Named(normalize_requirement_name(requirement)),
            None => satisfaction
                .structural_path
                .as_ref()
                .map_or(Obligation::WholeContract, |path| {
                    Obligation::Structured(path.clone())
                }),
        };
        // Ambiguity depends on the complete contract, including satisfied requirements.
        let mut matching = contract
            .obligations
            .iter()
            .enumerate()
            .filter_map(|(index, obligation)| (obligation == &required).then_some(index));
        if let Some(index) = matching.next()
            && matching.next().is_none()
        {
            state.remaining.remove(&index);
        }
    }

    pub(crate) fn trusts_function(&self, domain: CommentDomain, function: FunctionId) -> bool {
        match domain {
            CommentDomain::Panic => &self.trusted_panic_functions,
            CommentDomain::Safety => &self.trusted_safety_functions,
        }
        .contains(&function)
    }

    fn trusts_invocation(&self, domain: CommentDomain, invocation: InvocationId) -> bool {
        match domain {
            CommentDomain::Panic => &self.trusted_panic_invocations,
            CommentDomain::Safety => &self.trusted_safety_invocations,
        }
        .contains(&invocation)
    }

    #[must_use]
    pub(crate) fn is_ignored_invocation(
        &self,
        domain: CommentDomain,
        invocation: InvocationId,
    ) -> bool {
        match domain {
            CommentDomain::Panic => &self.ignored_panic_invocations,
            CommentDomain::Safety => &self.ignored_safety_invocations,
        }
        .contains(&invocation)
    }

    fn invocation_transition(
        &self,
        state: &CommentState,
        invocation: InvocationId,
        node: Option<TraceNodeId>,
    ) -> Option<CommentInvocationTransition> {
        if self.is_ignored_invocation(state.domain, invocation) {
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
        self.contracts.iter().flat_map(move |contract| {
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
                        remaining: (0..contract.obligations.len()).collect(),
                        termination: None,
                        trust_path: if self.trusts_function(contract.domain, function) {
                            TrustPath::default()
                        } else {
                            TrustPath::new(self.graph, function)
                        },
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
        if !self.trusts_function(state.domain, parent) {
            next.trust_path.enter(self.graph, parent);
        }
        if self.trusts_function(state.domain, parent)
            && next.trust_path.allows_boundary(self.graph, parent)
        {
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
            TraceSite::Invocation(invocation)
                if self.trusts_invocation(state.domain, invocation) =>
            {
                Some(CommentTermination::TrustedBoundary)
            }
            TraceSite::Function(_)
                if state.termination == Some(CommentTermination::TrustedBoundary) =>
            {
                state.termination
            }
            TraceSite::Function(function) => self
                .annotations
                .effective_contract(self.graph, function, state.domain.into())
                .filter(|contract| {
                    // Export the source contract itself, but let a caller's
                    // contract replace obligations arriving from its body.
                    contract.id() != state.contract.annotation()
                        || state.source_invocation.is_some()
                })
                .map(|contract| CommentTermination::Contract(contract.id())),
            TraceSite::Source(_) | TraceSite::Invocation(_) => None,
        }
    }
}

fn collect_obligations(annotation: &FunctionContractAnnotation) -> Vec<Obligation> {
    if annotation.requirements().is_empty() {
        return vec![Obligation::WholeContract];
    }
    annotation
        .requirements()
        .iter()
        .map(|requirement| {
            if requirement.name.is_empty() {
                Obligation::Structured(requirement.structural_path.clone())
            } else {
                Obligation::Named(normalize_requirement_name(&requirement.name))
            }
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
