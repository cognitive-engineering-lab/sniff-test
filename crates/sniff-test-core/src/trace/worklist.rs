//! Direct, path-specific propagation over the root-reachable invocation graph.
//!
//! Tracing runs in two passes. The concrete pass walks compiler-discovered
//! sources backward along body edges until each is handled, escapes, or
//! reaches a function with a documented contract, where it hands off to that
//! contract. The documentation pass then walks contract obligations backward
//! along signature edges. Handed-off and independently documented contracts
//! are seeded through the same entry point, [`Tracer::seed_documentation`].

use std::collections::{BTreeSet, HashSet, VecDeque};

use crate::artifact::EffectKey;
use crate::compiler::invocations::InvocationGraph;
use crate::effects::concrete::{
    ConcreteEffect, ConcreteEffectState, ConcreteSource, ConcreteTermination,
};
use crate::effects::obligation::{
    ContractId, ObligationTermination, TrackedEffect, TrackedOrigin, TrackedState,
    TrackedTermination,
};

use super::routes::{EdgeScope, RootRoutes};
use super::{
    EffectTrace, FunctionId, HandledTrace, InvocationId, Propagation, PropagationEdge,
    TerminationSite, TraceEdge, TraceEdgeId, TraceNode, TraceNodeId, TraceOutcome, TraceSite,
    UnknownBoundary, UnknownBoundaryKind, UnknownTrace,
};

pub type DomainTrace = EffectTrace<
    TrackedOrigin<ConcreteSource>,
    TrackedState<ConcreteEffectState>,
    TrackedTermination<ConcreteTermination>,
>;

type Origin = TrackedOrigin<ConcreteSource>;
type State = TrackedState<ConcreteEffectState>;
type Termination = TrackedTermination<ConcreteTermination>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceOptions {
    pub max_depth: usize,
    pub state_budget: usize,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            max_depth: 256,
            state_budget: 1_000_000,
        }
    }
}

/// Trace one effect along the routes discovered from the report roots.
#[must_use]
pub fn trace_effect(
    graph: &InvocationGraph,
    tracked: &TrackedEffect<'_, '_, ConcreteEffect<'_>>,
    effect: &EffectKey,
    options: TraceOptions,
    routes: &RootRoutes,
) -> DomainTrace {
    let mut tracer = Tracer {
        graph,
        tracked,
        effect,
        options,
        routes,
        trace: DomainTrace::default(),
        concrete_queue: VecDeque::new(),
        documentation_queue: VecDeque::new(),
        seen: HashSet::new(),
        reached: BTreeSet::new(),
    };
    tracer.concrete_pass();
    tracer.documentation_pass();
    tracer.trace
}

/// A documented contract obligation entering the documentation pass.
#[derive(Clone, Copy)]
struct DocumentationSeed {
    contract: ContractId,
    function: FunctionId,
    /// The node whose path reached `function`'s contract. Its trust context
    /// and depth carry over; an independent seed starts a fresh path.
    handoff_from: Option<TraceNodeId>,
}

struct Tracer<'t, 'e, 'a, 'c> {
    graph: &'t InvocationGraph,
    tracked: &'t TrackedEffect<'e, 'a, ConcreteEffect<'c>>,
    effect: &'t EffectKey,
    options: TraceOptions,
    routes: &'t RootRoutes,
    trace: DomainTrace,
    concrete_queue: VecDeque<TraceNodeId>,
    documentation_queue: VecDeque<TraceNodeId>,
    seen: HashSet<(Origin, FunctionId, State, usize)>,
    reached: BTreeSet<(ContractId, FunctionId)>,
}

impl Tracer<'_, '_, '_, '_> {
    fn concrete_pass(&mut self) {
        let concrete = self.tracked.concrete();
        for seed in concrete.sources() {
            if !self.routes.admits(seed.owner, EdgeScope::Body) {
                continue;
            }
            let origin = TrackedOrigin::Concrete(seed.origin);
            if let Some(termination) =
                concrete.terminate(&seed.state, TraceSite::Source(&seed.origin))
            {
                self.handled(
                    origin,
                    None,
                    TerminationSite::Source(origin),
                    TrackedTermination::Concrete(termination),
                );
            } else if let Some(node) = self.add_node(
                origin,
                seed.owner,
                TrackedState::Concrete(seed.state),
                0,
                None,
                true,
            ) {
                self.concrete_queue.push_back(node);
            }
        }
        while let Some(node) = self.concrete_queue.pop_front() {
            self.visit(node);
        }
    }

    /// Drains contracts handed off by the concrete pass, then seeds each
    /// independently documented contract that no handoff reached.
    fn documentation_pass(&mut self) {
        self.drain_documentation();
        for (contract, function) in self.independent_sites() {
            if !self.routes.admits(function, EdgeScope::Signature)
                || self.reached.contains(&(contract, function))
            {
                continue;
            }
            self.seed_documentation(DocumentationSeed {
                contract,
                function,
                handoff_from: None,
            });
            self.drain_documentation();
        }
    }

    fn drain_documentation(&mut self) {
        while let Some(node) = self.documentation_queue.pop_front() {
            self.visit(node);
        }
    }

    /// Contract sites ordered by how many other contract sites are upstream.
    fn independent_sites(&self) -> Vec<(ContractId, FunctionId)> {
        let mut sites = self
            .tracked
            .obligations()
            .contract_sites(self.effect)
            .collect::<Vec<_>>();
        if sites.len() > 1 {
            let mut upstream = UpstreamCounts::new(
                self.graph.function_count(),
                sites.iter().map(|&(_, function)| function),
            );
            sites.sort_by_cached_key(|&(_, function)| {
                std::cmp::Reverse(upstream.count(self.graph, function))
            });
        }
        sites
    }

    /// The only constructor of obligation nodes.
    fn seed_documentation(&mut self, seed: DocumentationSeed) {
        let DocumentationSeed {
            contract,
            function,
            handoff_from,
        } = seed;
        let (trust, depth, predecessor) = match handoff_from {
            Some(parent) => {
                if self.contract_in_ancestry(parent, contract) {
                    let origin = *self.trace.nodes[parent.index()].origin();
                    self.unknown_at(origin, parent, UnknownBoundaryKind::Cycle);
                    return;
                }
                let node = &self.trace.nodes[parent.index()];
                let trust = match node.state() {
                    TrackedState::Concrete(state) => state.trust_path().clone(),
                    TrackedState::Obligation(state) => state.trust_path().clone(),
                };
                (
                    Some(trust),
                    node.depth(),
                    Some((parent, PropagationEdge::Handoff)),
                )
            }
            None => (None, 0, None),
        };
        let Some(seed) = self
            .tracked
            .obligations()
            .seed_at(contract, function, trust)
        else {
            return;
        };
        self.reached.insert((contract, function));
        if let Some(node) = self.add_node(
            TrackedOrigin::Contract(contract),
            function,
            TrackedState::Obligation(seed.state),
            depth,
            predecessor,
            false,
        ) {
            self.documentation_queue.push_back(node);
        }
    }

    fn visit(&mut self, node: TraceNodeId) {
        let current = &self.trace.nodes[node.index()];
        let (origin, function) = (*current.origin(), current.function());
        if let Some((termination, handoff)) = self.function_stop(node) {
            self.handled(
                origin,
                Some(node),
                TerminationSite::Function(function),
                termination,
            );
            if let Some(contract) = handoff {
                self.seed_documentation(DocumentationSeed {
                    contract,
                    function,
                    handoff_from: Some(node),
                });
            }
            return;
        }
        self.step_to_callers(node);
    }

    /// Whether `node` stops at its function, and the contract it hands off
    /// to there. A contract boundary takes any path except an obligation
    /// still at its own contract's function.
    fn function_stop(&self, node: TraceNodeId) -> Option<(Termination, Option<ContractId>)> {
        let current = &self.trace.nodes[node.index()];
        let function = current.function();
        let boundary = self
            .tracked
            .obligations()
            .boundary_contract(function, self.effect);
        match current.state() {
            TrackedState::Concrete(state) => {
                if let Some(contract) = boundary {
                    return Some((TrackedTermination::ContractBoundary, Some(contract)));
                }
                self.tracked
                    .concrete()
                    .terminate(state, TraceSite::Function(function))
                    .map(|termination| (TrackedTermination::Concrete(termination), None))
            }
            TrackedState::Obligation(state) => {
                if let Some(contract) = boundary
                    && (state.contract() != contract || state.source_invocation().is_some())
                {
                    return Some((
                        TrackedTermination::Obligation(ObligationTermination::ContractBoundary),
                        Some(contract),
                    ));
                }
                self.tracked
                    .obligations()
                    .terminate(state, TraceSite::Function(function))
                    .map(|termination| (TrackedTermination::Obligation(termination), None))
            }
        }
    }

    fn step_to_callers(&mut self, node: TraceNodeId) {
        let routes = self.routes;
        let current = &self.trace.nodes[node.index()];
        let (origin, function, depth) = (*current.origin(), current.function(), current.depth());
        let scope = match current.state() {
            TrackedState::Concrete(_) => EdgeScope::Body,
            TrackedState::Obligation(_) => EdgeScope::Signature,
        };
        if routes.parents(function, scope).next().is_none() {
            self.escaped(origin, node);
            return;
        }
        if depth >= self.options.max_depth {
            self.unknown_at(origin, node, UnknownBoundaryKind::TraceDepth);
            return;
        }
        for (edge, parent) in routes.parents(function, scope) {
            match self.propagate(node, edge) {
                Propagation::Follow(next) => {
                    if let Some((invocation, termination)) =
                        self.invocation_termination(&next, edge)
                    {
                        self.handled(
                            origin,
                            Some(node),
                            TerminationSite::Invocation(invocation),
                            termination,
                        );
                        continue;
                    }
                    // Concrete paths entering a contract stay distinct, since
                    // each one hands off with its own trust context.
                    let dedup = matches!(next, TrackedState::Concrete(_))
                        && self
                            .tracked
                            .obligations()
                            .boundary_contract(parent, self.effect)
                            .is_none();
                    if let Some(child) =
                        self.add_node(origin, parent, next, depth + 1, Some((node, edge)), dedup)
                    {
                        match self.trace.nodes[child.index()].state() {
                            TrackedState::Concrete(_) => self.concrete_queue.push_back(child),
                            TrackedState::Obligation(_) => {
                                self.documentation_queue.push_back(child);
                            }
                        }
                    }
                }
                Propagation::Ignore => {}
                Propagation::Unknown(boundary) => {
                    self.unknown_boundary(origin, node, boundary);
                }
            }
        }
    }

    fn propagate(&self, node: TraceNodeId, edge: PropagationEdge) -> Propagation<State> {
        match self.trace.nodes[node.index()].state() {
            TrackedState::Concrete(state) => self
                .tracked
                .concrete()
                .propagate(state, edge)
                .map(TrackedState::Concrete),
            TrackedState::Obligation(state) => self
                .tracked
                .obligations()
                .propagate(state, edge)
                .map(TrackedState::Obligation),
        }
    }

    fn invocation_termination(
        &self,
        state: &State,
        edge: PropagationEdge,
    ) -> Option<(InvocationId, Termination)> {
        let PropagationEdge::Invocation(invocation) = edge else {
            return None;
        };
        let termination = match state {
            TrackedState::Concrete(state) => self
                .tracked
                .concrete()
                .terminate(state, TraceSite::Invocation(invocation))
                .map(TrackedTermination::Concrete),
            TrackedState::Obligation(state) => self
                .tracked
                .obligations()
                .terminate(state, TraceSite::Invocation(invocation))
                .map(TrackedTermination::Obligation),
        }?;
        Some((invocation, termination))
    }

    /// Appends a node unless it would repeat an ancestor, or, with `dedup`,
    /// repeat an already explored position.
    fn add_node(
        &mut self,
        origin: Origin,
        function: FunctionId,
        state: State,
        depth: usize,
        predecessor: Option<(TraceNodeId, PropagationEdge)>,
        dedup: bool,
    ) -> Option<TraceNodeId> {
        if let Some((parent, _)) = predecessor
            && self.same_ancestor(parent, origin, function, &state)
        {
            self.unknown_at(origin, parent, UnknownBoundaryKind::Cycle);
            return None;
        }
        if dedup && !self.seen.insert((origin, function, state.clone(), depth)) {
            return None;
        }
        if self.trace.nodes.len() >= self.options.state_budget {
            let kind = UnknownBoundaryKind::TraceStateBudget;
            match predecessor {
                Some((parent, _)) => self.unknown_at(origin, parent, kind),
                None => self.detached_unknown(origin, function, state, kind),
            }
            return None;
        }
        let id = TraceNodeId(self.trace.nodes.len());
        self.trace.nodes.push(TraceNode {
            origin,
            function,
            state,
            depth,
            predecessor: None,
        });
        if let Some((from, propagation)) = predecessor {
            let edge_id = TraceEdgeId(self.trace.edges.len());
            self.trace.edges.push(TraceEdge {
                from,
                to: id,
                propagation,
            });
            self.trace.nodes[id.index()].predecessor = Some(edge_id);
        }
        Some(id)
    }

    fn ancestry(&self, node: TraceNodeId) -> impl Iterator<Item = &TraceNode<Origin, State>> {
        std::iter::successors(Some(&self.trace.nodes[node.index()]), |current| {
            current
                .predecessor()
                .map(|edge| &self.trace.nodes[self.trace.edges[edge.index()].from.index()])
        })
    }

    fn same_ancestor(
        &self,
        node: TraceNodeId,
        origin: Origin,
        function: FunctionId,
        state: &State,
    ) -> bool {
        self.ancestry(node).any(|current| {
            *current.origin() == origin
                && current.function() == function
                && current.state() == state
        })
    }

    fn contract_in_ancestry(&self, node: TraceNodeId, contract: ContractId) -> bool {
        self.ancestry(node).any(
            |current| matches!(current.origin(), TrackedOrigin::Contract(id) if *id == contract),
        )
    }

    fn handled(
        &mut self,
        origin: Origin,
        node: Option<TraceNodeId>,
        site: TerminationSite<Origin>,
        termination: Termination,
    ) {
        self.trace.handled.push(HandledTrace {
            origin,
            node,
            site,
            termination,
        });
        self.trace.outcomes.push(TraceOutcome::Handled(origin));
    }

    fn escaped(&mut self, origin: Origin, node: TraceNodeId) {
        self.trace.escaped.push((origin, node));
        self.trace.outcomes.push(TraceOutcome::Escaped(origin));
    }

    fn unknown_at(&mut self, origin: Origin, node: TraceNodeId, kind: UnknownBoundaryKind) {
        self.unknown_boundary(origin, node, UnknownBoundary::new(kind));
    }

    fn unknown_boundary(&mut self, origin: Origin, node: TraceNodeId, boundary: UnknownBoundary) {
        let current = &self.trace.nodes[node.index()];
        self.trace.unknown.push(UnknownTrace {
            origin,
            node: Some(node),
            function: current.function(),
            state: current.state().clone(),
            boundary: boundary.clone(),
        });
        self.trace
            .outcomes
            .push(TraceOutcome::Unknown { origin, boundary });
    }

    fn detached_unknown(
        &mut self,
        origin: Origin,
        function: FunctionId,
        state: State,
        kind: UnknownBoundaryKind,
    ) {
        let boundary = UnknownBoundary::new(kind);
        self.trace.unknown.push(UnknownTrace {
            origin,
            node: None,
            function,
            state,
            boundary: boundary.clone(),
        });
        self.trace
            .outcomes
            .push(TraceOutcome::Unknown { origin, boundary });
    }
}

/// Scratch storage and owner counts for one effect's independent-seed ordering.
/// Candidate membership is fixed for the entire sort, including unreachable
/// seeds. Changing that set or tie order can change trace-budget outcomes.
struct UpstreamCounts {
    candidates: Vec<bool>,
    counts: Vec<Option<usize>>,
    visited: Vec<usize>,
    generation: usize,
    pending: Vec<FunctionId>,
}

impl UpstreamCounts {
    fn new(function_count: usize, candidates: impl Iterator<Item = FunctionId>) -> Self {
        let mut membership = vec![false; function_count];
        for candidate in candidates {
            membership[candidate.index()] = true;
        }
        Self {
            candidates: membership,
            counts: vec![None; function_count],
            visited: vec![0; function_count],
            generation: 0,
            pending: Vec::new(),
        }
    }

    fn count(&mut self, graph: &InvocationGraph, start: FunctionId) -> usize {
        if let Some(count) = self.counts[start.index()] {
            return count;
        }
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.visited.fill(0);
            self.generation = 1;
        }
        self.visited[start.index()] = self.generation;
        self.pending.push(start);
        let mut count = 0;
        while let Some(function) = self.pending.pop() {
            count += usize::from(self.candidates[function.index()]);
            for &invocation in graph.incoming_contract_visible_invocations(function) {
                self.visit(graph.caller(invocation));
            }
            for &edge in graph.transparent_parents(function) {
                self.visit(graph.transparent_parent(edge));
            }
        }
        self.counts[start.index()] = Some(count);
        count
    }

    fn visit(&mut self, function: FunctionId) {
        let stamp = &mut self.visited[function.index()];
        if *stamp != self.generation {
            *stamp = self.generation;
            self.pending.push(function);
        }
    }
}
