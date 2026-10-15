//! Direct, path-specific propagation over the invocation graph.

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

use super::{
    EffectTrace, FunctionId, HandledTrace, InvocationId, Propagation, PropagationEdge,
    TerminationSite, TraceEdge, TraceEdgeId, TraceNode, TraceNodeId, TraceOutcome, TraceSite,
    TransparentBodyEdgeId, UnknownBoundary, UnknownBoundaryKind, UnknownTrace,
};

pub type DomainTrace = EffectTrace<
    TrackedOrigin<ConcreteSource>,
    TrackedState<ConcreteEffectState>,
    TrackedTermination<ConcreteTermination>,
>;

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

/// The edges admitted by a walk that starts at the selected report root.
/// Contract declarations are visible at reached invocations, but are not
/// descended into as runtime bodies.
struct RootRoutes {
    concrete_reachable: BTreeSet<FunctionId>,
    contract_reachable: BTreeSet<FunctionId>,
    concrete_incoming: Vec<Vec<InvocationId>>,
    contract_incoming: Vec<Vec<InvocationId>>,
    transparent_parents: Vec<Vec<TransparentBodyEdgeId>>,
}

impl RootRoutes {
    fn from_roots(graph: &InvocationGraph, roots: &[FunctionId]) -> Self {
        let count = graph.function_count();
        let mut outgoing = vec![Vec::new(); count];
        for invocation in graph.invocations() {
            outgoing[invocation.caller().index()].push(invocation.id());
        }
        let mut transparent_children = vec![Vec::new(); count];
        for index in 0..count {
            let child = FunctionId::from_index(index);
            for &edge in graph.transparent_parents(child) {
                transparent_children[graph.transparent_parent(edge).index()].push((edge, child));
            }
        }
        let mut routes = Self {
            concrete_reachable: BTreeSet::new(),
            contract_reachable: BTreeSet::new(),
            concrete_incoming: vec![Vec::new(); count],
            contract_incoming: vec![Vec::new(); count],
            transparent_parents: vec![Vec::new(); count],
        };
        let mut queue = VecDeque::from(roots.to_vec());
        let mut visited = BTreeSet::new();
        while let Some(function) = queue.pop_front() {
            if !visited.insert(function) {
                continue;
            }
            routes.concrete_reachable.insert(function);
            routes.contract_reachable.insert(function);
            for &invocation_id in &outgoing[function.index()] {
                let invocation = graph.invocation(invocation_id);
                for target in invocation.function_targets() {
                    routes.concrete_incoming[target.index()].push(invocation_id);
                    routes.contract_incoming[target.index()].push(invocation_id);
                    queue.push_back(target);
                }
                for declaration in invocation.declaration_targets() {
                    routes.contract_incoming[declaration.index()].push(invocation_id);
                    routes.contract_reachable.insert(declaration);
                }
            }
            for &(edge, child) in &transparent_children[function.index()] {
                routes.transparent_parents[child.index()].push(edge);
                queue.push_back(child);
            }
        }
        routes
    }
}

/// Trace only routes discovered by a forward walk from the report root.
#[must_use]
pub fn trace_effect_from_roots(
    graph: &InvocationGraph,
    tracked: &TrackedEffect<'_, '_, ConcreteEffect<'_>>,
    effect: &EffectKey,
    options: TraceOptions,
    roots: &[FunctionId],
) -> DomainTrace {
    let routes = RootRoutes::from_roots(graph, roots);
    trace_effect_with_routes(graph, tracked, effect, options, &routes)
}

#[allow(
    clippy::too_many_lines,
    reason = "both direct worklists and their shared budget are visible in one traversal"
)]
fn trace_effect_with_routes(
    graph: &InvocationGraph,
    tracked: &TrackedEffect<'_, '_, ConcreteEffect<'_>>,
    effect: &EffectKey,
    options: TraceOptions,
    routes: &RootRoutes,
) -> DomainTrace {
    let mut trace = DomainTrace::default();
    let mut concrete_queue = VecDeque::new();
    let mut obligation_queue = VecDeque::new();
    let mut reached = BTreeSet::new();
    let mut concrete_seen = HashSet::new();

    for seed in tracked.concrete().sources() {
        if !routes.concrete_reachable.contains(&seed.owner) {
            continue;
        }
        if let Some(termination) = tracked
            .concrete()
            .terminate(&seed.state, TraceSite::Source(&seed.origin))
        {
            handled(
                &mut trace,
                TrackedOrigin::Concrete(seed.origin),
                None,
                TerminationSite::Source(TrackedOrigin::Concrete(seed.origin)),
                TrackedTermination::Concrete(termination),
            );
        } else if let Some(node) = add_concrete_node(
            &mut trace,
            &mut concrete_seen,
            seed.origin,
            seed.owner,
            seed.state,
            0,
            None,
            options,
            false,
        ) {
            concrete_queue.push_back(node);
        }
    }
    while let Some(node) = concrete_queue.pop_front() {
        let current = &trace.nodes[node.index()];
        let (origin, function, depth) = (*current.origin(), current.function(), current.depth());
        if let Some(contract) = tracked.obligations().boundary_contract(function, effect) {
            handled(
                &mut trace,
                origin,
                Some(node),
                TerminationSite::Function(function),
                TrackedTermination::ContractBoundary,
            );
            handoff(
                &mut trace,
                tracked,
                contract,
                function,
                node,
                depth,
                options,
                &mut obligation_queue,
                &mut reached,
            );
            continue;
        }
        let TrackedState::Concrete(concrete_state) = current.state() else {
            unreachable!()
        };
        if let Some(termination) = tracked
            .concrete()
            .terminate(concrete_state, TraceSite::Function(function))
        {
            handled(
                &mut trace,
                origin,
                Some(node),
                TerminationSite::Function(function),
                TrackedTermination::Concrete(termination),
            );
            continue;
        }
        let incoming = &routes.concrete_incoming[function.index()];
        let transparent = &routes.transparent_parents[function.index()];
        if incoming.is_empty() && transparent.is_empty() {
            escaped(&mut trace, origin, node);
            continue;
        }
        if depth >= options.max_depth && (!incoming.is_empty() || !transparent.is_empty()) {
            unknown_at(&mut trace, origin, node, UnknownBoundaryKind::TraceDepth);
            continue;
        }
        for (edge, parent) in parent_edges(graph, incoming, transparent) {
            if let PropagationEdge::Invocation(invocation) = edge
                && !graph
                    .invocation(invocation)
                    .function_targets()
                    .any(|target| target == function)
            {
                continue;
            }
            let propagation = {
                let TrackedState::Concrete(concrete_state) = trace.nodes[node.index()].state()
                else {
                    unreachable!()
                };
                tracked.concrete().propagate(concrete_state, edge)
            };
            match propagation {
                Propagation::Follow(next) => {
                    let termination = match edge {
                        PropagationEdge::Invocation(invocation) => tracked
                            .concrete()
                            .terminate(&next, TraceSite::Invocation(invocation))
                            .map(|termination| (invocation, termination)),
                        PropagationEdge::TransparentBody(_) => None,
                        PropagationEdge::Handoff => unreachable!(),
                    };
                    if let Some((invocation, termination)) = termination {
                        handled(
                            &mut trace,
                            origin,
                            Some(node),
                            TerminationSite::Invocation(invocation),
                            TrackedTermination::Concrete(termination),
                        );
                    } else if let Some(child) = add_concrete_node(
                        &mut trace,
                        &mut concrete_seen,
                        match origin {
                            TrackedOrigin::Concrete(source) => source,
                            TrackedOrigin::Contract(_) => unreachable!(),
                        },
                        parent,
                        next,
                        depth + 1,
                        Some((node, edge)),
                        options,
                        tracked
                            .obligations()
                            .boundary_contract(parent, effect)
                            .is_some(),
                    ) {
                        concrete_queue.push_back(child);
                    }
                }
                Propagation::Ignore => {}
                Propagation::Unknown(boundary) => {
                    unknown_boundary(&mut trace, origin, node, boundary);
                }
            }
        }
    }

    drain_obligations(
        graph,
        tracked,
        effect,
        options,
        &mut trace,
        &mut obligation_queue,
        &mut reached,
        routes,
    );

    let mut independent = tracked.obligations().seeds_for_effect(effect);
    if independent.len() > 1 {
        let mut upstream = UpstreamCounts::new(
            graph.function_count(),
            independent.iter().map(|seed| seed.owner),
        );
        independent.sort_by_cached_key(|seed| std::cmp::Reverse(upstream.count(graph, seed.owner)));
    }
    for seed in independent {
        if !routes.contract_reachable.contains(&seed.owner) {
            continue;
        }
        if reached.contains(&(seed.origin, seed.owner)) {
            continue;
        }
        if let Some(node) = add_node(
            &mut trace,
            TrackedOrigin::Contract(seed.origin),
            seed.owner,
            TrackedState::Obligation(seed.state),
            0,
            None,
            options,
        ) {
            obligation_queue.push_back(node);
            drain_obligations(
                graph,
                tracked,
                effect,
                options,
                &mut trace,
                &mut obligation_queue,
                &mut reached,
                routes,
            );
        }
    }
    trace
}

#[allow(
    clippy::too_many_lines,
    reason = "obligation transitions and handoffs share one queue loop"
)]
fn drain_obligations(
    graph: &InvocationGraph,
    tracked: &TrackedEffect<'_, '_, ConcreteEffect<'_>>,
    effect: &EffectKey,
    options: TraceOptions,
    trace: &mut DomainTrace,
    queue: &mut VecDeque<TraceNodeId>,
    reached: &mut BTreeSet<(ContractId, FunctionId)>,
    routes: &RootRoutes,
) {
    while let Some(node) = queue.pop_front() {
        let current = &trace.nodes[node.index()];
        let (origin, function, depth) = (*current.origin(), current.function(), current.depth());
        let TrackedState::Obligation(obligation) = current.state() else {
            unreachable!()
        };
        if let Some(contract) = tracked.obligations().boundary_contract(function, effect)
            && (obligation.contract() != contract || obligation.source_invocation().is_some())
        {
            handled(
                trace,
                origin,
                Some(node),
                TerminationSite::Function(function),
                TrackedTermination::Obligation(ObligationTermination::ContractBoundary),
            );
            if contract_in_ancestry(trace, node, contract) {
                unknown_at(trace, origin, node, UnknownBoundaryKind::Cycle);
            } else {
                handoff(
                    trace, tracked, contract, function, node, depth, options, queue, reached,
                );
            }
            continue;
        }
        if let Some(termination) = tracked
            .obligations()
            .terminate(obligation, TraceSite::Function(function))
        {
            handled(
                trace,
                origin,
                Some(node),
                TerminationSite::Function(function),
                TrackedTermination::Obligation(termination),
            );
            continue;
        }
        let incoming = &routes.contract_incoming[function.index()];
        let transparent = &routes.transparent_parents[function.index()];
        if incoming.is_empty() && transparent.is_empty() {
            escaped(trace, origin, node);
            continue;
        }
        if depth >= options.max_depth && (!incoming.is_empty() || !transparent.is_empty()) {
            unknown_at(trace, origin, node, UnknownBoundaryKind::TraceDepth);
            continue;
        }
        for (edge, parent) in parent_edges(graph, incoming, transparent) {
            // Borrow the queued state only while computing the transition;
            // the owned successor can then be appended to the trace.
            let propagation = {
                let TrackedState::Obligation(obligation) = trace.nodes[node.index()].state() else {
                    unreachable!()
                };
                tracked.obligations().propagate(obligation, edge)
            };
            match propagation {
                Propagation::Follow(next) => {
                    let termination = match edge {
                        PropagationEdge::Invocation(invocation) => tracked
                            .obligations()
                            .terminate(&next, TraceSite::Invocation(invocation))
                            .map(|termination| (invocation, termination)),
                        PropagationEdge::TransparentBody(_) => None,
                        PropagationEdge::Handoff => unreachable!(),
                    };
                    if let Some((invocation, termination)) = termination {
                        handled(
                            trace,
                            origin,
                            Some(node),
                            TerminationSite::Invocation(invocation),
                            TrackedTermination::Obligation(termination),
                        );
                    } else if let Some(child) = add_node(
                        trace,
                        origin,
                        parent,
                        TrackedState::Obligation(next),
                        depth + 1,
                        Some((node, edge)),
                        options,
                    ) {
                        queue.push_back(child);
                    }
                }
                Propagation::Ignore => {}
                Propagation::Unknown(boundary) => {
                    unknown_boundary(trace, origin, node, boundary);
                }
            }
        }
    }
}

fn parent_edges<'a>(
    graph: &'a InvocationGraph,
    incoming: &'a [InvocationId],
    transparent: &'a [TransparentBodyEdgeId],
) -> impl Iterator<Item = (PropagationEdge, FunctionId)> + 'a {
    incoming
        .iter()
        .copied()
        .map(|invocation| {
            (
                PropagationEdge::Invocation(invocation),
                graph.caller(invocation),
            )
        })
        .chain(transparent.iter().copied().map(|transparent_edge| {
            (
                PropagationEdge::TransparentBody(transparent_edge),
                graph.transparent_parent(transparent_edge),
            )
        }))
}

#[allow(
    clippy::too_many_arguments,
    reason = "handoffs retain all path and budget context explicitly"
)]
fn handoff(
    trace: &mut DomainTrace,
    tracked: &TrackedEffect<'_, '_, ConcreteEffect<'_>>,
    contract: ContractId,
    function: FunctionId,
    parent: TraceNodeId,
    depth: usize,
    options: TraceOptions,
    queue: &mut VecDeque<TraceNodeId>,
    reached: &mut BTreeSet<(ContractId, FunctionId)>,
) {
    let trust = match trace.nodes[parent.index()].state() {
        TrackedState::Concrete(state) => state.trust_path().clone(),
        TrackedState::Obligation(state) => state.trust_path().clone(),
    };
    if let Some(seed) = tracked
        .obligations()
        .seed_at(contract, function, Some(trust))
    {
        reached.insert((contract, function));
        if let Some(node) = add_node(
            trace,
            TrackedOrigin::Contract(contract),
            function,
            TrackedState::Obligation(seed.state),
            depth,
            Some((parent, PropagationEdge::Handoff)),
            options,
        ) {
            queue.push_back(node);
        }
    }
}

fn add_node(
    trace: &mut DomainTrace,
    origin: TrackedOrigin<ConcreteSource>,
    function: FunctionId,
    state: TrackedState<ConcreteEffectState>,
    depth: usize,
    predecessor: Option<(TraceNodeId, PropagationEdge)>,
    options: TraceOptions,
) -> Option<TraceNodeId> {
    if let Some((parent, _)) = predecessor
        && same_ancestor(trace, parent, origin, function, |candidate| {
            candidate == &state
        })
    {
        unknown_at(trace, origin, parent, UnknownBoundaryKind::Cycle);
        return None;
    }
    append_node(trace, origin, function, state, depth, predecessor, options)
}

fn append_node(
    trace: &mut DomainTrace,
    origin: TrackedOrigin<ConcreteSource>,
    function: FunctionId,
    state: TrackedState<ConcreteEffectState>,
    depth: usize,
    predecessor: Option<(TraceNodeId, PropagationEdge)>,
    options: TraceOptions,
) -> Option<TraceNodeId> {
    if trace.nodes.len() >= options.state_budget {
        match predecessor {
            Some((parent, _)) => {
                unknown_at(trace, origin, parent, UnknownBoundaryKind::TraceStateBudget);
            }
            None => {
                detached_unknown(
                    trace,
                    origin,
                    function,
                    state,
                    UnknownBoundaryKind::TraceStateBudget,
                );
            }
        }
        return None;
    }
    let id = TraceNodeId(trace.nodes.len());
    trace.nodes.push(TraceNode {
        origin,
        function,
        state,
        depth,
        predecessor: None,
    });
    if let Some((from, propagation)) = predecessor {
        let edge_id = TraceEdgeId(trace.edges.len());
        trace.edges.push(TraceEdge {
            from,
            to: id,
            propagation,
        });
        trace.nodes[id.index()].predecessor = Some(edge_id);
    }
    Some(id)
}

#[allow(clippy::too_many_arguments)]
fn add_concrete_node(
    trace: &mut DomainTrace,
    seen: &mut HashSet<(ConcreteSource, FunctionId, ConcreteEffectState, usize)>,
    origin: ConcreteSource,
    function: FunctionId,
    state: ConcreteEffectState,
    depth: usize,
    predecessor: Option<(TraceNodeId, PropagationEdge)>,
    options: TraceOptions,
    at_contract: bool,
) -> Option<TraceNodeId> {
    if let Some((parent, _)) = predecessor
        && same_ancestor(
            trace,
            parent,
            TrackedOrigin::Concrete(origin),
            function,
            |candidate| matches!(candidate, TrackedState::Concrete(candidate) if candidate == &state),
        )
    {
        unknown_at(
            trace,
            TrackedOrigin::Concrete(origin),
            parent,
            UnknownBoundaryKind::Cycle,
        );
        return None;
    }
    if !at_contract && !seen.insert((origin, function, state.clone(), depth)) {
        return None;
    }
    append_node(
        trace,
        TrackedOrigin::Concrete(origin),
        function,
        TrackedState::Concrete(state),
        depth,
        predecessor,
        options,
    )
}

fn same_ancestor(
    trace: &DomainTrace,
    mut node: TraceNodeId,
    origin: TrackedOrigin<ConcreteSource>,
    function: FunctionId,
    matches_state: impl Fn(&TrackedState<ConcreteEffectState>) -> bool,
) -> bool {
    loop {
        let current = &trace.nodes[node.index()];
        if *current.origin() == origin
            && current.function() == function
            && matches_state(current.state())
        {
            return true;
        }
        let Some(edge) = current.predecessor() else {
            return false;
        };
        node = trace.edges[edge.index()].from;
    }
}

fn contract_in_ancestry(trace: &DomainTrace, mut node: TraceNodeId, contract: ContractId) -> bool {
    loop {
        let current = &trace.nodes[node.index()];
        if matches!(current.origin(), TrackedOrigin::Contract(id) if *id == contract) {
            return true;
        }
        let Some(edge) = current.predecessor() else {
            return false;
        };
        node = trace.edges[edge.index()].from;
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

fn handled(
    trace: &mut DomainTrace,
    origin: TrackedOrigin<ConcreteSource>,
    node: Option<TraceNodeId>,
    site: TerminationSite<TrackedOrigin<ConcreteSource>>,
    termination: TrackedTermination<ConcreteTermination>,
) {
    trace.handled.push(HandledTrace {
        origin,
        node,
        site,
        termination,
    });
    trace.outcomes.push(TraceOutcome::Handled(origin));
}

fn escaped(trace: &mut DomainTrace, origin: TrackedOrigin<ConcreteSource>, node: TraceNodeId) {
    trace.escaped.push((origin, node));
    trace.outcomes.push(TraceOutcome::Escaped(origin));
}

fn unknown_at(
    trace: &mut DomainTrace,
    origin: TrackedOrigin<ConcreteSource>,
    node: TraceNodeId,
    kind: UnknownBoundaryKind,
) {
    unknown_boundary(trace, origin, node, UnknownBoundary::new(kind));
}

fn unknown_boundary(
    trace: &mut DomainTrace,
    origin: TrackedOrigin<ConcreteSource>,
    node: TraceNodeId,
    boundary: UnknownBoundary,
) {
    let current = &trace.nodes[node.index()];
    trace.unknown.push(UnknownTrace {
        origin,
        node: Some(node),
        function: current.function(),
        state: current.state().clone(),
        boundary: boundary.clone(),
    });
    trace
        .outcomes
        .push(TraceOutcome::Unknown { origin, boundary });
}

fn detached_unknown(
    trace: &mut DomainTrace,
    origin: TrackedOrigin<ConcreteSource>,
    function: FunctionId,
    state: TrackedState<ConcreteEffectState>,
    kind: UnknownBoundaryKind,
) {
    let boundary = UnknownBoundary::new(kind);
    trace.unknown.push(UnknownTrace {
        origin,
        node: None,
        function,
        state,
        boundary: boundary.clone(),
    });
    trace
        .outcomes
        .push(TraceOutcome::Unknown { origin, boundary });
}
