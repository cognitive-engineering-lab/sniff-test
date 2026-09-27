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
    UnknownBoundary, UnknownBoundaryKind, UnknownTrace,
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

#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "both direct worklists and their shared budget are visible in one traversal"
)]
pub fn trace_effect(
    graph: &InvocationGraph,
    tracked: &TrackedEffect<'_, '_, ConcreteEffect<'_>>,
    effect: &EffectKey,
    options: TraceOptions,
) -> DomainTrace {
    let mut trace = DomainTrace::default();
    let mut concrete_queue = VecDeque::new();
    let mut obligation_queue = VecDeque::new();
    let mut reached = BTreeSet::new();
    let mut concrete_seen = HashSet::new();

    for seed in tracked.concrete().sources() {
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
        let (origin, function, state, depth) = node_data(&trace, node);
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
        let TrackedState::Concrete(ref concrete_state) = state else {
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
        let incoming = graph.incoming_invocations(function);
        let transparent = graph.transparent_parents(function);
        if incoming.is_empty() && transparent.is_empty() {
            escaped(&mut trace, origin, node);
            continue;
        }
        if depth >= options.max_depth && (!incoming.is_empty() || !transparent.is_empty()) {
            unknown_at(&mut trace, origin, node, UnknownBoundaryKind::TraceDepth);
            continue;
        }
        for (edge, parent) in parent_edges(graph, function, incoming) {
            if let PropagationEdge::Invocation(invocation) = edge
                && !graph
                    .invocation(invocation)
                    .function_targets()
                    .any(|target| target == function)
            {
                continue;
            }
            match tracked.concrete().propagate(concrete_state, edge) {
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
    );

    let mut independent = tracked.obligations().seeds_for_effect(effect);
    let candidates = independent
        .iter()
        .map(|seed| seed.owner)
        .collect::<BTreeSet<_>>();
    independent
        .sort_by_key(|seed| std::cmp::Reverse(upstream_count(graph, seed.owner, &candidates)));
    for seed in independent {
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
) {
    while let Some(node) = queue.pop_front() {
        let (origin, function, state, depth) = node_data(trace, node);
        let TrackedState::Obligation(ref obligation) = state else {
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
        let incoming = graph.incoming_contract_visible_invocations(function);
        let transparent = graph.transparent_parents(function);
        if incoming.is_empty() && transparent.is_empty() {
            escaped(trace, origin, node);
            continue;
        }
        if depth >= options.max_depth && (!incoming.is_empty() || !transparent.is_empty()) {
            unknown_at(trace, origin, node, UnknownBoundaryKind::TraceDepth);
            continue;
        }
        for (edge, parent) in parent_edges(graph, function, incoming) {
            match tracked.obligations().propagate(obligation, edge) {
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
    function: FunctionId,
    incoming: &'a [InvocationId],
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
        .chain(
            graph
                .transparent_parents(function)
                .iter()
                .copied()
                .map(|transparent_edge| {
                    (
                        PropagationEdge::TransparentBody(transparent_edge),
                        graph.transparent_parent(transparent_edge),
                    )
                }),
        )
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

fn node_data(
    trace: &DomainTrace,
    node: TraceNodeId,
) -> (
    TrackedOrigin<ConcreteSource>,
    FunctionId,
    TrackedState<ConcreteEffectState>,
    usize,
) {
    let node = &trace.nodes[node.index()];
    (
        *node.origin(),
        node.function(),
        node.state().clone(),
        node.depth(),
    )
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
        && same_ancestor(trace, parent, origin, function, &state)
    {
        unknown_at(trace, origin, parent, UnknownBoundaryKind::Cycle);
        return None;
    }
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
            &TrackedState::Concrete(state.clone()),
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
    add_node(
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
    state: &TrackedState<ConcreteEffectState>,
) -> bool {
    loop {
        let current = &trace.nodes[node.index()];
        if *current.origin() == origin && current.function() == function && current.state() == state
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

fn upstream_count(
    graph: &InvocationGraph,
    start: FunctionId,
    candidates: &BTreeSet<FunctionId>,
) -> usize {
    let mut seen = BTreeSet::from([start]);
    let mut pending = vec![start];
    while let Some(function) = pending.pop() {
        for &invocation in graph.incoming_contract_visible_invocations(function) {
            let parent = graph.caller(invocation);
            if seen.insert(parent) {
                pending.push(parent);
            }
        }
        for &edge in graph.transparent_parents(function) {
            let parent = graph.transparent_parent(edge);
            if seen.insert(parent) {
                pending.push(parent);
            }
        }
    }
    seen.intersection(candidates).count()
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
