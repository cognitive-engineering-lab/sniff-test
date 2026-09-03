use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

use crate::trace::{
    EffectTrace, HandledTrace, TerminationSite, TraceEdge, TraceEdgeId, TraceNode, TraceNodeId,
    TraceOutcome, UnknownTrace,
};
use crate::{
    Effect, EffectGraph, FunctionId, Propagation, PropagationEdge, TraceCx, TraceSite,
    UnknownBoundary, UnknownBoundaryKind,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceOptions {
    /// Maximum number of propagation edges followed from any source.
    pub max_depth: usize,
    /// Maximum number of distinct `(origin, function, state)` trace nodes.
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

#[derive(Clone, Copy, Debug)]
struct QueuedNode {
    node: TraceNodeId,
    depth: usize,
}

pub struct EffectEngine<'graph> {
    graph: &'graph dyn EffectGraph,
    options: TraceOptions,
}

impl<'graph> EffectEngine<'graph> {
    #[must_use]
    pub fn new(graph: &'graph impl EffectGraph) -> Self {
        Self::with_options(graph, TraceOptions::default())
    }

    #[must_use]
    pub fn with_options(graph: &'graph impl EffectGraph, options: TraceOptions) -> Self {
        Self { graph, options }
    }

    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "the work queue and the three effect callbacks remain visible as one traversal loop"
    )]
    pub fn trace<E: Effect>(&self, effect: &E) -> EffectTrace<E::Origin, E::State, E::Termination> {
        let cx = TraceCx::new(self.graph);
        let mut trace = EffectTrace::default();
        let mut queue = VecDeque::new();
        let mut visited = HashMap::new();

        for seed in effect.sources() {
            if let Some(termination) =
                effect.terminate(&cx, &seed.state, TraceSite::Source(&seed.origin))
            {
                record_handled(
                    &mut trace,
                    seed.origin.clone(),
                    None,
                    TerminationSite::Source(seed.origin),
                    termination,
                );
                continue;
            }

            let key = VisitKey::new(seed.origin.clone(), seed.owner, seed.state.clone());
            if visited.contains_key(&key) {
                continue;
            }
            if trace.nodes.len() >= self.options.state_budget {
                record_detached_unknown(
                    &mut trace,
                    seed.origin,
                    seed.owner,
                    seed.state,
                    UnknownBoundary::new(UnknownBoundaryKind::TraceStateBudget),
                );
            } else {
                let node = push_node(
                    &mut trace,
                    seed.origin.clone(),
                    seed.owner,
                    seed.state.clone(),
                );
                visited.insert(key, node);
                queue.push_back(QueuedNode { node, depth: 0 });
            }
        }

        while let Some(QueuedNode {
            node: node_id,
            depth,
        }) = queue.pop_front()
        {
            let origin = trace.nodes[node_id.index()].origin.clone();
            let function = trace.nodes[node_id.index()].function;
            let state = trace.nodes[node_id.index()].state.clone();

            if let Some(termination) = effect.terminate(&cx, &state, TraceSite::Function(function))
            {
                record_handled(
                    &mut trace,
                    origin,
                    Some(node_id),
                    TerminationSite::Function(function),
                    termination,
                );
                continue;
            }

            let invocations = self.graph.incoming_invocations(function);
            let transparent = self.graph.transparent_parents(function);
            let unknown = self.graph.unknown_boundaries(function);
            if invocations.is_empty() && transparent.is_empty() && unknown.is_empty() {
                trace.escaped.push((origin.clone(), node_id));
                trace.outcomes.push(TraceOutcome::Escaped(origin));
                continue;
            }

            if depth >= self.options.max_depth
                && (!invocations.is_empty() || !transparent.is_empty())
            {
                record_unknown(
                    &mut trace,
                    origin,
                    node_id,
                    UnknownBoundary::new(UnknownBoundaryKind::TraceDepth),
                );
                continue;
            }

            for boundary in unknown {
                record_unknown(&mut trace, origin.clone(), node_id, boundary.clone());
            }

            for invocation in invocations.iter().copied() {
                let edge = PropagationEdge::Invocation(invocation);
                match effect.propagate(&cx, &state, edge) {
                    Propagation::Follow(next) => {
                        if let Some(termination) =
                            effect.terminate(&cx, &next, TraceSite::Invocation(invocation))
                        {
                            record_handled(
                                &mut trace,
                                origin.clone(),
                                Some(node_id),
                                TerminationSite::Invocation(invocation),
                                termination,
                            );
                        } else {
                            self.follow(
                                &mut trace,
                                &mut queue,
                                &mut visited,
                                origin.clone(),
                                node_id,
                                self.graph.caller(invocation),
                                next,
                                edge,
                                depth + 1,
                            );
                        }
                    }
                    Propagation::Ignore => {}
                    Propagation::Unknown(boundary) => {
                        record_unknown(&mut trace, origin.clone(), node_id, boundary);
                    }
                }
            }

            for transparent_edge in transparent.iter().copied() {
                let edge = PropagationEdge::TransparentBody(transparent_edge);
                match effect.propagate(&cx, &state, edge) {
                    Propagation::Follow(next) => self.follow(
                        &mut trace,
                        &mut queue,
                        &mut visited,
                        origin.clone(),
                        node_id,
                        self.graph.transparent_parent(transparent_edge),
                        next,
                        edge,
                        depth + 1,
                    ),
                    Propagation::Ignore => {}
                    Propagation::Unknown(boundary) => {
                        record_unknown(&mut trace, origin.clone(), node_id, boundary);
                    }
                }
            }
        }

        trace
    }

    #[allow(clippy::too_many_arguments)]
    fn follow<O, S, T>(
        &self,
        trace: &mut EffectTrace<O, S, T>,
        queue: &mut VecDeque<QueuedNode>,
        visited: &mut HashMap<VisitKey<O, S>, TraceNodeId>,
        origin: O,
        from: TraceNodeId,
        function: FunctionId,
        state: S,
        propagation: PropagationEdge,
        depth: usize,
    ) where
        O: Clone + Eq + Hash,
        S: Clone + Eq + Hash,
    {
        let key = VisitKey::new(origin.clone(), function, state.clone());
        if let Some(existing) = visited.get(&key).copied() {
            let cycle = is_ancestor(trace, existing, from);
            push_edge(trace, from, existing, propagation);
            if cycle {
                record_unknown(
                    trace,
                    origin,
                    from,
                    UnknownBoundary::new(UnknownBoundaryKind::Cycle),
                );
            }
            return;
        }

        if trace.nodes.len() >= self.options.state_budget {
            record_unknown(
                trace,
                origin,
                from,
                UnknownBoundary::new(UnknownBoundaryKind::TraceStateBudget),
            );
            return;
        }

        let next = push_node(trace, origin, function, state);
        visited.insert(key, next);
        push_edge(trace, from, next, propagation);
        queue.push_back(QueuedNode { node: next, depth });
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct VisitKey<O, S> {
    origin: O,
    function: FunctionId,
    state: S,
}

impl<O, S> VisitKey<O, S> {
    const fn new(origin: O, function: FunctionId, state: S) -> Self {
        Self {
            origin,
            function,
            state,
        }
    }
}

fn push_node<O, S, T>(
    trace: &mut EffectTrace<O, S, T>,
    origin: O,
    function: FunctionId,
    state: S,
) -> TraceNodeId {
    let id = TraceNodeId(trace.nodes.len());
    trace.nodes.push(TraceNode {
        origin,
        function,
        state,
        predecessors: Vec::new(),
    });
    id
}

fn push_edge<O, S, T>(
    trace: &mut EffectTrace<O, S, T>,
    from: TraceNodeId,
    to: TraceNodeId,
    propagation: PropagationEdge,
) {
    let id = TraceEdgeId(trace.edges.len());
    trace.edges.push(TraceEdge {
        from,
        to,
        propagation,
    });
    trace.nodes[to.index()].predecessors.push(id);
}

fn record_handled<O: Clone, S, T>(
    trace: &mut EffectTrace<O, S, T>,
    origin: O,
    node: Option<TraceNodeId>,
    site: TerminationSite<O>,
    termination: T,
) {
    trace.handled.push(HandledTrace {
        origin: origin.clone(),
        node,
        site,
        termination,
    });
    trace.outcomes.push(TraceOutcome::Handled(origin));
}

fn record_unknown<O: Clone, S: Clone, T>(
    trace: &mut EffectTrace<O, S, T>,
    origin: O,
    node: TraceNodeId,
    boundary: UnknownBoundary,
) {
    let function = trace.nodes[node.index()].function;
    let state = trace.nodes[node.index()].state.clone();
    trace.unknown.push(UnknownTrace {
        origin: origin.clone(),
        node: Some(node),
        function,
        state,
        boundary: boundary.clone(),
    });
    trace
        .outcomes
        .push(TraceOutcome::Unknown { origin, boundary });
}

fn record_detached_unknown<O: Clone, S, T>(
    trace: &mut EffectTrace<O, S, T>,
    origin: O,
    function: FunctionId,
    state: S,
    boundary: UnknownBoundary,
) {
    trace.unknown.push(UnknownTrace {
        origin: origin.clone(),
        node: None,
        function,
        state,
        boundary: boundary.clone(),
    });
    trace
        .outcomes
        .push(TraceOutcome::Unknown { origin, boundary });
}

fn is_ancestor<O, S, T>(
    trace: &EffectTrace<O, S, T>,
    candidate: TraceNodeId,
    node: TraceNodeId,
) -> bool {
    let mut stack = vec![node];
    let mut seen = vec![false; trace.nodes.len()];
    while let Some(current) = stack.pop() {
        if current == candidate {
            return true;
        }
        if seen[current.index()] {
            continue;
        }
        seen[current.index()] = true;
        stack.extend(
            trace.nodes[current.index()]
                .predecessors
                .iter()
                .map(|edge| trace.edges[edge.index()].from),
        );
    }
    false
}
