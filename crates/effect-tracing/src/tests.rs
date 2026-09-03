use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Effect, EffectEngine, EffectGraph, EffectSeed, FunctionId, InvocationId, Propagation,
    PropagationEdge, TraceCx, TraceOptions, TraceOutcome, TraceSite, TransparentBodyEdgeId,
    UnknownBoundary, UnknownBoundaryKind,
};

#[derive(Default)]
struct Graph {
    incoming: Vec<Vec<InvocationId>>,
    callers: Vec<FunctionId>,
    transparent: Vec<Vec<TransparentBodyEdgeId>>,
    parents: Vec<FunctionId>,
    unknown: Vec<Vec<UnknownBoundary>>,
}

impl Graph {
    fn with_functions(count: usize) -> Self {
        Self {
            incoming: vec![Vec::new(); count],
            transparent: vec![Vec::new(); count],
            unknown: vec![Vec::new(); count],
            ..Self::default()
        }
    }

    fn invoke(&mut self, caller: usize, destination: usize) -> InvocationId {
        let id = InvocationId::from_index(self.callers.len());
        self.callers.push(FunctionId::from_index(caller));
        self.incoming[destination].push(id);
        id
    }

    fn contain(&mut self, parent: usize, child: usize) -> TransparentBodyEdgeId {
        let id = TransparentBodyEdgeId::from_index(self.parents.len());
        self.parents.push(FunctionId::from_index(parent));
        self.transparent[child].push(id);
        id
    }

    fn make_unknown(&mut self, function: usize, kind: UnknownBoundaryKind) {
        self.unknown[function].push(UnknownBoundary::new(kind));
    }
}

impl EffectGraph for Graph {
    fn incoming_invocations(&self, function: FunctionId) -> &[InvocationId] {
        &self.incoming[function.index()]
    }

    fn caller(&self, invocation: InvocationId) -> FunctionId {
        self.callers[invocation.index()]
    }

    fn transparent_parents(&self, function: FunctionId) -> &[TransparentBodyEdgeId] {
        &self.transparent[function.index()]
    }

    fn transparent_parent(&self, edge: TransparentBodyEdgeId) -> FunctionId {
        self.parents[edge.index()]
    }

    fn unknown_boundaries(&self, function: FunctionId) -> &[UnknownBoundary] {
        &self.unknown[function.index()]
    }
}

struct TestEffect {
    seeds: Vec<EffectSeed<&'static str, BTreeSet<&'static str>>>,
    source_terminates: BTreeSet<&'static str>,
    invocation_satisfies: BTreeMap<InvocationId, &'static str>,
    invocation_terminates: BTreeSet<InvocationId>,
    function_terminates: BTreeSet<FunctionId>,
}

impl TestEffect {
    fn seeded(owner: usize, obligations: &[&'static str]) -> Self {
        Self {
            seeds: vec![EffectSeed::new(
                "origin",
                FunctionId::from_index(owner),
                obligations.iter().copied().collect(),
            )],
            source_terminates: BTreeSet::new(),
            invocation_satisfies: BTreeMap::new(),
            invocation_terminates: BTreeSet::new(),
            function_terminates: BTreeSet::new(),
        }
    }
}

impl Effect for TestEffect {
    type Origin = &'static str;
    type State = BTreeSet<&'static str>;
    type Termination = &'static str;

    fn sources(&self) -> impl Iterator<Item = EffectSeed<Self::Origin, Self::State>> + '_ {
        self.seeds.iter().cloned()
    }

    fn propagate(
        &self,
        _cx: &TraceCx<'_>,
        state: &Self::State,
        edge: PropagationEdge,
    ) -> Propagation<Self::State> {
        let mut next = state.clone();
        if let PropagationEdge::Invocation(invocation) = edge
            && let Some(satisfied) = self.invocation_satisfies.get(&invocation)
        {
            next.remove(satisfied);
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
            TraceSite::Source(origin) if self.source_terminates.contains(origin) => {
                Some("source justification")
            }
            TraceSite::Function(function) if self.function_terminates.contains(&function) => {
                Some("function contract")
            }
            TraceSite::Invocation(invocation)
                if self.invocation_terminates.contains(&invocation) =>
            {
                Some("site justification")
            }
            TraceSite::Invocation(_) if state.is_empty() => Some("obligations satisfied"),
            TraceSite::Source(_) | TraceSite::Function(_) | TraceSite::Invocation(_) => None,
        }
    }
}

fn outcomes(graph: &Graph, effect: &TestEffect) -> Vec<TraceOutcome<&'static str>> {
    EffectEngine::new(graph).trace(effect).outcomes().collect()
}

#[test]
fn single_source_escapes_through_its_only_caller() {
    let mut graph = Graph::with_functions(2);
    graph.invoke(0, 1);

    let outcomes = outcomes(&graph, &TestEffect::seeded(1, &["risk"]));

    assert_eq!(outcomes, vec![TraceOutcome::Escaped("origin")]);
}

#[test]
fn termination_is_path_local_across_multiple_callers() {
    let mut graph = Graph::with_functions(3);
    let handled = graph.invoke(0, 2);
    graph.invoke(1, 2);
    let mut effect = TestEffect::seeded(2, &["risk"]);
    effect.invocation_terminates.insert(handled);

    let outcomes = outcomes(&graph, &effect);

    assert_eq!(
        outcomes,
        vec![
            TraceOutcome::Handled("origin"),
            TraceOutcome::Escaped("origin")
        ]
    );
}

#[test]
fn converging_paths_share_work_without_losing_predecessors() {
    let mut graph = Graph::with_functions(4);
    graph.invoke(0, 1);
    graph.invoke(0, 2);
    graph.invoke(1, 3);
    graph.invoke(2, 3);

    let trace = EffectEngine::new(&graph).trace(&TestEffect::seeded(3, &["risk"]));

    assert_eq!(trace.outcomes().count(), 1);
    assert_eq!(
        trace.outcomes().next(),
        Some(TraceOutcome::Escaped("origin"))
    );
    assert_eq!(
        trace
            .nodes()
            .filter(|node| node.function() == FunctionId::from_index(0))
            .count(),
        1
    );
    assert_eq!(
        trace
            .nodes()
            .find(|node| node.function() == FunctionId::from_index(0))
            .expect("converged node")
            .predecessors()
            .count(),
        2
    );
}

#[test]
fn recursive_graph_reports_a_cycle_instead_of_looping() {
    let mut graph = Graph::with_functions(2);
    graph.invoke(0, 1);
    graph.invoke(1, 0);

    let outcomes = outcomes(&graph, &TestEffect::seeded(1, &["risk"]));

    assert_eq!(
        outcomes,
        vec![TraceOutcome::Unknown {
            origin: "origin",
            boundary: UnknownBoundary::new(UnknownBoundaryKind::Cycle),
        }]
    );
}

#[test]
fn cycle_detection_includes_effect_state() {
    let mut graph = Graph::with_functions(2);
    let satisfy = graph.invoke(0, 1);
    graph.invoke(1, 0);
    let mut effect = TestEffect::seeded(1, &["risk"]);
    effect.invocation_satisfies.insert(satisfy, "risk");

    let outcomes = outcomes(&graph, &effect);

    assert_eq!(outcomes, vec![TraceOutcome::Handled("origin")]);
}

#[test]
fn obligations_can_be_satisfied_across_multiple_invocations() {
    let mut graph = Graph::with_functions(3);
    let outer = graph.invoke(0, 1);
    let inner = graph.invoke(1, 2);
    let mut effect = TestEffect::seeded(2, &["initialized", "exclusive"]);
    effect.invocation_satisfies.insert(inner, "initialized");
    effect.invocation_satisfies.insert(outer, "exclusive");

    let trace = EffectEngine::new(&graph).trace(&effect);

    assert_eq!(
        trace.outcomes().collect::<Vec<_>>(),
        vec![TraceOutcome::Handled("origin")]
    );
    assert!(trace.nodes().any(|node| {
        node.function() == FunctionId::from_index(1)
            && node.state() == &BTreeSet::from(["exclusive"])
    }));
}

#[test]
fn graph_unknown_boundary_is_an_unknown_outcome() {
    let mut graph = Graph::with_functions(1);
    graph.make_unknown(0, UnknownBoundaryKind::IndirectCall);

    let outcomes = outcomes(&graph, &TestEffect::seeded(0, &["risk"]));

    assert_eq!(
        outcomes,
        vec![TraceOutcome::Unknown {
            origin: "origin",
            boundary: UnknownBoundary::new(UnknownBoundaryKind::IndirectCall),
        }]
    );
}

#[test]
fn transparent_nested_body_propagates_to_its_parent() {
    let mut graph = Graph::with_functions(2);
    graph.contain(0, 1);

    let outcomes = outcomes(&graph, &TestEffect::seeded(1, &["risk"]));

    assert_eq!(outcomes, vec![TraceOutcome::Escaped("origin")]);
}

#[test]
fn trace_state_budget_becomes_an_explicit_unknown_outcome() {
    let mut graph = Graph::with_functions(3);
    graph.invoke(1, 2);
    graph.invoke(0, 1);
    let effect = TestEffect::seeded(2, &["risk"]);

    let trace = EffectEngine::with_options(
        &graph,
        TraceOptions {
            state_budget: 2,
            ..TraceOptions::default()
        },
    )
    .trace(&effect);

    assert_eq!(
        trace.outcomes().collect::<Vec<_>>(),
        vec![TraceOutcome::Unknown {
            origin: "origin",
            boundary: UnknownBoundary::new(UnknownBoundaryKind::TraceStateBudget),
        }]
    );
}

#[test]
fn source_termination_does_not_exhaust_the_state_budget() {
    let graph = Graph::with_functions(1);
    let mut effect = TestEffect::seeded(0, &["risk"]);
    effect.source_terminates.insert("origin");

    let trace = EffectEngine::with_options(
        &graph,
        TraceOptions {
            state_budget: 0,
            ..TraceOptions::default()
        },
    )
    .trace(&effect);

    assert_eq!(
        trace.outcomes().collect::<Vec<_>>(),
        vec![TraceOutcome::Handled("origin")]
    );
    assert_eq!(trace.nodes().count(), 0);
    assert_eq!(trace.unknown().count(), 0);
    assert_eq!(trace.handled().next().unwrap().node(), None);
}

#[test]
fn source_heavy_trace_never_stores_more_nodes_than_its_budget() {
    let graph = Graph::with_functions(1);
    let mut effect = TestEffect::seeded(0, &["risk"]);
    effect.seeds.extend([
        EffectSeed::new(
            "second",
            FunctionId::from_index(0),
            BTreeSet::from(["risk"]),
        ),
        EffectSeed::new("third", FunctionId::from_index(0), BTreeSet::from(["risk"])),
    ]);

    let trace = EffectEngine::with_options(
        &graph,
        TraceOptions {
            state_budget: 1,
            ..TraceOptions::default()
        },
    )
    .trace(&effect);

    assert_eq!(trace.nodes().count(), 1);
    assert_eq!(trace.unknown().count(), 2);
    assert!(trace.unknown().all(|unknown| unknown.node().is_none()));
}

#[test]
fn max_depth_limits_each_path_instead_of_total_trace_size() {
    let mut graph = Graph::with_functions(5);
    graph.invoke(0, 1);
    graph.invoke(1, 2);
    graph.invoke(3, 2);
    graph.invoke(4, 3);
    let effect = TestEffect::seeded(2, &["risk"]);

    let trace = EffectEngine::with_options(
        &graph,
        TraceOptions {
            max_depth: 1,
            state_budget: 100,
        },
    )
    .trace(&effect);

    assert_eq!(
        trace.outcomes().collect::<Vec<_>>(),
        vec![
            TraceOutcome::Unknown {
                origin: "origin",
                boundary: UnknownBoundary::new(UnknownBoundaryKind::TraceDepth),
            },
            TraceOutcome::Unknown {
                origin: "origin",
                boundary: UnknownBoundary::new(UnknownBoundaryKind::TraceDepth),
            },
        ]
    );
}
