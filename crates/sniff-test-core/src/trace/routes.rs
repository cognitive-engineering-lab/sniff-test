//! Caller edges admitted by a forward walk from the report roots.

use std::collections::VecDeque;

use crate::compiler::invocations::InvocationGraph;

use super::{FunctionId, PropagationEdge};

/// Which caller edges an obligation at a function can travel backward along.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeScope {
    /// Edges that execute the function's body: invocations resolving to it
    /// as a call target, plus transparent-body parents. Concrete effects
    /// live in bodies, so they only flow through these edges.
    Body,
    /// Body edges plus invocations that only name the function as a
    /// declaration surface, such as a trait method behind a generic or `dyn`
    /// call. Documentation contracts attach to signatures, so they also
    /// flow through these edges.
    Signature,
}

/// The caller edges of every function reached from the report roots.
///
/// Only bodies are walked: declaration targets gain incoming signature edges
/// but are not descended into. Every recorded edge therefore starts at a
/// reached caller, so a function is reachable in a scope exactly when it is a
/// root or has an incoming edge in that scope.
pub struct RootRoutes {
    roots: Vec<bool>,
    body_callers: Vec<Vec<(PropagationEdge, FunctionId)>>,
    signature_callers: Vec<Vec<(PropagationEdge, FunctionId)>>,
    transparent_parents: Vec<Vec<(PropagationEdge, FunctionId)>>,
}

impl RootRoutes {
    #[must_use]
    pub fn new(graph: &InvocationGraph, roots: &[FunctionId]) -> Self {
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
            roots: vec![false; count],
            body_callers: vec![Vec::new(); count],
            signature_callers: vec![Vec::new(); count],
            transparent_parents: vec![Vec::new(); count],
        };
        for root in roots {
            routes.roots[root.index()] = true;
        }
        let mut queue = VecDeque::from(roots.to_vec());
        let mut visited = vec![false; count];
        while let Some(function) = queue.pop_front() {
            if std::mem::replace(&mut visited[function.index()], true) {
                continue;
            }
            for &invocation_id in &outgoing[function.index()] {
                let edge = (PropagationEdge::Invocation(invocation_id), function);
                let invocation = graph.invocation(invocation_id);
                for target in invocation.function_targets() {
                    routes.body_callers[target.index()].push(edge);
                    routes.signature_callers[target.index()].push(edge);
                    queue.push_back(target);
                }
                for declaration in invocation.declaration_targets() {
                    routes.signature_callers[declaration.index()].push(edge);
                }
            }
            for &(edge, child) in &transparent_children[function.index()] {
                routes.transparent_parents[child.index()]
                    .push((PropagationEdge::TransparentBody(edge), function));
                queue.push_back(child);
            }
        }
        routes
    }

    /// Caller edges of `function` in `scope`, invocations before transparent
    /// parents, each paired with the parent function it leads to.
    pub fn parents(
        &self,
        function: FunctionId,
        scope: EdgeScope,
    ) -> impl Iterator<Item = (PropagationEdge, FunctionId)> + '_ {
        let callers = match scope {
            EdgeScope::Body => &self.body_callers,
            EdgeScope::Signature => &self.signature_callers,
        };
        callers[function.index()]
            .iter()
            .chain(&self.transparent_parents[function.index()])
            .copied()
    }

    /// Whether `function` is reachable from a report root in `scope`.
    #[must_use]
    pub fn admits(&self, function: FunctionId, scope: EdgeScope) -> bool {
        self.roots[function.index()] || self.parents(function, scope).next().is_some()
    }
}
