use std::collections::BTreeSet;

use effect_tracing::FunctionId;

use crate::compiler::invocations::InvocationGraph;

/// Untrusted implementation crates crossed from the source toward its callers.
/// A boundary may cover these crates only through its own dependency tree;
/// independently trusted implementations need no additional dependency trust.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustPath(BTreeSet<u64>);

impl TrustPath {
    #[must_use]
    pub fn new(graph: &InvocationGraph, source: FunctionId) -> Self {
        Self(BTreeSet::from([Self::crate_id(graph, source)]))
    }

    pub fn enter(&mut self, graph: &InvocationGraph, function: FunctionId) {
        self.0.insert(Self::crate_id(graph, function));
    }

    #[must_use]
    pub fn allows_boundary(&self, graph: &InvocationGraph, boundary: FunctionId) -> bool {
        let owner = Self::crate_id(graph, boundary);
        self.0
            .iter()
            .all(|crate_id| *crate_id == owner || graph.is_dependency(owner, *crate_id))
    }

    fn crate_id(graph: &InvocationGraph, function: FunctionId) -> u64 {
        graph
            .stable_function(function)
            .def_path_hash
            .stable_crate_id()
    }
}
