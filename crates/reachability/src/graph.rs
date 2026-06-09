use std::collections::HashMap;
use std::fmt;

use rustc_middle::mir::AssertMessage;
use rustc_middle::ty::{Instance, Ty};
use rustc_span::Span;

use crate::hooks::{ReachabilityHalt, ReachabilityQueryStats};

/// Shared directed graph facts discovered by reachability queries.
///
/// The graph stores root-independent facts: nodes, edges, outgoing adjacency,
/// and the canonical node for each function instance. Per-root state such as
/// depth, predecessor edges, and halting reason lives in [`ReachabilitySnapshot`].
pub struct ReachabilityGraph<'tcx> {
    nodes: Vec<ReachabilityNode<'tcx>>,
    edges: Vec<ReachabilityEdge>,
    outgoing: Vec<Vec<ReachabilityEdgeId>>,
    instance_nodes: HashMap<Instance<'tcx>, ReachabilityNodeId>,
}

impl<'tcx> ReachabilityGraph<'tcx> {
    pub(crate) fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            outgoing: Vec::new(),
            instance_nodes: HashMap::new(),
        }
    }

    #[must_use]
    /// Returns all graph nodes in insertion order.
    ///
    /// This is low-level access to the whole shared graph arena. Prefer
    /// [`view`](Self::view) when inspecting one query's reachable subgraph.
    ///
    /// A node id can be used as an index into this slice through
    /// [`ReachabilityNodeId::index`].
    pub fn nodes(&self) -> &[ReachabilityNode<'tcx>] {
        &self.nodes
    }

    #[must_use]
    /// Returns all graph edges in discovery order.
    ///
    /// This is low-level access to the whole shared graph arena. Prefer
    /// [`view`](Self::view) when inspecting one query's accepted edges.
    ///
    /// Edges reference their source and target nodes by [`ReachabilityNodeId`].
    pub fn edges(&self) -> &[ReachabilityEdge] {
        &self.edges
    }

    #[must_use]
    /// Borrows this graph with one root-specific query snapshot.
    pub fn view<'view>(
        &'view self,
        snapshot: &'view ReachabilitySnapshot<'tcx>,
    ) -> ReachabilityView<'view, 'tcx> {
        ReachabilityView {
            graph: self,
            snapshot,
        }
    }

    #[must_use]
    /// Returns one graph-arena node by id.
    ///
    /// This does not check whether the node was reached by a particular query.
    /// Use [`ReachabilityView::node`] for snapshot-bound lookup.
    pub fn node(&self, node: ReachabilityNodeId) -> &ReachabilityNode<'tcx> {
        &self.nodes[node.index()]
    }

    #[must_use]
    /// Returns one graph-arena edge by id.
    ///
    /// This does not check whether the edge was accepted by a particular query.
    /// Prefer [`ReachabilityView::edges`] or [`ReachedNode::predecessor_edge`]
    /// when inspecting one query's reached subgraph.
    pub fn edge(&self, edge: ReachabilityEdgeId) -> &ReachabilityEdge {
        &self.edges[edge.index()]
    }

    #[must_use]
    /// Returns outgoing edge ids for `node`.
    pub fn outgoing_edges(&self, node: ReachabilityNodeId) -> &[ReachabilityEdgeId] {
        &self.outgoing[node.index()]
    }

    #[must_use]
    /// Returns the instance represented by `node`, if it is a function node.
    pub fn node_instance(&self, node: ReachabilityNodeId) -> Option<Instance<'tcx>> {
        match self.nodes[node.index()].kind {
            ReachabilityNodeKind::Instance(instance) => Some(instance),
            ReachabilityNodeKind::CompilerAssert { .. }
            | ReachabilityNodeKind::IndirectCall { .. }
            | ReachabilityNodeKind::DynObjectCast { .. } => None,
        }
    }

    pub(crate) fn snapshot_for_root(&self, root: ReachabilityNodeId) -> ReachabilitySnapshot<'tcx> {
        debug_assert!(root.index() < self.nodes.len());
        ReachabilitySnapshot::new(root, self.nodes.len())
    }

    pub(crate) fn node_for_instance(&mut self, instance: Instance<'tcx>) -> ReachabilityNodeId {
        if let Some(id) = self.instance_nodes.get(&instance) {
            return *id;
        }

        let id = self.push_node(ReachabilityNodeKind::Instance(instance));
        self.instance_nodes.insert(instance, id);
        id
    }

    pub(crate) fn node_for_kind(&mut self, kind: ReachabilityNodeKind<'tcx>) -> ReachabilityNodeId {
        match kind {
            ReachabilityNodeKind::Instance(instance) => self.node_for_instance(instance),
            kind => self.push_node(kind),
        }
    }

    pub(crate) fn push_edge(&mut self, edge: ReachabilityEdge) -> ReachabilityEdgeId {
        let id = ReachabilityEdgeId(self.edges.len());
        self.outgoing[edge.source.index()].push(id);
        self.edges.push(edge);
        id
    }

    fn push_node(&mut self, kind: ReachabilityNodeKind<'tcx>) -> ReachabilityNodeId {
        let id = ReachabilityNodeId(self.nodes.len());
        self.nodes.push(ReachabilityNode { id, kind });
        self.outgoing.push(Vec::new());
        id
    }
}

/// Graph-bound view of one root-specific reachability query.
///
/// This is the preferred inspection API. The underlying snapshot stores typed ids
/// so batch queries can keep running, while the view turns those ids into values
/// borrowed from the graph arena.
#[derive(Clone, Copy)]
pub struct ReachabilityView<'view, 'tcx> {
    graph: &'view ReachabilityGraph<'tcx>,
    snapshot: &'view ReachabilitySnapshot<'tcx>,
}

impl<'view, 'tcx> ReachabilityView<'view, 'tcx> {
    #[must_use]
    /// Returns the root node for this query.
    pub fn root(self) -> ReachedNode<'view, 'tcx> {
        self.reached_node(self.snapshot.root)
    }

    /// Returns reached nodes in first-discovery order.
    pub fn nodes(self) -> impl Iterator<Item = ReachedNode<'view, 'tcx>> + 'view {
        self.snapshot
            .node_ids
            .iter()
            .copied()
            .map(move |id| self.reached_node(id))
    }

    /// Returns accepted edges in traversal order.
    pub fn edges(self) -> impl Iterator<Item = ReachedEdge<'view, 'tcx>> + 'view {
        self.snapshot
            .edge_ids
            .iter()
            .copied()
            .map(move |id| self.reached_edge(id))
    }

    #[must_use]
    /// Returns one reached node by id, if this query reached it.
    pub fn node(self, id: ReachabilityNodeId) -> Option<ReachedNode<'view, 'tcx>> {
        self.snapshot.depth(id).map(|depth| ReachedNode {
            graph: self.graph,
            snapshot: self.snapshot,
            id,
            depth,
        })
    }

    fn reached_node(self, id: ReachabilityNodeId) -> ReachedNode<'view, 'tcx> {
        let depth = self.snapshot.depth(id).unwrap_or_default();
        debug_assert!(self.snapshot.depth(id).is_some());
        ReachedNode {
            graph: self.graph,
            snapshot: self.snapshot,
            id,
            depth,
        }
    }

    fn reached_edge(self, id: ReachabilityEdgeId) -> ReachedEdge<'view, 'tcx> {
        debug_assert!(id.index() < self.graph.edges.len());
        ReachedEdge::new(self.graph, self.snapshot, id)
    }

    #[must_use]
    /// Returns why traversal stopped early, if it did.
    pub fn halt(self) -> Option<&'view ReachabilityHalt<'tcx>> {
        self.snapshot.halt.as_ref()
    }
}

/// A node reached by one root-specific query.
#[derive(Clone, Copy)]
pub struct ReachedNode<'view, 'tcx> {
    graph: &'view ReachabilityGraph<'tcx>,
    snapshot: &'view ReachabilitySnapshot<'tcx>,
    id: ReachabilityNodeId,
    depth: usize,
}

impl<'view, 'tcx> ReachedNode<'view, 'tcx> {
    #[must_use]
    /// Returns this node's graph-local id.
    pub fn id(self) -> ReachabilityNodeId {
        self.id
    }

    #[must_use]
    /// Returns the graph node.
    pub fn node(self) -> &'view ReachabilityNode<'tcx> {
        self.graph.node(self.id)
    }

    #[must_use]
    /// Returns the semantic payload represented by this node.
    pub fn kind(self) -> &'view ReachabilityNodeKind<'tcx> {
        &self.node().kind
    }

    #[must_use]
    /// Returns the breadth-first depth from the query root.
    pub fn depth(self) -> usize {
        self.depth
    }

    #[must_use]
    /// Returns the instance represented by this node, if it is a function node.
    pub fn instance(self) -> Option<Instance<'tcx>> {
        match self.kind() {
            ReachabilityNodeKind::Instance(instance) => Some(*instance),
            ReachabilityNodeKind::CompilerAssert { .. }
            | ReachabilityNodeKind::IndirectCall { .. }
            | ReachabilityNodeKind::DynObjectCast { .. } => None,
        }
    }

    #[must_use]
    /// Returns the predecessor edge that first reached this node.
    pub fn predecessor_edge(self) -> Option<ReachedEdge<'view, 'tcx>> {
        self.snapshot.predecessor_edge(self.id).map(|id| {
            debug_assert!(id.index() < self.graph.edges.len());
            ReachedEdge::new(self.graph, self.snapshot, id)
        })
    }
}

/// An edge accepted by one root-specific query.
#[derive(Clone, Copy)]
pub struct ReachedEdge<'view, 'tcx> {
    graph: &'view ReachabilityGraph<'tcx>,
    snapshot: &'view ReachabilitySnapshot<'tcx>,
    id: ReachabilityEdgeId,
}

impl<'view, 'tcx> ReachedEdge<'view, 'tcx> {
    fn new(
        graph: &'view ReachabilityGraph<'tcx>,
        snapshot: &'view ReachabilitySnapshot<'tcx>,
        id: ReachabilityEdgeId,
    ) -> Self {
        Self {
            graph,
            snapshot,
            id,
        }
    }

    fn reached_node(self, id: ReachabilityNodeId) -> ReachedNode<'view, 'tcx> {
        let depth = self.snapshot.depth(id).unwrap_or_default();
        debug_assert!(self.snapshot.depth(id).is_some());
        ReachedNode {
            graph: self.graph,
            snapshot: self.snapshot,
            id,
            depth,
        }
    }

    #[must_use]
    /// Returns this edge's graph-local id.
    pub fn id(self) -> ReachabilityEdgeId {
        self.id
    }

    #[must_use]
    /// Returns the graph edge.
    pub fn edge(self) -> &'view ReachabilityEdge {
        self.graph.edge(self.id)
    }

    #[must_use]
    /// Returns the source node.
    pub fn source(self) -> ReachedNode<'view, 'tcx> {
        self.reached_node(self.edge().source)
    }

    #[must_use]
    /// Returns the target node.
    pub fn target(self) -> ReachedNode<'view, 'tcx> {
        self.reached_node(self.edge().target)
    }

    #[must_use]
    /// Returns the reason this edge exists.
    pub fn kind(self) -> ReachabilityEdgeKind {
        self.edge().kind
    }

    #[must_use]
    /// Returns the source span responsible for this edge.
    pub fn span(self) -> Span {
        self.edge().span
    }
}

/// Per-root reachability query snapshot over a shared [`ReachabilityGraph`].
///
/// Node and edge ids refer to the shared graph, but depth/predecessor data is
/// local to this root.
pub struct ReachabilitySnapshot<'tcx> {
    root: ReachabilityNodeId,
    node_ids: Vec<ReachabilityNodeId>,
    edge_ids: Vec<ReachabilityEdgeId>,
    depths: Vec<Option<usize>>,
    predecessor_edges: Vec<Option<ReachabilityEdgeId>>,
    halt: Option<ReachabilityHalt<'tcx>>,
}

impl<'tcx> ReachabilitySnapshot<'tcx> {
    fn new(root: ReachabilityNodeId, graph_node_count: usize) -> Self {
        let mut snapshot = Self {
            root,
            node_ids: Vec::new(),
            edge_ids: Vec::new(),
            depths: vec![None; graph_node_count],
            predecessor_edges: vec![None; graph_node_count],
            halt: None,
        };
        snapshot.record_node(root, 0, None);
        snapshot
    }

    #[must_use]
    /// Returns the breadth-first depth of `node` from this query's root.
    pub(crate) fn depth(&self, node: ReachabilityNodeId) -> Option<usize> {
        self.depths.get(node.index()).copied().flatten()
    }

    #[must_use]
    /// Returns the predecessor edge that first reached `node`.
    pub(crate) fn predecessor_edge(&self, node: ReachabilityNodeId) -> Option<ReachabilityEdgeId> {
        self.predecessor_edges.get(node.index()).copied().flatten()
    }

    pub(crate) fn stats(&self) -> ReachabilityQueryStats {
        ReachabilityQueryStats::new(self.node_ids.len(), self.edge_ids.len())
    }

    pub(crate) fn mark_halted(&mut self, halt: ReachabilityHalt<'tcx>) {
        self.halt = Some(halt);
    }

    pub(crate) fn record_edge(
        &mut self,
        edge_id: ReachabilityEdgeId,
        target: ReachabilityNodeId,
        depth: usize,
    ) -> bool {
        self.edge_ids.push(edge_id);
        self.record_node(target, depth, Some(edge_id))
    }

    fn record_node(
        &mut self,
        node: ReachabilityNodeId,
        depth: usize,
        predecessor_edge: Option<ReachabilityEdgeId>,
    ) -> bool {
        self.ensure_node_capacity(node);
        if self.depths[node.index()].is_some() {
            return false;
        }

        self.depths[node.index()] = Some(depth);
        self.predecessor_edges[node.index()] = predecessor_edge;
        self.node_ids.push(node);
        true
    }

    fn ensure_node_capacity(&mut self, node: ReachabilityNodeId) {
        let len = node.index() + 1;
        if self.depths.len() < len {
            self.depths.resize(len, None);
            self.predecessor_edges.resize(len, None);
        }
    }
}

/// Stable node handle inside a [`ReachabilityGraph`].
///
/// Use [`index`](Self::index) to address [`ReachabilityGraph::nodes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReachabilityNodeId(usize);

impl ReachabilityNodeId {
    #[must_use]
    /// Returns the node's index in [`ReachabilityGraph::nodes`].
    pub fn index(self) -> usize {
        self.0
    }
}

/// Stable edge handle inside a [`ReachabilityGraph`].
///
/// Like [`ReachabilityNodeId`], this is graph-local. It is a typed handle into
/// the graph edge arena, not a standalone global identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReachabilityEdgeId(usize);

impl ReachabilityEdgeId {
    #[must_use]
    /// Returns the edge's index in [`ReachabilityGraph::edges`].
    pub fn index(self) -> usize {
        self.0
    }
}

/// One node in the shared reachability graph.
#[derive(Debug)]
pub struct ReachabilityNode<'tcx> {
    /// Stable id for this node within the shared graph.
    pub id: ReachabilityNodeId,
    /// Semantic payload represented by this node.
    pub kind: ReachabilityNodeKind<'tcx>,
}

/// Semantic payload for a graph node.
#[derive(Debug)]
pub enum ReachabilityNodeKind<'tcx> {
    /// Concrete function instance that can potentially be descended into.
    Instance(Instance<'tcx>),
    /// Compiler-generated MIR assertion.
    ///
    /// This includes checks such as overflow, bounds, division by zero, and
    /// invalid shifts. The exact reason is kept as rustc's [`AssertMessage`].
    CompilerAssert { message: Box<AssertMessage<'tcx>> },
    /// Call-like operation whose concrete callee could not be resolved.
    ///
    /// This is used for function pointers and other callable values that do not
    /// monomorphize to a [`TyKind::FnDef`](rustc_middle::ty::TyKind::FnDef).
    IndirectCall { callee_ty: Ty<'tcx> },
    /// Dynamic object unsizing operation.
    ///
    /// The analyzer also emits [`VTableEntry`](ReachabilityEdgeKind::VTableEntry)
    /// edges for methods made available by the object vtable.
    DynObjectCast {
        source_ty: Ty<'tcx>,
        target_ty: Ty<'tcx>,
    },
}

/// Directed edge between two reachability nodes.
#[derive(Clone)]
pub struct ReachabilityEdge {
    /// Source node that emitted the edge.
    pub source: ReachabilityNodeId,
    /// Target node reached by the edge.
    pub target: ReachabilityNodeId,
    /// Reason this edge exists.
    pub kind: ReachabilityEdgeKind,
    /// Source span responsible for the edge.
    pub span: Span,
}

impl ReachabilityEdge {
    pub(crate) fn new(
        source: ReachabilityNodeId,
        target: ReachabilityNodeId,
        kind: ReachabilityEdgeKind,
        span: Span,
    ) -> Self {
        Self {
            source,
            target,
            kind,
            span,
        }
    }
}

/// Reason a reachability edge was emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityEdgeKind {
    /// MIR call terminator to a resolved callee.
    DirectCall,
    /// MIR tail-call terminator to a resolved callee.
    TailCall,
    /// Function item coerced/reified to a function pointer.
    ///
    /// This is not a runtime call. It records that the function value escaped as
    /// a callable pointer.
    FnPointerReify,
    /// Closure coerced to a function pointer.
    ///
    /// This is not a runtime call. It records that the closure's call shim is
    /// made reachable by the coercion.
    ClosureFnPointerReify,
    /// Closure value created in HIR or MIR.
    ///
    /// Closure construction makes the closure body relevant even before the
    /// closure is called directly.
    ClosureDefinition,
    /// Dynamic object unsizing, such as `&T` to `&dyn Trait`.
    DynObjectCast,
    /// Method entry reachable through a dynamic object vtable.
    VTableEntry,
    /// Anonymous or inline const body referenced by the current body.
    ConstBody,
    /// Compiler-generated MIR assertion.
    Assert,
    /// Call-like operation whose concrete callee could not be resolved.
    IndirectCall,
}

impl fmt::Display for ReachabilityEdgeKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DirectCall => "direct-call",
            Self::TailCall => "tail-call",
            Self::FnPointerReify => "fn-pointer-reify",
            Self::ClosureFnPointerReify => "closure-fn-pointer-reify",
            Self::ClosureDefinition => "closure-definition",
            Self::DynObjectCast => "dyn-object-cast",
            Self::VTableEntry => "vtable-entry",
            Self::ConstBody => "const-body",
            Self::Assert => "assert",
            Self::IndirectCall => "indirect-call",
        })
    }
}

#[cfg(test)]
mod tests {
    use rustc_hir::def_id::CRATE_DEF_ID;
    use rustc_middle::ty::{GenericArgs, Instance, InstanceKind};
    use rustc_span::DUMMY_SP;

    use super::{
        ReachabilityEdge, ReachabilityEdgeKind, ReachabilityGraph, ReachedEdge, ReachedNode,
    };
    use crate::hooks::ReachabilityHalt;

    fn crate_instance<'tcx>() -> Instance<'tcx> {
        Instance {
            def: InstanceKind::Item(CRATE_DEF_ID.to_def_id()),
            args: GenericArgs::empty(),
        }
    }

    #[test]
    fn graph_records_shared_nodes_edges_and_query_state() {
        let root = crate_instance();
        let mut graph = ReachabilityGraph::new();

        let root_node = graph.node_for_instance(root);
        let child = graph.node_for_instance(root);
        let edge = graph.push_edge(ReachabilityEdge::new(
            root_node,
            child,
            ReachabilityEdgeKind::ConstBody,
            DUMMY_SP,
        ));
        let mut snapshot = graph.snapshot_for_root(root_node);
        snapshot.record_edge(edge, child, 1);
        snapshot.mark_halted(ReachabilityHalt::NodeLimitReached { limit: 1 });
        let view = graph.view(&snapshot);

        assert_eq!(view.root().id(), root_node);
        assert_eq!(graph.nodes().len(), 1);
        assert_eq!(graph.edges().len(), 1);
        assert_eq!(view.nodes().count(), 1);
        assert_eq!(
            view.edges().map(ReachedEdge::id).collect::<Vec<_>>(),
            [edge]
        );
        assert_eq!(view.node(child).map(ReachedNode::depth), Some(0));
        assert_eq!(
            view.halt(),
            Some(&ReachabilityHalt::NodeLimitReached { limit: 1 })
        );
    }
}
