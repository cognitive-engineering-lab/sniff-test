use std::collections::HashMap;
use std::fmt;

use rustc_hir::def_id::DefId;
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
    edges: Vec<StoredEdge<'tcx>>,
    outgoing: Vec<Vec<ReachabilityEdgeId>>,
    instance_nodes: HashMap<Instance<'tcx>, ReachabilityNodeId>,
}

struct StoredEdge<'tcx> {
    edge: ReachabilityEdge,
    callable: Option<CallableEdgeInfo<'tcx>>,
    parent: Option<ReachabilityEdgeId>,
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
    pub fn edges(&self) -> impl ExactSizeIterator<Item = &ReachabilityEdge> + DoubleEndedIterator {
        self.edges.iter().map(|stored| &stored.edge)
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
        &self.edges[edge.index()].edge
    }

    #[must_use]
    /// Returns erased-callable metadata attached to an edge, if any.
    pub fn edge_callable(&self, edge: ReachabilityEdgeId) -> Option<CallableEdgeInfo<'tcx>> {
        self.edges[edge.index()].callable
    }

    #[must_use]
    pub(crate) fn edge_parent(&self, edge: ReachabilityEdgeId) -> Option<ReachabilityEdgeId> {
        self.edges[edge.index()].parent
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
            | ReachabilityNodeKind::DynObjectCast { .. }
            | ReachabilityNodeKind::MacroExpansion { .. } => None,
        }
    }

    pub(crate) fn snapshot_for_root(&self, root: ReachabilityNodeId) -> ReachabilitySnapshot<'tcx> {
        debug_assert!(root.index() < self.nodes.len());
        ReachabilitySnapshot::new(root, self.nodes.len(), self.edges.len())
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
        self.push_edge_with_callable(edge, None)
    }

    pub(crate) fn push_edge_with_callable(
        &mut self,
        edge: ReachabilityEdge,
        callable: Option<CallableEdgeInfo<'tcx>>,
    ) -> ReachabilityEdgeId {
        self.push_stored_edge(edge, callable, None)
    }

    pub(crate) fn push_callable_target_edge(
        &mut self,
        edge: ReachabilityEdge,
        callable: Option<CallableEdgeInfo<'tcx>>,
        parent: ReachabilityEdgeId,
    ) -> ReachabilityEdgeId {
        self.push_stored_edge(edge, callable, Some(parent))
    }

    fn push_stored_edge(
        &mut self,
        edge: ReachabilityEdge,
        callable: Option<CallableEdgeInfo<'tcx>>,
        parent: Option<ReachabilityEdgeId>,
    ) -> ReachabilityEdgeId {
        let id = ReachabilityEdgeId(self.edges.len());
        self.outgoing[edge.source.index()].push(id);
        self.edges.push(StoredEdge {
            edge,
            callable,
            parent,
        });
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
    /// Returns the shared graph arena underlying this query view.
    #[must_use]
    pub fn graph(self) -> &'view ReachabilityGraph<'tcx> {
        self.graph
    }

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

    /// Returns accepted outgoing edges for one node in this query.
    pub fn outgoing_edges(
        self,
        node: ReachabilityNodeId,
    ) -> impl Iterator<Item = ReachedEdge<'view, 'tcx>> + 'view {
        self.graph
            .outgoing_edges(node)
            .iter()
            .copied()
            .filter(move |edge| self.snapshot.contains_edge(*edge))
            .map(move |edge| self.reached_edge(edge))
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
            | ReachabilityNodeKind::DynObjectCast { .. }
            | ReachabilityNodeKind::MacroExpansion { .. } => None,
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
    /// Returns the instance node whose body expansion produced this edge,
    /// skipping any macro-expansion bridge nodes in between.
    pub fn origin(self) -> ReachedNode<'view, 'tcx> {
        self.reached_node(self.edge().origin)
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

    #[must_use]
    /// Returns the callee-segment span for call edges — `foo` in `x.foo(a)` —
    /// which can sit on a different line than the statement span in
    /// multi-line method chains.
    pub fn callee_span(self) -> Option<Span> {
        self.edge().callee_span
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
    reached_edges: Vec<bool>,
    depths: Vec<Option<usize>>,
    predecessor_edges: Vec<Option<ReachabilityEdgeId>>,
    halt: Option<ReachabilityHalt<'tcx>>,
}

impl<'tcx> ReachabilitySnapshot<'tcx> {
    fn new(root: ReachabilityNodeId, graph_node_count: usize, graph_edge_count: usize) -> Self {
        let mut snapshot = Self {
            root,
            node_ids: Vec::new(),
            edge_ids: Vec::new(),
            reached_edges: vec![false; graph_edge_count],
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

    fn contains_edge(&self, edge: ReachabilityEdgeId) -> bool {
        self.reached_edges
            .get(edge.index())
            .copied()
            .unwrap_or(false)
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
        self.ensure_edge_capacity(edge_id);
        if !self.reached_edges[edge_id.index()] {
            self.reached_edges[edge_id.index()] = true;
            self.edge_ids.push(edge_id);
        }
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

    fn ensure_edge_capacity(&mut self, edge: ReachabilityEdgeId) {
        let len = edge.index() + 1;
        if self.reached_edges.len() < len {
            self.reached_edges.resize(len, false);
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
    CompilerAssert {
        message: Box<AssertMessage<'tcx>>,
        locals: Vec<CompilerAssertLocal>,
    },
    /// Macro expansion frame that produced the source span for another edge.
    ///
    /// These nodes are intentionally not deduplicated by macro `DefId`.
    /// Expansion frames are path-specific bridge nodes; sharing them globally
    /// would merge unrelated outgoing edges from different macro call sites.
    MacroExpansion { def_id: DefId },
    /// Call-like operation whose concrete callee could not be resolved.
    ///
    /// This is used for function pointers and other callable values that do not
    /// monomorphize to a [`TyKind::FnDef`](rustc_middle::ty::TyKind::FnDef).
    IndirectCall { callee_ty: Ty<'tcx> },
    /// Dynamic object unsizing operation.
    ///
    /// The analyzer can also emit [`VTableEntry`](ReachabilityEdgeKind::VTableEntry)
    /// and [`DynDispatchVTableEntry`](ReachabilityEdgeKind::DynDispatchVTableEntry)
    /// edges for methods made available by the object vtable.
    DynObjectCast {
        source_ty: Ty<'tcx>,
        target_ty: Ty<'tcx>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerAssertLocal {
    pub index: usize,
    pub name: Option<String>,
    pub role: CompilerAssertLocalRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilerAssertLocalRole {
    ReturnPointer,
    Argument,
    Temporary,
}

/// Type key for callables erased into an indirect representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallableEdgeInfo<'tcx> {
    /// Function item or closure coerced to, or called through, a function pointer.
    FnPointer { fn_ptr_ty: Ty<'tcx> },
    /// Concrete vtable target introduced by, or call through, a dyn trait.
    DynDispatch { trait_def_id: DefId },
}

/// Directed edge between two reachability nodes.
#[derive(Clone)]
pub struct ReachabilityEdge {
    /// Source node that emitted the edge.
    pub source: ReachabilityNodeId,
    /// Target node reached by the edge.
    pub target: ReachabilityNodeId,
    /// Instance node whose body expansion produced the edge. Differs from
    /// `source` only for edges routed through macro-expansion bridge nodes.
    pub origin: ReachabilityNodeId,
    /// Reason this edge exists.
    pub kind: ReachabilityEdgeKind,
    /// Source span responsible for the edge.
    pub span: Span,
    /// Span of the callee segment for call edges — `foo` in `x.foo(a)`.
    pub callee_span: Option<Span>,
}

impl ReachabilityEdge {
    pub(crate) fn new(
        source: ReachabilityNodeId,
        target: ReachabilityNodeId,
        origin: ReachabilityNodeId,
        kind: ReachabilityEdgeKind,
        span: Span,
        callee_span: Option<Span>,
    ) -> Self {
        Self {
            source,
            target,
            origin,
            kind,
            span,
            callee_span,
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
    /// This is not a runtime call. It records that the closure value escaped as
    /// a callable pointer.
    ClosureFnPointerReify,
    /// Concrete callable target reached from a function-pointer call site.
    FnPointerCallTarget,
    /// Dynamic object unsizing, such as `&T` to `&dyn Trait`.
    DynObjectCast,
    /// Method entry reachable through a dynamic object vtable.
    VTableEntry,
    /// Method entry reachable through a dynamic dispatch call after a dynamic
    /// object vtable was introduced in the same body.
    DynDispatchVTableEntry,
    /// Macro expansion frame responsible for the next graph edge.
    MacroExpansion,
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
            Self::FnPointerCallTarget => "fn-pointer-call-target",
            Self::DynObjectCast => "dyn-object-cast",
            Self::VTableEntry => "vtable-entry",
            Self::DynDispatchVTableEntry => "dyn-dispatch-vtable-entry",
            Self::MacroExpansion => "macro-expansion",
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
        CallableEdgeInfo, ReachabilityEdge, ReachabilityEdgeKind, ReachabilityGraph, ReachedEdge,
        ReachedNode,
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
        let callable = CallableEdgeInfo::DynDispatch {
            trait_def_id: CRATE_DEF_ID.to_def_id(),
        };
        let edge = graph.push_edge_with_callable(
            ReachabilityEdge::new(
                root_node,
                child,
                root_node,
                ReachabilityEdgeKind::ConstBody,
                DUMMY_SP,
                None,
            ),
            Some(callable),
        );
        let derived = graph.push_callable_target_edge(
            ReachabilityEdge::new(
                root_node,
                child,
                root_node,
                ReachabilityEdgeKind::FnPointerCallTarget,
                DUMMY_SP,
                None,
            ),
            Some(callable),
            edge,
        );
        let mut snapshot = graph.snapshot_for_root(root_node);
        snapshot.record_edge(edge, child, 1);
        snapshot.mark_halted(ReachabilityHalt::NodeLimitReached { limit: 1 });
        let view = graph.view(&snapshot);

        assert_eq!(view.root().id(), root_node);
        assert_eq!(graph.nodes().len(), 1);
        assert_eq!(graph.edges().len(), 2);
        assert_eq!(graph.edge_callable(edge), Some(callable));
        assert_eq!(graph.edge_parent(edge), None);
        assert_eq!(graph.edge_parent(derived), Some(edge));
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
