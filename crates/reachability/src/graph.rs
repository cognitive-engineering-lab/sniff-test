use std::fmt;

use rustc_middle::mir::AssertMessage;
use rustc_middle::ty::{Instance, Ty};
use rustc_span::Span;

use crate::hooks::ReachabilityHalt;

/// Directed graph produced by reachability analysis.
///
/// Nodes represent functions or compiler-level artifacts discovered while
/// walking MIR/HIR. Edges represent the source span and reason the analyzer
/// connected one node to another.
///
/// Function instances are de-duplicated in the graph. Non-function artifacts,
/// such as compiler asserts and indirect calls, are emitted as distinct nodes
/// because their source span and payload are part of the evidence.
#[derive(Debug, Clone)]
pub struct ReachabilityGraph<'tcx> {
    root: ReachabilityNodeId,
    nodes: Vec<ReachabilityNode<'tcx>>,
    edges: Vec<ReachabilityEdge>,
    halt: Option<ReachabilityHalt<'tcx>>,
}

impl<'tcx> ReachabilityGraph<'tcx> {
    pub(crate) fn new(root: Instance<'tcx>) -> Self {
        Self {
            root: ReachabilityNodeId::ROOT,
            nodes: vec![ReachabilityNode {
                id: ReachabilityNodeId::ROOT,
                kind: ReachabilityNodeKind::Instance(root),
                depth: 0,
            }],
            edges: Vec::new(),
            halt: None,
        }
    }

    #[must_use]
    /// Returns the root node id.
    ///
    /// The root is always node `0` and is an [`Instance`](ReachabilityNodeKind::Instance)
    /// node unless analysis halted before a concrete root could be built.
    pub fn root(&self) -> ReachabilityNodeId {
        self.root
    }

    #[must_use]
    /// Returns all graph nodes in insertion order.
    ///
    /// A node id can be used as an index into this slice through
    /// [`ReachabilityNodeId::index`].
    pub fn nodes(&self) -> &[ReachabilityNode<'tcx>] {
        &self.nodes
    }

    #[must_use]
    /// Returns all graph edges in discovery order.
    ///
    /// Edges reference their source and target nodes by [`ReachabilityNodeId`].
    pub fn edges(&self) -> &[ReachabilityEdge] {
        &self.edges
    }

    #[must_use]
    /// Returns why traversal stopped early, if it did.
    ///
    /// A graph can still contain partial results when halted by a hook or node
    /// limit.
    pub fn halt(&self) -> Option<&ReachabilityHalt<'tcx>> {
        self.halt.as_ref()
    }

    pub(crate) fn push_node(
        &mut self,
        kind: ReachabilityNodeKind<'tcx>,
        depth: usize,
    ) -> ReachabilityNodeId {
        let id = ReachabilityNodeId(self.nodes.len());
        self.nodes.push(ReachabilityNode { id, kind, depth });
        id
    }

    pub(crate) fn mark_halted(&mut self, halt: ReachabilityHalt<'tcx>) {
        self.halt = Some(halt);
    }

    pub(crate) fn push_edge(&mut self, edge: ReachabilityEdge) {
        self.edges.push(edge);
    }
}

/// Stable node handle inside a [`ReachabilityGraph`].
///
/// The id is local to one graph. Use [`index`](Self::index) to address
/// [`ReachabilityGraph::nodes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReachabilityNodeId(usize);

impl ReachabilityNodeId {
    const ROOT: Self = Self(0);

    #[must_use]
    /// Returns the node's index in [`ReachabilityGraph::nodes`].
    pub fn index(self) -> usize {
        self.0
    }
}

/// One node in a reachability graph.
#[derive(Debug, Clone)]
pub struct ReachabilityNode<'tcx> {
    /// Stable id for this node within its graph.
    pub id: ReachabilityNodeId,
    /// Semantic payload represented by this node.
    pub kind: ReachabilityNodeKind<'tcx>,
    /// Breadth-first depth from the root node.
    pub depth: usize,
}

/// Semantic payload for a graph node.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
        ReachabilityEdge, ReachabilityEdgeKind, ReachabilityGraph, ReachabilityNodeId,
        ReachabilityNodeKind,
    };
    use crate::hooks::ReachabilityHalt;

    fn crate_instance<'tcx>() -> Instance<'tcx> {
        Instance {
            def: InstanceKind::Item(CRATE_DEF_ID.to_def_id()),
            args: GenericArgs::empty(),
        }
    }

    #[test]
    fn graph_records_nodes_edges_and_halt_reason() {
        let root = crate_instance();
        let mut graph = ReachabilityGraph::new(root);

        let child = graph.push_node(ReachabilityNodeKind::Instance(root), 1);
        graph.push_edge(ReachabilityEdge::new(
            graph.root(),
            child,
            ReachabilityEdgeKind::ConstBody,
            DUMMY_SP,
        ));
        graph.mark_halted(ReachabilityHalt::NodeLimitReached { limit: 1 });

        assert_eq!(graph.root(), ReachabilityNodeId::ROOT);
        assert_eq!(graph.nodes().len(), 2);
        assert_eq!(graph.edges().len(), 1);
        assert_eq!(
            graph.halt(),
            Some(&ReachabilityHalt::NodeLimitReached { limit: 1 })
        );
    }
}
