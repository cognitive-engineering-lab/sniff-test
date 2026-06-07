use std::ops::ControlFlow;

use rustc_middle::ty::{Instance, TyCtxt};
use rustc_span::Span;

use crate::graph::ReachabilityEdge;

/// Control-flow type used by reachability hooks.
///
/// Returning [`ControlFlow::Break`] halts analysis and stores the supplied
/// [`ReachabilityHalt`] in the graph.
pub type ReachabilityControl<'tcx, T = ()> = ControlFlow<ReachabilityHalt<'tcx>, T>;

/// Reason reachability analysis stopped before exhausting the work queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityHalt<'tcx> {
    /// A hook explicitly requested that traversal stop.
    HookRequested {
        /// Instance being visited when the hook stopped traversal.
        caller: Instance<'tcx>,
        /// Source span associated with the hook's decision.
        span: Span,
        /// Static human-readable reason for diagnostics.
        reason: &'static str,
    },
    /// The requested root was generic and no concrete instance was provided.
    RootRequiresConcreteInstance {
        /// Generic local root that could not be converted to an instance.
        root: rustc_hir::def_id::LocalDefId,
    },
    /// The configured node limit was reached.
    NodeLimitReached {
        /// Limit configured in [`ReachabilityOptions`](crate::ReachabilityOptions).
        limit: usize,
    },
}

/// Context passed to reachability hooks.
#[derive(Clone, Copy)]
pub struct ReachabilityContext<'tcx> {
    /// Rust compiler context.
    pub tcx: TyCtxt<'tcx>,
    /// Root instance for the current analysis.
    pub root: Instance<'tcx>,
    /// Function instance currently being visited.
    pub current: Instance<'tcx>,
    /// Breadth-first depth of `current` from the root.
    pub depth: usize,
    /// Number of graph edges emitted before this callback.
    pub edge_count: usize,
    /// Number of graph nodes emitted before this callback.
    pub node_count: usize,
}

/// Extension points for reachability traversal.
///
/// Hooks can observe nodes and edges, halt analysis, and decide whether a
/// reachable function should be recursively expanded. Returning `false` from
/// [`should_descend`](Self::should_descend) keeps the edge in the graph but
/// prevents the target function body from being queued.
pub trait ReachabilityHooks<'tcx> {
    /// Called when a function instance is dequeued for traversal.
    fn on_node(&mut self, _cx: ReachabilityContext<'tcx>) -> ReachabilityControl<'tcx> {
        ControlFlow::Continue(())
    }

    /// Called before an edge is inserted into the graph.
    ///
    /// Halting here prevents the edge from being pushed to the final graph.
    fn on_edge(
        &mut self,
        _cx: ReachabilityContext<'tcx>,
        _edge: &ReachabilityEdge,
    ) -> ReachabilityControl<'tcx> {
        ControlFlow::Continue(())
    }

    /// Decides whether to recursively analyze a target function instance.
    ///
    /// This callback only runs for edges whose target is a concrete
    /// [`Instance`]. Returning `false` still records the edge and target node.
    fn should_descend(
        &mut self,
        _cx: ReachabilityContext<'tcx>,
        _edge: &ReachabilityEdge,
        _target: Instance<'tcx>,
    ) -> ReachabilityControl<'tcx, bool> {
        ControlFlow::Continue(true)
    }
}

/// Hook implementation that observes nothing and descends into every target.
#[derive(Debug, Default)]
pub struct NoopReachabilityHooks;

impl ReachabilityHooks<'_> for NoopReachabilityHooks {}
