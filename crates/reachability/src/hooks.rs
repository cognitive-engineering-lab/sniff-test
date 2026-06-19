use std::ops::ControlFlow;

use rustc_middle::ty::{Instance, TyCtxt};
use rustc_span::Span;

use crate::graph::ReachabilityEdge;

/// Control-flow type used by reachability hooks.
///
/// Returning [`ControlFlow::Break`] halts the current query and stores the
/// supplied [`ReachabilityHalt`] in the result.
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
    /// The configured node limit was reached.
    NodeLimitReached {
        /// Limit configured in [`ReachabilityOptions`](crate::ReachabilityOptions).
        limit: usize,
    },
}

/// Root-specific traversal progress visible to hooks.
///
/// These counts describe the current query, not the shared graph arena. They
/// are intentionally exposed as hook progress data instead of as details of
/// [`ReachabilitySnapshot`](crate::ReachabilitySnapshot)'s internal storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReachabilityQueryStats {
    reached_nodes: usize,
    accepted_edges: usize,
}

impl ReachabilityQueryStats {
    pub(crate) fn new(reached_nodes: usize, accepted_edges: usize) -> Self {
        Self {
            reached_nodes,
            accepted_edges,
        }
    }

    #[must_use]
    /// Returns the number of nodes reached by this query before the callback.
    pub fn reached_nodes(self) -> usize {
        self.reached_nodes
    }

    #[must_use]
    /// Returns the number of edges accepted by this query before the callback.
    pub fn accepted_edges(self) -> usize {
        self.accepted_edges
    }
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
    /// Root-specific traversal progress before this callback.
    pub stats: ReachabilityQueryStats,
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

    /// Called before an edge is accepted into the current query result.
    ///
    /// Halting here prevents the edge from being pushed to the query result.
    fn on_edge(
        &mut self,
        _cx: ReachabilityContext<'tcx>,
        _edge: &ReachabilityEdge,
    ) -> ReachabilityControl<'tcx> {
        ControlFlow::Continue(())
    }

    /// Decides whether to accept an edge into the current query result.
    ///
    /// Returning `false` skips this edge for the current root without halting
    /// analysis. This is useful for source-local suppressions where a specific
    /// call or compiler assertion has been inspected and should not affect
    /// reachability from that root.
    fn should_record_edge(
        &mut self,
        _cx: ReachabilityContext<'tcx>,
        _edge: &ReachabilityEdge,
    ) -> ReachabilityControl<'tcx, bool> {
        ControlFlow::Continue(true)
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
