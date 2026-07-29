use rustc_middle::ty::{Instance, TyCtxt};

/// Reason reachability analysis stopped before exhausting the work queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachabilityHalt {
    /// The configured node limit was reached.
    NodeLimitReached {
        /// Limit configured in [`ReachabilityOptions`](crate::ReachabilityOptions).
        limit: usize,
    },
}

/// Extension points for reachability traversal.
///
/// Returning `false` from [`should_descend`](Self::should_descend) keeps the
/// edge in the graph but prevents the target function body from being queued.
pub trait ReachabilityHooks<'tcx> {
    /// Decides whether to recursively analyze a target function instance.
    ///
    /// This callback only runs for edges whose target is a concrete
    /// [`Instance`]. Returning `false` still records the edge and target node.
    fn should_descend(&self, _tcx: TyCtxt<'tcx>, _target: Instance<'tcx>) -> bool {
        true
    }
}

/// Hook implementation that observes nothing and descends into every target.
#[derive(Debug, Default)]
pub struct NoopReachabilityHooks;

impl ReachabilityHooks<'_> for NoopReachabilityHooks {}
