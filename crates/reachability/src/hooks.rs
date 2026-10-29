use rustc_hir::def_id::DefId;
use rustc_middle::ty::{Instance, Ty, TyCtxt};

/// A library summary invoking a trait method on one of its arguments.
#[derive(Clone, Copy)]
pub struct ModeledInvocation<'tcx> {
    /// MIR argument index, including `self` for methods.
    pub argument: usize,
    /// Trait method with `Self` as its sole generic argument.
    pub method: DefId,
    /// Instantiated receiver type; receiver provenance comes from `argument`.
    pub receiver_ty: Ty<'tcx>,
}

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
    /// Replace a library call's implementation with an argument invocation.
    /// The original API edge remains available for its own obligations.
    fn model_call(
        &self,
        _tcx: TyCtxt<'tcx>,
        _target: Instance<'tcx>,
    ) -> Option<ModeledInvocation<'tcx>> {
        None
    }

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
