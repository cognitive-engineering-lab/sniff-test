use std::collections::{HashSet, VecDeque};
use std::ops::ControlFlow;

use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::ty::{GenericArgs, Instance, InstanceKind, TyCtxt};

use crate::body::collect_body_edges;
use crate::graph::{ReachabilityEdge, ReachabilityGraph, ReachabilityNodeId, ReachabilitySnapshot};
use crate::hooks::{ReachabilityContext, ReachabilityControl, ReachabilityHalt, ReachabilityHooks};

/// Starting point for reachability analysis.
#[derive(Debug, Clone, Copy)]
pub enum ReachabilityRoot<'tcx> {
    /// Function definition id analyzed with identity generic arguments.
    ///
    /// Prefer [`Self::Instance`] when concrete generic arguments are known.
    DefId(DefId),
    /// Local HIR body.
    ///
    /// Generic local bodies are analyzed with identity generic arguments.
    /// Calls that still require trait/impl selection are recorded as indirect
    /// boundaries instead of guessing a downstream implementation.
    LocalBody(LocalDefId),
    /// Concrete function instance.
    ///
    /// This is the preferred root when analyzing monomorphized code, including
    /// generic functions after rustc has selected concrete type arguments.
    Instance(Instance<'tcx>),
}

impl From<DefId> for ReachabilityRoot<'_> {
    fn from(def_id: DefId) -> Self {
        Self::DefId(def_id)
    }
}

impl From<LocalDefId> for ReachabilityRoot<'_> {
    fn from(def_id: LocalDefId) -> Self {
        Self::LocalBody(def_id)
    }
}

impl<'tcx> From<Instance<'tcx>> for ReachabilityRoot<'tcx> {
    fn from(instance: Instance<'tcx>) -> Self {
        Self::Instance(instance)
    }
}

/// Converts a query root into the function instance used for traversal.
pub trait IntoInstance<'tcx> {
    fn into_instance(self, tcx: TyCtxt<'tcx>) -> Instance<'tcx>;
}

impl<'tcx> IntoInstance<'tcx> for ReachabilityRoot<'tcx> {
    fn into_instance(self, tcx: TyCtxt<'tcx>) -> Instance<'tcx> {
        match self {
            Self::Instance(instance) => instance,
            Self::DefId(def_id) => {
                Instance::new_raw(def_id, GenericArgs::identity_for_item(tcx, def_id))
            }
            Self::LocalBody(def_id) => Instance::new_raw(
                def_id.to_def_id(),
                GenericArgs::identity_for_item(tcx, def_id.to_def_id()),
            ),
        }
    }
}

impl<'tcx> IntoInstance<'tcx> for Instance<'tcx> {
    fn into_instance(self, _tcx: TyCtxt<'tcx>) -> Instance<'tcx> {
        self
    }
}

impl<'tcx> IntoInstance<'tcx> for DefId {
    fn into_instance(self, tcx: TyCtxt<'tcx>) -> Instance<'tcx> {
        ReachabilityRoot::from(self).into_instance(tcx)
    }
}

/// Options controlling graph traversal.
#[derive(Debug, Clone, Copy)]
pub struct ReachabilityOptions {
    /// Whether to enqueue reachable function instances and walk them
    /// transitively.
    ///
    /// When false, the snapshot contains only the root body and its immediate
    /// outgoing edges.
    pub transitive: bool,
    /// Maximum number of function instances to visit.
    ///
    /// The limit counts visited function nodes, not compiler artifact nodes.
    /// When reached, the snapshot is returned with
    /// [`ReachabilityHalt::NodeLimitReached`].
    pub node_limit: Option<usize>,
    /// Whether traversal may descend into non-local instances when MIR is
    /// available.
    ///
    /// Edges to external functions can still be recorded when this is false;
    /// they are just not recursively expanded.
    pub analyze_external: bool,
}

impl Default for ReachabilityOptions {
    fn default() -> Self {
        Self {
            transitive: true,
            node_limit: None,
            analyze_external: true,
        }
    }
}

/// Shared reachability index for one compiler context.
///
/// The index caches expanded outgoing edges per function instance and stores a
/// shared node/edge arena. Each call to [`query`](Self::query) performs a
/// root-specific BFS over that arena and returns a [`ReachabilitySnapshot`].
pub struct ReachabilityIndex<'tcx> {
    tcx: TyCtxt<'tcx>,
    graph: ReachabilityGraph<'tcx>,
    expanded_instances: HashSet<Instance<'tcx>>,
}

impl<'tcx> ReachabilityIndex<'tcx> {
    #[must_use]
    pub fn new(tcx: TyCtxt<'tcx>) -> Self {
        Self {
            tcx,
            graph: ReachabilityGraph::new(),
            expanded_instances: HashSet::new(),
        }
    }

    #[must_use]
    pub fn graph(&self) -> &ReachabilityGraph<'tcx> {
        &self.graph
    }

    /// Runs a root-specific reachability query over the shared graph.
    pub fn query<R, H>(
        &mut self,
        root: R,
        hooks: &mut H,
        options: ReachabilityOptions,
    ) -> ReachabilitySnapshot<'tcx>
    where
        R: IntoInstance<'tcx>,
        H: ReachabilityHooks<'tcx>,
    {
        let root = root.into_instance(self.tcx);
        let root_node_id = self.graph.node_for_instance(root);
        let snapshot = self.graph.snapshot_for_root(root_node_id);
        let query = ReachabilityQuery {
            index: self,
            root,
            hooks,
            options,
            visited: HashSet::new(),
            queue: VecDeque::from([QueueItem {
                node_id: root_node_id,
                instance: root,
                depth: 0,
            }]),
            snapshot,
        };

        query.run()
    }

    fn ensure_expanded(&mut self, instance: Instance<'tcx>) -> ReachabilityControl<'tcx> {
        if self.expanded_instances.contains(&instance) {
            return ControlFlow::Continue(());
        }

        let source = self.graph.node_for_instance(instance);
        let mut body_edges = Vec::new();
        collect_body_edges(self.tcx, instance, |edge| {
            body_edges.push(edge);
            ControlFlow::Continue(())
        })?;
        for body_edge in body_edges {
            let target = self.graph.node_for_kind(body_edge.target);
            self.graph.push_edge(ReachabilityEdge::new(
                source,
                target,
                body_edge.kind,
                body_edge.span,
            ));
        }
        self.expanded_instances.insert(instance);
        ControlFlow::Continue(())
    }

    fn can_descend_into(&self, options: ReachabilityOptions, instance: Instance<'tcx>) -> bool {
        match instance.def {
            InstanceKind::Item(def_id) => {
                (options.analyze_external || def_id.is_local()) && self.item_mir_available(def_id)
            }
            InstanceKind::Intrinsic(..) | InstanceKind::Virtual(..) => false,
            InstanceKind::VTableShim(..)
            | InstanceKind::ReifyShim(..)
            | InstanceKind::FnPtrShim(..)
            | InstanceKind::ClosureOnceShim { .. }
            | InstanceKind::ConstructCoroutineInClosureShim { .. }
            | InstanceKind::FutureDropPollShim(..)
            | InstanceKind::DropGlue(..)
            | InstanceKind::CloneShim(..)
            | InstanceKind::ThreadLocalShim(..)
            | InstanceKind::FnPtrAddrShim(..)
            | InstanceKind::AsyncDropGlueCtorShim(..)
            | InstanceKind::AsyncDropGlue(..) => {
                options.analyze_external || instance.def_id().is_local()
            }
        }
    }

    fn item_mir_available(&self, def_id: DefId) -> bool {
        if let Some(local) = def_id.as_local() {
            self.tcx.has_typeck_results(local) && self.tcx.hir_maybe_body_owned_by(local).is_some()
        } else {
            self.tcx.is_mir_available(def_id)
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct QueueItem<'tcx> {
    node_id: ReachabilityNodeId,
    instance: Instance<'tcx>,
    depth: usize,
}

struct ReachabilityQuery<'a, 'tcx, H> {
    index: &'a mut ReachabilityIndex<'tcx>,
    root: Instance<'tcx>,
    hooks: &'a mut H,
    options: ReachabilityOptions,
    visited: HashSet<Instance<'tcx>>,
    queue: VecDeque<QueueItem<'tcx>>,
    snapshot: ReachabilitySnapshot<'tcx>,
}

impl<'tcx, H> ReachabilityQuery<'_, 'tcx, H>
where
    H: ReachabilityHooks<'tcx>,
{
    fn run(mut self) -> ReachabilitySnapshot<'tcx> {
        if let ControlFlow::Break(halt) = self.traverse() {
            self.snapshot.mark_halted(halt);
        }

        self.snapshot
    }

    fn traverse(&mut self) -> ReachabilityControl<'tcx> {
        while let Some(item) = self.queue.pop_front() {
            if self.visited.contains(&item.instance) {
                continue;
            }

            if let Some(limit) = self.options.node_limit
                && self.visited.len() >= limit
            {
                return ControlFlow::Break(ReachabilityHalt::NodeLimitReached { limit });
            }

            self.visited.insert(item.instance);

            let cx = self.context(item.instance, item.depth);
            self.hooks.on_node(cx)?;

            if !self.index.can_descend_into(self.options, item.instance) {
                continue;
            }

            self.index.ensure_expanded(item.instance)?;
            self.visit_outgoing_edges(item)?;
        }

        ControlFlow::Continue(())
    }

    fn visit_outgoing_edges(&mut self, item: QueueItem<'tcx>) -> ReachabilityControl<'tcx> {
        let outgoing = self.index.graph.outgoing_edges(item.node_id).to_vec();

        for edge_id in outgoing {
            let edge = self.index.graph.edge(edge_id).clone();
            let cx = self.context(item.instance, item.depth);
            self.hooks.on_edge(cx, &edge)?;

            let first_reach = self
                .snapshot
                .record_edge(edge_id, edge.target, item.depth + 1);
            if self.options.transitive
                && let Some(target) = self.index.graph.node_instance(edge.target)
            {
                let should_descend = self.hooks.should_descend(cx, &edge, target)?;
                if should_descend && first_reach && !self.visited.contains(&target) {
                    self.queue.push_back(QueueItem {
                        node_id: edge.target,
                        instance: target,
                        depth: item.depth + 1,
                    });
                }
            }
        }

        ControlFlow::Continue(())
    }

    fn context(&self, current: Instance<'tcx>, depth: usize) -> ReachabilityContext<'tcx> {
        ReachabilityContext {
            tcx: self.index.tcx,
            root: self.root,
            current,
            depth,
            stats: self.snapshot.stats(),
        }
    }
}
