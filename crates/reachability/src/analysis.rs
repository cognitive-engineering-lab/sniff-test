use std::collections::{HashMap, VecDeque};
use std::ops::ControlFlow;

use rustc_hir::def_id::{CRATE_DEF_ID, DefId, LocalDefId};
use rustc_middle::ty::{GenericArgs, Instance, InstanceKind, TyCtxt};

use crate::body::{BodyEdge, collect_body_edges};
use crate::graph::{ReachabilityEdge, ReachabilityGraph, ReachabilityNodeId, ReachabilityNodeKind};
use crate::hooks::{ReachabilityContext, ReachabilityControl, ReachabilityHalt, ReachabilityHooks};

/// Starting point for reachability analysis.
#[derive(Debug, Clone, Copy)]
pub enum ReachabilityRoot<'tcx> {
    /// Local non-generic HIR body.
    ///
    /// Generic local bodies cannot be analyzed through this variant because
    /// reachability records concrete [`Instance`]s. Use [`Self::Instance`] once
    /// the generic item has been monomorphized.
    LocalBody(LocalDefId),
    /// Concrete function instance.
    ///
    /// This is the preferred root when analyzing monomorphized code, including
    /// generic functions after rustc has selected concrete type arguments.
    Instance(Instance<'tcx>),
}

impl<'tcx> ReachabilityRoot<'tcx> {
    fn into_instance(self, tcx: TyCtxt<'tcx>) -> Result<Instance<'tcx>, ReachabilityHalt<'tcx>> {
        match self {
            Self::Instance(instance) => Ok(instance),
            Self::LocalBody(def_id) => {
                if tcx
                    .generics_of(def_id.to_def_id())
                    .requires_monomorphization(tcx)
                {
                    Err(ReachabilityHalt::RootRequiresConcreteInstance { root: def_id })
                } else {
                    Ok(Instance::mono(tcx, def_id.to_def_id()))
                }
            }
        }
    }
}

/// Options controlling graph traversal.
#[derive(Debug, Clone, Copy)]
pub struct ReachabilityOptions {
    /// Whether to enqueue reachable function instances and walk them
    /// transitively.
    ///
    /// When false, the graph contains only the root body and its immediate
    /// outgoing edges.
    pub transitive: bool,
    /// Maximum number of function instances to visit.
    ///
    /// The limit counts visited function nodes, not compiler artifact nodes.
    /// When reached, the graph is returned with
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

#[derive(Debug, Clone, Copy)]
struct QueueItem<'tcx> {
    node_id: ReachabilityNodeId,
    instance: Instance<'tcx>,
    depth: usize,
}

/// Analyzes reachability from a local non-generic body with default options.
///
/// # Halting
///
/// If `root` requires monomorphization, the returned graph is marked with
/// [`ReachabilityHalt::RootRequiresConcreteInstance`].
pub fn analyze_local_reachability<'tcx, H>(
    tcx: TyCtxt<'tcx>,
    root: LocalDefId,
    hooks: &mut H,
) -> ReachabilityGraph<'tcx>
where
    H: ReachabilityHooks<'tcx>,
{
    analyze_reachability(
        tcx,
        ReachabilityRoot::LocalBody(root),
        hooks,
        ReachabilityOptions::default(),
    )
}

/// Analyzes reachability from a root function.
///
/// Traversal is breadth-first. Function instances are de-duplicated so a
/// function appears as one node even if multiple call sites point to it. Hooks
/// are called before descending and may stop traversal or suppress recursion
/// into selected targets.
///
/// The returned graph is useful even when [`ReachabilityGraph::halt`] is set;
/// in that case it contains the partial graph discovered before the halt.
pub fn analyze_reachability<'tcx, H>(
    tcx: TyCtxt<'tcx>,
    root: ReachabilityRoot<'tcx>,
    hooks: &mut H,
    options: ReachabilityOptions,
) -> ReachabilityGraph<'tcx>
where
    H: ReachabilityHooks<'tcx>,
{
    let root = match root.into_instance(tcx) {
        Ok(root) => root,
        Err(halt) => {
            let fallback = Instance {
                def: InstanceKind::Item(CRATE_DEF_ID.to_def_id()),
                args: GenericArgs::empty(),
            };
            let mut graph = ReachabilityGraph::new(fallback);
            graph.mark_halted(halt);
            return graph;
        }
    };
    let graph = ReachabilityGraph::new(root);
    let root_node_id = graph.root();
    let instance_nodes = HashMap::from([(root, root_node_id)]);
    let mut builder = ReachabilityGraphBuilder {
        tcx,
        root,
        graph,
        hooks,
        options,
        visited: HashMap::new(),
        instance_nodes,
        queue: VecDeque::from([QueueItem {
            node_id: root_node_id,
            instance: root,
            depth: 0,
        }]),
    };

    if let ControlFlow::Break(halt) = builder.run() {
        builder.graph.mark_halted(halt);
    }

    builder.graph
}

struct ReachabilityGraphBuilder<'a, 'tcx, H> {
    tcx: TyCtxt<'tcx>,
    root: Instance<'tcx>,
    graph: ReachabilityGraph<'tcx>,
    hooks: &'a mut H,
    options: ReachabilityOptions,
    visited: HashMap<Instance<'tcx>, usize>,
    instance_nodes: HashMap<Instance<'tcx>, ReachabilityNodeId>,
    queue: VecDeque<QueueItem<'tcx>>,
}

impl<'tcx, H> ReachabilityGraphBuilder<'_, 'tcx, H>
where
    H: ReachabilityHooks<'tcx>,
{
    fn run(&mut self) -> ReachabilityControl<'tcx> {
        while let Some(item) = self.queue.pop_front() {
            if self.visited.contains_key(&item.instance) {
                continue;
            }

            if let Some(limit) = self.options.node_limit
                && self.visited.len() >= limit
            {
                return ControlFlow::Break(ReachabilityHalt::NodeLimitReached { limit });
            }

            self.visited.insert(item.instance, item.depth);

            let cx = self.context(item.instance, item.depth);
            self.hooks.on_node(cx)?;

            if !self.can_descend_into(item.instance) {
                continue;
            }

            collect_body_edges(self.tcx, item.instance, |edge| self.push_edge(item, edge))?;
        }

        ControlFlow::Continue(())
    }

    fn push_edge(
        &mut self,
        item: QueueItem<'tcx>,
        edge: BodyEdge<'tcx>,
    ) -> ReachabilityControl<'tcx> {
        let (target_id, target_instance) = self.target_node(edge.target, item.depth + 1);
        let edge = ReachabilityEdge::new(item.node_id, target_id, edge.kind, edge.span);
        let cx = self.context(item.instance, item.depth);
        self.hooks.on_edge(cx, &edge)?;

        if self.options.transitive
            && let Some(target) = target_instance
        {
            let should_descend = self.hooks.should_descend(cx, &edge, target)?;
            if should_descend && !self.visited.contains_key(&target) {
                self.queue.push_back(QueueItem {
                    node_id: target_id,
                    instance: target,
                    depth: item.depth + 1,
                });
            }
        }

        self.graph.push_edge(edge);
        ControlFlow::Continue(())
    }

    fn target_node(
        &mut self,
        target: ReachabilityNodeKind<'tcx>,
        depth: usize,
    ) -> (ReachabilityNodeId, Option<Instance<'tcx>>) {
        match target {
            ReachabilityNodeKind::Instance(instance) => {
                let id = if let Some(id) = self.instance_nodes.get(&instance) {
                    *id
                } else {
                    let id = self
                        .graph
                        .push_node(ReachabilityNodeKind::Instance(instance), depth);
                    self.instance_nodes.insert(instance, id);
                    id
                };
                (id, Some(instance))
            }
            target => (self.graph.push_node(target, depth), None),
        }
    }

    fn can_descend_into(&self, instance: Instance<'tcx>) -> bool {
        match instance.def {
            InstanceKind::Item(def_id) => {
                (self.options.analyze_external || def_id.is_local())
                    && self.item_mir_available(def_id)
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
                self.options.analyze_external || instance.def_id().is_local()
            }
        }
    }

    fn item_mir_available(&self, def_id: DefId) -> bool {
        if let Some(local) = def_id.as_local() {
            self.tcx.has_typeck_results(local)
        } else {
            self.tcx.is_mir_available(def_id)
        }
    }

    fn context(&self, current: Instance<'tcx>, depth: usize) -> ReachabilityContext<'tcx> {
        ReachabilityContext {
            tcx: self.tcx,
            root: self.root,
            current,
            depth,
            edge_count: self.graph.edges().len(),
            node_count: self.graph.nodes().len(),
        }
    }
}
