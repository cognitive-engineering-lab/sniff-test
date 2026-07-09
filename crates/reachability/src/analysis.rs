use std::collections::{HashMap, HashSet, VecDeque};
use std::ops::ControlFlow;

use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::ty::{GenericArgs, Instance, InstanceKind, Ty, TyCtxt};
use rustc_span::Span;

use crate::body::BodyEdge;
use crate::body::collect_body_edges;
use crate::graph::{
    CallableEdgeInfo, ReachabilityEdge, ReachabilityEdgeId, ReachabilityEdgeKind,
    ReachabilityGraph, ReachabilityNodeId, ReachabilityNodeKind, ReachabilitySnapshot,
};
use crate::hooks::{ReachabilityContext, ReachabilityControl, ReachabilityHalt, ReachabilityHooks};

/// Starting point for reachability analysis.
#[derive(Debug, Clone, Copy)]
pub enum ReachabilityRoot<'tcx> {
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

/// Options controlling graph traversal.
#[derive(Debug, Clone, Copy)]
pub struct ReachabilityOptions {
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
    /// Where concrete vtable method edges introduced by dynamic object casts
    /// should be recorded.
    pub dyn_dispatch_vtable_edges: DynDispatchVTableEdges,
    /// Where concrete function-pointer targets introduced by reification
    /// should be recorded.
    pub fn_pointer_edges: FnPointerEdges,
}

impl Default for ReachabilityOptions {
    fn default() -> Self {
        Self {
            node_limit: None,
            analyze_external: true,
            dyn_dispatch_vtable_edges: DynDispatchVTableEdges::CastSites,
            fn_pointer_edges: FnPointerEdges::ReifySites,
        }
    }
}

/// Source locations used for concrete vtable methods introduced by dynamic
/// object casts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynDispatchVTableEdges {
    /// Record concrete vtable methods at the object unsizing cast.
    CastSites,
    /// Record concrete vtable methods at dynamic dispatch call sites.
    ///
    /// This is a query-local, trait-keyed approximation. If a query reaches
    /// multiple concrete values cast to the same dyn trait, each dyn call to
    /// that trait may be connected to every observed concrete impl.
    CallSites,
}

/// Source locations used for concrete function-pointer targets introduced by
/// function item or closure reification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FnPointerEdges {
    /// Record concrete callables at the reification site.
    ReifySites,
    /// Record concrete callables at function-pointer call sites.
    ///
    /// This is a query-local, function-pointer-type-keyed approximation. If a
    /// query reaches multiple reifications to the same function-pointer type,
    /// each matching call site may be connected to every observed target.
    CallSites,
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
            visited_instances: HashSet::new(),
            visited_bridge_nodes: HashSet::new(),
            fn_pointer_targets: HashMap::new(),
            dyn_dispatch_targets: HashMap::new(),
            pending_fn_pointer_calls: HashMap::new(),
            pending_dyn_dispatch_calls: HashMap::new(),
            queue: VecDeque::from([QueueItem {
                node_id: root_node_id,
                current_instance: root,
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
            self.push_body_edge(source, body_edge);
        }
        self.expanded_instances.insert(instance);
        ControlFlow::Continue(())
    }

    fn push_body_edge(&mut self, source: ReachabilityNodeId, body_edge: BodyEdge<'tcx>) {
        let mut current = source;
        for frame in macro_expansion_frames(body_edge.span) {
            let macro_node = self
                .graph
                .node_for_kind(ReachabilityNodeKind::MacroExpansion {
                    def_id: frame.def_id,
                });
            self.graph.push_edge(ReachabilityEdge::new(
                current,
                macro_node,
                source,
                ReachabilityEdgeKind::MacroExpansion,
                frame.call_site,
                None,
            ));
            current = macro_node;
        }

        let target = self.graph.node_for_kind(body_edge.target);
        self.graph.push_edge_with_callable(
            ReachabilityEdge::new(
                current,
                target,
                source,
                body_edge.kind,
                body_edge.span,
                body_edge.callee_span,
            ),
            body_edge.callable,
        );
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
    current_instance: Instance<'tcx>,
    depth: usize,
}

struct ReachabilityQuery<'a, 'tcx, H> {
    index: &'a mut ReachabilityIndex<'tcx>,
    root: Instance<'tcx>,
    hooks: &'a mut H,
    options: ReachabilityOptions,
    visited_instances: HashSet<Instance<'tcx>>,
    visited_bridge_nodes: HashSet<ReachabilityNodeId>,
    fn_pointer_targets: HashMap<Ty<'tcx>, Vec<Instance<'tcx>>>,
    dyn_dispatch_targets: HashMap<DefId, Vec<Instance<'tcx>>>,
    pending_fn_pointer_calls: HashMap<Ty<'tcx>, Vec<PendingCallableCallSite<'tcx>>>,
    pending_dyn_dispatch_calls: HashMap<DefId, Vec<PendingCallableCallSite<'tcx>>>,
    queue: VecDeque<QueueItem<'tcx>>,
    snapshot: ReachabilitySnapshot<'tcx>,
}

#[derive(Debug, Clone, Copy)]
struct PendingCallableCallSite<'tcx> {
    item: QueueItem<'tcx>,
    edge_id: ReachabilityEdgeId,
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
            if let Some(instance) = self.index.graph.node_instance(item.node_id) {
                if self.visited_instances.contains(&instance) {
                    continue;
                }

                if let Some(limit) = self.options.node_limit
                    && self.visited_instances.len() >= limit
                {
                    return ControlFlow::Break(ReachabilityHalt::NodeLimitReached { limit });
                }

                self.visited_instances.insert(instance);

                let cx = self.context(instance, item.depth);
                self.hooks.on_node(cx)?;

                if !self.index.can_descend_into(self.options, instance) {
                    continue;
                }

                self.index.ensure_expanded(instance)?;
            } else if !self.visited_bridge_nodes.insert(item.node_id) {
                continue;
            }

            self.visit_outgoing_edges(item)?;
        }

        ControlFlow::Continue(())
    }

    fn visit_outgoing_edges(&mut self, item: QueueItem<'tcx>) -> ReachabilityControl<'tcx> {
        let outgoing = self.index.graph.outgoing_edges(item.node_id).to_vec();

        for edge_id in outgoing {
            self.register_erased_callable_target(edge_id)?;
            let edge = self.index.graph.edge(edge_id);
            if !self.edge_matches_options(edge) {
                continue;
            }

            if self.accept_edge(item, edge_id)? {
                self.register_callable_call_site(item, edge_id)?;
            }
        }

        ControlFlow::Continue(())
    }

    fn accept_edge(
        &mut self,
        item: QueueItem<'tcx>,
        edge_id: ReachabilityEdgeId,
    ) -> ReachabilityControl<'tcx, bool> {
        let edge = self.index.graph.edge(edge_id).clone();
        let cx = self.context(item.current_instance, item.depth);
        self.hooks.on_edge(cx, &edge)?;
        if !self.hooks.should_record_edge(cx, &edge)? {
            return ControlFlow::Continue(false);
        }

        let first_reach = self
            .snapshot
            .record_edge(edge_id, edge.target, item.depth + 1);
        if let Some(target) = self.index.graph.node_instance(edge.target) {
            let should_descend = self.hooks.should_descend(cx, &edge, target)?;
            if should_descend && first_reach && !self.visited_instances.contains(&target) {
                self.queue.push_back(QueueItem {
                    node_id: edge.target,
                    current_instance: target,
                    depth: item.depth + 1,
                });
            }
        } else if first_reach {
            self.queue.push_back(QueueItem {
                node_id: edge.target,
                current_instance: item.current_instance,
                depth: item.depth + 1,
            });
        }

        ControlFlow::Continue(true)
    }

    fn register_erased_callable_target(
        &mut self,
        edge_id: ReachabilityEdgeId,
    ) -> ReachabilityControl<'tcx> {
        let edge = self.index.graph.edge(edge_id);
        match (edge.kind, self.index.graph.edge_callable(edge_id)) {
            (
                ReachabilityEdgeKind::FnPointerReify | ReachabilityEdgeKind::ClosureFnPointerReify,
                Some(CallableEdgeInfo::FnPointer { fn_ptr_ty }),
            ) if matches!(self.options.fn_pointer_edges, FnPointerEdges::CallSites) => {
                let Some(target) = self.index.graph.node_instance(edge.target) else {
                    return ControlFlow::Continue(());
                };
                if insert_unique(
                    self.fn_pointer_targets.entry(fn_ptr_ty).or_default(),
                    target,
                ) {
                    let pending = self
                        .pending_fn_pointer_calls
                        .get(&fn_ptr_ty)
                        .cloned()
                        .unwrap_or_default();
                    for call_site in pending {
                        self.accept_callable_target_edge(
                            call_site.item,
                            call_site.edge_id,
                            target,
                            ReachabilityEdgeKind::FnPointerCallTarget,
                        )?;
                    }
                }
            }
            (
                ReachabilityEdgeKind::VTableEntry,
                Some(CallableEdgeInfo::DynDispatch { trait_def_id }),
            ) if matches!(
                self.options.dyn_dispatch_vtable_edges,
                DynDispatchVTableEdges::CallSites
            ) =>
            {
                let Some(target) = self.index.graph.node_instance(edge.target) else {
                    return ControlFlow::Continue(());
                };
                if insert_unique(
                    self.dyn_dispatch_targets.entry(trait_def_id).or_default(),
                    target,
                ) {
                    let pending = self
                        .pending_dyn_dispatch_calls
                        .get(&trait_def_id)
                        .cloned()
                        .unwrap_or_default();
                    for call_site in pending {
                        self.accept_callable_target_edge(
                            call_site.item,
                            call_site.edge_id,
                            target,
                            ReachabilityEdgeKind::DynDispatchVTableEntry,
                        )?;
                    }
                }
            }
            _ => {}
        }

        ControlFlow::Continue(())
    }

    fn register_callable_call_site(
        &mut self,
        item: QueueItem<'tcx>,
        edge_id: ReachabilityEdgeId,
    ) -> ReachabilityControl<'tcx> {
        if !matches!(
            self.index.graph.edge(edge_id).kind,
            ReachabilityEdgeKind::DirectCall
                | ReachabilityEdgeKind::TailCall
                | ReachabilityEdgeKind::IndirectCall
        ) {
            return ControlFlow::Continue(());
        }

        match self.index.graph.edge_callable(edge_id) {
            Some(CallableEdgeInfo::FnPointer { fn_ptr_ty })
                if matches!(self.options.fn_pointer_edges, FnPointerEdges::CallSites) =>
            {
                let call_site = PendingCallableCallSite { item, edge_id };
                self.pending_fn_pointer_calls
                    .entry(fn_ptr_ty)
                    .or_default()
                    .push(call_site);
                let targets = self
                    .fn_pointer_targets
                    .get(&fn_ptr_ty)
                    .cloned()
                    .unwrap_or_default();
                for target in targets {
                    self.accept_callable_target_edge(
                        item,
                        edge_id,
                        target,
                        ReachabilityEdgeKind::FnPointerCallTarget,
                    )?;
                }
            }
            Some(CallableEdgeInfo::DynDispatch { trait_def_id })
                if matches!(
                    self.options.dyn_dispatch_vtable_edges,
                    DynDispatchVTableEdges::CallSites
                ) =>
            {
                let call_site = PendingCallableCallSite { item, edge_id };
                self.pending_dyn_dispatch_calls
                    .entry(trait_def_id)
                    .or_default()
                    .push(call_site);
                let targets = self
                    .dyn_dispatch_targets
                    .get(&trait_def_id)
                    .cloned()
                    .unwrap_or_default();
                for target in targets {
                    self.accept_callable_target_edge(
                        item,
                        edge_id,
                        target,
                        ReachabilityEdgeKind::DynDispatchVTableEntry,
                    )?;
                }
            }
            _ => {}
        }

        ControlFlow::Continue(())
    }

    fn accept_callable_target_edge(
        &mut self,
        item: QueueItem<'tcx>,
        call_edge_id: ReachabilityEdgeId,
        target: Instance<'tcx>,
        kind: ReachabilityEdgeKind,
    ) -> ReachabilityControl<'tcx> {
        let call_edge = self.index.graph.edge(call_edge_id).clone();
        let callable = self.index.graph.edge_callable(call_edge_id);
        let target_id = self.index.graph.node_for_instance(target);
        let edge_id = self.callable_target_edge_id(&call_edge, target_id, kind, callable);
        self.accept_edge(item, edge_id)?;
        ControlFlow::Continue(())
    }

    fn callable_target_edge_id(
        &mut self,
        call_edge: &ReachabilityEdge,
        target: ReachabilityNodeId,
        kind: ReachabilityEdgeKind,
        callable: Option<CallableEdgeInfo<'tcx>>,
    ) -> ReachabilityEdgeId {
        if let Some(edge_id) = self
            .index
            .graph
            .outgoing_edges(call_edge.source)
            .iter()
            .copied()
            .find(|edge_id| {
                let edge = self.index.graph.edge(*edge_id);
                edge.target == target
                    && edge.kind == kind
                    && edge.span.source_equal(call_edge.span)
                    && optional_span_source_equal(edge.callee_span, call_edge.callee_span)
                    && self.index.graph.edge_callable(*edge_id) == callable
            })
        {
            return edge_id;
        }

        self.index.graph.push_edge_with_callable(
            ReachabilityEdge::new(
                call_edge.source,
                target,
                call_edge.origin,
                kind,
                call_edge.span,
                call_edge.callee_span,
            ),
            callable,
        )
    }

    fn edge_matches_options(&self, edge: &ReachabilityEdge) -> bool {
        match edge.kind {
            crate::graph::ReachabilityEdgeKind::FnPointerReify
            | crate::graph::ReachabilityEdgeKind::ClosureFnPointerReify => {
                matches!(self.options.fn_pointer_edges, FnPointerEdges::ReifySites)
            }
            crate::graph::ReachabilityEdgeKind::FnPointerCallTarget => {
                matches!(self.options.fn_pointer_edges, FnPointerEdges::CallSites)
            }
            crate::graph::ReachabilityEdgeKind::VTableEntry => matches!(
                self.options.dyn_dispatch_vtable_edges,
                DynDispatchVTableEdges::CastSites
            ),
            crate::graph::ReachabilityEdgeKind::DynDispatchVTableEntry => matches!(
                self.options.dyn_dispatch_vtable_edges,
                DynDispatchVTableEdges::CallSites
            ),
            crate::graph::ReachabilityEdgeKind::DirectCall
            | crate::graph::ReachabilityEdgeKind::TailCall
            | crate::graph::ReachabilityEdgeKind::ClosureDefinition
            | crate::graph::ReachabilityEdgeKind::DynObjectCast
            | crate::graph::ReachabilityEdgeKind::ConstBody
            | crate::graph::ReachabilityEdgeKind::MacroExpansion
            | crate::graph::ReachabilityEdgeKind::Assert
            | crate::graph::ReachabilityEdgeKind::IndirectCall => true,
        }
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

fn insert_unique<T: PartialEq>(values: &mut Vec<T>, value: T) -> bool {
    if values.contains(&value) {
        false
    } else {
        values.push(value);
        true
    }
}

fn optional_span_source_equal(left: Option<Span>, right: Option<Span>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.source_equal(right),
        (None, None) => true,
        _ => false,
    }
}

#[derive(Clone, Copy)]
struct MacroExpansionFrame {
    def_id: DefId,
    call_site: Span,
}

fn macro_expansion_frames(span: Span) -> Vec<MacroExpansionFrame> {
    let mut frames = span
        .macro_backtrace()
        .filter_map(|expansion| {
            expansion.macro_def_id.map(|def_id| MacroExpansionFrame {
                def_id,
                call_site: expansion.call_site,
            })
        })
        .collect::<Vec<_>>();
    frames.reverse();
    frames.dedup_by(|left, right| {
        left.def_id == right.def_id && left.call_site.source_equal(right.call_site)
    });
    frames
}
