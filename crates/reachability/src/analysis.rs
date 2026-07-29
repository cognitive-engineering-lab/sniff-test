use std::collections::{HashMap, HashSet, VecDeque};

use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::ty::{GenericArgs, Instance, InstanceKind, TyCtxt};
use rustc_span::Span;

use crate::body::BodyEdge;
use crate::body::collect_body_edges;
use crate::graph::{
    CallableEdgeInfo, ReachabilityEdge, ReachabilityEdgeId, ReachabilityEdgeKind,
    ReachabilityGraph, ReachabilityNodeExpansion, ReachabilityNodeId, ReachabilityNodeKind,
    ReachabilitySnapshot,
};
use crate::hooks::{ReachabilityHalt, ReachabilityHooks};

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

/// Artifact boundary used while expanding reached function instances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactScope {
    /// Expand only instances defined by the crate containing the query root.
    ///
    /// Calls into another crate remain recorded and are classified as
    /// [`ReachabilityNodeExpansion::DifferentArtifact`].
    RootArtifact,
    /// Expand instances from any crate when their MIR is available.
    AllArtifacts,
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
    /// Which artifacts may have their function bodies expanded.
    pub artifact_scope: ArtifactScope,
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
            artifact_scope: ArtifactScope::AllArtifacts,
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
    /// This is a shared-index, trait-keyed approximation. Concrete targets
    /// observed by one query become graph edges that later queries against the
    /// same index can reuse. Each matching dyn call may therefore be connected
    /// to every concrete impl observed so far.
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
    /// This is a shared-index, function-pointer-type-keyed approximation.
    /// Concrete targets observed by one query become graph edges that later
    /// queries against the same index can reuse. Each matching call site may
    /// therefore be connected to every target observed so far.
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
    callable_targets: HashMap<CallableEdgeInfo<'tcx>, Vec<Instance<'tcx>>>,
}

impl<'tcx> ReachabilityIndex<'tcx> {
    #[must_use]
    pub fn new(tcx: TyCtxt<'tcx>) -> Self {
        Self {
            tcx,
            graph: ReachabilityGraph::new(),
            expanded_instances: HashSet::new(),
            callable_targets: HashMap::new(),
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
        hooks: &H,
        options: ReachabilityOptions,
    ) -> ReachabilitySnapshot
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
            pending_callable_calls: HashMap::new(),
            queue: VecDeque::from([QueueItem {
                node_id: root_node_id,
                depth: 0,
            }]),
            snapshot,
        };

        query.run()
    }

    fn ensure_expanded(&mut self, instance: Instance<'tcx>) {
        if self.expanded_instances.contains(&instance) {
            return;
        }

        let source = self.graph.node_for_instance(instance);
        for body_edge in collect_body_edges(self.tcx, instance) {
            self.push_body_edge(source, body_edge);
        }
        self.expanded_instances.insert(instance);
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

    fn expansion_blocker(
        &self,
        root: Instance<'tcx>,
        artifact_scope: ArtifactScope,
        instance: Instance<'tcx>,
    ) -> Option<ReachabilityNodeExpansion> {
        if artifact_scope == ArtifactScope::RootArtifact
            && instance.def_id().krate != root.def_id().krate
        {
            return Some(ReachabilityNodeExpansion::DifferentArtifact);
        }

        match instance.def {
            InstanceKind::Item(def_id) if !self.item_mir_available(def_id) => {
                Some(ReachabilityNodeExpansion::MirUnavailable)
            }
            InstanceKind::Intrinsic(..) | InstanceKind::Virtual(..) => {
                Some(ReachabilityNodeExpansion::UnsupportedInstance)
            }
            InstanceKind::Item(..)
            | InstanceKind::VTableShim(..)
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
            | InstanceKind::AsyncDropGlue(..) => None,
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
struct QueueItem {
    node_id: ReachabilityNodeId,
    depth: usize,
}

struct ReachabilityQuery<'a, 'tcx, H> {
    index: &'a mut ReachabilityIndex<'tcx>,
    root: Instance<'tcx>,
    hooks: &'a H,
    options: ReachabilityOptions,
    visited_instances: HashSet<Instance<'tcx>>,
    visited_bridge_nodes: HashSet<ReachabilityNodeId>,
    pending_callable_calls: HashMap<CallableEdgeInfo<'tcx>, Vec<PendingCallableCallSite>>,
    queue: VecDeque<QueueItem>,
    snapshot: ReachabilitySnapshot,
}

#[derive(Debug, Clone, Copy)]
struct PendingCallableCallSite {
    item: QueueItem,
    edge_id: ReachabilityEdgeId,
}

impl<'tcx, H> ReachabilityQuery<'_, 'tcx, H>
where
    H: ReachabilityHooks<'tcx>,
{
    fn run(mut self) -> ReachabilitySnapshot {
        self.traverse();
        self.snapshot
    }

    fn traverse(&mut self) {
        while let Some(item) = self.queue.pop_front() {
            if let Some(instance) = self.index.graph.node_instance(item.node_id) {
                if self.visited_instances.contains(&instance) {
                    continue;
                }

                if let Some(limit) = self.options.node_limit
                    && self.visited_instances.len() >= limit
                {
                    self.mark_node_limit_frontier(item.node_id);
                    self.snapshot
                        .mark_halted(ReachabilityHalt::NodeLimitReached { limit });
                    return;
                }

                self.visited_instances.insert(instance);

                if let Some(expansion) =
                    self.index
                        .expansion_blocker(self.root, self.options.artifact_scope, instance)
                {
                    self.snapshot.record_expansion(item.node_id, expansion);
                    continue;
                }

                self.index.ensure_expanded(instance);
                self.snapshot
                    .record_expansion(item.node_id, ReachabilityNodeExpansion::Expanded);
            } else if !self.visited_bridge_nodes.insert(item.node_id) {
                continue;
            }

            self.visit_outgoing_edges(item);
        }
    }

    fn visit_outgoing_edges(&mut self, item: QueueItem) {
        let outgoing = self.index.graph.outgoing_edges(item.node_id).to_vec();

        for edge_id in outgoing {
            if self.index.graph.edge_parent(edge_id).is_some() {
                continue;
            }
            self.register_erased_callable_target(edge_id);
            let edge = self.index.graph.edge(edge_id);
            if !self.edge_matches_options(edge) {
                continue;
            }

            self.accept_edge(item, edge_id);
            self.register_callable_call_site(item, edge_id);
        }
    }

    fn accept_edge(&mut self, item: QueueItem, edge_id: ReachabilityEdgeId) {
        let edge = self.index.graph.edge(edge_id).clone();
        let first_reach = self
            .snapshot
            .record_edge(edge_id, edge.target, item.depth + 1);
        if let Some(target) = self.index.graph.node_instance(edge.target) {
            let should_descend = self.hooks.should_descend(self.index.tcx, target);
            if !should_descend {
                self.snapshot
                    .record_expansion(edge.target, ReachabilityNodeExpansion::PolicyBoundary);
            } else if first_reach && !self.visited_instances.contains(&target) {
                self.queue.push_back(QueueItem {
                    node_id: edge.target,
                    depth: item.depth + 1,
                });
            }
        } else if first_reach {
            self.queue.push_back(QueueItem {
                node_id: edge.target,
                depth: item.depth + 1,
            });
        }
    }

    fn mark_node_limit_frontier(&mut self, current: ReachabilityNodeId) {
        let pending = std::iter::once(current)
            .chain(self.queue.iter().map(|item| item.node_id))
            .filter(|node| self.index.graph.node_instance(*node).is_some())
            .collect::<Vec<_>>();
        for node in pending {
            self.snapshot
                .record_expansion(node, ReachabilityNodeExpansion::NodeLimit);
        }
    }

    fn register_erased_callable_target(&mut self, edge_id: ReachabilityEdgeId) {
        let edge = self.index.graph.edge(edge_id);
        let Some(callable) = self.index.graph.edge_callable(edge_id) else {
            return;
        };
        if !is_callable_target_edge(edge.kind, callable) {
            return;
        }
        let Some(target) = self.index.graph.node_instance(edge.target) else {
            return;
        };

        for key in self.callable_target_keys(callable) {
            if !insert_unique(self.index.callable_targets.entry(key).or_default(), target) {
                continue;
            }
            if !self.call_site_attribution_enabled(key) {
                continue;
            }

            let pending = self
                .pending_callable_calls
                .get(&key)
                .cloned()
                .unwrap_or_default();
            for call_site in pending {
                self.accept_callable_target_edge(call_site.item, call_site.edge_id, target);
            }
        }
    }

    fn register_callable_call_site(&mut self, item: QueueItem, edge_id: ReachabilityEdgeId) {
        if !matches!(
            self.index.graph.edge(edge_id).kind,
            ReachabilityEdgeKind::DirectCall
                | ReachabilityEdgeKind::TailCall
                | ReachabilityEdgeKind::IndirectCall
        ) {
            return;
        }

        let Some(callable) = self.index.graph.edge_callable(edge_id) else {
            return;
        };
        if !self.call_site_attribution_enabled(callable) {
            return;
        }

        let call_site = PendingCallableCallSite { item, edge_id };
        self.pending_callable_calls
            .entry(callable)
            .or_default()
            .push(call_site);
        let targets = self
            .index
            .callable_targets
            .get(&callable)
            .cloned()
            .unwrap_or_default();
        for target in targets {
            self.accept_callable_target_edge(item, edge_id, target);
        }
    }

    fn call_site_attribution_enabled(&self, callable: CallableEdgeInfo<'tcx>) -> bool {
        match callable {
            CallableEdgeInfo::FnPointer { .. } => {
                matches!(self.options.fn_pointer_edges, FnPointerEdges::CallSites)
            }
            CallableEdgeInfo::DynDispatch { .. } => matches!(
                self.options.dyn_dispatch_vtable_edges,
                DynDispatchVTableEdges::CallSites
            ),
        }
    }

    fn callable_target_keys(
        &self,
        callable: CallableEdgeInfo<'tcx>,
    ) -> Vec<CallableEdgeInfo<'tcx>> {
        match callable {
            CallableEdgeInfo::FnPointer { .. } => vec![callable],
            CallableEdgeInfo::DynDispatch { trait_def_id } => {
                rustc_middle::ty::elaborate::supertrait_def_ids(self.index.tcx, trait_def_id)
                    .map(|trait_def_id| CallableEdgeInfo::DynDispatch { trait_def_id })
                    .collect()
            }
        }
    }

    fn accept_callable_target_edge(
        &mut self,
        item: QueueItem,
        call_edge_id: ReachabilityEdgeId,
        target: Instance<'tcx>,
    ) {
        let call_edge = self.index.graph.edge(call_edge_id).clone();
        let callable = self
            .index
            .graph
            .edge_callable(call_edge_id)
            .expect("callable target edges require callable parent metadata");
        let target_id = self.index.graph.node_for_instance(target);
        let edge_id = self.callable_target_edge_id(call_edge_id, &call_edge, target_id, callable);
        self.accept_edge(item, edge_id);
    }

    fn callable_target_edge_id(
        &mut self,
        call_edge_id: ReachabilityEdgeId,
        call_edge: &ReachabilityEdge,
        target: ReachabilityNodeId,
        callable: CallableEdgeInfo<'tcx>,
    ) -> ReachabilityEdgeId {
        let kind = callable_target_edge_kind(callable);
        if let Some(edge_id) = self
            .index
            .graph
            .outgoing_edges(call_edge.source)
            .iter()
            .copied()
            .find(|edge_id| {
                let edge = self.index.graph.edge(*edge_id);
                self.index.graph.edge_parent(*edge_id) == Some(call_edge_id)
                    && edge.target == target
                    && edge.kind == kind
                    && self.index.graph.edge_callable(*edge_id) == Some(callable)
            })
        {
            return edge_id;
        }

        self.index.graph.push_callable_target_edge(
            ReachabilityEdge::new(
                call_edge.source,
                target,
                call_edge.origin,
                kind,
                call_edge.span,
                call_edge.callee_span,
            ),
            Some(callable),
            call_edge_id,
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
            | crate::graph::ReachabilityEdgeKind::DynObjectCast
            | crate::graph::ReachabilityEdgeKind::ConstBody
            | crate::graph::ReachabilityEdgeKind::MacroExpansion
            | crate::graph::ReachabilityEdgeKind::Assert
            | crate::graph::ReachabilityEdgeKind::IndirectCall => true,
        }
    }
}

fn callable_target_edge_kind(callable: CallableEdgeInfo<'_>) -> ReachabilityEdgeKind {
    match callable {
        CallableEdgeInfo::FnPointer { .. } => ReachabilityEdgeKind::FnPointerCallTarget,
        CallableEdgeInfo::DynDispatch { .. } => ReachabilityEdgeKind::DynDispatchVTableEntry,
    }
}

fn is_callable_target_edge(
    edge_kind: ReachabilityEdgeKind,
    callable: CallableEdgeInfo<'_>,
) -> bool {
    match callable {
        CallableEdgeInfo::FnPointer { .. } => matches!(
            edge_kind,
            ReachabilityEdgeKind::FnPointerReify | ReachabilityEdgeKind::ClosureFnPointerReify
        ),
        CallableEdgeInfo::DynDispatch { .. } => edge_kind == ReachabilityEdgeKind::VTableEntry,
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
