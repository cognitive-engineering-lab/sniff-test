//! walk from entry points
//! for each function call, does it satisfy the requirements?
//!

use crate::check::LocalError;
use crate::properties::Property;
use crate::rustc_middle::mir::visit::Visitor;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::mir::{Operand, TerminatorKind};
use rustc_middle::ty::{TyCtxt, TyKind};
use rustc_span::Span;
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::hash::RandomState;

#[derive(Debug)]
pub struct CallGraph {
    data: petgraph::Graph<DefId, Span, petgraph::Directed>,
    indices: HashMap<DefId, petgraph::graph::NodeIndex>,
    // TODO: probably better to abstract this out of the call graph struct...
    entrypoints: HashSet<LocalDefId>,
}

impl CallGraph {
    pub fn new(entry: impl IntoIterator<Item = LocalDefId>) -> Self {
        let mut new = CallGraph {
            data: petgraph::Graph::new(),
            indices: HashMap::new(),
            entrypoints: entry.into_iter().collect(),
        };

        // Specifically insert the entrypoints as they're always reachable
        for entry in new.entrypoints.clone() {
            new.get_index_or_insert(entry.to_def_id());
        }

        new
    }

    fn get_index(&self, def_id: impl Borrow<DefId>) -> Option<NodeIndex> {
        self.indices.get(def_id.borrow()).copied()
    }

    fn get_index_or_insert(&mut self, def_id: impl Borrow<DefId>) -> NodeIndex {
        *self
            .indices
            .entry(*def_id.borrow())
            .or_insert_with_key(|def_id| self.data.add_node(*def_id))
    }

    pub fn add_call_edge(&mut self, from: LocalDefId, to: DefId, at_span: Span) {
        let from_i = self
            .get_index(from.to_def_id())
            .expect("should have already encountered the function we're calling from");
        let to_i = self.get_index_or_insert(to);

        self.data.add_edge(from_i, to_i, at_span);
    }

    // returns a hashmap containing a key for each def id that is called by `from`, with the values having
    // all callsites to that function
    pub fn calls_from(&self, func: LocalDefId) -> HashMap<DefId, Vec<Span>> {
        let Some(index) = self.get_index(func.to_def_id()) else {
            panic!("should have encountered all reachable local def ids, somethings up...");
        };
        let edges = self
            .data
            .edges_directed(index, petgraph::Direction::Outgoing);

        let mut calls: HashMap<DefId, Vec<Span>> = HashMap::new();
        for edge in edges {
            let to = self
                .data
                .node_weight(edge.target())
                .expect("we just got this id from .target()");
            calls.entry(*to).or_default().push(*edge.weight());
        }
        calls
    }

    /// Gets a reachability path from entrypoints to a given def id.
    fn reachability(&self, from: &[DefId], to: DefId) -> Reachability {
        if from.contains(&to) {
            return Reachability::direct();
        }

        let mut paths = from.iter().flat_map(|from| {
            petgraph::algo::all_simple_paths::<
                Vec<NodeIndex>,
                &petgraph::Graph<rustc_span::def_id::DefId, rustc_span::Span>,
                RandomState,
            >(
                &self.data,
                *self
                    .indices
                    .get(from)
                    .expect("should already be in the graph..."),
                *self
                    .indices
                    .get(&to)
                    .expect("should already be in the graph..."),
                0,
                None,
            )
        });
        let first_path: Vec<NodeIndex> = paths
            .next()
            .unwrap_or_else(|| panic!("no path from {from:?} to {to:?} in {self:#?}"));
        let through = first_path
            .into_iter()
            .map_windows(|[a, b]| {
                let def_id = *self.data.node_weight(*a).expect("should have value");
                let edge_i = self.data.find_edge(*a, *b).expect("should have edge");
                let span = *self.data.edge_weight(edge_i).unwrap();
                (def_id, span)
            })
            .collect::<Vec<_>>();
        Reachability { through }
    }

    fn with_reachability_from_entry<P: Property>(
        &self,
        t: LocalError<P>,
    ) -> WithReachability<LocalError<P>> {
        // Get the reachability info from any entry point to this error.
        let reachability = self.reachability(
            &self
                .entrypoints
                .iter()
                .map(|local| local.to_def_id())
                .collect::<Vec<_>>(),
            *t.func(),
        );
        WithReachability(t, reachability)
    }

    pub fn add_reachability<P: Property>(
        &self,
        errors: impl IntoIterator<Item = LocalError<P>>,
    ) -> impl Iterator<Item = WithReachability<LocalError<P>>> {
        errors
            .into_iter()
            .map(|err| self.with_reachability_from_entry(err))
    }

    pub fn local_reachable(&self, tcx: TyCtxt) -> Vec<LocalDefId> {
        let mut reachable: Vec<LocalDefId> = self
            .data
            .node_weights()
            .copied()
            .filter_map(DefId::as_local)
            .collect();

        // Sort by def path string to enforce consistent order
        reachable.sort_by_key(|local_def| tcx.def_path_debug_str(local_def.to_def_id()));

        reachable
    }
}

pub struct Reachability {
    through: Vec<(DefId, Span)>,
}

impl Reachability {
    /// The reachability for an item that is directly reachable (i.e. it is itself an entrypoint)
    pub fn direct() -> Self {
        Reachability {
            through: Vec::new(),
        }
    }

    pub fn through(&self) -> &[(DefId, Span)] {
        &self.through
    }
}

pub struct WithReachability<T>(pub T, pub Reachability);

/// Get an iterator over all locally reachable function definitions from the given `entry_points`.
pub fn build_callgraph(
    tcx: TyCtxt,
    entry_points: impl IntoIterator<Item = LocalDefId>,
) -> CallGraph {
    CallGraphVisitor::new(tcx, entry_points.into_iter()).call_graph()
}

struct CallGraphVisitor<'tcx> {
    tcx: TyCtxt<'tcx>,
    to_visit: Vec<LocalDefId>,
    visited: HashSet<LocalDefId>,
    graph: CallGraph,
}

impl<'tcx> CallGraphVisitor<'tcx> {
    fn new(tcx: TyCtxt<'tcx>, entry_points: impl Iterator<Item = LocalDefId>) -> Self {
        let entry: Vec<LocalDefId> = entry_points.collect();
        Self {
            tcx,
            to_visit: entry.clone(),
            visited: HashSet::new(),
            graph: CallGraph::new(entry),
        }
    }

    fn call_graph(mut self) -> CallGraph {
        while let Some(visit_next) = self.to_visit.pop() {
            if !self.visited.contains(&visit_next) {
                if !self.tcx.has_typeck_results(visit_next) {
                    log::warn!(
                        "found function with no typeck results, not doing anything with it for now... {visit_next:?}"
                    );
                    continue;
                }
                let body = self.tcx.optimized_mir(visit_next);

                let mut visitor = BodyVisitor {
                    call_graph_visitor: &mut self,
                    on_def_id: visit_next,
                };
                visitor.visit_body(body);
            }
        }
        self.graph
    }
}

#[allow(dead_code)]
struct BodyVisitor<'tcx, 'm> {
    call_graph_visitor: &'m mut CallGraphVisitor<'tcx>,
    on_def_id: LocalDefId,
}

impl<'tcx> rustc_middle::mir::visit::Visitor<'tcx> for BodyVisitor<'tcx, '_> {
    fn visit_terminator(
        &mut self,
        terminator: &rustc_middle::mir::Terminator<'tcx>,
        location: rustc_middle::mir::Location,
    ) {
        if let TerminatorKind::Call { func, .. } = &terminator.kind
            && let Operand::Constant(box co) = func
            && let TyKind::FnDef(def_id, _substs) = co.const_.ty().kind()
        {
            self.call_graph_visitor.graph.add_call_edge(
                self.on_def_id,
                *def_id,
                terminator.source_info.span,
            );

            if let Some(local_def) = def_id.as_local() {
                // if they're local, visit them too..
                self.call_graph_visitor.to_visit.push(local_def);
            }
        }

        self.super_terminator(terminator, location);
    }
}
