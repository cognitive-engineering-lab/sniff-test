//! walk from entry points
//! for each function call, does it satisfy the requirements?
//!

use crate::rustc_middle::mir::visit::Visitor;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::mir::{Operand, TerminatorKind};
use rustc_middle::ty::{TyCtxt, TyKind};
use rustc_span::Span;
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};

pub struct CallGraph {
    data: petgraph::Graph<DefId, Span, petgraph::Directed>,
    indices: HashMap<DefId, petgraph::graph::NodeIndex>,
    _entrypoints: HashSet<LocalDefId>,
}

impl CallGraph {
    pub fn new(entry: impl IntoIterator<Item = LocalDefId>) -> Self {
        CallGraph {
            data: petgraph::Graph::new(),
            indices: HashMap::new(),
            _entrypoints: entry.into_iter().collect(),
        }
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
        let from_i = self.get_index_or_insert(from.to_def_id());
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

    pub fn local_reachable(&self) -> Vec<LocalDefId> {
        self.data
            .node_weights()
            .copied()
            .filter_map(DefId::as_local)
            .collect()
    }
}

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
