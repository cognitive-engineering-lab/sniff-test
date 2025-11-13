//! walk from entry points
//! for each function call, does it satisfy the requirements?
//!

use crate::rustc_middle::mir::visit::Visitor;
use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_middle::mir::{Operand, TerminatorKind};
use rustc_middle::ty::{TyCtxt, TyKind};
use rustc_span::Span;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
pub struct LocallyReachable {
    /// The item that can be reached.
    pub reach: LocalDefId,
    /// The path of calls between items through which you can reach this item.
    pub through: Vec<(LocalDefId, Span)>,
    /// The functions (not necessarily local) that this one calls to.
    pub calls_to: HashMap<DefId, Vec<Span>>,
}

impl LocallyReachable {
    /// Say that this locally reachable item can go to another `def_id` through a call at a given `span`.
    fn extended_to(&self, def_id: LocalDefId, span: Span) -> Self {
        LocallyReachable {
            reach: def_id,
            through: self
                .through
                .iter()
                .copied()
                .chain(std::iter::once((self.reach, span)))
                .collect(),
            calls_to: HashMap::new(),
        }
    }

    fn calls_to(&mut self, def_id: DefId, span: Span) {
        self.calls_to.entry(def_id).or_default().push(span);
    }
}

/// Get an iterator over all locally reachable function definitions from the given `entry_points`.
pub fn locally_reachable_from(
    tcx: TyCtxt,
    entry_points: impl IntoIterator<Item = LocalDefId>,
) -> impl Iterator<Item = LocallyReachable> {
    CallGraphVisitor::new(tcx, entry_points.into_iter()).all_local_reachable()
}

struct CallGraphVisitor<'tcx> {
    tcx: TyCtxt<'tcx>,
    /// Queue of reachable items we want to visit.
    ///
    /// This lets us to BFS to get the shortest path to each item.
    to_visit: VecDeque<LocallyReachable>,
    reachable: HashMap<LocalDefId, LocallyReachable>,
}

impl<'tcx> CallGraphVisitor<'tcx> {
    fn new(tcx: TyCtxt<'tcx>, entry_points: impl Iterator<Item = LocalDefId>) -> Self {
        Self {
            tcx,
            to_visit: entry_points
                .map(|reach| LocallyReachable {
                    reach,
                    through: Vec::new(),
                    calls_to: HashMap::new(),
                })
                .collect(),
            reachable: HashMap::new(),
        }
    }

    fn all_local_reachable(mut self) -> impl Iterator<Item = LocallyReachable> {
        while let Some(mut d) = self.to_visit.pop_front() {
            if !self.reachable.contains_key(&d.reach) {
                let kind = self.tcx.def_kind(d.reach);
                let parent_kind = self.tcx.def_kind(self.tcx.parent(d.reach.into()));
                let is_trait_fn = kind == DefKind::AssocFn && parent_kind == DefKind::Trait;

                if is_trait_fn {
                    // TODO: Here, we need to check all implementors of the trait and mark them as reachable!!
                    // The core thing here is we want to be able to detect when we're calling into a trait function.
                    log::warn!("found trait function, not doing anything with it for now... {d:?}");
                    continue;
                }

                let body = self.tcx.optimized_mir(d.reach);
                // log::debug!("SUCCESS");
                let mut visitor = BodyVisitor(self.tcx, &mut self.to_visit, &mut d);
                visitor.visit_body(body);
                self.reachable.insert(d.reach, d);
            }
        }
        self.reachable.into_values()
    }
}

struct BodyVisitor<'tcx, 'm>(
    TyCtxt<'tcx>,
    &'m mut VecDeque<LocallyReachable>,
    &'m mut LocallyReachable,
);

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
            self.2.calls_to(*def_id, terminator.source_info.span);
            if let Some(local_def) = def_id.as_local() {
                // Doing BFS here to ensure we get the shortest path possible to all reachable items.
                self.1
                    .push_back(self.2.extended_to(local_def, terminator.source_info.span));
            }
        }

        self.super_terminator(terminator, location);
    }
}
