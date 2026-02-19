//! walk from entry points
//! for each function call, does it satisfy the requirements?
//!

use crate::rustc_middle::mir::visit::Visitor;
use rustc_hir::def_id::{DefId, LOCAL_CRATE, LocalDefId};
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
) -> Vec<LocallyReachable> {
    let (all_reachable, locally_reachable) =
        CallGraphVisitor::new(tcx, entry_points.into_iter()).reachable();
    let mut locally_reachable = locally_reachable.collect::<Vec<_>>();

    let crate_name = tcx.crate_name(LOCAL_CRATE);
    let total_calls = all_reachable.values().map(Vec::len).sum::<usize>();
    log::warn!(
        "{} reachable in {crate_name}, from {total_calls} calls",
        all_reachable.len()
    );

    let unsafe_reachable = all_reachable
        .iter()
        .filter(|(def_id, _calls)| tcx.fn_sig(*def_id).skip_binder().safety().is_unsafe())
        .map(|(a, b)| (a, b.len(), b))
        .collect::<Vec<_>>();

    let unsafe_calls = unsafe_reachable
        .iter()
        .map(|(_, count, _calls)| count)
        .sum::<usize>();
    log::warn!(
        "{} unsafe reachable in {crate_name}, from {unsafe_calls} calls",
        unsafe_reachable.len()
    );
    log::warn!("unsafe reachable: {unsafe_reachable:#?}");
    // Sort entry points so our analysis order is deterministic.
    locally_reachable.sort_by(|a, b| {
        tcx.def_path_str(a.reach.to_def_id())
            .cmp(&tcx.def_path_str(b.reach.to_def_id()))
    });
    locally_reachable
}

struct CallGraphVisitor<'tcx> {
    tcx: TyCtxt<'tcx>,
    /// Queue of reachable items we want to visit.
    ///
    /// This lets us to BFS to get the shortest path to each item.
    to_visit: VecDeque<LocallyReachable>,
    locally_reachable: HashMap<LocalDefId, LocallyReachable>,
    all_reachable: HashMap<DefId, Vec<Span>>,
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
            locally_reachable: HashMap::new(),
            all_reachable: HashMap::new(),
        }
    }

    fn reachable(
        mut self,
    ) -> (
        HashMap<DefId, Vec<Span>>,
        impl Iterator<Item = LocallyReachable>,
    ) {
        while let Some(mut d) = self.to_visit.pop_front() {
            if !self.locally_reachable.contains_key(&d.reach) {
                // let kind = self.tcx.def_kind(d.reach);
                // let parent_kind = self.tcx.def_kind(self.tcx.parent(d.reach.into()));
                // let is_trait_fn = kind == DefKind::AssocFn && parent_kind == DefKind::Trait;

                if !self.tcx.has_typeck_results(d.reach) {
                    log::warn!(
                        "found function with no typeck results, not doing anything with it for now... {d:?}"
                    );
                    continue;
                }
                let body = self.tcx.optimized_mir(d.reach);
                // log::debug!("SUCCESS");
                let mut visitor = BodyVisitor(
                    self.tcx,
                    &mut self.to_visit,
                    &mut d,
                    &mut self.all_reachable,
                );
                visitor.visit_body(body);
                self.locally_reachable.insert(d.reach, d);
            }
        }
        (self.all_reachable, self.locally_reachable.into_values())
    }
}

#[allow(dead_code)]
struct BodyVisitor<'tcx, 'm>(
    TyCtxt<'tcx>,
    &'m mut VecDeque<LocallyReachable>,
    &'m mut LocallyReachable,
    &'m mut HashMap<DefId, Vec<Span>>,
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
            // TODO: here need to handle non-local reachable
            if let Some(local_def) = def_id.as_local() {
                // Doing BFS here to ensure we get the shortest path possible to all reachable items.
                self.1
                    .push_back(self.2.extended_to(local_def, terminator.source_info.span));
            } else {
                // non-local crate
                self.3
                    .entry(*def_id)
                    .or_default()
                    .push(terminator.source_info.span);
            }
        }

        self.super_terminator(terminator, location);
    }
}
