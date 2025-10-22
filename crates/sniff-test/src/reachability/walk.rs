//! walk from entry points
//! for each function call, does it satisfy the requirements?
//!

use std::collections::HashMap;

use rustc_hir::def_id as internal;
use rustc_hir::intravisit::Visitor;
use rustc_middle::ty::TyCtxt;
use rustc_public::ty::FnDef;

use crate::{annotations::Requirement, reachability::err::ConsistencyError};

pub fn walk_from_entry_points(
    tcx: TyCtxt,
    entry_points: &[FnDef],
    requirements: HashMap<FnDef, Vec<Requirement>>,
) -> Result<(), ConsistencyError> {
    let entry_point_defs = entry_points
        .iter()
        .map(|fn_def| rustc_public::rustc_internal::internal(tcx, fn_def.0))
        .collect::<Vec<_>>();

    CallGraphVisitor::new(tcx, requirements).visit_from_entrypoints(&entry_point_defs)
}

struct CallGraphVisitor<'tcx> {
    tcx: TyCtxt<'tcx>,
    requirements: HashMap<FnDef, Vec<Requirement>>,
}

type CallGraphResult = ();
impl<'tcx> CallGraphVisitor<'tcx> {
    pub fn new(tcx: TyCtxt<'tcx>, requirements: HashMap<FnDef, Vec<Requirement>>) -> Self {
        Self { tcx, requirements }
    }

    pub fn visit_from_entrypoints(
        mut self,
        entry_points: &[internal::DefId],
    ) -> Result<CallGraphResult, ConsistencyError> {
        let to_visit = self
            .tcx
            .hir_crate_items(())
            .definitions()
            .filter(|a| entry_points.contains(&a.to_def_id()))
            .collect::<Vec<_>>();

        for i in self.tcx.hir_crate_items(()).free_items() {
            if entry_points.contains(&i.owner_id.to_def_id()) {
                println!("going to i {i:?}");
            }
        }

        Ok(())
    }
}

impl<'tcx> rustc_hir::intravisit::Visitor<'tcx> for CallGraphVisitor<'tcx> {
    type NestedFilter = rustc_middle::hir::nested_filter::OnlyBodies;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.tcx
    }

    fn visit_expr(&mut self, ex: &'tcx rustc_hir::Expr<'tcx>) -> Self::Result {}
}
