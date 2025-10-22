//! walk from entry points
//! for each function call, does it satisfy the requirements?
//!

use crate::rustc_middle::mir::visit::Visitor;
use rustc_hir::def_id::{self as internal, DefId, LocalDefId};
use rustc_hir::{ExprKind, Node, intravisit};
use rustc_middle::mir::{ConstOperand, Operand, TerminatorKind};
use rustc_middle::ty::{TyCtxt, TyKind};
use rustc_public::ty::FnDef;
use rustc_span::Span;
use rustc_span::sym::c;
use std::collections::{HashMap, HashSet};

use crate::{annotations::Requirement, reachability::err::ConsistencyError};

#[derive(Debug, Clone)]
pub struct LocalReachable {
    pub reach: LocalDefId,
    pub from: Vec<(LocalDefId, Span)>,
}

impl LocalReachable {
    fn goes_to(&self, def_id: LocalDefId, span: Span) -> Self {
        LocalReachable {
            reach: def_id,
            from: self
                .from
                .iter()
                .cloned()
                .chain(std::iter::once((self.reach, span)))
                .collect(),
        }
    }
}

pub fn local_reachable_from(
    tcx: TyCtxt,
    entry_points: impl IntoIterator<Item = LocalDefId>,
) -> impl Iterator<Item = LocalReachable> {
    CallGraphVisitor::new(tcx, entry_points.into_iter()).all_local_reachable()
}

struct CallGraphVisitor<'tcx> {
    tcx: TyCtxt<'tcx>,
    to_visit: Vec<LocalReachable>,
    reachable: HashMap<LocalDefId, LocalReachable>,
}

impl<'tcx> CallGraphVisitor<'tcx> {
    fn new(tcx: TyCtxt<'tcx>, entry_points: impl Iterator<Item = LocalDefId>) -> Self {
        Self {
            tcx,
            to_visit: entry_points
                .map(|reach| LocalReachable {
                    reach,
                    from: Vec::new(),
                })
                .collect(),
            reachable: HashMap::new(),
        }
    }

    fn all_local_reachable(mut self) -> impl Iterator<Item = LocalReachable> {
        while let Some(d) = self.to_visit.pop() {
            if !self.reachable.contains_key(&d.reach) {
                let body = self.tcx.optimized_mir(d.reach);
                println!("[!] visit body {:?}", d.reach);
                let mut visitor = BodyVisitor(self.tcx, &mut self.to_visit, &d);
                visitor.visit_body(body);
                self.reachable.insert(d.reach, d);
            }
        }
        self.reachable.into_values()
    }
}

struct BodyVisitor<'tcx, 'm>(
    TyCtxt<'tcx>,
    &'m mut Vec<LocalReachable>,
    &'m LocalReachable,
);

impl<'tcx> rustc_middle::mir::visit::Visitor<'tcx> for BodyVisitor<'tcx, '_> {
    fn visit_terminator(
        &mut self,
        terminator: &rustc_middle::mir::Terminator<'tcx>,
        location: rustc_middle::mir::Location,
    ) {
        println!("terminator {:?}", terminator);
        if let TerminatorKind::Call {
            func,
            call_source,
            fn_span,
            ..
        } = &terminator.kind
        {
            if let Operand::Constant(box co) = func {
                if let TyKind::FnDef(def_id, _substs) = co.const_.ty().kind() {
                    println!("call to {def_id:?}");

                    if let Some(local_def) = def_id.as_local() {
                        println!("and it's local!");
                        self.1
                            .push(self.2.goes_to(local_def, terminator.source_info.span));
                    }
                }
            }
        }

        self.super_terminator(terminator, location);
    }
}

// pub fn walk_from_entry_points(
//     tcx: TyCtxt,
//     entry_points: &[FnDef],
//     requirements: HashMap<FnDef, Vec<Requirement>>,
// ) -> Result<(), ConsistencyError> {
//     let entry_point_defs = entry_points
//         .iter()
//         .map(|fn_def| rustc_public::rustc_internal::internal(tcx, fn_def.0))
//         .collect::<Vec<_>>();

//     CallGraphVisitor::new(tcx, requirements).visit_from_entrypoints(&entry_point_defs)
// }

// struct CallGraphVisitor<'tcx> {
//     tcx: TyCtxt<'tcx>,
//     requirements: HashMap<FnDef, Vec<Requirement>>,
// }

// type CallGraphResult = ();
// impl<'tcx> CallGraphVisitor<'tcx> {
//     pub fn new(tcx: TyCtxt<'tcx>, requirements: HashMap<FnDef, Vec<Requirement>>) -> Self {
//         Self { tcx, requirements }
//     }

//     pub fn visit_from_entrypoints(
//         mut self,
//         entry_points: &[internal::DefId],
//     ) -> Result<CallGraphResult, ConsistencyError> {
//         let to_visit = self
//             .tcx
//             .hir_crate_items(())
//             .definitions()
//             .filter(|a| entry_points.contains(&a.to_def_id()))
//             .collect::<Vec<_>>();

//         for i in self.tcx.hir_crate_items(()).free_items() {
//             if entry_points.contains(&i.owner_id.to_def_id()) {
//                 println!("going to i {i:?}");
//             }
//         }

//         Ok(())
//     }
// }

// impl<'tcx> rustc_hir::intravisit::Visitor<'tcx> for CallGraphVisitor<'tcx> {
//     type NestedFilter = rustc_middle::hir::nested_filter::OnlyBodies;

//     fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
//         self.tcx
//     }

//     fn visit_expr(&mut self, ex: &'tcx rustc_hir::Expr<'tcx>) -> Self::Result {}
// }
