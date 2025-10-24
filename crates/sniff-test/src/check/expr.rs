use std::{
    cell::{LazyCell, RefCell},
    collections::HashMap,
    sync::{LazyLock, Mutex},
};

use rustc_hir::{
    Expr, ExprKind, HirId,
    def_id::{DefId, LocalDefId},
    intravisit::{self, Visitor},
};
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;

// thread_local! {
//     static MAPPINGS: RefCell<HashMap<Span, HirId>> = Default::default();
// }

// fn find_expr_for_call(tcx: TyCtxt, call_to: DefId, call_from: Span) -> Expr {
//     // MAPPINGS.with_borrow_mut(move |map| {
//     //     *map.entry(call_from)
//     //         .or_insert_with(move || find_expr_for_call_inner(tcx, call_from))
//     // })
//     find_expr_for_call_inner(tcx, call_to, call_from)
// }

pub fn find_expr_for_call(
    tcx: TyCtxt<'_>,
    call_to: DefId,
    call_from: LocalDefId,
    call_from_span: Span,
) -> &Expr<'_> {
    let mut f = SpanExprFinder(tcx, call_to, call_from_span, None);
    f.visit_body(tcx.hir_body_owned_by(call_from));
    f.3.expect("hello")
}

struct SpanExprFinder<'tcx>(TyCtxt<'tcx>, DefId, Span, Option<&'tcx Expr<'tcx>>);

impl<'tcx> intravisit::Visitor<'tcx> for SpanExprFinder<'tcx> {
    type MaybeTyCtxt = TyCtxt<'tcx>;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.0
    }

    fn visit_expr(&mut self, ex: &'tcx Expr<'tcx>) -> Self::Result {
        if let ExprKind::Call(to, from) = ex.kind
            && ex.span == self.2
        {
            // println!("call and matching spa to {to:?}");
            if let ExprKind::Path(qpath) = &to.kind {
                let tychck = self.0.typeck(ex.hir_id.owner.def_id);

                // Resolve the path to get the DefId
                if let Some(def_id) = tychck.qpath_res(qpath, to.hir_id).opt_def_id() {
                    // println!("resolve to defid {def_id:?}");
                    if def_id == self.1 {
                        // println!("WHICH MATCHES!!");
                        self.3 = Some(ex);
                        return;
                    }
                }
            } else {
                todo!("should handle more complex resolution here...");
            }
        }

        intravisit::walk_expr(self, ex);
    }
}
