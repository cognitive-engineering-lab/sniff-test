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

pub fn find_expr_for_call(
    tcx: TyCtxt<'_>,
    call_to: DefId,
    call_from: LocalDefId,
    call_from_span: Span,
) -> &Expr<'_> {
    let body = tcx.hir_body_owned_by(call_from);
    let mut f = SpanExprFinder(
        tcx,
        call_to,
        call_from,
        call_from_span,
        None,
        tcx.typeck_body(body.id()),
    );
    f.visit_body(body);
    f.4.unwrap_or_else(|| panic!(
        "unable to find HIR stmt that corresponds to call to {call_to:?} from {call_from_span:?} :("
    ))
}

struct SpanExprFinder<'tcx>(
    TyCtxt<'tcx>,
    DefId,
    LocalDefId,
    Span,
    Option<&'tcx Expr<'tcx>>,
    &'tcx rustc_middle::ty::TypeckResults<'tcx>,
);

impl<'tcx> intravisit::Visitor<'tcx> for SpanExprFinder<'tcx> {
    type MaybeTyCtxt = TyCtxt<'tcx>;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.0
    }

    fn visit_expr(&mut self, ex: &'tcx Expr<'tcx>) -> Self::Result {
        log::debug!("visiting expr {ex:#?}");
        if ex.span == self.3 {
            self.4 = Some(ex);
            return;
        }

        intravisit::walk_expr(self, ex);
    }
}
