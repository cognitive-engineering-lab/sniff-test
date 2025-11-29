use rustc_hir::{
    Expr,
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
    let mut f = SpanExprFinder(tcx, call_from_span, None);
    f.visit_body(body);
    f.2.unwrap_or_else(|| panic!(
        "unable to find HIR stmt that corresponds to call to {call_to:?} from {call_from_span:?} :("
    ))
}

struct SpanExprFinder<'tcx>(TyCtxt<'tcx>, Span, Option<&'tcx Expr<'tcx>>);

impl<'tcx> intravisit::Visitor<'tcx> for SpanExprFinder<'tcx> {
    type MaybeTyCtxt = TyCtxt<'tcx>;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.0
    }

    fn visit_expr(&mut self, ex: &'tcx Expr<'tcx>) -> Self::Result {
        log::debug!("visiting expr {ex:#?}");
        if ex.span == self.1 {
            self.2 = Some(ex);
            return;
        }

        intravisit::walk_expr(self, ex);
    }
}
