use rustc_hir::ExprKind;
use rustc_middle::ty::TyCtxt;
use rustc_public::ty::FnDef;
use rustc_span::source_map::{Spanned, respan};
use rustc_type_ir::TyKind;

use crate::axioms::AxiomFinder;

use super::Axiom;

pub struct SafetyFinder;

#[derive(Debug, Clone)]
pub enum SafetyAxiom {
    RawPtrDeref,
}

impl Axiom for SafetyAxiom {}

impl AxiomFinder for SafetyFinder {
    type Axiom = SafetyAxiom;

    fn from_expr(
        &mut self,
        tcx: TyCtxt,
        tyck: &rustc_middle::ty::TypeckResults,
        expr: &rustc_hir::Expr,
    ) -> Vec<Spanned<Self::Axiom>> {
        if let ExprKind::Unary(op, expr) = expr.kind {
            let inner_ty = tyck.expr_ty(expr);

            if let TyKind::RawPtr(ty, _mut) = inner_ty.kind() {
                let value = respan(expr.span, SafetyAxiom::RawPtrDeref);
                return vec![value];
            }
        }

        vec![]
        // todo!()
    }
}
