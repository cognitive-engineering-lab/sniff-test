use std::fmt::Display;

use rustc_ast::UnOp;
use rustc_hir::ExprKind;
use rustc_middle::ty::TyCtxt;
use rustc_span::source_map::{Spanned, respan};
use rustc_type_ir::TyKind;

use super::Axiom;
use crate::{
    annotations,
    axioms::{AxiomFinder, AxiomaticBadness},
};

/// A finder that looks for axioms that **could cause UB**.
///
/// Currently just looks for raw pointer dereferences.
pub struct SafetyFinder;

#[derive(Debug, Clone)]
pub enum SafetyAxiom {
    RawPtrDeref,
}

impl Axiom for SafetyAxiom {
    fn axiom_kind_name() -> &'static str {
        "unsafe"
    }

    fn known_requirements(&self) -> Option<AxiomaticBadness> {
        match self {
            Self::RawPtrDeref => Some(AxiomaticBadness::Conditional(
                annotations::Requirement::construct([
                    ("ptr-non-null", "the dereferenced pointer must be non-null"),
                    ("ptr-aligned", "the dereferenced pointer must be aligned"),
                ]),
            )),
        }
    }
}

impl Display for SafetyAxiom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RawPtrDeref => f.write_str("raw pointer derefence"),
        }
    }
}

impl AxiomFinder for SafetyFinder {
    type Axiom = SafetyAxiom;

    fn find_in_expr(
        &mut self,
        _tcx: TyCtxt,
        tyck: &rustc_middle::ty::TypeckResults,
        expr: &rustc_hir::Expr,
    ) -> Vec<Spanned<Self::Axiom>> {
        // println!("looking at {}", expr.to_debug_str(_tcx));
        if let ExprKind::Unary(UnOp::Deref, expr) = expr.kind {
            let inner_ty = tyck.expr_ty(expr);

            if let TyKind::RawPtr(_ty, _mut) = inner_ty.kind() {
                let value = respan(expr.span, SafetyAxiom::RawPtrDeref);
                return vec![value];
            }
        }

        vec![]
    }
}
