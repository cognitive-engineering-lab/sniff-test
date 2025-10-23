use rustc_hir::ExprKind;
use rustc_middle::ty::TyCtxt;
use rustc_span::source_map::{Spanned, respan};
use std::fmt::Display;

use super::Axiom;
use crate::axioms::{AxiomFinder, AxiomaticBadness};

pub struct PanicFinder;

#[derive(Debug, Clone)]
pub enum PanicAxiom {
    ExplicitPanic,
}

impl Axiom for PanicAxiom {
    fn axiom_kind_name() -> &'static str {
        "panicking"
    }

    fn known_requirements(&self) -> Option<AxiomaticBadness> {
        match self {
            Self::ExplicitPanic => Some(AxiomaticBadness::Unconditional),
        }
    }
}

impl Display for PanicAxiom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExplicitPanic => f.write_str("explicit panic"),
        }
    }
}

impl AxiomFinder for PanicFinder {
    type Axiom = PanicAxiom;

    fn from_expr(
        &mut self,
        tcx: TyCtxt,
        tyck: &rustc_middle::ty::TypeckResults,
        expr: &rustc_hir::Expr,
    ) -> Vec<Spanned<Self::Axiom>> {
        if let ExprKind::Call(func, _) = expr.kind
            && let Some(def_id) = tyck.type_dependent_def_id(func.hir_id)
        {
            let lang_items = tcx.lang_items();

            // Check against lang items
            if Some(def_id) == lang_items.panic_fn()
                || Some(def_id) == lang_items.panic_fmt()
                || Some(def_id) == lang_items.begin_panic_fn()
                || Some(def_id) == lang_items.panic_impl()
            {
                let value = respan(expr.span, PanicAxiom::ExplicitPanic);
                return vec![value];
            }
        }

        vec![]
    }
}
