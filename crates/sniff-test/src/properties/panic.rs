use regex::Regex;
use rustc_hir::ExprKind;
use rustc_middle::ty::TyCtxt;
use rustc_span::source_map::{Spanned, respan};
use std::fmt::Display;

use super::Axiom;
use crate::{annotations::PropertyViolation, properties::Property};

#[derive(Debug, Clone)]
pub enum PanicAxiom {
    ExplicitPanic,
}

#[derive(Debug, Clone, Copy)]
pub struct PanicProperty;

impl Property for PanicProperty {
    type Axiom = PanicAxiom;
    fn name() -> &'static str {
        "panicking"
    }

    fn callsite_regex(&self) -> Regex {
        todo!()
    }

    fn fn_def_regex(&self) -> Regex {
        Regex::new("(\n|^)(\\s*)[#]+ (Panics|PANICS)(\n|$)").unwrap()
    }

    fn find_axioms_in_expr(
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

impl Axiom for PanicAxiom {
    type Property = PanicProperty;
    fn axiom_kind_name() -> &'static str {
        "panicking"
    }

    fn known_requirements(&self) -> Option<PropertyViolation> {
        match self {
            Self::ExplicitPanic => Some(PropertyViolation::Unconditional),
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
