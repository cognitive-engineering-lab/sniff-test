use regex::Regex;
use rustc_hir::ExprKind;
use rustc_middle::ty::TyCtxt;
use std::fmt::Display;

use super::Axiom;
use crate::{
    annotations::PropertyViolation,
    properties::{FoundAxiom, Property},
};

#[derive(Debug, Clone)]
pub enum PanicAxiom {
    ExplicitPanic,
}

#[derive(Debug, Clone, Copy)]
pub struct PanicProperty;

impl Property for PanicProperty {
    type Axiom = PanicAxiom;
    fn property_name() -> &'static str {
        "panicking"
    }

    fn callsite_regex(&self) -> Regex {
        todo!()
    }

    fn fn_def_regex(&self) -> Regex {
        Regex::new("(\n|^)(\\s*)[#]+ (Panics|PANICS)(\n|$)").unwrap()
    }

    fn find_axioms_in_expr<'tcx>(
        &mut self,
        tcx: TyCtxt<'tcx>,
        _tyck: &rustc_middle::ty::TypeckResults,
        expr: &'tcx rustc_hir::Expr<'tcx>,
    ) -> Vec<FoundAxiom<'tcx, Self::Axiom>> {
        if let ExprKind::Call(func, _) = expr.kind {
            // TODO: this is for sure hacky and requires more work.
            // we've already got this in the call graph, so should probably just map up from MIR to HIR to find comments
            let ExprKind::Path(qpath) = func.kind else {
                panic!();
            };

            let rustc_hir::QPath::Resolved(_ty, path) = &qpath else {
                // panic language items should always have a fully resolved path
                return vec![];
            };

            let Some(def_id) = path.res.opt_def_id() else {
                println!(
                    "WARN: unable to find def_id for call to {:?} (to check if it is a panic)",
                    path.res
                );
                return vec![];
            };

            let lang_items = tcx.lang_items();

            // Check against lang items
            if Some(def_id) == lang_items.panic_fn()
                || Some(def_id) == lang_items.panic_fmt()
                || Some(def_id) == lang_items.begin_panic_fn()
                || Some(def_id) == lang_items.panic_impl()
            {
                return vec![FoundAxiom {
                    axiom: PanicAxiom::ExplicitPanic,
                    span: expr.span,
                    found_in: expr,
                }];
            }
        }

        vec![]
    }
}

impl Axiom for PanicAxiom {
    type Property = PanicProperty;

    fn known_requirements(&self) -> Option<PropertyViolation> {
        match self {
            Self::ExplicitPanic => Some(PropertyViolation::Unconditional),
        }
    }
}

impl Display for PanicAxiom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::ExplicitPanic => "explicit panic",
        };
        f.write_str(name)
    }
}
