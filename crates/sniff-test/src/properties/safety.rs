use std::fmt::Display;

use regex::Regex;
use rustc_ast::UnOp;
use rustc_hir::ExprKind;
use rustc_middle::ty::TyCtxt;
use rustc_span::source_map::{Spanned, respan};
use rustc_type_ir::TyKind;

use super::Axiom;
use crate::{
    annotations::{self, PropertyViolation},
    properties::Property,
};

#[derive(Debug, Clone, Copy)]
pub struct SafetyProperty;

impl Property for SafetyProperty {
    type Axiom = SafetyAxiom;
    fn name() -> &'static str {
        "safety"
    }

    fn fn_def_regex(&self) -> Regex {
        Regex::new("(\n|^)(\\s*)[#]+ (Safety|SAFETY)(\n|$)").unwrap()
    }

    fn callsite_regex(&self) -> Regex {
        Regex::new("(\n|^)(\\s*)(Safety|SAFETY):").unwrap()
    }

    fn find_axioms_in_expr(
        &mut self,
        tcx: TyCtxt,
        tyck: &rustc_middle::ty::TypeckResults,
        expr: &rustc_hir::Expr,
    ) -> Vec<Spanned<Self::Axiom>> {
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

#[derive(Debug, Clone)]
pub enum SafetyAxiom {
    RawPtrDeref,
}

impl Axiom for SafetyAxiom {
    type Property = SafetyProperty;
    fn axiom_kind_name() -> &'static str {
        "unsafe"
    }

    fn known_requirements(&self) -> Option<PropertyViolation> {
        todo!()
        // match self {
        //     Self::RawPtrDeref => Some(Badness::ConditionallyBad(
        //         annotations::Requirement::construct([
        //             ("ptr-non-null", "the dereferenced pointer must be non-null"),
        //             ("ptr-aligned", "the dereferenced pointer must be aligned"),
        //         ]),
        //     )),
        // }
    }
}

impl Display for SafetyAxiom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RawPtrDeref => f.write_str("raw pointer derefence"),
        }
    }
}
