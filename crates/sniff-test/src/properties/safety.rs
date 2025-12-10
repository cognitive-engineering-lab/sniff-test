use std::fmt::Display;

use regex::Regex;
use rustc_ast::UnOp;
use rustc_hir::ExprKind;
use rustc_middle::ty::TyCtxt;
use rustc_type_ir::TyKind;

use super::Axiom;
use crate::{
    annotations::PropertyViolation,
    properties::{FoundAxiom, Property},
};

#[derive(Debug, Clone, Copy)]
pub struct SafetyProperty;

// TODO: add some sort of additional checks function here that lets you do additional checks
// in this case, ensuring that all annotated unsafe functions have the unsafe keyword.
impl Property for SafetyProperty {
    type Axiom = SafetyAxiom;
    fn property_name() -> &'static str {
        "unsafe"
    }

    fn fn_def_regex(&self) -> Regex {
        Regex::new("(\n|^)(\\s*)[#]+ (Safety|SAFETY)(\n|$)").unwrap()
    }

    fn callsite_regex(&self) -> Regex {
        Regex::new("(\n|^)(\\s*)(Safety|SAFETY):").unwrap()
    }

    fn find_axioms_in_expr<'tcx>(
        &mut self,
        _tcx: TyCtxt<'tcx>,
        tyck: &rustc_middle::ty::TypeckResults,
        expr: &'tcx rustc_hir::Expr<'tcx>,
    ) -> Vec<FoundAxiom<'tcx, Self::Axiom>> {
        if let ExprKind::Unary(UnOp::Deref, expr) = expr.kind {
            let inner_ty = tyck.expr_ty(expr);

            if let TyKind::RawPtr(_ty, _mut) = inner_ty.kind() {
                return vec![FoundAxiom {
                    axiom: SafetyAxiom::RawPtrDeref,
                    span: expr.span,
                    found_in: expr,
                }];
            }
        }

        vec![]
    }

    fn additional_check(
        &self,
        tcx: TyCtxt,
        fn_def: rustc_hir::def_id::DefId, // TODO: change to fn_def
    ) -> Result<(), rustc_span::ErrorGuaranteed> {
        match tcx.fn_sig(fn_def).skip_binder().safety() {
            rustc_hir::Safety::Safe => Err(tcx.dcx().struct_span_err(tcx.def_span(fn_def), format!("function {fn_def:?} is annotated as having safety preconditions, but does not use the `unsafe` keyword!")).emit()),
            rustc_hir::Safety::Unsafe => Ok(()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SafetyAxiom {
    RawPtrDeref,
}

impl Axiom for SafetyAxiom {
    type Property = SafetyProperty;

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
        let name = match self {
            Self::RawPtrDeref => "raw pointer derefence",
        };
        f.write_str(name)
    }
}
