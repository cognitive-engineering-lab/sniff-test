use regex::Regex;
use rustc_hir::ExprKind;
use rustc_middle::ty::TyCtxt;
use rustc_span::Span;
use std::fmt::Display;

use super::Axiom;
use crate::{
    annotations::PropertyViolation,
    properties::{FoundAxiom, Property},
};

#[derive(Debug, Clone)]
// TODO: for slices, it would be nice to have more info here about the offending type to display to the user!
pub enum PanicAxiom {
    ExplicitPanic, // Always panics
    SliceIndex,    // Panics if out of bounds
    Div,           // Panics if divisor is zero
    Rem,           // Panics if divisor is zero
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
        tyck: &rustc_middle::ty::TypeckResults,
        expr: &'tcx rustc_hir::Expr<'tcx>,
    ) -> Vec<FoundAxiom<'tcx, Self::Axiom>> {
        [
            find_explicit_panic(tcx, expr).map(|span| FoundAxiom {
                axiom: PanicAxiom::ExplicitPanic,
                found_in: expr,
                span,
            }),
            find_binop(tcx, expr, rustc_ast::BinOpKind::Div).map(|span| FoundAxiom {
                axiom: PanicAxiom::Div,
                found_in: expr,
                span,
            }),
            find_binop(tcx, expr, rustc_ast::BinOpKind::Rem).map(|span| FoundAxiom {
                axiom: PanicAxiom::Rem,
                found_in: expr,
                span,
            }),
            find_slice_index(tyck, expr).map(|span| FoundAxiom {
                axiom: PanicAxiom::SliceIndex,
                found_in: expr,
                span,
            }),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

fn find_binop<'tcx>(
    _tcx: TyCtxt<'tcx>,
    expr: &'tcx rustc_hir::Expr<'tcx>,
    binop: rustc_ast::BinOpKind,
) -> Option<Span> {
    if let ExprKind::Binary(op, _, _) = expr.kind
        && op.node == binop
    {
        Some(op.span)
    } else {
        None
    }
}

// TODO: don't think this handles custom derefs. I don't think smart pointers, or things with
// custom impl of the `Deref` trait (e.g. a `Box<[]>`) will get peeled away by `.peel_refs()`, but
// the index will still be on the deref-ed inner type.
fn type_can_panic_on_index(ty: rustc_middle::ty::Ty) -> bool {
    println!("is {:?} a slice", ty.peel_refs().kind());
    matches!(
        ty.peel_refs().kind(),
        rustc_type_ir::TyKind::Slice(_) | rustc_type_ir::TyKind::Array(..)
    )
}

fn find_slice_index<'tcx>(
    tyck: &rustc_middle::ty::TypeckResults,
    expr: &'tcx rustc_hir::Expr<'tcx>,
) -> Option<Span> {
    if let ExprKind::Index(val, _, span) = expr.kind
        && type_can_panic_on_index(tyck.expr_ty(val))
    {
        Some(span)
    } else {
        None
    }
}

fn find_explicit_panic<'tcx>(tcx: TyCtxt<'tcx>, expr: &'tcx rustc_hir::Expr<'tcx>) -> Option<Span> {
    let ExprKind::Call(func, _) = expr.kind else {
        return None;
    };
    // TODO: this is for sure hacky and requires more work.
    // we've already got this in the call graph, so should probably just map up from MIR to HIR to find comments
    let ExprKind::Path(qpath) = func.kind else {
        panic!();
    };

    let rustc_hir::QPath::Resolved(_ty, path) = &qpath else {
        // panic language items should always have a fully resolved path
        return None;
    };

    let Some(def_id) = path.res.opt_def_id() else {
        println!(
            "WARN: unable to find def_id for call to {:?} (to check if it is a panic)",
            path.res
        );
        return None;
    };

    let lang_items = tcx.lang_items();

    // Check against lang items
    if Some(def_id) == lang_items.panic_fn()
        || Some(def_id) == lang_items.panic_fmt()
        || Some(def_id) == lang_items.begin_panic_fn()
        || Some(def_id) == lang_items.panic_impl()
    {
        Some(expr.span)
    } else {
        None
    }
}

impl Axiom for PanicAxiom {
    type Property = PanicProperty;

    fn known_requirements(&self) -> Option<PropertyViolation> {
        match self {
            Self::ExplicitPanic => Some(PropertyViolation::Unconditional),
            _ => todo!(),
        }
    }
}

impl Display for PanicAxiom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::ExplicitPanic => "explicit panic",
            Self::SliceIndex => "slice index",
            Self::Div => "division",
            Self::Rem => "remainder",
        };
        f.write_str(name)
    }
}
