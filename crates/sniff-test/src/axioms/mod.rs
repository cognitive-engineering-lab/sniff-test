use std::fmt::Display;

use rustc_hir::{
    BodyId,
    intravisit::{self, Visitor},
};
use rustc_middle::{
    hir::nested_filter,
    ty::{TyCtxt, TypeckResults},
};
use rustc_span::source_map::Spanned;

mod safety;

pub use safety::{SafetyAxiom, SafetyFinder};

pub trait Axiom: Display {
    fn known_requirements(&self) -> Option<Vec<crate::annotations::Requirement>> {
        None
    }
}

pub trait AxiomFinder {
    type Axiom: Axiom;

    fn from_expr(
        &mut self,
        tcx: TyCtxt,
        tyck: &TypeckResults,
        expr: &rustc_hir::Expr,
    ) -> Vec<Spanned<Self::Axiom>>;
}

struct FinderWrapper<'tcx, T: AxiomFinder> {
    tcx: TyCtxt<'tcx>,
    finder: T,
    tychck: &'tcx TypeckResults<'tcx>,
    axioms: Vec<Spanned<T::Axiom>>,
}

pub fn find_axioms<T: AxiomFinder>(finder: T, tcx: TyCtxt, body: BodyId) -> Vec<Spanned<T::Axiom>> {
    let tychck = tcx.typeck_body(body);

    let mut finder = FinderWrapper {
        finder,
        tychck,
        tcx,
        axioms: Vec::new(),
    };

    finder.visit_nested_body(body);

    finder.axioms
}

impl<'tcx, T: AxiomFinder> Visitor<'tcx> for FinderWrapper<'tcx, T> {
    type NestedFilter = nested_filter::OnlyBodies;
    type MaybeTyCtxt = TyCtxt<'tcx>;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.tcx
    }

    #[allow(clippy::semicolon_if_nothing_returned)]
    fn visit_expr(&mut self, ex: &'tcx rustc_hir::Expr<'tcx>) -> Self::Result {
        self.axioms
            .extend(self.finder.from_expr(self.tcx, self.tychck, ex));

        intravisit::walk_expr(self, ex)
    }
}
