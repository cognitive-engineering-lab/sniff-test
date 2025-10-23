//! A module for detecting axiomatic program patterns

use crate::{annotations, reachability::LocallyReachable};
use rustc_hir::intravisit::{self, Visitor};
use rustc_middle::{
    hir::nested_filter,
    ty::{TyCtxt, TypeckResults},
};
use rustc_span::source_map::Spanned;
use std::fmt::Display;

mod panic;
mod safety;

pub use safety::SafetyFinder;

pub enum AxiomaticBadness {
    Unconditional,
    Conditional(Vec<annotations::Requirement>),
}

pub trait Axiom: Display {
    /// The name for this kind of axiom (e.g. `I found a {name} axiom in your code`)
    fn axiom_kind_name() -> &'static str;

    /// The requirements that this axiom has, if known.
    fn known_requirements(&self) -> Option<AxiomaticBadness> {
        None
    }
}

pub trait AxiomFinder {
    type Axiom: Axiom;

    fn find_in_expr(
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

pub fn find_axioms<T: AxiomFinder>(
    finder: T,
    tcx: TyCtxt,
    locally_reachable: &LocallyReachable,
) -> Vec<Spanned<T::Axiom>> {
    let body = tcx.hir_body_owned_by(locally_reachable.reach).id();
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
            .extend(self.finder.find_in_expr(self.tcx, self.tychck, ex));

        intravisit::walk_expr(self, ex)
    }
}
