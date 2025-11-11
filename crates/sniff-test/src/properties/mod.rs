//! A module for detecting axiomatic program patterns

use crate::{
    annotations::{self, PropertyViolation},
    reachability::{LocallyReachable, attr::SniffToolAttr},
};
use regex::Regex;
use rustc_hir::intravisit::{self, Visitor};
use rustc_middle::{
    hir::nested_filter,
    ty::{TyCtxt, TypeckResults},
};
use rustc_span::source_map::Spanned;
use std::fmt::Debug;
use std::{fmt::Display, sync::Arc};

mod panic;
mod safety;

pub use panic::PanicProperty;
pub use safety::SafetyProperty;

pub trait Property: Debug + 'static + Copy {
    type Axiom: Axiom;
    fn name() -> &'static str;

    /// The regex marker (to be placed within function definition doc comments)
    /// which will register the function's body as having this property.
    fn fn_def_regex(&self) -> Regex;

    /// The regex marker (to be placed on calls to functions with this property)
    /// that indicates obligations have been discharged.
    fn callsite_regex(&self) -> Regex;

    fn find_axioms_in_expr(
        &mut self,
        tcx: TyCtxt,
        tyck: &TypeckResults,
        expr: &rustc_hir::Expr,
    ) -> Vec<Spanned<Self::Axiom>>;
}

pub trait Axiom: Display + Debug {
    type Property: Property;

    /// The name for this kind of axiom (e.g. `I found a {name} axiom in your code`)
    fn axiom_kind_name() -> &'static str;

    /// The requirements that this axiom has, if known.
    fn known_requirements(&self) -> Option<PropertyViolation> {
        None
    }
}

struct FinderWrapper<'tcx, T: Property> {
    tcx: TyCtxt<'tcx>,
    property: T,
    tychck: &'tcx TypeckResults<'tcx>,
    axioms: Vec<Spanned<T::Axiom>>,
}

pub fn find_axioms<T: Property>(
    tcx: TyCtxt,
    locally_reachable: &LocallyReachable,
    property: T,
) -> Vec<Spanned<T::Axiom>> {
    let body = tcx.hir_body_owned_by(locally_reachable.reach).id();
    let tychck = tcx.typeck_body(body);

    let mut finder = FinderWrapper {
        property,
        tychck,
        tcx,
        axioms: Vec::new(),
    };

    finder.visit_nested_body(body);

    finder.axioms
}

impl<'tcx, T: Property> Visitor<'tcx> for FinderWrapper<'tcx, T> {
    type NestedFilter = nested_filter::OnlyBodies;
    type MaybeTyCtxt = TyCtxt<'tcx>;

    fn maybe_tcx(&mut self) -> Self::MaybeTyCtxt {
        self.tcx
    }

    #[allow(clippy::semicolon_if_nothing_returned)]
    fn visit_expr(&mut self, ex: &'tcx rustc_hir::Expr<'tcx>) -> Self::Result {
        self.axioms
            .extend(self.property.find_axioms_in_expr(self.tcx, self.tychck, ex));

        intravisit::walk_expr(self, ex)
    }
}
