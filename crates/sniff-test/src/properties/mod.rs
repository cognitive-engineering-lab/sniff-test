//! A module for detecting axiomatic program patterns

use crate::annotations::PropertyViolation;
use crate::check::LocalError;
use regex::Regex;
use rustc_hir::def_id::LocalDefId;
use rustc_hir::intravisit::{self, Visitor};
use rustc_macros::Decodable;
use rustc_middle::{
    hir::nested_filter,
    ty::{TyCtxt, TypeckResults},
};
use rustc_serialize::Encodable;
use rustc_serialize::opaque::FileEncoder;
use std::fmt::Debug;
use std::fmt::Display;

mod panic;
mod safety;

pub use panic::PanicProperty;
pub use safety::SafetyProperty;

pub trait Property: Debug + Copy + 'static + Encodable<FileEncoder> {
    type Axiom: Axiom + Encodable<FileEncoder>;
    fn property_name() -> &'static str;

    /// The regex marker (to be placed within function definition doc comments)
    /// which will register the function's body as having this property.
    fn fn_def_regex(&self) -> Regex;

    /// The regex marker (to be placed on calls to functions with this property)
    /// that indicates obligations have been discharged.
    fn callsite_regex(&self) -> Regex;

    fn find_axioms_in_expr<'tcx>(
        &mut self, // TODO: why is this a mutable reference?
        tcx: TyCtxt<'tcx>,
        tyck: &TypeckResults,
        expr: &'tcx rustc_hir::Expr,
    ) -> Vec<FoundAxiom<'tcx, Self::Axiom>>;

    /// An additional check to perform on all function defs that are annotated as having this property.
    fn additional_check(&self, _tcx: TyCtxt, _fn_def: LocalDefId) -> Result<(), LocalError<Self>> {
        Ok(())
    }
}

pub trait Axiom: Display + Debug {
    type Property: Property;

    /// The name for this kind of axiom (e.g. `I found a {name} axiom in your code`)
    fn property_name() -> &'static str {
        Self::Property::property_name()
    }

    /// The requirements that this axiom has, if known.
    fn known_requirements(&self) -> Option<PropertyViolation> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct FoundAxiom<'tcx, A: Axiom> {
    pub axiom: A,
    pub found_in: &'tcx rustc_hir::Expr<'tcx>,
    pub span: rustc_span::Span,
}

impl<A: Axiom> ::rustc_serialize::Encodable<FileEncoder> for UnjustifiedAxiom<A>
where
    A: ::rustc_serialize::Encodable<FileEncoder>,
{
    fn encode(&self, __encoder: &mut FileEncoder) {
        match *self {
            UnjustifiedAxiom {
                axiom: ref __binding_0,
                span: ref __binding_1,
            } => {
                ::rustc_serialize::Encodable::<FileEncoder>::encode(__binding_0, __encoder);
                ::rustc_serialize::Encodable::<FileEncoder>::encode(__binding_1, __encoder);
            }
        }
    }
}

#[derive(Debug, Clone, Decodable)]
pub struct UnjustifiedAxiom<A: Axiom> {
    pub axiom: A,
    pub span: rustc_span::Span,
}

struct FinderWrapper<'tcx, T: Property> {
    tcx: TyCtxt<'tcx>,
    property: T,
    tychck: &'tcx TypeckResults<'tcx>,
    axioms: Vec<FoundAxiom<'tcx, T::Axiom>>,
}

pub fn find_axioms<'tcx, T: Property>(
    tcx: TyCtxt<'tcx>,
    locally_reachable: &LocalDefId,
    property: T,
) -> impl Iterator<Item = FoundAxiom<'tcx, T::Axiom>> {
    let body = tcx.hir_body_owned_by(*locally_reachable).id();
    let tychck = tcx.typeck_body(body);

    let mut finder = FinderWrapper {
        property,
        tychck,
        tcx,
        axioms: Vec::new(),
    };

    finder.visit_nested_body(body);

    finder.axioms.into_iter()
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
