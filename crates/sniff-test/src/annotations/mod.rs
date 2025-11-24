//! The utilities needed to find and parse code annotations.
use crate::{
    annotations::{
        doc::{Attributeable, DocStr, get_doc_str},
        toml::TomlAnnotation,
    },
    properties::Property,
};
use regex::Regex;
use rustc_ast::Item;
use rustc_middle::ty::TyCtxt;
use rustc_span::{
    Span,
    source_map::{Spanned, respan},
};
use std::{
    any::Any,
    ops::{FromResidual, Try},
};
use std::{any::TypeId, borrow::Borrow, collections::HashMap, fmt::Debug, hash::Hash};

mod doc;
mod span;
pub mod toml;

#[derive(Debug)]
pub enum PropertyViolation {
    /// This property will always be violated.
    Unconditional,
    // Conditionally(Vec<Spanned<Requirement>>),
    /// This property will never be violated.
    Never,
}

#[derive(Debug)]
pub enum AnnotationSource {
    DocComment(Span),
    TomlOverride,
}

#[derive(Debug)]
pub struct DefAnnotation {
    /// The name of the property this obligation refers to.
    pub property_name: &'static str,
    /// The user's annotation for whether the given property is violated locally within this function.
    pub local_violation_annotation: PropertyViolation,
    // The textual content of this annotation.
    pub text: String,
    /// Where this obligation has come from.
    pub source: AnnotationSource,
}

#[derive(Debug)]
pub struct ExpressionAnnotation {
    pub property_name: &'static str,
    pub text: String,
    pub span: Span,
}

impl DefAnnotation {
    /// Whether this function's annotation creates an obligation that it's callers must uphold.
    pub fn creates_obligation(&self) -> bool {
        match self.local_violation_annotation {
            PropertyViolation::Unconditional => true,
            PropertyViolation::Never => false,
        }
    }
}

/// Parses the given function definition for a certain property, returning none if it is not
/// annotated.
pub fn parse_fn_def<P: Property>(
    tcx: TyCtxt<'_>,
    toml_annotation: &TomlAnnotation,
    fn_def: impl Into<rustc_span::def_id::DefId>,
    property: P,
) -> Option<DefAnnotation> {
    // 1. Get the DefId
    let fn_def: rustc_span::def_id::DefId = fn_def.into();

    // 2. Check if we have a TOML override for this function
    if let Some(toml_str) = toml_annotation.get_requirements_string(&tcx.def_path_str(fn_def)) {
        parse_fn_def_toml(toml_str, property)
    } else {
        // 3. No TOML override found, get the doc string from source code
        let doc_str = get_doc_str(fn_def, tcx)?;
        // 4. parse the doc string based on the property
        parse_fn_def_src(doc_str, property)
    }
}

pub fn parse_expr<'tcx, P: Property>(
    tcx: TyCtxt<'tcx>,
    call_expr: &'tcx rustc_hir::Expr<'tcx>,
    property: P,
) -> Option<ExpressionAnnotation> {
    // Keep looking at parent expressions until we hit a root item or impl block.
    // We need to cover annotations on let stmts & unsafe blocks so this is the most generalizable way to handle it.
    let mut try_these = [(call_expr.hir_id, rustc_hir::Node::Expr(call_expr))]
        .into_iter()
        .chain(tcx.hir_parent_iter(call_expr.hir_id))
        .take_while(|(_id, node)| {
            !matches!(
                node,
                rustc_hir::Node::ImplItem(_) | rustc_hir::Node::Item(_)
            )
        });

    try_these.find_map(|(id, node)| {
        get_doc_str(id, tcx).and_then(|doc_str| parse_expr_src(doc_str, property))
    })
}

fn parse_expr_src<P: Property>(doc_str: DocStr, property: P) -> Option<ExpressionAnnotation> {
    property
        .callsite_regex()
        .find(doc_str.str())
        .map(|found| ExpressionAnnotation {
            property_name: P::property_name(),
            text: doc_str.str()[found.end()..].to_string(),
            span: doc_str.span_of_chars(found.range()),
        })
}

/// Simple check if the obligation regex is contained anywhere in the doc string, otherwise no obligations.
fn parse_fn_def_src<P: Property>(doc_str: DocStr, property: P) -> Option<DefAnnotation> {
    property
        .fn_def_regex()
        .find(doc_str.str())
        .map(|found| DefAnnotation {
            property_name: P::property_name(),
            local_violation_annotation: PropertyViolation::Unconditional,
            text: doc_str.str()[found.end()..].to_string(),
            source: AnnotationSource::DocComment(doc_str.span_of_chars(found.range())),
        })
}

fn parse_fn_def_toml<P: Property>(toml_str: &str, property: P) -> Option<DefAnnotation> {
    property
        .fn_def_regex()
        .find(toml_str)
        .map(|found| DefAnnotation {
            property_name: P::property_name(),
            local_violation_annotation: PropertyViolation::Unconditional,
            text: toml_str[found.end()..].to_string(),
            source: AnnotationSource::TomlOverride,
        })
}
