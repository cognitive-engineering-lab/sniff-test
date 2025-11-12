//! The utilities needed to find and parse code annotations.
use crate::{
    annotations::doc::{Attributeable, DocStr, get_doc_str},
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
    fn_def: impl Into<rustc_span::def_id::DefId>,
    property: P,
) -> Option<DefAnnotation> {
    // TODO: add yash's logic here for checking the override toml file first.

    // 1. get the doc string
    let fn_def: rustc_span::def_id::DefId = fn_def.into();
    let doc_str = get_doc_str(fn_def, tcx)?;

    // 2. parse the doc string based on the property
    parse_fn_def_src(doc_str, property)
}

fn parent_block_expr<'tcx>(
    tcx: TyCtxt<'tcx>,
    call_expr: rustc_hir::Expr<'tcx>,
) -> Option<rustc_hir::Block<'tcx>> {
    tcx.hir_parent_iter(call_expr.hir_id)
        .find_map(|(id, node)| {
            if let rustc_hir::Node::Block(b) = &node {
                Some(**b)
            } else {
                None
            }
        })
}

pub fn parse_expr<'tcx, P: Property>(
    tcx: TyCtxt<'tcx>,
    call_expr: rustc_hir::Expr<'tcx>,
    property: P,
) -> Option<ExpressionAnnotation> {
    // 1. get the doc string directly
    let direct_annotation =
        get_doc_str(call_expr, tcx).and_then(|doc_str| parse_expr_src(doc_str, property));
    if let Some(direct) = direct_annotation {
        return Some(direct);
    }

    // 1. if we don't have it directly, trying getting it from a parent block...
    parse_expr_src(
        get_doc_str(parent_block_expr(tcx, call_expr)?, tcx)?,
        property,
    )
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
