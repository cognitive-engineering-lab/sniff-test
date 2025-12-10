//! The utilities needed to find and parse code annotations.
use crate::{
    ARGS,
    annotations::{doc::get_comment_doc_str, span::Mergeable, toml::TomlAnnotation},
    properties::Property,
};
use rustc_hir::Attribute;
use rustc_middle::ty::TyCtxt;
use rustc_span::{ErrorGuaranteed, Span, source_map::Spanned};
use std::{fmt::Debug, ops::Range};

mod doc;
mod span;
pub mod toml;

#[derive(Debug)]
pub enum PropertyViolation {
    /// This property will always be violated.
    Unconditional,
    Conditionally(Vec<Spanned<String>>),
    /// This property will never be violated.
    Never,
}

#[derive(Debug, Clone)]
pub enum DocStrSource {
    DocComment(Vec<Attribute>),
    TomlOverride,
}

impl DocStrSource {
    #[must_use]
    fn into_annotation_source(self, used_chars: Range<usize>) -> AnnotationSource {
        match self {
            Self::TomlOverride => AnnotationSource::TomlOverride,
            Self::DocComment(attrs) => AnnotationSource::DocComment(
                span::span_some_comments(&attrs, used_chars)
                    .merge_adjacent()
                    .into_iter()
                    .next()
                    .expect("should have a span"),
            ),
        }
    }
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

pub struct ExpressionAnnotation {
    pub property_name: &'static str,
    pub text: String,
    pub span: AnnotationSource,
}

impl ExpressionAnnotation {
    pub fn satisfies_obligation(&self, obligation: &Obligation) -> Result<(), ErrorGuaranteed> {
        match obligation {
            Obligation::ConsiderProperty => Ok(()),
            Obligation::ConsiderConditions => todo!(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Obligation {
    /// Callers must consider the property generally.
    ConsiderProperty,
    /// Callers must specifically consider the set of conditions
    /// under which this property will not hold.
    ConsiderConditions,
}

impl DefAnnotation {
    /// Whether this function's annotation creates an obligation that it's callers must uphold.
    pub fn creates_obligation(&self) -> Option<Obligation> {
        match &self.local_violation_annotation {
            PropertyViolation::Conditionally(_)
                if ARGS.lock().unwrap().as_ref().unwrap().fine_grained =>
            {
                Some(Obligation::ConsiderConditions)
            }
            PropertyViolation::Unconditional | PropertyViolation::Conditionally(_) => {
                Some(Obligation::ConsiderProperty)
            }
            PropertyViolation::Never => None,
        }
    }
}

/// Parses the given function definition for a certain property, returning none if it is not
/// annotated.
pub fn parse_fn_def<P: Property>(
    tcx: TyCtxt<'_>,
    toml_annotation: &TomlAnnotation, // TODO: this could be an arc or smth
    fn_def: impl Into<rustc_span::def_id::DefId>,
    property: P,
) -> Option<DefAnnotation> {
    // 1. Get the DefId
    let fn_def: rustc_span::def_id::DefId = fn_def.into();

    // 2. Check if we have a TOML override for this function
    let (doc_str, doc_str_src) =
        match toml_annotation.get_requirements_string(&tcx.def_path_str(fn_def)) {
            Some(override_str) => (override_str.to_owned(), DocStrSource::TomlOverride),
            None => get_comment_doc_str(fn_def, tcx)?,
        };

    property
        .fn_def_regex()
        .find(&doc_str)
        .map(|found| DefAnnotation {
            property_name: P::property_name(),
            local_violation_annotation: PropertyViolation::Unconditional,
            text: doc_str[found.end()..].to_string(),
            source: doc_str_src.into_annotation_source(found.range()),
        })
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

    // Look through the parent exprs until we find one which has a doc comment string.
    try_these.find_map(|(id, _node)| {
        get_comment_doc_str(id, tcx).and_then(|(doc_str, doc_str_src)| {
            property
                .callsite_regex()
                .find(&doc_str)
                .map(|found| ExpressionAnnotation {
                    property_name: P::property_name(),
                    text: doc_str[found.end()..].to_string(),
                    span: doc_str_src.into_annotation_source(found.range()),
                })
        })
    })
}
