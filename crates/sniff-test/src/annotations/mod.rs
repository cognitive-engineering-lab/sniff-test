//! The utilities needed to find and parse code annotations.
use crate::{
    ARGS,
    annotations::{doc::get_comment_doc_str, span::Mergeable, toml::TomlAnnotation},
    properties::Property,
};
use regex::Regex;
use rustc_hir::{Attribute, def_id::DefId};
use rustc_middle::ty::TyCtxt;
use rustc_span::{ErrorGuaranteed, Span, source_map::Spanned};
use std::{collections::HashMap, fmt::Debug, ops::Range};

mod doc;
mod new_parsing;
mod span;
pub mod toml;

#[derive(Debug)]
pub enum PropertyViolation {
    /// This property will always be violated.
    Unconditional,
    Conditionally(Vec<Spanned<Condition>>),
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
                span::span_some_comments(&attrs, used_chars).merge_adjacent(),
            ),
        }
    }

    fn src_span(&self, chars: Range<usize>) -> Option<Span> {
        if let Self::DocComment(attrs) = self {
            Some(
                *span::span_some_comments(attrs, chars)
                    .merge_adjacent()
                    .first()
                    .unwrap(),
            )
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub enum AnnotationSource {
    DocComment(Vec<Span>),
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
    pub fn satisfies_obligation(
        &self,
        obligation: &Obligation,
        call_to: DefId,
        from_span: Span,
        tcx: TyCtxt<'_>,
    ) -> Result<(), ErrorGuaranteed> {
        match obligation {
            Obligation::ConsiderProperty => Ok(()),
            Obligation::ConsiderConditions(conditions) => {
                let unconsidered = self.unconsidered_conditions(conditions);
                if unconsidered.is_empty() {
                    log::warn!(
                        "call to {:?} on {:?} satisfies all conditions",
                        call_to,
                        self.span
                    );
                    Ok(())
                } else {
                    let names = unconsidered
                        .iter()
                        .map(|a| &a.node.name)
                        .collect::<Vec<&String>>();
                    Err(tcx
                        .dcx()
                        .struct_span_err(
                            from_span,
                            format!(
                                "call to {:?} w/ text {:?} didn't consider some obligations {:?}",
                                self.text, call_to, names
                            ),
                        )
                        .emit())
                }
            }
        }
    }

    fn unconsidered_conditions(
        &self,
        conditions: &[Spanned<Condition>],
    ) -> Vec<Spanned<Condition>> {
        let text_lower = self.text.to_lowercase();
        conditions
            .iter()
            .filter(|condition| {
                assert!(
                    ARGS.lock().unwrap().as_ref().unwrap().buzzword_checking,
                    "not sure how to check properly yet."
                );
                !buzzword_satisfied(&text_lower, &condition.node.name)
            })
            .cloned()
            .collect::<Vec<_>>()
    }
}

fn similar_buzzwords() -> HashMap<&'static str, Vec<&'static str>> {
    [
        ("validity", vec!["valid"]),
        ("size", vec!["larger"]),
        ("length", vec!["len()"]),
        ("soundness", vec!["sound"]),
        ("alignment", vec!["align"]),
        ("lifetime", vec!["outlive", "live for at least"]),
    ]
    .into_iter()
    .collect()
}

fn buzzword_satisfied(justification: &str, condition_name: &str) -> bool {
    condition_name
        .split(['&', '-'])
        .all(|word| contains_word_or_synonym(justification, word))
}

fn contains_word_or_synonym(justification: &str, word: &str) -> bool {
    let mut valid_names = vec![word];

    if let Some(similar) = similar_buzzwords().get(word) {
        valid_names.extend(similar);
    }

    if valid_names
        .into_iter()
        .any(|buzzword| justification.contains(buzzword))
    {
        log::warn!("{justification:?} satisfies condition {word:?}");
        true
    } else {
        false
    }
}

#[derive(Debug, Clone)]
pub struct Condition {
    pub name: String,
    pub description: String,
}

// Specifically ignore descriptions when comparing conditions for equality, as only the name
// is important.
impl PartialEq for Condition {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Obligation {
    /// Callers must consider the property generally.
    ConsiderProperty,
    /// Callers must specifically consider the set of conditions
    /// under which this property will not hold.
    ConsiderConditions(Vec<Spanned<Condition>>),
}

impl DefAnnotation {
    /// Whether this function's annotation creates an obligation that it's callers must uphold.
    pub fn creates_obligation(&self) -> Option<Obligation> {
        match &self.local_violation_annotation {
            PropertyViolation::Conditionally(conditions)
                if ARGS.lock().unwrap().as_ref().unwrap().fine_grained =>
            {
                Some(Obligation::ConsiderConditions(conditions.clone()))
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

    property.fn_def_regex().find(&doc_str).map(|found| {
        let next_section = Regex::new(r"(?m)^\s*#\s+[A-Z]")
            .unwrap()
            .find(&doc_str[found.end()..])
            .map(|m| m.start() + found.end());
        let text = &doc_str[found.end()..next_section.unwrap_or(doc_str.len())];
        let source = doc_str_src
            .clone()
            .into_annotation_source(found.start()..doc_str.len());
        DefAnnotation {
            property_name: P::property_name(),
            local_violation_annotation: new_parsing::violation_from_text(
                fn_def,
                text,
                &source,
                &doc_str_src,
                tcx,
            ),
            text: text.to_string(),
            source,
        }
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
