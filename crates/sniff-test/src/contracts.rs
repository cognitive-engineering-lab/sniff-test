//! Shared parsing for API contract documentation.
//!
//! Panic and safety analysis both read rustdoc sections with named requirement
//! bullets. Keep the markdown-ish parsing here so the two policies do not drift.

use rustc_hir::attrs::{AttributeKind, HasAttrs};
use rustc_hir::{Attribute, def_id::DefId};
use rustc_middle::ty::TyCtxt;
use rustc_span::{DUMMY_SP, Span};
use serde::{Deserialize, Serialize};

use crate::config::ContractDocOverrides;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectKind {
    Panic,
    Safety,
}

impl EffectKind {
    pub(crate) const ALL: [Self; 2] = [Self::Panic, Self::Safety];

    pub(crate) fn marker_prefix(self) -> &'static str {
        match self {
            Self::Panic => "PANIC:",
            Self::Safety => "SAFETY:",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRequirement {
    pub name: String,
    pub condition: String,
    #[serde(skip, default = "dummy_span")]
    pub span: Span,
}

fn dummy_span() -> Span {
    DUMMY_SP
}

impl ContractRequirement {
    pub(crate) fn render(&self) -> String {
        if self.condition.is_empty() {
            self.name.clone()
        } else {
            format!("{}: {}", self.name, self.condition)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousContractRequirements {
    pub normalized_name: String,
    pub requirements: Vec<ContractRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerSatisfaction {
    pub requirement: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContractCheck {
    Satisfied,
    MissingJustification,
    MissingRequirements(Vec<ContractRequirement>),
}

impl ContractCheck {
    pub(crate) fn is_satisfied(&self) -> bool {
        matches!(self, Self::Satisfied)
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ContractDocSummary {
    pub(crate) has_docs: bool,
    pub(crate) requirements: Vec<ContractRequirement>,
    pub(crate) ambiguous_requirements: Vec<AmbiguousContractRequirements>,
}

// One rustc session per process and single-threaded analysis, so DefId-keyed
// caching is sound. Doc attributes are re-read and re-parsed for every edge
// classification without this.
thread_local! {
    static SUMMARY_CACHE: std::cell::RefCell<
        std::collections::HashMap<(DefId, EffectKind), ContractDocSummary>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

#[must_use]
pub(crate) fn contract_doc_summary(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    kind: EffectKind,
    overrides: &ContractDocOverrides,
) -> ContractDocSummary {
    if let Some(markdown) = overrides.markdown_for_def(tcx, def_id) {
        return parse_contract_doc_markdown(markdown, tcx.def_span(def_id), kind);
    }

    SUMMARY_CACHE.with_borrow_mut(|cache| {
        cache
            .entry((def_id, kind))
            .or_insert_with(|| {
                parse_contract_doc_lines(
                    HasAttrs::get_attrs(def_id, &tcx)
                        .iter()
                        .filter_map(doc_comment)
                        .flat_map(|(comment, span)| {
                            let lines = comment
                                .as_str()
                                .lines()
                                .map(move |line| (line.to_owned(), span))
                                .collect::<Vec<_>>();
                            lines.into_iter()
                        }),
                    kind,
                )
            })
            .clone()
    })
}

#[must_use]
pub(crate) fn parse_contract_doc_lines(
    lines: impl IntoIterator<Item = impl Into<ContractDocLine>>,
    kind: EffectKind,
) -> ContractDocSummary {
    let lines = lines.into_iter().map(Into::into).collect::<Vec<_>>();
    let mut markdown = String::new();
    let mut line_spans = Vec::new();
    for line in lines {
        let start = markdown.len();
        markdown.push_str(&line.line);
        let end = markdown.len();
        line_spans.push((start..end, line.span));
        markdown.push('\n');
    }

    parse_contract_doc_markdown_with_spans(&markdown, &line_spans, kind)
}

fn parse_contract_doc_markdown(markdown: &str, span: Span, kind: EffectKind) -> ContractDocSummary {
    parse_contract_doc_markdown_with_spans(markdown, &[(0..markdown.len(), span)], kind)
}

fn parse_contract_doc_markdown_with_spans(
    markdown: &str,
    line_spans: &[(std::ops::Range<usize>, Span)],
    kind: EffectKind,
) -> ContractDocSummary {
    use pulldown_cmark::{Event, Parser, Tag, TagEnd};

    let mut summary = ContractDocSummary::default();
    let mut in_contract_section = false;
    let mut heading = None::<String>;
    let mut item = None::<MarkdownItem>;
    let mut list_depth = 0usize;

    for (event, range) in Parser::new(markdown).into_offset_iter() {
        match event {
            Event::Start(Tag::Heading { .. }) => heading = Some(String::new()),
            Event::End(TagEnd::Heading(_)) => {
                if let Some(heading) = heading.take() {
                    in_contract_section = kind.matches_heading(markdown_heading_text(&heading));
                    summary.has_docs |= in_contract_section;
                }
            }
            Event::Start(Tag::List(_)) if in_contract_section => {
                list_depth += 1;
            }
            Event::End(TagEnd::List(_)) if in_contract_section => {
                list_depth = list_depth.saturating_sub(1);
            }
            Event::Start(Tag::Item) if in_contract_section && list_depth == 1 => {
                item = Some(MarkdownItem {
                    text: String::new(),
                    span: span_for_offset(line_spans, range.start),
                });
            }
            Event::Start(Tag::Item) if in_contract_section && list_depth > 1 => {
                if let Some(item) = &mut item {
                    item.text.push(' ');
                }
            }
            Event::End(TagEnd::Item) if in_contract_section && list_depth == 1 => {
                if let Some(item) = item.take()
                    && let Some(requirement) = parse_requirement_text(&item)
                {
                    summary.requirements.push(requirement);
                }
            }
            Event::Text(text) | Event::Code(text) => {
                if let Some(heading) = &mut heading {
                    heading.push_str(&text);
                }
                if let Some(item) = &mut item {
                    item.text.push_str(&text);
                }
            }
            Event::SoftBreak | Event::HardBreak => {
                if let Some(heading) = &mut heading {
                    heading.push(' ');
                }
                if let Some(item) = &mut item {
                    item.text.push(' ');
                }
            }
            _ => {}
        }
    }

    summary.ambiguous_requirements = ambiguous_requirements(&summary.requirements);
    summary
}

struct MarkdownItem {
    text: String,
    span: Span,
}

pub(crate) struct ContractDocLine {
    line: String,
    span: Span,
}

impl From<&str> for ContractDocLine {
    fn from(line: &str) -> Self {
        Self {
            line: line.to_owned(),
            span: DUMMY_SP,
        }
    }
}

impl From<(String, Span)> for ContractDocLine {
    fn from((line, span): (String, Span)) -> Self {
        Self { line, span }
    }
}

#[cfg(test)]
#[must_use]
pub(crate) fn line_has_contract_heading(line: &str, kind: EffectKind) -> bool {
    let mut heading = None::<String>;
    for event in pulldown_cmark::Parser::new(line) {
        match event {
            pulldown_cmark::Event::Start(pulldown_cmark::Tag::Heading { .. }) => {
                heading = Some(String::new());
            }
            pulldown_cmark::Event::End(pulldown_cmark::TagEnd::Heading(_)) => {
                return heading
                    .is_some_and(|heading| kind.matches_heading(markdown_heading_text(&heading)));
            }
            pulldown_cmark::Event::Text(text) | pulldown_cmark::Event::Code(text) => {
                if let Some(heading) = &mut heading {
                    heading.push_str(&text);
                }
            }
            _ => {}
        }
    }
    false
}

/// Normalized names of requirements satisfied by marker bullets with
/// non-empty reasons; shared by the panic and safety requirement checks.
pub(crate) fn satisfied_requirement_names<'a>(
    satisfactions: impl IntoIterator<Item = (Option<&'a str>, &'a str)>,
) -> std::collections::HashSet<String> {
    satisfactions
        .into_iter()
        .filter(|(_, reason)| !reason.trim().is_empty())
        .filter_map(|(requirement, _)| requirement)
        .map(normalize_requirement_name)
        .collect()
}

pub(crate) fn check_contract(
    requirements: &[ContractRequirement],
    satisfactions: &[MarkerSatisfaction],
) -> ContractCheck {
    if requirements.is_empty() {
        return if satisfactions
            .iter()
            .any(|satisfaction| !satisfaction.reason.trim().is_empty())
        {
            ContractCheck::Satisfied
        } else {
            ContractCheck::MissingJustification
        };
    }

    let satisfied_requirements = satisfied_requirement_names(
        satisfactions
            .iter()
            .map(|satisfaction| (satisfaction.requirement.as_deref(), &*satisfaction.reason)),
    );
    let missing = requirements
        .iter()
        .filter(|requirement| {
            !satisfied_requirements.contains(&normalize_requirement_name(&requirement.name))
        })
        .cloned()
        .collect::<Vec<_>>();

    if missing.is_empty() {
        ContractCheck::Satisfied
    } else {
        ContractCheck::MissingRequirements(missing)
    }
}

fn ambiguous_requirements(
    requirements: &[ContractRequirement],
) -> Vec<AmbiguousContractRequirements> {
    let mut groups: Vec<AmbiguousContractRequirements> = Vec::new();
    let mut indexes = std::collections::HashMap::new();

    for requirement in requirements {
        let normalized_name = normalize_requirement_name(&requirement.name);
        let index = *indexes.entry(normalized_name.clone()).or_insert_with(|| {
            groups.push(AmbiguousContractRequirements {
                normalized_name,
                requirements: Vec::new(),
            });
            groups.len() - 1
        });
        groups[index].requirements.push(requirement.clone());
    }

    groups
        .into_iter()
        .filter(|group| group.requirements.len() > 1)
        .collect()
}

#[must_use]
pub(crate) fn normalize_requirement_name(name: &str) -> String {
    let mut normalized = String::new();
    let mut pending_space = false;

    for character in name.trim().chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            if pending_space && !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.push(character);
            pending_space = false;
        } else {
            pending_space = true;
        }
    }

    normalized
}

fn doc_comment(attr: &Attribute) -> Option<(rustc_span::Symbol, Span)> {
    match attr {
        Attribute::Parsed(AttributeKind::DocComment { comment, span, .. }) => {
            Some((*comment, *span))
        }
        Attribute::Parsed(_) | Attribute::Unparsed(_) => None,
    }
}

fn parse_requirement_text(item: &MarkdownItem) -> Option<ContractRequirement> {
    let (name, condition) = item.text.split_once(':')?;
    let name = name.trim();
    let condition = condition.trim();

    (!normalize_requirement_name(name).is_empty()).then(|| ContractRequirement {
        name: name.to_owned(),
        condition: condition.to_owned(),
        span: item.span,
    })
}

fn markdown_heading_text(heading: &str) -> &str {
    heading.trim().trim_end_matches([':', '-']).trim()
}

fn span_for_offset(line_spans: &[(std::ops::Range<usize>, Span)], offset: usize) -> Span {
    line_spans
        .iter()
        .find(|(range, _)| range.contains(&offset))
        .map_or(DUMMY_SP, |(_, span)| *span)
}

impl EffectKind {
    fn matches_heading(self, heading: &str) -> bool {
        match self {
            Self::Panic => matches!(
                heading.to_ascii_lowercase().as_str(),
                "panic" | "panics" | "panic(s)"
            ),
            Self::Safety => heading.eq_ignore_ascii_case("safety"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ContractCheck, ContractRequirement, EffectKind, MarkerSatisfaction, check_contract,
        parse_contract_doc_lines,
    };
    use rustc_span::DUMMY_SP;

    #[test]
    fn contract_check_distinguishes_justification_from_named_requirements() {
        assert_eq!(
            check_contract(&[], &[]),
            ContractCheck::MissingJustification
        );
        assert_eq!(
            check_contract(
                &[],
                &[MarkerSatisfaction {
                    requirement: None,
                    reason: String::from("the caller established the invariant"),
                }],
            ),
            ContractCheck::Satisfied
        );

        let requirements = vec![
            ContractRequirement {
                name: String::from("nonzero"),
                condition: String::from("the divisor must not be zero"),
                span: DUMMY_SP,
            },
            ContractRequirement {
                name: String::from("bounded"),
                condition: String::from("the input must fit"),
                span: DUMMY_SP,
            },
        ];
        assert_eq!(
            check_contract(
                &requirements,
                &[MarkerSatisfaction {
                    requirement: Some(String::from("NONZERO!")),
                    reason: String::from("checked above"),
                }],
            ),
            ContractCheck::MissingRequirements(vec![requirements[1].clone()])
        );
    }

    #[test]
    fn commonmark_setext_contract_headings_are_recognized() {
        let summary = parse_contract_doc_lines(
            [
                "Panics",
                "------",
                "",
                "- nonzero: denominator must not be zero",
            ],
            EffectKind::Panic,
        );

        assert!(summary.has_docs);
        assert_eq!(summary.requirements.len(), 1);
        assert_eq!(summary.requirements[0].name, "nonzero");
    }

    #[test]
    fn commonmark_inline_formatting_is_not_part_of_requirement_names() {
        let summary = parse_contract_doc_lines(
            [
                "# Safety",
                "",
                "- `valid_ptr`: pointer must be non-null",
                "- **initialized**: pointer must reference initialized memory",
            ],
            EffectKind::Safety,
        );

        assert_eq!(summary.requirements.len(), 2);
        assert_eq!(summary.requirements[0].name, "valid_ptr");
        assert_eq!(summary.requirements[1].name, "initialized");
    }

    #[test]
    fn commonmark_nested_bullets_remain_part_of_parent_requirement() {
        let summary = parse_contract_doc_lines(
            [
                "# Safety",
                "",
                "- not-null[data]: `data` must be non-null and aligned. This means:",
                "",
                "    - The memory range must be contained within one allocation.",
                "    - `data` must be non-null even for zero-length slices.",
                "",
                "- valid[data]: `data` must point to initialized values.",
            ],
            EffectKind::Safety,
        );

        assert_eq!(summary.requirements.len(), 2);
        assert_eq!(summary.requirements[0].name, "not-null[data]");
        assert!(summary.requirements[0].condition.contains("one allocation"));
        assert_eq!(summary.requirements[1].name, "valid[data]");
    }

    #[test]
    fn contract_headings_inside_code_fences_are_example_text() {
        let summary = parse_contract_doc_lines(
            [
                "Shows how to document panics:",
                "```text",
                "# Panics",
                "- flag: must be set",
                "```",
            ],
            EffectKind::Panic,
        );

        assert!(!summary.has_docs);
        assert!(summary.requirements.is_empty());
    }

    #[test]
    fn hidden_doctest_lines_do_not_close_contract_sections() {
        let summary = parse_contract_doc_lines(
            [
                "# Safety",
                "",
                "```",
                "# use std::ptr;",
                "# fn main() {",
                "let value = 1;",
                "# }",
                "```",
                "",
                "- valid_ptr: pointer must be non-null",
            ],
            EffectKind::Safety,
        );

        assert!(summary.has_docs);
        assert_eq!(summary.requirements.len(), 1);
        assert_eq!(summary.requirements[0].name, "valid_ptr");
    }

    #[test]
    fn tilde_fences_and_longer_closers_are_respected() {
        let summary = parse_contract_doc_lines(
            ["~~~", "# Panics", "~~~", "# Panics", "- flag: must be set"],
            EffectKind::Panic,
        );

        assert!(summary.has_docs);
        assert_eq!(summary.requirements.len(), 1);

        let nested = parse_contract_doc_lines(
            ["````", "```", "# Panics", "```", "````", "# Safety"],
            EffectKind::Panic,
        );
        assert!(!nested.has_docs);
    }

    #[test]
    fn duplicate_requirement_names_are_ambiguous_after_normalization() {
        let summary = parse_contract_doc_lines(
            [
                "# Panics",
                "- valid_ptr: pointer must be non-null",
                "- valid ptr: pointer must be initialized",
                "- other: independent requirement",
            ],
            EffectKind::Panic,
        );

        assert_eq!(summary.ambiguous_requirements.len(), 1);
        assert_eq!(
            summary.ambiguous_requirements[0].normalized_name,
            "valid ptr"
        );
        assert_eq!(summary.ambiguous_requirements[0].requirements.len(), 2);
    }
}
