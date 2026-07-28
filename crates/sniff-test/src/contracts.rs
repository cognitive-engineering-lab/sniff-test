//! Shared parsing for API contract documentation.
//!
//! Panic and safety analysis both read rustdoc sections with named requirement
//! bullets. Keep the markdown-ish parsing here so the two policies do not drift.

use std::fmt::{Debug, Formatter};

use rustc_hir::attrs::{AttributeKind, HasAttrs};
use rustc_hir::{Attribute, def_id::DefId};
use rustc_middle::ty::TyCtxt;
use rustc_span::{DUMMY_SP, Span};
use serde::{Deserialize, Serialize};

use crate::path_patterns::PathPatterns;

/// Synthetic rustdoc markdown matched by Rust namespace glob.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct ContractDocOverrides {
    entries: Vec<ContractDocOverride>,
    patterns: PathPatterns,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContractDocOverride {
    pattern: String,
    markdown: String,
}

impl ContractDocOverrides {
    /// Compiles documentation overrides.
    ///
    /// # Errors
    ///
    /// Returns an error if any configured glob pattern is invalid.
    pub(crate) fn new(entries: Vec<(String, String)>) -> Result<Self, globset::Error> {
        let patterns =
            PathPatterns::new(entries.iter().map(|(pattern, _)| pattern.clone()).collect())?;
        Ok(Self {
            entries: entries
                .into_iter()
                .map(|(pattern, markdown)| ContractDocOverride { pattern, markdown })
                .collect(),
            patterns,
        })
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn markdown_for_namespace(&self, namespace: &str) -> Option<&str> {
        let matched = self.patterns.best_match(namespace)?;
        self.markdown_for_pattern(matched.pattern)
    }

    #[must_use]
    pub(crate) fn markdown_for_def(&self, tcx: TyCtxt<'_>, def_id: DefId) -> Option<&str> {
        let matched = self.patterns.best_def_match(tcx, def_id)?;
        self.markdown_for_pattern(matched.pattern)
    }

    fn markdown_for_pattern(&self, pattern: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| entry.pattern == pattern)
            .map(|entry| entry.markdown.as_str())
    }
}

impl Debug for ContractDocOverrides {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        self.entries.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy)]
enum ContractSyntax {
    Panic,
    Safety,
}

impl ContractSyntax {
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

impl MarkerSatisfaction {
    pub(crate) fn has_justification(&self) -> bool {
        !self.reason.trim().is_empty()
    }

    pub(crate) fn satisfies_requirement(&self, requirement: Option<&str>) -> bool {
        self.has_justification()
            && match requirement {
                Some(required) => self
                    .requirement
                    .as_deref()
                    .is_some_and(|name| normalize_requirement_name(name) == required),
                None => self.requirement.is_none(),
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContractCheck {
    Satisfied,
    MissingJustification,
    MissingRequirements(Vec<ContractRequirement>),
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
    static PANIC_SUMMARY_CACHE: std::cell::RefCell<
        std::collections::HashMap<DefId, ContractDocSummary>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
    static SAFETY_SUMMARY_CACHE: std::cell::RefCell<
        std::collections::HashMap<DefId, ContractDocSummary>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

#[must_use]
pub(crate) fn panic_contract_doc_summary(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    overrides: &ContractDocOverrides,
) -> ContractDocSummary {
    if let Some(markdown) = overrides.markdown_for_def(tcx, def_id) {
        return parse_contract_doc_markdown(markdown, tcx.def_span(def_id), ContractSyntax::Panic);
    }

    PANIC_SUMMARY_CACHE.with_borrow_mut(|cache| {
        cache
            .entry(def_id)
            .or_insert_with(|| contract_doc_summary_from_attrs(tcx, def_id, ContractSyntax::Panic))
            .clone()
    })
}

#[must_use]
pub(crate) fn safety_contract_doc_summary(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    overrides: &ContractDocOverrides,
) -> ContractDocSummary {
    if let Some(markdown) = overrides.markdown_for_def(tcx, def_id) {
        return parse_contract_doc_markdown(markdown, tcx.def_span(def_id), ContractSyntax::Safety);
    }

    SAFETY_SUMMARY_CACHE.with_borrow_mut(|cache| {
        cache
            .entry(def_id)
            .or_insert_with(|| contract_doc_summary_from_attrs(tcx, def_id, ContractSyntax::Safety))
            .clone()
    })
}

fn contract_doc_summary_from_attrs(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    syntax: ContractSyntax,
) -> ContractDocSummary {
    parse_contract_doc_lines_with(
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
        syntax,
    )
}

#[must_use]
#[cfg(test)]
fn parse_panic_contract_doc_lines(
    lines: impl IntoIterator<Item = impl Into<ContractDocLine>>,
) -> ContractDocSummary {
    parse_contract_doc_lines_with(lines, ContractSyntax::Panic)
}

#[must_use]
#[cfg(test)]
fn parse_safety_contract_doc_lines(
    lines: impl IntoIterator<Item = impl Into<ContractDocLine>>,
) -> ContractDocSummary {
    parse_contract_doc_lines_with(lines, ContractSyntax::Safety)
}

fn parse_contract_doc_lines_with(
    lines: impl IntoIterator<Item = impl Into<ContractDocLine>>,
    syntax: ContractSyntax,
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

    parse_contract_doc_markdown_with_spans(&markdown, &line_spans, syntax)
}

fn parse_contract_doc_markdown(
    markdown: &str,
    span: Span,
    syntax: ContractSyntax,
) -> ContractDocSummary {
    parse_contract_doc_markdown_with_spans(markdown, &[(0..markdown.len(), span)], syntax)
}

fn parse_contract_doc_markdown_with_spans(
    markdown: &str,
    line_spans: &[(std::ops::Range<usize>, Span)],
    syntax: ContractSyntax,
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
                    in_contract_section = syntax.matches_heading(markdown_heading_text(&heading));
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

fn satisfied_requirement_names(
    satisfactions: &[MarkerSatisfaction],
) -> std::collections::HashSet<String> {
    satisfactions
        .iter()
        .filter(|satisfaction| satisfaction.has_justification())
        .filter_map(|satisfaction| satisfaction.requirement.as_deref())
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
            .any(|satisfaction| satisfaction.satisfies_requirement(None))
        {
            ContractCheck::Satisfied
        } else {
            ContractCheck::MissingJustification
        };
    }

    let satisfied_requirements = satisfied_requirement_names(satisfactions);
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

#[cfg(test)]
mod tests {
    use super::{
        ContractCheck, ContractRequirement, MarkerSatisfaction, check_contract,
        parse_panic_contract_doc_lines, parse_safety_contract_doc_lines,
    };
    use rustc_span::DUMMY_SP;

    #[test]
    fn panic_doc_headings_match_supported_styles() {
        for heading in ["# Panics", "   ## Panics   ", "### PANICS", "#### Panic(s)"] {
            assert!(parse_panic_contract_doc_lines([heading]).has_docs);
        }
    }

    #[test]
    fn panic_doc_headings_do_not_match_arbitrary_text() {
        for line in [
            "Panics: no heading",
            "#Panics",
            "# Panics in rare cases",
            "# Safety",
        ] {
            assert!(!parse_panic_contract_doc_lines([line]).has_docs);
        }
    }

    #[test]
    fn panic_doc_requirements_are_named_bullets_under_panics() {
        let summary = parse_panic_contract_doc_lines([
            "# Panics",
            "",
            "Panics when the caller violates any listed requirement.",
            "",
            "Requirements:",
            "",
            "- nonzero: denominator must not be zero",
            "* index in bounds: index must be within the slice",
            "- something[var_1]:",
            "# Safety",
            "- ignored: this is outside the panic section",
        ]);

        assert!(summary.has_docs);
        assert_eq!(
            summary.requirements,
            [
                ContractRequirement {
                    name: String::from("nonzero"),
                    condition: String::from("denominator must not be zero"),
                    span: DUMMY_SP,
                },
                ContractRequirement {
                    name: String::from("index in bounds"),
                    condition: String::from("index must be within the slice"),
                    span: DUMMY_SP,
                },
                ContractRequirement {
                    name: String::from("something[var_1]"),
                    condition: String::new(),
                    span: DUMMY_SP,
                },
            ]
        );
    }

    #[test]
    fn panic_doc_duplicate_requirement_names_are_ambiguous() {
        let summary = parse_panic_contract_doc_lines([
            "# Panics",
            "- nonzero: denominator must not be zero",
            "- nonzero!: total must be bounded",
        ]);

        assert_eq!(summary.ambiguous_requirements.len(), 1);
        assert_eq!(summary.ambiguous_requirements[0].normalized_name, "nonzero");
        assert_eq!(summary.ambiguous_requirements[0].requirements.len(), 2);
    }

    #[test]
    fn safety_doc_headings_match_supported_styles() {
        for heading in ["# Safety", "   ## SAFETY   ", "### Safety:"] {
            assert!(parse_safety_contract_doc_lines([heading]).has_docs);
        }
    }

    #[test]
    fn safety_doc_headings_do_not_match_arbitrary_text() {
        for line in [
            "Safety: no heading",
            "#Safety",
            "# Panics",
            "# Safety notes",
        ] {
            assert!(!parse_safety_contract_doc_lines([line]).has_docs);
        }
    }

    #[test]
    fn safety_doc_requirements_are_named_bullets_under_safety() {
        let summary = parse_safety_contract_doc_lines([
            "# Safety",
            "",
            "The caller must satisfy all listed requirements.",
            "",
            "Requirements:",
            "",
            "- valid_ptr: pointer must be non-null",
            "* initialized: pointer must reference initialized memory",
            "- aligned:",
            "# Panics",
            "- ignored: this is outside the safety section",
        ]);

        assert!(summary.has_docs);
        assert_eq!(
            summary.requirements,
            [
                ContractRequirement {
                    name: String::from("valid_ptr"),
                    condition: String::from("pointer must be non-null"),
                    span: DUMMY_SP,
                },
                ContractRequirement {
                    name: String::from("initialized"),
                    condition: String::from("pointer must reference initialized memory"),
                    span: DUMMY_SP,
                },
                ContractRequirement {
                    name: String::from("aligned"),
                    condition: String::new(),
                    span: DUMMY_SP,
                },
            ]
        );
    }

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
    fn named_satisfaction_does_not_justify_an_unnamed_effect() {
        let check = check_contract(
            &[],
            &[MarkerSatisfaction {
                requirement: Some(String::from("unrelated")),
                reason: String::from("this proves a different condition"),
            }],
        );

        assert_eq!(check, ContractCheck::MissingJustification);
    }

    #[test]
    fn commonmark_setext_contract_headings_are_recognized() {
        let summary = parse_panic_contract_doc_lines([
            "Panics",
            "------",
            "",
            "- nonzero: denominator must not be zero",
        ]);

        assert!(summary.has_docs);
        assert_eq!(summary.requirements.len(), 1);
        assert_eq!(summary.requirements[0].name, "nonzero");
    }

    #[test]
    fn explicit_contract_parsers_keep_effect_domains_separate() {
        let panic = parse_panic_contract_doc_lines([
            "# Safety",
            "- initialized: memory must be initialized",
        ]);
        let safety = parse_safety_contract_doc_lines([
            "# Panics",
            "- nonzero: denominator must not be zero",
        ]);

        assert!(!panic.has_docs);
        assert!(panic.requirements.is_empty());
        assert!(!safety.has_docs);
        assert!(safety.requirements.is_empty());
    }

    #[test]
    fn commonmark_inline_formatting_is_not_part_of_requirement_names() {
        let summary = parse_safety_contract_doc_lines([
            "# Safety",
            "",
            "- `valid_ptr`: pointer must be non-null",
            "- **initialized**: pointer must reference initialized memory",
        ]);

        assert_eq!(summary.requirements.len(), 2);
        assert_eq!(summary.requirements[0].name, "valid_ptr");
        assert_eq!(summary.requirements[1].name, "initialized");
    }

    #[test]
    fn commonmark_nested_bullets_remain_part_of_parent_requirement() {
        let summary = parse_safety_contract_doc_lines([
            "# Safety",
            "",
            "- not-null[data]: `data` must be non-null and aligned. This means:",
            "",
            "    - The memory range must be contained within one allocation.",
            "    - `data` must be non-null even for zero-length slices.",
            "",
            "- valid[data]: `data` must point to initialized values.",
        ]);

        assert_eq!(summary.requirements.len(), 2);
        assert_eq!(summary.requirements[0].name, "not-null[data]");
        assert!(summary.requirements[0].condition.contains("one allocation"));
        assert_eq!(summary.requirements[1].name, "valid[data]");
    }

    #[test]
    fn contract_headings_inside_code_fences_are_example_text() {
        let summary = parse_panic_contract_doc_lines([
            "Shows how to document panics:",
            "```text",
            "# Panics",
            "- flag: must be set",
            "```",
        ]);

        assert!(!summary.has_docs);
        assert!(summary.requirements.is_empty());
    }

    #[test]
    fn hidden_doctest_lines_do_not_close_contract_sections() {
        let summary = parse_safety_contract_doc_lines([
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
        ]);

        assert!(summary.has_docs);
        assert_eq!(summary.requirements.len(), 1);
        assert_eq!(summary.requirements[0].name, "valid_ptr");
    }

    #[test]
    fn tilde_fences_and_longer_closers_are_respected() {
        let summary = parse_panic_contract_doc_lines([
            "~~~",
            "# Panics",
            "~~~",
            "# Panics",
            "- flag: must be set",
        ]);

        assert!(summary.has_docs);
        assert_eq!(summary.requirements.len(), 1);

        let nested =
            parse_panic_contract_doc_lines(["````", "```", "# Panics", "```", "````", "# Safety"]);
        assert!(!nested.has_docs);
    }

    #[test]
    fn duplicate_requirement_names_are_ambiguous_after_normalization() {
        let summary = parse_panic_contract_doc_lines([
            "# Panics",
            "- valid_ptr: pointer must be non-null",
            "- valid ptr: pointer must be initialized",
            "- other: independent requirement",
        ]);

        assert_eq!(summary.ambiguous_requirements.len(), 1);
        assert_eq!(
            summary.ambiguous_requirements[0].normalized_name,
            "valid ptr"
        );
        assert_eq!(summary.ambiguous_requirements[0].requirements.len(), 2);
    }
}
