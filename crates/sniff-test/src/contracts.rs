//! Shared parsing for API contract documentation.
//!
//! Panic and safety analysis both read rustdoc sections with named requirement
//! bullets. Keep the markdown-ish parsing here so the two policies do not drift.

use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};

use rustc_hir::attrs::{AttributeKind, HasAttrs};
use rustc_hir::{Attribute, def_id::DefId};
use rustc_middle::ty::TyCtxt;
use rustc_span::{DUMMY_SP, Span};
use serde::{Deserialize, Serialize};

use crate::artifact::is_portable_source_path;
use crate::path_patterns::PathPatterns;

/// Exact package source location used to select synthetic rustdoc markdown.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SourceContractSelector {
    crate_name: String,
    version: String,
    path: String,
    start_line: u32,
    end_line: u32,
}

impl SourceContractSelector {
    /// Parses a package-relative `path:start:end` source selector.
    ///
    /// Line numbers are one-based and inclusive.
    pub(crate) fn parse(
        crate_name: impl Into<String>,
        version: impl Into<String>,
        location: &str,
    ) -> Result<Self, SourceContractSelectorError> {
        let crate_name = crate_name.into();
        Self::validate_crate_name(&crate_name)?;

        let version = version.into();
        Self::validate_version(&version)?;

        let Some((path_and_start, end_line)) = location.rsplit_once(':') else {
            return Err(SourceContractSelectorError::Location(location.to_owned()));
        };
        let Some((path, start_line)) = path_and_start.rsplit_once(':') else {
            return Err(SourceContractSelectorError::Location(location.to_owned()));
        };
        if !is_portable_source_path(path) {
            return Err(SourceContractSelectorError::Path(path.to_owned()));
        }

        let line_range = format!("{start_line}:{end_line}");
        let Ok(start_line) = start_line.parse::<u32>() else {
            return Err(SourceContractSelectorError::LineRange(line_range));
        };
        let Ok(end_line) = end_line.parse::<u32>() else {
            return Err(SourceContractSelectorError::LineRange(line_range));
        };
        if start_line == 0 || start_line > end_line {
            return Err(SourceContractSelectorError::LineRange(line_range));
        }

        Ok(Self {
            crate_name,
            version,
            path: path.to_owned(),
            start_line,
            end_line,
        })
    }

    pub(crate) fn validate_crate_name(crate_name: &str) -> Result<(), SourceContractSelectorError> {
        if is_valid_crate_name(crate_name) {
            Ok(())
        } else {
            Err(SourceContractSelectorError::CrateName(
                crate_name.to_owned(),
            ))
        }
    }

    pub(crate) fn validate_version(version: &str) -> Result<(), SourceContractSelectorError> {
        if version.trim() == version && cargo_metadata::semver::Version::parse(version).is_ok() {
            Ok(())
        } else {
            Err(SourceContractSelectorError::Version(version.to_owned()))
        }
    }

    #[must_use]
    pub(crate) fn crate_name(&self) -> &str {
        &self.crate_name
    }

    #[must_use]
    pub(crate) fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub(crate) const fn start_line(&self) -> u32 {
        self.start_line
    }

    #[must_use]
    pub(crate) const fn end_line(&self) -> u32 {
        self.end_line
    }
}

fn is_valid_crate_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|first| {
        (first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceContractSelectorError {
    CrateName(String),
    Version(String),
    Location(String),
    Path(String),
    LineRange(String),
}

impl Display for SourceContractSelectorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CrateName(name) => write!(formatter, "invalid Rust crate name `{name}`"),
            Self::Version(version) => {
                write!(formatter, "invalid exact Cargo package version `{version}`")
            }
            Self::Location(location) => write!(
                formatter,
                "invalid source location `{location}`; expected path:start:end"
            ),
            Self::Path(path) => {
                write!(formatter, "invalid package-relative source path `{path}`")
            }
            Self::LineRange(range) => write!(
                formatter,
                "invalid source line range `{range}`; expected positive start:end"
            ),
        }
    }
}

impl std::error::Error for SourceContractSelectorError {}

/// Synthetic rustdoc markdown selected by namespace glob or exact source location.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct ContractDocOverrides {
    entries: Vec<ContractDocOverride>,
    source_entries: BTreeMap<SourceContractSelector, String>,
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
        Self::with_source_entries(entries, BTreeMap::new())
    }

    /// Compiles namespace documentation overrides and stores exact source overrides.
    ///
    /// # Errors
    ///
    /// Returns an error if any configured namespace glob pattern is invalid.
    pub(crate) fn with_source_entries(
        entries: Vec<(String, String)>,
        source_entries: BTreeMap<SourceContractSelector, String>,
    ) -> Result<Self, globset::Error> {
        let patterns =
            PathPatterns::new(entries.iter().map(|(pattern, _)| pattern.clone()).collect())?;
        Ok(Self {
            entries: entries
                .into_iter()
                .map(|(pattern, markdown)| ContractDocOverride { pattern, markdown })
                .collect(),
            source_entries,
            patterns,
        })
    }

    pub(crate) fn source_entries(
        &self,
    ) -> impl ExactSizeIterator<Item = (&SourceContractSelector, &str)> + DoubleEndedIterator {
        self.source_entries
            .iter()
            .map(|(selector, markdown)| (selector, markdown.as_str()))
    }

    #[must_use]
    pub(crate) fn markdown_for_candidates(&self, candidates: &[String]) -> Option<&str> {
        self.markdown_for_pattern(self.best_pattern_for_candidates(candidates)?)
    }

    #[must_use]
    pub(crate) fn best_pattern_for_candidates(&self, candidates: &[String]) -> Option<&str> {
        self.patterns
            .best_candidates_match(candidates)
            .map(|matched| matched.pattern)
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
        formatter
            .debug_struct("ContractDocOverrides")
            .field("namespace_entries", &self.entries)
            .field("source_entries", &self.source_entries)
            .finish_non_exhaustive()
    }
}

fn is_panic_heading(heading: &str) -> bool {
    heading.eq_ignore_ascii_case("panic")
        || heading.eq_ignore_ascii_case("panics")
        || heading.eq_ignore_ascii_case("panic(s)")
}

fn is_safety_heading(heading: &str) -> bool {
    heading.eq_ignore_ascii_case("safety")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRequirement {
    pub name: String,
    pub condition: String,
    pub path: Vec<usize>,
    #[serde(skip, default = "dummy_span")]
    pub span: Span,
}

fn dummy_span() -> Span {
    DUMMY_SP
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
    pub path: Option<Vec<usize>>,
}

impl MarkerSatisfaction {
    pub(crate) fn has_justification(&self) -> bool {
        !self.reason.trim().is_empty()
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
    static PANIC_SUMMARY_CACHE: std::cell::RefCell<
        std::collections::HashMap<DefId, ContractDocSummary>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
    static SAFETY_SUMMARY_CACHE: std::cell::RefCell<
        std::collections::HashMap<DefId, ContractDocSummary>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Parses a panic contract directly from rustdoc attributes.
#[must_use]
pub(crate) fn panic_contract_doc_summary_from_attrs(
    tcx: TyCtxt<'_>,
    def_id: DefId,
) -> ContractDocSummary {
    PANIC_SUMMARY_CACHE.with_borrow_mut(|cache| {
        cache
            .entry(def_id)
            .or_insert_with(|| contract_doc_summary_from_attrs(tcx, def_id, is_panic_heading))
            .clone()
    })
}

/// Parses a safety contract directly from rustdoc attributes.
#[must_use]
pub(crate) fn safety_contract_doc_summary_from_attrs(
    tcx: TyCtxt<'_>,
    def_id: DefId,
) -> ContractDocSummary {
    SAFETY_SUMMARY_CACHE.with_borrow_mut(|cache| {
        cache
            .entry(def_id)
            .or_insert_with(|| contract_doc_summary_from_attrs(tcx, def_id, is_safety_heading))
            .clone()
    })
}

fn contract_doc_summary_from_attrs(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    is_contract_heading: fn(&str) -> bool,
) -> ContractDocSummary {
    parse_contract_doc_lines_with(
        def_id
            .get_attrs(&tcx)
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
        is_contract_heading,
    )
}

#[must_use]
#[cfg(test)]
fn parse_panic_contract_doc_lines(
    lines: impl IntoIterator<Item = impl Into<ContractDocLine>>,
) -> ContractDocSummary {
    parse_contract_doc_lines_with(lines, is_panic_heading)
}

#[must_use]
#[cfg(test)]
fn parse_safety_contract_doc_lines(
    lines: impl IntoIterator<Item = impl Into<ContractDocLine>>,
) -> ContractDocSummary {
    parse_contract_doc_lines_with(lines, is_safety_heading)
}

fn parse_contract_doc_lines_with(
    lines: impl IntoIterator<Item = impl Into<ContractDocLine>>,
    is_contract_heading: fn(&str) -> bool,
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

    parse_contract_doc_markdown_with_spans(&markdown, &line_spans, is_contract_heading)
}

fn parse_contract_doc_markdown(
    markdown: &str,
    span: Span,
    is_contract_heading: fn(&str) -> bool,
) -> ContractDocSummary {
    parse_contract_doc_markdown_with_spans(
        markdown,
        &[(0..markdown.len(), span)],
        is_contract_heading,
    )
}

#[must_use]
pub(crate) fn panic_contract_doc_summary_from_markdown(markdown: &str) -> ContractDocSummary {
    parse_contract_doc_markdown(markdown, DUMMY_SP, is_panic_heading)
}

#[must_use]
pub(crate) fn safety_contract_doc_summary_from_markdown(markdown: &str) -> ContractDocSummary {
    parse_contract_doc_markdown(markdown, DUMMY_SP, is_safety_heading)
}

fn parse_contract_doc_markdown_with_spans(
    markdown: &str,
    line_spans: &[(std::ops::Range<usize>, Span)],
    is_contract_heading: fn(&str) -> bool,
) -> ContractDocSummary {
    use pulldown_cmark::{CodeBlockKind, Event, Parser, Tag, TagEnd};

    let mut summary = ContractDocSummary::default();
    let mut in_contract_section = false;
    let mut heading = None::<String>;
    let mut items = Vec::<(usize, MarkdownItem, usize)>::new();
    let mut parsed_items = Vec::<(usize, ContractRequirement)>::new();
    let mut next_item = 0usize;
    let mut next_root_item = 0usize;
    let mut indented_code_block = None::<(String, usize)>;

    for (event, range) in Parser::new(markdown).into_offset_iter() {
        match event {
            Event::Start(Tag::Heading { .. }) => heading = Some(String::new()),
            Event::End(TagEnd::Heading(_)) => {
                if let Some(heading) = heading.take() {
                    in_contract_section = is_contract_heading(markdown_heading_text(&heading));
                    summary.has_docs |= in_contract_section;
                }
            }
            Event::Start(Tag::CodeBlock(CodeBlockKind::Indented)) if in_contract_section => {
                indented_code_block = Some((String::new(), range.start));
            }
            Event::End(TagEnd::CodeBlock) if in_contract_section => {
                if let Some((block, offset)) = indented_code_block.take() {
                    summary
                        .requirements
                        .extend(parse_indented_requirement_block(&block, offset, line_spans));
                }
            }
            Event::Start(Tag::Item) if in_contract_section => {
                let path = if let Some((_, parent, next_child)) = items.last_mut() {
                    let mut path = parent.path.clone();
                    path.push(*next_child);
                    *next_child += 1;
                    path
                } else {
                    let path = vec![next_root_item];
                    next_root_item += 1;
                    path
                };
                items.push((
                    next_item,
                    MarkdownItem {
                        text: String::new(),
                        span: span_for_offset(line_spans, range.start),
                        path,
                    },
                    0,
                ));
                next_item += 1;
            }
            Event::End(TagEnd::Item) if in_contract_section => {
                if let Some((ordinal, item, _)) = items.pop() {
                    if let Some(requirement) = parse_requirement_text(&item) {
                        parsed_items.push((ordinal, requirement));
                    } else if let Some((_, parent, _)) = items.last_mut() {
                        if !parent.text.is_empty() && !item.text.is_empty() {
                            parent.text.push(' ');
                        }
                        parent.text.push_str(&item.text);
                    }
                }
            }
            Event::Text(text) | Event::Code(text) => {
                if let Some(heading) = &mut heading {
                    heading.push_str(&text);
                }
                if let Some((_, item, _)) = items.last_mut() {
                    item.text.push_str(&text);
                }
                if let Some((block, _)) = &mut indented_code_block {
                    block.push_str(&text);
                }
            }
            Event::SoftBreak | Event::HardBreak => {
                if let Some(heading) = &mut heading {
                    heading.push(' ');
                }
                if let Some((_, item, _)) = items.last_mut() {
                    item.text.push(' ');
                }
            }
            _ => {}
        }
    }

    parsed_items.sort_by_key(|(ordinal, _)| *ordinal);
    summary
        .requirements
        .extend(parsed_items.into_iter().map(|(_, requirement)| requirement));

    summary.ambiguous_requirements = ambiguous_requirements(&summary.requirements);
    summary
}

/// `CommonMark` interprets a four-space-indented bullet as an indented code
/// block. Rustdoc authors nevertheless commonly indent requirement lists this
/// way for source readability. Accept such a block only when every nonblank
/// line is a requirement-list item, so actual code examples retain
/// their normal meaning.
fn parse_indented_requirement_block(
    block: &str,
    offset: usize,
    line_spans: &[(std::ops::Range<usize>, Span)],
) -> Vec<ContractRequirement> {
    let items = block
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(markdown_list_item_body)
        .collect::<Option<Vec<_>>>();
    let Some(items) = items else {
        return Vec::new();
    };

    let span = span_for_offset(line_spans, offset);
    let mut levels = Vec::new();
    items
        .into_iter()
        .enumerate()
        .filter_map(|(index, text)| {
            parse_requirement_text(&MarkdownItem {
                text: text.to_owned(),
                span,
                path: list_path_for_indented_line(block, index, &mut levels),
            })
        })
        .collect()
}

fn list_path_for_indented_line(
    block: &str,
    item_index: usize,
    levels: &mut Vec<(usize, usize, usize)>,
) -> Vec<usize> {
    let line = block
        .lines()
        .filter(|line| !line.trim().is_empty())
        .nth(item_index)
        .expect("item index came from the same nonblank lines");
    structural_list_path(line.len() - line.trim_start().len(), levels)
}

pub(crate) fn structural_list_path(
    indentation: usize,
    levels: &mut Vec<(usize, usize, usize)>,
) -> Vec<usize> {
    while levels
        .last()
        .is_some_and(|(indent, _, _)| *indent > indentation)
    {
        levels.pop();
    }
    if levels
        .last()
        .is_none_or(|(indent, _, _)| *indent < indentation)
    {
        levels.push((indentation, 0, 1));
    } else if let Some((_, current, next)) = levels.last_mut() {
        *current = *next;
        *next += 1;
    }
    levels.iter().map(|(_, current, _)| *current).collect()
}

pub(crate) fn markdown_list_item_body(line: &str) -> Option<&str> {
    let line = line.trim_start();
    if let Some(body) = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .or_else(|| line.strip_prefix("+ "))
    {
        return Some(body);
    }

    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || digits > 9 {
        return None;
    }
    line[digits..]
        .strip_prefix(['.', ')'])?
        .strip_prefix(char::is_whitespace)
        .map(str::trim_start)
}

struct MarkdownItem {
    text: String,
    span: Span,
    path: Vec<usize>,
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

fn ambiguous_requirements(
    requirements: &[ContractRequirement],
) -> Vec<AmbiguousContractRequirements> {
    let mut groups: Vec<AmbiguousContractRequirements> = Vec::new();
    let mut indexes = std::collections::HashMap::new();

    for requirement in requirements {
        let normalized_name = normalize_requirement_name(&requirement.name);
        if normalized_name.is_empty() {
            continue;
        }
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
    let text = item.text.trim();
    if text.is_empty() {
        return None;
    }
    let (name, condition) = text
        .split_once(':')
        .map_or(("", text), |(name, condition)| {
            if normalize_requirement_name(name).is_empty() {
                ("", text)
            } else {
                (name.trim(), condition.trim())
            }
        });

    Some(ContractRequirement {
        name: name.to_owned(),
        condition: condition.to_owned(),
        path: item.path.clone(),
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
    use std::collections::BTreeMap;

    use super::{
        SourceContractSelector, parse_panic_contract_doc_lines, parse_safety_contract_doc_lines,
    };

    #[test]
    fn source_contract_selector_parses_typed_identity_and_inclusive_lines() {
        let selector =
            SourceContractSelector::parse("zerocopy", "0.8.27", "src/layout/for_type.rs:123:130")
                .expect("valid source selector");

        assert_eq!(selector.crate_name(), "zerocopy");
        assert_eq!(selector.version(), "0.8.27");
        assert_eq!(selector.path(), "src/layout/for_type.rs");
        assert_eq!(selector.start_line(), 123);
        assert_eq!(selector.end_line(), 130);
    }

    #[test]
    fn source_contract_selector_rejects_invalid_crate_names_and_versions() {
        for crate_name in [
            "",
            "9crate",
            "crate-name",
            "crate.name",
            "crate name",
            "crateé",
        ] {
            assert!(
                SourceContractSelector::parse(crate_name, "1.0.0", "src/lib.rs:1:1").is_err(),
                "invalid crate name `{crate_name}` was accepted"
            );
        }
        for version in ["", "   ", " 1.0.0", "1.0.0 ", "latest", "1.2"] {
            assert!(
                SourceContractSelector::parse("valid_crate", version, "src/lib.rs:1:1").is_err(),
                "invalid exact version `{version}` was accepted"
            );
        }

        SourceContractSelector::parse("valid_crate", "1.2.3-alpha.1+build.7", "src/lib.rs:1:1")
            .expect("Cargo prerelease and build versions should be accepted");
    }

    #[test]
    fn source_contract_selector_rejects_nonportable_paths() {
        for location in [
            ":1:1",
            "/src/lib.rs:1:1",
            "src\\lib.rs:1:1",
            "./src/lib.rs:1:1",
            "src/../lib.rs:1:1",
            "src//lib.rs:1:1",
            "src/lib.rs/:1:1",
            "src:generated/lib.rs:1:1",
        ] {
            assert!(
                SourceContractSelector::parse("valid_crate", "1.0.0", location).is_err(),
                "nonportable location `{location}` was accepted"
            );
        }
    }

    #[test]
    fn source_contract_selector_rejects_invalid_line_ranges() {
        for location in [
            "src/lib.rs:0:1",
            "src/lib.rs:1:0",
            "src/lib.rs:2:1",
            "src/lib.rs:1",
            "src/lib.rs:1:",
            "src/lib.rs::1",
            "src/lib.rs:one:2",
            "src/lib.rs:1-2",
            "src/lib.rs:1:2:3",
            "src/lib.rs:4294967296:4294967296",
        ] {
            assert!(
                SourceContractSelector::parse("valid_crate", "1.0.0", location).is_err(),
                "invalid location `{location}` was accepted"
            );
        }
    }

    #[test]
    fn contract_overrides_expose_namespace_and_source_entries_separately() {
        let selector = SourceContractSelector::parse("zerocopy", "0.8.27", "src/layout.rs:123:130")
            .expect("valid source selector");
        let overrides = super::ContractDocOverrides::with_source_entries(
            vec![(
                "zerocopy::Layout::for_type".to_owned(),
                "# Panics".to_owned(),
            )],
            BTreeMap::from([(selector.clone(), "# Safety".to_owned())]),
        )
        .expect("valid overrides");

        assert_eq!(
            overrides.markdown_for_candidates(&[String::from("zerocopy::Layout::for_type")]),
            Some("# Panics")
        );
        assert_eq!(
            overrides.source_entries().collect::<Vec<_>>(),
            [(&selector, "# Safety")]
        );
    }

    #[test]
    fn contract_parsers_accept_supported_heading_styles() {
        for heading in [
            "# Panic",
            "# Panics",
            "   ## Panics   ",
            "### PANICS",
            "#### Panic(s)",
        ] {
            assert!(parse_panic_contract_doc_lines([heading]).has_docs);
        }
        for heading in ["# Safety", "   ## SAFETY   ", "### Safety:"] {
            assert!(parse_safety_contract_doc_lines([heading]).has_docs);
        }
    }

    #[test]
    fn contract_parsers_ignore_malformed_headings() {
        assert!(!parse_panic_contract_doc_lines(["# Panics in rare cases"]).has_docs);
        assert!(!parse_safety_contract_doc_lines(["# Safety notes"]).has_docs);
    }

    #[test]
    fn contract_parsers_extract_their_named_requirements() {
        let panic = parse_panic_contract_doc_lines([
            "# Panics",
            "",
            "- nonzero: denominator must not be zero",
            "* index in bounds: index must be within the slice",
            "# Safety",
            "- ignored: this is outside the panic section",
        ]);
        let safety = parse_safety_contract_doc_lines([
            "# Safety",
            "",
            "- valid_ptr: pointer must be non-null",
            "* initialized: pointer must reference initialized memory",
            "- aligned:",
            "# Panics",
            "- ignored: this is outside the safety section",
        ]);

        assert!(panic.has_docs);
        assert_eq!(
            panic
                .requirements
                .iter()
                .map(|requirement| (requirement.name.as_str(), requirement.condition.as_str()))
                .collect::<Vec<_>>(),
            [
                ("nonzero", "denominator must not be zero"),
                ("index in bounds", "index must be within the slice"),
            ]
        );
        assert!(safety.has_docs);
        assert_eq!(
            safety
                .requirements
                .iter()
                .map(|requirement| (requirement.name.as_str(), requirement.condition.as_str()))
                .collect::<Vec<_>>(),
            [
                ("valid_ptr", "pointer must be non-null"),
                ("initialized", "pointer must reference initialized memory"),
                ("aligned", ""),
            ]
        );
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
    fn commonmark_nested_unnamed_bullets_become_structural_requirements() {
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

        assert_eq!(summary.requirements.len(), 4);
        assert_eq!(summary.requirements[0].name, "not-null[data]");
        assert_eq!(summary.requirements[0].path, [0]);
        assert!(summary.requirements[1].name.is_empty());
        assert_eq!(summary.requirements[1].path, [0, 0]);
        assert!(summary.requirements[1].condition.contains("one allocation"));
        assert!(summary.requirements[2].name.is_empty());
        assert_eq!(summary.requirements[2].path, [0, 1]);
        assert_eq!(summary.requirements[3].name, "valid[data]");
        assert_eq!(summary.requirements[3].path, [1]);
    }

    #[test]
    fn named_requirements_are_extracted_at_every_list_depth() {
        let summary = parse_safety_contract_doc_lines([
            "# Safety",
            "1. outer: outer condition",
            "   - nested: nested condition",
            "     + deep: deepest condition",
            "2. final: final condition",
        ]);

        assert_eq!(
            summary
                .requirements
                .iter()
                .map(|requirement| requirement.name.as_str())
                .collect::<Vec<_>>(),
            ["outer", "nested", "deep", "final"]
        );
    }

    #[test]
    fn indented_requirement_bullets_are_not_mistaken_for_unstructured_code() {
        let summary = parse_safety_contract_doc_lines([
            "# Safety",
            "    * req_1: first condition",
            "    * req_2: second condition",
        ]);

        assert!(summary.has_docs);
        assert_eq!(
            summary
                .requirements
                .iter()
                .map(|requirement| (requirement.name.as_str(), requirement.condition.as_str()))
                .collect::<Vec<_>>(),
            [("req_1", "first condition"), ("req_2", "second condition")]
        );
    }

    #[test]
    fn ordinary_indented_code_blocks_do_not_become_requirements() {
        let summary = parse_safety_contract_doc_lines([
            "# Safety",
            "    let label = \"req_1: not a requirement\";",
        ]);

        assert!(summary.has_docs);
        assert!(summary.requirements.is_empty());
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
