//! Shared parsing for API contract documentation.
//!
//! Panic and safety analysis both read rustdoc sections with named requirement
//! bullets. Keep the markdown-ish parsing here so the two policies do not drift.

use rustc_hir::attrs::{AttributeKind, HasAttrs};
use rustc_hir::{Attribute, def_id::DefId};
use rustc_middle::ty::TyCtxt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ContractKind {
    Panic,
    Safety,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContractRequirement {
    pub(crate) name: String,
    pub(crate) condition: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ContractDocSummary {
    pub(crate) has_docs: bool,
    pub(crate) requirements: Vec<ContractRequirement>,
}

// One rustc session per process and single-threaded analysis, so DefId-keyed
// caching is sound. Doc attributes are re-read and re-parsed for every edge
// classification without this.
thread_local! {
    static SUMMARY_CACHE: std::cell::RefCell<
        std::collections::HashMap<(DefId, ContractKind), ContractDocSummary>,
    > = std::cell::RefCell::new(std::collections::HashMap::new());
}

#[must_use]
pub(crate) fn contract_doc_summary(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    kind: ContractKind,
) -> ContractDocSummary {
    SUMMARY_CACHE.with_borrow_mut(|cache| {
        cache
            .entry((def_id, kind))
            .or_insert_with(|| {
                parse_contract_doc_lines(
                    HasAttrs::get_attrs(def_id, &tcx)
                        .iter()
                        .filter_map(doc_comment)
                        .flat_map(str::lines),
                    kind,
                )
            })
            .clone()
    })
}

#[must_use]
pub(crate) fn parse_contract_doc_lines<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    kind: ContractKind,
) -> ContractDocSummary {
    let mut summary = ContractDocSummary::default();
    let mut in_contract_section = false;
    let mut fence: Option<&str> = None;

    for line in lines {
        // Lines inside fenced code blocks are example text, not structure: a
        // literal `# Panics` there is not a contract heading, and hidden
        // doctest lines like `# use foo;` must not close a real section.
        if let Some(marker) = code_fence_marker(line) {
            match fence {
                Some(open) if marker.starts_with(open) => fence = None,
                Some(_) => {}
                None => fence = Some(marker),
            }
            continue;
        }
        if fence.is_some() {
            continue;
        }

        if let Some(heading) = markdown_heading_text(line) {
            in_contract_section = kind.matches_heading(heading);
            summary.has_docs |= in_contract_section;
            continue;
        }

        if in_contract_section && let Some(requirement) = parse_requirement_bullet(line) {
            summary.requirements.push(requirement);
        }
    }

    summary
}

/// The backtick or tilde run opening or closing a fenced code block, ignoring
/// any info string. Closing fences must be at least as long as the opener,
/// which `starts_with` on the returned marker checks.
fn code_fence_marker(line: &str) -> Option<&str> {
    let line = line.trim_start();
    let len = if line.starts_with("```") {
        line.len() - line.trim_start_matches('`').len()
    } else if line.starts_with("~~~") {
        line.len() - line.trim_start_matches('~').len()
    } else {
        return None;
    };
    Some(&line[..len])
}

#[cfg(test)]
#[must_use]
pub(crate) fn line_has_contract_heading(line: &str, kind: ContractKind) -> bool {
    markdown_heading_text(line).is_some_and(|heading| kind.matches_heading(heading))
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

fn doc_comment(attr: &Attribute) -> Option<&str> {
    match attr {
        Attribute::Parsed(AttributeKind::DocComment { comment, .. }) => Some(comment.as_str()),
        Attribute::Parsed(_) | Attribute::Unparsed(_) => None,
    }
}

fn parse_requirement_bullet(line: &str) -> Option<ContractRequirement> {
    let line = line.trim_start();
    let body = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("* "))
        .or_else(|| line.strip_prefix("+ "))?;
    let (name, condition) = body.split_once(':')?;
    let name = name.trim();
    let condition = condition.trim();

    (!normalize_requirement_name(name).is_empty()).then(|| ContractRequirement {
        name: name.to_owned(),
        condition: condition.to_owned(),
    })
}

fn markdown_heading_text(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix('#')?;
    let rest = rest.trim_start_matches('#');
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }

    let heading = rest.trim();
    Some(heading.trim_end_matches([':', '-']).trim())
}

impl ContractKind {
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
    use super::{ContractKind, parse_contract_doc_lines};

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
            ContractKind::Panic,
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
            ContractKind::Safety,
        );

        assert!(summary.has_docs);
        assert_eq!(summary.requirements.len(), 1);
        assert_eq!(summary.requirements[0].name, "valid_ptr");
    }

    #[test]
    fn tilde_fences_and_longer_closers_are_respected() {
        let summary = parse_contract_doc_lines(
            ["~~~", "# Panics", "~~~", "# Panics", "- flag: must be set"],
            ContractKind::Panic,
        );

        assert!(summary.has_docs);
        assert_eq!(summary.requirements.len(), 1);

        let nested = parse_contract_doc_lines(
            ["````", "```", "# Panics", "```", "````", "# Safety"],
            ContractKind::Panic,
        );
        assert!(!nested.has_docs);
    }
}
