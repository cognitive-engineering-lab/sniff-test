//! Shared parsing for API contract documentation.
//!
//! Panic and safety analysis both read rustdoc sections with named requirement
//! bullets. Keep the markdown-ish parsing here so the two policies do not drift.

use rustc_hir::attrs::{AttributeKind, HasAttrs};
use rustc_hir::{Attribute, def_id::DefId};
use rustc_middle::ty::TyCtxt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContractKind {
    Panic,
    Safety,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContractRequirement {
    pub(crate) name: String,
    pub(crate) condition: String,
}

#[derive(Debug, Default)]
pub(crate) struct ContractDocSummary {
    pub(crate) has_docs: bool,
    pub(crate) requirements: Vec<ContractRequirement>,
}

#[must_use]
pub(crate) fn contract_doc_summary(
    tcx: TyCtxt<'_>,
    def_id: DefId,
    kind: ContractKind,
) -> ContractDocSummary {
    parse_contract_doc_lines(
        HasAttrs::get_attrs(def_id, &tcx)
            .iter()
            .filter_map(doc_comment)
            .flat_map(str::lines),
        kind,
    )
}

#[must_use]
pub(crate) fn parse_contract_doc_lines<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    kind: ContractKind,
) -> ContractDocSummary {
    let mut summary = ContractDocSummary::default();
    let mut in_contract_section = false;

    for line in lines {
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

#[cfg(test)]
#[must_use]
pub(crate) fn line_has_contract_heading(line: &str, kind: ContractKind) -> bool {
    markdown_heading_text(line).is_some_and(|heading| kind.matches_heading(heading))
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
