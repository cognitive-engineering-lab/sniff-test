//! The utilities needed to parse
//!

use std::{borrow::Borrow, collections::HashMap, sync::LazyLock};

use regex::Regex;
use rustc_middle::ty::TyCtxt;
use rustc_public::DefId;

#[cfg(test)]
mod test;

/// A condition that must hold such that a given function call exhibits a certain property.
///
/// For example,
#[derive(PartialEq, Eq, Debug)]
struct Requirement {
    name: String,
    description: String,
}

impl Requirement {
    pub fn new<T: Borrow<str>>(name: T, description: T) -> Self {
        Requirement {
            name: name.borrow().to_string(),
            description: description.borrow().to_string(),
        }
    }
}

/// A map of each function def to the requirements for the precoditions ([Requirements]),
/// on calls of that function.
struct AllRequirements(HashMap<DefId, Vec<Requirement>>);

struct Justification {
    requirement: Requirement,
    explanation: String,
}

struct CallSite();

#[derive(PartialEq, Eq, Debug)]
enum ParsingError {
    /// The `FnDef` in question doesn't have a `#[doc(..)]` attribute.
    NoDocString,
    /// No marker patterns were found.
    NoMarkerPattern,
    /// Multiple marker patters were found.
    MultipleMarkerPatterns,
    /// No colon delimiter was found after the condition name.
    ///
    /// This probably should just default in an empty description but, for now, is an error.
    NoColon,
    /// A marker was found, but it had no requirements.
    EmptyMarker,
    /// The name of a condition was multiple words.
    MultiWordConditionName,
    /// The bullet types found were non-matching.
    NonMatchingBullets,
}

/// For requirements, we can get them from the doc attr.
fn parse_requirements(tcx: TyCtxt<'_>, def_id: DefId) -> Result<Vec<Requirement>, ParsingError> {
    requirements_from_string(&get_doc_str(tcx, def_id).ok_or(ParsingError::NoDocString)?)
}

static UNSAFE_REQ_MARKER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("(\n|^)(\\s*)# (Unsafe|UNSAFE)(\n|$)").unwrap());

static SECTION_END_PAT: LazyLock<Regex> = LazyLock::new(|| Regex::new("\n(\\s*)#").unwrap());

enum BulletOption {
    Asterisk,
    Hypen,
}

impl BulletOption {
    pub fn regex_pattern(&self) -> Regex {
        let bullet_pat = match self {
            Self::Asterisk => "\\*",
            Self::Hypen => "-",
        };

        Regex::new(&format!("(\n|^)(\\s*){bullet_pat}")).unwrap()
    }

    fn choose(for_string: &str) -> Result<Self, ParsingError> {
        match (
            BulletOption::Asterisk.regex_pattern().find(for_string),
            BulletOption::Hypen.regex_pattern().find(for_string),
        ) {
            (Some(_a_pos), Some(_h_pos)) => Err(ParsingError::NonMatchingBullets),
            (Some(_a_pos), None) => Ok(BulletOption::Asterisk),
            (None, Some(_h_pos)) => Ok(BulletOption::Hypen),
            _ => Err(ParsingError::EmptyMarker),
        }
    }
}

fn requirements_from_string(doc_str: &str) -> Result<Vec<Requirement>, ParsingError> {
    // First, make sure we have the marker and trim everything before that.
    let doc_str = &doc_str[UNSAFE_REQ_MARKER
        .find(doc_str)
        .ok_or(ParsingError::NoMarkerPattern)?
        .end()..];

    // Return an error if there are any other markers after that.
    if UNSAFE_REQ_MARKER.find(doc_str).is_some() {
        return Err(ParsingError::MultipleMarkerPatterns);
    }

    // Trim everything after this section, if any
    let doc_str = &doc_str[..SECTION_END_PAT
        .find(doc_str)
        .map_or(doc_str.len(), |found| found.start())];

    // See which kind of bullets exists in this string, and get the regex for that
    let bullet_pat = BulletOption::choose(doc_str)?.regex_pattern();

    bullet_pat
        .split(doc_str)
        .skip(1)
        .map(parse_bullet)
        .collect::<Result<Vec<_>, ParsingError>>()
}

const NAME_SEP: &str = ":";

/// Takes in the string between two bullets (e.g. `" align: ptr should be aligned"`)
/// and tries to parse it into a [`Requirement`].
fn parse_bullet(bullet_str: &str) -> Result<Requirement, ParsingError> {
    let bullet_str = bullet_str.trim();
    println!("parsing bullet string {bullet_str:?}");

    let colon_loc = bullet_str.find(NAME_SEP).ok_or(ParsingError::NoColon)?;

    let name = validated_name(&bullet_str[..colon_loc])?;
    let description = bullet_str[(colon_loc + 1)..].trim().to_string();

    Ok(Requirement::new(name, description))
}

fn validated_name(name: &str) -> Result<String, ParsingError> {
    // Valid requirement names shouldn't contain whitespace.
    if name.contains([' ', '\n', '\t']) {
        return Err(ParsingError::MultiWordConditionName);
    }

    Ok(name.to_string())
}

/// Gets the doc string, if one exists, for a given [`DefId`].
fn get_doc_str(tcx: TyCtxt<'_>, def_id: DefId) -> Option<String> {
    tcx.get_attr(
        rustc_public::rustc_internal::internal(tcx, def_id),
        rustc_span::symbol::Symbol::intern("doc"),
    )
    .map(|attr| {
        attr.doc_str()
            .expect("FIXME: honestly don't know when this can fail")
            .to_string()
    })
}
