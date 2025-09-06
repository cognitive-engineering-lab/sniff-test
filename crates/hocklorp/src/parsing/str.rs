//! Utilities for parsing [Requirement] values from doc strings.

use super::err::ParsingIssue;
use crate::parsing::Requirement;
use regex::Regex;
use std::sync::LazyLock;

static UNSAFE_REQ_MARKER_PAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("(\n|^)(\\s*)# (Unsafe|UNSAFE)(\n|$)").unwrap());

static SECTION_END_PAT: LazyLock<Regex> = LazyLock::new(|| Regex::new("\n(\\s*)(#|\n)").unwrap());

const NAME_SEP: &str = ":";

pub fn requirements_from_string(doc_str: &str) -> Result<Vec<Requirement>, ParsingIssue> {
    // First, make sure we have the marker and trim everything before that.
    let doc_str = &doc_str[UNSAFE_REQ_MARKER_PAT
        .find(doc_str)
        .ok_or(ParsingIssue::NoMarkerPattern)?
        .end()..];

    // Return an error if there are any other markers after that.
    if UNSAFE_REQ_MARKER_PAT.find(doc_str).is_some() {
        return Err(ParsingIssue::MultipleMarkerPatterns);
    }

    // Trim everything after this section, if any
    let doc_str = &doc_str[..SECTION_END_PAT
        .find(doc_str)
        .map_or(doc_str.len(), |found| found.start())];

    // See which kind of bullets exists in this string, and get the regex for that
    let bullet_pat = bullet::BulletKind::choose(doc_str)?.regex_pattern();

    bullet_pat
        .split(doc_str)
        .skip(1)
        .map(parse_bullet)
        .collect::<Result<Vec<_>, ParsingIssue>>()
}

/// Takes in the string between two bullets (e.g. `" align: ptr should be aligned"`)
/// and tries to parse it into a [`Requirement`].
fn parse_bullet(bullet_str: &str) -> Result<Requirement, ParsingIssue> {
    let bullet_str = bullet_str.trim();
    println!("parsing bullet string {bullet_str:?}");

    let colon_loc = bullet_str.find(NAME_SEP).ok_or(ParsingIssue::NoColon)?;

    let (name, description) = (
        &bullet_str[..colon_loc],
        bullet_str[(colon_loc + 1)..].trim(),
    );

    Requirement::try_new(name, description)
}

/// Helper utilities for properly recognizing bulleted lists.
mod bullet {
    use crate::parsing::err::ParsingIssue;
    use regex::Regex;

    pub enum BulletKind {
        Asterisk,
        Hypen,
    }

    impl BulletKind {
        /// Try to determine which bullet type is being used for a given string.
        pub fn choose(for_string: &str) -> Result<Self, ParsingIssue> {
            match (
                BulletKind::Asterisk.regex_pattern().find(for_string),
                BulletKind::Hypen.regex_pattern().find(for_string),
            ) {
                (Some(_a_pos), Some(_h_pos)) => Err(ParsingIssue::NonMatchingBullets),
                (Some(_a_pos), None) => Ok(BulletKind::Asterisk),
                (None, Some(_h_pos)) => Ok(BulletKind::Hypen),
                _ => Err(ParsingIssue::EmptyMarker),
            }
        }

        /// Get the regex pattern for a given kind of bullet.
        pub fn regex_pattern(&self) -> Regex {
            let bullet_pat = match self {
                Self::Asterisk => "\\*",
                Self::Hypen => "-",
            };

            Regex::new(&format!("(\n|^)(\\s*){bullet_pat}")).unwrap()
        }
    }
}

#[cfg(test)]
#[rustfmt::skip] // Skip formatting because it looks weird for the testing macros.
mod test {
    use crate::parsing::{ParsingIssue, Requirement};

    /// The string parsing function to test.
    const STRING_PARSING_FUNCTION: fn(&str) -> Result<Vec<Requirement>, ParsingIssue> =
        super::requirements_from_string;

    /// Construct a test function to check that parsing a certain string with
    /// [STRING_PARSING_FUNCTION] results in the expected error or requirements.
    macro_rules! test_string_parse {
        ($test_name: tt: $str: expr => ok $expected_requirements: expr) => {
            #[test]
            fn $test_name() {
                let doc_str = $str;
                let requirements = STRING_PARSING_FUNCTION(doc_str);
                assert_eq!(requirements, Ok($expected_requirements));
            }
        };
        ($test_name: tt: $str: expr => err $expected_err: ident) => {
            #[test]
            fn $test_name() {
                let doc_str = $str;
                let requirements = STRING_PARSING_FUNCTION(doc_str);
                std::assert_matches::assert_matches!(
                    requirements,
                    Err(crate::parsing::ParsingIssue::$expected_err)
                );
            }
        };
    }

    /// Sugar around constructing a `Vec<Requirement>`.
    macro_rules! reqs {
        ($($name: expr => $desc: expr)*) => {
            vec![$(crate::parsing::Requirement::try_new($name, $desc).unwrap(),)*]
        };
    }

    test_string_parse!(simple_no_requirements:
            r#"# Unsafe"#
        => err EmptyMarker);

    test_string_parse!(simple_no_marker:
            r#"This is a random doc comment"#
        => err NoMarkerPattern);

    test_string_parse!(multi_line_no_marker:
            r#"This is a random doc comment.
            It is multiple lines, but it still has no marker
            unfortunately..."#
        => err NoMarkerPattern);

    test_string_parse!(incorrect_markers:
            r#"# Hi!
            # Hello!
            # Usage
            # Overview"#
        => err NoMarkerPattern);

    test_string_parse!(incorrect_marker_w_desc:
            r#"# Usage
                - nn: the pointer must be non-null
                - align: the pointer must be aligned"#
        => err NoMarkerPattern);

    test_string_parse!(simplest_use:
            r#"# Unsafe
                - nn: the pointer must be non-null"#
        => ok reqs!(
                "nn" => "the pointer must be non-null"
            ));

    test_string_parse!(simple_use_many_requirements:
            r#"# Unsafe
                    - nn: the pointer must be non-null
                    - align: the pointer must be aligned
                    - heap-allocated: the pointer must be heap-allocated"#
        => ok reqs!(
                "nn" => "the pointer must be non-null"
                "align" => "the pointer must be aligned"
                "heap-allocated" => "the pointer must be heap-allocated"
            ));

    test_string_parse!(ignores_text_before:
            r#"filler text, blah blah blah...
                # Unsafe
                    - nn: the pointer must be non-null
                    - align: the pointer must be aligned"#
        => ok reqs!(
                "nn" => "the pointer must be non-null"
                "align"=> "the pointer must be aligned"
            ));

    test_string_parse!(ignores_other_markers_before:
            r#"# Usage
                - Use this struct however you'd like, I don't mind.
                # Unsafe
                    - nn: the pointer must be non-null
                    - align: the pointer must be aligned"#
        => ok reqs!(
                "nn" => "the pointer must be non-null"
                "align"=> "the pointer must be aligned"
            ));

    test_string_parse!(ignores_other_markers_after:
            r#"# Unsafe
                    - nn: the pointer must be non-null
                    - align: the pointer must be aligned
                # Usage
                    - Use this struct however you'd like, I don't mind."#
        => ok reqs!(
                "nn" => "the pointer must be non-null"
                "align"=> "the pointer must be aligned"
            ));

    test_string_parse!(ignores_sandwiched_other_markers:
            r#"# Overview
                    - this is a function of some kind
                # Unsafe
                    - nn: the pointer must be non-null
                    - align: the pointer must be aligned
                # Usage
                    - Use this struct however you'd like, I don't mind."#
        => ok reqs!(
                "nn" => "the pointer must be non-null"
                "align"=> "the pointer must be aligned"
            ));

    test_string_parse!(section_ends_with_empty_line:
            r#"# Unsafe
                    - nn: the pointer must be non-null
                    - align: the pointer must be aligned

                    - Use this struct however you'd like, I don't mind."#
        => ok reqs!(
                "nn" => "the pointer must be non-null"
                "align"=> "the pointer must be aligned"
            ));

    test_string_parse!(section_ends_with_whitespace_only_line:
            r#"# Unsafe
                    - nn: the pointer must be non-null
                    - align: the pointer must be aligned
                    
                    - Use this struct however you'd like, I don't mind."#
        => ok reqs!(
                "nn" => "the pointer must be non-null"
                "align"=> "the pointer must be aligned"
            ));

    test_string_parse!(markers_arent_case_sensitive:
            r#"# UNSAFE
                    - nn: the pointer must be non-null
                    - align: the pointer must be aligned"#
        => ok reqs!(
                "nn" => "the pointer must be non-null"
                "align"=> "the pointer must be aligned"
            ));

    test_string_parse!(asterisk_bullets_allowed:
            r#"# Unsafe
                    * nn: the pointer must be non-null
                    * align: the pointer must be aligned"#
        => ok reqs!(
                "nn" => "the pointer must be non-null"
                "align"=> "the pointer must be aligned"
            ));

    test_string_parse!(bullet_types_must_match:
            r#"# Unsafe
                    * nn: the pointer must be non-null
                    - align: the pointer must be aligned"#
        => err NonMatchingBullets);

    test_string_parse!(spaces_after_bullet_ignored:
            r#"# Unsafe
                    -  nn: the pointer must be non-null
                    -   align: the pointer must be aligned"#
        => ok reqs!(
                "nn" => "the pointer must be non-null"
                "align"=> "the pointer must be aligned"
            ));

    test_string_parse!(spaces_before_colon_disallowed:
            r#"# Unsafe
                    - nn : the pointer must be non-null
                    - align     : the pointer must be aligned"#
        => err SpaceAfterColon);
}
