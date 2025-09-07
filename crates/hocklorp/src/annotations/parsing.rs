//! Utilities for parsing [Requirement] values from doc strings.

use super::err::ParsingIssue;
use crate::annotations::{Justification, Requirement};
use regex::Regex;

/// A trait for parsing structured data from bulleted lists in doc strings.
pub trait ParseBulletsFromString: Sized {
    /// The delimiter used to separate out two portions of each bullet.
    /// See [`parse_bullet`](ParseBulletsFromString::parse_bullet) for how it can be used.
    const BULLET_SEP: &str = ":";

    /// The regex to recognize the start of a section of bullets for this type.
    fn section_marker_regex() -> Regex;

    /// The regex to recognize the end of a section of bullets.
    fn section_end_regex() -> Regex {
        Regex::new("\n(\\s*)([#]+|\n)").unwrap()
    }

    /// Takes in the string between two bullets (e.g. `" align: ptr should be aligned"`)
    /// and tries to parse it into a [`Self`].
    fn parse_bullet(bullet_pre_sep: &str, bullet_post_sep: &str) -> Result<Self, ParsingIssue>;

    fn parse_bullets_from_string(comment_str: &str) -> Result<Vec<Self>, ParsingIssue> {
        // First, make sure we have the marker and trim everything before that.
        let comment_str = &comment_str[Self::section_marker_regex()
            .find(comment_str)
            .ok_or(ParsingIssue::NoMarkerPattern)?
            .end()..];

        // Return an error if there are any other markers after that.
        if Self::section_marker_regex().find(comment_str).is_some() {
            return Err(ParsingIssue::MultipleMarkerPatterns);
        }

        // Trim everything after this section, if any.
        let comment_str = &comment_str[..Self::section_end_regex()
            .find(comment_str)
            .map_or(comment_str.len(), |found| found.start())];

        // See which kind of bullets exists in this string, and get the regex for that.
        let bullet_pat = bullet::BulletKind::choose(comment_str)?.regex_pattern();

        bullet_pat
            .split(comment_str)
            .skip(1)
            .map(|bullet_str| {
                let (pre, post) = bullet_str
                    .trim()
                    .split_once(Self::BULLET_SEP)
                    .ok_or(ParsingIssue::NoColon)?;
                Self::parse_bullet(pre, post)
            })
            .collect::<Result<Vec<_>, ParsingIssue>>()
    }
}

impl ParseBulletsFromString for Requirement {
    /// Regex to match on an "Unsafe" header ignoring the text's case,
    /// leading whitespace and the header level, but ensuring it is the only text on that line.
    fn section_marker_regex() -> Regex {
        Regex::new("(\n|^)(\\s*)[#]+ (Unsafe|UNSAFE)(\n|$)").unwrap()
    }

    fn parse_bullet(bullet_pre_sep: &str, bullet_post_sep: &str) -> Result<Self, ParsingIssue> {
        Requirement::try_new(bullet_pre_sep, bullet_post_sep.trim())
    }
}

impl ParseBulletsFromString for Justification {
    /// Regex to match on the "Safety:" part of a comment, ignoring case and whitespace,
    /// but ensuring it is the only text on that line.
    fn section_marker_regex() -> Regex {
        Regex::new("(\n|^)(\\s*)(Safety|SAFETY):(\n|$)").unwrap()
    }

    fn parse_bullet(bullet_pre_sep: &str, bullet_post_sep: &str) -> Result<Self, ParsingIssue> {
        Justification::try_new(bullet_pre_sep, bullet_post_sep.trim())
    }
}

/// Helper utilities for properly recognizing different kinds of bulleted lists.
mod bullet {
    use crate::annotations::err::ParsingIssue;
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

        /// Construct the regex pattern for recognizing a given kind of bullet.
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
mod test {
    /// General utility macro for testing that parsing a certain `$type` from a certain `$str`
    /// results in the expected result.
    macro_rules! test_string_parse {
        (($type: ty) $test_name: tt: $str: expr => ok $expected_requirements: expr) => {
            #[test]
            fn $test_name() {
                let doc_str = $str;
                let requirements = <$type>::parse_bullets_from_string(doc_str);
                assert_eq!(requirements, Ok($expected_requirements));
            }
        };
        (($type: ty) $test_name: tt: $str: expr => err $expected_err: ident) => {
            #[test]
            fn $test_name() {
                let doc_str = $str;
                let requirements = <$type>::parse_bullets_from_string(doc_str);
                std::assert_matches::assert_matches!(
                    requirements,
                    Err(crate::annotations::ParsingIssue::$expected_err)
                );
            }
        };
        (($type: ty) $test_name: tt: $str: expr => err $expected_err: ident ($err_pat: pat)) => {
            #[test]
            fn $test_name() {
                let doc_str = $str;
                let requirements = <$type>::parse_bullets_from_string(doc_str);
                std::assert_matches::assert_matches!(
                    requirements,
                    Err(crate::annotations::ParsingIssue::$expected_err($err_pat))
                );
            }
        };
    }

    /// General utility macro for making a vector of types that can be
    /// constructed with a `try_new` method.
    macro_rules! try_new {
        ($type: ident, $($name: expr => $desc: expr)*) => {
            vec![$(crate::annotations::$type::try_new($name, $desc).unwrap(),)*]
        };
    }

    #[rustfmt::skip] // Skip formatting because it looks weird for the testing macros.
    mod requirements {
        use crate::annotations::{parsing::ParseBulletsFromString, Requirement};
        use crate::annotations::types::InvalidConditionNameReason::*;

        macro_rules! test_req_parse {
            ($test_name: tt: $str: expr => ok $expected_requirements: expr) => {
                test_string_parse!((Requirement) $test_name: $str => ok $expected_requirements);
            };
            ($test_name: tt: $str: expr => err $expected_err: ident) => {
                test_string_parse!((Requirement) $test_name: $str => err $expected_err);
            };
            ($test_name: tt: $str: expr => err $expected_err: ident ($expr: pat)) => {
                test_string_parse!((Requirement) $test_name: $str => err $expected_err($expr));
            };
        }

        /// Helper for easily creating vectors of [`Requirement`]s.
        macro_rules! reqs {
            ($($name: expr => $desc: expr)*) => {
                try_new!(Requirement, $($name => $desc)*)
            };
        }

        test_req_parse!(simple_no_requirements:
                r#"# Unsafe"#
            => err EmptyMarker);

        test_req_parse!(simple_no_marker:
                r#"This is a random doc comment"#
            => err NoMarkerPattern);

        test_req_parse!(multi_line_no_marker:
                r#"This is a random doc comment.
                It is multiple lines, but it still has no marker
                unfortunately..."#
            => err NoMarkerPattern);

        test_req_parse!(incorrect_markers:
                r#"# Hi!
                # Hello!
                # Usage
                # Overview"#
            => err NoMarkerPattern);

        test_req_parse!(incorrect_marker_w_desc:
                r#"# Usage
                    - nn: the pointer must be non-null
                    - align: the pointer must be aligned"#
            => err NoMarkerPattern);

        test_req_parse!(simplest_use:
                r#"# Unsafe
                    - nn: the pointer must be non-null"#
            => ok reqs!(
                    "nn" => "the pointer must be non-null"
                ));

        test_req_parse!(simple_use_many_requirements:
                r#"# Unsafe
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned
                        - heap-allocated: the pointer must be heap-allocated"#
            => ok reqs!(
                    "nn" => "the pointer must be non-null"
                    "align" => "the pointer must be aligned"
                    "heap-allocated" => "the pointer must be heap-allocated"
                ));

        test_req_parse!(ignores_text_before:
                r#"filler text, blah blah blah...
                    # Unsafe
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned"#
            => ok reqs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));

        test_req_parse!(intro_prose_allowed:
                r#"# Unsafe
                    This function must satisfy the following invariants
                    to avoid UB:
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned"#
            => ok reqs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));

        test_req_parse!(ignores_other_markers_before:
                r#"# Usage
                    - Use this struct however you'd like, I don't mind.
                    # Unsafe
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned"#
            => ok reqs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));

        test_req_parse!(ignores_other_markers_after:
                r#"# Unsafe
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned
                    # Usage
                        - Use this struct however you'd like, I don't mind."#
            => ok reqs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));

        test_req_parse!(ignores_sandwiched_other_markers:
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

        test_req_parse!(section_ends_with_empty_line:
                r#"# Unsafe
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned

                        - Use this struct however you'd like, I don't mind."#
            => ok reqs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));

        test_req_parse!(section_ends_with_whitespace_only_line:
                r#"# Unsafe
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned
                        
                        - Use this struct however you'd like, I don't mind."#
            => ok reqs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));

        test_req_parse!(markers_arent_case_sensitive:
                r#"# UNSAFE
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned"#
            => ok reqs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));
        test_req_parse!(markers_allow_any_markdown_header:
                r#"### UNSAFE
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned"#
            => ok reqs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));

        test_req_parse!(asterisk_bullets_allowed:
                r#"# Unsafe
                        * nn: the pointer must be non-null
                        * align: the pointer must be aligned"#
            => ok reqs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));

        test_req_parse!(bullet_types_must_match:
                r#"# Unsafe
                        * nn: the pointer must be non-null
                        - align: the pointer must be aligned"#
            => err NonMatchingBullets);

        test_req_parse!(spaces_after_bullet_ignored:
                r#"# Unsafe
                        -  nn: the pointer must be non-null
                        -   align: the pointer must be aligned"#
            => ok reqs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));

        test_req_parse!(spaces_before_colon_disallowed:
                r#"# Unsafe
                        - nn : the pointer must be non-null
                        - align     : the pointer must be aligned"#
            => err InvalidConditionName(TrailingWhitespace));

        test_req_parse!(multi_word_names_disallowed:
                r#"# Unsafe
                        - non null: the pointer must be non-null
                        - aligned ptr: the pointer must be aligned"#
            => err InvalidConditionName(MultipleWords));

        test_req_parse!(kebab_case_names_allowed:
                r#"# Unsafe
                        - non-null: the pointer must be non-null
                        - aligned-ptr: the pointer must be aligned"#
            => ok reqs!(
                    "non-null" => "the pointer must be non-null"
                    "aligned-ptr"=> "the pointer must be aligned"
                ));

        test_req_parse!(snake_case_names_allowed:
                r#"# Unsafe
                        - non_null: the pointer must be non-null
                        - aligned_ptr: the pointer must be aligned"#
            => ok reqs!(
                    "non_null" => "the pointer must be non-null"
                    "aligned_ptr"=> "the pointer must be aligned"
                ));
    }

    #[rustfmt::skip] // Skip formatting because it looks weird for the testing macros.
    mod justifications {
        use crate::annotations::{parsing::ParseBulletsFromString, Justification};
        use crate::annotations::types::InvalidConditionNameReason::*;

        macro_rules! test_just_parse {
            ($test_name: tt: $str: expr => ok $expected_requirements: expr) => {
                test_string_parse!((Justification) $test_name: $str => ok $expected_requirements);
            };
            ($test_name: tt: $str: expr => err $expected_err: ident) => {
                test_string_parse!((Justification) $test_name: $str => err $expected_err);
            };
            ($test_name: tt: $str: expr => err $expected_err: ident ($expr: pat)) => {
                test_string_parse!((Justification) $test_name: $str => err $expected_err($expr));
            };
        }

        /// Helper for easily creating vectors of [`Justification`]s.
        macro_rules! justs {
            ($($name: expr => $desc: expr)*) => {
                try_new!(Justification, $($name => $desc)*)
            };
        }

        test_just_parse!(simple_no_requirements:
                r#"SAFETY:"#
            => err EmptyMarker);
            
        test_just_parse!(simple_no_marker:
                r#"This is a random doc comment"#
            => err NoMarkerPattern);
            
        test_just_parse!(multi_line_no_marker:
                r#"This is a random doc comment.
                It is multiple lines, but it still has no marker
                unfortunately..."#
            => err NoMarkerPattern);
            
        test_just_parse!(incorrect_markers:
                r#"# Hi!
                Unsafety:
                # Usage
                Usage:"#
            => err NoMarkerPattern);
            
        test_just_parse!(incorrect_marker_w_desc:
                r#"Usage:
                    - nn: the pointer must be non-null
                    - align: the pointer must be aligned"#
            => err NoMarkerPattern);
            
        test_just_parse!(simplest_use:
                r#"SAFETY:
                    - nn: the pointer must be non-null"#
            => ok justs!(
                    "nn" => "the pointer must be non-null"
                ));
            
        test_just_parse!(simple_use_many_requirements:
                r#"SAFETY:
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned
                        - heap-allocated: the pointer must be heap-allocated"#
            => ok justs!(
                    "nn" => "the pointer must be non-null"
                    "align" => "the pointer must be aligned"
                    "heap-allocated" => "the pointer must be heap-allocated"
                ));
            
        test_just_parse!(ignores_text_before:
                r#"filler text, blah blah blah...
                    SAFETY:
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned"#
            => ok justs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));

        test_just_parse!(intro_prose_allowed:
                r#"SAFETY:
                    This function call will avoid UB because we have satisfied
                    the following conditions:
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned"#
            => ok justs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));
            
        test_just_parse!(ignores_other_markers_before:
                r#"Usage:
                    - Use this struct however you'd like, I don't mind.
                    
                    Safety:
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned"#
            => ok justs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));
            
        test_just_parse!(ignores_other_markers_after:
                r#"SAFETY:
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned

                    USAGE:
                        - Use this struct however you'd like, I don't mind."#
            => ok justs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));
            
        test_just_parse!(ignores_sandwiched_other_markers:
                r#"Overview:
                        - this is a function of some kind

                    SAFETY:
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned

                    Usage
                        - Use this struct however you'd like, I don't mind."#
            => ok justs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));
            
        test_just_parse!(section_ends_with_empty_line:
                r#"SAFETY:
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned
            
                        - Use this struct however you'd like, I don't mind."#
            => ok justs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));
            
        test_just_parse!(section_ends_with_whitespace_only_line:
                r#"SAFETY:
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned
                        
                        - Use this struct however you'd like, I don't mind."#
            => ok justs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));
            
        test_just_parse!(markers_arent_case_sensitive:
                r#"Safety:
                        - nn: the pointer must be non-null
                        - align: the pointer must be aligned"#
            => ok justs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));
            
        test_just_parse!(asterisk_bullets_allowed:
                r#"Safety:
                        * nn: the pointer must be non-null
                        * align: the pointer must be aligned"#
            => ok justs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));
            
        test_just_parse!(bullet_types_must_match:
                r#"Safety:
                        * nn: the pointer must be non-null
                        - align: the pointer must be aligned"#
            => err NonMatchingBullets);
            
        test_just_parse!(spaces_after_bullet_ignored:
                r#"Safety:
                        -  nn: the pointer must be non-null
                        -   align: the pointer must be aligned"#
            => ok justs!(
                    "nn" => "the pointer must be non-null"
                    "align"=> "the pointer must be aligned"
                ));
            
        test_just_parse!(spaces_before_colon_disallowed:
                r#"Safety:
                        - nn : the pointer must be non-null
                        - align     : the pointer must be aligned"#
            => err InvalidConditionName(TrailingWhitespace));

        test_just_parse!(multi_word_names_disallowed:
                r#"Safety:
                        - non null: the pointer must be non-null
                        - aligned ptr: the pointer must be aligned"#
            => err InvalidConditionName(MultipleWords));

        test_just_parse!(kebab_case_names_allowed:
                r#"Safety:
                        - non-null: the pointer must be non-null
                        - aligned-ptr: the pointer must be aligned"#
            => ok justs!(
                    "non-null" => "the pointer must be non-null"
                    "aligned-ptr"=> "the pointer must be aligned"
                ));

        test_just_parse!(snake_case_names_allowed:
                r#"Safety:
                        - non_null: the pointer must be non-null
                        - aligned_ptr: the pointer must be aligned"#
            => ok justs!(
                    "non_null" => "the pointer must be non-null"
                    "aligned_ptr"=> "the pointer must be aligned"
                ));
    }
}
