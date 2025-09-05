use crate::parsing::{ParsingError, Requirement};

const STRING_PARSING_FUNCTION: fn(&str) -> Result<Vec<Requirement>, ParsingError> =
    crate::parsing::requirements_from_string;

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
                Err(crate::parsing::ParsingError::$expected_err)
            );
        }
    };
}

/// Sugar around constructing a `Vec<Requirement>`.
macro_rules! reqs {
        ($($name: expr => $desc: expr)*) => {
            vec![$(crate::parsing::Requirement::new($name, $desc),)*]
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

test_string_parse!(markers_arent_case_sensitive:
r#"# UNSAFE
                - nn: the pointer must be non-null
                - align: the pointer must be aligned"#
=> ok reqs!(
        "nn" => "the pointer must be non-null"
        "align"=> "the pointer must be aligned"
    ));

test_string_parse!(other_bullet_types_allowed:
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
