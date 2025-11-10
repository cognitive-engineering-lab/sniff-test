use std::collections::HashMap;

use rustc_span::{
    DUMMY_SP,
    source_map::{Spanned, respan},
};

use crate::annotations::{ParsingIssue, Requirement, parsing::ParseBulletsFromString};

/// Struct encapsulating annotations parsed from a TOML file.
#[derive(Default)]
pub struct TomlAnnotation {
    function_to_requirements: HashMap<String, Vec<Spanned<Requirement>>>,
}

// Errors that can occur when parsing TOML annotations.
#[derive(Debug)]
pub enum TomlParseError {
    Io(std::io::Error),
    Toml(toml::de::Error),
    Schema(String),
    Parse(ParsingIssue),
}

impl From<std::io::Error> for TomlParseError {
    fn from(err: std::io::Error) -> Self {
        TomlParseError::Io(err)
    }
}

impl From<toml::de::Error> for TomlParseError {
    fn from(err: toml::de::Error) -> Self {
        TomlParseError::Toml(err)
    }
}

impl From<ParsingIssue> for TomlParseError {
    fn from(err: ParsingIssue) -> Self {
        TomlParseError::Parse(err)
    }
}

impl TomlAnnotation {
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, TomlParseError> {
        // Get the contents of the TOML file
        let text = std::fs::read_to_string(path)?;
        let value: toml::Value = toml::from_str(&text)?;

        // Parse the TOML file into a map from function names to requirement strings
        // The expected schema is:
        // [function_name]
        // requirements = """
        // - Requirement 1
        // - Requirement 2
        // """
        let Some(table) = value.as_table() else {
            return Err(TomlParseError::Schema(
                "Expected a TOML table at the top level".to_string(),
            ));
        };
        let mut function_to_requirements: HashMap<String, Vec<Spanned<Requirement>>> =
            HashMap::new();

        for (function_name, value) in table {
            let Some(inner_table) = value.as_table() else {
                return Err(TomlParseError::Schema(format!(
                    "Expected a TOML table for function {function_name}"
                )));
            };

            if inner_table.len() != 1 || !inner_table.contains_key("requirements") {
                return Err(TomlParseError::Schema(format!(
                    "Expected a single 'requirements' entry for function {function_name}"
                )));
            }

            let Some(requirements_string) = inner_table["requirements"].as_str() else {
                return Err(TomlParseError::Schema(format!(
                    "Expected a 'requirements' string for function {function_name}"
                )));
            };

            match Requirement::parse_bullets_from_string(requirements_string) {
                Ok(requirements) => {
                    let spanned_requirements: Vec<Spanned<Requirement>> = requirements
                        .into_iter()
                        .map(|(req, _range)| respan(DUMMY_SP, req))
                        .collect();
                    function_to_requirements.insert(function_name.clone(), spanned_requirements);
                }
                Err(parse_error) => {
                    return Err(TomlParseError::Parse(parse_error));
                }
            }
        }

        // Return the parsed annotations
        Ok(TomlAnnotation {
            function_to_requirements,
        })
    }

    pub fn get_requirements_for_function(
        &self,
        function_name: &str,
    ) -> Option<&Vec<Spanned<Requirement>>> {
        self.function_to_requirements.get(function_name)
    }
}
