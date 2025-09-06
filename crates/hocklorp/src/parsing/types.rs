use std::borrow::Borrow;

use crate::parsing::err::ParsingIssue;

#[derive(PartialEq, Eq, Debug)]
/// A condition that must hold such that a given function call exhibits a certain property.
pub struct Requirement {
    name: String,
    description: String,
}

impl Requirement {
    pub fn try_new(
        name: impl Borrow<str>,
        description: impl Borrow<str>,
    ) -> Result<Self, ParsingIssue> {
        Ok(Requirement {
            name: Self::validate_name(name.borrow())?,
            description: description.borrow().to_owned(),
        })
    }

    fn validate_name(name: &str) -> Result<String, ParsingIssue> {
        let invalid_whitespace = [' ', '\n', '\t'];
        // Valid requirement names shouldn't contain whitespace.
        if name.contains(invalid_whitespace) {
            if name
                .split(invalid_whitespace)
                .filter(|word| !word.is_empty())
                .count()
                == 1
            {
                // no other words, just invalid whitespace
                return Err(ParsingIssue::SpaceAfterColon);
            }
            return Err(ParsingIssue::MultiWordConditionName);
        }

        Ok(name.to_string())
    }
}
