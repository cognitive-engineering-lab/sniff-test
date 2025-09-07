use std::borrow::Borrow;

use crate::annotations::err::ParsingIssue;

#[derive(PartialEq, Eq, Debug)]
/// A condition that must hold such that a given function call will not cause UB.
pub struct Requirement {
    name: ConditionName,
    description: String,
}

impl Requirement {
    pub fn try_new(
        name: impl Borrow<str>,
        description: impl Borrow<str>,
    ) -> Result<Self, ParsingIssue> {
        Ok(Requirement {
            name: ConditionName::new(name.borrow())?,
            description: description.borrow().to_owned(),
        })
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct Justification {
    name: ConditionName,
    explanation: String,
}

impl Justification {
    pub fn try_new(
        name: impl Borrow<str>,
        explanation: impl Borrow<str>,
    ) -> Result<Self, ParsingIssue> {
        Ok(Justification {
            name: ConditionName::new(name.borrow())?,
            explanation: explanation.borrow().to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConditionName(String);

impl ConditionName {
    /// Construct a new requirement name, checking all invariants to ensure it is valid.
    fn new(name: &str) -> Result<ConditionName, ParsingIssue> {
        Ok(ConditionName(check_single_word(name)?.to_string()))
    }
}

fn check_single_word(name: &str) -> Result<&str, ParsingIssue> {
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
    Ok(name)
}
