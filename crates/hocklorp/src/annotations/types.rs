//! Core annotation types.

use std::borrow::Borrow;

#[derive(PartialEq, Eq, Debug)]
/// A condition that must hold such that a given function call will not cause UB.
pub struct Requirement {
    name: ConditionName,
    description: String,
}

impl Requirement {
    pub fn new(name: ConditionName, description: impl Borrow<str>) -> Self {
        Requirement {
            name,
            description: description.borrow().to_string(),
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct Justification {
    name: ConditionName,
    explanation: String,
}

impl Justification {
    pub fn new(name: ConditionName, explanation: impl Borrow<str>) -> Self {
        Justification {
            name,
            explanation: explanation.borrow().to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionName(String);

impl ConditionName {
    /// Construct a new requirement name, checking all invariants to ensure it is valid.
    pub fn try_new(name: &str) -> Result<ConditionName, InvalidConditionNameReason> {
        Ok(ConditionName(check_single_word(name)?.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidConditionNameReason {
    TrailingWhitespace,
    MultipleWords,
}

pub const INVALID_WHITESPACE: [char; 3] = [' ', '\n', '\t'];

fn check_single_word(name: &str) -> Result<&str, InvalidConditionNameReason> {
    // Valid requirement names shouldn't contain whitespace.
    if name.contains(INVALID_WHITESPACE) {
        if name
            .split(INVALID_WHITESPACE)
            .filter(|word| !word.is_empty())
            .count()
            == 1
        {
            // no other words, just invalid whitespace
            return Err(InvalidConditionNameReason::TrailingWhitespace);
        }
        return Err(InvalidConditionNameReason::MultipleWords);
    }
    Ok(name)
}
