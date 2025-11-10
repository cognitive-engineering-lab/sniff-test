//! Core annotation types.

use std::borrow::Borrow;

use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
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

    pub fn name(&self) -> &ConditionName {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn construct<A: Borrow<str>, B: Borrow<str>>(
        iter: impl IntoIterator<Item = (A, B)>,
    ) -> Vec<Self> {
        iter.into_iter()
            .map(|(name, desc)| {
                Requirement::new(
                    ConditionName::try_new(name)
                        .expect("construct should only be called with valid condition names"),
                    desc,
                )
            })
            .collect()
    }
}

#[derive(PartialEq, Eq, Debug)]
/// The justification for why a given condition has been satisfied.
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

    pub fn name(&self) -> &ConditionName {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.explanation
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionName(String);

impl ConditionName {
    /// Construct a new condition name, checking all invariants to ensure it is valid.
    pub fn try_new<T: Borrow<str>>(name: T) -> Result<ConditionName, InvalidConditionNameReason> {
        // For now, just check that it's a single word with no extra white space.
        Ok(ConditionName(check_single_word(name)?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidConditionNameReason {
    TrailingWhitespace,
    MultipleWords,
}

pub const INVALID_WHITESPACE: [char; 3] = [' ', '\n', '\t'];

fn check_single_word<T: Borrow<str>>(name: T) -> Result<String, InvalidConditionNameReason> {
    let name = name.borrow();
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
        // contains other words
        return Err(InvalidConditionNameReason::MultipleWords);
    }
    Ok(name.to_string())
}
