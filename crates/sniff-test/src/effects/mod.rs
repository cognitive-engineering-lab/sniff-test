pub(crate) mod comment;
pub(crate) mod panic;
pub(crate) mod safety;

use std::fmt;

use crate::artifact::{CallFact, FunctionTargetFact};

/// One raw call branch that actually produced an invocation-level effect.
///
/// Several rustc edges can share one source [`effect_tracing::InvocationId`].
/// The engine keeps that source identity grouped, while reporting uses these
/// branches to avoid borrowing an unrelated target, span, or contract.
#[derive(Clone, Debug)]
pub(crate) struct InvocationSourceBranch {
    edge: CallFact,
    target: Option<FunctionTargetFact>,
}

impl InvocationSourceBranch {
    pub(super) fn new(edge: CallFact, target: Option<FunctionTargetFact>) -> Self {
        Self { edge, target }
    }

    #[must_use]
    pub(crate) const fn edge(&self) -> &CallFact {
        &self.edge
    }

    #[must_use]
    pub(crate) const fn target(&self) -> Option<&FunctionTargetFact> {
        self.target.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProbeError {
    message: String,
}

impl ProbeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProbeError {}

#[cfg(test)]
mod tests;
