//! Root-specific evaluation over immutable artifact facts.

mod model;
mod rule;
mod scheduler;
mod store;

pub(crate) use model::{
    DomainId, EvaluationIssueContext, EvaluationRoot, ObligationRecord, RelationTrace,
    deserialize_strict_relation_trace,
};
pub(crate) use rule::{EvaluationCx, EvaluationInput, EvaluationOutput, EvaluationRule, RuleError};
pub(crate) use scheduler::{
    EvaluationPipelineError, EvaluationRuleScheduler, RuleDescriptor, RuleRegistrationError,
};
#[cfg(test)]
pub(crate) use scheduler::{RuleRunError, RuleScheduleError};
#[cfg(test)]
pub(crate) use store::EvaluationResults;
pub(crate) use store::{
    EvaluationDb, EvaluationStorageError, TypedDerivedRow, TypedEvaluatedIssue,
};

#[cfg(test)]
mod tests;
