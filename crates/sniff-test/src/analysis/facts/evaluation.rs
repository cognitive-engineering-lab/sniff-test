//! Root-specific evaluation over immutable artifact facts.

mod model;
mod rule;
mod scheduler;
mod store;

// This facade intentionally retains the complete pre-split module API.
#[allow(unused_imports)]
pub(crate) use model::{
    DomainId, EvaluationIssueContext, EvaluationRoot, ObligationRecord, RelationTrace,
    deserialize_strict_relation_trace,
};
#[allow(unused_imports)]
pub(crate) use rule::{
    DerivedRowInput, EvaluatedIssueInput, EvaluationCx, EvaluationInput, EvaluationOutput,
    EvaluationRule, RuleError,
};
#[allow(unused_imports)]
pub(crate) use scheduler::{
    EvaluationPipelineError, EvaluationRuleScheduler, RuleDescriptor, RuleRegistrationError,
    RuleRunError, RuleScheduleError, RuleSchemaAccess,
};
#[allow(unused_imports)]
pub(crate) use store::{
    DerivedIndexRow, EvaluatedIssueIndexRow, EvaluationDb, EvaluationResults,
    EvaluationStorageError, TypedDerivedRow, TypedEvaluatedIssue,
};

#[cfg(test)]
mod tests;
