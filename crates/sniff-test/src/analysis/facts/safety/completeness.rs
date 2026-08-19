//! Typed safety-traversal completeness authority.

use serde::{Deserialize, Serialize};

use super::{SafetyRootInputs, safety_domain};
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationInput, EvaluationIssueContext, EvaluationOutput, EvaluationRule,
    RuleDescriptor, RuleError,
};
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::panic::{
    PanicCompletenessOutcome, PanicIncompleteReason, project_traversal_summary,
};
use crate::analysis::facts::program::topology::{
    CallMacroExpansionEntity, CallOccurrenceEntity, CallSiteEntity, CallableEntity,
};
use crate::analysis::facts::program::{FunctionEntity, SourceAnchorEntity};
use crate::analysis::facts::schema::{DerivedSchema, IssueSchema, PassId, RowSchema};

const EMIT_SAFETY_COMPLETENESS_RULE: &str = "sniff-test.safety.emit-completeness";
const REPORT_SAFETY_INCOMPLETE_RULE: &str = "sniff-test.safety.report-incomplete";

/// One traversal-ordered safety incompleteness reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct SafetyCompletenessReason {
    traversal_order: u64,
    reason: PanicIncompleteReason,
}

impl SafetyCompletenessReason {
    #[must_use]
    pub(crate) const fn traversal_order(&self) -> u64 {
        self.traversal_order
    }

    #[must_use]
    pub(crate) const fn reason(&self) -> &PanicIncompleteReason {
        &self.reason
    }
}

/// One validated root-scoped safety completeness summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct SafetyCompletenessOutcome {
    expanded_bodies: u64,
    reasons: Vec<SafetyCompletenessReason>,
}

impl RowSchema for SafetyCompletenessOutcome {
    const ID: &'static str = "sniff-test.safety.completeness-outcome";
    const VERSION: u32 = 1;
}

impl DerivedSchema for SafetyCompletenessOutcome {}

impl SafetyCompletenessOutcome {
    fn from_projected(projected: &PanicCompletenessOutcome) -> Self {
        Self {
            expanded_bodies: projected.expanded_bodies(),
            reasons: projected
                .reasons()
                .iter()
                .map(|reason| SafetyCompletenessReason {
                    traversal_order: reason.traversal_order(),
                    reason: reason.reason().clone(),
                })
                .collect(),
        }
    }

    #[must_use]
    pub(crate) const fn expanded_bodies(&self) -> u64 {
        self.expanded_bodies
    }

    #[must_use]
    pub(crate) fn reasons(&self) -> &[SafetyCompletenessReason] {
        &self.reasons
    }

    #[must_use]
    pub(crate) fn complete(&self) -> bool {
        self.reasons.is_empty()
    }
}

/// A validated safety incompleteness reason selected for reporting.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct SafetyAnalysisIncompleteIssue {
    traversal_order: u64,
    reason: PanicIncompleteReason,
}

impl RowSchema for SafetyAnalysisIncompleteIssue {
    const ID: &'static str = "sniff-test.safety.analysis-incomplete";
    const VERSION: u32 = 1;
}

impl IssueSchema for SafetyAnalysisIncompleteIssue {}

impl SafetyAnalysisIncompleteIssue {
    #[must_use]
    pub(crate) const fn traversal_order(&self) -> u64 {
        self.traversal_order
    }

    #[must_use]
    pub(crate) const fn reason(&self) -> &PanicIncompleteReason {
        &self.reason
    }
}

pub(crate) struct SafetyCompletenessPack;

impl AnalysisPack<SafetyRootInputs> for SafetyCompletenessPack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<SafetyRootInputs>,
    ) -> Result<(), PackRegistrationError> {
        registry.register_derived::<SafetyCompletenessOutcome>()?;
        registry.register_issue::<SafetyAnalysisIncompleteIssue>()?;
        registry.register_evaluation_rule(EmitSafetyCompleteness)?;
        registry.register_evaluation_rule(ReportSafetyIncomplete)
    }
}

struct EmitSafetyCompleteness;

impl EvaluationRule<SafetyRootInputs> for EmitSafetyCompleteness {
    fn descriptor(&self) -> RuleDescriptor {
        projection_descriptor(EMIT_SAFETY_COMPLETENESS_RULE)
            .write_derived::<SafetyCompletenessOutcome>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, SafetyRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        validate_context(cx, input)?;
        let projected = project_traversal_summary(cx.services().traversal(), input, output)?;
        output.emit_derived(&SafetyCompletenessOutcome::from_projected(&projected))
    }
}

struct ReportSafetyIncomplete;

impl EvaluationRule<SafetyRootInputs> for ReportSafetyIncomplete {
    fn descriptor(&self) -> RuleDescriptor {
        projection_descriptor(REPORT_SAFETY_INCOMPLETE_RULE)
            .read::<SafetyCompletenessOutcome>()
            .write_issue::<SafetyAnalysisIncompleteIssue>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, SafetyRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        validate_context(cx, input)?;
        let rows = input.derived_rows::<SafetyCompletenessOutcome>()?;
        let [row] = rows.as_slice() else {
            return Err(RuleError::failed(format!(
                "safety completeness requires one summary, found {}",
                rows.len()
            )));
        };
        if row.root != *cx.root()
            || row.producer != PassId::new(EMIT_SAFETY_COMPLETENESS_RULE).unwrap()
        {
            return Err(RuleError::failed(
                "safety completeness summary has the wrong root or producer",
            ));
        }
        let expected = SafetyCompletenessOutcome::from_projected(&project_traversal_summary(
            cx.services().traversal(),
            input,
            output,
        )?);
        if row.data != expected {
            return Err(RuleError::failed(
                "committed safety completeness disagrees with resolved traversal inputs",
            ));
        }
        for reason in row.data.reasons().iter().cloned() {
            let mut context = EvaluationIssueContext::new(cx.root().clone());
            if let PanicIncompleteReason::MissingManagedBody {
                presentation_source,
                relation_trace,
                ..
            } = reason.reason()
            {
                if let Some(source) = presentation_source {
                    context = context.with_source(source.anchor().as_row());
                }
                context = context
                    .with_endpoint(relation_trace.target().clone())
                    .with_trace(relation_trace.clone());
            }
            output.emit_issue(
                &SafetyAnalysisIncompleteIssue {
                    traversal_order: reason.traversal_order,
                    reason: reason.reason,
                },
                context,
            )?;
        }
        Ok(())
    }
}

fn projection_descriptor(rule: &'static str) -> RuleDescriptor {
    RuleDescriptor::new(PassId::new(rule).unwrap())
        .read::<FunctionEntity>()
        .read::<CallOccurrenceEntity>()
        .read::<CallSiteEntity>()
        .read::<CallMacroExpansionEntity>()
        .read::<CallableEntity>()
        .read::<SourceAnchorEntity>()
}

fn validate_context(
    cx: &EvaluationCx<'_, SafetyRootInputs>,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    if cx.root().domain != safety_domain()
        || cx.services().root() != cx.root()
        || !input.has_workspace_identity(cx.services().workspace_identity())
    {
        return Err(RuleError::failed(
            "safety completeness belongs to a different workspace, domain, or root",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::SafetyCompletenessOutcome;
    use crate::analysis::facts::schema::RowSchema;

    #[test]
    fn complete_safety_summary_is_a_strict_v1_projection() {
        let summary = SafetyCompletenessOutcome {
            expanded_bodies: 2,
            reasons: Vec::new(),
        };
        assert_eq!(summary.expanded_bodies(), 2);
        assert!(summary.complete());
        assert_eq!(SafetyCompletenessOutcome::VERSION, 1);
        assert_eq!(
            serde_json::to_value(summary).unwrap(),
            json!({"expanded-bodies": 2, "reasons": []})
        );
    }
}
