//! Typed unsafe-operation reporting from resolved safety traversal inputs.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::operations::{SafetyOperationKind, UnsafeOperationEntity};
use super::{SafetyRootInputs, safety_domain};
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationInput, EvaluationIssueContext, EvaluationOutput, EvaluationRule,
    RuleDescriptor, RuleError,
};
use crate::analysis::facts::human::EvidenceClaimSelector;
use crate::analysis::facts::human::markers::MarkerClaimEntity;
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::program::FunctionEntity;
use crate::analysis::facts::program::topology::SafetyEffectGroupEntity;
use crate::analysis::facts::schema::{IssueSchema, PassId, RowSchema};

const REPORT_UNSAFE_OPERATIONS_RULE: &str = "sniff-test.safety.report-unsafe-operations";

/// One reached unsafe operation without an unnamed safety justification.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct UnsatisfiedUnsafeOperationIssue {
    kind: SafetyOperationKind,
    witness_order: u64,
}

impl RowSchema for UnsatisfiedUnsafeOperationIssue {
    const ID: &'static str = "sniff-test.safety.unsatisfied-unsafe-operation";
    const VERSION: u32 = 1;
}

impl IssueSchema for UnsatisfiedUnsafeOperationIssue {}

impl UnsatisfiedUnsafeOperationIssue {
    #[must_use]
    pub(crate) const fn new(kind: SafetyOperationKind, witness_order: u64) -> Self {
        Self {
            kind,
            witness_order,
        }
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> SafetyOperationKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }
}

pub(crate) struct SafetyOperationIssuePack;

impl AnalysisPack<SafetyRootInputs> for SafetyOperationIssuePack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<SafetyRootInputs>,
    ) -> Result<(), PackRegistrationError> {
        registry.register_issue::<UnsatisfiedUnsafeOperationIssue>()?;
        registry.register_evaluation_rule(ReportUnsafeOperations)
    }
}

struct ReportUnsafeOperations;

impl EvaluationRule<SafetyRootInputs> for ReportUnsafeOperations {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new(REPORT_UNSAFE_OPERATIONS_RULE).unwrap())
            .read::<UnsafeOperationEntity>()
            .read::<FunctionEntity>()
            .read::<SafetyEffectGroupEntity>()
            .read::<MarkerClaimEntity>()
            .write_issue::<UnsatisfiedUnsafeOperationIssue>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, SafetyRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        if cx.root().domain != safety_domain() {
            return Ok(());
        }
        if !input.has_workspace_identity(cx.services().workspace_identity())
            || cx.services().root() != cx.root()
            || cx.services().traversal().root() != cx.root()
        {
            return Err(RuleError::failed(
                "unsafe-operation inputs belong to a different workspace or root",
            ));
        }
        let mut witnesses = BTreeSet::new();
        let mut pending = Vec::new();
        for visit in cx.services().traversal().unsafe_operation_visits() {
            let identity = (
                visit.operation().clone(),
                visit.trace().clone(),
                visit.order(),
            );
            if !witnesses.insert(identity) {
                return Err(RuleError::failed(
                    "unsafe-operation traversal repeats one exact witness",
                ));
            }
            validate_visit(cx, input, visit)?;
            let mut satisfied = false;
            for marker in visit.active_markers() {
                let claim =
                    input.artifact_entity_at::<MarkerClaimEntity>(&marker.claim().erase())?;
                if claim != *marker.data() {
                    return Err(RuleError::failed(
                        "unsafe-operation marker changed after traversal preparation",
                    ));
                }
                if claim.key().domain() == &cx.root().domain
                    && matches!(claim.selector(), EvidenceClaimSelector::Unnamed)
                    && !claim.rationale().trim().is_empty()
                {
                    satisfied = true;
                }
            }
            if !satisfied {
                pending.push((
                    UnsatisfiedUnsafeOperationIssue::new(visit.data().kind(), visit.order()),
                    EvaluationIssueContext::new(cx.root().clone())
                        .with_source(visit.operation().erase().as_row())
                        .with_endpoint(visit.operation().erase())
                        .with_trace(visit.trace().clone()),
                ));
            }
        }
        for (issue, context) in pending {
            output.emit_issue(&issue, context)?;
        }
        Ok(())
    }
}

fn validate_visit(
    cx: &EvaluationCx<'_, SafetyRootInputs>,
    input: &EvaluationInput<'_>,
    visit: &crate::analysis::facts::program::root_traversal::ResolvedUnsafeOperationVisit,
) -> Result<(), RuleError> {
    let operation =
        input.artifact_entity_at::<UnsafeOperationEntity>(&visit.operation().erase())?;
    let owner = input.artifact_entity_at::<FunctionEntity>(&visit.owner().erase())?;
    let group =
        input.artifact_entity_at::<SafetyEffectGroupEntity>(&visit.safety_group().erase())?;
    if operation != *visit.data()
        || owner != *visit.owner_data()
        || group != *visit.safety_group_data()
        || operation.key().owner() != owner.key()
        || group.key().owner() != owner.key()
        || visit.trace().root() != &cx.root().entity
        || visit.trace().target() != &visit.operation().erase()
    {
        return Err(RuleError::failed(
            "unsafe-operation witness changed its operation, owner, group, or trace",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::UnsatisfiedUnsafeOperationIssue;
    use crate::analysis::facts::schema::RowSchema;
    use crate::safety::SafetyOpKind;

    #[test]
    fn unsafe_operation_issue_is_a_strict_v1_witness() {
        let issue = UnsatisfiedUnsafeOperationIssue::new(SafetyOpKind::DerefRawPointer, 7);

        assert_eq!(issue.kind(), SafetyOpKind::DerefRawPointer);
        assert_eq!(issue.witness_order(), 7);
        assert_eq!(UnsatisfiedUnsafeOperationIssue::VERSION, 1);
        assert_eq!(
            serde_json::to_value(issue).unwrap(),
            json!({
                "kind": "raw-pointer-dereference",
                "witness-order": 7,
            })
        );
    }
}
