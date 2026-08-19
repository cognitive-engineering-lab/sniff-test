//! Root-scoped typed safety issues.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::collector::COLLECT_SAFETY_ARTIFACT_PASS;
use super::contract_index::{
    EffectiveSafetyContract, EffectiveSafetyContractOrigin, EffectiveSafetyContractSourceAnchor,
    EffectiveSafetyRequirement,
};
use super::{
    SafetyBoundary, SafetyContractFact, SafetyRequirement, SafetyRootInputs, safety_domain,
};
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationInput, EvaluationIssueContext, EvaluationOutput, EvaluationRule,
    RelationTrace, RuleDescriptor, RuleError,
};
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::program::root_traversal::ResolvedBodyBoundary;
use crate::analysis::facts::program::topology::CallableEntity;
use crate::analysis::facts::program::{FunctionEntity, SourceAnchorEntity};
use crate::analysis::facts::schema::{IssueSchema, PassId, RowSchema};
use crate::analysis::facts::workspace::{ScopedEntityRef, ScopedRowRef};

const REPORT_MISSING_SAFETY_DOCS_RULE: &str = "sniff-test.safety.report-missing-docs";
const REPORT_DUPLICATE_SAFETY_ROOT_REQUIREMENTS_RULE: &str =
    "sniff-test.safety.report-duplicate-root-requirements";

/// One exported unsafe report root without an effective `# Safety` contract.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct MissingSafetyDocsIssue {}

impl RowSchema for MissingSafetyDocsIssue {
    const ID: &'static str = "sniff-test.safety.missing-docs";
    const VERSION: u32 = 1;
}

impl IssueSchema for MissingSafetyDocsIssue {}

impl MissingSafetyDocsIssue {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {}
    }
}

/// One normalized requirement name declared repeatedly by a root safety contract.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct DuplicateSafetyRootRequirementIssue {
    normalized_name: String,
    requirement_ordinals: Vec<u32>,
}

impl RowSchema for DuplicateSafetyRootRequirementIssue {
    const ID: &'static str = "sniff-test.safety.duplicate-root-requirement";
    const VERSION: u32 = 1;
}

impl IssueSchema for DuplicateSafetyRootRequirementIssue {}

impl DuplicateSafetyRootRequirementIssue {
    #[must_use]
    pub(crate) fn new(normalized_name: impl Into<String>, requirement_ordinals: Vec<u32>) -> Self {
        Self {
            normalized_name: normalized_name.into(),
            requirement_ordinals,
        }
    }

    #[must_use]
    pub(crate) fn normalized_name(&self) -> &str {
        &self.normalized_name
    }

    #[must_use]
    pub(crate) fn requirement_ordinals(&self) -> &[u32] {
        &self.requirement_ordinals
    }
}

/// Root-specific safety issues consumed by the typed safety authority.
pub(crate) struct SafetyRootIssuePack;

impl AnalysisPack<SafetyRootInputs> for SafetyRootIssuePack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<SafetyRootInputs>,
    ) -> Result<(), PackRegistrationError> {
        registry.register_issue::<MissingSafetyDocsIssue>()?;
        registry.register_issue::<DuplicateSafetyRootRequirementIssue>()?;
        registry.register_evaluation_rule(ReportMissingSafetyDocs)?;
        registry.register_evaluation_rule(ReportDuplicateSafetyRootRequirements)
    }
}

struct ReportMissingSafetyDocs;

impl EvaluationRule<SafetyRootInputs> for ReportMissingSafetyDocs {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new(REPORT_MISSING_SAFETY_DOCS_RULE).unwrap())
            .read::<FunctionEntity>()
            .read::<CallableEntity>()
            .write_issue::<MissingSafetyDocsIssue>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, SafetyRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        validate_context(cx, input)?;
        if cx.root().domain != safety_domain() || !cx.services().root_missing_safety_docs() {
            return Ok(());
        }
        let context = missing_docs_context(cx.services(), input)?;
        output.emit_issue(&MissingSafetyDocsIssue::new(), context)
    }
}

struct ReportDuplicateSafetyRootRequirements;

impl EvaluationRule<SafetyRootInputs> for ReportDuplicateSafetyRootRequirements {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new(REPORT_DUPLICATE_SAFETY_ROOT_REQUIREMENTS_RULE).unwrap())
            .read::<FunctionEntity>()
            .read::<CallableEntity>()
            .read::<SourceAnchorEntity>()
            .read::<SafetyContractFact>()
            .read::<SafetyRequirement>()
            .write_issue::<DuplicateSafetyRootRequirementIssue>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, SafetyRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        validate_context(cx, input)?;
        if cx.root().domain != safety_domain() {
            return Ok(());
        }
        let Some(boundary) = root_contract_boundary(cx.services())? else {
            return Ok(());
        };
        let contract = root_contract(boundary)?;
        validate_contract_identity(boundary, contract, input)?;
        for (issue, context) in expected_duplicate_issues(boundary, contract, cx.root())? {
            output.emit_issue(&issue, context)?;
        }
        Ok(())
    }
}

fn validate_context(
    cx: &EvaluationCx<'_, SafetyRootInputs>,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    if !input.has_workspace_identity(cx.services().workspace_identity()) {
        return Err(RuleError::failed(
            "safety root inputs belong to a replacement workspace fact view",
        ));
    }
    if cx.services().root() != cx.root() || cx.services().traversal().root() != cx.root() {
        return Err(RuleError::failed(
            "safety root inputs belong to a different evaluation root",
        ));
    }
    Ok(())
}

fn missing_docs_context(
    inputs: &SafetyRootInputs,
    input: &EvaluationInput<'_>,
) -> Result<EvaluationIssueContext, RuleError> {
    let callable = input.artifact_entity_at::<CallableEntity>(&inputs.root_callable().erase())?;
    if callable != *inputs.root_callable_data() || !callable.is_exported() || !callable.is_unsafe()
    {
        return Err(RuleError::failed(
            "missing safety-docs root callable changed after preparation",
        ));
    }
    let body = input.artifact_entity_at::<FunctionEntity>(&inputs.root().entity)?;
    if body.key() != callable.key() {
        return Err(RuleError::failed(
            "missing safety-docs function and callable identities disagree",
        ));
    }
    Ok(EvaluationIssueContext::new(inputs.root().clone())
        .with_endpoint(inputs.root().entity.clone())
        .with_trace(RelationTrace::new(
            inputs.root().entity.clone(),
            inputs.root().entity.clone(),
            Vec::new(),
        )))
}

fn root_contract_boundary(
    inputs: &SafetyRootInputs,
) -> Result<Option<&ResolvedBodyBoundary<SafetyBoundary>>, RuleError> {
    let traversal = inputs.traversal();
    let mut roots = traversal
        .body_boundaries()
        .iter()
        .filter(|boundary| matches!(boundary.payload(), SafetyBoundary::RootContract(_)));
    let Some(boundary) = roots.next() else {
        return Ok(None);
    };
    if roots.next().is_some()
        || traversal.body_boundaries().len() != 1
        || !traversal.body_visits().is_empty()
        || !traversal.effect_visits().is_empty()
        || !traversal.unsafe_operation_visits().is_empty()
        || !traversal.occurrence_visits().is_empty()
        || !traversal.callable_resolutions().is_empty()
        || !traversal.consumer_body_sources().is_empty()
        || !traversal.consumer_reconciliations().is_empty()
        || !traversal.followed_calls().is_empty()
        || !traversal.call_boundaries().is_empty()
        || !traversal.outcomes().is_empty()
        || inputs.root_missing_safety_docs()
    {
        return Err(RuleError::failed(
            "safety root-contract boundary is not the whole silent traversal",
        ));
    }
    if boundary.order() != 0
        || boundary.body().erase() != inputs.root().entity
        || boundary.callable() != inputs.root_callable()
        || boundary.callable_data() != inputs.root_callable_data()
        || boundary.trace().root() != &inputs.root().entity
        || boundary.trace().target() != &inputs.root().entity
        || !boundary.trace().relations().is_empty()
    {
        return Err(RuleError::failed(
            "safety root-contract boundary changed its exact empty root witness",
        ));
    }
    Ok(Some(boundary))
}

fn root_contract(
    boundary: &ResolvedBodyBoundary<SafetyBoundary>,
) -> Result<&EffectiveSafetyContract, RuleError> {
    let SafetyBoundary::RootContract(contract) = boundary.payload() else {
        return Err(RuleError::failed(
            "safety root-contract projection received a non-root boundary",
        ));
    };
    Ok(contract)
}

fn validate_contract_identity(
    boundary: &ResolvedBodyBoundary<SafetyBoundary>,
    contract: &EffectiveSafetyContract,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    let body = input.artifact_entity_at::<FunctionEntity>(&boundary.body().erase())?;
    let queried = input.artifact_entity_at::<CallableEntity>(&boundary.callable().erase())?;
    let declaration =
        input.artifact_entity_at::<CallableEntity>(&contract.declaration_owner().erase())?;
    if body != *boundary.body_data()
        || queried != *boundary.callable_data()
        || contract.queried_callable() != boundary.callable()
        || queried.key() != boundary.body_data().key()
    {
        return Err(RuleError::failed(
            "safety root contract changed its body, queried callable, or declaration owner",
        ));
    }
    validate_contract_origin(contract, queried.key(), declaration.key())?;
    match contract.raw_contract() {
        Some(reference) => validate_raw_contract(reference, contract, input)?,
        None => {
            if contract.source_anchor().is_some()
                || contract.requirements().iter().any(|requirement| {
                    requirement.raw_requirement().is_some() || requirement.source_anchor().is_some()
                })
            {
                return Err(RuleError::failed(
                    "safety root override fabricated raw contract or source identities",
                ));
            }
        }
    }
    validate_requirement_sequence(contract, input)
}

fn validate_contract_origin(
    contract: &EffectiveSafetyContract,
    queried: &crate::analysis::facts::program::FunctionKey,
    declaration: &crate::analysis::facts::program::FunctionKey,
) -> Result<(), RuleError> {
    let valid = match contract.origin() {
        EffectiveSafetyContractOrigin::Override => {
            contract.raw_contract().is_none()
                && contract.source_anchor().is_none()
                && contract.declaration_owner() == contract.queried_callable()
        }
        EffectiveSafetyContractOrigin::RawExact => {
            contract.raw_contract().is_some()
                && contract.declaration_owner() == contract.queried_callable()
        }
        EffectiveSafetyContractOrigin::RawGeneric => {
            contract.raw_contract().is_some()
                && contract.declaration_owner() != contract.queried_callable()
                && queried.instance().is_some()
                && declaration.instance().is_none()
                && queried.definition() == declaration.definition()
        }
    };
    valid.then_some(()).ok_or_else(|| {
        RuleError::failed("safety root contract has malformed effective-origin provenance")
    })
}

fn validate_raw_contract(
    reference: &ScopedRowRef,
    contract: &EffectiveSafetyContract,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    let raw = input.artifact_fact_at::<SafetyContractFact>(reference)?;
    let scope = reference.scope().clone();
    let owner = raw
        .metadata
        .owner
        .clone()
        .map(|owner| ScopedEntityRef::new(scope.clone(), owner));
    let anchor = raw
        .metadata
        .anchor
        .clone()
        .map(|anchor| ScopedEntityRef::new(scope.clone(), anchor));
    let actual = raw
        .metadata
        .requirements
        .iter()
        .cloned()
        .map(|requirement| ScopedRowRef::new(scope.clone(), requirement))
        .collect::<BTreeSet<_>>();
    let expected = contract
        .requirements()
        .iter()
        .map(|requirement| requirement.raw_requirement().cloned())
        .collect::<Option<BTreeSet<_>>>()
        .ok_or_else(|| RuleError::failed("raw safety root contract lost a requirement identity"))?;
    if owner.as_ref() != Some(&contract.declaration_owner().erase())
        || anchor.as_ref()
            != contract
                .source_anchor()
                .map(EffectiveSafetyContractSourceAnchor::reference)
        || actual.len() != raw.metadata.requirements.len()
        || actual != expected
        || raw.metadata.producer.as_str() != COLLECT_SAFETY_ARTIFACT_PASS
    {
        return Err(RuleError::failed(
            "safety root contract disagrees with its exact permanent fact metadata",
        ));
    }
    if let Some(source) = contract.source_anchor()
        && (source.id().erase() != *source.reference()
            || input.artifact_entity_at::<SourceAnchorEntity>(source.reference())?
                != *source.data())
    {
        return Err(RuleError::failed(
            "safety root contract source anchor changed after indexing",
        ));
    }
    Ok(())
}

fn validate_requirement_sequence(
    contract: &EffectiveSafetyContract,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    for (ordinal, requirement) in contract.requirements().iter().enumerate() {
        let ordinal = u32::try_from(ordinal)
            .map_err(|_| RuleError::failed("safety root requirement count exceeds u32"))?;
        if requirement.ordinal() != ordinal || requirement.normalized_name().is_empty() {
            return Err(RuleError::failed(
                "safety root requirements are not dense nonblank declarations",
            ));
        }
        validate_requirement_identity(contract, requirement, input)?;
    }
    Ok(())
}

fn validate_requirement_identity(
    contract: &EffectiveSafetyContract,
    requirement: &EffectiveSafetyRequirement,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    let Some(reference) = requirement.raw_requirement() else {
        return Ok(());
    };
    let raw = input.artifact_requirement_at::<SafetyRequirement>(reference)?;
    let declaration =
        input.artifact_entity_at::<CallableEntity>(&contract.declaration_owner().erase())?;
    if raw.owner() != declaration.key()
        || raw.ordinal() != requirement.ordinal()
        || raw.name() != requirement.name()
        || raw.normalized_name() != requirement.normalized_name()
        || raw.condition() != requirement.condition()
        || raw.source_anchor()
            != requirement
                .source_anchor()
                .map(|source| source.data().anchor())
    {
        return Err(RuleError::failed(
            "safety root requirement disagrees with its exact permanent row",
        ));
    }
    if let Some(source) = requirement.source_anchor()
        && (source.id().erase() != *source.reference()
            || source.reference().scope() != reference.scope()
            || input.artifact_entity_at::<SourceAnchorEntity>(source.reference())?
                != *source.data())
    {
        return Err(RuleError::failed(
            "safety root requirement source anchor changed after indexing",
        ));
    }
    Ok(())
}

fn expected_duplicate_issues(
    boundary: &ResolvedBodyBoundary<SafetyBoundary>,
    contract: &EffectiveSafetyContract,
    root: &crate::analysis::facts::evaluation::EvaluationRoot,
) -> Result<Vec<(DuplicateSafetyRootRequirementIssue, EvaluationIssueContext)>, RuleError> {
    let mut pending = Vec::with_capacity(contract.duplicate_requirement_groups().len());
    for group in contract.duplicate_requirement_groups() {
        if group.normalized_name().is_empty() || group.requirements().len() < 2 {
            return Err(RuleError::failed(
                "safety root contract retained an invalid duplicate requirement group",
            ));
        }
        let mut ordinals = Vec::with_capacity(group.requirements().len());
        for requirement in group.requirements() {
            let indexed = contract
                .requirements()
                .get(usize::try_from(requirement.ordinal()).map_err(|_| {
                    RuleError::failed("safety root requirement ordinal does not fit usize")
                })?)
                .filter(|indexed| *indexed == requirement)
                .ok_or_else(|| {
                    RuleError::failed(
                        "safety root duplicate group references a foreign requirement",
                    )
                })?;
            if indexed.normalized_name() != group.normalized_name() {
                return Err(RuleError::failed(
                    "safety root duplicate group changed its normalized name",
                ));
            }
            ordinals.push(indexed.ordinal());
        }
        let issue = DuplicateSafetyRootRequirementIssue::new(group.normalized_name(), ordinals);
        let mut context = EvaluationIssueContext::new(root.clone())
            .with_endpoint(boundary.body().erase())
            .with_trace(boundary.trace().clone());
        if let Some(source) = contract.raw_contract() {
            context = context.with_source(source.clone());
        }
        pending.push((issue, context));
    }
    Ok(pending)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{DuplicateSafetyRootRequirementIssue, MissingSafetyDocsIssue};
    use crate::analysis::facts::schema::RowSchema;

    #[test]
    fn missing_safety_docs_issue_is_a_strict_v1_unit_payload() {
        let issue = MissingSafetyDocsIssue::new();

        assert_eq!(MissingSafetyDocsIssue::VERSION, 1);
        assert_eq!(serde_json::to_value(issue).unwrap(), json!({}));
        assert!(
            serde_json::from_value::<MissingSafetyDocsIssue>(json!({
                "unexpected": true,
            }))
            .is_err()
        );
    }

    #[test]
    fn duplicate_safety_root_requirement_issue_is_a_strict_v1_projection() {
        let issue = DuplicateSafetyRootRequirementIssue::new("ready", vec![0, 2]);

        assert_eq!(issue.normalized_name(), "ready");
        assert_eq!(issue.requirement_ordinals(), [0, 2]);
        assert_eq!(DuplicateSafetyRootRequirementIssue::VERSION, 1);
        assert_eq!(
            serde_json::to_value(issue).unwrap(),
            json!({
                "normalized-name": "ready",
                "requirement-ordinals": [0, 2],
            })
        );
    }
}
