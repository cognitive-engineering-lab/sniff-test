//! Duplicate-requirement reporting for a selected root's own panic contract.
//!
//! A root contract is a body boundary, not a call obligation. This pack reads
//! the already validated effective contract retained by `PanicRootInputs` and
//! emits only root-specific ambiguity issues in the unified typed-panic
//! production registry.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::compiler_assert_inputs::{
    CompilerAssertBoundary, PanicContractBoundary, PanicRootInputs,
};
use super::contract_collector::COLLECT_PANIC_CONTRACTS_PASS;
use super::contract_index::{
    EffectivePanicContract, EffectivePanicContractOrigin, EffectivePanicContractSourceAnchor,
    EffectivePanicRequirement,
};
use super::contracts::{PanicContractFact, PanicRequirement};
use super::rules::panic_domain;
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationInput, EvaluationIssueContext, EvaluationOutput, EvaluationRule,
    RuleDescriptor, RuleError,
};
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::program::root_traversal::ResolvedBodyBoundary;
use crate::analysis::facts::program::topology::CallableEntity;
use crate::analysis::facts::program::{FunctionEntity, SourceAnchorEntity};
use crate::analysis::facts::schema::{IssueSchema, PassId, RowSchema};
use crate::analysis::facts::workspace::{ScopedEntityRef, ScopedRowRef};

pub(super) const REPORT_DUPLICATE_PANIC_ROOT_REQUIREMENTS_RULE: &str =
    "sniff-test.panic.report-duplicate-root-requirements";

/// One normalized requirement name declared more than once by the root contract.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct DuplicatePanicRootRequirementIssue {
    normalized_name: String,
    requirement_ordinals: Vec<u32>,
}

impl RowSchema for DuplicatePanicRootRequirementIssue {
    const ID: &'static str = "sniff-test.panic.duplicate-root-requirement";
    const VERSION: u32 = 1;
}

impl IssueSchema for DuplicatePanicRootRequirementIssue {}

impl DuplicatePanicRootRequirementIssue {
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

/// Root-contract issue pack installed by the unified typed-panic authority.
pub(crate) struct PanicRootContractPack;

impl AnalysisPack<PanicRootInputs> for PanicRootContractPack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<PanicRootInputs>,
    ) -> Result<(), PackRegistrationError> {
        registry.register_issue::<DuplicatePanicRootRequirementIssue>()?;
        registry.register_evaluation_rule(ReportDuplicatePanicRootRequirements)
    }
}

struct ReportDuplicatePanicRootRequirements;

impl EvaluationRule<PanicRootInputs> for ReportDuplicatePanicRootRequirements {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new(REPORT_DUPLICATE_PANIC_ROOT_REQUIREMENTS_RULE).unwrap())
            .read::<FunctionEntity>()
            .read::<CallableEntity>()
            .read::<SourceAnchorEntity>()
            .read::<PanicContractFact>()
            .read::<PanicRequirement>()
            .write_issue::<DuplicatePanicRootRequirementIssue>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, PanicRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        validate_context(cx, input)?;
        if cx.root().domain != panic_domain() {
            return Ok(());
        }
        let Some(boundary) = root_contract_boundary(cx.services())? else {
            return Ok(());
        };
        let contract = root_contract(boundary)?;
        validate_contract_identity(boundary, contract, input)?;
        let pending = expected_issues(boundary, contract, cx.root())?;
        for (issue, context) in pending {
            output.emit_issue(&issue, context)?;
        }
        Ok(())
    }
}

fn validate_context(
    cx: &EvaluationCx<'_, PanicRootInputs>,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    if !input.has_workspace_identity(cx.services().workspace_identity()) {
        return Err(RuleError::failed(
            "panic root-contract inputs belong to a replacement workspace fact view",
        ));
    }
    if cx.services().root() != cx.root() || cx.services().traversal().root() != cx.root() {
        return Err(RuleError::failed(
            "panic root-contract inputs belong to a different evaluation root",
        ));
    }
    Ok(())
}

pub(crate) fn root_contract_boundary(
    inputs: &PanicRootInputs,
) -> Result<Option<&ResolvedBodyBoundary<CompilerAssertBoundary>>, RuleError> {
    let traversal = inputs.traversal();
    let mut roots = traversal.body_boundaries().iter().filter(|boundary| {
        matches!(
            boundary.payload(),
            CompilerAssertBoundary::PanicContract(PanicContractBoundary::Root { .. })
        )
    });
    let Some(boundary) = roots.next() else {
        return Ok(None);
    };
    if roots.next().is_some() {
        return Err(RuleError::failed(
            "panic traversal retained multiple root-contract boundaries",
        ));
    }
    if traversal.body_boundaries().len() != 1
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
        || !inputs.compiler_asserts().assertions().is_empty()
        || inputs.call_count() != 0
        || !inputs.evidence_order().is_empty()
    {
        return Err(RuleError::failed(
            "panic root-contract boundary is not the whole silent traversal",
        ));
    }
    let body = boundary.body().erase();
    let trace = boundary.trace();
    if boundary.order() != 0
        || body != inputs.root().entity
        || trace.root() != &inputs.root().entity
        || trace.target() != &inputs.root().entity
        || !trace.relations().is_empty()
    {
        return Err(RuleError::failed(
            "panic root-contract boundary does not retain the exact empty root witness",
        ));
    }
    Ok(Some(boundary))
}

pub(crate) fn root_contract(
    boundary: &ResolvedBodyBoundary<CompilerAssertBoundary>,
) -> Result<&EffectivePanicContract, RuleError> {
    let CompilerAssertBoundary::PanicContract(PanicContractBoundary::Root { contract }) =
        boundary.payload()
    else {
        return Err(RuleError::failed(
            "panic root-contract projection received a non-root boundary",
        ));
    };
    Ok(contract)
}

fn validate_contract_identity(
    boundary: &ResolvedBodyBoundary<CompilerAssertBoundary>,
    contract: &EffectivePanicContract,
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
            "panic root contract changed its body, queried callable, or declaration owner",
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
                    "panic root override fabricated raw contract or source identities",
                ));
            }
        }
    }
    validate_requirement_sequence(contract, input)
}

fn validate_contract_origin(
    contract: &EffectivePanicContract,
    queried: &crate::analysis::facts::program::FunctionKey,
    declaration: &crate::analysis::facts::program::FunctionKey,
) -> Result<(), RuleError> {
    let valid = match contract.origin() {
        EffectivePanicContractOrigin::Override => {
            contract.raw_contract().is_none()
                && contract.source_anchor().is_none()
                && contract.declaration_owner() == contract.queried_callable()
                && contract.requirements().iter().all(|requirement| {
                    requirement.raw_requirement().is_none() && requirement.source_anchor().is_none()
                })
        }
        EffectivePanicContractOrigin::RawExact => {
            contract.raw_contract().is_some()
                && contract.declaration_owner() == contract.queried_callable()
        }
        EffectivePanicContractOrigin::RawGeneric => {
            contract.raw_contract().is_some()
                && contract.declaration_owner() != contract.queried_callable()
                && queried.instance().is_some()
                && declaration.instance().is_none()
                && queried.definition() == declaration.definition()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(RuleError::failed(
            "panic root contract has malformed effective-origin provenance",
        ))
    }
}

fn validate_raw_contract(
    reference: &ScopedRowRef,
    contract: &EffectivePanicContract,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    let raw = input.artifact_fact_at::<PanicContractFact>(reference)?;
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
    let requirements = raw
        .metadata
        .requirements
        .iter()
        .cloned()
        .map(|requirement| ScopedRowRef::new(scope.clone(), requirement))
        .collect::<Vec<_>>();
    let expected_requirements = contract
        .requirements()
        .iter()
        .map(|requirement| requirement.raw_requirement().cloned())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| RuleError::failed("raw panic root contract lost a requirement identity"))?;
    let requirement_set = requirements.iter().cloned().collect::<BTreeSet<_>>();
    let expected_requirement_set = expected_requirements
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if owner.as_ref() != Some(&contract.declaration_owner().erase())
        || anchor.as_ref()
            != contract
                .source_anchor()
                .map(EffectivePanicContractSourceAnchor::reference)
        || requirements.len() != requirement_set.len()
        || expected_requirements.len() != expected_requirement_set.len()
        || requirement_set != expected_requirement_set
        || raw.metadata.producer.as_str() != COLLECT_PANIC_CONTRACTS_PASS
    {
        return Err(RuleError::failed(
            "panic root contract disagrees with its exact permanent fact metadata",
        ));
    }
    if let Some(source) = contract.source_anchor() {
        if source.id().erase() != *source.reference() {
            return Err(RuleError::failed(
                "panic root contract source typed ID disagrees with its reference",
            ));
        }
        let data = input.artifact_entity_at::<SourceAnchorEntity>(source.reference())?;
        if &data != source.data() {
            return Err(RuleError::failed(
                "panic root contract source anchor changed after indexing",
            ));
        }
    }
    Ok(())
}

fn validate_requirement_sequence(
    contract: &EffectivePanicContract,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    for (ordinal, requirement) in contract.requirements().iter().enumerate() {
        let ordinal = u32::try_from(ordinal)
            .map_err(|_| RuleError::failed("panic root contract requirement count exceeds u32"))?;
        if requirement.ordinal() != ordinal || requirement.normalized_name().is_empty() {
            return Err(RuleError::failed(
                "panic root contract requirements are not dense nonblank declarations",
            ));
        }
        validate_requirement_identity(contract, requirement, input)?;
    }
    Ok(())
}

fn validate_requirement_identity(
    contract: &EffectivePanicContract,
    requirement: &EffectivePanicRequirement,
    input: &EvaluationInput<'_>,
) -> Result<(), RuleError> {
    let Some(reference) = requirement.raw_requirement() else {
        return Ok(());
    };
    let raw = input.artifact_requirement_at::<PanicRequirement>(reference)?;
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
            "panic root requirement disagrees with its exact permanent row",
        ));
    }
    if let Some(source) = requirement.source_anchor() {
        if source.id().erase() != *source.reference()
            || source.reference().scope() != reference.scope()
        {
            return Err(RuleError::failed(
                "panic root requirement source identity or scope was altered",
            ));
        }
        let data = input.artifact_entity_at::<SourceAnchorEntity>(source.reference())?;
        if &data != source.data() {
            return Err(RuleError::failed(
                "panic root requirement source anchor changed after indexing",
            ));
        }
    }
    Ok(())
}

fn expected_issues(
    boundary: &ResolvedBodyBoundary<CompilerAssertBoundary>,
    contract: &EffectivePanicContract,
    root: &crate::analysis::facts::evaluation::EvaluationRoot,
) -> Result<Vec<(DuplicatePanicRootRequirementIssue, EvaluationIssueContext)>, RuleError> {
    let mut pending = Vec::with_capacity(contract.duplicate_requirement_groups().len());
    for group in contract.duplicate_requirement_groups() {
        if group.normalized_name().is_empty() || group.requirements().len() < 2 {
            return Err(RuleError::failed(
                "panic root contract retained an invalid duplicate requirement group",
            ));
        }
        let mut ordinals = Vec::with_capacity(group.requirements().len());
        for requirement in group.requirements() {
            let indexed = contract
                .requirements()
                .get(usize::try_from(requirement.ordinal()).map_err(|_| {
                    RuleError::failed("panic root requirement ordinal does not fit usize")
                })?)
                .filter(|indexed| *indexed == requirement)
                .ok_or_else(|| {
                    RuleError::failed("panic root duplicate group references a foreign requirement")
                })?;
            if indexed.normalized_name() != group.normalized_name() {
                return Err(RuleError::failed(
                    "panic root duplicate group changed its normalized name",
                ));
            }
            ordinals.push(indexed.ordinal());
        }
        let issue = DuplicatePanicRootRequirementIssue::new(group.normalized_name(), ordinals);
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

    use super::*;

    #[test]
    fn duplicate_root_requirement_issue_is_a_strict_v1_projection() {
        let issue = DuplicatePanicRootRequirementIssue::new("ready", vec![0, 2]);

        assert_eq!(issue.normalized_name(), "ready");
        assert_eq!(issue.requirement_ordinals(), [0, 2]);
        assert_eq!(DuplicatePanicRootRequirementIssue::VERSION, 1);
        assert_eq!(
            serde_json::to_value(&issue).unwrap(),
            json!({
                "normalized-name": "ready",
                "requirement-ordinals": [0, 2],
            })
        );

        for hostile in [
            json!({ "requirement-ordinals": [0, 2] }),
            json!({ "normalized-name": "ready" }),
            json!({
                "normalized_name": "ready",
                "requirement_ordinals": [0, 2],
            }),
            json!({
                "normalized-name": "ready",
                "requirement-ordinals": [0, 2],
                "unexpected": true,
            }),
        ] {
            assert!(serde_json::from_value::<DuplicatePanicRootRequirementIssue>(hostile).is_err());
        }
    }
}
