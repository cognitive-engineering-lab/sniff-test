//! Typed safety-call reporting from resolved safety boundaries.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{SafetyBoundary, SafetyRootInputs, safety_domain};
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationInput, EvaluationIssueContext, EvaluationOutput, EvaluationRule,
    RuleDescriptor, RuleError,
};
use crate::analysis::facts::human::EvidenceClaimSelector;
use crate::analysis::facts::human::markers::MarkerClaimEntity;
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::program::topology::{
    CallKind, CallOccurrenceEntity, CallableEntity, SafetyEffectGroupEntity,
};
use crate::analysis::facts::schema::{IssueSchema, PassId, RowSchema};
use crate::contracts::normalize_requirement_name;

const REPORT_SAFETY_CALLS_RULE: &str = "sniff-test.safety.report-calls";

/// Which established safety diagnostic family applies at one call boundary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SafetyCallIssueKind {
    Unsafe,
    Obligation,
}

/// One safety call whose justification does not cover its effective contract.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct UnsatisfiedSafetyCallIssue {
    kind: SafetyCallIssueKind,
    witness_order: u64,
    missing_requirement_ordinals: Vec<u32>,
    trusted: bool,
}

impl RowSchema for UnsatisfiedSafetyCallIssue {
    const ID: &'static str = "sniff-test.safety.unsatisfied-call";
    const VERSION: u32 = 1;
}

impl IssueSchema for UnsatisfiedSafetyCallIssue {}

/// One duplicate normalized requirement group on a reached call contract.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct DuplicateSafetyCallRequirementIssue {
    witness_order: u64,
    normalized_name: String,
    requirement_ordinals: Vec<u32>,
}

impl RowSchema for DuplicateSafetyCallRequirementIssue {
    const ID: &'static str = "sniff-test.safety.duplicate-call-requirement";
    const VERSION: u32 = 1;
}

impl IssueSchema for DuplicateSafetyCallRequirementIssue {}

/// One reached call whose target-specific safety obligations cannot be known.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct IndirectSafetyCallBoundaryIssue {
    witness_order: u64,
    description: String,
}

impl RowSchema for IndirectSafetyCallBoundaryIssue {
    const ID: &'static str = "sniff-test.safety.indirect-call-boundary";
    const VERSION: u32 = 1;
}

impl IssueSchema for IndirectSafetyCallBoundaryIssue {}

impl UnsatisfiedSafetyCallIssue {
    #[must_use]
    pub(crate) fn new(
        kind: SafetyCallIssueKind,
        witness_order: u64,
        missing_requirement_ordinals: Vec<u32>,
        trusted: bool,
    ) -> Self {
        Self {
            kind,
            witness_order,
            missing_requirement_ordinals,
            trusted,
        }
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> SafetyCallIssueKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) fn missing_requirement_ordinals(&self) -> &[u32] {
        &self.missing_requirement_ordinals
    }

    #[must_use]
    pub(crate) const fn trusted(&self) -> bool {
        self.trusted
    }
}

impl DuplicateSafetyCallRequirementIssue {
    #[must_use]
    pub(crate) fn new(
        witness_order: u64,
        normalized_name: impl Into<String>,
        requirement_ordinals: Vec<u32>,
    ) -> Self {
        Self {
            witness_order,
            normalized_name: normalized_name.into(),
            requirement_ordinals,
        }
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
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

impl IndirectSafetyCallBoundaryIssue {
    #[must_use]
    pub(crate) fn new(witness_order: u64, description: impl Into<String>) -> Self {
        Self {
            witness_order,
            description: description.into(),
        }
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) fn description(&self) -> &str {
        &self.description
    }
}

pub(crate) struct SafetyCallIssuePack;

impl AnalysisPack<SafetyRootInputs> for SafetyCallIssuePack {
    fn register(
        &self,
        registry: &mut AnalysisRegistry<SafetyRootInputs>,
    ) -> Result<(), PackRegistrationError> {
        registry.register_issue::<UnsatisfiedSafetyCallIssue>()?;
        registry.register_issue::<DuplicateSafetyCallRequirementIssue>()?;
        registry.register_issue::<IndirectSafetyCallBoundaryIssue>()?;
        registry.register_evaluation_rule(ReportSafetyCalls)
    }
}

struct ReportSafetyCalls;

#[derive(Default)]
struct PendingSafetyCallIssues {
    calls: Vec<(UnsatisfiedSafetyCallIssue, EvaluationIssueContext)>,
    duplicates: Vec<(DuplicateSafetyCallRequirementIssue, EvaluationIssueContext)>,
    indirect: Vec<(IndirectSafetyCallBoundaryIssue, EvaluationIssueContext)>,
}

impl EvaluationRule<SafetyRootInputs> for ReportSafetyCalls {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new(REPORT_SAFETY_CALLS_RULE).unwrap())
            .read::<CallOccurrenceEntity>()
            .read::<CallableEntity>()
            .read::<SafetyEffectGroupEntity>()
            .read::<MarkerClaimEntity>()
            .write_issue::<UnsatisfiedSafetyCallIssue>()
            .write_issue::<DuplicateSafetyCallRequirementIssue>()
            .write_issue::<IndirectSafetyCallBoundaryIssue>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, SafetyRootInputs>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        validate_root(cx)?;
        let mut witnesses = BTreeSet::new();
        let mut pending = PendingSafetyCallIssues::default();
        for boundary in cx.services().traversal().call_boundaries() {
            if !witnesses.insert((
                boundary.occurrence().clone(),
                boundary.trace().clone(),
                boundary.order(),
            )) {
                return Err(RuleError::failed(
                    "safety-call traversal repeats one exact witness",
                ));
            }
            validate_boundary(cx, input, boundary)?;
            collect_boundary_issues(cx, boundary, &mut pending);
        }
        for (issue, context) in pending.calls {
            output.emit_issue(&issue, context)?;
        }
        for (issue, context) in pending.duplicates {
            output.emit_issue(&issue, context)?;
        }
        for (issue, context) in pending.indirect {
            output.emit_issue(&issue, context)?;
        }
        Ok(())
    }
}

fn collect_boundary_issues(
    cx: &EvaluationCx<'_, SafetyRootInputs>,
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        SafetyBoundary,
    >,
    pending: &mut PendingSafetyCallIssues,
) {
    let context = || {
        EvaluationIssueContext::new(cx.root().clone())
            .with_source(boundary.occurrence().erase().as_row())
            .with_endpoint(boundary.occurrence().erase())
            .with_trace(boundary.trace().clone())
    };
    match boundary.payload() {
        SafetyBoundary::CallContract(call_contract) => {
            let contract = call_contract.contract();
            for group in contract.duplicate_requirement_groups() {
                let issue = DuplicateSafetyCallRequirementIssue::new(
                    boundary.order(),
                    group.normalized_name(),
                    group
                        .requirements()
                        .iter()
                        .map(super::contract_index::EffectiveSafetyRequirement::ordinal)
                        .collect(),
                );
                let issue_context = contract
                    .raw_contract()
                    .map_or_else(context, |source| context().with_source(source.clone()));
                pending.duplicates.push((issue, issue_context));
            }
            if let Some(kind) = call_issue_kind(boundary)
                && let Some(missing) = missing_requirements(cx, boundary, contract)
            {
                pending.calls.push((
                    UnsatisfiedSafetyCallIssue::new(
                        kind,
                        boundary.order(),
                        missing,
                        call_contract.trusted(),
                    ),
                    context(),
                ));
            }
        }
        SafetyBoundary::UndocumentedUnsafeCall
        | SafetyBoundary::ForeignDeclaration
        | SafetyBoundary::BodylessDeclaration => {
            collect_undocumented_unsafe_call(cx, boundary, pending, &context);
            if matches!(boundary.payload(), SafetyBoundary::BodylessDeclaration)
                && is_actual_call(boundary.effective_kind())
            {
                pending.indirect.push((
                    IndirectSafetyCallBoundaryIssue::new(
                        boundary.order(),
                        boundary
                            .target_data()
                            .map_or("bodyless declaration", CallableEntity::display_path),
                    ),
                    context(),
                ));
            }
        }
        SafetyBoundary::OpaqueCall { description } => {
            collect_undocumented_unsafe_call(cx, boundary, pending, &context);
            if is_actual_call(boundary.effective_kind()) {
                pending.indirect.push((
                    IndirectSafetyCallBoundaryIssue::new(boundary.order(), description),
                    context(),
                ));
            }
        }
        SafetyBoundary::RootContract(_)
        | SafetyBoundary::TrustedNamespace
        | SafetyBoundary::BuiltinUnsafe => {}
    }
}

fn collect_undocumented_unsafe_call(
    cx: &EvaluationCx<'_, SafetyRootInputs>,
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        SafetyBoundary,
    >,
    pending: &mut PendingSafetyCallIssues,
    context: &impl Fn() -> EvaluationIssueContext,
) {
    if call_issue_kind(boundary) == Some(SafetyCallIssueKind::Unsafe)
        && !has_unnamed_claim(cx, boundary)
    {
        pending.calls.push((
            UnsatisfiedSafetyCallIssue::new(
                SafetyCallIssueKind::Unsafe,
                boundary.order(),
                Vec::new(),
                false,
            ),
            context(),
        ));
    }
}

fn validate_root(cx: &EvaluationCx<'_, SafetyRootInputs>) -> Result<(), RuleError> {
    if cx.root().domain != safety_domain()
        || cx.services().root() != cx.root()
        || cx.services().traversal().root() != cx.root()
    {
        return Err(RuleError::failed(
            "safety-call inputs belong to a different domain or root",
        ));
    }
    Ok(())
}

fn validate_boundary(
    cx: &EvaluationCx<'_, SafetyRootInputs>,
    input: &EvaluationInput<'_>,
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        SafetyBoundary,
    >,
) -> Result<(), RuleError> {
    let occurrence =
        input.artifact_entity_at::<CallOccurrenceEntity>(&boundary.occurrence().erase())?;
    let group =
        input.artifact_entity_at::<SafetyEffectGroupEntity>(&boundary.safety_group().erase())?;
    let expected_trace_target = boundary.target().map_or_else(
        || boundary.occurrence().erase(),
        |target| target.callable().erase(),
    );
    if occurrence != *boundary.occurrence_data()
        || group != *boundary.safety_group_data()
        || group.key().owner() != occurrence.key().owner()
        || boundary.trace().root() != &cx.root().entity
        || boundary.trace().target() != &expected_trace_target
    {
        return Err(RuleError::failed(
            "safety-call witness changed its occurrence, group, or trace",
        ));
    }
    if let Some(target) = boundary.target() {
        let target_data = input.artifact_entity_at::<CallableEntity>(&target.callable().erase())?;
        if Some(&target_data) != boundary.target_data() {
            return Err(RuleError::failed(
                "safety-call target changed after traversal preparation",
            ));
        }
    } else if boundary.target_data().is_some() {
        return Err(RuleError::failed(
            "targetless safety-call witness retained target metadata",
        ));
    }
    for marker in boundary.active_markers() {
        let claim = input.artifact_entity_at::<MarkerClaimEntity>(&marker.claim().erase())?;
        if claim != *marker.data() {
            return Err(RuleError::failed(
                "safety-call marker changed after traversal preparation",
            ));
        }
    }
    if let SafetyBoundary::CallContract(call_contract) = boundary.payload() {
        let _contract_target = input.artifact_entity_at::<CallableEntity>(
            &call_contract.contract_target().callable().erase(),
        )?;
        if call_contract.contract().queried_callable() != call_contract.contract_target().callable()
        {
            return Err(RuleError::failed(
                "safety-call contract no longer matches its selected contract callable",
            ));
        }
    }
    Ok(())
}

fn missing_requirements(
    cx: &EvaluationCx<'_, SafetyRootInputs>,
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        SafetyBoundary,
    >,
    contract: &super::EffectiveSafetyContract,
) -> Option<Vec<u32>> {
    if contract.requirements().is_empty() {
        return (!has_unnamed_claim(cx, boundary)).then(Vec::new);
    }
    let named_claims = boundary
        .active_markers()
        .iter()
        .filter_map(|marker| {
            (marker.data().key().domain() == &cx.root().domain
                && !marker.data().rationale().trim().is_empty())
            .then(|| match marker.data().selector() {
                EvidenceClaimSelector::Named(name) => Some(normalize_requirement_name(name)),
                EvidenceClaimSelector::Unnamed | EvidenceClaimSelector::Explicit(_) => None,
            })
            .flatten()
        })
        .collect::<BTreeSet<_>>();
    let missing = contract
        .requirements()
        .iter()
        .filter(|requirement| !named_claims.contains(requirement.normalized_name()))
        .map(super::contract_index::EffectiveSafetyRequirement::ordinal)
        .collect::<Vec<_>>();
    (!missing.is_empty()).then_some(missing)
}

fn has_unnamed_claim(
    cx: &EvaluationCx<'_, SafetyRootInputs>,
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        SafetyBoundary,
    >,
) -> bool {
    boundary.active_markers().iter().any(|marker| {
        marker.data().key().domain() == &cx.root().domain
            && !marker.data().rationale().trim().is_empty()
            && matches!(marker.data().selector(), EvidenceClaimSelector::Unnamed)
    })
}

fn call_issue_kind(
    boundary: &crate::analysis::facts::program::root_traversal::ResolvedCallBoundary<
        SafetyBoundary,
    >,
) -> Option<SafetyCallIssueKind> {
    if boundary.occurrence_data().requires_unsafe() && is_actual_call(boundary.effective_kind()) {
        Some(SafetyCallIssueKind::Unsafe)
    } else if boundary
        .target_data()
        .is_some_and(|target| !target.is_unsafe())
    {
        Some(SafetyCallIssueKind::Obligation)
    } else {
        None
    }
}

const fn is_actual_call(kind: CallKind) -> bool {
    matches!(
        kind,
        CallKind::DirectCall
            | CallKind::TailCall
            | CallKind::FnPointerCallTarget
            | CallKind::DynDispatchVTableEntry
            | CallKind::IndirectCall
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        DuplicateSafetyCallRequirementIssue, IndirectSafetyCallBoundaryIssue, SafetyCallIssueKind,
        UnsatisfiedSafetyCallIssue,
    };
    use crate::analysis::facts::schema::RowSchema;

    #[test]
    fn unsatisfied_safety_call_issue_is_a_strict_v1_projection() {
        let issue =
            UnsatisfiedSafetyCallIssue::new(SafetyCallIssueKind::Obligation, 7, vec![1, 3], true);
        assert_eq!(issue.kind(), SafetyCallIssueKind::Obligation);
        assert_eq!(issue.witness_order(), 7);
        assert_eq!(issue.missing_requirement_ordinals(), [1, 3]);
        assert!(issue.trusted());
        assert_eq!(UnsatisfiedSafetyCallIssue::VERSION, 1);
        assert_eq!(
            serde_json::to_value(issue).unwrap(),
            json!({
                "kind": "obligation",
                "witness-order": 7,
                "missing-requirement-ordinals": [1, 3],
                "trusted": true,
            })
        );
    }

    #[test]
    fn additional_safety_call_issues_are_strict_v1_projections() {
        let duplicate = DuplicateSafetyCallRequirementIssue::new(3, "valid", vec![0, 2]);
        assert_eq!(duplicate.witness_order(), 3);
        assert_eq!(duplicate.normalized_name(), "valid");
        assert_eq!(duplicate.requirement_ordinals(), [0, 2]);
        assert_eq!(DuplicateSafetyCallRequirementIssue::VERSION, 1);

        let indirect = IndirectSafetyCallBoundaryIssue::new(4, "opaque function pointer");
        assert_eq!(indirect.witness_order(), 4);
        assert_eq!(indirect.description(), "opaque function pointer");
        assert_eq!(IndirectSafetyCallBoundaryIssue::VERSION, 1);
    }
}
