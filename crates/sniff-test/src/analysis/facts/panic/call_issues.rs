//! Shadow-only issue projections for validated panic-call inputs.

use std::collections::{BTreeMap, BTreeSet};

use super::call_ingress::{validate_batch, validate_context};
use super::call_matching::{
    expected_matches, validate_committed_inputs, validate_committed_matches,
};
use super::call_model::{
    DuplicatePanicCallRequirementIssue, PanicCallBoundaryKind, PanicCallEvidenceMatch,
    PanicCallObligation, PanicCallRequirementMatchId, PanicCallRequirementValue,
    UnsatisfiedPanicCallIssue,
};
use super::compiler_assert_inputs::PanicRootInputs;
use super::contracts::{PanicContractFact, PanicRequirement};
use super::model::PanicEvidenceOrdering;
use super::rules::panic_domain;
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationInput, EvaluationIssueContext, EvaluationOutput, EvaluationRule,
    RuleDescriptor, RuleError,
};
use crate::analysis::facts::human::markers::MarkerClaimEntity;
use crate::analysis::facts::program::FunctionKey;
use crate::analysis::facts::program::SourceAnchorEntity;
use crate::analysis::facts::program::topology::{
    CallKind, CallOccurrenceEntity, CallSiteEntity, CallableEntity,
};
use crate::analysis::facts::schema::PassId;
use crate::analysis::facts::workspace::{ArtifactScopeId, ScopedEntityRef, ScopedRowRef};
use crate::contracts::normalize_requirement_name;

pub(super) const REPORT_UNSATISFIED_PANIC_CALLS_RULE: &str =
    "sniff-test.panic.report-unsatisfied-call-obligations";

pub(super) struct ReportUnsatisfiedPanicCalls;

pub(super) const REPORT_DUPLICATE_PANIC_CALL_REQUIREMENTS_RULE: &str =
    "sniff-test.panic.report-duplicate-call-requirements";

pub(super) struct ReportDuplicatePanicCallRequirements;

#[cfg(test)]
std::thread_local! {
    static REJECTED_ISSUE_CALL_ID: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) struct RejectedCallIssue {
    previous: Option<u64>,
}

#[cfg(test)]
impl Drop for RejectedCallIssue {
    fn drop(&mut self) {
        REJECTED_ISSUE_CALL_ID.set(self.previous);
    }
}

#[cfg(test)]
pub(super) fn reject_call_issue_for_test(call_id: u64) -> RejectedCallIssue {
    let previous = REJECTED_ISSUE_CALL_ID.replace(Some(call_id));
    RejectedCallIssue { previous }
}

#[cfg(test)]
fn rejects_call_issue(call_id: u64) -> bool {
    REJECTED_ISSUE_CALL_ID.get() == Some(call_id)
}

#[cfg(test)]
std::thread_local! {
    static REJECTED_DUPLICATE_CALL_ID: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) struct RejectedDuplicateCallIssue {
    previous: Option<u64>,
}

#[cfg(test)]
impl Drop for RejectedDuplicateCallIssue {
    fn drop(&mut self) {
        REJECTED_DUPLICATE_CALL_ID.set(self.previous);
    }
}

#[cfg(test)]
pub(super) fn reject_duplicate_call_issue_for_test(call_id: u64) -> RejectedDuplicateCallIssue {
    let previous = REJECTED_DUPLICATE_CALL_ID.replace(Some(call_id));
    RejectedDuplicateCallIssue { previous }
}

#[cfg(test)]
fn rejects_duplicate_call_issue(call_id: u64) -> bool {
    REJECTED_DUPLICATE_CALL_ID.get() == Some(call_id)
}

impl EvaluationRule<PanicRootInputs> for ReportUnsatisfiedPanicCalls {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new(REPORT_UNSATISFIED_PANIC_CALLS_RULE).unwrap())
            .read::<CallOccurrenceEntity>()
            .read::<CallSiteEntity>()
            .read::<CallableEntity>()
            .read::<SourceAnchorEntity>()
            .read::<MarkerClaimEntity>()
            .read::<PanicContractFact>()
            .read::<PanicRequirement>()
            .read::<PanicCallObligation>()
            .read::<PanicEvidenceOrdering>()
            .read::<PanicCallEvidenceMatch>()
            .write_issue::<UnsatisfiedPanicCallIssue>()
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
        let expected = validate_batch(cx.services(), input, output)?;
        validate_committed_inputs(input, &expected)?;
        let matches = expected_matches(&expected)?;
        validate_committed_matches(input, &matches)?;
        let pending = prepare_issues(expected.obligations(), &matches, cx.root())?;
        for candidate in pending {
            output.emit_issue(&candidate.issue, candidate.context)?;
        }
        Ok(())
    }
}

impl EvaluationRule<PanicRootInputs> for ReportDuplicatePanicCallRequirements {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new(REPORT_DUPLICATE_PANIC_CALL_REQUIREMENTS_RULE).unwrap())
            .read::<CallOccurrenceEntity>()
            .read::<CallSiteEntity>()
            .read::<CallableEntity>()
            .read::<SourceAnchorEntity>()
            .read::<MarkerClaimEntity>()
            .read::<PanicContractFact>()
            .read::<PanicRequirement>()
            .read::<PanicCallObligation>()
            .read::<PanicEvidenceOrdering>()
            .write_issue::<DuplicatePanicCallRequirementIssue>()
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
        let expected = validate_batch(cx.services(), input, output)?;
        validate_committed_inputs(input, &expected)?;
        let pending = prepare_duplicate_requirement_issues(expected.obligations(), cx.root())?;
        for candidate in pending {
            output.emit_issue(&candidate.issue, candidate.context)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum LegacyPanicCallClass {
    Sink,
    Documented { trusted: bool },
    Opaque,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LegacyPanicCallKey {
    endpoint: ScopedEntityRef,
    resolution_target: Option<FunctionKey>,
    class: LegacyPanicCallClass,
    missing_names: Vec<String>,
}

struct PendingIssue {
    traversal_order: u64,
    issue: UnsatisfiedPanicCallIssue,
    context: EvaluationIssueContext,
}

fn prepare_issues(
    obligations: &[PanicCallObligation],
    matches: &[PanicCallEvidenceMatch],
    root: &crate::analysis::facts::evaluation::EvaluationRoot,
) -> Result<Vec<PendingIssue>, RuleError> {
    let mut discharged = BTreeMap::<u64, BTreeSet<PanicCallRequirementMatchId>>::new();
    for matched in matches {
        discharged
            .entry(matched.witness_order())
            .or_default()
            .extend(matched.satisfied_requirements().iter().copied());
    }

    let mut candidates = BTreeMap::<LegacyPanicCallKey, PendingIssue>::new();
    for obligation in obligations {
        #[cfg(test)]
        if rejects_call_issue(obligation.call_id()) {
            return Err(RuleError::failed(format!(
                "panic-call issue projection rejected call {} for atomicity testing",
                obligation.call_id()
            )));
        }
        let missing = missing_requirement_atoms(
            obligation.call_id(),
            obligation.requirements(),
            discharged.get(&obligation.call_id()),
        )?;
        if missing.is_empty() {
            continue;
        }
        let key = LegacyPanicCallKey {
            endpoint: obligation.endpoint().clone(),
            resolution_target: legacy_resolution_target(
                obligation.effective_kind(),
                obligation
                    .metadata_target()
                    .map(|metadata| *metadata.data().key()),
            ),
            class: legacy_class(obligation.boundary_kind()),
            missing_names: missing_requirement_names(
                obligation.call_id(),
                obligation.requirements(),
                &missing,
            )?,
        };
        let candidate = PendingIssue {
            traversal_order: obligation.traversal_order(),
            issue: UnsatisfiedPanicCallIssue::new(
                obligation.source().clone(),
                obligation.endpoint().clone(),
                obligation.boundary_kind().clone(),
                obligation.call_id(),
                missing,
            ),
            context: EvaluationIssueContext::new(root.clone())
                .with_source(obligation.source().clone())
                .with_endpoint(obligation.endpoint().clone())
                .with_trace(obligation.trace().clone()),
        };
        retain_first_candidate(&mut candidates, key, candidate);
    }
    Ok(candidates.into_values().collect())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DuplicatePanicCallRequirementKey {
    scope: ArtifactScopeId,
    function: FunctionKey,
    normalized_name: String,
}

struct SelectedDuplicateRequirement<'a> {
    traversal_order: u64,
    witness_order: u64,
    source: &'a ScopedRowRef,
    presentation_function: &'a super::call_model::PanicCallPresentationFunction,
    trace: &'a crate::analysis::facts::evaluation::RelationTrace,
    requirements: Vec<PanicCallRequirementMatchId>,
}

struct PendingDuplicateRequirementIssue {
    traversal_order: u64,
    issue: DuplicatePanicCallRequirementIssue,
    context: EvaluationIssueContext,
}

fn prepare_duplicate_requirement_issues(
    obligations: &[PanicCallObligation],
    root: &crate::analysis::facts::evaluation::EvaluationRoot,
) -> Result<Vec<PendingDuplicateRequirementIssue>, RuleError> {
    let mut selected =
        BTreeMap::<DuplicatePanicCallRequirementKey, SelectedDuplicateRequirement<'_>>::new();
    for obligation in obligations {
        if !eligible_for_duplicate_requirement_issue(
            obligation.boundary_kind(),
            obligation.contract().is_some(),
            obligation.effective_kind(),
        ) {
            continue;
        }
        let groups =
            duplicate_named_requirement_groups(obligation.call_id(), obligation.requirements())?;
        #[cfg(test)]
        if !groups.is_empty() && rejects_duplicate_call_issue(obligation.call_id()) {
            return Err(RuleError::failed(format!(
                "panic-call duplicate requirement projection rejected call {} for atomicity testing",
                obligation.call_id()
            )));
        }
        for (normalized_name, requirements) in groups {
            let key =
                duplicate_requirement_key(obligation.presentation_function(), normalized_name);
            let candidate = SelectedDuplicateRequirement {
                traversal_order: obligation.traversal_order(),
                witness_order: obligation.call_id(),
                source: obligation.source(),
                presentation_function: obligation.presentation_function(),
                trace: obligation.trace(),
                requirements,
            };
            retain_first_duplicate_candidate(&mut selected, key, candidate);
        }
    }
    Ok(finish_duplicate_candidates(selected, root))
}

const fn eligible_for_duplicate_requirement_issue(
    boundary: &PanicCallBoundaryKind,
    has_contract: bool,
    // Ambiguity is recorded before actual/structural call-kind filtering.
    _effective_kind: CallKind,
) -> bool {
    has_contract && matches!(boundary, PanicCallBoundaryKind::Documented { .. })
}

fn finish_duplicate_candidates(
    selected: BTreeMap<DuplicatePanicCallRequirementKey, SelectedDuplicateRequirement<'_>>,
    root: &crate::analysis::facts::evaluation::EvaluationRoot,
) -> Vec<PendingDuplicateRequirementIssue> {
    let mut pending = selected
        .into_iter()
        .map(|(key, selected)| PendingDuplicateRequirementIssue {
            traversal_order: selected.traversal_order,
            issue: DuplicatePanicCallRequirementIssue::new(
                selected.source.clone(),
                selected.presentation_function.clone(),
                selected.witness_order,
                key.normalized_name,
                selected.requirements,
            ),
            context: EvaluationIssueContext::new(root.clone())
                .with_source(selected.source.clone())
                .with_endpoint(selected.presentation_function.endpoint().clone())
                .with_trace(selected.trace.clone()),
        })
        .collect::<Vec<_>>();
    pending.sort_by(|left, right| duplicate_issue_order(left).cmp(&duplicate_issue_order(right)));
    pending
}

fn duplicate_requirement_key(
    presentation: &super::call_model::PanicCallPresentationFunction,
    normalized_name: String,
) -> DuplicatePanicCallRequirementKey {
    DuplicatePanicCallRequirementKey {
        scope: presentation.scope().clone(),
        function: *presentation.function(),
        normalized_name,
    }
}

fn retain_first_duplicate_candidate<'a>(
    selected: &mut BTreeMap<DuplicatePanicCallRequirementKey, SelectedDuplicateRequirement<'a>>,
    key: DuplicatePanicCallRequirementKey,
    candidate: SelectedDuplicateRequirement<'a>,
) {
    match selected.entry(key) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(candidate);
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            if candidate.traversal_order < entry.get().traversal_order {
                entry.insert(candidate);
            }
        }
    }
}

fn duplicate_issue_order(
    candidate: &PendingDuplicateRequirementIssue,
) -> (u64, u64, &ScopedRowRef, &str) {
    (
        candidate.traversal_order,
        candidate.issue.witness_order(),
        candidate.issue.source(),
        candidate.issue.normalized_name(),
    )
}

fn candidate_order(candidate: &PendingIssue) -> (u64, u64, &ScopedRowRef) {
    (
        candidate.traversal_order,
        candidate.issue.witness_order(),
        candidate.issue.source(),
    )
}

fn retain_first_candidate(
    candidates: &mut BTreeMap<LegacyPanicCallKey, PendingIssue>,
    key: LegacyPanicCallKey,
    candidate: PendingIssue,
) {
    match candidates.entry(key) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(candidate);
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            if candidate_order(&candidate) < candidate_order(entry.get()) {
                entry.insert(candidate);
            }
        }
    }
}

fn missing_requirement_atoms(
    call_id: u64,
    requirements: &[PanicCallRequirementValue],
    discharged: Option<&BTreeSet<PanicCallRequirementMatchId>>,
) -> Result<Vec<PanicCallRequirementMatchId>, RuleError> {
    let atoms = requirement_atoms(call_id, requirements)?;
    Ok(atoms
        .into_iter()
        .filter(|atom| discharged.is_none_or(|matched| !matched.contains(atom)))
        .collect())
}

fn requirement_atoms(
    call_id: u64,
    requirements: &[PanicCallRequirementValue],
) -> Result<Vec<PanicCallRequirementMatchId>, RuleError> {
    if requirements == [PanicCallRequirementValue::Unnamed] {
        return Ok(vec![PanicCallRequirementMatchId::unnamed()]);
    }
    requirements
        .iter()
        .map(|requirement| {
            requirement.ordinal().map_or_else(
                || {
                    Err(RuleError::failed(format!(
                        "panic-call obligation {call_id} mixes unnamed and named requirements"
                    )))
                },
                |ordinal| Ok(PanicCallRequirementMatchId::named(ordinal)),
            )
        })
        .collect()
}

fn duplicate_named_requirement_groups(
    call_id: u64,
    requirements: &[PanicCallRequirementValue],
) -> Result<Vec<(String, Vec<PanicCallRequirementMatchId>)>, RuleError> {
    if requirements == [PanicCallRequirementValue::Unnamed] {
        return Ok(Vec::new());
    }
    if requirements.is_empty() {
        return Err(RuleError::failed(format!(
            "panic-call obligation {call_id} has no requirement values"
        )));
    }

    let mut groups = BTreeMap::<String, Vec<PanicCallRequirementMatchId>>::new();
    for (index, requirement) in requirements.iter().enumerate() {
        let expected = u32::try_from(index).map_err(|_| {
            RuleError::failed("panic-call duplicate requirement ordinal exceeds u32")
        })?;
        let (Some(ordinal), Some(name), Some(normalized_name)) = (
            requirement.ordinal(),
            requirement.name(),
            requirement.normalized_name(),
        ) else {
            return Err(RuleError::failed(format!(
                "panic-call obligation {call_id} mixes unnamed and named requirements"
            )));
        };
        if ordinal != expected {
            return Err(RuleError::failed(format!(
                "panic-call obligation {call_id} has a non-declaration requirement ordinal"
            )));
        }
        if normalized_name.is_empty() || normalize_requirement_name(name) != normalized_name {
            return Err(RuleError::failed(format!(
                "panic-call obligation {call_id} has a noncanonical normalized requirement name"
            )));
        }
        groups
            .entry(normalized_name.to_owned())
            .or_default()
            .push(PanicCallRequirementMatchId::named(ordinal));
    }

    Ok(groups
        .into_iter()
        .filter(|(_, occurrences)| occurrences.len() > 1)
        .collect())
}

fn missing_requirement_names(
    call_id: u64,
    requirements: &[PanicCallRequirementValue],
    missing: &[PanicCallRequirementMatchId],
) -> Result<Vec<String>, RuleError> {
    let mut names = Vec::with_capacity(missing.len());
    for atom in missing {
        let PanicCallRequirementMatchId::Named { ordinal } = *atom else {
            continue;
        };
        let index = usize::try_from(ordinal)
            .map_err(|_| RuleError::failed("panic-call requirement ordinal exceeds usize"))?;
        let normalized = requirements
            .get(index)
            .and_then(PanicCallRequirementValue::normalized_name)
            .ok_or_else(|| {
                RuleError::failed(format!(
                    "panic-call obligation {call_id} lost missing requirement ordinal {ordinal}"
                ))
            })?;
        names.push(normalized.to_owned());
    }
    Ok(names)
}

fn legacy_resolution_target(
    effective_kind: CallKind,
    metadata_target: Option<FunctionKey>,
) -> Option<FunctionKey> {
    match effective_kind {
        CallKind::FnPointerCallTarget | CallKind::DynDispatchVTableEntry => metadata_target,
        _ => None,
    }
}

const fn legacy_class(boundary: &PanicCallBoundaryKind) -> LegacyPanicCallClass {
    match boundary {
        PanicCallBoundaryKind::PanicSink => LegacyPanicCallClass::Sink,
        PanicCallBoundaryKind::Documented { trusted } => {
            LegacyPanicCallClass::Documented { trusted: *trusted }
        }
        PanicCallBoundaryKind::Opaque { .. } => LegacyPanicCallClass::Opaque,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{
        DuplicatePanicCallRequirementKey, LegacyPanicCallClass, LegacyPanicCallKey, PendingIssue,
        SelectedDuplicateRequirement, duplicate_named_requirement_groups,
        duplicate_requirement_key, eligible_for_duplicate_requirement_issue,
        finish_duplicate_candidates, legacy_class, legacy_resolution_target,
        missing_requirement_atoms, missing_requirement_names, retain_first_candidate,
        retain_first_duplicate_candidate,
    };
    use crate::analysis::facts::encoded::{EntityRef, RowRef};
    use crate::analysis::facts::evaluation::{
        DomainId, EvaluationIssueContext, EvaluationRoot, RelationTrace,
    };
    use crate::analysis::facts::panic::call_model::{
        PanicCallBoundaryKind, PanicCallOpaqueKind, PanicCallPresentationFunction,
        PanicCallRequirementMatchId, PanicCallRequirementValue, UnsatisfiedPanicCallIssue,
    };
    use crate::analysis::facts::program::FunctionKey;
    use crate::analysis::facts::program::topology::CallKind;
    use crate::analysis::facts::schema::SchemaId;
    use crate::analysis::facts::workspace::{ArtifactScopeId, ScopedEntityRef, ScopedRowRef};
    use crate::namespace::{StableDefPathHash, StableInstanceHash};

    fn named(ordinal: u32, name: &str, normalized_name: &str) -> PanicCallRequirementValue {
        PanicCallRequirementValue::named(
            ordinal,
            name,
            normalized_name,
            format!("condition {ordinal}"),
            None,
            None,
        )
    }

    #[test]
    fn missing_atoms_preserve_declaration_order_and_duplicate_normalized_names() {
        let unnamed = [PanicCallRequirementValue::unnamed()];
        assert_eq!(
            missing_requirement_atoms(0, &unnamed, None).unwrap(),
            [PanicCallRequirementMatchId::unnamed()]
        );
        let unnamed_discharged = BTreeSet::from([PanicCallRequirementMatchId::unnamed()]);
        assert!(
            missing_requirement_atoms(0, &unnamed, Some(&unnamed_discharged))
                .unwrap()
                .is_empty()
        );

        let named = [
            named(0, "Ready", "ready"),
            named(1, "READY", "ready"),
            named(2, "Capacity", "capacity"),
        ];
        let all_missing = missing_requirement_atoms(1, &named, None).unwrap();
        assert_eq!(
            all_missing,
            [
                PanicCallRequirementMatchId::named(0),
                PanicCallRequirementMatchId::named(1),
                PanicCallRequirementMatchId::named(2),
            ]
        );
        assert_eq!(
            missing_requirement_names(1, &named, &all_missing).unwrap(),
            ["ready", "ready", "capacity"]
        );

        let partially_discharged = BTreeSet::from([PanicCallRequirementMatchId::named(1)]);
        assert_eq!(
            missing_requirement_atoms(1, &named, Some(&partially_discharged)).unwrap(),
            [
                PanicCallRequirementMatchId::named(0),
                PanicCallRequirementMatchId::named(2),
            ]
        );
        let fully_discharged = BTreeSet::from([
            PanicCallRequirementMatchId::named(0),
            PanicCallRequirementMatchId::named(1),
            PanicCallRequirementMatchId::named(2),
        ]);
        assert!(
            missing_requirement_atoms(1, &named, Some(&fully_discharged))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn duplicate_groups_are_lexical_and_preserve_declaration_occurrences() {
        let requirements = [
            named(0, "Zeta", "zeta"),
            named(1, "Ready", "ready"),
            named(2, "READY", "ready"),
            named(3, "Alpha", "alpha"),
            named(4, "ZETA", "zeta"),
        ];

        assert_eq!(
            duplicate_named_requirement_groups(7, &requirements).unwrap(),
            [
                (
                    String::from("ready"),
                    vec![
                        PanicCallRequirementMatchId::named(1),
                        PanicCallRequirementMatchId::named(2),
                    ],
                ),
                (
                    String::from("zeta"),
                    vec![
                        PanicCallRequirementMatchId::named(0),
                        PanicCallRequirementMatchId::named(4),
                    ],
                ),
            ]
        );
        assert!(
            duplicate_named_requirement_groups(8, &[PanicCallRequirementValue::unnamed()])
                .unwrap()
                .is_empty()
        );

        let wrong_ordinal = [named(1, "Ready", "ready")];
        assert!(duplicate_named_requirement_groups(9, &wrong_ordinal).is_err());
        let noncanonical = [named(0, "Ready", "READY")];
        assert!(duplicate_named_requirement_groups(10, &noncanonical).is_err());
        let blank = [named(0, "---", "")];
        assert!(duplicate_named_requirement_groups(11, &blank).is_err());
    }

    #[test]
    fn duplicate_eligibility_requires_a_documented_contract_and_ignores_call_shape() {
        for trusted in [false, true] {
            let documented = PanicCallBoundaryKind::Documented { trusted };
            for kind in [
                CallKind::DirectCall,
                CallKind::ConstBody,
                CallKind::CoroutineBody,
            ] {
                assert!(eligible_for_duplicate_requirement_issue(
                    &documented,
                    true,
                    kind
                ));
                assert!(!eligible_for_duplicate_requirement_issue(
                    &documented,
                    false,
                    kind
                ));
            }
        }
        assert!(!eligible_for_duplicate_requirement_issue(
            &PanicCallBoundaryKind::PanicSink,
            true,
            CallKind::DirectCall,
        ));
        assert!(!eligible_for_duplicate_requirement_issue(
            &PanicCallBoundaryKind::Opaque {
                opaque_kind: PanicCallOpaqueKind::ExplicitOpaque,
                description: String::from("opaque"),
            },
            true,
            CallKind::CoroutineBody,
        ));
    }

    fn function_key(local: u64) -> FunctionKey {
        let definition =
            serde_json::from_str::<StableDefPathHash>(&format!("\"0000000000000001{local:016x}\""))
                .unwrap();
        let instance =
            serde_json::from_str::<StableInstanceHash>(&format!("\"{local:032x}\"")).unwrap();
        FunctionKey::new(definition, Some(instance))
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial test freezes semantic dedup, winner retention, and issue context"
    )]
    fn duplicate_key_is_semantic_and_dedup_keeps_lowest_actual_traversal() {
        let endpoint_scope = ArtifactScopeId::for_in_memory(1, 0);
        let semantic_scope = ArtifactScopeId::for_in_memory(2, 0);
        let other_scope = ArtifactScopeId::for_in_memory(3, 0);
        let function = function_key(1);
        let first = PanicCallPresentationFunction::new(
            entity(&endpoint_scope, "sample.callable", 1),
            semantic_scope.clone(),
            function,
        );
        let different_endpoint = PanicCallPresentationFunction::new(
            entity(&endpoint_scope, "sample.callable", 2),
            semantic_scope,
            function,
        );
        let different_scope = PanicCallPresentationFunction::new(
            entity(&endpoint_scope, "sample.callable", 1),
            other_scope,
            function,
        );
        let different_function = PanicCallPresentationFunction::new(
            entity(&endpoint_scope, "sample.callable", 1),
            first.scope().clone(),
            function_key(2),
        );

        let key = duplicate_requirement_key(&first, String::from("ready"));
        assert_eq!(
            key,
            duplicate_requirement_key(&different_endpoint, String::from("ready"))
        );
        assert_ne!(
            key,
            duplicate_requirement_key(&different_scope, String::from("ready"))
        );
        assert_ne!(
            key,
            duplicate_requirement_key(&different_function, String::from("ready"))
        );
        assert_ne!(
            key,
            duplicate_requirement_key(&first, String::from("capacity"))
        );

        let mut selected =
            BTreeMap::<DuplicatePanicCallRequirementKey, SelectedDuplicateRequirement>::new();
        let later_source = source(&endpoint_scope, 0);
        let earlier_source = source(&endpoint_scope, 1);
        let root_entity = entity(&endpoint_scope, "sample.root", 0);
        let root = EvaluationRoot::new(
            DomainId::new("sniff-test.panic").unwrap(),
            root_entity.clone(),
        );
        let later_trace =
            RelationTrace::new(root_entity.clone(), first.endpoint().clone(), Vec::new());
        let earlier_trace = RelationTrace::new(
            root_entity,
            different_endpoint.endpoint().clone(),
            Vec::new(),
        );
        retain_first_duplicate_candidate(
            &mut selected,
            key.clone(),
            SelectedDuplicateRequirement {
                traversal_order: 20,
                witness_order: 0,
                source: &later_source,
                presentation_function: &first,
                trace: &later_trace,
                requirements: vec![
                    PanicCallRequirementMatchId::named(0),
                    PanicCallRequirementMatchId::named(1),
                ],
            },
        );
        retain_first_duplicate_candidate(
            &mut selected,
            key,
            SelectedDuplicateRequirement {
                traversal_order: 10,
                witness_order: 1,
                source: &earlier_source,
                presentation_function: &different_endpoint,
                trace: &earlier_trace,
                requirements: vec![
                    PanicCallRequirementMatchId::named(1),
                    PanicCallRequirementMatchId::named(2),
                ],
            },
        );
        retain_first_duplicate_candidate(
            &mut selected,
            duplicate_requirement_key(&different_endpoint, String::from("capacity")),
            SelectedDuplicateRequirement {
                traversal_order: 10,
                witness_order: 1,
                source: &earlier_source,
                presentation_function: &different_endpoint,
                trace: &earlier_trace,
                requirements: vec![
                    PanicCallRequirementMatchId::named(0),
                    PanicCallRequirementMatchId::named(1),
                ],
            },
        );

        let pending = finish_duplicate_candidates(selected, &root);
        assert_eq!(
            pending
                .iter()
                .map(|candidate| candidate.issue.normalized_name())
                .collect::<Vec<_>>(),
            ["capacity", "ready"]
        );
        let winner = &pending[1];
        assert_eq!(winner.traversal_order, 10);
        assert_eq!(winner.issue.witness_order(), 1);
        assert_eq!(winner.issue.source(), &earlier_source);
        assert_eq!(winner.issue.presentation_function(), &different_endpoint);
        assert_eq!(
            winner.issue.requirements(),
            [
                PanicCallRequirementMatchId::named(1),
                PanicCallRequirementMatchId::named(2),
            ]
        );
        assert_eq!(winner.context.source.as_ref(), Some(&earlier_source));
        assert_eq!(
            winner.context.endpoint.as_ref(),
            Some(different_endpoint.endpoint())
        );
        assert_eq!(winner.context.trace.as_ref(), Some(&earlier_trace));
    }

    fn entity(scope: &ArtifactScopeId, schema: &str, row: u32) -> ScopedEntityRef {
        ScopedEntityRef::new(
            scope.clone(),
            EntityRef {
                schema: SchemaId::new(schema).unwrap(),
                row,
            },
        )
    }

    fn source(scope: &ArtifactScopeId, row: u32) -> ScopedRowRef {
        ScopedRowRef::new(
            scope.clone(),
            RowRef {
                schema: SchemaId::new("sample.call").unwrap(),
                row,
            },
        )
    }

    #[test]
    fn legacy_key_separates_classes_and_only_effective_synthetic_targets() {
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let endpoint = entity(&scope, "sample.call", 0);
        let missing_names = vec![String::from("ready")];
        let key = |class, resolution_target| LegacyPanicCallKey {
            endpoint: endpoint.clone(),
            resolution_target,
            class,
            missing_names: missing_names.clone(),
        };
        let classes = BTreeSet::from([
            key(LegacyPanicCallClass::Sink, None),
            key(LegacyPanicCallClass::Documented { trusted: false }, None),
            key(LegacyPanicCallClass::Documented { trusted: true }, None),
            key(LegacyPanicCallClass::Opaque, None),
        ]);
        assert_eq!(classes.len(), 4);
        assert_eq!(
            legacy_class(&PanicCallBoundaryKind::PanicSink),
            LegacyPanicCallClass::Sink
        );
        assert_eq!(
            legacy_class(&PanicCallBoundaryKind::Documented { trusted: false }),
            LegacyPanicCallClass::Documented { trusted: false }
        );
        assert_eq!(
            legacy_class(&PanicCallBoundaryKind::Documented { trusted: true }),
            LegacyPanicCallClass::Documented { trusted: true }
        );
        assert_eq!(
            legacy_class(&PanicCallBoundaryKind::Opaque {
                opaque_kind: PanicCallOpaqueKind::BodylessDeclaration,
                description: String::from("bodyless"),
            }),
            legacy_class(&PanicCallBoundaryKind::Opaque {
                opaque_kind: PanicCallOpaqueKind::ExplicitOpaque,
                description: String::from("explicit"),
            })
        );

        let target_a = function_key(1);
        let target_b = function_key(2);
        assert_eq!(
            legacy_resolution_target(CallKind::FnPointerCallTarget, Some(target_a)),
            Some(target_a)
        );
        assert_eq!(
            legacy_resolution_target(CallKind::DynDispatchVTableEntry, Some(target_b)),
            Some(target_b)
        );
        assert_ne!(
            key(
                LegacyPanicCallClass::Opaque,
                legacy_resolution_target(CallKind::FnPointerCallTarget, Some(target_a)),
            ),
            key(
                LegacyPanicCallClass::Opaque,
                legacy_resolution_target(CallKind::FnPointerCallTarget, Some(target_b)),
            )
        );
        for kind in [
            CallKind::DirectCall,
            CallKind::TailCall,
            CallKind::FnPointerReify,
            CallKind::ClosureFnPointerReify,
            CallKind::DynObjectCast,
            CallKind::VTableEntry,
            CallKind::MacroExpansion,
            CallKind::ConstBody,
            CallKind::CoroutineBody,
            CallKind::Assert,
            CallKind::IndirectCall,
        ] {
            assert_eq!(legacy_resolution_target(kind, Some(target_a)), None);
        }
        assert_eq!(
            legacy_resolution_target(CallKind::FnPointerCallTarget, None),
            None
        );
    }

    #[test]
    fn opaque_dedup_retains_lowest_actual_traversal_witness() {
        let scope = ArtifactScopeId::for_in_memory(1, 0);
        let endpoint = entity(&scope, "sample.call", 0);
        let root_entity = entity(&scope, "sample.root", 0);
        let root = EvaluationRoot::new(DomainId::new("sniff-test.panic").unwrap(), root_entity);
        let key = LegacyPanicCallKey {
            endpoint: endpoint.clone(),
            resolution_target: None,
            class: LegacyPanicCallClass::Opaque,
            missing_names: Vec::new(),
        };
        let candidate = |witness_order, traversal_order, opaque_kind, description: &str| {
            let source = source(&scope, witness_order);
            let boundary = PanicCallBoundaryKind::Opaque {
                opaque_kind,
                description: description.to_owned(),
            };
            PendingIssue {
                traversal_order,
                issue: UnsatisfiedPanicCallIssue::new(
                    source.clone(),
                    endpoint.clone(),
                    boundary,
                    u64::from(witness_order),
                    vec![PanicCallRequirementMatchId::unnamed()],
                ),
                context: EvaluationIssueContext::new(root.clone())
                    .with_source(source)
                    .with_endpoint(endpoint.clone())
                    .with_trace(RelationTrace::new(
                        root.entity.clone(),
                        endpoint.clone(),
                        Vec::new(),
                    )),
            }
        };
        let mut selected = BTreeMap::new();
        retain_first_candidate(
            &mut selected,
            key.clone(),
            candidate(
                0,
                20,
                PanicCallOpaqueKind::BodylessDeclaration,
                "bodyless later",
            ),
        );
        retain_first_candidate(
            &mut selected,
            key,
            candidate(
                1,
                10,
                PanicCallOpaqueKind::ExplicitOpaque,
                "explicit earlier",
            ),
        );

        let mut winners = selected.into_values();
        let winner = winners.next().unwrap();
        assert!(winners.next().is_none());
        assert_eq!(winner.issue.witness_order(), 1);
        assert_eq!(winner.traversal_order, 10);
        assert_eq!(
            winner.issue.boundary_kind(),
            &PanicCallBoundaryKind::Opaque {
                opaque_kind: PanicCallOpaqueKind::ExplicitOpaque,
                description: String::from("explicit earlier"),
            }
        );
        assert_eq!(winner.context.source.as_ref(), Some(winner.issue.source()));
        assert_eq!(winner.context.endpoint.as_ref(), Some(&endpoint));
    }
}
