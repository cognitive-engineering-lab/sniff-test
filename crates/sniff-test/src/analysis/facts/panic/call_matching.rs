//! Call-specific human-evidence matching over validated panic-call inputs.

use std::collections::{BTreeMap, btree_map::Entry};

use super::call_ingress::{ValidatedBatch, validate_batch, validate_context};
use super::call_model::{
    PanicCallEvidenceMatch, PanicCallObligation, PanicCallRequirementMatchId,
    PanicCallRequirementValue,
};
use super::compiler_assert_inputs::PanicRootInputs;
use super::contracts::{PanicContractFact, PanicRequirement};
use super::model::PanicEvidenceOrdering;
use super::rules::panic_domain;
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationInput, EvaluationOutput, EvaluationRule, RuleDescriptor, RuleError,
};
use crate::analysis::facts::evidence::EvidenceUseRecord;
use crate::analysis::facts::human::EvidenceClaimSelector;
use crate::analysis::facts::human::markers::MarkerClaimEntity;
use crate::analysis::facts::program::SourceAnchorEntity;
use crate::analysis::facts::program::topology::{
    CallOccurrenceEntity, CallSiteEntity, CallableEntity,
};
use crate::analysis::facts::schema::{PassId, RowSchema};
use crate::contracts::normalize_requirement_name;

pub(super) const MATCH_PANIC_CALL_EVIDENCE_RULE: &str = "sniff-test.panic.match-call-evidence";

pub(super) struct MatchPanicCallEvidence;

#[cfg(test)]
std::thread_local! {
    static REJECTED_MATCH_CALL_ID: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) struct RejectedCallMatch {
    previous: Option<u64>,
}

#[cfg(test)]
impl Drop for RejectedCallMatch {
    fn drop(&mut self) {
        REJECTED_MATCH_CALL_ID.set(self.previous);
    }
}

#[cfg(test)]
pub(super) fn reject_call_match_for_test(call_id: u64) -> RejectedCallMatch {
    let previous = REJECTED_MATCH_CALL_ID.replace(Some(call_id));
    RejectedCallMatch { previous }
}

#[cfg(test)]
fn rejects_call_match(call_id: u64) -> bool {
    REJECTED_MATCH_CALL_ID.get() == Some(call_id)
}

impl EvaluationRule<PanicRootInputs> for MatchPanicCallEvidence {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new(MATCH_PANIC_CALL_EVIDENCE_RULE).unwrap())
            .read::<CallOccurrenceEntity>()
            .read::<CallSiteEntity>()
            .read::<CallableEntity>()
            .read::<SourceAnchorEntity>()
            .read::<MarkerClaimEntity>()
            .read::<PanicContractFact>()
            .read::<PanicRequirement>()
            .read::<PanicCallObligation>()
            .read::<PanicEvidenceOrdering>()
            .write_derived::<PanicCallEvidenceMatch>()
            .write_derived::<EvidenceUseRecord>()
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
        let pending = prepare_matches(&expected)?;
        for row in &pending {
            output.emit_derived(&row.matched)?;
        }
        for row in &pending {
            output.emit_derived(&row.usage)?;
        }
        Ok(())
    }
}

pub(super) fn validate_committed_inputs(
    input: &EvaluationInput<'_>,
    expected: &ValidatedBatch,
) -> Result<(), RuleError> {
    let mut expected_obligations = BTreeMap::new();
    for obligation in expected.obligations() {
        if expected_obligations
            .insert(obligation.call_id(), obligation)
            .is_some()
        {
            return Err(RuleError::failed(
                "validated panic-call batch repeats an obligation witness",
            ));
        }
    }
    let mut actual_obligations = BTreeMap::new();
    for row in input.derived_rows::<PanicCallObligation>()? {
        match actual_obligations.entry(row.data.call_id()) {
            Entry::Vacant(entry) => {
                entry.insert(row.data);
            }
            Entry::Occupied(_) => {
                return Err(RuleError::failed(
                    "panic-call obligations repeat an exact witness identity",
                ));
            }
        }
    }
    require_exact_rows(
        "panic-call obligation",
        &expected_obligations,
        &actual_obligations,
    )?;

    let mut expected_orderings = BTreeMap::new();
    for ordering in expected.orderings() {
        if expected_orderings
            .insert(ordering.witness_order(), ordering)
            .is_some()
        {
            return Err(RuleError::failed(
                "validated panic-call batch repeats an ordering witness",
            ));
        }
    }
    let mut actual_orderings = BTreeMap::new();
    for row in input.derived_rows::<PanicEvidenceOrdering>()? {
        if row.data.obligation_source().row().schema.as_str() != CallOccurrenceEntity::ID {
            continue;
        }
        match actual_orderings.entry(row.data.witness_order()) {
            Entry::Vacant(entry) => {
                entry.insert(row.data);
            }
            Entry::Occupied(_) => {
                return Err(RuleError::failed(
                    "panic-call evidence orderings repeat an exact witness identity",
                ));
            }
        }
    }
    require_exact_rows(
        "panic-call evidence ordering",
        &expected_orderings,
        &actual_orderings,
    )
}

fn require_exact_rows<K: Ord + std::fmt::Debug, T: Eq>(
    label: &str,
    expected: &BTreeMap<K, &T>,
    actual: &BTreeMap<K, T>,
) -> Result<(), RuleError> {
    if let Some(missing) = expected
        .keys()
        .find(|identity| !actual.contains_key(*identity))
    {
        return Err(RuleError::failed(format!(
            "{label} is missing an expected witness: {missing:?}"
        )));
    }
    if let Some(orphan) = actual
        .keys()
        .find(|identity| !expected.contains_key(*identity))
    {
        return Err(RuleError::failed(format!(
            "{label} has an orphan witness: {orphan:?}"
        )));
    }
    if expected
        .iter()
        .any(|(identity, expected)| actual.get(identity) != Some(*expected))
    {
        return Err(RuleError::failed(format!(
            "{label} changed after validated ingress"
        )));
    }
    Ok(())
}

struct PendingCallEvidence {
    matched: PanicCallEvidenceMatch,
    usage: EvidenceUseRecord,
}

fn prepare_matches(expected: &ValidatedBatch) -> Result<Vec<PendingCallEvidence>, RuleError> {
    let mut orderings = BTreeMap::new();
    for ordering in expected.orderings() {
        if orderings
            .insert(ordering.witness_order(), ordering)
            .is_some()
        {
            return Err(RuleError::failed(
                "validated panic-call orderings repeat a witness during matching",
            ));
        }
    }
    let matches = expected_matches(expected)?;
    let mut pending = Vec::with_capacity(matches.len());
    for matched in matches {
        let ordering = orderings.get(&matched.witness_order()).ok_or_else(|| {
            RuleError::failed("validated panic-call match lost its ordering sidecar")
        })?;
        let usage = EvidenceUseRecord::new(
            panic_domain(),
            matched.claim().clone(),
            matched.endpoint().clone(),
            matched.group().clone(),
            matched.obligation_source().clone(),
            matched.trace().clone(),
            matched.witness_order(),
            ordering.semantic_order().clone(),
        );
        pending.push(PendingCallEvidence { matched, usage });
    }
    Ok(pending)
}

pub(super) fn expected_matches(
    expected: &ValidatedBatch,
) -> Result<Vec<PanicCallEvidenceMatch>, RuleError> {
    expected_matches_from_obligations(expected.obligations())
}

pub(crate) fn expected_matches_from_obligations(
    obligations: &[PanicCallObligation],
) -> Result<Vec<PanicCallEvidenceMatch>, RuleError> {
    let mut pending = Vec::new();
    for obligation in obligations {
        #[cfg(test)]
        if rejects_call_match(obligation.call_id()) {
            return Err(RuleError::failed(format!(
                "panic-call matching rejected call {} for atomicity testing",
                obligation.call_id()
            )));
        }
        let requirements =
            CallRequirementIndex::new(obligation.requirements()).map_err(|reason| {
                RuleError::failed(format!(
                    "panic-call obligation {} {reason}",
                    obligation.call_id()
                ))
            })?;
        for marker in obligation.active_markers() {
            let satisfied = requirements.matches(marker.data().selector());
            if satisfied.is_empty() {
                continue;
            }
            validate_matched_requirements(satisfied, obligation)?;
            let matched = PanicCallEvidenceMatch::new_declaration_ordered(
                marker.claim().clone(),
                obligation.source().clone(),
                obligation.endpoint().clone(),
                obligation.evidence_group().clone(),
                obligation.trace_target().clone(),
                obligation.trace().clone(),
                obligation.call_id(),
                satisfied.to_vec(),
            );
            pending.push(matched);
        }
    }
    Ok(pending)
}

impl PanicCallObligation {
    pub(crate) fn expected_evidence_matches_for_report(
        &self,
    ) -> Result<Vec<PanicCallEvidenceMatch>, RuleError> {
        expected_matches_from_obligations(std::slice::from_ref(self))
    }
}

pub(super) fn validate_committed_matches(
    input: &EvaluationInput<'_>,
    expected: &[PanicCallEvidenceMatch],
) -> Result<(), RuleError> {
    let mut expected_by_witness = BTreeMap::new();
    for matched in expected {
        let identity = (matched.witness_order(), matched.claim().clone());
        if expected_by_witness.insert(identity, matched).is_some() {
            return Err(RuleError::failed(
                "expected panic-call evidence matches repeat an exact witness identity",
            ));
        }
    }
    let mut actual_by_witness = BTreeMap::new();
    for row in input.derived_rows::<PanicCallEvidenceMatch>()? {
        let identity = (row.data.witness_order(), row.data.claim().clone());
        match actual_by_witness.entry(identity) {
            Entry::Vacant(entry) => {
                entry.insert(row.data);
            }
            Entry::Occupied(_) => {
                return Err(RuleError::failed(
                    "panic-call evidence matches repeat an exact witness identity",
                ));
            }
        }
    }
    require_exact_rows(
        "panic-call evidence match",
        &expected_by_witness,
        &actual_by_witness,
    )
}

fn validate_matched_requirements(
    satisfied: &[PanicCallRequirementMatchId],
    obligation: &PanicCallObligation,
) -> Result<(), RuleError> {
    if satisfied.is_empty() || satisfied.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(RuleError::failed(
            "panic-call matched requirements are not unique and declaration ordered",
        ));
    }
    for identity in satisfied {
        match *identity {
            PanicCallRequirementMatchId::Unnamed
                if obligation.requirements() == [PanicCallRequirementValue::Unnamed] => {}
            PanicCallRequirementMatchId::Named { ordinal } => {
                let index = usize::try_from(ordinal).map_err(|_| {
                    RuleError::failed("panic-call matched requirement ordinal exceeds usize")
                })?;
                if obligation
                    .requirements()
                    .get(index)
                    .and_then(PanicCallRequirementValue::ordinal)
                    != Some(ordinal)
                {
                    return Err(RuleError::failed(
                        "panic-call matched requirement is outside its obligation",
                    ));
                }
            }
            PanicCallRequirementMatchId::Unnamed => {
                return Err(RuleError::failed(
                    "unnamed panic-call evidence matched a named requirement set",
                ));
            }
        }
    }
    Ok(())
}

struct CallRequirementIndex {
    unnamed: Vec<PanicCallRequirementMatchId>,
    named: BTreeMap<String, Vec<PanicCallRequirementMatchId>>,
}

impl CallRequirementIndex {
    fn new(requirements: &[PanicCallRequirementValue]) -> Result<Self, &'static str> {
        if requirements.len() == 1 && requirements[0].ordinal().is_none() {
            return Ok(Self {
                unnamed: vec![PanicCallRequirementMatchId::unnamed()],
                named: BTreeMap::new(),
            });
        }
        if requirements.is_empty()
            || requirements
                .iter()
                .enumerate()
                .any(|(ordinal, requirement)| {
                    u32::try_from(ordinal).ok() != requirement.ordinal()
                        || match (requirement.name(), requirement.normalized_name()) {
                            (Some(name), Some(normalized_name)) => {
                                normalized_name.is_empty()
                                    || normalize_requirement_name(name) != normalized_name
                            }
                            _ => true,
                        }
                })
        {
            return Err("panic-call requirements do not have one valid local identity shape");
        }
        let mut named = BTreeMap::<String, Vec<PanicCallRequirementMatchId>>::new();
        for requirement in requirements {
            let (Some(ordinal), Some(normalized_name)) =
                (requirement.ordinal(), requirement.normalized_name())
            else {
                return Err("panic-call named requirement lost its validated identity");
            };
            named
                .entry(normalized_name.to_owned())
                .or_default()
                .push(PanicCallRequirementMatchId::named(ordinal));
        }
        Ok(Self {
            unnamed: Vec::new(),
            named,
        })
    }

    fn matches(&self, selector: &EvidenceClaimSelector) -> &[PanicCallRequirementMatchId] {
        match selector {
            EvidenceClaimSelector::Unnamed => &self.unnamed,
            EvidenceClaimSelector::Named(name) => self
                .named
                .get(&normalize_requirement_name(name))
                .map_or(&[], Vec::as_slice),
            EvidenceClaimSelector::Explicit(_) => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CallRequirementIndex;
    use crate::analysis::facts::human::EvidenceClaimSelector;
    use crate::analysis::facts::panic::call_model::{
        PanicCallRequirementMatchId, PanicCallRequirementValue,
    };

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
    fn selectors_match_exact_call_local_requirement_atoms() {
        let unnamed = [PanicCallRequirementValue::unnamed()];
        let unnamed = CallRequirementIndex::new(&unnamed).unwrap();
        assert_eq!(
            unnamed.matches(&EvidenceClaimSelector::Unnamed),
            &[PanicCallRequirementMatchId::unnamed()]
        );
        assert!(
            unnamed
                .matches(&EvidenceClaimSelector::Named(String::from("condition")))
                .is_empty()
        );

        let named_requirements = [
            named(0, "Index_In-Bounds", "index in bounds"),
            named(1, "index-in_bounds", "index in bounds"),
            named(2, "Ready", "ready"),
        ];
        let named_index = CallRequirementIndex::new(&named_requirements).unwrap();
        assert_eq!(
            named_index.matches(&EvidenceClaimSelector::Named(String::from(
                "  INDEX_in-bounds "
            ))),
            [
                PanicCallRequirementMatchId::named(0),
                PanicCallRequirementMatchId::named(1),
            ]
        );
        assert!(
            named_index
                .matches(&EvidenceClaimSelector::Unnamed)
                .is_empty()
        );
        assert!(
            named_index
                .matches(&EvidenceClaimSelector::Named(String::from(" --- ")))
                .is_empty()
        );
        assert!(
            named_index
                .matches(&EvidenceClaimSelector::Explicit(vec![String::from(
                    "panic.index-in-bounds"
                )]))
                .is_empty()
        );

        let altered = [named(0, "Index_In-Bounds", "ready")];
        assert!(CallRequirementIndex::new(&altered).is_err());
    }
}
