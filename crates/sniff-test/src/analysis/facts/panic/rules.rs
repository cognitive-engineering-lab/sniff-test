//! Pure root-specific evaluation rules for compiler assertions.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

use super::super::encoded::TableKind;
use super::super::evaluation::{
    DomainId, EvaluationCx, EvaluationInput, EvaluationIssueContext, EvaluationOutput,
    EvaluationRule, ObligationRecord, RelationTrace, RuleDescriptor, RuleError,
};
use super::super::evidence::{EvidenceSemanticOrder, EvidenceUseRecord, register_derived_once};
use super::super::human::markers::MarkerClaimEntity;
use super::super::human::{EvidenceAttachment, EvidenceClaimSelector};
use super::super::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use super::super::schema::{PassId, RowSchema};
use super::super::workspace::{ScopedEntityRef, ScopedRowRef};
use super::model::{
    MirAssertFact, MirAssertKind, PanicEvidenceMatch, PanicEvidenceOrdering, ReachableMirAssert,
    UnsatisfiedCompilerAssertIssue,
};
use super::render::UnsatisfiedCompilerAssertRenderer;

const PANIC_DOMAIN: &str = "sniff-test.panic";

#[must_use]
pub(crate) fn panic_domain() -> DomainId {
    DomainId::new(PANIC_DOMAIN).expect("the panic pack domain ID is static and valid")
}

fn evaluates_panic_domain<C: ?Sized>(cx: &EvaluationCx<'_, C>) -> bool {
    cx.root().domain.as_str() == PANIC_DOMAIN
}

fn is_compiler_assert_obligation(obligation: &ObligationRecord, domain: &DomainId) -> bool {
    obligation.domain() == domain && obligation.source().row().schema.as_str() == MirAssertFact::ID
}

struct CreateCompilerAssertObligations;

impl<C: ?Sized> EvaluationRule<C> for CreateCompilerAssertObligations {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new("sniff-test.panic.create-assert-obligations").unwrap())
            .read::<MirAssertFact>()
            .read::<ReachableMirAssert>()
            .write_derived::<ObligationRecord>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, C>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        if !evaluates_panic_domain(cx) {
            return Ok(());
        }
        let mut witness_identities = BTreeSet::new();
        for reached in input.derived_rows::<ReachableMirAssert>()? {
            let candidate = reached.data;
            if !witness_identities.insert((
                candidate.assertion().clone(),
                candidate.endpoint().clone(),
                candidate.trace().clone(),
                candidate.witness_order(),
            )) {
                return Err(RuleError::failed(
                    "reachable MIR assertions contain the same traversal witness more than once",
                ));
            }
            if candidate.trace().root() != &cx.root().entity {
                return Err(RuleError::failed(
                    "reachable MIR assertion trace does not start at the active root",
                ));
            }
            let fact = input.artifact_fact_at::<MirAssertFact>(candidate.assertion())?;
            let fact_scope = candidate.assertion().scope();
            let owner = fact.metadata.owner.as_ref().ok_or_else(|| {
                RuleError::failed("MIR assertion fact has no owning effect-site entity")
            })?;
            let owner = ScopedEntityRef::new(fact_scope.clone(), owner.clone());
            if candidate.trace().target() != &owner {
                return Err(RuleError::failed(
                    "reachable MIR assertion trace does not end at the fact owner",
                ));
            }
            if candidate.endpoint() != &owner {
                return Err(RuleError::failed(
                    "reachable MIR assertion endpoint does not match the fact owner",
                ));
            }
            if fact.metadata.requirements.is_empty() {
                return Err(RuleError::failed(
                    "MIR assertion fact has no precise or opaque compiler requirement",
                ));
            }
            let requirements = fact
                .metadata
                .requirements
                .iter()
                .cloned()
                .map(|requirement| ScopedRowRef::new(fact_scope.clone(), requirement))
                .collect();
            output.emit_obligation(
                &ObligationRecord::new(
                    cx.root().domain.clone(),
                    candidate.assertion().clone(),
                    candidate.endpoint().clone(),
                    requirements,
                    candidate.trace().target().clone(),
                    candidate.trace().clone(),
                )
                .with_witness_order(candidate.witness_order()),
            )?;
        }
        Ok(())
    }
}

struct MatchCompilerAssertEvidence;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CompilerAssertWitnessIdentity {
    source: ScopedRowRef,
    endpoint: ScopedEntityRef,
    trace_target: ScopedEntityRef,
    trace: RelationTrace,
    witness_order: u64,
}

impl CompilerAssertWitnessIdentity {
    fn from_obligation(obligation: &ObligationRecord) -> Self {
        Self {
            source: obligation.source().clone(),
            endpoint: obligation.endpoint().clone(),
            trace_target: obligation.trace_target().clone(),
            trace: obligation.trace().clone(),
            witness_order: obligation.witness_order(),
        }
    }

    fn from_attachment(attachment: &EvidenceAttachment) -> Self {
        Self {
            source: attachment.obligation_source().clone(),
            endpoint: attachment.endpoint().clone(),
            trace_target: attachment.trace().target().clone(),
            trace: attachment.trace().clone(),
            witness_order: attachment.witness_order(),
        }
    }

    fn from_ordering(ordering: &PanicEvidenceOrdering) -> Self {
        Self {
            source: ordering.obligation_source().clone(),
            endpoint: ordering.endpoint().clone(),
            trace_target: ordering.trace_target().clone(),
            trace: ordering.trace().clone(),
            witness_order: ordering.witness_order(),
        }
    }
}

struct CompilerAssertObligationIndex {
    by_witness: BTreeMap<CompilerAssertWitnessIdentity, ObligationRecord>,
    duplicate_witnesses: BTreeSet<CompilerAssertWitnessIdentity>,
}

struct CompilerAssertOrderingIndex {
    by_witness: BTreeMap<CompilerAssertWitnessIdentity, PanicEvidenceOrdering>,
}

impl CompilerAssertOrderingIndex {
    fn validate(
        input: &EvaluationInput<'_>,
        output: &EvaluationOutput<'_>,
        obligations: &CompilerAssertObligationIndex,
    ) -> Result<Self, RuleError> {
        if !obligations.duplicate_witnesses.is_empty() {
            return Err(RuleError::failed(
                "compiler-assert obligations repeat an exact witness identity",
            ));
        }
        let mut by_witness = BTreeMap::new();
        let mut traversal_orders = BTreeSet::new();
        for row in input.derived_rows::<PanicEvidenceOrdering>()? {
            let ordering = row.data;
            if ordering.obligation_source().row().schema.as_str() != MirAssertFact::ID {
                continue;
            }
            output.validate_row_reference(ordering.obligation_source(), Some(TableKind::Fact))?;
            output.validate_entity_reference(ordering.endpoint())?;
            output.validate_entity_reference(ordering.trace_target())?;
            output.validate_relation_trace(ordering.trace())?;
            if ordering.trace().target() != ordering.trace_target() {
                return Err(RuleError::failed(
                    "compiler-assert evidence ordering trace target was altered",
                ));
            }
            ordering
                .semantic_order()
                .validate()
                .map_err(RuleError::failed)?;
            let identity = CompilerAssertWitnessIdentity::from_ordering(&ordering);
            if !traversal_orders.insert(ordering.semantic_order().traversal_order()) {
                return Err(RuleError::failed(
                    "compiler-assert evidence orderings repeat an actual traversal order",
                ));
            }
            match by_witness.entry(identity) {
                Entry::Vacant(entry) => {
                    entry.insert(ordering);
                }
                Entry::Occupied(_) => {
                    return Err(RuleError::failed(
                        "compiler-assert evidence ordering repeats an exact witness identity",
                    ));
                }
            }
        }

        let obligation_keys = obligations.by_witness.keys().collect::<BTreeSet<_>>();
        let ordering_keys = by_witness.keys().collect::<BTreeSet<_>>();
        if let Some(missing) = obligation_keys.difference(&ordering_keys).next() {
            return Err(RuleError::failed(format!(
                "compiler-assert obligation has no evidence ordering sidecar: {missing:?}"
            )));
        }
        if let Some(orphan) = ordering_keys.difference(&obligation_keys).next() {
            return Err(RuleError::failed(format!(
                "compiler-assert evidence ordering has no active obligation: {orphan:?}"
            )));
        }
        Ok(Self { by_witness })
    }

    fn get(
        &self,
        identity: &CompilerAssertWitnessIdentity,
    ) -> Result<&PanicEvidenceOrdering, RuleError> {
        self.by_witness.get(identity).ok_or_else(|| {
            RuleError::failed("validated compiler-assert evidence ordering disappeared")
        })
    }
}

struct PendingEvidenceMatch {
    requirements: BTreeSet<ScopedRowRef>,
    semantic_order: EvidenceSemanticOrder,
}

impl CompilerAssertObligationIndex {
    fn new(obligations: impl IntoIterator<Item = ObligationRecord>) -> Self {
        let mut by_witness = BTreeMap::new();
        let mut duplicate_witnesses = BTreeSet::new();
        for obligation in obligations {
            let identity = CompilerAssertWitnessIdentity::from_obligation(&obligation);
            match by_witness.entry(identity) {
                Entry::Vacant(entry) => {
                    entry.insert(obligation);
                }
                Entry::Occupied(entry) => {
                    duplicate_witnesses.insert(entry.key().clone());
                }
            }
        }
        Self {
            by_witness,
            duplicate_witnesses,
        }
    }

    fn unique(
        &self,
        identity: &CompilerAssertWitnessIdentity,
    ) -> Result<&ObligationRecord, RuleError> {
        if self.duplicate_witnesses.contains(identity) {
            return Err(RuleError::failed(
                "compiler-assert evidence identifies more than one obligation witness",
            ));
        }
        self.by_witness.get(identity).ok_or_else(|| {
            RuleError::failed(
                "compiler-assert evidence does not identify an active obligation witness",
            )
        })
    }
}

impl<C: ?Sized> EvaluationRule<C> for MatchCompilerAssertEvidence {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new("sniff-test.panic.match-assert-evidence").unwrap())
            .read::<MarkerClaimEntity>()
            .read::<EvidenceAttachment>()
            .read::<ObligationRecord>()
            .read::<PanicEvidenceOrdering>()
            .write_derived::<PanicEvidenceMatch>()
            .write_derived::<EvidenceUseRecord>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, C>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        if !evaluates_panic_domain(cx) {
            return Ok(());
        }
        let obligations = input
            .derived_rows::<ObligationRecord>()?
            .into_iter()
            .map(|row| row.data)
            .filter(|obligation| is_compiler_assert_obligation(obligation, &cx.root().domain));
        let obligation_index = CompilerAssertObligationIndex::new(obligations);
        let ordering_index =
            CompilerAssertOrderingIndex::validate(input, output, &obligation_index)?;
        let mut matches = BTreeMap::<
            (
                ScopedEntityRef,
                ScopedRowRef,
                ScopedEntityRef,
                ScopedEntityRef,
                RelationTrace,
                u64,
            ),
            PendingEvidenceMatch,
        >::new();
        for attachment in input.derived_rows::<EvidenceAttachment>()? {
            let attachment = attachment.data;
            let claim = input.artifact_entity_at::<MarkerClaimEntity>(attachment.claim())?;
            if claim.key().domain() != &cx.root().domain {
                continue;
            }
            let Some(obligation) =
                validate_compiler_assert_attachment(&attachment, &obligation_index, output)?
            else {
                continue;
            };
            if claim.rationale().trim().is_empty() {
                continue;
            }
            let satisfied = matching_requirements(&claim, &attachment, obligation);
            if satisfied.is_empty() {
                continue;
            }
            let identity = CompilerAssertWitnessIdentity::from_attachment(&attachment);
            let semantic_order = ordering_index.get(&identity)?.semantic_order().clone();
            matches
                .entry((
                    attachment.claim().clone(),
                    attachment.obligation_source().clone(),
                    attachment.endpoint().clone(),
                    attachment.group().clone(),
                    attachment.trace().clone(),
                    attachment.witness_order(),
                ))
                .and_modify(|pending| pending.requirements.extend(satisfied.iter().cloned()))
                .or_insert(PendingEvidenceMatch {
                    requirements: satisfied,
                    semantic_order,
                });
        }
        for ((claim, source, endpoint, group, trace, witness_order), pending) in matches {
            let requirements = pending.requirements.into_iter().collect::<Vec<_>>();
            output.emit_derived(&PanicEvidenceMatch::new(
                claim.clone(),
                source.clone(),
                endpoint.clone(),
                group.clone(),
                trace.clone(),
                witness_order,
                requirements,
            ))?;
            output.emit_derived(&EvidenceUseRecord::new(
                cx.root().domain.clone(),
                claim,
                endpoint,
                group,
                source,
                trace,
                witness_order,
                pending.semantic_order,
            ))?;
        }
        Ok(())
    }
}

fn validate_compiler_assert_attachment<'a>(
    attachment: &EvidenceAttachment,
    obligations: &'a CompilerAssertObligationIndex,
    output: &EvaluationOutput<'_>,
) -> Result<Option<&'a ObligationRecord>, RuleError> {
    if attachment.obligation_source().row().schema.as_str() != MirAssertFact::ID {
        return Ok(None);
    }
    output.validate_row_reference(attachment.obligation_source(), Some(TableKind::Fact))?;
    output.validate_entity_reference(attachment.endpoint())?;
    output.validate_entity_reference(attachment.group())?;
    output.validate_relation_trace(attachment.trace())?;
    if attachment.trace().target() != attachment.endpoint() {
        return Err(RuleError::failed(
            "compiler-assert evidence trace does not end at its obligation endpoint",
        ));
    }
    if attachment.group() != attachment.endpoint() {
        return Err(RuleError::failed(
            "compiler-assert evidence group does not match its obligation endpoint",
        ));
    }
    for requirement in attachment.resolved_requirements() {
        output.validate_row_reference(requirement, Some(TableKind::Requirement))?;
    }
    let identity = CompilerAssertWitnessIdentity::from_attachment(attachment);
    let obligation = obligations.unique(&identity)?;
    if attachment.endpoint() != obligation.endpoint() {
        return Err(RuleError::failed(
            "compiler-assert evidence endpoint does not match its obligation endpoint",
        ));
    }
    if attachment
        .resolved_requirements()
        .iter()
        .any(|requirement| !obligation.requirements().contains(requirement))
    {
        return Err(RuleError::failed(
            "compiler-assert evidence names a requirement outside its obligation",
        ));
    }
    Ok(Some(obligation))
}

fn matching_requirements(
    claim: &MarkerClaimEntity,
    attachment: &EvidenceAttachment,
    obligation: &ObligationRecord,
) -> BTreeSet<ScopedRowRef> {
    match claim.selector() {
        EvidenceClaimSelector::Unnamed => obligation.requirements().iter().cloned().collect(),
        EvidenceClaimSelector::Named(_) | EvidenceClaimSelector::Explicit(_) => attachment
            .resolved_requirements()
            .iter()
            .filter(|requirement| obligation.requirements().contains(requirement))
            .cloned()
            .collect(),
    }
}

struct ReportUnsatisfiedCompilerAsserts;

#[derive(Clone)]
struct PendingUnsatisfied {
    assertion: ScopedRowRef,
    kind: MirAssertKind,
    trace: RelationTrace,
    witness_order: u64,
}

impl<C: ?Sized> EvaluationRule<C> for ReportUnsatisfiedCompilerAsserts {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new("sniff-test.panic.report-unsatisfied-asserts").unwrap())
            .read::<MirAssertFact>()
            .read::<ObligationRecord>()
            .read::<PanicEvidenceMatch>()
            .write_issue::<UnsatisfiedCompilerAssertIssue>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, C>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        if !evaluates_panic_domain(cx) {
            return Ok(());
        }
        let mut satisfied = BTreeMap::<
            (
                ScopedRowRef,
                ScopedEntityRef,
                ScopedEntityRef,
                RelationTrace,
                u64,
            ),
            BTreeSet<ScopedRowRef>,
        >::new();
        for evidence in input.derived_rows::<PanicEvidenceMatch>()? {
            satisfied
                .entry((
                    evidence.data.obligation_source().clone(),
                    evidence.data.endpoint().clone(),
                    evidence.data.group().clone(),
                    evidence.data.trace().clone(),
                    evidence.data.witness_order(),
                ))
                .or_default()
                .extend(evidence.data.satisfied_requirements().iter().cloned());
        }
        let mut pending =
            BTreeMap::<(ScopedEntityRef, Vec<ScopedRowRef>), PendingUnsatisfied>::new();
        for obligation in input.derived_rows::<ObligationRecord>()? {
            let obligation = obligation.data;
            if !is_compiler_assert_obligation(&obligation, &cx.root().domain) {
                continue;
            }
            let discharged = satisfied
                .get(&(
                    obligation.source().clone(),
                    obligation.endpoint().clone(),
                    obligation.endpoint().clone(),
                    obligation.trace().clone(),
                    obligation.witness_order(),
                ))
                .cloned()
                .unwrap_or_default();
            let missing = obligation
                .requirements()
                .iter()
                .filter(|requirement| !discharged.contains(*requirement))
                .cloned()
                .collect::<Vec<_>>();
            if missing.is_empty() {
                continue;
            }
            let fact = input
                .artifact_fact_at::<MirAssertFact>(obligation.source())?
                .fact
                .data;
            let candidate = PendingUnsatisfied {
                assertion: obligation.source().clone(),
                kind: fact.kind(),
                trace: obligation.trace().clone(),
                witness_order: obligation.witness_order(),
            };
            pending
                .entry((obligation.endpoint().clone(), missing))
                .and_modify(|existing| {
                    if canonical_trace_key(&candidate) < canonical_trace_key(existing) {
                        *existing = candidate.clone();
                    }
                })
                .or_insert(candidate);
        }
        for ((endpoint, missing), issue) in pending {
            output.emit_issue(
                &UnsatisfiedCompilerAssertIssue::new(
                    issue.assertion.clone(),
                    endpoint.clone(),
                    issue.kind,
                    issue.witness_order,
                    missing,
                ),
                EvaluationIssueContext::new(cx.root().clone())
                    .with_source(issue.assertion)
                    .with_endpoint(endpoint)
                    .with_trace(issue.trace),
            )?;
        }
        Ok(())
    }
}

fn canonical_trace_key(
    candidate: &PendingUnsatisfied,
) -> (u64, usize, &RelationTrace, &ScopedRowRef, MirAssertKind) {
    (
        candidate.witness_order,
        candidate.trace.relations().len(),
        &candidate.trace,
        &candidate.assertion,
        candidate.kind,
    )
}

/// Compile-time panic analysis pack for the MIR-assert vertical slice.
pub(crate) struct PanicPack;

impl<C: ?Sized> AnalysisPack<C> for PanicPack {
    fn register(&self, registry: &mut AnalysisRegistry<C>) -> Result<(), PackRegistrationError> {
        registry.register_derived::<ReachableMirAssert>()?;
        register_derived_once::<PanicEvidenceOrdering, C>(registry)?;
        register_derived_once::<ObligationRecord, C>(registry)?;
        registry.register_derived::<PanicEvidenceMatch>()?;
        register_derived_once::<EvidenceUseRecord, C>(registry)?;
        registry.register_issue::<UnsatisfiedCompilerAssertIssue>()?;
        registry.register_issue_renderer::<UnsatisfiedCompilerAssertIssue, _>(
            UnsatisfiedCompilerAssertRenderer,
        )?;
        registry.register_evaluation_rule(CreateCompilerAssertObligations)?;
        registry.register_evaluation_rule(MatchCompilerAssertEvidence)?;
        registry.register_evaluation_rule(ReportUnsatisfiedCompilerAsserts)?;
        Ok(())
    }
}

#[cfg(test)]
mod witness_index_tests {
    use super::*;
    use crate::analysis::facts::encoded::{EntityRef, RowRef};
    use crate::analysis::facts::schema::SchemaId;
    use crate::analysis::facts::workspace::ArtifactScopeId;

    fn obligation(endpoint_row: u32, witness_order: u64) -> ObligationRecord {
        let scope = ArtifactScopeId::new("test.panic.witness-index").unwrap();
        let source = ScopedRowRef::new(
            scope.clone(),
            RowRef {
                schema: SchemaId::new(MirAssertFact::ID).unwrap(),
                row: 0,
            },
        );
        let endpoint = ScopedEntityRef::new(
            scope.clone(),
            EntityRef {
                schema: SchemaId::new("test.panic.witness-endpoint").unwrap(),
                row: endpoint_row,
            },
        );
        ObligationRecord::new(
            panic_domain(),
            source,
            endpoint.clone(),
            Vec::new(),
            endpoint.clone(),
            RelationTrace::new(endpoint.clone(), endpoint, Vec::new()),
        )
        .with_witness_order(witness_order)
    }

    #[test]
    fn exact_witness_index_partitions_duplicates_and_reports_missing_identity() {
        let first = obligation(0, 0);
        let duplicate = first.clone();
        let unique = obligation(1, 1);
        let missing = obligation(1, 2);
        let obligations = [first, duplicate, unique, missing.clone()];
        let index = CompilerAssertObligationIndex::new(obligations[..3].iter().cloned());

        assert_eq!(index.by_witness.len(), 2);
        assert_eq!(index.duplicate_witnesses.len(), 1);
        assert_eq!(
            index
                .unique(&CompilerAssertWitnessIdentity::from_obligation(
                    &obligations[2],
                ))
                .unwrap(),
            &obligations[2]
        );
        assert!(
            index
                .unique(&CompilerAssertWitnessIdentity::from_obligation(
                    &obligations[0],
                ))
                .unwrap_err()
                .to_string()
                .contains("identifies more than one obligation witness")
        );
        assert!(
            index
                .unique(&CompilerAssertWitnessIdentity::from_obligation(&missing))
                .unwrap_err()
                .to_string()
                .contains("does not identify an active obligation witness")
        );
    }
}
