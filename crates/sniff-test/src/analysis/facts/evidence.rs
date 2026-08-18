//! Domain-neutral evidence-use coordination across analysis packs.
//!
//! Domain packs emit [`EvidenceUseRecord`] rows after a claim contributes to
//! one semantic obligation group. The coordinator observes every producer,
//! so ambiguity is computed once per root and domain rather than separately
//! inside panic, safety, or a future analysis pack.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::encoded::TableKind;
use super::evaluation::{
    DomainId, EvaluationCx, EvaluationInput, EvaluationIssueContext, EvaluationOutput,
    EvaluationRule, RelationTrace, RuleDescriptor, RuleError, deserialize_strict_relation_trace,
};
use super::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use super::program::topology::CallKind;
use super::render::{IssueRenderer, RenderCx, RenderedDiagnostic};
use super::schema::{DerivedSchema, IssueSchema, PassId, RowSchema, SchemaId};
use super::workspace::{ScopedEntityRef, ScopedRowRef};
use crate::analysis::facts::human::markers::{MarkerClaimEntity, MarkerOccurrenceEntity};
use crate::safety::SafetyOpKind;

/// File-independent presentation coordinates used to stabilize evidence paths.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct EvidenceSemanticSourceOrder {
    byte_start: u64,
    byte_end: u64,
}

impl EvidenceSemanticSourceOrder {
    #[must_use]
    pub(crate) const fn new(byte_start: u64, byte_end: u64) -> Self {
        Self {
            byte_start,
            byte_end,
        }
    }

    #[must_use]
    pub(crate) const fn byte_start(&self) -> u64 {
        self.byte_start
    }

    #[must_use]
    pub(crate) const fn byte_end(&self) -> u64 {
        self.byte_end
    }
}

/// Domain-neutral semantic edge ordering retained from the legacy interpreter.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    tag = "class",
    content = "kind",
    deny_unknown_fields
)]
pub(crate) enum EvidenceSemanticEdgeOrder {
    Reachability(CallKind),
    UnsafeOperation(SafetyOpKind),
}

impl Ord for EvidenceSemanticEdgeOrder {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Reachability(left), Self::Reachability(right)) => {
                call_kind_order(*left).cmp(&call_kind_order(*right))
            }
            (Self::Reachability(_), Self::UnsafeOperation(_)) => Ordering::Less,
            (Self::UnsafeOperation(_), Self::Reachability(_)) => Ordering::Greater,
            (Self::UnsafeOperation(left), Self::UnsafeOperation(right)) => {
                safety_operation_order(*left).cmp(&safety_operation_order(*right))
            }
        }
    }
}

impl PartialOrd for EvidenceSemanticEdgeOrder {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

const fn call_kind_order(kind: CallKind) -> u8 {
    match kind {
        CallKind::DirectCall => 0,
        CallKind::TailCall => 1,
        CallKind::FnPointerReify => 2,
        CallKind::ClosureFnPointerReify => 3,
        CallKind::FnPointerCallTarget => 4,
        CallKind::DynObjectCast => 5,
        CallKind::VTableEntry => 6,
        CallKind::DynDispatchVTableEntry => 7,
        CallKind::MacroExpansion => 8,
        CallKind::ConstBody => 9,
        CallKind::CoroutineBody => 10,
        CallKind::Assert => 11,
        CallKind::IndirectCall => 12,
    }
}

const fn safety_operation_order(kind: SafetyOpKind) -> u8 {
    match kind {
        SafetyOpKind::DerefRawPointer => 0,
        SafetyOpKind::UseOfMutableStatic => 1,
        SafetyOpKind::UseOfExternStatic => 2,
        SafetyOpKind::AccessToUnionField => 3,
        SafetyOpKind::UseOfUnsafeField => 4,
        SafetyOpKind::InitializingLayoutConstrainedType => 5,
        SafetyOpKind::InitializingTypeWithUnsafeField => 6,
        SafetyOpKind::MutationOfLayoutConstrainedField => 7,
        SafetyOpKind::BorrowOfLayoutConstrainedField => 8,
        SafetyOpKind::InlineAssembly => 9,
        SafetyOpKind::UnsafeBinderCast => 10,
    }
}

/// One public, presentation-stable step in an evidence witness path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct EvidenceSemanticStepOrder {
    caller: String,
    kind: EvidenceSemanticEdgeOrder,
    target: Option<String>,
    source: Option<EvidenceSemanticSourceOrder>,
}

impl EvidenceSemanticStepOrder {
    #[must_use]
    pub(crate) fn new(
        caller: impl Into<String>,
        kind: EvidenceSemanticEdgeOrder,
        target: Option<String>,
        source: Option<EvidenceSemanticSourceOrder>,
    ) -> Self {
        Self {
            caller: caller.into(),
            kind,
            target,
            source,
        }
    }

    #[must_use]
    pub(crate) fn caller(&self) -> &str {
        &self.caller
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> EvidenceSemanticEdgeOrder {
        self.kind
    }

    #[must_use]
    pub(crate) fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    #[must_use]
    pub(crate) const fn source(&self) -> Option<&EvidenceSemanticSourceOrder> {
        self.source.as_ref()
    }
}

fn semantic_step_order(
    left: &EvidenceSemanticStepOrder,
    right: &EvidenceSemanticStepOrder,
) -> Ordering {
    left.caller()
        .cmp(right.caller())
        .then_with(|| left.kind().cmp(&right.kind()))
        .then_with(|| left.target().cmp(&right.target()))
        .then_with(|| semantic_source_order(left.source(), right.source()))
}

fn semantic_source_order(
    left: Option<&EvidenceSemanticSourceOrder>,
    right: Option<&EvidenceSemanticSourceOrder>,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => {
            (left.byte_start(), left.byte_end()).cmp(&(right.byte_start(), right.byte_end()))
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Complete semantic path ordering plus its actual traversal-order tie-break.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct EvidenceSemanticOrder {
    steps: Vec<EvidenceSemanticStepOrder>,
    traversal_order: u64,
}

impl EvidenceSemanticOrder {
    #[must_use]
    pub(crate) const fn new(steps: Vec<EvidenceSemanticStepOrder>, traversal_order: u64) -> Self {
        Self {
            steps,
            traversal_order,
        }
    }

    #[must_use]
    pub(crate) fn steps(&self) -> &[EvidenceSemanticStepOrder] {
        &self.steps
    }

    #[must_use]
    pub(crate) const fn traversal_order(&self) -> u64 {
        self.traversal_order
    }

    /// Checks invariants that constructors cannot enforce after deserialization.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.steps().is_empty() {
            return Err("semantic evidence order has no steps");
        }
        if self.steps().iter().any(|step| {
            step.source()
                .is_some_and(|source| source.byte_start() > source.byte_end())
        }) {
            return Err("semantic evidence source range starts after it ends");
        }
        Ok(())
    }
}

impl Ord for EvidenceSemanticOrder {
    fn cmp(&self, other: &Self) -> Ordering {
        self.steps()
            .len()
            .cmp(&other.steps().len())
            .then_with(|| {
                self.steps()
                    .iter()
                    .zip(other.steps())
                    .find_map(|(left, right)| {
                        let ordering = semantic_step_order(left, right);
                        (!ordering.is_eq()).then_some(ordering)
                    })
                    .unwrap_or(Ordering::Equal)
            })
            .then_with(|| self.traversal_order().cmp(&other.traversal_order()))
    }
}

impl PartialOrd for EvidenceSemanticOrder {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// One human evidence claim contributing through one exact witness to one
/// semantic obligation group.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct EvidenceUseRecord {
    domain: DomainId,
    claim: ScopedEntityRef,
    endpoint: ScopedEntityRef,
    group: ScopedEntityRef,
    source: ScopedRowRef,
    #[serde(deserialize_with = "deserialize_strict_relation_trace")]
    trace: RelationTrace,
    witness_order: u64,
    semantic_order: EvidenceSemanticOrder,
}

impl RowSchema for EvidenceUseRecord {
    const ID: &'static str = "sniff-test.evidence.use";
    const VERSION: u32 = 4;
}

impl DerivedSchema for EvidenceUseRecord {}

impl EvidenceUseRecord {
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor deliberately mirrors the strict persisted row contract"
    )]
    pub(crate) const fn new(
        domain: DomainId,
        claim: ScopedEntityRef,
        endpoint: ScopedEntityRef,
        group: ScopedEntityRef,
        source: ScopedRowRef,
        trace: RelationTrace,
        witness_order: u64,
        semantic_order: EvidenceSemanticOrder,
    ) -> Self {
        Self {
            domain,
            claim,
            endpoint,
            group,
            source,
            trace,
            witness_order,
            semantic_order,
        }
    }

    #[must_use]
    pub(crate) const fn domain(&self) -> &DomainId {
        &self.domain
    }

    #[must_use]
    pub(crate) const fn claim(&self) -> &ScopedEntityRef {
        &self.claim
    }

    #[must_use]
    pub(crate) const fn endpoint(&self) -> &ScopedEntityRef {
        &self.endpoint
    }

    #[must_use]
    pub(crate) const fn group(&self) -> &ScopedEntityRef {
        &self.group
    }

    #[must_use]
    pub(crate) const fn source(&self) -> &ScopedRowRef {
        &self.source
    }

    #[must_use]
    pub(crate) const fn trace(&self) -> &RelationTrace {
        &self.trace
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) const fn semantic_order(&self) -> &EvidenceSemanticOrder {
        &self.semantic_order
    }
}

/// One physical marker occurrence was reused for more than one semantic group
/// in a root/domain, retaining the canonical witness that explains the issue.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct AmbiguousEvidenceReuseIssue {
    domain: DomainId,
    marker: ScopedEntityRef,
    witness_source: ScopedRowRef,
    witness_endpoint: ScopedEntityRef,
    witness_order: u64,
    groups: Vec<ScopedEntityRef>,
}

impl RowSchema for AmbiguousEvidenceReuseIssue {
    const ID: &'static str = "sniff-test.evidence.ambiguous-reuse";
    const VERSION: u32 = 3;
}

impl IssueSchema for AmbiguousEvidenceReuseIssue {}

impl AmbiguousEvidenceReuseIssue {
    fn new(
        domain: DomainId,
        marker: ScopedEntityRef,
        witness_source: ScopedRowRef,
        witness_endpoint: ScopedEntityRef,
        witness_order: u64,
        mut groups: Vec<ScopedEntityRef>,
    ) -> Self {
        groups.sort();
        groups.dedup();
        Self {
            domain,
            marker,
            witness_source,
            witness_endpoint,
            witness_order,
            groups,
        }
    }

    #[must_use]
    pub(crate) const fn domain(&self) -> &DomainId {
        &self.domain
    }

    #[must_use]
    pub(crate) const fn marker(&self) -> &ScopedEntityRef {
        &self.marker
    }

    #[must_use]
    pub(crate) const fn witness_source(&self) -> &ScopedRowRef {
        &self.witness_source
    }

    #[must_use]
    pub(crate) const fn witness_endpoint(&self) -> &ScopedEntityRef {
        &self.witness_endpoint
    }

    #[must_use]
    pub(crate) const fn witness_order(&self) -> u64 {
        self.witness_order
    }

    #[must_use]
    pub(crate) fn groups(&self) -> &[ScopedEntityRef] {
        &self.groups
    }
}

struct AmbiguousEvidenceReuseRenderer;

impl IssueRenderer<AmbiguousEvidenceReuseIssue> for AmbiguousEvidenceReuseRenderer {
    fn render(
        &self,
        issue: &AmbiguousEvidenceReuseIssue,
        _cx: &RenderCx<'_>,
    ) -> RenderedDiagnostic {
        let domain = issue
            .domain()
            .as_str()
            .rsplit_once('.')
            .map_or(issue.domain().as_str(), |(_, domain)| domain);
        let mut diagnostic = RenderedDiagnostic::new("human evidence marker is ambiguous");
        diagnostic.notes.push(format!(
            "this evidence marker applies to {} distinct {domain} obligation groups",
            issue.groups().len()
        ));
        diagnostic.help.push(String::from(
            "move the marker directly above one obligation, or split it into separate markers",
        ));
        diagnostic.sort_key.push(String::from(domain));
        diagnostic
    }
}

fn canonical_evidence_use<'a>(
    uses: impl IntoIterator<Item = &'a EvidenceUseRecord>,
) -> Option<&'a EvidenceUseRecord> {
    uses.into_iter()
        .min_by(|left, right| canonical_evidence_use_order(left, right))
}

fn canonical_evidence_use_order(left: &EvidenceUseRecord, right: &EvidenceUseRecord) -> Ordering {
    left.semantic_order()
        .cmp(right.semantic_order())
        .then_with(|| left.trace().cmp(right.trace()))
        .then_with(|| left.source().cmp(right.source()))
        .then_with(|| left.endpoint().cmp(right.endpoint()))
        .then_with(|| left.witness_order().cmp(&right.witness_order()))
        .then_with(|| left.claim().cmp(right.claim()))
}

struct PendingAmbiguousEvidenceReuse {
    issue: AmbiguousEvidenceReuseIssue,
    context: EvaluationIssueContext,
}

struct DetectEvidenceReuse;

impl<C: ?Sized> EvaluationRule<C> for DetectEvidenceReuse {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new("sniff-test.evidence.detect-reuse").unwrap())
            .read::<EvidenceUseRecord>()
            .read::<MarkerClaimEntity>()
            .read::<MarkerOccurrenceEntity>()
            .write_issue::<AmbiguousEvidenceReuseIssue>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, C>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        let mut uses_by_marker =
            BTreeMap::<(DomainId, ScopedEntityRef), Vec<EvidenceUseRecord>>::new();
        for usage in input.derived_rows::<EvidenceUseRecord>()? {
            if &usage.root != cx.root() {
                return Err(RuleError::failed(
                    "evidence use belongs to a different evaluation root",
                ));
            }
            if usage.data.domain() != &cx.root().domain {
                return Err(RuleError::failed(
                    "evidence use domain does not match the active root",
                ));
            }
            output.validate_entity_reference(usage.data.claim())?;
            output.validate_row_reference(usage.data.source(), None)?;
            output.validate_entity_reference(usage.data.endpoint())?;
            output.validate_entity_reference(usage.data.group())?;
            output.validate_relation_trace(usage.data.trace())?;
            usage
                .data
                .semantic_order()
                .validate()
                .map_err(RuleError::failed)?;

            let claim = input.artifact_entity_at::<MarkerClaimEntity>(usage.data.claim())?;
            if claim.key().domain() != usage.data.domain() {
                return Err(RuleError::failed(
                    "evidence claim domain does not match its use domain",
                ));
            }
            let marker = input
                .artifact_entity_by_key::<MarkerOccurrenceEntity>(
                    usage.data.claim().scope(),
                    claim.key().occurrence(),
                )?
                .ok_or_else(|| {
                    RuleError::failed(
                        "evidence claim references a missing physical marker occurrence",
                    )
                })?;
            output.validate_entity_reference(&marker)?;
            uses_by_marker
                .entry((usage.data.domain().clone(), marker))
                .or_default()
                .push(usage.data);
        }
        let mut pending = Vec::new();
        for ((domain, marker), uses) in uses_by_marker {
            let groups = uses
                .iter()
                .map(|usage| usage.group().clone())
                .collect::<BTreeSet<_>>();
            if groups.len() < 2 {
                continue;
            }
            let Some(canonical) = canonical_evidence_use(&uses) else {
                return Err(RuleError::failed(
                    "ambiguous evidence grouping lost every contributing use record",
                ));
            };
            pending.push(PendingAmbiguousEvidenceReuse {
                issue: AmbiguousEvidenceReuseIssue::new(
                    domain,
                    marker.clone(),
                    canonical.source().clone(),
                    canonical.endpoint().clone(),
                    canonical.witness_order(),
                    groups.into_iter().collect(),
                ),
                context: EvaluationIssueContext::new(cx.root().clone())
                    .with_source(marker.as_row())
                    .with_endpoint(canonical.endpoint().clone())
                    .with_trace(canonical.trace().clone()),
            });
        }
        for pending in pending {
            output.emit_issue(&pending.issue, pending.context)?;
        }
        Ok(())
    }
}

/// Installs root/domain-wide evidence-reuse coordination once.
pub(crate) struct EvidenceCoordinatorPack;

impl<C: ?Sized> AnalysisPack<C> for EvidenceCoordinatorPack {
    fn register(&self, registry: &mut AnalysisRegistry<C>) -> Result<(), PackRegistrationError> {
        register_derived_once::<EvidenceUseRecord, C>(registry)?;
        register_issue_once::<AmbiguousEvidenceReuseIssue, C>(registry)?;
        registry.register_issue_renderer::<AmbiguousEvidenceReuseIssue, _>(
            AmbiguousEvidenceReuseRenderer,
        )?;
        registry.register_evaluation_rule(DetectEvidenceReuse)?;
        Ok(())
    }
}

pub(super) fn register_derived_once<D: DerivedSchema, C: ?Sized>(
    registry: &mut AnalysisRegistry<C>,
) -> Result<(), PackRegistrationError> {
    let schema =
        SchemaId::new(D::ID).map_err(|error| PackRegistrationError::invalid(error.to_string()))?;
    let Some(existing) = registry.schemas().descriptor(&schema) else {
        return registry.register_derived::<D>();
    };
    registry.schemas().descriptor_for::<D>()?;
    if existing.kind() != TableKind::Derived {
        return Err(PackRegistrationError::invalid(format!(
            "shared schema {schema} is {:?}, expected Derived",
            existing.kind()
        )));
    }
    Ok(())
}

fn register_issue_once<I: IssueSchema, C: ?Sized>(
    registry: &mut AnalysisRegistry<C>,
) -> Result<(), PackRegistrationError> {
    let schema =
        SchemaId::new(I::ID).map_err(|error| PackRegistrationError::invalid(error.to_string()))?;
    let Some(existing) = registry.schemas().descriptor(&schema) else {
        return registry.register_issue::<I>();
    };
    registry.schemas().descriptor_for::<I>()?;
    if existing.kind() != TableKind::Issue {
        return Err(PackRegistrationError::invalid(format!(
            "shared schema {schema} is {:?}, expected Issue",
            existing.kind()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
