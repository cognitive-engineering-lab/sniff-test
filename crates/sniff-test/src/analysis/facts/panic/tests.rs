use serde::{Deserialize, Serialize};
use serde_json::json;

use super::model::{
    AlignedPointerRequirement, BinaryOverflowOperation, CompilerAssertRequirement,
    CoroutineStateRequirement, CoroutineTerminalState, InBoundsRequirement, MirAssertFact,
    MirAssertKind, NoOverflowRequirement, NonNullPointerRequirement, NonZeroRequirement,
    OpaqueCompilerRequirement, OverflowOperation, PanicEvidenceMatch, PanicEvidenceOrdering,
    ReachableMirAssert, UnsatisfiedCompilerAssertIssue, ValidEnumRequirement,
};
use super::rules::{PanicPack, panic_domain};
use super::{coarse_public_assert_kind, compiler_assert_presentation};
use crate::analysis::facts::builder::{ArtifactDbBuilder, FactMeta};
use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
use crate::analysis::facts::composition::{
    CompositionRelationBuilder, CompositionRelationDb, CompositionRelationRegistry,
    WorkspaceEvaluationView, WorkspaceRelationRef,
};
use crate::analysis::facts::encoded::{ArtifactFactIr, EntityRef, FACT_IR_FORMAT_VERSION, RowRef};
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationDb, EvaluationInput, EvaluationOutput, EvaluationPipelineError,
    EvaluationResults, EvaluationRoot, EvaluationRule, ObligationRecord, RelationTrace,
    RuleDescriptor, RuleError,
};
use crate::analysis::facts::evidence::{
    AmbiguousEvidenceReuseIssue, EvidenceCoordinatorPack, EvidenceSemanticEdgeOrder,
    EvidenceSemanticOrder, EvidenceSemanticSourceOrder, EvidenceSemanticStepOrder,
    EvidenceUseRecord,
};
use crate::analysis::facts::human::markers::{
    MarkerClaimEntity, MarkerClaimKey, MarkerOccurrenceEntity, MarkerOccurrenceKey,
};
use crate::analysis::facts::human::{EvidenceAttachment, EvidenceClaimSelector, HumanEvidencePack};
use crate::analysis::facts::pack::{AnalysisPack, AnalysisRegistry, PackRegistrationError};
use crate::analysis::facts::pass::{
    ArtifactPass, PassDescriptor, PassError, PassInput, PassOutput,
};
use crate::analysis::facts::program::SourceAnchorKey;
use crate::analysis::facts::program::topology::CallKind;
use crate::analysis::facts::render::{RelationPresentation, RelationPresenter, RenderCx};
use crate::analysis::facts::schema::{
    CompositionRelationSchema, EntitySchema, FactSchema, PassId, RelationSchema, RowSchema,
    SchemaId,
};
use crate::analysis::facts::view::{ArtifactDbView, IndexedRow, TypedFact};
use crate::analysis::facts::workspace::{
    ArtifactScopeId, ScopedEntityRef, ScopedRelationRef, ScopedRowRef, WorkspaceFactView,
};
use crate::panics::CompilerAssertKind;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct TestNode {
    name: String,
}

impl RowSchema for TestNode {
    const ID: &'static str = "test.panic.node";
    const VERSION: u32 = 1;
}

impl EntitySchema for TestNode {
    type Key = String;

    fn key(&self) -> Self::Key {
        self.name.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ForeignPanicFact;

impl RowSchema for ForeignPanicFact {
    const ID: &'static str = "test.panic.foreign-obligation-source";
    const VERSION: u32 = 1;
}

impl FactSchema for ForeignPanicFact {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct TestReachabilityEdge;

impl RowSchema for TestReachabilityEdge {
    const ID: &'static str = "test.panic.reaches";
    const VERSION: u32 = 1;
}

impl RelationSchema for TestReachabilityEdge {
    type From = TestNode;
    type To = TestNode;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ResolvesDependencyAssert;

impl RowSchema for ResolvesDependencyAssert {
    const ID: &'static str = "test.panic.resolves-dependency-assert";
    const VERSION: u32 = 1;
}

impl RelationSchema for ResolvesDependencyAssert {
    type From = TestNode;
    type To = TestNode;
}

impl CompositionRelationSchema for ResolvesDependencyAssert {}

struct TestReachabilityPresenter;

impl RelationPresenter<TestReachabilityEdge> for TestReachabilityPresenter {
    fn present(
        &self,
        _relation: &TestReachabilityEdge,
        _cx: &RenderCx<'_>,
    ) -> RelationPresentation {
        RelationPresentation::new("reaches compiler assertion")
    }
}

#[derive(Clone)]
struct FixtureConfig {
    reachability: ReachabilityInput,
    assertion_count: usize,
    claim: Option<MarkerClaimEntity>,
    attachment_coverage: AttachmentCoverage,
    witness_order: WitnessOrder,
    requirement_attachment: RequirementAttachment,
    ordering_coverage: OrderingCoverage,
    extra_input: ExtraFixtureInput,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReachabilityInput {
    Reachable,
    ConvergingPaths,
    DuplicateTraceStates,
    Unreachable,
    MismatchedEndpoint,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AttachmentCoverage {
    EveryWitness,
    FirstWitnessOnly,
    MalformedFirstWitness,
    MismatchedGroupFirstWitness,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WitnessOrder {
    TraceOrder,
    ReverseTraceOrder,
    AllZero,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RequirementAttachment {
    Unlinked,
    Linked,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OrderingCoverage {
    Exact,
    MissingLast,
    DuplicateFirst,
    Orphan,
    TamperedTraceTarget,
    EmptySemanticOrder,
    ReversedSourceRange,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ExtraFixtureInput {
    None,
    SameDomainForeignObligation,
    EvidenceUseFromAnotherProducer,
}

struct FixtureArtifactPass {
    config: FixtureConfig,
}

impl ArtifactPass<()> for FixtureArtifactPass {
    fn descriptor(&self) -> PassDescriptor {
        PassDescriptor::new(PassId::new("test.panic.collect").unwrap()).with_writes([
            SchemaId::new(TestNode::ID).unwrap(),
            SchemaId::new(TestReachabilityEdge::ID).unwrap(),
            SchemaId::new(MirAssertFact::ID).unwrap(),
            SchemaId::new(ForeignPanicFact::ID).unwrap(),
            SchemaId::new(MarkerOccurrenceEntity::ID).unwrap(),
            SchemaId::new(MarkerClaimEntity::ID).unwrap(),
            SchemaId::new(NonZeroRequirement::ID).unwrap(),
            SchemaId::new(InBoundsRequirement::ID).unwrap(),
            SchemaId::new(NoOverflowRequirement::ID).unwrap(),
            SchemaId::new(OpaqueCompilerRequirement::ID).unwrap(),
        ])
    }

    fn run(
        &mut self,
        _cx: &(),
        _input: PassInput<'_>,
        output: &mut PassOutput<'_>,
    ) -> Result<(), PassError> {
        let root = output.insert_entity(&TestNode {
            name: String::from("root"),
        })?;
        let requirement = output.insert_requirement(&NonZeroRequirement::new())?;
        if self.config.extra_input == ExtraFixtureInput::SameDomainForeignObligation {
            let meta = output.fact_meta();
            let meta = output.with_fact_owner(meta, &root)?;
            let meta = output.with_fact_requirement(meta, &requirement)?;
            output.insert_fact(&ForeignPanicFact, meta)?;
        }
        for index in 0..self.config.assertion_count {
            let target = output.insert_entity(&TestNode {
                name: format!("assertion-{index}"),
            })?;
            let meta = output.fact_meta();
            let meta = output.with_fact_owner(meta, &target)?;
            let meta = output.with_fact_requirement(meta, &requirement)?;
            output.insert_fact(&MirAssertFact::new(MirAssertKind::DivisionByZero), meta)?;
            if self.config.reachability == ReachabilityInput::ConvergingPaths {
                for route in ["a-marked-route", "z-unmarked-route"] {
                    let route = output.insert_entity(&TestNode {
                        name: format!("{route}-{index}"),
                    })?;
                    output.relate(&root, &route, &TestReachabilityEdge)?;
                    output.relate(&route, &target, &TestReachabilityEdge)?;
                }
            } else {
                output.relate(&root, &target, &TestReachabilityEdge)?;
            }
        }
        if let Some(claim) = &self.config.claim {
            output.insert_entity(&MarkerOccurrenceEntity::new(
                claim.key().occurrence().clone(),
                Vec::new(),
            ))?;
            output.insert_entity(claim)?;
        }
        Ok(())
    }
}

struct FixtureInputRule {
    config: FixtureConfig,
}

struct DependencyInputRule {
    reachable: ReachableMirAssert,
    attachment: EvidenceAttachment,
}

impl EvaluationRule<()> for DependencyInputRule {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new("test.panic.dependency-input").unwrap())
            .write_derived::<ReachableMirAssert>()
            .write_derived::<PanicEvidenceOrdering>()
            .write_derived::<EvidenceAttachment>()
    }

    fn evaluate(
        &self,
        _cx: &EvaluationCx<'_, ()>,
        _input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        output.emit_derived(&self.reachable)?;
        output.emit_derived(&PanicEvidenceOrdering::new(
            self.reachable.assertion().clone(),
            self.reachable.endpoint().clone(),
            self.reachable.trace().target().clone(),
            self.reachable.trace().clone(),
            self.reachable.witness_order(),
            fixture_semantic_order(self.reachable.trace(), 0),
        ))?;
        output.emit_derived(&self.attachment)
    }
}

impl EvaluationRule<()> for FixtureInputRule {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new("test.panic.workspace-input").unwrap())
            .read::<MirAssertFact>()
            .read::<ForeignPanicFact>()
            .read::<MarkerClaimEntity>()
            .read::<NonZeroRequirement>()
            .read::<TestNode>()
            .read::<TestReachabilityEdge>()
            .write_derived::<ReachableMirAssert>()
            .write_derived::<PanicEvidenceOrdering>()
            .write_derived::<EvidenceAttachment>()
            .write_derived::<EvidenceUseRecord>()
            .write_derived::<ObligationRecord>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, ()>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        let scope = cx.root().entity.scope().clone();
        let assertions = input.artifact_facts::<MirAssertFact>()?;
        let reachable = self.reachable_assertions(cx, input, &assertions)?;
        for candidate in &reachable {
            output.emit_derived(candidate)?;
        }
        for ordering in &self.fixture_orderings(cx, &reachable)? {
            output.emit_derived(ordering)?;
        }
        let linked = (self.config.requirement_attachment == RequirementAttachment::Linked)
            .then(|| {
                input.artifact_rows::<NonZeroRequirement>().map(|rows| {
                    rows.into_iter()
                        .map(|row| ScopedRowRef::new(scope.clone(), row.reference))
                        .collect::<Vec<_>>()
                })
            })
            .transpose()?
            .unwrap_or_default();
        let claims = input.artifact_rows::<MarkerClaimEntity>()?;
        self.emit_claim_attachments(cx, output, &scope, &reachable, &claims, &linked)?;
        Self::emit_foreign_obligations(cx, input, output, &scope, &claims, &linked)?;
        self.emit_extra_evidence_use(cx, output, &scope, &reachable, &claims)?;
        Ok(())
    }
}

impl FixtureInputRule {
    fn fixture_orderings(
        &self,
        cx: &EvaluationCx<'_, ()>,
        reachable: &[ReachableMirAssert],
    ) -> Result<Vec<PanicEvidenceOrdering>, RuleError> {
        let mut orderings = reachable
            .iter()
            .enumerate()
            .map(|(traversal_order, candidate)| {
                let traversal_order = u64::try_from(traversal_order)
                    .map_err(|_| RuleError::failed("fixture traversal order exceeds u64"))?;
                Ok(fixture_ordering(candidate, traversal_order))
            })
            .collect::<Result<Vec<_>, RuleError>>()?;
        let Some(first) = reachable.first() else {
            return Ok(orderings);
        };
        match self.config.ordering_coverage {
            OrderingCoverage::Exact => {}
            OrderingCoverage::MissingLast => {
                orderings.pop();
            }
            OrderingCoverage::DuplicateFirst => orderings.push(fixture_ordering(first, 100)),
            OrderingCoverage::Orphan => orderings.push(PanicEvidenceOrdering::new(
                first.assertion().clone(),
                first.endpoint().clone(),
                first.trace().target().clone(),
                first.trace().clone(),
                first.witness_order() + 100,
                fixture_semantic_order(first.trace(), 100),
            )),
            OrderingCoverage::TamperedTraceTarget => {
                orderings[0] = PanicEvidenceOrdering::new(
                    first.assertion().clone(),
                    first.endpoint().clone(),
                    cx.root().entity.clone(),
                    first.trace().clone(),
                    first.witness_order(),
                    fixture_semantic_order(first.trace(), 0),
                );
            }
            OrderingCoverage::EmptySemanticOrder => {
                orderings[0] = PanicEvidenceOrdering::new(
                    first.assertion().clone(),
                    first.endpoint().clone(),
                    first.trace().target().clone(),
                    first.trace().clone(),
                    first.witness_order(),
                    EvidenceSemanticOrder::new(Vec::new(), 0),
                );
            }
            OrderingCoverage::ReversedSourceRange => {
                orderings[0] = PanicEvidenceOrdering::new(
                    first.assertion().clone(),
                    first.endpoint().clone(),
                    first.trace().target().clone(),
                    first.trace().clone(),
                    first.witness_order(),
                    EvidenceSemanticOrder::new(
                        vec![EvidenceSemanticStepOrder::new(
                            "z-fixture",
                            EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert),
                            Some(String::from("compiler assert division by zero")),
                            Some(EvidenceSemanticSourceOrder::new(2, 1)),
                        )],
                        0,
                    ),
                );
            }
        }
        Ok(orderings)
    }

    fn emit_claim_attachments(
        &self,
        cx: &EvaluationCx<'_, ()>,
        output: &mut EvaluationOutput<'_>,
        scope: &ArtifactScopeId,
        reachable: &[ReachableMirAssert],
        claims: &[IndexedRow<MarkerClaimEntity>],
        linked: &[ScopedRowRef],
    ) -> Result<(), RuleError> {
        for claim in claims {
            let attachment_count = match self.config.attachment_coverage {
                AttachmentCoverage::EveryWitness => reachable.len(),
                AttachmentCoverage::FirstWitnessOnly
                | AttachmentCoverage::MalformedFirstWitness
                | AttachmentCoverage::MismatchedGroupFirstWitness => {
                    usize::from(!reachable.is_empty())
                }
            };
            for candidate in reachable.iter().take(attachment_count) {
                let endpoint = if self.config.attachment_coverage
                    == AttachmentCoverage::MalformedFirstWitness
                {
                    cx.root().entity.clone()
                } else {
                    candidate.endpoint().clone()
                };
                let claim = ScopedEntityRef::new(
                    scope.clone(),
                    EntityRef {
                        schema: claim.reference.schema.clone(),
                        row: claim.reference.row,
                    },
                );
                let group = if self.config.attachment_coverage
                    == AttachmentCoverage::MismatchedGroupFirstWitness
                {
                    cx.root().entity.clone()
                } else {
                    endpoint.clone()
                };
                output.emit_derived(&EvidenceAttachment::new_for_test(
                    claim,
                    candidate.assertion().clone(),
                    endpoint,
                    group,
                    candidate.trace().clone(),
                    candidate.witness_order(),
                    linked.to_vec(),
                ))?;
            }
        }
        Ok(())
    }

    fn emit_foreign_obligations(
        cx: &EvaluationCx<'_, ()>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
        scope: &ArtifactScopeId,
        claims: &[IndexedRow<MarkerClaimEntity>],
        linked: &[ScopedRowRef],
    ) -> Result<(), RuleError> {
        for foreign in input.artifact_facts::<ForeignPanicFact>()? {
            let source = ScopedRowRef::new(scope.clone(), foreign.fact.reference);
            let requirements = foreign
                .metadata
                .requirements
                .into_iter()
                .map(|requirement| ScopedRowRef::new(scope.clone(), requirement))
                .collect();
            let trace = RelationTrace::new(
                cx.root().entity.clone(),
                cx.root().entity.clone(),
                Vec::new(),
            );
            output.emit_obligation(&ObligationRecord::new(
                panic_domain(),
                source.clone(),
                cx.root().entity.clone(),
                requirements,
                cx.root().entity.clone(),
                trace.clone(),
            ))?;
            for claim in claims {
                let claim = ScopedEntityRef::new(
                    scope.clone(),
                    EntityRef {
                        schema: claim.reference.schema.clone(),
                        row: claim.reference.row,
                    },
                );
                output.emit_derived(&EvidenceAttachment::new_for_test(
                    claim,
                    source.clone(),
                    cx.root().entity.clone(),
                    cx.root().entity.clone(),
                    trace.clone(),
                    0,
                    linked.to_vec(),
                ))?;
            }
        }
        Ok(())
    }

    fn emit_extra_evidence_use(
        &self,
        cx: &EvaluationCx<'_, ()>,
        output: &mut EvaluationOutput<'_>,
        scope: &ArtifactScopeId,
        reachable: &[ReachableMirAssert],
        claims: &[IndexedRow<MarkerClaimEntity>],
    ) -> Result<(), RuleError> {
        if self.config.extra_input == ExtraFixtureInput::EvidenceUseFromAnotherProducer {
            let claim = claims
                .first()
                .expect("legacy fixture has one evidence claim");
            let claim = ScopedEntityRef::new(
                scope.clone(),
                EntityRef {
                    schema: claim.reference.schema.clone(),
                    row: claim.reference.row,
                },
            );
            assert!(
                !reachable.is_empty(),
                "the cross-producer evidence-use fixture has one reachable assertion"
            );
            let endpoint = cx.root().entity.clone();
            let group = endpoint.clone();
            let trace = RelationTrace::new(endpoint.clone(), endpoint.clone(), Vec::new());
            let source = claim.as_row();
            output.emit_derived(&EvidenceUseRecord::new(
                panic_domain(),
                claim,
                endpoint,
                group,
                source,
                trace,
                u64::MAX,
                EvidenceSemanticOrder::new(
                    vec![EvidenceSemanticStepOrder::new(
                        "a-extra",
                        EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert),
                        Some(String::from("compiler assert division by zero")),
                        None,
                    )],
                    u64::MAX,
                ),
            ))?;
        }
        Ok(())
    }
}

fn fixture_semantic_order(trace: &RelationTrace, traversal_order: u64) -> EvidenceSemanticOrder {
    let last = trace.relations().len().saturating_sub(1);
    let steps = trace
        .relations()
        .iter()
        .enumerate()
        .map(|(index, relation)| {
            EvidenceSemanticStepOrder::new(
                format!("z-fixture-{relation:?}"),
                EvidenceSemanticEdgeOrder::Reachability(if index == last {
                    CallKind::Assert
                } else {
                    CallKind::DirectCall
                }),
                Some(format!("fixture-target-{}", trace.target().entity().row)),
                None,
            )
        })
        .collect();
    EvidenceSemanticOrder::new(steps, traversal_order)
}

fn fixture_ordering(candidate: &ReachableMirAssert, traversal_order: u64) -> PanicEvidenceOrdering {
    PanicEvidenceOrdering::new(
        candidate.assertion().clone(),
        candidate.endpoint().clone(),
        candidate.trace().target().clone(),
        candidate.trace().clone(),
        candidate.witness_order(),
        fixture_semantic_order(candidate.trace(), traversal_order),
    )
}

impl FixtureInputRule {
    fn reachable_assertions(
        &self,
        cx: &EvaluationCx<'_, ()>,
        input: &EvaluationInput<'_>,
        assertions: &[TypedFact<MirAssertFact>],
    ) -> Result<Vec<ReachableMirAssert>, RuleError> {
        if self.config.reachability == ReachabilityInput::Unreachable {
            return Ok(Vec::new());
        }
        let scope = cx.root().entity.scope();
        let relations = input.artifact_relations::<TestReachabilityEdge>()?;
        let mut reachable = Vec::new();
        for assertion in assertions {
            let target_ref = assertion
                .metadata
                .owner
                .clone()
                .expect("fixture assertion has an owner");
            let target = ScopedEntityRef::new(scope.clone(), target_ref.clone());
            let traces = if self.config.reachability == ReachabilityInput::ConvergingPaths {
                relations
                    .iter()
                    .filter(|relation| relation.from.erase() == *cx.root().entity.entity())
                    .map(|first| {
                        let second = relations
                            .iter()
                            .find(|relation| {
                                relation.from == first.to && relation.to.erase() == target_ref
                            })
                            .expect("each converging route reaches the assertion");
                        RelationTrace::new(
                            cx.root().entity.clone(),
                            target.clone(),
                            [first, second]
                                .into_iter()
                                .map(|relation| {
                                    WorkspaceRelationRef::Artifact(ScopedRelationRef::new(
                                        scope.clone(),
                                        relation.relation.clone(),
                                    ))
                                })
                                .collect(),
                        )
                    })
                    .collect::<Vec<_>>()
            } else {
                let relation = relations
                    .iter()
                    .find(|relation| relation.to.erase() == target_ref)
                    .expect("fixture assertion has a reachability edge");
                vec![RelationTrace::new(
                    cx.root().entity.clone(),
                    target.clone(),
                    vec![WorkspaceRelationRef::Artifact(ScopedRelationRef::new(
                        scope.clone(),
                        relation.relation.clone(),
                    ))],
                )]
            };
            for trace in traces {
                let endpoint = if self.config.reachability == ReachabilityInput::MismatchedEndpoint
                {
                    cx.root().entity.clone()
                } else {
                    target.clone()
                };
                reachable.push(ReachableMirAssert::new(
                    ScopedRowRef::new(scope.clone(), assertion.fact.reference.clone()),
                    endpoint,
                    trace,
                    0,
                ));
            }
        }
        reachable.sort_by(|left, right| left.trace().cmp(right.trace()));
        if self.config.reachability == ReachabilityInput::DuplicateTraceStates {
            let duplicate = reachable
                .first()
                .expect("duplicate-state fixture has one reachable assertion")
                .clone();
            reachable.push(duplicate);
        }
        let last = reachable.len().saturating_sub(1);
        Ok(reachable
            .into_iter()
            .enumerate()
            .map(|(index, candidate)| {
                let index = match self.config.witness_order {
                    WitnessOrder::TraceOrder => index,
                    WitnessOrder::ReverseTraceOrder => last - index,
                    WitnessOrder::AllZero => 0,
                };
                candidate.with_witness_order(
                    u64::try_from(index).expect("fixture witness count fits in u64"),
                )
            })
            .collect())
    }
}

struct FixturePack {
    config: FixtureConfig,
}

impl AnalysisPack<()> for FixturePack {
    fn register(&self, registry: &mut AnalysisRegistry<()>) -> Result<(), PackRegistrationError> {
        registry.register_entity::<TestNode>()?;
        registry.register_fact::<ForeignPanicFact>()?;
        registry.register_relation::<TestReachabilityEdge>()?;
        registry
            .register_relation_presenter::<TestReachabilityEdge, _>(TestReachabilityPresenter)?;
        registry.register_artifact_pass(FixtureArtifactPass {
            config: self.config.clone(),
        })?;
        registry.register_evaluation_rule(FixtureInputRule {
            config: self.config.clone(),
        })?;
        Ok(())
    }
}

struct FinishedFixture {
    registry: AnalysisRegistry<()>,
    artifact: ArtifactFactIr,
    results: EvaluationResults,
}

struct FixtureEvaluation {
    registry: AnalysisRegistry<()>,
    artifact: ArtifactFactIr,
    evaluated: EvaluationDb,
    outcome: Result<(), EvaluationPipelineError>,
}

fn run_fixture(config: FixtureConfig) -> FinishedFixture {
    let FixtureEvaluation {
        registry,
        artifact,
        evaluated,
        outcome,
    } = evaluate_fixture(config);
    outcome.unwrap();
    let results = evaluated.finish().unwrap();
    FinishedFixture {
        registry,
        artifact,
        results,
    }
}

fn evaluate_fixture(config: FixtureConfig) -> FixtureEvaluation {
    let mut registry = AnalysisRegistry::<()>::new();
    registry.install(&CollectedArtifactSchemaPack).unwrap();
    registry.install(&HumanEvidencePack).unwrap();
    registry.install(&EvidenceCoordinatorPack).unwrap();
    registry.install(&PanicPack).unwrap();
    registry.install(&FixturePack { config }).unwrap();
    let mut builder = crate::analysis::facts::builder::ArtifactDbBuilder::new();
    registry.run_artifact_passes(&(), &mut builder).unwrap();
    let artifact = builder.finalize(registry.schemas()).unwrap();
    let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
    let root = view
        .entity_id_by_key::<TestNode>(&String::from("root"))
        .unwrap()
        .unwrap();
    let root = EvaluationRoot::new(
        panic_domain(),
        ScopedEntityRef::new(
            ArtifactScopeId::new("test.panic.generation").unwrap(),
            root.erase(),
        ),
    );
    let mut evaluated = EvaluationDb::new();
    let outcome = registry.run_evaluation(&(), &root, view, &mut evaluated);
    FixtureEvaluation {
        registry,
        artifact,
        evaluated,
        outcome,
    }
}

fn marker_claim(
    domain: crate::analysis::facts::evaluation::DomainId,
    selector: EvidenceClaimSelector,
    rationale: impl Into<String>,
) -> MarkerClaimEntity {
    MarkerClaimEntity::new(
        MarkerClaimKey::new(
            MarkerOccurrenceKey::new(SourceAnchorKey::new("src/lib.rs", 0, 1), None),
            domain,
            0,
        ),
        selector,
        rationale,
    )
}

fn config(claim: Option<MarkerClaimEntity>) -> FixtureConfig {
    FixtureConfig {
        reachability: ReachabilityInput::Reachable,
        assertion_count: 1,
        claim,
        attachment_coverage: AttachmentCoverage::EveryWitness,
        witness_order: WitnessOrder::TraceOrder,
        requirement_attachment: RequirementAttachment::Unlinked,
        ordering_coverage: OrderingCoverage::Exact,
        extra_input: ExtraFixtureInput::None,
    }
}

fn dependency_artifacts(registry: &AnalysisRegistry<()>) -> (ArtifactFactIr, ArtifactFactIr) {
    let mut local = ArtifactDbBuilder::new();
    declare_panic_artifact_inputs(&mut local, registry);
    local
        .insert_entity(&TestNode {
            name: String::from("local-root"),
        })
        .unwrap();

    let mut dependency = ArtifactDbBuilder::new();
    declare_panic_artifact_inputs(&mut dependency, registry);
    let endpoint = dependency
        .insert_entity(&TestNode {
            name: String::from("dependency-assert"),
        })
        .unwrap();
    let requirement = dependency
        .insert_requirement(&NonZeroRequirement::new())
        .unwrap();
    let assertion_meta = FactMeta::new(PassId::new("test.panic.dependency-collector").unwrap())
        .with_owner(&endpoint)
        .unwrap()
        .with_requirement(&requirement)
        .unwrap();
    dependency
        .insert_fact(
            &MirAssertFact::new(MirAssertKind::DivisionByZero),
            assertion_meta,
        )
        .unwrap();
    let claim = marker_claim(
        panic_domain(),
        EvidenceClaimSelector::Unnamed,
        "dependency-scoped rationale attached elsewhere",
    );
    dependency
        .insert_entity(&MarkerOccurrenceEntity::new(
            claim.key().occurrence().clone(),
            Vec::new(),
        ))
        .unwrap();
    dependency.insert_entity(&claim).unwrap();

    (
        local.finalize(registry.schemas()).unwrap(),
        dependency.finalize(registry.schemas()).unwrap(),
    )
}

fn declare_panic_artifact_inputs(builder: &mut ArtifactDbBuilder, registry: &AnalysisRegistry<()>) {
    for descriptor in [
        registry
            .schemas()
            .descriptor_for::<MirAssertFact>()
            .unwrap(),
        registry
            .schemas()
            .descriptor_for::<MarkerOccurrenceEntity>()
            .unwrap(),
        registry
            .schemas()
            .descriptor_for::<MarkerClaimEntity>()
            .unwrap(),
    ] {
        builder.declare_table(descriptor).unwrap();
    }
}

fn dependency_scopes() -> (ArtifactScopeId, ArtifactScopeId) {
    (
        ArtifactScopeId::for_in_memory(0x51, 0),
        ArtifactScopeId::for_in_memory(0x52, 0),
    )
}

fn dependency_evaluation_input(
    registry: &AnalysisRegistry<()>,
    workspace: &WorkspaceFactView<'_>,
    local_scope: &ArtifactScopeId,
    dependency_scope: &ArtifactScopeId,
) -> (
    EvaluationRoot,
    ReachableMirAssert,
    EvidenceAttachment,
    CompositionRelationDb,
) {
    let dependency_view = workspace.artifact(dependency_scope).unwrap();
    let assertion = dependency_view
        .facts::<MirAssertFact>()
        .unwrap()
        .pop()
        .unwrap();
    let claim = dependency_view
        .indexed_rows::<MarkerClaimEntity>()
        .unwrap()
        .pop()
        .unwrap();
    let claim = workspace
        .entity_id_by_key::<MarkerClaimEntity>(dependency_scope, claim.data.key())
        .unwrap()
        .unwrap();
    let local_root = workspace
        .entity_id_by_key::<TestNode>(local_scope, &String::from("local-root"))
        .unwrap()
        .unwrap();
    let dependency_target = workspace
        .entity_id_by_key::<TestNode>(dependency_scope, &String::from("dependency-assert"))
        .unwrap()
        .unwrap();
    let root = EvaluationRoot::new(panic_domain(), local_root.erase());
    let mut relation_schemas = CompositionRelationRegistry::new();
    relation_schemas
        .register::<ResolvesDependencyAssert>(registry.schemas())
        .unwrap();
    let mut builder = CompositionRelationBuilder::new(&root, workspace, &relation_schemas).unwrap();
    builder
        .relate(&local_root, &dependency_target, &ResolvesDependencyAssert)
        .unwrap();
    let composition = builder.finalize().unwrap();
    let evaluation = WorkspaceEvaluationView::open(&root, workspace, &composition).unwrap();
    let target = dependency_target.erase();
    let trace = RelationTrace::new(
        root.entity.clone(),
        target.clone(),
        evaluation
            .graph()
            .shortest_path(&root.entity, &target)
            .unwrap(),
    );
    let assertion = ScopedRowRef::new(dependency_scope.clone(), assertion.fact.reference);
    let reachable = ReachableMirAssert::new(assertion.clone(), target.clone(), trace.clone(), 0);
    let attachment = EvidenceAttachment::new(
        claim,
        assertion,
        target.clone(),
        target,
        trace,
        0,
        Vec::new(),
    );
    (root, reachable, attachment, composition)
}

#[test]
fn every_mir_assert_kind_constructs_its_precise_typed_requirement() {
    let cases = [
        (
            MirAssertKind::BoundsCheck,
            CompilerAssertRequirement::InBounds(InBoundsRequirement::new()),
        ),
        (
            MirAssertKind::Overflow(BinaryOverflowOperation::Addition),
            CompilerAssertRequirement::NoOverflow(NoOverflowRequirement::new(
                OverflowOperation::Binary(BinaryOverflowOperation::Addition),
            )),
        ),
        (
            MirAssertKind::OpaqueOverflow,
            CompilerAssertRequirement::Opaque(OpaqueCompilerRequirement::new(
                "the arithmetic operation must not overflow",
            )),
        ),
        (
            MirAssertKind::OverflowNegation,
            CompilerAssertRequirement::NoOverflow(NoOverflowRequirement::new(
                OverflowOperation::Negation,
            )),
        ),
        (
            MirAssertKind::DivisionByZero,
            CompilerAssertRequirement::NonZero(NonZeroRequirement::new()),
        ),
        (
            MirAssertKind::RemainderByZero,
            CompilerAssertRequirement::NonZero(NonZeroRequirement::new()),
        ),
        (
            MirAssertKind::ResumedAfterReturn,
            CompilerAssertRequirement::CoroutineState(CoroutineStateRequirement::new(
                CoroutineTerminalState::Returned,
            )),
        ),
        (
            MirAssertKind::ResumedAfterPanic,
            CompilerAssertRequirement::CoroutineState(CoroutineStateRequirement::new(
                CoroutineTerminalState::Panicked,
            )),
        ),
        (
            MirAssertKind::ResumedAfterDrop,
            CompilerAssertRequirement::CoroutineState(CoroutineStateRequirement::new(
                CoroutineTerminalState::Dropped,
            )),
        ),
        (
            MirAssertKind::MisalignedPointerDereference,
            CompilerAssertRequirement::AlignedPointer(AlignedPointerRequirement::new()),
        ),
        (
            MirAssertKind::NullPointerDereference,
            CompilerAssertRequirement::NonNullPointer(NonNullPointerRequirement::new()),
        ),
        (
            MirAssertKind::InvalidEnumConstruction,
            CompilerAssertRequirement::ValidEnum(ValidEnumRequirement::new()),
        ),
    ];

    for (kind, expected) in cases {
        assert_eq!(kind.implicit_requirement(), expected);
    }
}

#[test]
fn every_binary_overflow_operation_remains_typed_in_the_requirement() {
    for operation in [
        BinaryOverflowOperation::Addition,
        BinaryOverflowOperation::Subtraction,
        BinaryOverflowOperation::Multiplication,
        BinaryOverflowOperation::Division,
        BinaryOverflowOperation::Remainder,
        BinaryOverflowOperation::LeftShift,
        BinaryOverflowOperation::RightShift,
    ] {
        assert_eq!(
            MirAssertKind::Overflow(operation).implicit_requirement(),
            CompilerAssertRequirement::NoOverflow(NoOverflowRequirement::new(
                OverflowOperation::Binary(operation),
            ))
        );
    }
}

#[test]
fn unreachable_assertion_produces_no_obligation_or_issue() {
    let fixture = run_fixture(FixtureConfig {
        reachability: ReachabilityInput::Unreachable,
        ..config(None)
    });

    assert!(
        fixture
            .results
            .derived_rows::<ObligationRecord>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
    assert!(
        fixture
            .results
            .issues::<UnsatisfiedCompilerAssertIssue>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn reachable_assertion_without_evidence_produces_an_unsatisfied_issue() {
    let fixture = run_fixture(config(None));

    assert_eq!(
        fixture
            .results
            .derived_rows::<ObligationRecord>(fixture.registry.schemas())
            .unwrap()
            .len(),
        1
    );
    let issues = fixture
        .results
        .issues::<UnsatisfiedCompilerAssertIssue>(fixture.registry.schemas())
        .unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].data.kind(), MirAssertKind::DivisionByZero);
    assert_eq!(issues[0].data.missing_requirements().len(), 1);
}

#[test]
fn panic_pack_registers_and_dispatches_its_issue_renderer() {
    let fixture = run_fixture(config(None));
    let issue = fixture
        .results
        .issues::<UnsatisfiedCompilerAssertIssue>(fixture.registry.schemas())
        .unwrap()
        .into_iter()
        .next()
        .expect("reachable assertion produces one issue")
        .data;
    let schema = SchemaId::new(UnsatisfiedCompilerAssertIssue::ID).unwrap();
    assert!(fixture.registry.rendering().has_issue_renderer(&schema));
    assert!(
        fixture
            .registry
            .schemas()
            .descriptor_for::<PanicEvidenceOrdering>()
            .is_ok()
    );

    let cx = RenderCx::open(&fixture.artifact, fixture.registry.schemas()).unwrap();
    let diagnostic = fixture.registry.rendering().render(&issue, &cx).unwrap();
    assert_eq!(
        diagnostic.message,
        "compiler assertion may panic: division by zero"
    );
}

const COMPILER_ASSERT_RENDER_CASES: &[(MirAssertKind, u8, &str, &str)] = &[
    (
        MirAssertKind::BoundsCheck,
        0,
        "bounds-check",
        "index out of bounds",
    ),
    (
        MirAssertKind::Overflow(BinaryOverflowOperation::Addition),
        1,
        "overflow",
        "arithmetic overflow",
    ),
    (
        MirAssertKind::Overflow(BinaryOverflowOperation::Subtraction),
        1,
        "overflow",
        "arithmetic overflow",
    ),
    (
        MirAssertKind::Overflow(BinaryOverflowOperation::Multiplication),
        1,
        "overflow",
        "arithmetic overflow",
    ),
    (
        MirAssertKind::Overflow(BinaryOverflowOperation::Division),
        1,
        "overflow",
        "arithmetic overflow",
    ),
    (
        MirAssertKind::Overflow(BinaryOverflowOperation::Remainder),
        1,
        "overflow",
        "arithmetic overflow",
    ),
    (
        MirAssertKind::Overflow(BinaryOverflowOperation::LeftShift),
        1,
        "overflow",
        "arithmetic overflow",
    ),
    (
        MirAssertKind::Overflow(BinaryOverflowOperation::RightShift),
        1,
        "overflow",
        "arithmetic overflow",
    ),
    (
        MirAssertKind::OpaqueOverflow,
        1,
        "overflow",
        "arithmetic overflow",
    ),
    (
        MirAssertKind::OverflowNegation,
        2,
        "overflow-negation",
        "negation overflow",
    ),
    (
        MirAssertKind::DivisionByZero,
        3,
        "division-by-zero",
        "division by zero",
    ),
    (
        MirAssertKind::RemainderByZero,
        4,
        "remainder-by-zero",
        "remainder with a zero divisor",
    ),
    (
        MirAssertKind::ResumedAfterReturn,
        5,
        "resumed-after-return",
        "coroutine resumed after returning",
    ),
    (
        MirAssertKind::ResumedAfterPanic,
        6,
        "resumed-after-panic",
        "coroutine resumed after panicking",
    ),
    (
        MirAssertKind::ResumedAfterDrop,
        7,
        "resumed-after-drop",
        "coroutine resumed after being dropped",
    ),
    (
        MirAssertKind::MisalignedPointerDereference,
        8,
        "misaligned-pointer-dereference",
        "misaligned pointer dereference",
    ),
    (
        MirAssertKind::NullPointerDereference,
        9,
        "null-pointer-dereference",
        "null pointer dereference",
    ),
    (
        MirAssertKind::InvalidEnumConstruction,
        10,
        "invalid-enum-construction",
        "invalid enum construction",
    ),
];

#[test]
fn compiler_assert_renderer_exhaustively_preserves_the_public_diagnostic_contract() {
    let mut registry = AnalysisRegistry::<()>::new();
    registry.install(&CollectedArtifactSchemaPack).unwrap();
    registry.install(&HumanEvidencePack).unwrap();
    registry.install(&PanicPack).unwrap();
    let artifact = ArtifactFactIr {
        format_version: FACT_IR_FORMAT_VERSION,
        tables: Vec::new(),
        fact_index: Vec::new(),
        relation_index: Vec::new(),
    };
    let cx = RenderCx::open(&artifact, registry.schemas()).unwrap();
    let scope = ArtifactScopeId::for_in_memory(0x71, 0);

    for &(kind, public_order, public_kind, description) in COMPILER_ASSERT_RENDER_CASES {
        let typed_public_kind =
            serde_json::from_value::<CompilerAssertKind>(json!(public_kind)).unwrap();
        assert_eq!(coarse_public_assert_kind(kind), typed_public_kind);
        let presentation = compiler_assert_presentation(kind);
        assert_eq!(presentation.public_kind(), typed_public_kind);
        assert_eq!(presentation.description(), description);
        assert_eq!(presentation.reason(), "compiler assert");
        assert_eq!(
            presentation.target(),
            format!("compiler assert {description}")
        );
        assert_eq!(
            presentation.message(),
            format!("compiler assertion may panic: {description}")
        );
        assert_eq!(
            presentation.effect_note(),
            format!("panic may happen here: compiler assertion: {description}")
        );
        assert_eq!(
            presentation.help(),
            "add a guard, document the panic with `# Panics`, or add `// PANIC:` if a local invariant proves it cannot panic"
        );
        let issue = UnsatisfiedCompilerAssertIssue::new(
            ScopedRowRef::new(
                scope.clone(),
                RowRef {
                    schema: SchemaId::new(MirAssertFact::ID).unwrap(),
                    row: 0,
                },
            ),
            ScopedEntityRef::new(
                scope.clone(),
                EntityRef {
                    schema: SchemaId::new(TestNode::ID).unwrap(),
                    row: 0,
                },
            ),
            kind,
            0,
            Vec::new(),
        );

        let diagnostic = registry.rendering().render(&issue, &cx).unwrap();

        assert_eq!(
            diagnostic.message,
            format!("compiler assertion may panic: {description}"),
            "message for {kind:?}"
        );
        assert_eq!(
            diagnostic.notes,
            [format!(
                "panic may happen here: compiler assertion: {description}"
            )],
            "effect note for {kind:?}"
        );
        assert_eq!(
            diagnostic.help,
            [
                "add a guard, document the panic with `# Panics`, or add `// PANIC:` if a local invariant proves it cannot panic"
            ],
            "general help for {kind:?}"
        );
        assert_eq!(
            diagnostic.data,
            json!({
                "kind": "compiler-assert",
                "compiler-assert-kind": public_kind,
                "reason": "compiler assert",
                "target": format!("compiler assert {description}"),
            }),
            "JSON projection data for {kind:?}"
        );
        assert_eq!(
            diagnostic.sort_key,
            [
                format!("{public_order:02}"),
                String::from(public_kind),
                String::from(description),
            ],
            "sort key for {kind:?}"
        );
        assert_eq!(diagnostic.primary_anchor, None);
        assert!(diagnostic.labels.is_empty());
        assert!(diagnostic.trace.is_empty());
    }
}

#[test]
fn provenance_relation_owner_registers_its_presenter_without_a_trace_enum() {
    let fixture = run_fixture(config(None));
    let schema = SchemaId::new(TestReachabilityEdge::ID).unwrap();
    assert!(fixture.registry.rendering().has_relation_presenter(&schema));

    let cx = RenderCx::open(&fixture.artifact, fixture.registry.schemas()).unwrap();
    let presentation = fixture
        .registry
        .rendering()
        .present(&TestReachabilityEdge, &cx)
        .unwrap();
    assert_eq!(presentation.summary, "reaches compiler assertion");
}

#[test]
fn nonempty_unnamed_evidence_satisfies_all_compiler_requirements() {
    let fixture = run_fixture(config(Some(marker_claim(
        panic_domain(),
        EvidenceClaimSelector::Unnamed,
        "the caller establishes the divisor invariant",
    ))));

    let matches = fixture
        .results
        .derived_rows::<PanicEvidenceMatch>(fixture.registry.schemas())
        .unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].data.satisfied_requirements().len(), 1);
    assert!(
        fixture
            .results
            .issues::<UnsatisfiedCompilerAssertIssue>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn evidence_applies_only_to_the_exact_reachable_witness() {
    let fixture = run_fixture(FixtureConfig {
        reachability: ReachabilityInput::ConvergingPaths,
        attachment_coverage: AttachmentCoverage::FirstWitnessOnly,
        claim: Some(marker_claim(
            panic_domain(),
            EvidenceClaimSelector::Unnamed,
            "the marked route establishes the divisor invariant",
        )),
        ..config(None)
    });

    assert_eq!(
        fixture
            .results
            .derived_rows::<ObligationRecord>(fixture.registry.schemas())
            .unwrap()
            .len(),
        2
    );
    let matches = fixture
        .results
        .derived_rows::<PanicEvidenceMatch>(fixture.registry.schemas())
        .unwrap();
    assert_eq!(matches.len(), 1);
    let issues = fixture
        .results
        .issues::<UnsatisfiedCompilerAssertIssue>(fixture.registry.schemas())
        .unwrap();
    assert_eq!(issues.len(), 1);
    assert_ne!(
        matches[0].data.trace(),
        issues[0]
            .context
            .trace
            .as_ref()
            .expect("the unmarked route remains the issue witness")
    );
}

#[test]
fn equal_traces_with_distinct_traversal_states_do_not_share_evidence() {
    let fixture = run_fixture(FixtureConfig {
        reachability: ReachabilityInput::DuplicateTraceStates,
        attachment_coverage: AttachmentCoverage::FirstWitnessOnly,
        claim: Some(marker_claim(
            panic_domain(),
            EvidenceClaimSelector::Unnamed,
            "only the first traversal state carries this marker",
        )),
        ..config(None)
    });

    assert_eq!(
        fixture
            .results
            .derived_rows::<ObligationRecord>(fixture.registry.schemas())
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        fixture
            .results
            .derived_rows::<PanicEvidenceMatch>(fixture.registry.schemas())
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        fixture
            .results
            .issues::<UnsatisfiedCompilerAssertIssue>(fixture.registry.schemas())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn duplicate_traversal_witness_identity_is_rejected() {
    let fixture = evaluate_fixture(FixtureConfig {
        reachability: ReachabilityInput::DuplicateTraceStates,
        witness_order: WitnessOrder::AllZero,
        ..config(None)
    });

    let error = fixture
        .outcome
        .expect_err("duplicate witness identities must stop evaluation");
    assert!(
        error
            .to_string()
            .contains("same traversal witness more than once")
    );
    let results = fixture.evaluated.finish().unwrap();
    assert!(
        results
            .derived_rows::<ObligationRecord>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn malformed_evidence_attachment_is_rejected_without_a_match() {
    let fixture = evaluate_fixture(FixtureConfig {
        claim: Some(marker_claim(
            panic_domain(),
            EvidenceClaimSelector::Unnamed,
            "the route establishes the required invariant",
        )),
        attachment_coverage: AttachmentCoverage::MalformedFirstWitness,
        ..config(None)
    });

    let error = fixture
        .outcome
        .expect_err("malformed evidence must stop matching");
    assert!(error.to_string().contains("does not end"));
    let results = fixture.evaluated.finish().unwrap();
    assert!(
        results
            .derived_rows::<PanicEvidenceMatch>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn compiler_assert_evidence_group_must_be_the_exact_obligation_endpoint() {
    let fixture = evaluate_fixture(FixtureConfig {
        claim: Some(marker_claim(
            panic_domain(),
            EvidenceClaimSelector::Unnamed,
            "the route establishes the required invariant",
        )),
        attachment_coverage: AttachmentCoverage::MismatchedGroupFirstWitness,
        ..config(None)
    });

    let error = fixture
        .outcome
        .expect_err("a compiler-assert evidence group cannot identify another entity");
    assert!(error.to_string().contains("group"));
    let results = fixture.evaluated.finish().unwrap();
    assert!(
        results
            .derived_rows::<PanicEvidenceMatch>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
}

fn assert_invalid_ordering_batch_is_atomic(
    ordering_coverage: OrderingCoverage,
    expected_error: &str,
) {
    let fixture = evaluate_fixture(FixtureConfig {
        reachability: ReachabilityInput::ConvergingPaths,
        claim: Some(marker_claim(
            panic_domain(),
            EvidenceClaimSelector::Unnamed,
            "both routes establish the divisor invariant",
        )),
        ordering_coverage,
        ..config(None)
    });

    let error = fixture
        .outcome
        .expect_err("invalid evidence ordering coverage must stop matching");
    assert!(
        error.to_string().contains(expected_error),
        "unexpected ordering failure: {error}"
    );
    let results = fixture.evaluated.finish().unwrap();
    assert!(
        !results
            .derived_rows::<PanicEvidenceOrdering>(fixture.registry.schemas())
            .unwrap()
            .is_empty(),
        "the hostile input rule must have emitted sidecars"
    );
    assert!(
        results
            .derived_rows::<PanicEvidenceMatch>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
    assert!(
        results
            .derived_rows::<EvidenceUseRecord>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn missing_later_evidence_ordering_discards_all_matches_and_uses() {
    assert_invalid_ordering_batch_is_atomic(OrderingCoverage::MissingLast, "no evidence ordering");
}

#[test]
fn duplicate_evidence_ordering_discards_all_matches_and_uses() {
    assert_invalid_ordering_batch_is_atomic(
        OrderingCoverage::DuplicateFirst,
        "repeats an exact witness identity",
    );
}

#[test]
fn orphan_evidence_ordering_discards_all_matches_and_uses() {
    assert_invalid_ordering_batch_is_atomic(OrderingCoverage::Orphan, "no active obligation");
}

#[test]
fn tampered_evidence_ordering_trace_target_discards_all_matches_and_uses() {
    assert_invalid_ordering_batch_is_atomic(
        OrderingCoverage::TamperedTraceTarget,
        "trace target was altered",
    );
}

#[test]
fn malformed_semantic_orderings_discard_all_matches_and_uses() {
    assert_invalid_ordering_batch_is_atomic(OrderingCoverage::EmptySemanticOrder, "has no steps");
    assert_invalid_ordering_batch_is_atomic(
        OrderingCoverage::ReversedSourceRange,
        "starts after it ends",
    );
}

#[test]
fn one_claim_applied_to_two_marked_routes_discharges_both_witnesses() {
    let fixture = run_fixture(FixtureConfig {
        reachability: ReachabilityInput::ConvergingPaths,
        claim: Some(marker_claim(
            panic_domain(),
            EvidenceClaimSelector::Unnamed,
            "both routes establish the divisor invariant",
        )),
        ..config(None)
    });

    assert_eq!(
        fixture
            .results
            .derived_rows::<PanicEvidenceMatch>(fixture.registry.schemas())
            .unwrap()
            .len(),
        2
    );
    assert!(
        fixture
            .results
            .issues::<UnsatisfiedCompilerAssertIssue>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn duplicate_issue_selection_preserves_root_traversal_order() {
    let fixture = run_fixture(FixtureConfig {
        reachability: ReachabilityInput::ConvergingPaths,
        witness_order: WitnessOrder::ReverseTraceOrder,
        ..config(None)
    });

    let obligations = fixture
        .results
        .derived_rows::<ObligationRecord>(fixture.registry.schemas())
        .unwrap();
    assert_eq!(obligations.len(), 2);
    let selected = obligations
        .iter()
        .min_by_key(|obligation| obligation.data.witness_order())
        .expect("the fixture has reachable witnesses");
    let canonical = obligations
        .iter()
        .min_by_key(|obligation| obligation.data.trace())
        .expect("the fixture has reachable witnesses");
    assert_ne!(selected.data.trace(), canonical.data.trace());

    let issues = fixture
        .results
        .issues::<UnsatisfiedCompilerAssertIssue>(fixture.registry.schemas())
        .unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(
        issues[0]
            .context
            .trace
            .as_ref()
            .expect("the selected issue retains its witness"),
        selected.data.trace()
    );
    assert_eq!(
        issues[0].data.witness_order(),
        selected.data.witness_order()
    );
}

#[test]
fn empty_evidence_never_satisfies_a_compiler_requirement() {
    let fixture = run_fixture(config(Some(marker_claim(
        panic_domain(),
        EvidenceClaimSelector::Unnamed,
        "  ",
    ))));

    assert!(
        fixture
            .results
            .derived_rows::<PanicEvidenceMatch>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture
            .results
            .issues::<UnsatisfiedCompilerAssertIssue>(fixture.registry.schemas())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn human_evidence_from_another_domain_is_ignored() {
    let fixture = run_fixture(config(Some(marker_claim(
        crate::analysis::facts::evaluation::DomainId::new("sniff-test.safety").unwrap(),
        EvidenceClaimSelector::Unnamed,
        "this rationale belongs to safety evaluation",
    ))));

    assert!(
        fixture
            .results
            .derived_rows::<PanicEvidenceMatch>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture
            .results
            .issues::<UnsatisfiedCompilerAssertIssue>(fixture.registry.schemas())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn compiler_assert_rules_ignore_other_panic_domain_obligation_sources() {
    let fixture = run_fixture(FixtureConfig {
        reachability: ReachabilityInput::Unreachable,
        assertion_count: 0,
        extra_input: ExtraFixtureInput::SameDomainForeignObligation,
        claim: Some(marker_claim(
            panic_domain(),
            EvidenceClaimSelector::Unnamed,
            "this claim belongs to a documented panic-call obligation",
        )),
        ..config(None)
    });

    assert_eq!(
        fixture
            .results
            .derived_rows::<ObligationRecord>(fixture.registry.schemas())
            .unwrap()
            .len(),
        1
    );
    assert!(
        fixture
            .results
            .derived_rows::<PanicEvidenceMatch>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
    assert!(
        fixture
            .results
            .issues::<UnsatisfiedCompilerAssertIssue>(fixture.registry.schemas())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn malformed_reachable_endpoint_is_rejected_without_committing_an_obligation() {
    let FixtureEvaluation {
        registry,
        evaluated,
        outcome,
        ..
    } = evaluate_fixture(FixtureConfig {
        reachability: ReachabilityInput::MismatchedEndpoint,
        ..config(None)
    });

    let error = outcome.expect_err("a candidate endpoint cannot differ from its trace target");
    assert!(error.to_string().contains("endpoint"));
    let results = evaluated.finish().unwrap();
    assert!(
        results
            .derived_rows::<ObligationRecord>(registry.schemas())
            .unwrap()
            .is_empty()
    );
    assert!(
        results
            .issues::<UnsatisfiedCompilerAssertIssue>(registry.schemas())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn dependency_scoped_assertions_claims_and_obligations_use_exact_workspace_lookups() {
    let mut registry = AnalysisRegistry::<()>::new();
    registry.install(&CollectedArtifactSchemaPack).unwrap();
    registry.install(&HumanEvidencePack).unwrap();
    registry.install(&EvidenceCoordinatorPack).unwrap();
    registry.install(&PanicPack).unwrap();
    registry.register_entity::<TestNode>().unwrap();
    let (local_artifact, dependency_artifact) = dependency_artifacts(&registry);
    let (local_scope, dependency_scope) = dependency_scopes();
    let mut workspace_registry = AnalysisRegistry::<()>::new();
    workspace_registry
        .install(&CollectedArtifactSchemaPack)
        .unwrap();
    workspace_registry.install(&HumanEvidencePack).unwrap();
    workspace_registry
        .install(&EvidenceCoordinatorPack)
        .unwrap();
    workspace_registry.install(&PanicPack).unwrap();
    workspace_registry.register_entity::<TestNode>().unwrap();
    let workspace = WorkspaceFactView::compose([
        (
            local_scope.clone(),
            ArtifactDbView::open(&local_artifact, workspace_registry.schemas()).unwrap(),
        ),
        (
            dependency_scope.clone(),
            ArtifactDbView::open(&dependency_artifact, workspace_registry.schemas()).unwrap(),
        ),
    ])
    .unwrap();
    let (root, reachable, attachment, composition) = dependency_evaluation_input(
        &workspace_registry,
        &workspace,
        &local_scope,
        &dependency_scope,
    );
    registry
        .register_evaluation_rule(DependencyInputRule {
            reachable,
            attachment,
        })
        .unwrap();

    let evaluation = WorkspaceEvaluationView::open(&root, &workspace, &composition).unwrap();
    let mut evaluated = EvaluationDb::new();
    registry
        .evaluation_rules()
        .run_all_workspace(&(), &root, &evaluation, &mut evaluated)
        .unwrap();
    let results = evaluated.finish().unwrap();

    let obligations = results
        .derived_rows::<ObligationRecord>(registry.schemas())
        .unwrap();
    assert_eq!(obligations.len(), 1);
    assert_eq!(obligations[0].data.source().scope(), &dependency_scope);
    assert_eq!(
        obligations[0].data.requirements()[0].scope(),
        &dependency_scope
    );
    let matches = results
        .derived_rows::<PanicEvidenceMatch>(registry.schemas())
        .unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].data.claim().scope(), &dependency_scope);
    assert_eq!(
        matches[0].data.obligation_source().scope(),
        &dependency_scope
    );
    assert_eq!(matches[0].data.endpoint(), matches[0].data.group());
    assert!(
        results
            .issues::<UnsatisfiedCompilerAssertIssue>(registry.schemas())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn named_or_explicit_evidence_needs_a_linked_exact_requirement_reference() {
    for selector in [
        EvidenceClaimSelector::Named(String::from("non zero")),
        EvidenceClaimSelector::Explicit(vec![String::from("compiler.non-zero")]),
    ] {
        let unlinked = run_fixture(config(Some(marker_claim(
            panic_domain(),
            selector.clone(),
            "the divisor was checked",
        ))));
        assert_eq!(
            unlinked
                .results
                .issues::<UnsatisfiedCompilerAssertIssue>(unlinked.registry.schemas())
                .unwrap()
                .len(),
            1
        );

        let linked = run_fixture(FixtureConfig {
            requirement_attachment: RequirementAttachment::Linked,
            ..config(Some(marker_claim(
                panic_domain(),
                selector,
                "the divisor was checked",
            )))
        });
        assert_eq!(
            linked
                .results
                .derived_rows::<PanicEvidenceMatch>(linked.registry.schemas())
                .unwrap()
                .len(),
            1
        );
        assert!(
            linked
                .results
                .issues::<UnsatisfiedCompilerAssertIssue>(linked.registry.schemas())
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn evidence_reuse_is_coordinated_across_distinct_scoped_effect_groups() {
    let fixture = run_fixture(FixtureConfig {
        extra_input: ExtraFixtureInput::EvidenceUseFromAnotherProducer,
        claim: Some(marker_claim(
            panic_domain(),
            EvidenceClaimSelector::Unnamed,
            "one claim cannot justify two semantic sites",
        )),
        ..config(None)
    });

    assert_eq!(
        fixture
            .results
            .derived_rows::<EvidenceUseRecord>(fixture.registry.schemas())
            .unwrap()
            .len(),
        2
    );
    let issues = fixture
        .results
        .issues::<AmbiguousEvidenceReuseIssue>(fixture.registry.schemas())
        .unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].data.groups().len(), 2);
    assert_eq!(
        issues[0].data.marker().entity().schema.as_str(),
        MarkerOccurrenceEntity::ID
    );
    assert_eq!(
        issues[0].context.source.as_ref(),
        Some(&issues[0].data.marker().as_row())
    );
    assert_eq!(
        issues[0].data.witness_endpoint(),
        issues[0].context.endpoint.as_ref().unwrap()
    );
    assert_eq!(
        issues[0].data.witness_source(),
        fixture
            .results
            .derived_rows::<EvidenceUseRecord>(fixture.registry.schemas())
            .unwrap()
            .iter()
            .min_by(|left, right| { left.data.semantic_order().cmp(right.data.semantic_order()) })
            .unwrap()
            .data
            .source()
    );
    let selected_trace = issues[0]
        .context
        .trace
        .as_ref()
        .expect("an ambiguous evidence issue retains its explanatory trace");
    assert!(selected_trace.relations().is_empty());
    assert_eq!(selected_trace.target(), &issues[0].context.root.entity);
    assert_eq!(
        issues[0].context.endpoint.as_ref(),
        Some(&issues[0].context.root.entity)
    );

    let schema = SchemaId::new(AmbiguousEvidenceReuseIssue::ID).unwrap();
    assert!(fixture.registry.rendering().has_issue_renderer(&schema));
    let cx = RenderCx::open(&fixture.artifact, fixture.registry.schemas()).unwrap();
    let diagnostic = fixture
        .registry
        .rendering()
        .render(&issues[0].data, &cx)
        .unwrap();
    assert_eq!(diagnostic.message, "human evidence marker is ambiguous");
    assert_eq!(
        diagnostic.notes,
        ["this evidence marker applies to 2 distinct panic obligation groups"]
    );
    assert_eq!(
        diagnostic.help,
        ["move the marker directly above one obligation, or split it into separate markers"]
    );
}

#[derive(Clone, Serialize, Deserialize)]
enum FutureLocalPanicDetail {
    AllocatorContract,
}

#[derive(Clone, Serialize, Deserialize)]
struct FutureLocalPanicFact {
    detail: FutureLocalPanicDetail,
}

impl RowSchema for FutureLocalPanicFact {
    const ID: &'static str = "test.panic.future-local-fact";
    const VERSION: u32 = 1;
}

impl FactSchema for FutureLocalPanicFact {}

#[test]
fn a_future_pack_local_enum_registers_without_changing_any_core_enum() {
    let mut registry = AnalysisRegistry::<()>::new();
    registry.install(&CollectedArtifactSchemaPack).unwrap();
    registry.install(&HumanEvidencePack).unwrap();
    registry.install(&EvidenceCoordinatorPack).unwrap();
    registry.install(&PanicPack).unwrap();

    registry.register_fact::<FutureLocalPanicFact>().unwrap();

    assert!(
        registry
            .schemas()
            .descriptor(&SchemaId::new(FutureLocalPanicFact::ID).unwrap())
            .is_some()
    );
}

#[test]
fn human_evidence_pack_owns_only_derived_attachments() {
    let marker_claim = SchemaId::new(MarkerClaimEntity::ID).unwrap();
    let legacy_claim = SchemaId::new("sniff-test.human.evidence-claim").unwrap();
    let attachment = SchemaId::new(EvidenceAttachment::ID).unwrap();
    let mut human_only = AnalysisRegistry::<()>::new();
    human_only.install(&HumanEvidencePack).unwrap();

    assert!(human_only.schemas().descriptor(&attachment).is_some());
    assert!(human_only.schemas().descriptor(&marker_claim).is_none());
    assert!(human_only.schemas().descriptor(&legacy_claim).is_none());

    let mut permanent = AnalysisRegistry::<()>::new();
    permanent.install(&CollectedArtifactSchemaPack).unwrap();
    permanent.install(&HumanEvidencePack).unwrap();
    assert!(permanent.schemas().descriptor(&marker_claim).is_some());
    assert!(permanent.schemas().descriptor(&attachment).is_some());
    assert!(permanent.schemas().descriptor(&legacy_claim).is_none());

    assert_eq!(EvidenceAttachment::VERSION, 4);
    assert_eq!(PanicEvidenceOrdering::VERSION, 1);
    assert_eq!(PanicEvidenceMatch::VERSION, 4);
    assert_eq!(UnsatisfiedCompilerAssertIssue::VERSION, 2);
}

#[test]
fn panic_evidence_ordering_requires_semantic_order_and_rejects_unknown_nested_fields() {
    let scope = ArtifactScopeId::new("test.panic.strict-ordering").unwrap();
    let endpoint = ScopedEntityRef::new(
        scope.clone(),
        EntityRef {
            schema: SchemaId::new(TestNode::ID).unwrap(),
            row: 0,
        },
    );
    let ordering = PanicEvidenceOrdering::new(
        ScopedRowRef::new(
            scope,
            RowRef {
                schema: SchemaId::new(MirAssertFact::ID).unwrap(),
                row: 0,
            },
        ),
        endpoint.clone(),
        endpoint.clone(),
        RelationTrace::new(endpoint.clone(), endpoint, Vec::new()),
        0,
        EvidenceSemanticOrder::new(
            vec![EvidenceSemanticStepOrder::new(
                "crate::root",
                EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert),
                Some(String::from("compiler assert division by zero")),
                None,
            )],
            0,
        ),
    );
    let encoded = serde_json::to_value(ordering).unwrap();
    for path in ["missing-order", "ordering", "step", "edge", "trace"] {
        let mut hostile = encoded.clone();
        match path {
            "missing-order" => {
                hostile.as_object_mut().unwrap().remove("semantic-order");
            }
            "ordering" => hostile["semantic-order"]["unexpected"] = json!(true),
            "step" => hostile["semantic-order"]["steps"][0]["unexpected"] = json!(true),
            "edge" => {
                hostile["semantic-order"]["steps"][0]["kind"]["unexpected"] = json!(true);
            }
            "trace" => hostile["trace"]["unexpected"] = json!(true),
            _ => unreachable!(),
        }
        assert!(
            serde_json::from_value::<PanicEvidenceOrdering>(hostile).is_err(),
            "hostile {path} envelope must be rejected"
        );
    }
}
