use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::*;
use crate::analysis::facts::composition::{
    CompositionRelationBuilder, CompositionRelationRegistry, WorkspaceEvaluationView,
    WorkspaceRelationRef,
};
use crate::analysis::facts::encoded::{
    ArtifactFactIr, EncodedRow, EncodedTable, EntityRef, FACT_IR_FORMAT_VERSION, FactIndexRow,
    RelationIndexRow, RowRef, TableKind,
};
use crate::analysis::facts::registry::SchemaRegistry;
use crate::analysis::facts::schema::{
    DerivedSchema, EntitySchema, FactSchema, IssueSchema, PassId, RelationSchema,
    RequirementSchema, RowSchema, SchemaId,
};
use crate::analysis::facts::view::ArtifactDbView;
use crate::analysis::facts::workspace::{
    ArtifactScopeId, ScopedEntityRef, ScopedRelationRef, ScopedRowRef, WorkspaceFactView,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Node {
    name: String,
}

impl RowSchema for Node {
    const ID: &'static str = "sample.node";
    const VERSION: u32 = 1;
}

impl EntitySchema for Node {
    type Key = String;

    fn key(&self) -> Self::Key {
        self.name.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct EntityShapedFact {
    name: String,
}

impl RowSchema for EntityShapedFact {
    const ID: &'static str = "sample.entity-shaped-fact";
    const VERSION: u32 = 1;
}

impl EntitySchema for EntityShapedFact {
    type Key = String;

    fn key(&self) -> Self::Key {
        self.name.clone()
    }
}

impl FactSchema for EntityShapedFact {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Assertion {
    detail: String,
}

impl RowSchema for Assertion {
    const ID: &'static str = "sample.assertion";
    const VERSION: u32 = 1;
}

impl FactSchema for Assertion {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct OptionalFact;

impl RowSchema for OptionalFact {
    const ID: &'static str = "sample.optional-fact";
    const VERSION: u32 = 1;
}

impl FactSchema for OptionalFact {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Calls;

impl RowSchema for Calls {
    const ID: &'static str = "sample.calls";
    const VERSION: u32 = 1;
}

impl RelationSchema for Calls {
    type From = Node;
    type To = Node;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RequirementA {
    statement: String,
}

impl RowSchema for RequirementA {
    const ID: &'static str = "sample.requirement-a";
    const VERSION: u32 = 1;
}

impl RequirementSchema for RequirementA {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RequirementB {
    statement: String,
}

impl RowSchema for RequirementB {
    const ID: &'static str = "sample.requirement-b";
    const VERSION: u32 = 1;
}

impl RequirementSchema for RequirementB {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Alert {
    message: String,
}

impl RowSchema for Alert {
    const ID: &'static str = "sample.alert";
    const VERSION: u32 = 1;
}

impl IssueSchema for Alert {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DerivedAlert {
    message: String,
}

impl RowSchema for DerivedAlert {
    const ID: &'static str = "sample.derived-alert";
    const VERSION: u32 = 1;
}

impl IssueSchema for DerivedAlert {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct EvidenceMatch {
    satisfied_requirements: usize,
}

impl RowSchema for EvidenceMatch {
    const ID: &'static str = "sample.evidence-match";
    const VERSION: u32 = 1;
}

impl DerivedSchema for EvidenceMatch {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct EvidenceSummary {
    observed_matches: usize,
}

impl RowSchema for EvidenceSummary {
    const ID: &'static str = "sample.evidence-summary";
    const VERSION: u32 = 1;
}

impl DerivedSchema for EvidenceSummary {}

fn schema(id: &str) -> SchemaId {
    SchemaId::new(id).expect("valid sample schema ID")
}

fn encoded_table(
    schema_id: &str,
    kind: TableKind,
    rows: Vec<(Option<Value>, Value)>,
) -> EncodedTable {
    EncodedTable {
        schema: schema(schema_id),
        version: 1,
        kind,
        rows: rows
            .into_iter()
            .map(|(stable_key, data)| EncodedRow { stable_key, data })
            .collect(),
    }
}

fn node_artifact(name: &str) -> ArtifactFactIr {
    ArtifactFactIr {
        format_version: FACT_IR_FORMAT_VERSION,
        tables: vec![encoded_table(
            Node::ID,
            TableKind::Entity,
            vec![(Some(json!(name)), json!({ "name": name }))],
        )],
        fact_index: Vec::new(),
        relation_index: Vec::new(),
    }
}

fn read_artifact_entity<E: EntitySchema>(
    registry: &SchemaRegistry,
    root_artifact: ArtifactDbView<'_>,
    workspace: &WorkspaceFactView<'_>,
    declared_reads: impl IntoIterator<Item = SchemaId>,
    reference: &ScopedEntityRef,
) -> Result<E, RuleError> {
    let rule = PassId::new("sample.read-artifact-entity").unwrap();
    let declared_reads = declared_reads.into_iter().collect::<BTreeSet<_>>();
    let evaluated = EvaluationDb::new();
    EvaluationInput::new(
        &rule,
        &declared_reads,
        root_artifact,
        workspace,
        &evaluated,
        registry,
    )
    .artifact_entity_at::<E>(reference)
}

fn read_artifact_entity_by_key<E: EntitySchema>(
    registry: &SchemaRegistry,
    root_artifact: ArtifactDbView<'_>,
    workspace: &WorkspaceFactView<'_>,
    declared_reads: impl IntoIterator<Item = SchemaId>,
    scope: &ArtifactScopeId,
    key: &E::Key,
) -> Result<Option<ScopedEntityRef>, RuleError> {
    let rule = PassId::new("sample.read-artifact-entity-by-key").unwrap();
    let declared_reads = declared_reads.into_iter().collect::<BTreeSet<_>>();
    let evaluated = EvaluationDb::new();
    EvaluationInput::new(
        &rule,
        &declared_reads,
        root_artifact,
        workspace,
        &evaluated,
        registry,
    )
    .artifact_entity_by_key::<E>(scope, key)
}

fn read_artifact_requirement<R: RequirementSchema>(
    registry: &SchemaRegistry,
    root_artifact: ArtifactDbView<'_>,
    workspace: &WorkspaceFactView<'_>,
    declared_reads: impl IntoIterator<Item = SchemaId>,
    reference: &ScopedRowRef,
) -> Result<R, RuleError> {
    let rule = PassId::new("sample.read-artifact-requirement").unwrap();
    let declared_reads = declared_reads.into_iter().collect::<BTreeSet<_>>();
    let evaluated = EvaluationDb::new();
    EvaluationInput::new(
        &rule,
        &declared_reads,
        root_artifact,
        workspace,
        &evaluated,
        registry,
    )
    .artifact_requirement_at::<R>(reference)
}

struct Fixture {
    registry: SchemaRegistry,
    artifact: ArtifactFactIr,
    root: EvaluationRoot,
    target: ScopedEntityRef,
    assertion: ScopedRowRef,
    requirements: Vec<ScopedRowRef>,
    trace: RelationTrace,
}

fn fixture_registry() -> SchemaRegistry {
    let mut registry = SchemaRegistry::new();
    registry.register_entity::<Node>().unwrap();
    registry.register_fact::<Assertion>().unwrap();
    registry.register_fact::<OptionalFact>().unwrap();
    registry.register_relation::<Calls>().unwrap();
    registry.register_requirement::<RequirementA>().unwrap();
    registry.register_requirement::<RequirementB>().unwrap();
    registry.register_derived::<ObligationRecord>().unwrap();
    registry.register_derived::<EvidenceMatch>().unwrap();
    registry.register_derived::<EvidenceSummary>().unwrap();
    registry.register_issue::<Alert>().unwrap();
    registry.register_issue::<DerivedAlert>().unwrap();
    registry
}

impl Fixture {
    fn new() -> Self {
        let registry = fixture_registry();

        let root_entity = EntityRef {
            schema: schema(Node::ID),
            row: 0,
        };
        let target = EntityRef {
            schema: schema(Node::ID),
            row: 1,
        };
        let assertion = RowRef {
            schema: schema(Assertion::ID),
            row: 0,
        };
        let requirement_a = RowRef {
            schema: schema(RequirementA::ID),
            row: 0,
        };
        let requirement_b = RowRef {
            schema: schema(RequirementB::ID),
            row: 0,
        };
        let relation = RowRef {
            schema: schema(Calls::ID),
            row: 0,
        };
        let artifact = ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables: vec![
                encoded_table(
                    Assertion::ID,
                    TableKind::Fact,
                    vec![(
                        None,
                        json!({ "detail": "division requires a nonzero divisor" }),
                    )],
                ),
                encoded_table(Calls::ID, TableKind::Relation, vec![(None, json!(null))]),
                encoded_table(
                    Node::ID,
                    TableKind::Entity,
                    vec![
                        (Some(json!("root")), json!({ "name": "root" })),
                        (Some(json!("target")), json!({ "name": "target" })),
                    ],
                ),
                encoded_table(
                    RequirementA::ID,
                    TableKind::Requirement,
                    vec![(None, json!({ "statement": "nonzero" }))],
                ),
                encoded_table(
                    RequirementB::ID,
                    TableKind::Requirement,
                    vec![(None, json!({ "statement": "in range" }))],
                ),
            ],
            fact_index: vec![FactIndexRow {
                fact: assertion.clone(),
                owner: Some(target.clone()),
                anchor: None,
                provenance_root: Some(root_entity.clone()),
                requirements: vec![requirement_a.clone(), requirement_b.clone()],
                producer: PassId::new("sample.collect").unwrap(),
            }],
            relation_index: vec![RelationIndexRow {
                relation: relation.clone(),
                from: root_entity.clone(),
                to: target.clone(),
                source: None,
            }],
        };
        ArtifactDbView::open(&artifact, &registry).expect("valid sample artifact");
        let scope = ArtifactScopeId::new("sample.fixture-generation").unwrap();
        let root = EvaluationRoot::new(
            DomainId::new("sample.panic").unwrap(),
            ScopedEntityRef::new(scope.clone(), root_entity),
        );
        let target = ScopedEntityRef::new(scope.clone(), target);
        let assertion = ScopedRowRef::new(scope.clone(), assertion);
        let requirements = vec![
            ScopedRowRef::new(scope.clone(), requirement_a),
            ScopedRowRef::new(scope.clone(), requirement_b),
        ];
        let trace = RelationTrace::new(
            root.entity.clone(),
            target.clone(),
            vec![WorkspaceRelationRef::Artifact(ScopedRelationRef::new(
                scope, relation,
            ))],
        );
        Self {
            registry,
            artifact,
            root,
            target,
            assertion,
            requirements,
            trace,
        }
    }

    fn view(&self) -> ArtifactDbView<'_> {
        ArtifactDbView::open(&self.artifact, &self.registry).expect("valid sample artifact")
    }

    fn issue_context(&self) -> EvaluationIssueContext {
        EvaluationIssueContext::new(self.root.clone())
            .with_source(self.assertion.clone())
            .with_endpoint(self.target.clone())
            .with_trace(self.trace.clone())
    }

    fn obligation(&self) -> ObligationRecord {
        ObligationRecord::new(
            self.root.domain.clone(),
            self.assertion.clone(),
            self.target.clone(),
            self.requirements.clone(),
            self.target.clone(),
            self.trace.clone(),
        )
    }
}

type Log = RefCell<Vec<String>>;

struct NoopRule {
    descriptor: RuleDescriptor,
}

struct StatefulDescriptorRule {
    calls: Rc<Cell<usize>>,
}

struct ReadOptionalFactRule {
    ran: Rc<Cell<bool>>,
}

struct ReadScopedAssertionRule {
    assertion: ScopedRowRef,
}

impl EvaluationRule<Log> for ReadScopedAssertionRule {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new("sample.read-scoped-assertion").unwrap())
            .read::<Assertion>()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, Log>,
        input: &EvaluationInput<'_>,
        _output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        let assertion = input.artifact_fact_at::<Assertion>(&self.assertion)?;
        cx.services().borrow_mut().push(assertion.fact.data.detail);
        Ok(())
    }
}

impl EvaluationRule<Log> for ReadOptionalFactRule {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new("sample.read-optional").unwrap()).read::<OptionalFact>()
    }

    fn evaluate(
        &self,
        _cx: &EvaluationCx<'_, Log>,
        input: &EvaluationInput<'_>,
        _output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        self.ran.set(true);
        assert!(input.artifact_facts::<OptionalFact>()?.is_empty());
        Ok(())
    }
}

impl EvaluationRule<Log> for StatefulDescriptorRule {
    fn descriptor(&self) -> RuleDescriptor {
        let calls = self.calls.get();
        self.calls.set(calls + 1);
        let id = if calls == 0 {
            "sample.captured-descriptor"
        } else {
            "sample.changed-descriptor"
        };
        RuleDescriptor::new(PassId::new(id).unwrap())
    }

    fn evaluate(
        &self,
        _cx: &EvaluationCx<'_, Log>,
        _input: &EvaluationInput<'_>,
        _output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        Ok(())
    }
}

impl EvaluationRule<Log> for NoopRule {
    fn descriptor(&self) -> RuleDescriptor {
        self.descriptor.clone()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, Log>,
        _input: &EvaluationInput<'_>,
        _output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        cx.services()
            .borrow_mut()
            .push(self.descriptor.id().as_str().to_owned());
        Ok(())
    }
}

struct EmitAlertRule {
    descriptor: RuleDescriptor,
    context: EvaluationIssueContext,
    obligation: ObligationRecord,
    fail_after_output: bool,
}

impl EvaluationRule<Log> for EmitAlertRule {
    fn descriptor(&self) -> RuleDescriptor {
        self.descriptor.clone()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, Log>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        cx.services()
            .borrow_mut()
            .push(self.descriptor.id().as_str().to_owned());
        let assertions = input.artifact_facts::<Assertion>()?;
        assert_eq!(assertions.len(), 1);
        assert_eq!(
            assertions[0].metadata.requirements,
            self.obligation
                .requirements()
                .iter()
                .map(|requirement| requirement.row().clone())
                .collect::<Vec<_>>()
        );
        let calls = input.artifact_relations::<Calls>()?;
        assert_eq!(calls.len(), 1);
        output.emit_obligation(&self.obligation)?;
        output.emit_issue(
            &Alert {
                message: assertions[0].fact.data.detail.clone(),
            },
            self.context.clone(),
        )?;
        if self.fail_after_output {
            return Err(RuleError::failed(
                "sample rule failed after emitting output",
            ));
        }
        Ok(())
    }
}

struct MatchEvidenceRule {
    descriptor: RuleDescriptor,
}

impl EvaluationRule<Log> for MatchEvidenceRule {
    fn descriptor(&self) -> RuleDescriptor {
        self.descriptor.clone()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, Log>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        cx.services()
            .borrow_mut()
            .push(self.descriptor.id().as_str().to_owned());
        for obligation in input.derived_rows::<ObligationRecord>()? {
            output.emit_derived(&EvidenceMatch {
                satisfied_requirements: obligation.data.requirements().len(),
            })?;
        }
        Ok(())
    }
}

struct ReportEvidenceRule {
    descriptor: RuleDescriptor,
    context: EvaluationIssueContext,
}

struct EmitEvidenceRule {
    descriptor: RuleDescriptor,
    satisfied_requirements: Vec<usize>,
}

struct SummarizeEvidenceRule {
    descriptor: RuleDescriptor,
}

impl EvaluationRule<Log> for SummarizeEvidenceRule {
    fn descriptor(&self) -> RuleDescriptor {
        self.descriptor.clone()
    }

    fn evaluate(
        &self,
        _cx: &EvaluationCx<'_, Log>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        output.emit_derived(&EvidenceSummary {
            observed_matches: input.derived_rows::<EvidenceMatch>()?.len(),
        })
    }
}

fn evidence_scheduler(
    fixture: &Fixture,
    summary_first: bool,
    producers: [(&str, Vec<usize>); 2],
) -> EvaluationRuleScheduler<Log> {
    let mut scheduler = EvaluationRuleScheduler::default();
    let summary = || SummarizeEvidenceRule {
        descriptor: RuleDescriptor::new(PassId::new("sample.summarize-evidence").unwrap())
            .read::<EvidenceMatch>()
            .write_derived::<EvidenceSummary>(),
    };
    if summary_first {
        scheduler.register(&fixture.registry, summary()).unwrap();
    }
    for (id, satisfied_requirements) in producers {
        scheduler
            .register(
                &fixture.registry,
                EmitEvidenceRule {
                    descriptor: RuleDescriptor::new(PassId::new(id).unwrap())
                        .write_derived::<EvidenceMatch>(),
                    satisfied_requirements,
                },
            )
            .unwrap();
    }
    if !summary_first {
        scheduler.register(&fixture.registry, summary()).unwrap();
    }
    scheduler
}

impl EvaluationRule<Log> for EmitEvidenceRule {
    fn descriptor(&self) -> RuleDescriptor {
        self.descriptor.clone()
    }

    fn evaluate(
        &self,
        _cx: &EvaluationCx<'_, Log>,
        _input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        for satisfied_requirements in &self.satisfied_requirements {
            output.emit_derived(&EvidenceMatch {
                satisfied_requirements: *satisfied_requirements,
            })?;
        }
        Ok(())
    }
}

impl EvaluationRule<Log> for ReportEvidenceRule {
    fn descriptor(&self) -> RuleDescriptor {
        self.descriptor.clone()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, Log>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        cx.services()
            .borrow_mut()
            .push(self.descriptor.id().as_str().to_owned());
        for evidence in input.derived_rows::<EvidenceMatch>()? {
            output.emit_issue(
                &DerivedAlert {
                    message: format!(
                        "matched {} requirements",
                        evidence.data.satisfied_requirements
                    ),
                },
                self.context.clone(),
            )?;
        }
        Ok(())
    }
}

struct DeriveAlertRule {
    descriptor: RuleDescriptor,
    context: EvaluationIssueContext,
}

impl EvaluationRule<Log> for DeriveAlertRule {
    fn descriptor(&self) -> RuleDescriptor {
        self.descriptor.clone()
    }

    fn evaluate(
        &self,
        cx: &EvaluationCx<'_, Log>,
        input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        cx.services()
            .borrow_mut()
            .push(self.descriptor.id().as_str().to_owned());
        let alerts = input.issues::<Alert>()?;
        assert_eq!(alerts.len(), 1);
        output.emit_issue(
            &DerivedAlert {
                message: format!("derived: {}", alerts[0].data.message),
            },
            self.context.clone(),
        )
    }
}

struct UndeclaredReadRule;

impl EvaluationRule<Log> for UndeclaredReadRule {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new("sample.undeclared-read").unwrap())
    }

    fn evaluate(
        &self,
        _cx: &EvaluationCx<'_, Log>,
        input: &EvaluationInput<'_>,
        _output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        input.artifact_rows::<Assertion>().map(drop)
    }
}

struct UndeclaredWriteRule {
    context: EvaluationIssueContext,
}

struct UndeclaredDerivedReadRule;

impl EvaluationRule<Log> for UndeclaredDerivedReadRule {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new("sample.undeclared-derived-read").unwrap())
    }

    fn evaluate(
        &self,
        _cx: &EvaluationCx<'_, Log>,
        input: &EvaluationInput<'_>,
        _output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        input.derived_rows::<ObligationRecord>().map(drop)
    }
}

struct UndeclaredDerivedWriteRule {
    obligation: ObligationRecord,
}

impl EvaluationRule<Log> for UndeclaredDerivedWriteRule {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new("sample.undeclared-derived-write").unwrap())
    }

    fn evaluate(
        &self,
        _cx: &EvaluationCx<'_, Log>,
        _input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        output.emit_derived(&self.obligation)
    }
}

impl EvaluationRule<Log> for UndeclaredWriteRule {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(PassId::new("sample.undeclared-write").unwrap())
    }

    fn evaluate(
        &self,
        _cx: &EvaluationCx<'_, Log>,
        _input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        output.emit_issue(
            &Alert {
                message: String::from("not declared"),
            },
            self.context.clone(),
        )
    }
}

#[test]
fn evaluation_layer_exposes_a_stable_rule_descriptor() {
    let descriptor = RuleDescriptor::new(PassId::new("sample.evaluate").unwrap())
        .read::<Assertion>()
        .write_derived::<ObligationRecord>()
        .write_issue::<Alert>();

    assert_eq!(descriptor.id().as_str(), "sample.evaluate");
    assert_eq!(descriptor.reads().next().unwrap().as_str(), Assertion::ID);
    assert_eq!(
        descriptor
            .writes()
            .map(SchemaId::as_str)
            .collect::<Vec<_>>(),
        vec![ObligationRecord::ID, Alert::ID]
    );
}

#[test]
fn obligation_keeps_arbitrary_requirements_and_a_relation_trace() {
    let scope = ArtifactScopeId::new("sample.generation").unwrap();
    let entity_schema = SchemaId::new("sample.node").unwrap();
    let requirement_a = RowRef {
        schema: SchemaId::new("sample.requirement-a").unwrap(),
        row: 2,
    };
    let requirement_b = RowRef {
        schema: SchemaId::new("sample.requirement-b").unwrap(),
        row: 1,
    };
    let root = EntityRef {
        schema: entity_schema.clone(),
        row: 0,
    };
    let target = EntityRef {
        schema: entity_schema,
        row: 1,
    };
    let relation = RowRef {
        schema: SchemaId::new("sample.calls").unwrap(),
        row: 3,
    };
    let root = ScopedEntityRef::new(scope.clone(), root);
    let target = ScopedEntityRef::new(scope.clone(), target);
    let requirement_a = ScopedRowRef::new(scope.clone(), requirement_a);
    let requirement_b = ScopedRowRef::new(scope.clone(), requirement_b);
    let relation = WorkspaceRelationRef::Artifact(ScopedRelationRef::new(scope.clone(), relation));
    let trace = RelationTrace::new(root, target.clone(), vec![relation.clone()]);
    let obligation = ObligationRecord::new(
        DomainId::new("sample.panic").unwrap(),
        ScopedRowRef::new(
            scope,
            RowRef {
                schema: SchemaId::new("sample.assertion").unwrap(),
                row: 0,
            },
        ),
        target.clone(),
        vec![requirement_b.clone(), requirement_a.clone()],
        target,
        trace,
    );

    assert_eq!(obligation.requirements(), &[requirement_a, requirement_b]);
    assert_eq!(obligation.trace().relations(), &[relation]);
}

#[test]
fn obligation_preserves_exact_artifact_generation_scope() {
    let first_scope = ArtifactScopeId::new("sample.generation-a").unwrap();
    let second_scope = ArtifactScopeId::new("sample.generation-b").unwrap();
    let local_root = EntityRef {
        schema: SchemaId::new("sample.node").unwrap(),
        row: 0,
    };
    let local_target = EntityRef {
        schema: SchemaId::new("sample.node").unwrap(),
        row: 1,
    };
    let local_assertion = RowRef {
        schema: SchemaId::new("sample.assertion").unwrap(),
        row: 0,
    };
    let local_requirement = RowRef {
        schema: SchemaId::new("sample.requirement-a").unwrap(),
        row: 0,
    };
    let local_relation = RowRef {
        schema: SchemaId::new("sample.calls").unwrap(),
        row: 0,
    };
    let first_target = ScopedEntityRef::new(first_scope.clone(), local_target.clone());
    let second_target = ScopedEntityRef::new(second_scope, local_target);
    let relation =
        WorkspaceRelationRef::Artifact(ScopedRelationRef::new(first_scope.clone(), local_relation));
    let trace = RelationTrace::new(
        ScopedEntityRef::new(first_scope.clone(), local_root),
        first_target.clone(),
        vec![relation.clone()],
    );
    let obligation = ObligationRecord::new(
        DomainId::new("sample.panic").unwrap(),
        ScopedRowRef::new(first_scope.clone(), local_assertion),
        first_target.clone(),
        vec![ScopedRowRef::new(first_scope, local_requirement)],
        first_target,
        trace,
    );

    assert_ne!(obligation.endpoint(), &second_target);
    assert_eq!(obligation.trace().relations(), &[relation]);
}

#[test]
fn obligation_rejects_a_reference_from_another_generation_atomically() {
    let fixture = Fixture::new();
    let wrong_scope = ArtifactScopeId::new("sample.other-generation").unwrap();
    let obligation = ObligationRecord::new(
        fixture.root.domain.clone(),
        ScopedRowRef::new(wrong_scope, fixture.assertion.row().clone()),
        fixture.target.clone(),
        fixture.requirements.clone(),
        fixture.target.clone(),
        fixture.trace.clone(),
    );
    let mut scheduler = EvaluationRuleScheduler::<Log>::default();
    scheduler
        .register(
            &fixture.registry,
            EmitAlertRule {
                descriptor: RuleDescriptor::new(
                    PassId::new("sample.reject-other-generation").unwrap(),
                )
                .read::<Assertion>()
                .read::<Calls>()
                .write_derived::<ObligationRecord>()
                .write_issue::<Alert>(),
                context: fixture.issue_context(),
                obligation,
                fail_after_output: false,
            },
        )
        .unwrap();
    let mut evaluated = EvaluationDb::new();

    let error = scheduler
        .run_all(
            &Log::new(Vec::new()),
            &fixture.root,
            fixture.view(),
            &mut evaluated,
        )
        .expect_err("cross-generation row references must not be flattened");

    assert!(matches!(
        error,
        EvaluationPipelineError::Run(RuleRunError {
            source: RuleError::InvalidReference { reason, .. },
            ..
        }) if reason.contains("other-generation")
    ));
    assert_eq!(evaluated.derived_count(), 0);
    assert_eq!(evaluated.issue_count(), 0);
}

#[test]
fn independent_rules_schedule_by_stable_id_not_registration_order() {
    let fixture = Fixture::new();
    let mut scheduler = EvaluationRuleScheduler::<Log>::default();
    scheduler
        .register(
            &fixture.registry,
            NoopRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.zeta").unwrap()),
            },
        )
        .unwrap();
    scheduler
        .register(
            &fixture.registry,
            NoopRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.alpha").unwrap()),
            },
        )
        .unwrap();

    assert_eq!(
        scheduler
            .schedule()
            .unwrap()
            .iter()
            .map(PassId::as_str)
            .collect::<Vec<_>>(),
        vec!["sample.alpha", "sample.zeta"]
    );
}

#[test]
fn rule_registration_captures_a_stateful_descriptor_exactly_once() {
    let fixture = Fixture::new();
    let calls = Rc::new(Cell::new(0));
    let mut scheduler = EvaluationRuleScheduler::<Log>::default();

    scheduler
        .register(
            &fixture.registry,
            StatefulDescriptorRule {
                calls: Rc::clone(&calls),
            },
        )
        .unwrap();

    assert_eq!(calls.get(), 1);
    assert!(
        scheduler
            .descriptor(&PassId::new("sample.captured-descriptor").unwrap())
            .is_some()
    );
    assert!(
        scheduler
            .descriptor(&PassId::new("sample.changed-descriptor").unwrap())
            .is_none()
    );
}

#[test]
fn artifact_reads_distinguish_a_missing_table_from_a_present_empty_table() {
    let fixture = Fixture::new();
    let ran = Rc::new(Cell::new(false));
    let mut scheduler = EvaluationRuleScheduler::<Log>::default();
    scheduler
        .register(
            &fixture.registry,
            ReadOptionalFactRule {
                ran: Rc::clone(&ran),
            },
        )
        .unwrap();
    scheduler
        .register(
            &fixture.registry,
            NoopRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.aaa-before-missing").unwrap()),
            },
        )
        .unwrap();
    let mut evaluated = EvaluationDb::new();
    let log = Log::new(Vec::new());

    assert!(matches!(
        scheduler.run_all(
            &log,
            &fixture.root,
            fixture.view(),
            &mut evaluated,
        ),
        Err(EvaluationPipelineError::Run(RuleRunError {
            source: RuleError::MissingArtifactInput { schema, .. },
            ..
        })) if schema.as_str() == OptionalFact::ID
    ));
    assert!(!ran.get());
    assert!(log.borrow().is_empty());

    let mut artifact = fixture.artifact.clone();
    artifact
        .tables
        .push(encoded_table(OptionalFact::ID, TableKind::Fact, Vec::new()));
    artifact
        .tables
        .sort_by(|left, right| left.schema.cmp(&right.schema));
    let view = ArtifactDbView::open(&artifact, &fixture.registry).unwrap();
    scheduler
        .run_all(&log, &fixture.root, view, &mut evaluated)
        .unwrap();
    assert!(ran.get());
}

#[test]
fn typed_entity_lookup_reads_the_referenced_dependency_scope() {
    let registry = fixture_registry();
    let local_scope = ArtifactScopeId::for_in_memory(890, 0);
    let dependency_scope = ArtifactScopeId::for_in_memory(891, 0);
    let local_artifact = node_artifact("local");
    let dependency_artifact = node_artifact("dependency");
    let local_view = ArtifactDbView::open(&local_artifact, &registry).unwrap();
    let workspace = WorkspaceFactView::compose([
        (local_scope, local_view),
        (
            dependency_scope.clone(),
            ArtifactDbView::open(&dependency_artifact, &registry).unwrap(),
        ),
    ])
    .unwrap();
    let reference = ScopedEntityRef::new(
        dependency_scope,
        EntityRef {
            schema: schema(Node::ID),
            row: 0,
        },
    );

    assert_eq!(
        read_artifact_entity::<Node>(
            &registry,
            local_view,
            &workspace,
            [schema(Node::ID)],
            &reference,
        )
        .unwrap(),
        Node {
            name: String::from("dependency")
        }
    );
}

#[test]
fn typed_entity_key_lookup_is_declared_and_bound_to_the_exact_scope() {
    let registry = fixture_registry();
    let local_scope = ArtifactScopeId::for_in_memory(918, 0);
    let dependency_scope = ArtifactScopeId::for_in_memory(919, 0);
    let unmanaged_scope = ArtifactScopeId::for_in_memory(920, 0);
    let local_artifact = node_artifact("same-key");
    let dependency_artifact = node_artifact("same-key");
    let local_view = ArtifactDbView::open(&local_artifact, &registry).unwrap();
    let workspace = WorkspaceFactView::compose([
        (local_scope.clone(), local_view),
        (
            dependency_scope.clone(),
            ArtifactDbView::open(&dependency_artifact, &registry).unwrap(),
        ),
    ])
    .unwrap();
    let key = String::from("same-key");

    let found = read_artifact_entity_by_key::<Node>(
        &registry,
        local_view,
        &workspace,
        [schema(Node::ID)],
        &dependency_scope,
        &key,
    )
    .unwrap()
    .unwrap();
    assert_eq!(found.scope(), &dependency_scope);
    assert_eq!(found.entity().row, 0);

    assert!(matches!(
        read_artifact_entity_by_key::<Node>(
            &registry,
            local_view,
            &workspace,
            [],
            &local_scope,
            &key,
        ),
        Err(RuleError::UndeclaredRead { schema, .. }) if schema.as_str() == Node::ID
    ));
    assert!(matches!(
        read_artifact_entity_by_key::<Node>(
            &registry,
            local_view,
            &workspace,
            [schema(Node::ID)],
            &unmanaged_scope,
            &key,
        ),
        Err(RuleError::ArtifactRead { schema, reason, .. })
            if schema.as_str() == Node::ID && reason.contains("has no artifact scope")
    ));
}

#[test]
fn typed_requirement_lookup_is_declared_exact_and_fail_closed() {
    let registry = fixture_registry();
    let root_scope = ArtifactScopeId::for_in_memory(889, 0);
    let dependency_scope =
        ArtifactScopeId::for_persisted(889, "0123456789abcdef0123456789abcdef").unwrap();
    let root_artifact = ArtifactFactIr {
        format_version: FACT_IR_FORMAT_VERSION,
        tables: vec![encoded_table(
            RequirementA::ID,
            TableKind::Requirement,
            Vec::new(),
        )],
        fact_index: Vec::new(),
        relation_index: Vec::new(),
    };
    let dependency_artifact = ArtifactFactIr {
        format_version: FACT_IR_FORMAT_VERSION,
        tables: vec![encoded_table(
            RequirementA::ID,
            TableKind::Requirement,
            vec![(None, json!({ "statement": "ready" }))],
        )],
        fact_index: Vec::new(),
        relation_index: Vec::new(),
    };
    let root_view = ArtifactDbView::open(&root_artifact, &registry).unwrap();
    let dependency_view = ArtifactDbView::open(&dependency_artifact, &registry).unwrap();
    let workspace = WorkspaceFactView::compose([
        (root_scope.clone(), root_view),
        (dependency_scope.clone(), dependency_view),
    ])
    .unwrap();
    let reference = ScopedRowRef::new(
        dependency_scope.clone(),
        RowRef {
            schema: schema(RequirementA::ID),
            row: 0,
        },
    );

    assert_eq!(
        read_artifact_requirement::<RequirementA>(
            &registry,
            root_view,
            &workspace,
            [schema(RequirementA::ID)],
            &reference,
        )
        .unwrap(),
        RequirementA {
            statement: String::from("ready")
        }
    );
    assert!(matches!(
        read_artifact_requirement::<RequirementA>(
            &registry,
            root_view,
            &workspace,
            [],
            &reference,
        ),
        Err(RuleError::UndeclaredRead { schema, .. }) if schema.as_str() == RequirementA::ID
    ));
    let wrong = ScopedRowRef::new(
        dependency_scope,
        RowRef {
            schema: schema(RequirementB::ID),
            row: 0,
        },
    );
    assert!(matches!(
        read_artifact_requirement::<RequirementA>(
            &registry,
            root_view,
            &workspace,
            [schema(RequirementA::ID)],
            &wrong,
        ),
        Err(RuleError::ArtifactRead { schema, reason, .. })
            if schema.as_str() == RequirementA::ID
                && reason.contains("wrong schema")
    ));
    let replacement_scope = ScopedRowRef::new(
        root_scope,
        RowRef {
            schema: schema(RequirementA::ID),
            row: 0,
        },
    );
    assert!(matches!(
        read_artifact_requirement::<RequirementA>(
            &registry,
            root_view,
            &workspace,
            [schema(RequirementA::ID)],
            &replacement_scope,
        ),
        Err(RuleError::ArtifactRead { schema, .. }) if schema.as_str() == RequirementA::ID
    ));
}

#[test]
fn typed_entity_lookup_rejects_an_undeclared_schema() {
    let registry = fixture_registry();
    let scope = ArtifactScopeId::for_in_memory(892, 0);
    let artifact = node_artifact("node");
    let view = ArtifactDbView::open(&artifact, &registry).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let reference = ScopedEntityRef::new(
        scope,
        EntityRef {
            schema: schema(Node::ID),
            row: 0,
        },
    );

    assert!(matches!(
        read_artifact_entity::<Node>(&registry, view, &workspace, [], &reference),
        Err(RuleError::UndeclaredRead { schema, .. }) if schema.as_str() == Node::ID
    ));
}

#[test]
fn typed_entity_lookup_rejects_a_reference_to_the_wrong_schema() {
    let registry = fixture_registry();
    let scope = ArtifactScopeId::for_in_memory(893, 0);
    let artifact = node_artifact("node");
    let view = ArtifactDbView::open(&artifact, &registry).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let reference = ScopedEntityRef::new(
        scope,
        EntityRef {
            schema: schema(Assertion::ID),
            row: 0,
        },
    );

    assert!(matches!(
        read_artifact_entity::<Node>(
            &registry,
            view,
            &workspace,
            [schema(Node::ID)],
            &reference,
        ),
        Err(RuleError::ArtifactRead { schema, reason, .. })
            if schema.as_str() == Node::ID && reason.contains("does not match expected schema")
    ));
}

#[test]
fn typed_entity_lookup_rejects_a_non_entity_registration() {
    let mut registry = SchemaRegistry::new();
    registry.register_fact::<EntityShapedFact>().unwrap();
    let scope = ArtifactScopeId::for_in_memory(894, 0);
    let artifact = ArtifactFactIr {
        format_version: FACT_IR_FORMAT_VERSION,
        tables: vec![encoded_table(
            EntityShapedFact::ID,
            TableKind::Fact,
            Vec::new(),
        )],
        fact_index: Vec::new(),
        relation_index: Vec::new(),
    };
    let view = ArtifactDbView::open(&artifact, &registry).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let reference = ScopedEntityRef::new(
        scope,
        EntityRef {
            schema: schema(EntityShapedFact::ID),
            row: 0,
        },
    );

    assert!(matches!(
        read_artifact_entity::<EntityShapedFact>(
            &registry,
            view,
            &workspace,
            [schema(EntityShapedFact::ID)],
            &reference,
        ),
        Err(RuleError::WrongInputKind {
            schema,
            expected: "artifact entity",
            found: TableKind::Fact,
            ..
        }) if schema.as_str() == EntityShapedFact::ID
    ));
}

#[test]
fn typed_entity_lookup_rejects_a_dangling_row() {
    let registry = fixture_registry();
    let scope = ArtifactScopeId::for_in_memory(895, 0);
    let artifact = node_artifact("node");
    let view = ArtifactDbView::open(&artifact, &registry).unwrap();
    let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
    let reference = ScopedEntityRef::new(
        scope,
        EntityRef {
            schema: schema(Node::ID),
            row: 7,
        },
    );

    assert!(matches!(
        read_artifact_entity::<Node>(
            &registry,
            view,
            &workspace,
            [schema(Node::ID)],
            &reference,
        ),
        Err(RuleError::ArtifactRead { schema, reason, .. })
            if schema.as_str() == Node::ID && reason.contains("outside schema")
    ));
}

#[test]
fn typed_entity_lookup_rejects_an_unmanaged_scope() {
    let registry = fixture_registry();
    let managed_scope = ArtifactScopeId::for_in_memory(896, 0);
    let unmanaged_scope = ArtifactScopeId::for_in_memory(897, 0);
    let artifact = node_artifact("node");
    let view = ArtifactDbView::open(&artifact, &registry).unwrap();
    let workspace = WorkspaceFactView::compose([(managed_scope, view)]).unwrap();
    let reference = ScopedEntityRef::new(
        unmanaged_scope,
        EntityRef {
            schema: schema(Node::ID),
            row: 0,
        },
    );

    assert!(matches!(
        read_artifact_entity::<Node>(
            &registry,
            view,
            &workspace,
            [schema(Node::ID)],
            &reference,
        ),
        Err(RuleError::ArtifactRead { schema, reason, .. })
            if schema.as_str() == Node::ID && reason.contains("has no artifact scope")
    ));
}

#[test]
fn typed_entity_lookup_is_bound_to_the_exact_workspace_view() {
    let registry = fixture_registry();
    let scope = ArtifactScopeId::for_in_memory(898, 0);
    let original_artifact = node_artifact("original");
    let replacement_artifact = node_artifact("replacement");
    let original_view = ArtifactDbView::open(&original_artifact, &registry).unwrap();
    let replacement_view = ArtifactDbView::open(&replacement_artifact, &registry).unwrap();
    let original_workspace = WorkspaceFactView::compose([(scope.clone(), original_view)]).unwrap();
    let reference = ScopedEntityRef::new(
        scope,
        EntityRef {
            schema: schema(Node::ID),
            row: 0,
        },
    );

    assert_eq!(
        read_artifact_entity::<Node>(
            &registry,
            replacement_view,
            &original_workspace,
            [schema(Node::ID)],
            &reference,
        )
        .unwrap(),
        Node {
            name: String::from("original")
        }
    );
}

#[test]
fn workspace_preflight_and_typed_fact_lookup_use_the_referenced_dependency_scope() {
    let fixture = Fixture::new();
    let local_scope = ArtifactScopeId::for_in_memory(900, 0);
    let dependency_scope = ArtifactScopeId::for_in_memory(901, 0);
    let local_artifact = ArtifactFactIr {
        format_version: FACT_IR_FORMAT_VERSION,
        tables: vec![
            encoded_table(Assertion::ID, TableKind::Fact, Vec::new()),
            encoded_table(
                Node::ID,
                TableKind::Entity,
                vec![(Some(json!("local-root")), json!({ "name": "local-root" }))],
            ),
        ],
        fact_index: Vec::new(),
        relation_index: Vec::new(),
    };
    let workspace = WorkspaceFactView::compose([
        (
            local_scope.clone(),
            ArtifactDbView::open(&local_artifact, &fixture.registry).unwrap(),
        ),
        (
            dependency_scope.clone(),
            ArtifactDbView::open(&fixture.artifact, &fixture.registry).unwrap(),
        ),
    ])
    .unwrap();
    let root = EvaluationRoot::new(
        fixture.root.domain.clone(),
        ScopedEntityRef::new(
            local_scope,
            EntityRef {
                schema: schema(Node::ID),
                row: 0,
            },
        ),
    );
    let composition_schemas = CompositionRelationRegistry::new();
    let composition = CompositionRelationBuilder::new(&root, &workspace, &composition_schemas)
        .unwrap()
        .finalize()
        .unwrap();
    let evaluation = WorkspaceEvaluationView::open(&root, &workspace, &composition).unwrap();
    let mut scheduler = EvaluationRuleScheduler::<Log>::default();
    scheduler
        .register(
            &fixture.registry,
            ReadScopedAssertionRule {
                assertion: ScopedRowRef::new(
                    dependency_scope,
                    RowRef {
                        schema: schema(Assertion::ID),
                        row: 0,
                    },
                ),
            },
        )
        .unwrap();
    let log = Log::new(Vec::new());
    let mut evaluated = EvaluationDb::new();

    scheduler
        .run_all_workspace(&log, &root, &evaluation, &mut evaluated)
        .unwrap();

    assert_eq!(
        log.into_inner(),
        vec![String::from("division requires a nonzero divisor")]
    );
}

#[test]
fn workspace_preflight_rejects_a_declared_input_missing_from_one_managed_scope() {
    let fixture = Fixture::new();
    let local_scope = ArtifactScopeId::for_in_memory(910, 0);
    let dependency_scope = ArtifactScopeId::for_in_memory(911, 0);
    let local_artifact = ArtifactFactIr {
        format_version: FACT_IR_FORMAT_VERSION,
        tables: vec![encoded_table(
            Node::ID,
            TableKind::Entity,
            vec![(Some(json!("local-root")), json!({ "name": "local-root" }))],
        )],
        fact_index: Vec::new(),
        relation_index: Vec::new(),
    };
    let workspace = WorkspaceFactView::compose([
        (
            local_scope.clone(),
            ArtifactDbView::open(&local_artifact, &fixture.registry).unwrap(),
        ),
        (
            dependency_scope.clone(),
            ArtifactDbView::open(&fixture.artifact, &fixture.registry).unwrap(),
        ),
    ])
    .unwrap();
    let root = EvaluationRoot::new(
        fixture.root.domain.clone(),
        ScopedEntityRef::new(
            local_scope,
            EntityRef {
                schema: schema(Node::ID),
                row: 0,
            },
        ),
    );
    let composition_schemas = CompositionRelationRegistry::new();
    let composition = CompositionRelationBuilder::new(&root, &workspace, &composition_schemas)
        .unwrap()
        .finalize()
        .unwrap();
    let evaluation = WorkspaceEvaluationView::open(&root, &workspace, &composition).unwrap();
    let mut scheduler = EvaluationRuleScheduler::<Log>::default();
    scheduler
        .register(
            &fixture.registry,
            ReadScopedAssertionRule {
                assertion: ScopedRowRef::new(
                    dependency_scope,
                    RowRef {
                        schema: schema(Assertion::ID),
                        row: 0,
                    },
                ),
            },
        )
        .unwrap();
    let log = Log::new(Vec::new());
    let mut evaluated = EvaluationDb::new();

    assert!(matches!(
        scheduler.run_all_workspace(&log, &root, &evaluation, &mut evaluated),
        Err(EvaluationPipelineError::Run(RuleRunError {
            source: RuleError::MissingArtifactInput { schema, .. },
            ..
        })) if schema.as_str() == Assertion::ID
    ));
    assert!(log.into_inner().is_empty());
    assert_eq!(evaluated.derived_count(), 0);
    assert_eq!(evaluated.issue_count(), 0);
}

#[test]
fn issue_dependency_drives_typed_rules_and_keeps_artifact_immutable() {
    let fixture = Fixture::new();
    let original = fixture.artifact.clone();
    let mut scheduler = EvaluationRuleScheduler::<Log>::default();
    scheduler
        .register(
            &fixture.registry,
            DeriveAlertRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.derive").unwrap())
                    .read::<Alert>()
                    .write_issue::<DerivedAlert>(),
                context: fixture.issue_context(),
            },
        )
        .unwrap();
    scheduler
        .register(
            &fixture.registry,
            EmitAlertRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.emit").unwrap())
                    .read::<Assertion>()
                    .read::<Calls>()
                    .write_derived::<ObligationRecord>()
                    .write_issue::<Alert>(),
                context: fixture.issue_context(),
                obligation: fixture.obligation(),
                fail_after_output: false,
            },
        )
        .unwrap();
    let log = Log::new(Vec::new());
    let mut evaluated = EvaluationDb::new();

    scheduler
        .run_all(&log, &fixture.root, fixture.view(), &mut evaluated)
        .unwrap();
    let results = evaluated.finish().unwrap();

    assert_eq!(&*log.borrow(), &["sample.emit", "sample.derive"]);
    assert_eq!(fixture.artifact, original);
    let obligations = results
        .derived_rows::<ObligationRecord>(&fixture.registry)
        .unwrap();
    assert_eq!(obligations.len(), 1);
    assert_eq!(obligations[0].data, fixture.obligation());
    let alerts = results.issues::<Alert>(&fixture.registry).unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        alerts[0].data.message,
        "division requires a nonzero divisor"
    );
    assert_eq!(alerts[0].context, fixture.issue_context());
    let derived = results.issues::<DerivedAlert>(&fixture.registry).unwrap();
    assert_eq!(derived.len(), 1);
    assert_eq!(
        derived[0].data.message,
        "derived: division requires a nonzero divisor"
    );

    let mut reversed = EvaluationRuleScheduler::<Log>::default();
    reversed
        .register(
            &fixture.registry,
            EmitAlertRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.emit").unwrap())
                    .read::<Assertion>()
                    .read::<Calls>()
                    .write_derived::<ObligationRecord>()
                    .write_issue::<Alert>(),
                context: fixture.issue_context(),
                obligation: fixture.obligation(),
                fail_after_output: false,
            },
        )
        .unwrap();
    reversed
        .register(
            &fixture.registry,
            DeriveAlertRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.derive").unwrap())
                    .read::<Alert>()
                    .write_issue::<DerivedAlert>(),
                context: fixture.issue_context(),
            },
        )
        .unwrap();
    let mut reversed_db = EvaluationDb::new();
    reversed
        .run_all(
            &Log::new(Vec::new()),
            &fixture.root,
            fixture.view(),
            &mut reversed_db,
        )
        .unwrap();
    let reversed_results = reversed_db.finish().unwrap();
    assert_eq!(results.issue_tables(), reversed_results.issue_tables());
    assert_eq!(results.issue_index(), reversed_results.issue_index());
    assert_eq!(results.derived_tables(), reversed_results.derived_tables());
    assert_eq!(results.derived_index(), reversed_results.derived_index());
}

#[test]
fn typed_derived_rows_chain_obligations_through_evidence_into_issues() {
    let fixture = Fixture::new();
    let mut scheduler = EvaluationRuleScheduler::<Log>::default();
    scheduler
        .register(
            &fixture.registry,
            ReportEvidenceRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.report-evidence").unwrap())
                    .read::<EvidenceMatch>()
                    .write_issue::<DerivedAlert>(),
                context: fixture.issue_context(),
            },
        )
        .unwrap();
    scheduler
        .register(
            &fixture.registry,
            MatchEvidenceRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.match-evidence").unwrap())
                    .read::<ObligationRecord>()
                    .write_derived::<EvidenceMatch>(),
            },
        )
        .unwrap();
    scheduler
        .register(
            &fixture.registry,
            EmitAlertRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.emit-obligation").unwrap())
                    .read::<Assertion>()
                    .read::<Calls>()
                    .write_derived::<ObligationRecord>()
                    .write_issue::<Alert>(),
                context: fixture.issue_context(),
                obligation: fixture.obligation(),
                fail_after_output: false,
            },
        )
        .unwrap();
    let log = Log::new(Vec::new());
    let mut evaluated = EvaluationDb::new();

    scheduler
        .run_all(&log, &fixture.root, fixture.view(), &mut evaluated)
        .unwrap();
    let results = evaluated.finish().unwrap();

    assert_eq!(
        &*log.borrow(),
        &[
            "sample.emit-obligation",
            "sample.match-evidence",
            "sample.report-evidence"
        ]
    );
    let obligations = results
        .derived_rows::<ObligationRecord>(&fixture.registry)
        .unwrap();
    assert_eq!(obligations[0].data, fixture.obligation());
    assert_eq!(obligations[0].root, fixture.root);
    let evidence = results
        .derived_rows::<EvidenceMatch>(&fixture.registry)
        .unwrap();
    assert_eq!(evidence[0].data.satisfied_requirements, 2);
    let issues = results.issues::<DerivedAlert>(&fixture.registry).unwrap();
    assert_eq!(issues[0].data.message, "matched 2 requirements");
}

#[test]
fn derived_rows_are_canonical_and_root_scoped_without_any_issue() {
    let fixture = Fixture::new();
    let first_scheduler = evidence_scheduler(
        &fixture,
        true,
        [
            ("sample.emit-evidence-b", vec![4, 3]),
            ("sample.emit-evidence-a", vec![2, 1]),
        ],
    );
    let mut first = EvaluationDb::new();
    first_scheduler
        .run_all(
            &Log::new(Vec::new()),
            &fixture.root,
            fixture.view(),
            &mut first,
        )
        .unwrap();
    let other_root = EvaluationRoot::new(fixture.root.domain.clone(), fixture.target.clone());
    assert!(matches!(
        first_scheduler.run_all(
            &Log::new(Vec::new()),
            &other_root,
            fixture.view(),
            &mut first,
        ),
        Err(EvaluationPipelineError::RootContextMismatch { expected, found })
            if *expected == other_root && *found == fixture.root
    ));
    let first = first.finish().unwrap();

    let second_scheduler = evidence_scheduler(
        &fixture,
        false,
        [
            ("sample.emit-evidence-a", vec![1, 2]),
            ("sample.emit-evidence-b", vec![3, 4]),
        ],
    );
    let mut second = EvaluationDb::new();
    second_scheduler
        .run_all(
            &Log::new(Vec::new()),
            &fixture.root,
            fixture.view(),
            &mut second,
        )
        .unwrap();
    let second = second.finish().unwrap();

    assert_eq!(first.derived_tables(), second.derived_tables());
    assert_eq!(first.derived_index(), second.derived_index());
    assert_eq!(
        first
            .derived_rows::<EvidenceSummary>(&fixture.registry)
            .unwrap()[0]
            .data
            .observed_matches,
        4
    );
    assert_eq!(
        first
            .derived_rows::<EvidenceMatch>(&fixture.registry)
            .unwrap()
            .into_iter()
            .map(|row| row.data.satisfied_requirements)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
}

#[test]
fn duplicate_missing_and_cyclic_rules_are_structured_errors() {
    let fixture = Fixture::new();
    let duplicate_id = PassId::new("sample.duplicate").unwrap();
    let mut duplicate = EvaluationRuleScheduler::<Log>::default();
    duplicate
        .register(
            &fixture.registry,
            NoopRule {
                descriptor: RuleDescriptor::new(duplicate_id.clone()),
            },
        )
        .unwrap();
    assert!(matches!(
        duplicate.register(
            &fixture.registry,
            NoopRule {
                descriptor: RuleDescriptor::new(duplicate_id.clone()),
            }
        ),
        Err(RuleRegistrationError::DuplicateRuleId { rule }) if rule == duplicate_id
    ));

    let mut missing = EvaluationRuleScheduler::<Log>::default();
    missing
        .register(
            &fixture.registry,
            NoopRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.missing").unwrap())
                    .read::<Alert>(),
            },
        )
        .unwrap();
    assert!(matches!(
        missing.schedule(),
        Err(RuleScheduleError::MissingInput { schema, .. }) if schema.as_str() == Alert::ID
    ));

    let mut cyclic = EvaluationRuleScheduler::<Log>::default();
    cyclic
        .register(
            &fixture.registry,
            NoopRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.cycle-a").unwrap())
                    .read::<DerivedAlert>()
                    .write_issue::<Alert>(),
            },
        )
        .unwrap();
    cyclic
        .register(
            &fixture.registry,
            NoopRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.cycle-b").unwrap())
                    .read::<Alert>()
                    .write_issue::<DerivedAlert>(),
            },
        )
        .unwrap();
    assert!(matches!(
        cyclic.schedule(),
        Err(RuleScheduleError::Cycle { rules, schemas })
            if rules.len() == 2 && schemas.len() == 2
    ));
}

#[test]
fn undeclared_reads_and_evaluation_writes_are_rejected() {
    let fixture = Fixture::new();
    let log = Log::new(Vec::new());

    let mut reads = EvaluationRuleScheduler::<Log>::default();
    reads
        .register(&fixture.registry, UndeclaredReadRule)
        .unwrap();
    let mut evaluated = EvaluationDb::new();
    assert!(matches!(
        reads.run_all(&log, &fixture.root, fixture.view(), &mut evaluated),
        Err(EvaluationPipelineError::Run(RuleRunError {
            source: RuleError::UndeclaredRead { schema, .. },
            ..
        })) if schema.as_str() == Assertion::ID
    ));

    let mut writes = EvaluationRuleScheduler::<Log>::default();
    writes
        .register(
            &fixture.registry,
            UndeclaredWriteRule {
                context: fixture.issue_context(),
            },
        )
        .unwrap();
    assert!(matches!(
        writes.run_all(&log, &fixture.root, fixture.view(), &mut evaluated),
        Err(EvaluationPipelineError::Run(RuleRunError {
            source: RuleError::UndeclaredWrite { schema, .. },
            ..
        })) if schema.as_str() == Alert::ID
    ));
    assert_eq!(evaluated.issue_count(), 0);

    let mut derived_reads = EvaluationRuleScheduler::<Log>::default();
    derived_reads
        .register(&fixture.registry, UndeclaredDerivedReadRule)
        .unwrap();
    assert!(matches!(
        derived_reads.run_all(&log, &fixture.root, fixture.view(), &mut evaluated),
        Err(EvaluationPipelineError::Run(RuleRunError {
            source: RuleError::UndeclaredRead { schema, .. },
            ..
        })) if schema.as_str() == ObligationRecord::ID
    ));

    let mut derived_writes = EvaluationRuleScheduler::<Log>::default();
    derived_writes
        .register(
            &fixture.registry,
            UndeclaredDerivedWriteRule {
                obligation: fixture.obligation(),
            },
        )
        .unwrap();
    assert!(matches!(
        derived_writes.run_all(&log, &fixture.root, fixture.view(), &mut evaluated),
        Err(EvaluationPipelineError::Run(RuleRunError {
            source: RuleError::UndeclaredWrite { schema, .. },
            ..
        })) if schema.as_str() == ObligationRecord::ID
    ));
    assert_eq!(evaluated.derived_count(), 0);
}

#[test]
fn failed_rule_discards_its_complete_issue_and_obligation_delta() {
    let fixture = Fixture::new();
    let mut scheduler = EvaluationRuleScheduler::<Log>::default();
    scheduler
        .register(
            &fixture.registry,
            EmitAlertRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.fails").unwrap())
                    .read::<Assertion>()
                    .read::<Calls>()
                    .write_derived::<ObligationRecord>()
                    .write_issue::<Alert>(),
                context: fixture.issue_context(),
                obligation: fixture.obligation(),
                fail_after_output: true,
            },
        )
        .unwrap();
    let mut evaluated = EvaluationDb::new();

    assert!(matches!(
        scheduler.run_all(
            &Log::new(Vec::new()),
            &fixture.root,
            fixture.view(),
            &mut evaluated
        ),
        Err(EvaluationPipelineError::Run(_))
    ));
    assert_eq!(evaluated.issue_count(), 0);
    assert_eq!(evaluated.derived_count(), 0);
}

#[test]
fn committed_evaluation_rows_cannot_leak_into_another_root() {
    let fixture = Fixture::new();
    let mut scheduler = EvaluationRuleScheduler::<Log>::default();
    scheduler
        .register(
            &fixture.registry,
            EmitAlertRule {
                descriptor: RuleDescriptor::new(PassId::new("sample.root-scoped").unwrap())
                    .read::<Assertion>()
                    .read::<Calls>()
                    .write_derived::<ObligationRecord>()
                    .write_issue::<Alert>(),
                context: fixture.issue_context(),
                obligation: fixture.obligation(),
                fail_after_output: false,
            },
        )
        .unwrap();
    let log = Log::new(Vec::new());
    let mut evaluated = EvaluationDb::new();
    scheduler
        .run_all(&log, &fixture.root, fixture.view(), &mut evaluated)
        .unwrap();
    let other_root = EvaluationRoot::new(fixture.root.domain.clone(), fixture.target.clone());

    assert!(matches!(
        scheduler.run_all(&log, &other_root, fixture.view(), &mut evaluated),
        Err(EvaluationPipelineError::RootContextMismatch {
            expected,
            found,
        }) if *expected == other_root && *found == fixture.root
    ));
}
