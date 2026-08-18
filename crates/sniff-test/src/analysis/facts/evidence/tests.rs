use super::*;
use crate::analysis::facts::builder::ArtifactDbBuilder;
use crate::analysis::facts::composition::{
    CompositionRelationBuilder, CompositionRelationRegistry, WorkspaceEvaluationView,
    WorkspaceRelationRef,
};
use crate::analysis::facts::encoded::{EntityRef, RowRef, TableKind};
use crate::analysis::facts::evaluation::{
    EvaluationCx, EvaluationDb, EvaluationInput, EvaluationOutput, EvaluationPipelineError,
    EvaluationRoot, EvaluationRule, RelationTrace, RuleDescriptor, RuleError,
};
use crate::analysis::facts::human::EvidenceClaimSelector;
use crate::analysis::facts::human::markers::{
    MarkerClaimEntity, MarkerClaimKey, MarkerOccurrenceEntity, MarkerOccurrenceKey,
};
use crate::analysis::facts::pack::AnalysisRegistry;
use crate::analysis::facts::program::SourceAnchorKey;
use crate::analysis::facts::program::topology::CallKind;
use crate::analysis::facts::schema::{EntitySchema, PassId, SchemaId};
use crate::analysis::facts::view::ArtifactDbView;
use crate::analysis::facts::workspace::{
    ArtifactScopeId, ScopedEntityRef, ScopedRelationRef, ScopedRowRef, WorkspaceFactView,
};
use crate::safety::SafetyOpKind;

fn row(schema: &str, row: u32) -> RowRef {
    RowRef {
        schema: SchemaId::new(schema).unwrap(),
        row,
    }
}

fn entity(scope: &ArtifactScopeId, row: u32) -> ScopedEntityRef {
    ScopedEntityRef::new(
        scope.clone(),
        EntityRef {
            schema: SchemaId::new("test.evidence.entity").unwrap(),
            row,
        },
    )
}

fn relation(scope: &ArtifactScopeId, index: u32) -> WorkspaceRelationRef {
    WorkspaceRelationRef::Artifact(ScopedRelationRef::new(
        scope.clone(),
        row("test.evidence.relation", index),
    ))
}

fn source(byte_start: u64, byte_end: u64) -> EvidenceSemanticSourceOrder {
    EvidenceSemanticSourceOrder::new(byte_start, byte_end)
}

fn step(
    caller: &str,
    kind: EvidenceSemanticEdgeOrder,
    target: Option<&str>,
    source: Option<EvidenceSemanticSourceOrder>,
) -> EvidenceSemanticStepOrder {
    EvidenceSemanticStepOrder::new(caller, kind, target.map(String::from), source)
}

fn semantic_order(
    steps: Vec<EvidenceSemanticStepOrder>,
    traversal_order: u64,
) -> EvidenceSemanticOrder {
    EvidenceSemanticOrder::new(steps, traversal_order)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct EvidenceFixtureEntity {
    name: String,
}

impl RowSchema for EvidenceFixtureEntity {
    const ID: &'static str = "test.evidence.entity";
    const VERSION: u32 = 1;
}

impl EntitySchema for EvidenceFixtureEntity {
    type Key = String;

    fn key(&self) -> Self::Key {
        self.name.clone()
    }
}

struct SeedEvidenceUses {
    pass: PassId,
    uses: Vec<EvidenceUseRecord>,
}

impl EvaluationRule<()> for SeedEvidenceUses {
    fn descriptor(&self) -> RuleDescriptor {
        RuleDescriptor::new(self.pass.clone()).write_derived::<EvidenceUseRecord>()
    }

    fn evaluate(
        &self,
        _cx: &EvaluationCx<'_, ()>,
        _input: &EvaluationInput<'_>,
        output: &mut EvaluationOutput<'_>,
    ) -> Result<(), RuleError> {
        for usage in &self.uses {
            output.emit_derived(usage)?;
        }
        Ok(())
    }
}

fn fixture_domain() -> DomainId {
    DomainId::new("test.evidence.domain").unwrap()
}

fn fixture_marker(start: u64) -> MarkerOccurrenceEntity {
    MarkerOccurrenceEntity::new(
        MarkerOccurrenceKey::new(SourceAnchorKey::new("src/lib.rs", start, start + 1), None),
        Vec::new(),
    )
}

fn fixture_claim(marker: &MarkerOccurrenceEntity, ordinal: u32) -> MarkerClaimEntity {
    MarkerClaimEntity::new(
        MarkerClaimKey::new(marker.key().clone(), fixture_domain(), ordinal),
        EvidenceClaimSelector::Unnamed,
        format!("evidence bullet {ordinal}"),
    )
}

fn evidence_fixture_registry() -> AnalysisRegistry<()> {
    let mut registry = AnalysisRegistry::new();
    registry.register_entity::<EvidenceFixtureEntity>().unwrap();
    registry
        .register_entity::<MarkerOccurrenceEntity>()
        .unwrap();
    registry.register_entity::<MarkerClaimEntity>().unwrap();
    registry.install(&EvidenceCoordinatorPack).unwrap();
    registry
}

fn evidence_fixture_artifact(
    registry: &AnalysisRegistry<()>,
    markers: &[MarkerOccurrenceEntity],
    claims: &[MarkerClaimEntity],
) -> crate::analysis::facts::encoded::ArtifactFactIr {
    let mut builder = ArtifactDbBuilder::new();
    for name in ["root", "group-a", "group-b", "group-c"] {
        builder
            .insert_entity(&EvidenceFixtureEntity {
                name: String::from(name),
            })
            .unwrap();
    }
    for marker in markers {
        builder.insert_entity(marker).unwrap();
    }
    for claim in claims {
        builder.insert_entity(claim).unwrap();
    }
    builder.finalize(registry.schemas()).unwrap()
}

fn fixture_ref<E: EntitySchema>(
    view: ArtifactDbView<'_>,
    scope: &ArtifactScopeId,
    key: &E::Key,
) -> ScopedEntityRef {
    ScopedEntityRef::new(
        scope.clone(),
        view.entity_id_by_key::<E>(key)
            .unwrap()
            .expect("fixture entity exists")
            .erase(),
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the helper mirrors the strict EvidenceUseRecord fixture contract"
)]
fn fixture_usage(
    claim: ScopedEntityRef,
    root: &ScopedEntityRef,
    group: ScopedEntityRef,
    source: ScopedRowRef,
    witness_order: u64,
    semantic_caller: &str,
) -> EvidenceUseRecord {
    fixture_usage_in_domain(
        fixture_domain(),
        claim,
        root,
        group,
        source,
        witness_order,
        semantic_caller,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the helper mirrors the strict EvidenceUseRecord fixture contract"
)]
fn fixture_usage_in_domain(
    domain: DomainId,
    claim: ScopedEntityRef,
    root: &ScopedEntityRef,
    group: ScopedEntityRef,
    source: ScopedRowRef,
    witness_order: u64,
    semantic_caller: &str,
) -> EvidenceUseRecord {
    EvidenceUseRecord::new(
        domain,
        claim,
        root.clone(),
        group,
        source,
        RelationTrace::new(root.clone(), root.clone(), Vec::new()),
        witness_order,
        semantic_order(
            vec![step(
                semantic_caller,
                EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert),
                None,
                None,
            )],
            witness_order,
        ),
    )
}

struct EvidenceFixtureRefs {
    root: ScopedEntityRef,
    markers: Vec<ScopedEntityRef>,
    claims: Vec<ScopedEntityRef>,
    groups: [ScopedEntityRef; 3],
}

struct EvidenceFixtureEvaluation {
    registry: AnalysisRegistry<()>,
    evaluated: EvaluationDb,
    outcome: Result<(), EvaluationPipelineError>,
}

fn evaluate_evidence_fixture(
    markers: &[MarkerOccurrenceEntity],
    claims: &[MarkerClaimEntity],
    make_uses: impl FnOnce(&EvidenceFixtureRefs) -> Vec<EvidenceUseRecord>,
) -> EvidenceFixtureEvaluation {
    let mut registry = evidence_fixture_registry();
    let artifact = evidence_fixture_artifact(&registry, markers, claims);
    let scope = ArtifactScopeId::for_in_memory(0x68, 0);
    let refs = {
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        EvidenceFixtureRefs {
            root: fixture_ref::<EvidenceFixtureEntity>(view, &scope, &String::from("root")),
            markers: markers
                .iter()
                .map(|marker| fixture_ref::<MarkerOccurrenceEntity>(view, &scope, marker.key()))
                .collect(),
            claims: claims
                .iter()
                .map(|claim| fixture_ref::<MarkerClaimEntity>(view, &scope, claim.key()))
                .collect(),
            groups: ["group-a", "group-b", "group-c"].map(|name| {
                fixture_ref::<EvidenceFixtureEntity>(view, &scope, &String::from(name))
            }),
        }
    };
    let root = EvaluationRoot::new(fixture_domain(), refs.root.clone());
    registry
        .register_evaluation_rule(SeedEvidenceUses {
            pass: PassId::new("test.evidence.seed-invalid-uses").unwrap(),
            uses: make_uses(&refs),
        })
        .unwrap();
    let mut evaluated = EvaluationDb::new();
    let outcome = registry.run_evaluation(
        &(),
        &root,
        ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        &mut evaluated,
    );
    EvidenceFixtureEvaluation {
        registry,
        evaluated,
        outcome,
    }
}

#[test]
fn canonical_use_prefers_shorter_semantic_path_over_dense_witness_rank() {
    let scope = ArtifactScopeId::for_in_memory(0x61, 0);
    let root = entity(&scope, 0);
    let trace_target = entity(&scope, 3);
    let short_endpoint = entity(&scope, 4);
    let long_endpoint = entity(&scope, 5);
    let short_group = entity(&scope, 1);
    let long_group = entity(&scope, 2);
    let claim = entity(&scope, 6);
    let source_row = ScopedRowRef::new(scope.clone(), row("test.evidence.source", 0));
    let short = EvidenceUseRecord::new(
        DomainId::new("test.evidence.domain").unwrap(),
        claim.clone(),
        short_endpoint.clone(),
        short_group.clone(),
        source_row.clone(),
        RelationTrace::new(
            root.clone(),
            trace_target.clone(),
            vec![relation(&scope, 0)],
        ),
        9,
        semantic_order(
            vec![step(
                "crate::root",
                EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert),
                Some("compiler assert index out of bounds"),
                Some(source(40, 50)),
            )],
            20,
        ),
    );
    let long = EvidenceUseRecord::new(
        DomainId::new("test.evidence.domain").unwrap(),
        claim,
        long_endpoint.clone(),
        long_group.clone(),
        source_row,
        RelationTrace::new(
            root,
            trace_target,
            vec![relation(&scope, 1), relation(&scope, 2)],
        ),
        0,
        semantic_order(
            vec![
                step(
                    "crate::root",
                    EvidenceSemanticEdgeOrder::Reachability(CallKind::DirectCall),
                    Some("crate::callee"),
                    Some(source(0, 5)),
                ),
                step(
                    "crate::callee",
                    EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert),
                    Some("compiler assert arithmetic overflow"),
                    Some(source(10, 15)),
                ),
            ],
            1,
        ),
    );

    let short_first = canonical_evidence_use([&short, &long]).unwrap();
    let long_first = canonical_evidence_use([&long, &short]).unwrap();

    assert_eq!(short_first.endpoint(), &short_endpoint);
    assert_eq!(long_first.endpoint(), &short_endpoint);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one test pins the complete legacy comparator precedence ladder"
)]
fn semantic_order_matches_legacy_step_fields_and_uses_traversal_last() {
    let base = semantic_order(
        vec![step(
            "crate::a",
            EvidenceSemanticEdgeOrder::Reachability(CallKind::DirectCall),
            None,
            Some(source(10, 20)),
        )],
        9,
    );
    let later_caller = semantic_order(
        vec![step(
            "crate::z",
            EvidenceSemanticEdgeOrder::Reachability(CallKind::DirectCall),
            None,
            Some(source(10, 20)),
        )],
        0,
    );
    let later_edge = semantic_order(
        vec![step(
            "crate::a",
            EvidenceSemanticEdgeOrder::UnsafeOperation(SafetyOpKind::DerefRawPointer),
            None,
            Some(source(10, 20)),
        )],
        0,
    );
    let target = semantic_order(
        vec![step(
            "crate::a",
            EvidenceSemanticEdgeOrder::Reachability(CallKind::DirectCall),
            Some("crate::target"),
            Some(source(10, 20)),
        )],
        0,
    );
    let no_source = semantic_order(
        vec![step(
            "crate::a",
            EvidenceSemanticEdgeOrder::Reachability(CallKind::DirectCall),
            None,
            None,
        )],
        0,
    );
    let later_source = semantic_order(
        vec![step(
            "crate::a",
            EvidenceSemanticEdgeOrder::Reachability(CallKind::DirectCall),
            None,
            Some(source(11, 20)),
        )],
        0,
    );
    let earlier_traversal = semantic_order(base.steps().to_vec(), 8);
    let later_target = semantic_order(
        vec![step(
            "crate::a",
            EvidenceSemanticEdgeOrder::Reachability(CallKind::DirectCall),
            Some("crate::z"),
            Some(source(10, 20)),
        )],
        0,
    );
    let earlier_target = semantic_order(
        vec![step(
            "crate::a",
            EvidenceSemanticEdgeOrder::Reachability(CallKind::DirectCall),
            Some("crate::a"),
            Some(source(10, 20)),
        )],
        0,
    );
    let later_source_end = semantic_order(
        vec![step(
            "crate::a",
            EvidenceSemanticEdgeOrder::Reachability(CallKind::DirectCall),
            None,
            Some(source(10, 21)),
        )],
        0,
    );
    let later_call_kind = semantic_order(
        vec![step(
            "crate::a",
            EvidenceSemanticEdgeOrder::Reachability(CallKind::TailCall),
            None,
            Some(source(10, 20)),
        )],
        0,
    );
    let two_steps = semantic_order([base.steps(), base.steps()].concat(), 0);

    assert!(base < later_caller);
    assert!(base < later_edge);
    assert!(
        base < target,
        "ordinary Option ordering must prefer no target"
    );
    assert!(base < no_source, "usable source evidence must sort first");
    assert!(base < later_source);
    assert!(base < later_source_end);
    assert!(base < later_call_kind);
    assert!(earlier_target < later_target);
    assert!(base < two_steps);
    assert!(earlier_traversal < base);
    assert_eq!(base, base.clone());
}

#[test]
fn semantic_edge_ordinals_cover_every_legacy_call_kind() {
    let kinds = [
        CallKind::DirectCall,
        CallKind::TailCall,
        CallKind::FnPointerReify,
        CallKind::ClosureFnPointerReify,
        CallKind::FnPointerCallTarget,
        CallKind::DynObjectCast,
        CallKind::VTableEntry,
        CallKind::DynDispatchVTableEntry,
        CallKind::MacroExpansion,
        CallKind::ConstBody,
        CallKind::CoroutineBody,
        CallKind::Assert,
        CallKind::IndirectCall,
    ];

    assert!(kinds.windows(2).all(|pair| {
        EvidenceSemanticEdgeOrder::Reachability(pair[0])
            < EvidenceSemanticEdgeOrder::Reachability(pair[1])
    }));

    let safety_kinds = [
        SafetyOpKind::DerefRawPointer,
        SafetyOpKind::UseOfMutableStatic,
        SafetyOpKind::UseOfExternStatic,
        SafetyOpKind::AccessToUnionField,
        SafetyOpKind::UseOfUnsafeField,
        SafetyOpKind::InitializingLayoutConstrainedType,
        SafetyOpKind::InitializingTypeWithUnsafeField,
        SafetyOpKind::MutationOfLayoutConstrainedField,
        SafetyOpKind::BorrowOfLayoutConstrainedField,
        SafetyOpKind::InlineAssembly,
        SafetyOpKind::UnsafeBinderCast,
    ];
    assert!(safety_kinds.windows(2).all(|pair| {
        EvidenceSemanticEdgeOrder::UnsafeOperation(pair[0])
            < EvidenceSemanticEdgeOrder::UnsafeOperation(pair[1])
    }));
}

#[test]
fn group_never_breaks_an_otherwise_equal_canonical_use_tie() {
    let scope = ArtifactScopeId::for_in_memory(0x62, 0);
    let root = entity(&scope, 0);
    let endpoint = entity(&scope, 1);
    let claim = entity(&scope, 2);
    let source_row = ScopedRowRef::new(scope.clone(), row("test.evidence.source", 0));
    let order = semantic_order(
        vec![step(
            "crate::root",
            EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert),
            Some("compiler assert index out of bounds"),
            Some(source(1, 2)),
        )],
        3,
    );
    let first = EvidenceUseRecord::new(
        DomainId::new("test.evidence.domain").unwrap(),
        claim.clone(),
        endpoint.clone(),
        entity(&scope, 3),
        source_row.clone(),
        RelationTrace::new(root.clone(), endpoint.clone(), Vec::new()),
        0,
        order.clone(),
    );
    let second = EvidenceUseRecord::new(
        DomainId::new("test.evidence.domain").unwrap(),
        claim,
        endpoint.clone(),
        entity(&scope, 4),
        source_row,
        RelationTrace::new(root, endpoint, Vec::new()),
        0,
        order,
    );

    assert_eq!(
        canonical_evidence_use_order(&first, &second),
        Ordering::Equal
    );
}

#[test]
fn claim_is_the_final_canonical_use_tie_break() {
    let scope = ArtifactScopeId::for_in_memory(0x64, 0);
    let root = entity(&scope, 0);
    let endpoint = entity(&scope, 1);
    let source_row = ScopedRowRef::new(scope.clone(), row("test.evidence.source", 0));
    let order = semantic_order(
        vec![step(
            "crate::root",
            EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert),
            None,
            Some(source(1, 2)),
        )],
        3,
    );
    let earlier_claim = entity(&scope, 2);
    let later_claim = entity(&scope, 3);
    let earlier = EvidenceUseRecord::new(
        DomainId::new("test.evidence.domain").unwrap(),
        earlier_claim,
        endpoint.clone(),
        entity(&scope, 4),
        source_row.clone(),
        RelationTrace::new(root.clone(), endpoint.clone(), Vec::new()),
        0,
        order.clone(),
    );
    let later = EvidenceUseRecord::new(
        DomainId::new("test.evidence.domain").unwrap(),
        later_claim,
        endpoint.clone(),
        entity(&scope, 5),
        source_row,
        RelationTrace::new(root, endpoint, Vec::new()),
        0,
        order,
    );

    assert_eq!(canonical_evidence_use([&later, &earlier]), Some(&earlier));
}

#[test]
fn semantic_order_rejects_empty_steps_invalid_ranges_and_unknown_nested_fields() {
    assert!(semantic_order(Vec::new(), 0).validate().is_err());
    assert!(
        semantic_order(
            vec![step(
                "crate::root",
                EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert),
                None,
                Some(source(5, 4)),
            )],
            0,
        )
        .validate()
        .is_err()
    );

    let valid = semantic_order(
        vec![step(
            "crate::root",
            EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert),
            None,
            Some(source(1, 2)),
        )],
        0,
    );
    let encoded = serde_json::to_value(&valid).unwrap();
    for path in ["order", "step", "edge", "source"] {
        let mut hostile = encoded.clone();
        match path {
            "order" => hostile["unexpected"] = serde_json::json!(true),
            "step" => hostile["steps"][0]["unexpected"] = serde_json::json!(true),
            "edge" => {
                hostile["steps"][0]["kind"]["unexpected"] = serde_json::json!(true);
            }
            "source" => {
                hostile["steps"][0]["source"]["unexpected"] = serde_json::json!(true);
            }
            _ => unreachable!(),
        }
        assert!(
            serde_json::from_value::<EvidenceSemanticOrder>(hostile).is_err(),
            "unknown {path} field must be rejected"
        );
    }
}

#[test]
fn evidence_use_v4_requires_semantic_order_and_strict_nested_trace() {
    let scope = ArtifactScopeId::for_in_memory(0x63, 0);
    let root = entity(&scope, 0);
    let endpoint = entity(&scope, 1);
    let usage = EvidenceUseRecord::new(
        DomainId::new("test.evidence.domain").unwrap(),
        entity(&scope, 2),
        endpoint.clone(),
        endpoint.clone(),
        ScopedRowRef::new(scope, row("test.evidence.source", 0)),
        RelationTrace::new(root, endpoint, Vec::new()),
        0,
        semantic_order(
            vec![step(
                "crate::root",
                EvidenceSemanticEdgeOrder::Reachability(CallKind::Assert),
                Some("compiler assert index out of bounds"),
                Some(source(1, 2)),
            )],
            0,
        ),
    );
    let encoded = serde_json::to_value(usage).unwrap();
    let mut missing_order = encoded.clone();
    missing_order
        .as_object_mut()
        .unwrap()
        .remove("semantic-order");
    let mut hostile_trace = encoded;
    hostile_trace["trace"]["unexpected"] = serde_json::json!(true);

    assert!(serde_json::from_value::<EvidenceUseRecord>(missing_order).is_err());
    assert!(serde_json::from_value::<EvidenceUseRecord>(hostile_trace).is_err());
}

#[test]
fn separate_claims_from_one_physical_marker_union_groups_across_producers() {
    let marker = fixture_marker(10);
    let claims = [fixture_claim(&marker, 0), fixture_claim(&marker, 1)];
    let mut registry = evidence_fixture_registry();
    let artifact = evidence_fixture_artifact(&registry, std::slice::from_ref(&marker), &claims);
    let scope = ArtifactScopeId::for_in_memory(0x66, 0);
    let (root, marker_ref, claim_refs, groups) = {
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        (
            fixture_ref::<EvidenceFixtureEntity>(view, &scope, &String::from("root")),
            fixture_ref::<MarkerOccurrenceEntity>(view, &scope, marker.key()),
            claims
                .iter()
                .map(|claim| fixture_ref::<MarkerClaimEntity>(view, &scope, claim.key()))
                .collect::<Vec<_>>(),
            ["group-a", "group-b"].map(|name| {
                fixture_ref::<EvidenceFixtureEntity>(view, &scope, &String::from(name))
            }),
        )
    };
    let compiler_use = fixture_usage(
        claim_refs[0].clone(),
        &root,
        groups[0].clone(),
        groups[0].as_row(),
        4,
        "a-compiler-assert",
    );
    let panic_call_use = fixture_usage(
        claim_refs[1].clone(),
        &root,
        groups[1].clone(),
        groups[1].as_row(),
        8,
        "z-panic-call",
    );
    registry
        .register_evaluation_rule(SeedEvidenceUses {
            pass: PassId::new("test.evidence.compiler-assert-use").unwrap(),
            uses: vec![compiler_use.clone()],
        })
        .unwrap();
    registry
        .register_evaluation_rule(SeedEvidenceUses {
            pass: PassId::new("test.evidence.panic-call-use").unwrap(),
            uses: vec![panic_call_use],
        })
        .unwrap();
    let evaluation_root = EvaluationRoot::new(fixture_domain(), root.clone());
    let mut evaluated = EvaluationDb::new();
    registry
        .run_evaluation(
            &(),
            &evaluation_root,
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
            &mut evaluated,
        )
        .unwrap();
    let results = evaluated.finish().unwrap();
    let issues = results
        .issues::<AmbiguousEvidenceReuseIssue>(registry.schemas())
        .unwrap();

    assert_eq!(issues.len(), 1);
    let issue = &issues[0];
    assert_eq!(issue.data.marker(), &marker_ref);
    assert_eq!(issue.data.groups(), &groups);
    assert_eq!(issue.data.witness_source(), compiler_use.source());
    assert_eq!(issue.data.witness_endpoint(), compiler_use.endpoint());
    assert_eq!(issue.data.witness_order(), compiler_use.witness_order());
    assert_eq!(issue.context.source.as_ref(), Some(&marker_ref.as_row()));
    assert_eq!(
        issue.context.endpoint.as_ref(),
        Some(compiler_use.endpoint())
    );
    assert_eq!(issue.context.trace.as_ref(), Some(compiler_use.trace()));
}

#[test]
fn same_group_reuse_is_unambiguous_and_distinct_marker_occurrences_do_not_merge() {
    let markers = [fixture_marker(20), fixture_marker(30), fixture_marker(40)];
    let claims = [
        fixture_claim(&markers[0], 0),
        fixture_claim(&markers[0], 1),
        fixture_claim(&markers[1], 0),
        fixture_claim(&markers[2], 0),
    ];
    let mut registry = evidence_fixture_registry();
    let artifact = evidence_fixture_artifact(&registry, &markers, &claims);
    let scope = ArtifactScopeId::for_in_memory(0x67, 0);
    let (root, claim_refs, groups) = {
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        (
            fixture_ref::<EvidenceFixtureEntity>(view, &scope, &String::from("root")),
            claims
                .iter()
                .map(|claim| fixture_ref::<MarkerClaimEntity>(view, &scope, claim.key()))
                .collect::<Vec<_>>(),
            ["group-a", "group-b", "group-c"].map(|name| {
                fixture_ref::<EvidenceFixtureEntity>(view, &scope, &String::from(name))
            }),
        )
    };
    let uses = [
        (0, 0, "same-marker-first"),
        (1, 0, "same-marker-second"),
        (2, 1, "other-marker-a"),
        (3, 2, "other-marker-b"),
    ]
    .into_iter()
    .enumerate()
    .map(|(order, (claim, group, caller))| {
        fixture_usage(
            claim_refs[claim].clone(),
            &root,
            groups[group].clone(),
            groups[group].as_row(),
            u64::try_from(order).unwrap(),
            caller,
        )
    })
    .collect();
    registry
        .register_evaluation_rule(SeedEvidenceUses {
            pass: PassId::new("test.evidence.unambiguous-uses").unwrap(),
            uses,
        })
        .unwrap();
    let evaluation_root = EvaluationRoot::new(fixture_domain(), root);
    let mut evaluated = EvaluationDb::new();
    registry
        .run_evaluation(
            &(),
            &evaluation_root,
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
            &mut evaluated,
        )
        .unwrap();

    assert!(
        evaluated
            .finish()
            .unwrap()
            .issues::<AmbiguousEvidenceReuseIssue>(registry.schemas())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn identical_marker_and_claim_keys_in_distinct_artifact_scopes_do_not_merge() {
    let marker = fixture_marker(45);
    let claim = fixture_claim(&marker, 0);
    let mut registry = evidence_fixture_registry();
    let local_artifact = evidence_fixture_artifact(
        &registry,
        std::slice::from_ref(&marker),
        std::slice::from_ref(&claim),
    );
    let dependency_artifact = local_artifact.clone();
    let local_scope = ArtifactScopeId::for_in_memory(0x6a, 0);
    let dependency_scope = ArtifactScopeId::for_in_memory(0x6b, 0);
    let (root, local_claim, dependency_claim, local_group, dependency_group) = {
        let local_view = ArtifactDbView::open(&local_artifact, registry.schemas()).unwrap();
        let dependency_view =
            ArtifactDbView::open(&dependency_artifact, registry.schemas()).unwrap();
        (
            fixture_ref::<EvidenceFixtureEntity>(local_view, &local_scope, &String::from("root")),
            fixture_ref::<MarkerClaimEntity>(local_view, &local_scope, claim.key()),
            fixture_ref::<MarkerClaimEntity>(dependency_view, &dependency_scope, claim.key()),
            fixture_ref::<EvidenceFixtureEntity>(
                local_view,
                &local_scope,
                &String::from("group-a"),
            ),
            fixture_ref::<EvidenceFixtureEntity>(
                dependency_view,
                &dependency_scope,
                &String::from("group-b"),
            ),
        )
    };
    registry
        .register_evaluation_rule(SeedEvidenceUses {
            pass: PassId::new("test.evidence.cross-scope-uses").unwrap(),
            uses: vec![
                fixture_usage(
                    local_claim,
                    &root,
                    local_group.clone(),
                    local_group.as_row(),
                    0,
                    "local",
                ),
                fixture_usage(
                    dependency_claim,
                    &root,
                    dependency_group.clone(),
                    dependency_group.as_row(),
                    1,
                    "dependency",
                ),
            ],
        })
        .unwrap();
    let local_view = ArtifactDbView::open(&local_artifact, registry.schemas()).unwrap();
    let dependency_view = ArtifactDbView::open(&dependency_artifact, registry.schemas()).unwrap();
    let workspace = WorkspaceFactView::compose([
        (local_scope, local_view),
        (dependency_scope, dependency_view),
    ])
    .unwrap();
    let evaluation_root = EvaluationRoot::new(fixture_domain(), root);
    let composition_registry = CompositionRelationRegistry::new();
    let composition =
        CompositionRelationBuilder::new(&evaluation_root, &workspace, &composition_registry)
            .unwrap()
            .finalize()
            .unwrap();
    let evaluation =
        WorkspaceEvaluationView::open(&evaluation_root, &workspace, &composition).unwrap();
    let mut evaluated = EvaluationDb::new();
    registry
        .run_workspace_evaluation(&(), &evaluation_root, &evaluation, &mut evaluated)
        .unwrap();

    assert!(
        evaluated
            .finish()
            .unwrap()
            .issues::<AmbiguousEvidenceReuseIssue>(registry.schemas())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn orphan_claim_after_a_valid_ambiguity_fails_without_committing_any_issue() {
    let marker = fixture_marker(50);
    let orphan_marker = fixture_marker(60);
    let claims = [
        fixture_claim(&marker, 0),
        fixture_claim(&marker, 1),
        fixture_claim(&orphan_marker, 0),
    ];
    let fixture = evaluate_evidence_fixture(std::slice::from_ref(&marker), &claims, |refs| {
        vec![
            fixture_usage(
                refs.claims[0].clone(),
                &refs.root,
                refs.groups[0].clone(),
                refs.groups[0].as_row(),
                0,
                "valid-a",
            ),
            fixture_usage(
                refs.claims[1].clone(),
                &refs.root,
                refs.groups[1].clone(),
                refs.groups[1].as_row(),
                1,
                "valid-b",
            ),
            fixture_usage(
                refs.claims[2].clone(),
                &refs.root,
                refs.groups[2].clone(),
                refs.groups[2].as_row(),
                2,
                "orphan",
            ),
        ]
    });

    let error = fixture
        .outcome
        .expect_err("an orphan marker occurrence must fail closed");
    assert!(
        error
            .to_string()
            .contains("missing physical marker occurrence")
    );
    assert_eq!(fixture.evaluated.derived_count(), 3);
    assert_eq!(fixture.evaluated.issue_count(), 0);
}

#[test]
fn claim_and_use_domains_must_both_match_the_active_root_without_partial_issues() {
    let other_domain = DomainId::new("test.evidence.other-domain").unwrap();
    let marker = fixture_marker(70);
    let wrong_claim = MarkerClaimEntity::new(
        MarkerClaimKey::new(marker.key().clone(), other_domain.clone(), 0),
        EvidenceClaimSelector::Unnamed,
        "wrong-domain claim",
    );
    let wrong_claim_fixture = evaluate_evidence_fixture(
        std::slice::from_ref(&marker),
        std::slice::from_ref(&wrong_claim),
        |refs| {
            vec![fixture_usage(
                refs.claims[0].clone(),
                &refs.root,
                refs.groups[0].clone(),
                refs.groups[0].as_row(),
                0,
                "wrong-claim-domain",
            )]
        },
    );
    let error = wrong_claim_fixture
        .outcome
        .expect_err("the claim domain must agree with the use");
    assert!(error.to_string().contains("claim domain"));
    assert_eq!(wrong_claim_fixture.evaluated.issue_count(), 0);

    let valid_claim = fixture_claim(&marker, 0);
    let wrong_use_fixture = evaluate_evidence_fixture(
        std::slice::from_ref(&marker),
        std::slice::from_ref(&valid_claim),
        |refs| {
            vec![fixture_usage_in_domain(
                other_domain,
                refs.claims[0].clone(),
                &refs.root,
                refs.groups[0].clone(),
                refs.groups[0].as_row(),
                0,
                "wrong-use-domain",
            )]
        },
    );
    let error = wrong_use_fixture
        .outcome
        .expect_err("the use domain must agree with the active root");
    assert!(error.to_string().contains("active root"));
    assert_eq!(wrong_use_fixture.evaluated.issue_count(), 0);
}

#[test]
fn malformed_persisted_claim_is_rejected_before_evidence_evaluation() {
    let marker = fixture_marker(80);
    let claim = fixture_claim(&marker, 0);
    let registry = evidence_fixture_registry();
    let mut artifact = evidence_fixture_artifact(
        &registry,
        std::slice::from_ref(&marker),
        std::slice::from_ref(&claim),
    );
    let claim_table = artifact
        .tables
        .iter_mut()
        .find(|table| table.schema.as_str() == MarkerClaimEntity::ID)
        .unwrap();
    claim_table.rows[0].data["unexpected"] = serde_json::json!(true);

    let error = ArtifactDbView::open(&artifact, registry.schemas())
        .expect_err("strict marker-claim decoding must reject unknown fields");
    assert!(error.to_string().contains(MarkerClaimEntity::ID));
}

#[test]
fn permanent_evidence_coordination_rows_have_the_migrated_versions() {
    assert_eq!(EvidenceUseRecord::VERSION, 4);
    assert_eq!(AmbiguousEvidenceReuseIssue::VERSION, 3);
}

#[test]
fn coordinator_descriptor_reads_occurrence_authority_and_writes_only_the_v3_issue() {
    let registry = evidence_fixture_registry();
    let descriptor = registry
        .evaluation_rules()
        .descriptor(&PassId::new("sniff-test.evidence.detect-reuse").unwrap())
        .expect("the coordinator installs exactly one stable rule identity");

    assert_eq!(
        descriptor.reads().map(SchemaId::as_str).collect::<Vec<_>>(),
        [
            EvidenceUseRecord::ID,
            MarkerClaimEntity::ID,
            MarkerOccurrenceEntity::ID,
        ]
    );
    assert_eq!(
        descriptor
            .writes()
            .map(SchemaId::as_str)
            .collect::<Vec<_>>(),
        [AmbiguousEvidenceReuseIssue::ID]
    );
    let issue = registry
        .schemas()
        .descriptor_for::<AmbiguousEvidenceReuseIssue>()
        .unwrap();
    assert_eq!(issue.version(), 3);
    assert_eq!(issue.kind(), TableKind::Issue);
}

#[test]
fn ambiguous_reuse_v3_is_strict_and_self_identifies_its_canonical_witness() {
    let scope = ArtifactScopeId::for_in_memory(0x65, 0);
    let marker = ScopedEntityRef::new(
        scope.clone(),
        EntityRef {
            schema: SchemaId::new(MarkerOccurrenceEntity::ID).unwrap(),
            row: 7,
        },
    );
    let witness_source = ScopedRowRef::new(scope.clone(), row("test.evidence.source", 8));
    let witness_endpoint = entity(&scope, 9);
    let issue = AmbiguousEvidenceReuseIssue::new(
        DomainId::new("test.evidence.domain").unwrap(),
        marker.clone(),
        witness_source.clone(),
        witness_endpoint.clone(),
        11,
        vec![entity(&scope, 13), entity(&scope, 12)],
    );

    assert_eq!(issue.marker(), &marker);
    assert_eq!(issue.witness_source(), &witness_source);
    assert_eq!(issue.witness_endpoint(), &witness_endpoint);
    assert_eq!(issue.witness_order(), 11);
    assert_eq!(issue.groups(), &[entity(&scope, 12), entity(&scope, 13)]);

    let encoded = serde_json::to_value(&issue).unwrap();
    assert_eq!(
        encoded
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        [
            "domain",
            "groups",
            "marker",
            "witness-endpoint",
            "witness-order",
            "witness-source",
        ]
    );
    assert!(encoded.get("claim").is_none());

    let mut unknown = encoded.clone();
    unknown["claim"] = serde_json::to_value(entity(&scope, 14)).unwrap();
    assert!(serde_json::from_value::<AmbiguousEvidenceReuseIssue>(unknown).is_err());

    for required in [
        "domain",
        "groups",
        "marker",
        "witness-endpoint",
        "witness-order",
        "witness-source",
    ] {
        let mut missing = encoded.clone();
        missing.as_object_mut().unwrap().remove(required);
        assert!(
            serde_json::from_value::<AmbiguousEvidenceReuseIssue>(missing).is_err(),
            "missing {required} must be rejected"
        );
    }
}
