use serde::{Deserialize, Serialize};
use serde_json::json;

use super::graph::{WorkspaceRelationError, WorkspaceRelationIndex};
use super::presentation::{
    CompositionRelationPresenter, CompositionRenderCx, CompositionRenderRegistry,
};
use super::*;
use crate::analysis::facts::builder::ArtifactDbBuilder;
use crate::analysis::facts::evaluation::{DomainId, EvaluationRoot, RelationTrace};
use crate::analysis::facts::registry::SchemaRegistry;
use crate::analysis::facts::schema::{
    CompositionRelationSchema, EntitySchema, RelationSchema, RowSchema,
};
use crate::analysis::facts::view::ArtifactDbView;
use crate::analysis::facts::workspace::{ArtifactScopeId, ScopedEntityId, WorkspaceFactView};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Node {
    key: String,
}

impl RowSchema for Node {
    const ID: &'static str = "sample.composition.node";
    const VERSION: u32 = 1;
}

impl EntitySchema for Node {
    type Key = String;

    fn key(&self) -> Self::Key {
        self.key.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct OtherNode {
    key: String,
}

impl RowSchema for OtherNode {
    const ID: &'static str = "sample.composition.other-node";
    const VERSION: u32 = 1;
}

impl EntitySchema for OtherNode {
    type Key = String;

    fn key(&self) -> Self::Key {
        self.key.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ResolvesTo {
    reason: String,
}

impl RowSchema for ResolvesTo {
    const ID: &'static str = "sample.composition.resolves-to";
    const VERSION: u32 = 1;
}

impl RelationSchema for ResolvesTo {
    type From = Node;
    type To = Node;
}

impl CompositionRelationSchema for ResolvesTo {}

struct ResolvesToPresenter;

impl CompositionRelationPresenter<ResolvesTo> for ResolvesToPresenter {
    fn present(
        &self,
        relation: &ResolvesTo,
        metadata: &CompositionRelationIndexRow,
        _cx: &CompositionRenderCx<'_>,
    ) -> crate::analysis::facts::render::RelationPresentation {
        crate::analysis::facts::render::RelationPresentation::new("resolved exact instance")
            .with_detail(format!(
                "{} ({} -> {})",
                relation.reason,
                metadata.from.scope(),
                metadata.to.scope()
            ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct IncompatibleResolvesTo;

impl RowSchema for IncompatibleResolvesTo {
    const ID: &'static str = ResolvesTo::ID;
    const VERSION: u32 = 2;
}

impl RelationSchema for IncompatibleResolvesTo {
    type From = Node;
    type To = Node;
}

impl CompositionRelationSchema for IncompatibleResolvesTo {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct MissingEndpoint;

impl RowSchema for MissingEndpoint {
    const ID: &'static str = "sample.composition.missing-endpoint";
    const VERSION: u32 = 1;
}

impl RelationSchema for MissingEndpoint {
    type From = Node;
    type To = OtherNode;
}

impl CompositionRelationSchema for MissingEndpoint {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ArtifactEdge {
    label: String,
}

impl RowSchema for ArtifactEdge {
    const ID: &'static str = "sample.composition.artifact-edge";
    const VERSION: u32 = 1;
}

impl RelationSchema for ArtifactEdge {
    type From = Node;
    type To = Node;
}

fn entity_schemas() -> SchemaRegistry {
    let mut schemas = SchemaRegistry::new();
    schemas.register_entity::<Node>().unwrap();
    schemas
}

fn scope(stable_crate_id: u64, ordinal: u32) -> ArtifactScopeId {
    ArtifactScopeId::for_in_memory(stable_crate_id, ordinal)
}

fn node_artifact(
    schemas: &SchemaRegistry,
    nodes: &[&str],
) -> super::super::encoded::ArtifactFactIr {
    let mut builder = ArtifactDbBuilder::new();
    for key in nodes {
        builder
            .insert_entity(&Node {
                key: (*key).to_owned(),
            })
            .unwrap();
    }
    builder.finalize(schemas).unwrap()
}

fn path_artifact(
    schemas: &SchemaRegistry,
    from: &str,
    to: &str,
    label: &str,
) -> super::super::encoded::ArtifactFactIr {
    let mut builder = ArtifactDbBuilder::new();
    let from = builder
        .insert_entity(&Node {
            key: from.to_owned(),
        })
        .unwrap();
    let to = builder.insert_entity(&Node { key: to.to_owned() }).unwrap();
    builder
        .relate(
            &from,
            &to,
            &ArtifactEdge {
                label: label.to_owned(),
            },
        )
        .unwrap();
    builder.finalize(schemas).unwrap()
}

fn assert_composition_presentation<'a>(
    evaluation: &'a WorkspaceEvaluationView<'a>,
    relations: &'a CompositionRelationRegistry,
    reference: &WorkspaceRelationRef,
    local_scope: &ArtifactScopeId,
    dependency_scope: &ArtifactScopeId,
) {
    let mut presenters = CompositionRenderRegistry::new();
    presenters
        .register::<ResolvesTo, _>(relations, ResolvesToPresenter)
        .unwrap();
    let render_cx = CompositionRenderCx::open(evaluation, relations);
    let WorkspaceRelationRef::Composition(reference) = reference else {
        panic!("the explicit cross-scope step is a composition relation");
    };
    let rendered = presenters.present_relation(reference, &render_cx).unwrap();
    assert_eq!(rendered.from.scope(), local_scope);
    assert_eq!(rendered.to.scope(), dependency_scope);
    assert_eq!(rendered.source.as_ref().unwrap().scope(), local_scope);
    assert_eq!(rendered.presentation.summary, "resolved exact instance");
    assert!(
        rendered
            .presentation
            .detail
            .as_deref()
            .unwrap()
            .contains("root-reachable exact instance")
    );
}

#[test]
fn composition_registry_accepts_typed_relations_without_authorizing_artifact_storage() {
    let schemas = entity_schemas();
    let mut registry = CompositionRelationRegistry::new();

    registry.register::<ResolvesTo>(&schemas).unwrap();

    let descriptor = registry.descriptor_for::<ResolvesTo>().unwrap();
    assert_eq!(descriptor.id().as_str(), ResolvesTo::ID);
    assert_eq!(descriptor.version(), ResolvesTo::VERSION);
    assert_eq!(descriptor.from().as_str(), Node::ID);
    assert_eq!(descriptor.to().as_str(), Node::ID);
    assert!(schemas.descriptor(descriptor.id()).is_none());
}

#[test]
fn composition_registry_rejects_missing_entity_endpoints() {
    let schemas = entity_schemas();
    let mut registry = CompositionRelationRegistry::new();

    assert!(matches!(
        registry.register::<MissingEndpoint>(&schemas),
        Err(CompositionRegistryError::EndpointUnavailable { endpoint: "to", .. })
    ));
}

#[test]
fn composition_registry_rejects_duplicate_ids_and_incompatible_versions() {
    let schemas = entity_schemas();
    let mut registry = CompositionRelationRegistry::new();
    registry.register::<ResolvesTo>(&schemas).unwrap();

    assert!(matches!(
        registry.register::<ResolvesTo>(&schemas),
        Err(CompositionRegistryError::DuplicateSchema { .. })
    ));
    assert!(matches!(
        registry.register::<IncompatibleResolvesTo>(&schemas),
        Err(CompositionRegistryError::IncompatibleVersion {
            registered: 1,
            incoming: 2,
            ..
        })
    ));
}

#[test]
fn composition_store_is_root_scoped_and_keeps_typed_cross_scope_endpoints() {
    let schemas = entity_schemas();
    let local_artifact = node_artifact(&schemas, &["local-root"]);
    let dependency_artifact = node_artifact(&schemas, &["dependency-target"]);
    let local_scope = scope(1, 0);
    let dependency_scope = scope(2, 0);
    let workspace = WorkspaceFactView::compose([
        (
            dependency_scope.clone(),
            ArtifactDbView::open(&dependency_artifact, &schemas).unwrap(),
        ),
        (
            local_scope.clone(),
            ArtifactDbView::open(&local_artifact, &schemas).unwrap(),
        ),
    ])
    .unwrap();
    let local = workspace
        .entity_id_by_key::<Node>(&local_scope, &String::from("local-root"))
        .unwrap()
        .unwrap();
    let dependency = workspace
        .entity_id_by_key::<Node>(&dependency_scope, &String::from("dependency-target"))
        .unwrap()
        .unwrap();
    let root = EvaluationRoot::new(
        DomainId::new("sample.composition-domain").unwrap(),
        local.clone().erase(),
    );
    let other_root = EvaluationRoot::new(root.domain.clone(), dependency.clone().erase());
    let mut relations = CompositionRelationRegistry::new();
    relations.register::<ResolvesTo>(&schemas).unwrap();
    let mut builder = CompositionRelationBuilder::new(&root, &workspace, &relations).unwrap();

    builder
        .relate(
            &local,
            &dependency,
            &ResolvesTo {
                reason: String::from("verified call resolution"),
            },
        )
        .unwrap();
    let database = builder.finalize().unwrap();

    assert_eq!(database.root(), &root);
    assert!(matches!(
        database.validate_root(&other_root),
        Err(CompositionBuildError::RootMismatch { .. })
    ));
    let reference = database.relations().next().unwrap().relation.clone();
    let typed = database
        .relation::<ResolvesTo>(&reference, &relations)
        .unwrap();
    assert_eq!(typed.from.erase(), local.erase());
    assert_eq!(typed.to.erase(), dependency.erase());
    assert_eq!(typed.data.reason, "verified call resolution");
    assert_eq!(
        serde_json::to_value(WorkspaceRelationRef::Composition(reference)).unwrap(),
        json!({
            "storage": "composition",
            "reference": {
                "schema": ResolvesTo::ID,
                "row": 0
            }
        })
    );
}

#[test]
fn composition_finalization_is_deterministic_and_rejects_duplicate_edges() {
    let schemas = entity_schemas();
    let artifact = node_artifact(&schemas, &["root", "target-a", "target-b"]);
    let exact_scope = scope(7, 0);
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, &schemas).unwrap(),
    )])
    .unwrap();
    let root_id = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("root"))
        .unwrap()
        .unwrap();
    let target_a = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("target-a"))
        .unwrap()
        .unwrap();
    let target_b = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("target-b"))
        .unwrap()
        .unwrap();
    let root = EvaluationRoot::new(
        DomainId::new("sample.composition-domain").unwrap(),
        root_id.clone().erase(),
    );
    let mut relations = CompositionRelationRegistry::new();
    relations.register::<ResolvesTo>(&schemas).unwrap();

    let build = |targets: [(&ScopedEntityId<Node>, &str); 2]| {
        let mut builder = CompositionRelationBuilder::new(&root, &workspace, &relations).unwrap();
        for (target, reason) in targets {
            builder
                .relate(
                    &root_id,
                    target,
                    &ResolvesTo {
                        reason: reason.to_owned(),
                    },
                )
                .unwrap();
        }
        builder.finalize().unwrap()
    };
    let forward = build([(&target_a, "a"), (&target_b, "b")]);
    let reverse = build([(&target_b, "b"), (&target_a, "a")]);
    assert_eq!(
        serde_json::to_vec(&forward).unwrap(),
        serde_json::to_vec(&reverse).unwrap()
    );

    let mut duplicate = CompositionRelationBuilder::new(&root, &workspace, &relations).unwrap();
    for _ in 0..2 {
        duplicate
            .relate(
                &root_id,
                &target_a,
                &ResolvesTo {
                    reason: String::from("same"),
                },
            )
            .unwrap();
    }
    assert!(matches!(
        duplicate.finalize(),
        Err(CompositionBuildError::DuplicateRelation { .. })
    ));
}

#[test]
fn composition_transaction_restores_exact_prior_draft_length_after_late_error() {
    let schemas = entity_schemas();
    let artifact = node_artifact(&schemas, &["root", "prior", "new-a", "new-b"]);
    let exact_scope = scope(8, 0);
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, &schemas).unwrap(),
    )])
    .unwrap();
    let root_id = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("root"))
        .unwrap()
        .unwrap();
    let prior = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("prior"))
        .unwrap()
        .unwrap();
    let new_a = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("new-a"))
        .unwrap()
        .unwrap();
    let new_b = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("new-b"))
        .unwrap()
        .unwrap();
    let root = EvaluationRoot::new(
        DomainId::new("sample.composition-domain").unwrap(),
        root_id.clone().erase(),
    );
    let mut relations = CompositionRelationRegistry::new();
    relations.register::<ResolvesTo>(&schemas).unwrap();
    let mut builder = CompositionRelationBuilder::new(&root, &workspace, &relations).unwrap();
    builder
        .relate(
            &root_id,
            &prior,
            &ResolvesTo {
                reason: String::from("prior"),
            },
        )
        .unwrap();
    let prior_draft_count = builder.drafts.len();

    let result = builder.transaction(|builder| {
        builder
            .relate(
                &root_id,
                &new_a,
                &ResolvesTo {
                    reason: String::from("new-a"),
                },
            )
            .map_err(|_| "unexpected relation error")?;
        builder
            .relate(
                &root_id,
                &new_b,
                &ResolvesTo {
                    reason: String::from("new-b"),
                },
            )
            .map_err(|_| "unexpected relation error")?;
        Err::<(), _>("late error")
    });

    assert_eq!(result, Err("late error"));
    assert_eq!(builder.drafts.len(), prior_draft_count);
    assert_eq!(prior_draft_count, 1);
    let database = builder.finalize().unwrap();
    let reference = database.relations().next().unwrap().relation.clone();
    let typed = database
        .relation::<ResolvesTo>(&reference, &relations)
        .unwrap();
    assert_eq!(typed.to, prior);
    assert_eq!(typed.data.reason, "prior");
}

#[test]
fn composition_transaction_retains_every_successful_draft() {
    let schemas = entity_schemas();
    let artifact = node_artifact(&schemas, &["root", "target-a", "target-b"]);
    let exact_scope = scope(9, 0);
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, &schemas).unwrap(),
    )])
    .unwrap();
    let root_id = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("root"))
        .unwrap()
        .unwrap();
    let target_a = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("target-a"))
        .unwrap()
        .unwrap();
    let target_b = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("target-b"))
        .unwrap()
        .unwrap();
    let root = EvaluationRoot::new(
        DomainId::new("sample.composition-domain").unwrap(),
        root_id.clone().erase(),
    );
    let mut relations = CompositionRelationRegistry::new();
    relations.register::<ResolvesTo>(&schemas).unwrap();
    let mut builder = CompositionRelationBuilder::new(&root, &workspace, &relations).unwrap();

    builder
        .transaction(|builder| {
            builder.relate(
                &root_id,
                &target_a,
                &ResolvesTo {
                    reason: String::from("a"),
                },
            )?;
            builder.relate(
                &root_id,
                &target_b,
                &ResolvesTo {
                    reason: String::from("b"),
                },
            )?;
            Ok::<_, CompositionBuildError>(())
        })
        .unwrap();

    assert_eq!(builder.drafts.len(), 2);
    let database = builder.finalize().unwrap();
    let mut reasons = database
        .relations()
        .map(|row| {
            database
                .relation::<ResolvesTo>(&row.relation, &relations)
                .unwrap()
                .data
                .reason
        })
        .collect::<Vec<_>>();
    reasons.sort();
    assert_eq!(reasons, ["a", "b"]);
}

#[test]
fn equal_entity_keys_do_not_create_an_implicit_cross_scope_path() {
    let schemas = entity_schemas();
    let local_artifact = node_artifact(&schemas, &["same-key"]);
    let dependency_artifact = node_artifact(&schemas, &["same-key"]);
    let local_scope = scope(11, 0);
    let dependency_scope = scope(12, 0);
    let workspace = WorkspaceFactView::compose([
        (
            local_scope.clone(),
            ArtifactDbView::open(&local_artifact, &schemas).unwrap(),
        ),
        (
            dependency_scope.clone(),
            ArtifactDbView::open(&dependency_artifact, &schemas).unwrap(),
        ),
    ])
    .unwrap();
    let local = workspace
        .entity_id_by_key::<Node>(&local_scope, &String::from("same-key"))
        .unwrap()
        .unwrap();
    let dependency = workspace
        .entity_id_by_key::<Node>(&dependency_scope, &String::from("same-key"))
        .unwrap()
        .unwrap();
    assert!(
        workspace
            .entities_equivalent::<Node>(&local.erase(), &dependency.erase())
            .unwrap()
    );
    let root = EvaluationRoot::new(
        DomainId::new("sample.composition-domain").unwrap(),
        local.clone().erase(),
    );
    let relations = CompositionRelationRegistry::new();
    let database = CompositionRelationBuilder::new(&root, &workspace, &relations)
        .unwrap()
        .finalize()
        .unwrap();

    let evaluation = WorkspaceEvaluationView::open(&root, &workspace, &database).unwrap();
    let graph = evaluation.graph();

    assert_eq!(
        graph.shortest_path(&local.erase(), &dependency.erase()),
        None
    );
}

#[test]
fn mixed_paths_cross_scopes_only_through_explicit_composition_relations() {
    let mut schemas = entity_schemas();
    schemas.register_relation::<ArtifactEdge>().unwrap();
    let local_artifact = path_artifact(&schemas, "local-root", "local-call", "calls");
    let dependency_artifact = path_artifact(
        &schemas,
        "dependency-function",
        "dependency-assert",
        "contains",
    );
    let local_scope = scope(21, 0);
    let dependency_scope = scope(22, 0);
    let workspace = WorkspaceFactView::compose([
        (
            local_scope.clone(),
            ArtifactDbView::open(&local_artifact, &schemas).unwrap(),
        ),
        (
            dependency_scope.clone(),
            ArtifactDbView::open(&dependency_artifact, &schemas).unwrap(),
        ),
    ])
    .unwrap();
    let local_root = workspace
        .entity_id_by_key::<Node>(&local_scope, &String::from("local-root"))
        .unwrap()
        .unwrap();
    let local_call = workspace
        .entity_id_by_key::<Node>(&local_scope, &String::from("local-call"))
        .unwrap()
        .unwrap();
    let dependency_function = workspace
        .entity_id_by_key::<Node>(&dependency_scope, &String::from("dependency-function"))
        .unwrap()
        .unwrap();
    let dependency_assert = workspace
        .entity_id_by_key::<Node>(&dependency_scope, &String::from("dependency-assert"))
        .unwrap()
        .unwrap();
    let root = EvaluationRoot::new(
        DomainId::new("sample.composition-domain").unwrap(),
        local_root.clone().erase(),
    );
    let mut relations = CompositionRelationRegistry::new();
    relations.register::<ResolvesTo>(&schemas).unwrap();
    let mut builder = CompositionRelationBuilder::new(&root, &workspace, &relations).unwrap();
    builder
        .relate_with_source(
            &local_call,
            &dependency_function,
            &local_root.erase(),
            &ResolvesTo {
                reason: String::from("root-reachable exact instance"),
            },
        )
        .unwrap();
    let database = builder.finalize().unwrap();
    let evaluation = WorkspaceEvaluationView::open(&root, &workspace, &database).unwrap();
    let graph = evaluation.graph();

    let path = graph
        .shortest_path(&local_root.erase(), &dependency_assert.erase())
        .expect("the explicit composition relation connects the artifacts");
    assert_eq!(path.len(), 3);
    assert!(matches!(path[0], WorkspaceRelationRef::Artifact(_)));
    assert!(matches!(path[1], WorkspaceRelationRef::Composition(_)));
    assert!(matches!(path[2], WorkspaceRelationRef::Artifact(_)));
    let trace = RelationTrace::new(local_root.erase(), dependency_assert.erase(), path.clone());
    assert_eq!(trace.relations(), path);

    let records = graph
        .validate_path(&local_root.erase(), &dependency_assert.erase(), &path)
        .unwrap();
    assert_eq!(records[0].from.scope(), &local_scope);
    assert_eq!(records[0].to.scope(), &local_scope);
    assert_eq!(records[1].from.scope(), &local_scope);
    assert_eq!(records[1].to.scope(), &dependency_scope);
    assert_eq!(records[1].source.as_ref().unwrap().scope(), &local_scope);
    assert_eq!(records[2].from.scope(), &dependency_scope);
    assert_eq!(records[2].to.scope(), &dependency_scope);

    assert_composition_presentation(
        &evaluation,
        &relations,
        &path[1],
        &local_scope,
        &dependency_scope,
    );

    let discontinuous = [path[0].clone(), path[2].clone()];
    assert!(matches!(
        graph.validate_path(
            &local_root.erase(),
            &dependency_assert.erase(),
            &discontinuous
        ),
        Err(WorkspaceRelationError::PathDiscontinuity { position: 1, .. })
    ));
}

#[test]
fn composition_graph_cannot_be_reused_for_another_evaluation_root() {
    let schemas = entity_schemas();
    let artifact = node_artifact(&schemas, &["root-a", "root-b"]);
    let exact_scope = scope(31, 0);
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, &schemas).unwrap(),
    )])
    .unwrap();
    let root_a = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("root-a"))
        .unwrap()
        .unwrap();
    let root_b = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("root-b"))
        .unwrap()
        .unwrap();
    let domain = DomainId::new("sample.composition-domain").unwrap();
    let first_root = EvaluationRoot::new(domain.clone(), root_a.erase());
    let second_root = EvaluationRoot::new(domain, root_b.erase());
    let relations = CompositionRelationRegistry::new();
    let database = CompositionRelationBuilder::new(&first_root, &workspace, &relations)
        .unwrap()
        .finalize()
        .unwrap();

    assert!(matches!(
        WorkspaceEvaluationView::open(&second_root, &workspace, &database),
        Err(WorkspaceRelationError::RootMismatch { .. })
    ));
}

#[test]
fn composition_graph_revalidates_endpoints_against_its_bound_workspace() {
    let schemas = entity_schemas();
    let artifact = node_artifact(&schemas, &["root", "target"]);
    let replacement_artifact = node_artifact(&schemas, &["root"]);
    let exact_scope = scope(41, 0);
    let original = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, &schemas).unwrap(),
    )])
    .unwrap();
    let root_id = original
        .entity_id_by_key::<Node>(&exact_scope, &String::from("root"))
        .unwrap()
        .unwrap();
    let target = original
        .entity_id_by_key::<Node>(&exact_scope, &String::from("target"))
        .unwrap()
        .unwrap();
    let root = EvaluationRoot::new(
        DomainId::new("sample.composition-domain").unwrap(),
        root_id.clone().erase(),
    );
    let mut relations = CompositionRelationRegistry::new();
    relations.register::<ResolvesTo>(&schemas).unwrap();
    let mut builder = CompositionRelationBuilder::new(&root, &original, &relations).unwrap();
    builder
        .relate(
            &root_id,
            &target,
            &ResolvesTo {
                reason: String::from("original workspace"),
            },
        )
        .unwrap();
    let database = builder.finalize().unwrap();
    let replacement = WorkspaceFactView::compose([(
        exact_scope,
        ArtifactDbView::open(&replacement_artifact, &schemas).unwrap(),
    )])
    .unwrap();

    assert!(matches!(
        WorkspaceEvaluationView::open(&root, &replacement, &database),
        Err(WorkspaceRelationError::WorkspaceMismatch)
    ));
}

#[test]
fn one_artifact_relation_index_can_bind_multiple_root_overlays() {
    let mut schemas = entity_schemas();
    schemas.register_relation::<ArtifactEdge>().unwrap();
    let artifact = path_artifact(&schemas, "root-a", "root-b", "calls");
    let exact_scope = scope(51, 0);
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, &schemas).unwrap(),
    )])
    .unwrap();
    let root_a = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("root-a"))
        .unwrap()
        .unwrap();
    let root_b = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("root-b"))
        .unwrap()
        .unwrap();
    let domain = DomainId::new("sample.composition-domain").unwrap();
    let first_root = EvaluationRoot::new(domain.clone(), root_a.erase());
    let second_root = EvaluationRoot::new(domain, root_b.erase());
    let schemas = CompositionRelationRegistry::new();
    let first_relations = CompositionRelationBuilder::new(&first_root, &workspace, &schemas)
        .unwrap()
        .finalize()
        .unwrap();
    let second_relations = CompositionRelationBuilder::new(&second_root, &workspace, &schemas)
        .unwrap()
        .finalize()
        .unwrap();

    // The overlay API has no workspace argument: artifact entities, relations,
    // and adjacency were already captured exactly once by this immutable index.
    let index = WorkspaceRelationIndex::open(&workspace).unwrap();
    let first_graph = index.bind(&first_root, first_relations).unwrap();
    let second_graph = index.bind(&second_root, second_relations).unwrap();
    let first = WorkspaceEvaluationView::from_graph(&workspace, first_graph).unwrap();
    let second = WorkspaceEvaluationView::from_graph(&workspace, second_graph).unwrap();

    assert_eq!(first.root(), &first_root);
    assert_eq!(second.root(), &second_root);
    assert_eq!(
        first
            .graph()
            .shortest_path(&root_a.erase(), &root_b.erase())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn artifact_and_composition_adjacency_has_one_canonical_order() {
    let mut schemas = entity_schemas();
    schemas.register_relation::<ArtifactEdge>().unwrap();
    let artifact = path_artifact(&schemas, "root", "target", "artifact");
    let exact_scope = scope(56, 0);
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, &schemas).unwrap(),
    )])
    .unwrap();
    let root_id = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("root"))
        .unwrap()
        .unwrap();
    let target = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("target"))
        .unwrap()
        .unwrap();
    let root = EvaluationRoot::new(
        DomainId::new("sample.composition-domain").unwrap(),
        root_id.erase(),
    );
    let mut relation_schemas = CompositionRelationRegistry::new();
    relation_schemas.register::<ResolvesTo>(&schemas).unwrap();
    let mut builder =
        CompositionRelationBuilder::new(&root, &workspace, &relation_schemas).unwrap();
    builder
        .relate(
            &root_id,
            &target,
            &ResolvesTo {
                reason: String::from("composition"),
            },
        )
        .unwrap();

    let index = WorkspaceRelationIndex::open(&workspace).unwrap();
    let graph = index.bind(&root, builder.finalize().unwrap()).unwrap();
    let all = graph
        .relations()
        .map(|relation| relation.relation.clone())
        .collect::<Vec<_>>();
    let outgoing = graph
        .outgoing(&root.entity)
        .map(|relation| relation.relation.clone())
        .collect::<Vec<_>>();

    assert_eq!(all, outgoing);
    assert!(matches!(all[0], WorkspaceRelationRef::Artifact(_)));
    assert!(matches!(all[1], WorkspaceRelationRef::Composition(_)));
}

#[test]
fn prepared_relation_index_cannot_be_attached_to_a_replacement_workspace() {
    let schemas = entity_schemas();
    let artifact = node_artifact(&schemas, &["root"]);
    let exact_scope = scope(61, 0);
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, &schemas).unwrap(),
    )])
    .unwrap();
    let root_id = workspace
        .entity_id_by_key::<Node>(&exact_scope, &String::from("root"))
        .unwrap()
        .unwrap();
    let root = EvaluationRoot::new(
        DomainId::new("sample.composition-domain").unwrap(),
        root_id.erase(),
    );
    let relation_schemas = CompositionRelationRegistry::new();
    let relations = CompositionRelationBuilder::new(&root, &workspace, &relation_schemas)
        .unwrap()
        .finalize()
        .unwrap();
    let index = WorkspaceRelationIndex::open(&workspace).unwrap();
    let graph = index.bind(&root, relations).unwrap();
    let replacement = WorkspaceFactView::compose([(
        exact_scope,
        ArtifactDbView::open(&artifact, &schemas).unwrap(),
    )])
    .unwrap();

    assert!(matches!(
        WorkspaceEvaluationView::from_graph(&replacement, graph),
        Err(WorkspaceRelationError::WorkspaceMismatch)
    ));
}

#[test]
fn relation_index_rejects_an_overlay_built_from_a_replacement_workspace() {
    let schemas = entity_schemas();
    let artifact = node_artifact(&schemas, &["root"]);
    let exact_scope = scope(62, 0);
    let workspace_a = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, &schemas).unwrap(),
    )])
    .unwrap();
    let workspace_b = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, &schemas).unwrap(),
    )])
    .unwrap();
    let root_a = EvaluationRoot::new(
        DomainId::new("sample.composition-domain").unwrap(),
        workspace_a
            .entity_id_by_key::<Node>(&exact_scope, &String::from("root"))
            .unwrap()
            .unwrap()
            .erase(),
    );
    let root_b = EvaluationRoot::new(
        root_a.domain.clone(),
        workspace_b
            .entity_id_by_key::<Node>(&exact_scope, &String::from("root"))
            .unwrap()
            .unwrap()
            .erase(),
    );
    assert_eq!(
        root_a, root_b,
        "the replacement reuses identical row coordinates"
    );
    let relation_schemas = CompositionRelationRegistry::new();
    let overlay_b = CompositionRelationBuilder::new(&root_b, &workspace_b, &relation_schemas)
        .unwrap()
        .finalize()
        .unwrap();
    let index_a = WorkspaceRelationIndex::open(&workspace_a).unwrap();

    assert!(matches!(
        index_a.bind(&root_a, overlay_b),
        Err(WorkspaceRelationError::WorkspaceMismatch)
    ));
}
