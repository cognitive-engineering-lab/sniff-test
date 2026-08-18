use serde::{Deserialize, Serialize};
use serde_json::json;

use super::*;
use crate::analysis::facts::builder::ArtifactDbBuilder;
use crate::analysis::facts::encoded::{ArtifactFactIr, FACT_IR_FORMAT_VERSION};
use crate::analysis::facts::registry::SchemaRegistry;
use crate::analysis::facts::schema::{
    EntitySchema, FactSchema, RelationSchema, RequirementSchema, RowSchema, SchemaId,
};
use crate::analysis::facts::view::ArtifactDbView;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Node {
    name: String,
    payload: String,
}

impl RowSchema for Node {
    const ID: &'static str = "sample.workspace.node";
    const VERSION: u32 = 1;
}

impl EntitySchema for Node {
    type Key = String;

    fn key(&self) -> Self::Key {
        self.name.clone()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OtherNode {
    name: String,
}

impl RowSchema for OtherNode {
    const ID: &'static str = "sample.workspace.other-node";
    const VERSION: u32 = 1;
}

impl EntitySchema for OtherNode {
    type Key = String;

    fn key(&self) -> Self::Key {
        self.name.clone()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FactMarkedEntity {
    name: String,
}

impl RowSchema for FactMarkedEntity {
    const ID: &'static str = "sample.workspace.fact-marked-entity";
    const VERSION: u32 = 1;
}

impl EntitySchema for FactMarkedEntity {
    type Key = String;

    fn key(&self) -> Self::Key {
        self.name.clone()
    }
}

impl FactSchema for FactMarkedEntity {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Note {
    text: String,
}

impl RowSchema for Note {
    const ID: &'static str = "sample.workspace.note";
    const VERSION: u32 = 1;
}

impl RequirementSchema for Note {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Reaches {
    label: String,
}

impl RowSchema for Reaches {
    const ID: &'static str = "sample.workspace.reaches";
    const VERSION: u32 = 1;
}

impl RelationSchema for Reaches {
    type From = Node;
    type To = Node;
}

fn empty_artifact() -> ArtifactFactIr {
    ArtifactFactIr {
        format_version: FACT_IR_FORMAT_VERSION,
        tables: Vec::new(),
        fact_index: Vec::new(),
        relation_index: Vec::new(),
    }
}

fn scope(id: &str) -> ArtifactScopeId {
    ArtifactScopeId::new(id).expect("valid exact artifact scope")
}

fn entity_registry() -> SchemaRegistry {
    let mut registry = SchemaRegistry::new();
    registry.register_entity::<Node>().unwrap();
    registry
}

fn node_artifact(registry: &SchemaRegistry, nodes: &[(&str, &str)]) -> ArtifactFactIr {
    let mut builder = ArtifactDbBuilder::new();
    for (name, payload) in nodes {
        builder
            .insert_entity(&Node {
                name: (*name).to_owned(),
                payload: (*payload).to_owned(),
            })
            .unwrap();
    }
    builder.finalize(registry).unwrap()
}

fn path_registry() -> SchemaRegistry {
    let mut registry = entity_registry();
    registry.register_relation::<Reaches>().unwrap();
    registry
}

fn path_artifact(registry: &SchemaRegistry) -> ArtifactFactIr {
    let mut builder = ArtifactDbBuilder::new();
    let root = builder
        .insert_entity(&Node {
            name: String::from("root"),
            payload: String::from("root payload"),
        })
        .unwrap();
    let middle = builder
        .insert_entity(&Node {
            name: String::from("middle"),
            payload: String::from("middle payload"),
        })
        .unwrap();
    let target = builder
        .insert_entity(&Node {
            name: String::from("target"),
            payload: String::from("target payload"),
        })
        .unwrap();
    let source = builder
        .insert_entity(&Node {
            name: String::from("source-anchor"),
            payload: String::from("source payload"),
        })
        .unwrap();
    builder
        .relate_with_source(
            &root,
            &middle,
            &source,
            &Reaches {
                label: String::from("first"),
            },
        )
        .unwrap();
    builder
        .relate(
            &middle,
            &target,
            &Reaches {
                label: String::from("second"),
            },
        )
        .unwrap();
    builder.finalize(registry).unwrap()
}

fn note_artifact(registry: &SchemaRegistry, text: &str) -> ArtifactFactIr {
    let mut builder = ArtifactDbBuilder::new();
    builder
        .insert_requirement(&Note {
            text: text.to_owned(),
        })
        .unwrap();
    builder.finalize(registry).unwrap()
}

#[test]
fn artifact_scope_ids_are_stable_string_brands() {
    let scope = scope("consumer.generation-7");

    assert_eq!(scope.as_str(), "consumer.generation-7");
    assert_eq!(serde_json::to_value(&scope).unwrap(), json!(scope.as_str()));
    assert_eq!(
        serde_json::from_value::<ArtifactScopeId>(json!(scope.as_str())).unwrap(),
        scope
    );
    assert!(ArtifactScopeId::new("Consumer Generation 7").is_err());
}

#[test]
fn authoritative_scope_factories_are_canonical_and_namespace_generations() {
    let persisted =
        ArtifactScopeId::for_persisted(0x0123_4567_89ab_cdef, "fedcba98765432100123456789abcdef")
            .unwrap();
    let same_persisted =
        ArtifactScopeId::for_persisted(0x0123_4567_89ab_cdef, "fedcba98765432100123456789abcdef")
            .unwrap();
    let first_memory = ArtifactScopeId::for_in_memory(0x0123_4567_89ab_cdef, 0);
    let second_memory = ArtifactScopeId::for_in_memory(0x0123_4567_89ab_cdef, 1);

    assert_eq!(
        persisted.as_str(),
        "persisted.0123456789abcdef.fedcba98765432100123456789abcdef"
    );
    assert_eq!(persisted, same_persisted);
    assert_eq!(first_memory.as_str(), "in-memory.0123456789abcdef.00000000");
    assert_eq!(
        second_memory.as_str(),
        "in-memory.0123456789abcdef.00000001"
    );
    assert_ne!(persisted, first_memory);
    assert_ne!(first_memory, second_memory);
}

#[test]
fn persisted_scope_factory_rejects_noncanonical_strict_version_hashes() {
    for invalid in [
        "",
        "0123456789abcdef",
        "FEDCBA98765432100123456789ABCDEF",
        "gedcba98765432100123456789abcdef",
        "fedcba98765432100123456789abcdef0",
    ] {
        assert!(matches!(
            ArtifactScopeId::for_persisted(7, invalid),
            Err(ArtifactScopeIdError::InvalidStrictVersionHash { found }) if found == invalid
        ));
    }
}

#[test]
fn scoped_entity_ids_are_ordered_and_hashable_without_entity_trait_bounds() {
    let alpha = ScopedEntityId::<Node>::new(scope("typed.alpha"), EntityId::new(1));
    let beta = ScopedEntityId::<Node>::new(scope("typed.beta"), EntityId::new(1));
    let later = ScopedEntityId::<Node>::new(scope("typed.alpha"), EntityId::new(2));

    let ordered = [beta.clone(), later.clone(), alpha.clone()]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        ordered.into_iter().collect::<Vec<_>>(),
        [alpha.clone(), later, beta]
    );

    let hashed = [alpha.clone(), alpha]
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(hashed.len(), 1);
}

#[test]
fn composition_rejects_duplicate_exact_scopes_and_orders_independent_scopes() {
    let registry = SchemaRegistry::new();
    let artifact = empty_artifact();
    let view = ArtifactDbView::open(&artifact, &registry).unwrap();

    let workspace = WorkspaceFactView::compose([
        (scope("consumer.zeta"), view),
        (scope("consumer.alpha"), view),
    ])
    .unwrap();
    assert_eq!(
        workspace
            .scopes()
            .map(ArtifactScopeId::as_str)
            .collect::<Vec<_>>(),
        vec!["consumer.alpha", "consumer.zeta"]
    );

    let duplicate = scope("consumer.same-generation");
    assert!(matches!(
        WorkspaceFactView::compose([(duplicate.clone(), view), (duplicate.clone(), view)]),
        Err(WorkspaceViewError::DuplicateScope { scope }) if scope == duplicate
    ));
}

#[test]
fn equal_entity_keys_in_two_consumers_keep_exact_scope_and_join_only_explicitly() {
    let registry = entity_registry();
    let alpha_artifact = node_artifact(&registry, &[("shared", "from alpha")]);
    let beta_artifact = node_artifact(&registry, &[("shared", "from beta")]);
    let alpha = scope("consumer.alpha-generation");
    let beta = scope("consumer.beta-generation");
    let workspace = WorkspaceFactView::compose([
        (
            beta.clone(),
            ArtifactDbView::open(&beta_artifact, &registry).unwrap(),
        ),
        (
            alpha.clone(),
            ArtifactDbView::open(&alpha_artifact, &registry).unwrap(),
        ),
    ])
    .unwrap();

    let key = String::from("shared");
    let alpha_ref = workspace
        .entity_by_key::<Node>(&alpha, &key)
        .unwrap()
        .unwrap();
    let beta_ref = workspace
        .entity_by_key::<Node>(&beta, &key)
        .unwrap()
        .unwrap();

    assert_eq!(alpha_ref.entity(), beta_ref.entity());
    assert_ne!(alpha_ref, beta_ref);
    assert_eq!(
        workspace.entity::<Node>(&alpha_ref).unwrap().payload,
        "from alpha"
    );
    assert_eq!(
        workspace.entity::<Node>(&beta_ref).unwrap().payload,
        "from beta"
    );
    assert!(
        workspace
            .entities_equivalent::<Node>(&alpha_ref, &beta_ref)
            .unwrap()
    );
    assert_eq!(
        workspace.equivalent_entities::<Node>(&beta_ref).unwrap(),
        vec![alpha_ref, beta_ref]
    );
}

#[test]
fn scope_specific_lookup_never_falls_through_to_another_artifact_row() {
    let registry = entity_registry();
    let alpha_artifact = node_artifact(&registry, &[("alpha-only", "alpha payload")]);
    let beta_artifact = node_artifact(&registry, &[("beta-only", "beta payload")]);
    let alpha = scope("consumer.alpha-only");
    let beta = scope("consumer.beta-only");
    let workspace = WorkspaceFactView::compose([
        (
            alpha.clone(),
            ArtifactDbView::open(&alpha_artifact, &registry).unwrap(),
        ),
        (
            beta.clone(),
            ArtifactDbView::open(&beta_artifact, &registry).unwrap(),
        ),
    ])
    .unwrap();

    assert!(
        workspace
            .entity_by_key::<Node>(&alpha, &String::from("beta-only"))
            .unwrap()
            .is_none()
    );
    let beta_ref = workspace
        .entity_by_key::<Node>(&beta, &String::from("beta-only"))
        .unwrap()
        .unwrap();
    assert_eq!(
        workspace.entity::<Node>(&beta_ref).unwrap().payload,
        "beta payload"
    );

    let same_local_row_in_alpha = ScopedEntityRef::new(alpha, beta_ref.entity().clone());
    assert_eq!(
        workspace
            .entity::<Node>(&same_local_row_in_alpha)
            .unwrap()
            .payload,
        "alpha payload"
    );
}

#[test]
fn generic_row_lookup_preserves_scope_when_local_row_ids_are_equal() {
    let mut registry = SchemaRegistry::new();
    registry.register_requirement::<Note>().unwrap();
    let alpha_artifact = note_artifact(&registry, "alpha note");
    let beta_artifact = note_artifact(&registry, "beta note");
    let alpha = scope("consumer.row-alpha");
    let beta = scope("consumer.row-beta");
    let workspace = WorkspaceFactView::compose([
        (
            alpha.clone(),
            ArtifactDbView::open(&alpha_artifact, &registry).unwrap(),
        ),
        (
            beta.clone(),
            ArtifactDbView::open(&beta_artifact, &registry).unwrap(),
        ),
    ])
    .unwrap();
    let local_row = crate::analysis::facts::encoded::RowRef {
        schema: SchemaId::new(Note::ID).unwrap(),
        row: 0,
    };
    let alpha_ref = ScopedRowRef::new(alpha.clone(), local_row.clone());
    let beta_ref = ScopedRowRef::new(beta.clone(), local_row);

    let alpha_row = workspace.row::<Note>(&alpha_ref).unwrap();
    let beta_row = workspace.row::<Note>(&beta_ref).unwrap();
    assert_eq!(alpha_row.reference.scope(), &alpha);
    assert_eq!(beta_row.reference.scope(), &beta);
    assert_eq!(alpha_row.data.text, "alpha note");
    assert_eq!(beta_row.data.text, "beta note");
}

#[test]
fn typed_equivalence_rejects_mismatched_and_non_entity_schema_registrations() {
    let mut registry = entity_registry();
    registry.register_entity::<OtherNode>().unwrap();
    registry.register_fact::<FactMarkedEntity>().unwrap();
    let mut builder = ArtifactDbBuilder::new();
    builder
        .insert_entity(&Node {
            name: String::from("node"),
            payload: String::from("node payload"),
        })
        .unwrap();
    builder
        .insert_entity(&OtherNode {
            name: String::from("other"),
        })
        .unwrap();
    let artifact = builder.finalize(&registry).unwrap();
    let exact_scope = scope("consumer.mismatched-join");
    let workspace = WorkspaceFactView::compose([(
        exact_scope.clone(),
        ArtifactDbView::open(&artifact, &registry).unwrap(),
    )])
    .unwrap();
    let node = workspace
        .entity_by_key::<Node>(&exact_scope, &String::from("node"))
        .unwrap()
        .unwrap();
    let other = ScopedEntityRef::new(
        exact_scope.clone(),
        crate::analysis::facts::encoded::EntityRef {
            schema: SchemaId::new(OtherNode::ID).unwrap(),
            row: 0,
        },
    );

    assert!(matches!(
        workspace.entities_equivalent::<Node>(&node, &other),
        Err(WorkspaceViewError::EntitySchemaMismatch { .. })
    ));
    assert!(matches!(
        workspace
            .entity_by_key::<FactMarkedEntity>(&exact_scope, &String::from("not-an-entity-table")),
        Err(WorkspaceViewError::SchemaKindMismatch { .. })
    ));
}

#[test]
fn equivalence_does_not_silently_skip_a_scope_without_the_registered_entity_schema() {
    let registry = entity_registry();
    let artifact = node_artifact(&registry, &[("shared", "registered")]);
    let opaque_registry = SchemaRegistry::new();
    let opaque_artifact = empty_artifact();
    let registered = scope("consumer.registered-schema");
    let opaque = scope("consumer.opaque-schema");
    let workspace = WorkspaceFactView::compose([
        (
            registered.clone(),
            ArtifactDbView::open(&artifact, &registry).unwrap(),
        ),
        (
            opaque.clone(),
            ArtifactDbView::open(&opaque_artifact, &opaque_registry).unwrap(),
        ),
    ])
    .unwrap();
    let anchor = workspace
        .entity_by_key::<Node>(&registered, &String::from("shared"))
        .unwrap()
        .unwrap();

    assert!(matches!(
        workspace.equivalent_entities::<Node>(&anchor),
        Err(WorkspaceViewError::SchemaUnavailable { scope, .. }) if scope == opaque
    ));
}

#[test]
fn relation_lookup_and_validated_paths_retain_endpoint_source_and_relation_scope() {
    let registry = path_registry();
    let alpha_artifact = path_artifact(&registry);
    let beta_artifact = node_artifact(
        &registry,
        &[
            ("root", "beta root"),
            ("middle", "beta middle"),
            ("target", "beta target"),
        ],
    );
    let alpha = scope("consumer.path-alpha");
    let beta = scope("consumer.path-beta");
    let workspace = WorkspaceFactView::compose([
        (
            alpha.clone(),
            ArtifactDbView::open(&alpha_artifact, &registry).unwrap(),
        ),
        (
            beta.clone(),
            ArtifactDbView::open(&beta_artifact, &registry).unwrap(),
        ),
    ])
    .unwrap();
    let root = workspace
        .entity_by_key::<Node>(&alpha, &String::from("root"))
        .unwrap()
        .unwrap();
    let target = workspace
        .entity_by_key::<Node>(&alpha, &String::from("target"))
        .unwrap()
        .unwrap();

    let path = workspace
        .shortest_path(&root, &target)
        .unwrap()
        .expect("alpha has an internal path");
    assert_eq!(path.len(), 2);
    assert!(path.iter().all(|relation| relation.scope() == &alpha));

    let records = workspace.validate_path(&root, &target, &path).unwrap();
    assert_eq!(records.len(), 2);
    for record in &records {
        assert_eq!(record.relation.scope(), &alpha);
        assert_eq!(record.from.scope(), &alpha);
        assert_eq!(record.to.scope(), &alpha);
        assert!(
            record
                .source
                .as_ref()
                .is_none_or(|source| source.scope() == &alpha)
        );
    }
    assert_eq!(records[0].source.as_ref().unwrap().scope(), &alpha);

    let wrong_scope_relation = ScopedRelationRef::new(beta.clone(), path[0].relation().clone());
    assert!(matches!(
        workspace.relation(&wrong_scope_relation),
        Err(WorkspaceViewError::View { scope, .. }) if scope == beta
    ));
}

#[test]
fn paths_never_cross_scopes_implicitly_and_reject_discontinuous_relations() {
    let registry = path_registry();
    let alpha_artifact = path_artifact(&registry);
    let beta_artifact = path_artifact(&registry);
    let alpha = scope("consumer.path-check-alpha");
    let beta = scope("consumer.path-check-beta");
    let workspace = WorkspaceFactView::compose([
        (
            alpha.clone(),
            ArtifactDbView::open(&alpha_artifact, &registry).unwrap(),
        ),
        (
            beta.clone(),
            ArtifactDbView::open(&beta_artifact, &registry).unwrap(),
        ),
    ])
    .unwrap();
    let alpha_root = workspace
        .entity_by_key::<Node>(&alpha, &String::from("root"))
        .unwrap()
        .unwrap();
    let alpha_target = workspace
        .entity_by_key::<Node>(&alpha, &String::from("target"))
        .unwrap()
        .unwrap();
    let beta_target = workspace
        .entity_by_key::<Node>(&beta, &String::from("target"))
        .unwrap()
        .unwrap();
    let path = workspace
        .shortest_path(&alpha_root, &alpha_target)
        .unwrap()
        .unwrap();

    assert!(matches!(
        workspace.shortest_path(&alpha_root, &beta_target),
        Err(WorkspaceViewError::CrossScopePath { .. })
    ));
    assert!(matches!(
        workspace.validate_path(&alpha_root, &alpha_target, &path[1..]),
        Err(WorkspaceViewError::PathDiscontinuity { position: 0, .. })
    ));

    let beta_relation = ScopedRelationRef::new(beta, path[0].relation().clone());
    assert!(matches!(
        workspace.validate_path(&alpha_root, &alpha_target, &[beta_relation]),
        Err(WorkspaceViewError::RelationScopeMismatch { position: 0, .. })
    ));
}
