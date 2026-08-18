//! Compile-time schema registration and erased persistence adapters.
//!
//! Registry descriptors contain only type identities and monomorphized serde
//! functions. Analysis code remains typed and never handles `Any` or performs
//! runtime downcasts.

use std::any::{TypeId, type_name};
use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Debug, Display, Formatter};

use serde_json::Value;

use super::encoded::TableKind;
use super::schema::{
    DerivedSchema, EntitySchema, FactSchema, IssueSchema, RelationSchema, RequirementSchema,
    RowSchema, SchemaCodecError, SchemaId, StableIdError, canonicalize_row, decode_row,
    encode_entity_key,
};

type RowCanonicalizer = fn(&Value) -> Result<Value, SchemaCodecError>;
type EntityKeyExtractor = fn(&Value) -> Result<Value, SchemaCodecError>;

/// Which endpoint of a relation descriptor failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelationEndpointRole {
    From,
    To,
}

impl Display for RelationEndpointRole {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::From => "from",
            Self::To => "to",
        })
    }
}

/// Registered entity schemas at the two ends of a relation table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelationEndpoints {
    pub(crate) from: SchemaId,
    pub(crate) to: SchemaId,
}

/// Infrastructure description of one concrete Rust row schema.
#[derive(Clone)]
pub(crate) struct SchemaDescriptor {
    id: SchemaId,
    version: u32,
    kind: TableKind,
    rust_type: TypeId,
    rust_type_name: &'static str,
    canonicalize_row: RowCanonicalizer,
    entity_key: Option<EntityKeyExtractor>,
    relation_endpoints: Option<RelationEndpoints>,
}

impl SchemaDescriptor {
    fn plain<S: RowSchema>(kind: TableKind) -> Result<Self, SchemaRegistryError> {
        let id = schema_id::<S>()?;
        if S::VERSION == 0 {
            return Err(SchemaRegistryError::ZeroVersion {
                schema: id,
                rust_type: type_name::<S>(),
            });
        }
        Ok(Self {
            id,
            version: S::VERSION,
            kind,
            rust_type: TypeId::of::<S>(),
            rust_type_name: type_name::<S>(),
            canonicalize_row: canonicalize_row::<S>,
            entity_key: None,
            relation_endpoints: None,
        })
    }

    fn entity<E: EntitySchema>() -> Result<Self, SchemaRegistryError> {
        let mut descriptor = Self::plain::<E>(TableKind::Entity)?;
        descriptor.entity_key = Some(extract_entity_key::<E>);
        Ok(descriptor)
    }

    fn relation<R: RelationSchema>() -> Result<Self, SchemaRegistryError> {
        let mut descriptor = Self::plain::<R>(TableKind::Relation)?;
        descriptor.relation_endpoints = Some(RelationEndpoints {
            from: schema_id::<R::From>()?,
            to: schema_id::<R::To>()?,
        });
        Ok(descriptor)
    }

    #[must_use]
    pub(crate) fn id(&self) -> &SchemaId {
        &self.id
    }

    #[must_use]
    pub(crate) const fn version(&self) -> u32 {
        self.version
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> TableKind {
        self.kind
    }

    #[must_use]
    pub(crate) fn relation_endpoints(&self) -> Option<&RelationEndpoints> {
        self.relation_endpoints.as_ref()
    }

    /// Fully decodes a row, then returns its canonical registered encoding.
    pub(crate) fn canonicalize_row(&self, value: &Value) -> Result<Value, SchemaCodecError> {
        (self.canonicalize_row)(value)
    }

    /// Checks that an erased value decodes as the registered row schema.
    pub(crate) fn validate_row(&self, value: &Value) -> Result<(), SchemaCodecError> {
        self.canonicalize_row(value).map(drop)
    }

    /// Extracts a canonical stable key from an entity row.
    ///
    /// Non-entity descriptors return `None`; malformed entity rows return a
    /// codec error with the entity schema's context.
    pub(crate) fn entity_key(&self, value: &Value) -> Result<Option<Value>, SchemaCodecError> {
        self.entity_key.map(|extract| extract(value)).transpose()
    }
}

impl Debug for SchemaDescriptor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchemaDescriptor")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("rust_type_name", &self.rust_type_name)
            .field("relation_endpoints", &self.relation_endpoints)
            .finish_non_exhaustive()
    }
}

fn extract_entity_key<E: EntitySchema>(value: &Value) -> Result<Value, SchemaCodecError> {
    let entity = decode_row::<E>(value)?;
    encode_entity_key::<E>(&entity.key())
}

fn schema_id<S: RowSchema>() -> Result<SchemaId, SchemaRegistryError> {
    SchemaId::new(S::ID).map_err(|source| SchemaRegistryError::InvalidSchemaId {
        declared: S::ID,
        rust_type: type_name::<S>(),
        source,
    })
}

/// Deterministic registry of compile-time row schemas.
#[derive(Debug, Default)]
pub(crate) struct SchemaRegistry {
    schemas: BTreeMap<SchemaId, SchemaDescriptor>,
    types: HashMap<TypeId, SchemaId>,
}

impl SchemaRegistry {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register_entity<E: EntitySchema>(&mut self) -> Result<(), SchemaRegistryError> {
        self.insert(SchemaDescriptor::entity::<E>()?)
    }

    pub(crate) fn register_fact<F: FactSchema>(&mut self) -> Result<(), SchemaRegistryError> {
        self.insert(SchemaDescriptor::plain::<F>(TableKind::Fact)?)
    }

    pub(crate) fn register_relation<R: RelationSchema>(
        &mut self,
    ) -> Result<(), SchemaRegistryError> {
        let descriptor = SchemaDescriptor::relation::<R>()?;
        let endpoints = descriptor
            .relation_endpoints
            .as_ref()
            .expect("relation descriptors always declare endpoints");
        self.validate_relation_endpoint::<R::From>(
            &descriptor.id,
            RelationEndpointRole::From,
            &endpoints.from,
        )?;
        self.validate_relation_endpoint::<R::To>(
            &descriptor.id,
            RelationEndpointRole::To,
            &endpoints.to,
        )?;
        self.insert(descriptor)
    }

    pub(crate) fn register_requirement<R: RequirementSchema>(
        &mut self,
    ) -> Result<(), SchemaRegistryError> {
        self.insert(SchemaDescriptor::plain::<R>(TableKind::Requirement)?)
    }

    pub(crate) fn register_derived<D: DerivedSchema>(&mut self) -> Result<(), SchemaRegistryError> {
        self.insert(SchemaDescriptor::plain::<D>(TableKind::Derived)?)
    }

    pub(crate) fn register_issue<I: IssueSchema>(&mut self) -> Result<(), SchemaRegistryError> {
        self.insert(SchemaDescriptor::plain::<I>(TableKind::Issue)?)
    }

    #[must_use]
    pub(crate) fn descriptor(&self, schema: &SchemaId) -> Option<&SchemaDescriptor> {
        self.schemas.get(schema)
    }

    pub(crate) fn descriptor_for<S: RowSchema>(
        &self,
    ) -> Result<&SchemaDescriptor, SchemaRegistryError> {
        let schema = schema_id::<S>()?;
        let descriptor =
            self.schemas
                .get(&schema)
                .ok_or_else(|| SchemaRegistryError::SchemaNotRegistered {
                    schema: schema.clone(),
                    rust_type: type_name::<S>(),
                })?;
        if descriptor.version != S::VERSION {
            return Err(SchemaRegistryError::IncompatibleVersion {
                schema,
                registered: descriptor.version,
                incoming: S::VERSION,
            });
        }
        if descriptor.rust_type != TypeId::of::<S>() {
            return Err(SchemaRegistryError::SchemaTypeMismatch {
                schema,
                registered_type: descriptor.rust_type_name,
                requested_type: type_name::<S>(),
            });
        }
        Ok(descriptor)
    }

    /// Iterates descriptors in stable schema-ID order.
    pub(crate) fn descriptors(
        &self,
    ) -> impl ExactSizeIterator<Item = &SchemaDescriptor> + DoubleEndedIterator {
        self.schemas.values()
    }

    /// Validates a known encoded table while preserving unknown schemas.
    pub(crate) fn validate_table(
        &self,
        schema: &SchemaId,
        version: u32,
        kind: TableKind,
    ) -> Result<Option<&SchemaDescriptor>, SchemaRegistryError> {
        let Some(descriptor) = self.schemas.get(schema) else {
            return Ok(None);
        };
        if descriptor.version != version {
            return Err(SchemaRegistryError::IncompatibleVersion {
                schema: schema.clone(),
                registered: descriptor.version,
                incoming: version,
            });
        }
        if descriptor.kind != kind {
            return Err(SchemaRegistryError::KindMismatch {
                schema: schema.clone(),
                registered: descriptor.kind,
                incoming: kind,
            });
        }
        Ok(Some(descriptor))
    }

    fn validate_relation_endpoint<E: EntitySchema>(
        &self,
        relation: &SchemaId,
        role: RelationEndpointRole,
        endpoint: &SchemaId,
    ) -> Result<(), SchemaRegistryError> {
        let Some(descriptor) = self.schemas.get(endpoint) else {
            return Err(SchemaRegistryError::MissingRelationEndpoint {
                relation: relation.clone(),
                role,
                endpoint: endpoint.clone(),
            });
        };
        if descriptor.kind != TableKind::Entity {
            return Err(SchemaRegistryError::RelationEndpointKindMismatch {
                relation: relation.clone(),
                role,
                endpoint: endpoint.clone(),
                registered: descriptor.kind,
            });
        }
        if descriptor.rust_type != TypeId::of::<E>() {
            return Err(SchemaRegistryError::RelationEndpointTypeMismatch {
                relation: relation.clone(),
                role,
                endpoint: endpoint.clone(),
                registered_type: descriptor.rust_type_name,
                requested_type: type_name::<E>(),
            });
        }
        Ok(())
    }

    fn insert(&mut self, descriptor: SchemaDescriptor) -> Result<(), SchemaRegistryError> {
        if let Some(registered) = self.schemas.get(&descriptor.id) {
            if registered.version != descriptor.version {
                return Err(SchemaRegistryError::IncompatibleVersion {
                    schema: descriptor.id,
                    registered: registered.version,
                    incoming: descriptor.version,
                });
            }
            if registered.kind != descriptor.kind {
                return Err(SchemaRegistryError::KindMismatch {
                    schema: descriptor.id,
                    registered: registered.kind,
                    incoming: descriptor.kind,
                });
            }
            if registered.rust_type != descriptor.rust_type {
                return Err(SchemaRegistryError::SchemaIdCollision {
                    schema: descriptor.id,
                    registered_type: registered.rust_type_name,
                    incoming_type: descriptor.rust_type_name,
                });
            }
            return Err(SchemaRegistryError::DuplicateSchemaId {
                schema: descriptor.id,
                rust_type: descriptor.rust_type_name,
            });
        }

        if let Some(registered_id) = self.types.get(&descriptor.rust_type) {
            return Err(SchemaRegistryError::RustTypeAlreadyRegistered {
                rust_type: descriptor.rust_type_name,
                registered_schema: registered_id.clone(),
                incoming_schema: descriptor.id,
            });
        }

        self.types
            .insert(descriptor.rust_type, descriptor.id.clone());
        self.schemas.insert(descriptor.id.clone(), descriptor);
        Ok(())
    }
}

/// Structured schema registration or encoded-table compatibility failure.
#[derive(Debug)]
pub(crate) enum SchemaRegistryError {
    InvalidSchemaId {
        declared: &'static str,
        rust_type: &'static str,
        source: StableIdError,
    },
    ZeroVersion {
        schema: SchemaId,
        rust_type: &'static str,
    },
    DuplicateSchemaId {
        schema: SchemaId,
        rust_type: &'static str,
    },
    SchemaIdCollision {
        schema: SchemaId,
        registered_type: &'static str,
        incoming_type: &'static str,
    },
    IncompatibleVersion {
        schema: SchemaId,
        registered: u32,
        incoming: u32,
    },
    KindMismatch {
        schema: SchemaId,
        registered: TableKind,
        incoming: TableKind,
    },
    RustTypeAlreadyRegistered {
        rust_type: &'static str,
        registered_schema: SchemaId,
        incoming_schema: SchemaId,
    },
    MissingRelationEndpoint {
        relation: SchemaId,
        role: RelationEndpointRole,
        endpoint: SchemaId,
    },
    RelationEndpointKindMismatch {
        relation: SchemaId,
        role: RelationEndpointRole,
        endpoint: SchemaId,
        registered: TableKind,
    },
    RelationEndpointTypeMismatch {
        relation: SchemaId,
        role: RelationEndpointRole,
        endpoint: SchemaId,
        registered_type: &'static str,
        requested_type: &'static str,
    },
    SchemaNotRegistered {
        schema: SchemaId,
        rust_type: &'static str,
    },
    SchemaTypeMismatch {
        schema: SchemaId,
        registered_type: &'static str,
        requested_type: &'static str,
    },
}

impl Display for SchemaRegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchemaId {
                declared,
                rust_type,
                source,
            } => write!(
                formatter,
                "schema type {rust_type} declares invalid ID {declared:?}: {source}"
            ),
            Self::ZeroVersion { schema, rust_type } => write!(
                formatter,
                "schema {schema} for type {rust_type} declares invalid version zero"
            ),
            Self::DuplicateSchemaId { schema, rust_type } => write!(
                formatter,
                "schema {schema} for type {rust_type} was registered more than once"
            ),
            Self::SchemaIdCollision {
                schema,
                registered_type,
                incoming_type,
            } => write!(
                formatter,
                "schema ID {schema} is already owned by {registered_type}, not {incoming_type}"
            ),
            Self::IncompatibleVersion {
                schema,
                registered,
                incoming,
            } => write!(
                formatter,
                "schema {schema} version {incoming} is incompatible with registered version {registered}"
            ),
            Self::KindMismatch {
                schema,
                registered,
                incoming,
            } => write!(
                formatter,
                "schema {schema} has kind {incoming:?}, but registered kind is {registered:?}"
            ),
            Self::RustTypeAlreadyRegistered {
                rust_type,
                registered_schema,
                incoming_schema,
            } => write!(
                formatter,
                "Rust type {rust_type} is already registered as {registered_schema}, not {incoming_schema}"
            ),
            Self::MissingRelationEndpoint {
                relation,
                role,
                endpoint,
            } => write!(
                formatter,
                "relation {relation} has unregistered {role} endpoint schema {endpoint}"
            ),
            Self::RelationEndpointKindMismatch {
                relation,
                role,
                endpoint,
                registered,
            } => write!(
                formatter,
                "relation {relation} {role} endpoint {endpoint} is {registered:?}, not an entity"
            ),
            Self::RelationEndpointTypeMismatch {
                relation,
                role,
                endpoint,
                registered_type,
                requested_type,
            } => write!(
                formatter,
                "relation {relation} {role} endpoint {endpoint} is registered for {registered_type}, not {requested_type}"
            ),
            Self::SchemaNotRegistered { schema, rust_type } => {
                write!(
                    formatter,
                    "schema {schema} for type {rust_type} is not registered"
                )
            }
            Self::SchemaTypeMismatch {
                schema,
                registered_type,
                requested_type,
            } => write!(
                formatter,
                "schema {schema} is registered for {registered_type}, not {requested_type}"
            ),
        }
    }
}

impl std::error::Error for SchemaRegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSchemaId { source, .. } => Some(source),
            Self::ZeroVersion { .. }
            | Self::DuplicateSchemaId { .. }
            | Self::SchemaIdCollision { .. }
            | Self::IncompatibleVersion { .. }
            | Self::KindMismatch { .. }
            | Self::RustTypeAlreadyRegistered { .. }
            | Self::MissingRelationEndpoint { .. }
            | Self::RelationEndpointKindMismatch { .. }
            | Self::RelationEndpointTypeMismatch { .. }
            | Self::SchemaNotRegistered { .. }
            | Self::SchemaTypeMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use super::*;
    use crate::analysis::facts::schema::{
        EntitySchema, FactSchema, IssueSchema, RelationSchema, RequirementSchema, RowSchema,
    };

    #[derive(Clone, Serialize, Deserialize)]
    struct Person {
        name: String,
    }

    impl RowSchema for Person {
        const ID: &'static str = "sample.person";
        const VERSION: u32 = 1;
    }

    impl EntitySchema for Person {
        type Key = String;

        fn key(&self) -> Self::Key {
            self.name.clone()
        }
    }

    impl RequirementSchema for Person {}

    #[derive(Clone, Serialize, Deserialize)]
    struct Place {
        name: String,
    }

    impl RowSchema for Place {
        const ID: &'static str = "sample.place";
        const VERSION: u32 = 1;
    }

    impl EntitySchema for Place {
        type Key = String;

        fn key(&self) -> Self::Key {
            self.name.clone()
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct LivesIn;

    impl RowSchema for LivesIn {
        const ID: &'static str = "sample.lives-in";
        const VERSION: u32 = 1;
    }

    impl RelationSchema for LivesIn {
        type From = Person;
        type To = Place;
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct Observation {
        detail: String,
    }

    impl RowSchema for Observation {
        const ID: &'static str = "sample.observation";
        const VERSION: u32 = 2;
    }

    impl FactSchema for Observation {}

    #[derive(Clone, Serialize, Deserialize)]
    struct Requirement;

    impl RowSchema for Requirement {
        const ID: &'static str = "sample.requirement";
        const VERSION: u32 = 1;
    }

    impl RequirementSchema for Requirement {}

    #[derive(Clone, Serialize, Deserialize)]
    struct Issue;

    impl RowSchema for Issue {
        const ID: &'static str = "sample.issue";
        const VERSION: u32 = 1;
    }

    impl IssueSchema for Issue {}

    #[derive(Clone, Serialize, Deserialize)]
    struct Derived;

    impl RowSchema for Derived {
        const ID: &'static str = "sample.derived";
        const VERSION: u32 = 1;
    }

    impl DerivedSchema for Derived {}

    #[derive(Clone, Serialize, Deserialize)]
    struct ConflictingPerson;

    impl RowSchema for ConflictingPerson {
        const ID: &'static str = Person::ID;
        const VERSION: u32 = 1;
    }

    impl EntitySchema for ConflictingPerson {
        type Key = String;

        fn key(&self) -> Self::Key {
            "conflict".to_owned()
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct NewerPerson;

    impl RowSchema for NewerPerson {
        const ID: &'static str = Person::ID;
        const VERSION: u32 = 2;
    }

    impl EntitySchema for NewerPerson {
        type Key = String;

        fn key(&self) -> Self::Key {
            "newer".to_owned()
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct PersonFact;

    impl RowSchema for PersonFact {
        const ID: &'static str = Person::ID;
        const VERSION: u32 = Person::VERSION;
    }

    impl FactSchema for PersonFact {}

    #[derive(Clone, Serialize, Deserialize)]
    struct ZeroVersion;

    impl RowSchema for ZeroVersion {
        const ID: &'static str = "sample.zero-version";
        const VERSION: u32 = 0;
    }

    impl FactSchema for ZeroVersion {}

    #[test]
    fn registers_every_infrastructure_kind_and_typed_descriptors() {
        let mut registry = SchemaRegistry::new();
        registry.register_entity::<Person>().unwrap();
        registry.register_entity::<Place>().unwrap();
        registry.register_relation::<LivesIn>().unwrap();
        registry.register_fact::<Observation>().unwrap();
        registry.register_requirement::<Requirement>().unwrap();
        registry.register_derived::<Derived>().unwrap();
        registry.register_issue::<Issue>().unwrap();

        assert_eq!(
            registry.descriptor_for::<Person>().unwrap().kind(),
            TableKind::Entity
        );
        assert_eq!(
            registry.descriptor_for::<Observation>().unwrap().version(),
            2
        );
        assert_eq!(
            registry.descriptor_for::<Derived>().unwrap().kind(),
            TableKind::Derived
        );
        let relation = registry.descriptor_for::<LivesIn>().unwrap();
        let endpoints = relation.relation_endpoints().expect("relation endpoints");
        assert_eq!(endpoints.from.as_str(), Person::ID);
        assert_eq!(endpoints.to.as_str(), Place::ID);
        assert_eq!(registry.descriptors().count(), 7);
    }

    #[test]
    fn rejects_schema_collisions_versions_and_kinds_structurally() {
        let mut collision = SchemaRegistry::new();
        collision.register_entity::<Person>().unwrap();
        assert!(matches!(
            collision.register_entity::<ConflictingPerson>(),
            Err(SchemaRegistryError::SchemaIdCollision { .. })
        ));

        let mut version = SchemaRegistry::new();
        version.register_entity::<Person>().unwrap();
        assert!(matches!(
            version.register_entity::<NewerPerson>(),
            Err(SchemaRegistryError::IncompatibleVersion { .. })
        ));

        let mut kind = SchemaRegistry::new();
        kind.register_entity::<Person>().unwrap();
        assert!(matches!(
            kind.register_fact::<PersonFact>(),
            Err(SchemaRegistryError::KindMismatch { .. })
        ));

        let mut zero = SchemaRegistry::new();
        assert!(matches!(
            zero.register_fact::<ZeroVersion>(),
            Err(SchemaRegistryError::ZeroVersion { .. })
        ));
    }

    #[test]
    fn relation_registration_requires_registered_entity_endpoints() {
        let mut registry = SchemaRegistry::new();
        let error = registry
            .register_relation::<LivesIn>()
            .expect_err("endpoints are absent");

        assert!(matches!(
            error,
            SchemaRegistryError::MissingRelationEndpoint {
                role: RelationEndpointRole::From,
                ..
            }
        ));
    }

    #[test]
    fn relation_registration_rejects_non_entity_endpoint_tables() {
        let mut registry = SchemaRegistry::new();
        registry.register_requirement::<Person>().unwrap();
        registry.register_entity::<Place>().unwrap();

        let error = registry
            .register_relation::<LivesIn>()
            .expect_err("a requirement table cannot be a relation endpoint");

        assert!(matches!(
            error,
            SchemaRegistryError::RelationEndpointKindMismatch {
                role: RelationEndpointRole::From,
                registered: TableKind::Requirement,
                ..
            }
        ));
    }

    #[test]
    fn internal_registration_rejects_one_rust_type_under_two_ids() {
        let mut registry = SchemaRegistry::new();
        let descriptor = SchemaDescriptor::entity::<Person>().unwrap();
        let mut alias = descriptor.clone();
        alias.id = SchemaId::new("sample.person-alias").unwrap();
        registry.insert(descriptor).unwrap();

        let error = registry
            .insert(alias)
            .expect_err("a Rust type has one authoritative schema ID");

        assert!(matches!(
            error,
            SchemaRegistryError::RustTypeAlreadyRegistered { .. }
        ));
    }

    #[test]
    fn descriptors_validate_rows_and_extract_canonical_entity_keys() {
        let mut registry = SchemaRegistry::new();
        registry.register_entity::<Person>().unwrap();
        let descriptor = registry.descriptor_for::<Person>().unwrap();

        assert!(descriptor.validate_row(&json!({"name": "Ada"})).is_ok());
        assert!(
            descriptor
                .validate_row(&json!({"name": "Ada", "unknown": true}))
                .is_err()
        );
        assert_eq!(
            descriptor.entity_key(&json!({"name": "Ada"})).unwrap(),
            Some(json!("Ada"))
        );
    }

    #[test]
    fn unknown_tables_remain_opaque_but_known_mismatches_fail() {
        let mut registry = SchemaRegistry::new();
        registry.register_fact::<Observation>().unwrap();

        let unknown = SchemaId::new("future.pack.fact").unwrap();
        assert!(
            registry
                .validate_table(&unknown, 17, TableKind::Fact)
                .unwrap()
                .is_none()
        );
        let known = SchemaId::new(Observation::ID).unwrap();
        assert!(matches!(
            registry.validate_table(&known, 1, TableKind::Fact),
            Err(SchemaRegistryError::IncompatibleVersion { .. })
        ));
        assert!(matches!(
            registry.validate_table(&known, 2, TableKind::Issue),
            Err(SchemaRegistryError::KindMismatch { .. })
        ));
    }
}
