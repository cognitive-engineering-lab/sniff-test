//! Compile-time schemas for ephemeral workspace-composition relations.

use std::any::{TypeId, type_name};
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde_json::Value;

use super::super::encoded::TableKind;
use super::super::registry::SchemaRegistry;
use super::super::schema::{
    CompositionRelationSchema, EntitySchema, RowSchema, SchemaCodecError, SchemaId, StableIdError,
    canonicalize_row,
};

type RowCanonicalizer = fn(&Value) -> Result<Value, SchemaCodecError>;

/// Registered shape of one workspace-only typed relation schema.
#[derive(Clone)]
pub(crate) struct CompositionRelationDescriptor {
    id: SchemaId,
    version: u32,
    rust_type: TypeId,
    rust_type_name: &'static str,
    from: SchemaId,
    to: SchemaId,
    canonicalize_row: RowCanonicalizer,
}

impl CompositionRelationDescriptor {
    #[must_use]
    pub(crate) const fn id(&self) -> &SchemaId {
        &self.id
    }

    #[must_use]
    pub(crate) const fn version(&self) -> u32 {
        self.version
    }

    #[must_use]
    pub(crate) const fn from(&self) -> &SchemaId {
        &self.from
    }

    #[must_use]
    pub(crate) const fn to(&self) -> &SchemaId {
        &self.to
    }

    pub(crate) fn canonicalize(&self, value: &Value) -> Result<Value, SchemaCodecError> {
        (self.canonicalize_row)(value)
    }
}

impl fmt::Debug for CompositionRelationDescriptor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompositionRelationDescriptor")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("rust_type_name", &self.rust_type_name)
            .field("from", &self.from)
            .field("to", &self.to)
            .finish_non_exhaustive()
    }
}

/// Compile-time schemas permitted in the ephemeral composition relation DB.
#[derive(Debug, Default)]
pub(crate) struct CompositionRelationRegistry {
    schemas: BTreeMap<SchemaId, CompositionRelationDescriptor>,
    types: HashMap<TypeId, SchemaId>,
}

impl CompositionRelationRegistry {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register<R: CompositionRelationSchema>(
        &mut self,
        entities: &SchemaRegistry,
    ) -> Result<(), CompositionRegistryError> {
        let id = schema_id::<R>()?;
        if R::VERSION == 0 {
            return Err(CompositionRegistryError::ZeroVersion {
                schema: id,
                rust_type: type_name::<R>(),
            });
        }
        let from = endpoint_schema::<R::From>(entities, &id, "from")?;
        let to = endpoint_schema::<R::To>(entities, &id, "to")?;

        if let Some(existing) = self.schemas.get(&id) {
            if existing.version != R::VERSION {
                return Err(CompositionRegistryError::IncompatibleVersion {
                    schema: id,
                    registered: existing.version,
                    incoming: R::VERSION,
                });
            }
            if existing.rust_type != TypeId::of::<R>() {
                return Err(CompositionRegistryError::SchemaTypeMismatch {
                    schema: id,
                    registered_type: existing.rust_type_name,
                    incoming_type: type_name::<R>(),
                });
            }
            return Err(CompositionRegistryError::DuplicateSchema { schema: id });
        }
        if let Some(existing) = self.types.get(&TypeId::of::<R>()) {
            return Err(CompositionRegistryError::RustTypeAlreadyRegistered {
                rust_type: type_name::<R>(),
                registered: existing.clone(),
                incoming: id,
            });
        }

        self.types.insert(TypeId::of::<R>(), id.clone());
        self.schemas.insert(
            id.clone(),
            CompositionRelationDescriptor {
                id,
                version: R::VERSION,
                rust_type: TypeId::of::<R>(),
                rust_type_name: type_name::<R>(),
                from,
                to,
                canonicalize_row: canonicalize_row::<R>,
            },
        );
        Ok(())
    }

    #[must_use]
    pub(crate) fn descriptor(&self, schema: &SchemaId) -> Option<&CompositionRelationDescriptor> {
        self.schemas.get(schema)
    }

    pub(crate) fn descriptor_for<R: CompositionRelationSchema>(
        &self,
    ) -> Result<&CompositionRelationDescriptor, CompositionRegistryError> {
        let id = schema_id::<R>()?;
        let descriptor =
            self.schemas
                .get(&id)
                .ok_or_else(|| CompositionRegistryError::SchemaNotRegistered {
                    schema: id.clone(),
                    rust_type: type_name::<R>(),
                })?;
        if descriptor.version != R::VERSION {
            return Err(CompositionRegistryError::IncompatibleVersion {
                schema: id,
                registered: descriptor.version,
                incoming: R::VERSION,
            });
        }
        if descriptor.rust_type != TypeId::of::<R>() {
            return Err(CompositionRegistryError::SchemaTypeMismatch {
                schema: id,
                registered_type: descriptor.rust_type_name,
                incoming_type: type_name::<R>(),
            });
        }
        Ok(descriptor)
    }
}

fn schema_id<S: RowSchema>() -> Result<SchemaId, CompositionRegistryError> {
    SchemaId::new(S::ID).map_err(|source| CompositionRegistryError::InvalidSchemaId {
        declared: S::ID,
        rust_type: type_name::<S>(),
        source,
    })
}

fn endpoint_schema<E: EntitySchema>(
    entities: &SchemaRegistry,
    relation: &SchemaId,
    endpoint: &'static str,
) -> Result<SchemaId, CompositionRegistryError> {
    let schema = schema_id::<E>()?;
    let descriptor = entities.descriptor_for::<E>().map_err(|error| {
        CompositionRegistryError::EndpointUnavailable {
            relation: relation.clone(),
            endpoint,
            schema: schema.clone(),
            reason: error.to_string(),
        }
    })?;
    if descriptor.kind() != TableKind::Entity {
        return Err(CompositionRegistryError::EndpointUnavailable {
            relation: relation.clone(),
            endpoint,
            schema,
            reason: format!("registered as {:?}, expected Entity", descriptor.kind()),
        });
    }
    Ok(descriptor.id().clone())
}

/// Structured compile-time composition-schema registration failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompositionRegistryError {
    InvalidSchemaId {
        declared: &'static str,
        rust_type: &'static str,
        source: StableIdError,
    },
    ZeroVersion {
        schema: SchemaId,
        rust_type: &'static str,
    },
    EndpointUnavailable {
        relation: SchemaId,
        endpoint: &'static str,
        schema: SchemaId,
        reason: String,
    },
    DuplicateSchema {
        schema: SchemaId,
    },
    IncompatibleVersion {
        schema: SchemaId,
        registered: u32,
        incoming: u32,
    },
    SchemaTypeMismatch {
        schema: SchemaId,
        registered_type: &'static str,
        incoming_type: &'static str,
    },
    RustTypeAlreadyRegistered {
        rust_type: &'static str,
        registered: SchemaId,
        incoming: SchemaId,
    },
    SchemaNotRegistered {
        schema: SchemaId,
        rust_type: &'static str,
    },
}

impl Display for CompositionRegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchemaId {
                declared,
                rust_type,
                source,
            } => write!(
                formatter,
                "composition relation {rust_type} declares invalid schema ID {declared:?}: {source}"
            ),
            Self::ZeroVersion { schema, rust_type } => write!(
                formatter,
                "composition relation `{schema}` ({rust_type}) declares version zero"
            ),
            Self::EndpointUnavailable {
                relation,
                endpoint,
                schema,
                reason,
            } => write!(
                formatter,
                "composition relation `{relation}` {endpoint} endpoint `{schema}` is unavailable: {reason}"
            ),
            Self::DuplicateSchema { schema } => {
                write!(
                    formatter,
                    "duplicate composition relation schema `{schema}`"
                )
            }
            Self::IncompatibleVersion {
                schema,
                registered,
                incoming,
            } => write!(
                formatter,
                "composition relation `{schema}` version {incoming} conflicts with registered version {registered}"
            ),
            Self::SchemaTypeMismatch {
                schema,
                registered_type,
                incoming_type,
            } => write!(
                formatter,
                "composition relation `{schema}` belongs to {registered_type}, not {incoming_type}"
            ),
            Self::RustTypeAlreadyRegistered {
                rust_type,
                registered,
                incoming,
            } => write!(
                formatter,
                "composition relation type {rust_type} is already registered as `{registered}`, not `{incoming}`"
            ),
            Self::SchemaNotRegistered { schema, rust_type } => write!(
                formatter,
                "composition relation `{schema}` ({rust_type}) is not registered"
            ),
        }
    }
}

impl Error for CompositionRegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidSchemaId { source, .. } => Some(source),
            Self::ZeroVersion { .. }
            | Self::EndpointUnavailable { .. }
            | Self::DuplicateSchema { .. }
            | Self::IncompatibleVersion { .. }
            | Self::SchemaTypeMismatch { .. }
            | Self::RustTypeAlreadyRegistered { .. }
            | Self::SchemaNotRegistered { .. } => None,
        }
    }
}
