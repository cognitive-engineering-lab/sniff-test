//! Root-scoped typed relations created while composing artifact databases.
//!
//! Composition relations are ephemeral: they never enter an artifact cache and
//! may only be reused inside the exact evaluation-root context that produced
//! them. Their schemas and presenters remain compile-time extension points.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::evaluation::EvaluationRoot;
use super::schema::{
    CompositionRelationSchema, EntityId, SchemaId, canonical_json_bytes, decode_row, encode_row,
};
use super::workspace::{ScopedEntityId, ScopedEntityRef, WorkspaceFactView, WorkspaceIdentity};

pub(crate) mod presentation;

mod registry;

pub(crate) use registry::{CompositionRegistryError, CompositionRelationRegistry};

/// Canonical row identity of one root-scoped workspace composition relation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CompositionRelationRef {
    pub(crate) schema: SchemaId,
    pub(crate) row: u32,
}

pub(crate) mod graph;

pub(crate) use graph::{
    WorkspaceEvaluationView, WorkspaceRelationGraph, WorkspaceRelationIndex, WorkspaceRelationRef,
};

/// Generic exact-scoped endpoint metadata for one composition relation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CompositionRelationIndexRow {
    pub(crate) relation: CompositionRelationRef,
    pub(crate) from: ScopedEntityRef,
    pub(crate) to: ScopedEntityRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<ScopedEntityRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct CompositionRelationTable {
    schema: SchemaId,
    version: u32,
    rows: Vec<Value>,
}

/// One typed composition payload and its exact scoped endpoints.
#[derive(Debug, Clone)]
pub(crate) struct TypedCompositionRelation<R: CompositionRelationSchema> {
    pub(crate) relation: CompositionRelationRef,
    pub(crate) from: ScopedEntityId<R::From>,
    pub(crate) to: ScopedEntityId<R::To>,
    pub(crate) source: Option<ScopedEntityRef>,
    pub(crate) data: R,
}

/// Immutable canonical composition relations owned by exactly one evaluation root.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct CompositionRelationDb {
    #[serde(skip_serializing)]
    workspace: Arc<WorkspaceIdentity>,
    root: EvaluationRoot,
    tables: Vec<CompositionRelationTable>,
    relation_index: Vec<CompositionRelationIndexRow>,
}

impl PartialEq for CompositionRelationDb {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.tables == other.tables
            && self.relation_index == other.relation_index
    }
}

impl Eq for CompositionRelationDb {}

impl CompositionRelationDb {
    #[must_use]
    pub(crate) const fn root(&self) -> &EvaluationRoot {
        &self.root
    }

    pub(crate) fn validate_root(&self, root: &EvaluationRoot) -> Result<(), CompositionBuildError> {
        if root == &self.root {
            Ok(())
        } else {
            Err(CompositionBuildError::RootMismatch {
                expected: Box::new(self.root.clone()),
                found: Box::new(root.clone()),
            })
        }
    }

    pub(super) fn has_workspace_identity(&self, identity: &Arc<WorkspaceIdentity>) -> bool {
        Arc::ptr_eq(&self.workspace, identity)
    }

    pub(crate) fn relations(&self) -> impl ExactSizeIterator<Item = &CompositionRelationIndexRow> {
        self.relation_index.iter()
    }

    pub(crate) fn relation<R: CompositionRelationSchema>(
        &self,
        reference: &CompositionRelationRef,
        registry: &CompositionRelationRegistry,
    ) -> Result<TypedCompositionRelation<R>, CompositionBuildError> {
        let descriptor =
            registry
                .descriptor_for::<R>()
                .map_err(|error| CompositionBuildError::Registry {
                    schema: reference.schema.clone(),
                    reason: error.to_string(),
                })?;
        if reference.schema != *descriptor.id() {
            return Err(CompositionBuildError::SchemaMismatch {
                reference: reference.clone(),
                expected: descriptor.id().clone(),
            });
        }
        let table = self
            .tables
            .binary_search_by(|table| table.schema.cmp(&reference.schema))
            .ok()
            .map(|index| &self.tables[index])
            .ok_or_else(|| CompositionBuildError::MissingTable {
                schema: reference.schema.clone(),
            })?;
        if table.version != descriptor.version() {
            return Err(CompositionBuildError::VersionMismatch {
                schema: table.schema.clone(),
                registered: descriptor.version(),
                encoded: table.version,
            });
        }
        let data = table.rows.get(reference.row as usize).ok_or_else(|| {
            CompositionBuildError::MissingRow {
                reference: reference.clone(),
            }
        })?;
        let metadata = self
            .relation_index
            .binary_search_by(|row| row.relation.cmp(reference))
            .ok()
            .map(|index| &self.relation_index[index])
            .ok_or_else(|| CompositionBuildError::MissingIndex {
                reference: reference.clone(),
            })?;
        if metadata.from.entity().schema != *descriptor.from()
            || metadata.to.entity().schema != *descriptor.to()
        {
            return Err(CompositionBuildError::EndpointSchemaMismatch {
                reference: reference.clone(),
            });
        }
        let data = decode_row::<R>(data).map_err(|error| CompositionBuildError::Codec {
            schema: reference.schema.clone(),
            reason: error.to_string(),
        })?;
        Ok(TypedCompositionRelation {
            relation: reference.clone(),
            from: ScopedEntityId::new(
                metadata.from.scope().clone(),
                EntityId::new(metadata.from.entity().row),
            ),
            to: ScopedEntityId::new(
                metadata.to.scope().clone(),
                EntityId::new(metadata.to.entity().row),
            ),
            source: metadata.source.clone(),
            data,
        })
    }
}

#[derive(Debug)]
struct DraftCompositionRelation {
    schema: SchemaId,
    version: u32,
    from: ScopedEntityRef,
    to: ScopedEntityRef,
    source: Option<ScopedEntityRef>,
    data: Value,
    canonical_data: Vec<u8>,
}

/// Root-bound collector that assigns composition row IDs only at finalization.
pub(crate) struct CompositionRelationBuilder<'a, 'facts> {
    root: EvaluationRoot,
    workspace: &'a WorkspaceFactView<'facts>,
    registry: &'a CompositionRelationRegistry,
    drafts: Vec<DraftCompositionRelation>,
}

impl<'a, 'facts> CompositionRelationBuilder<'a, 'facts> {
    pub(crate) fn new(
        root: &EvaluationRoot,
        workspace: &'a WorkspaceFactView<'facts>,
        registry: &'a CompositionRelationRegistry,
    ) -> Result<Self, CompositionBuildError> {
        workspace.validate_entity(&root.entity).map_err(|error| {
            CompositionBuildError::InvalidReference {
                reason: format!("evaluation root is unavailable: {error}"),
            }
        })?;
        Ok(Self {
            root: root.clone(),
            workspace,
            registry,
            drafts: Vec::new(),
        })
    }

    pub(super) fn has_workspace_identity(&self, identity: &Arc<WorkspaceIdentity>) -> bool {
        self.workspace.has_identity(identity)
    }

    pub(super) const fn root(&self) -> &EvaluationRoot {
        &self.root
    }

    pub(crate) fn transaction<T, E>(
        &mut self,
        mutate: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let draft_count = self.drafts.len();
        match mutate(self) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.drafts.truncate(draft_count);
                Err(error)
            }
        }
    }

    pub(crate) fn relate<R: CompositionRelationSchema>(
        &mut self,
        from: &ScopedEntityId<R::From>,
        to: &ScopedEntityId<R::To>,
        data: &R,
    ) -> Result<(), CompositionBuildError> {
        self.insert(from, to, None, data)
    }

    pub(crate) fn relate_with_source<R: CompositionRelationSchema>(
        &mut self,
        from: &ScopedEntityId<R::From>,
        to: &ScopedEntityId<R::To>,
        source: &ScopedEntityRef,
        data: &R,
    ) -> Result<(), CompositionBuildError> {
        self.insert(from, to, Some(source.clone()), data)
    }

    fn insert<R: CompositionRelationSchema>(
        &mut self,
        from: &ScopedEntityId<R::From>,
        to: &ScopedEntityId<R::To>,
        source: Option<ScopedEntityRef>,
        data: &R,
    ) -> Result<(), CompositionBuildError> {
        let descriptor = self.registry.descriptor_for::<R>().map_err(|error| {
            CompositionBuildError::Registry {
                schema: SchemaId::new(R::ID).expect("registered relation schemas have valid IDs"),
                reason: error.to_string(),
            }
        })?;
        let from = from.erase();
        let to = to.erase();
        for (label, endpoint) in [("from", &from), ("to", &to)] {
            self.workspace.validate_entity(endpoint).map_err(|error| {
                CompositionBuildError::InvalidReference {
                    reason: format!("composition {label} endpoint is unavailable: {error}"),
                }
            })?;
        }
        if let Some(source) = &source {
            self.workspace.validate_entity(source).map_err(|error| {
                CompositionBuildError::InvalidReference {
                    reason: format!("composition source anchor is unavailable: {error}"),
                }
            })?;
        }
        let encoded = encode_row(data).map_err(|error| CompositionBuildError::Codec {
            schema: descriptor.id().clone(),
            reason: error.to_string(),
        })?;
        let data =
            descriptor
                .canonicalize(&encoded)
                .map_err(|error| CompositionBuildError::Codec {
                    schema: descriptor.id().clone(),
                    reason: error.to_string(),
                })?;
        let canonical_data =
            canonical_json_bytes(R::ID, &data).map_err(|error| CompositionBuildError::Codec {
                schema: descriptor.id().clone(),
                reason: error.to_string(),
            })?;
        self.drafts.push(DraftCompositionRelation {
            schema: descriptor.id().clone(),
            version: descriptor.version(),
            from,
            to,
            source,
            data,
            canonical_data,
        });
        Ok(())
    }

    pub(crate) fn finalize(mut self) -> Result<CompositionRelationDb, CompositionBuildError> {
        self.drafts.sort_by(canonical_draft_order);
        for pair in self.drafts.windows(2) {
            if canonical_draft_order(&pair[0], &pair[1]).is_eq() {
                return Err(CompositionBuildError::DuplicateRelation {
                    schema: pair[0].schema.clone(),
                    from: Box::new(pair[0].from.clone()),
                    to: Box::new(pair[0].to.clone()),
                });
            }
        }

        let mut tables = Vec::<CompositionRelationTable>::new();
        let mut relation_index = Vec::with_capacity(self.drafts.len());
        for draft in self.drafts {
            let table = if tables
                .last()
                .is_some_and(|table| table.schema == draft.schema)
            {
                tables.last_mut().expect("the matching final table exists")
            } else {
                tables.push(CompositionRelationTable {
                    schema: draft.schema.clone(),
                    version: draft.version,
                    rows: Vec::new(),
                });
                tables.last_mut().expect("a final table was just inserted")
            };
            let row = u32::try_from(table.rows.len()).map_err(|_| {
                CompositionBuildError::TooManyRows {
                    schema: table.schema.clone(),
                }
            })?;
            table.rows.push(draft.data);
            relation_index.push(CompositionRelationIndexRow {
                relation: CompositionRelationRef {
                    schema: table.schema.clone(),
                    row,
                },
                from: draft.from,
                to: draft.to,
                source: draft.source,
            });
        }
        Ok(CompositionRelationDb {
            workspace: self.workspace.identity(),
            root: self.root,
            tables,
            relation_index,
        })
    }
}

fn canonical_draft_order(
    left: &DraftCompositionRelation,
    right: &DraftCompositionRelation,
) -> std::cmp::Ordering {
    left.schema
        .cmp(&right.schema)
        .then_with(|| left.from.cmp(&right.from))
        .then_with(|| left.to.cmp(&right.to))
        .then_with(|| left.source.cmp(&right.source))
        .then_with(|| left.canonical_data.cmp(&right.canonical_data))
}

/// Structured root-scope, collection, finalization, or typed-view failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CompositionBuildError {
    RootMismatch {
        expected: Box<EvaluationRoot>,
        found: Box<EvaluationRoot>,
    },
    Registry {
        schema: SchemaId,
        reason: String,
    },
    InvalidReference {
        reason: String,
    },
    Codec {
        schema: SchemaId,
        reason: String,
    },
    DuplicateRelation {
        schema: SchemaId,
        from: Box<ScopedEntityRef>,
        to: Box<ScopedEntityRef>,
    },
    TooManyRows {
        schema: SchemaId,
    },
    SchemaMismatch {
        reference: CompositionRelationRef,
        expected: SchemaId,
    },
    MissingTable {
        schema: SchemaId,
    },
    VersionMismatch {
        schema: SchemaId,
        registered: u32,
        encoded: u32,
    },
    MissingRow {
        reference: CompositionRelationRef,
    },
    MissingIndex {
        reference: CompositionRelationRef,
    },
    EndpointSchemaMismatch {
        reference: CompositionRelationRef,
    },
}

impl Display for CompositionBuildError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMismatch { expected, found } => write!(
                formatter,
                "composition relations belong to evaluation root {expected:?}, not {found:?}"
            ),
            Self::Registry { schema, reason } => {
                write!(
                    formatter,
                    "composition schema `{schema}` is unavailable: {reason}"
                )
            }
            Self::InvalidReference { reason } => formatter.write_str(reason),
            Self::Codec { schema, reason } => {
                write!(formatter, "composition row `{schema}` is invalid: {reason}")
            }
            Self::DuplicateRelation { schema, from, to } => write!(
                formatter,
                "duplicate composition relation `{schema}` from {from:?} to {to:?}"
            ),
            Self::TooManyRows { schema } => {
                write!(
                    formatter,
                    "composition schema `{schema}` exceeds u32 row IDs"
                )
            }
            Self::SchemaMismatch {
                reference,
                expected,
            } => write!(
                formatter,
                "composition row `{}`:{} does not match expected schema `{expected}`",
                reference.schema, reference.row
            ),
            Self::MissingTable { schema } => {
                write!(formatter, "composition table `{schema}` does not exist")
            }
            Self::VersionMismatch {
                schema,
                registered,
                encoded,
            } => write!(
                formatter,
                "composition table `{schema}` has version {encoded}, expected {registered}"
            ),
            Self::MissingRow { reference } => write!(
                formatter,
                "composition row `{}`:{} does not exist",
                reference.schema, reference.row
            ),
            Self::MissingIndex { reference } => write!(
                formatter,
                "composition row `{}`:{} has no endpoint metadata",
                reference.schema, reference.row
            ),
            Self::EndpointSchemaMismatch { reference } => write!(
                formatter,
                "composition row `{}`:{} has endpoints incompatible with its typed schema",
                reference.schema, reference.row
            ),
        }
    }
}

impl Error for CompositionBuildError {}

#[cfg(test)]
mod tests;
