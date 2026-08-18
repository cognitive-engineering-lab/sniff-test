//! Registered typed views over the erased artifact fact container.
//!
//! JSON values are decoded only after a schema has been registered and its
//! persisted version and infrastructure kind have been checked. Unregistered
//! tables stay available through [`ArtifactDbView::opaque_tables`] without
//! requiring the core to understand their rows.

use std::fmt::{self, Display, Formatter};

use serde_json::Value;

use super::encoded::{
    ArtifactFactIr, EncodedTable, EntityRef, FactIndexRow, RelationIndexRow, RowRef, TableKind,
};
use super::registry::SchemaRegistry;
use super::schema::{
    EntityId, EntitySchema, FactSchema, RelationSchema, RowId, RowSchema, SchemaCodecError,
    SchemaId, encode_entity_key,
};

/// A typed, decoded table borrowed conceptually from one artifact view.
///
/// Rows are owned so callers never receive references into `serde_json::Value`.
/// Type erasure remains confined to the persistence boundary.
#[derive(Debug, Clone)]
pub(crate) struct TypedTable<S> {
    schema: SchemaId,
    rows: Vec<S>,
}

/// One decoded row paired with its finalized, artifact-local reference.
#[derive(Debug, Clone)]
pub(crate) struct IndexedRow<S> {
    pub(crate) reference: RowRef,
    pub(crate) data: S,
}

impl<S: RowSchema> IndexedRow<S> {
    /// Returns the row's schema-branded finalized ID.
    #[must_use]
    pub(crate) const fn id(&self) -> RowId<S> {
        RowId::new(self.reference.row)
    }
}

/// One decoded fact paired with its generic persisted provenance metadata.
#[derive(Debug, Clone)]
pub(crate) struct TypedFact<F>
where
    F: FactSchema,
{
    pub(crate) fact: IndexedRow<F>,
    pub(crate) metadata: FactIndexRow,
}

impl<S> TypedTable<S> {
    /// Stable identity of this table's schema.
    #[must_use]
    pub(crate) const fn schema(&self) -> &SchemaId {
        &self.schema
    }

    /// Number of decoded rows.
    #[must_use]
    pub(crate) const fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table contains no rows.
    #[must_use]
    pub(crate) const fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Returns a row by its finalized artifact-local index.
    #[must_use]
    pub(crate) fn get(&self, row: u32) -> Option<&S> {
        self.rows.get(usize::try_from(row).ok()?)
    }

    /// Iterates rows in their finalized canonical order.
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &S> {
        self.rows.iter()
    }
}

/// One typed relation payload together with its generic provenance endpoints.
#[derive(Debug, Clone)]
pub(crate) struct TypedRelation<R>
where
    R: RelationSchema,
{
    pub(crate) relation: RowRef,
    pub(crate) from: EntityId<R::From>,
    pub(crate) to: EntityId<R::To>,
    pub(crate) source: Option<EntityRef>,
    pub(crate) data: R,
}

/// One erased persisted relation resolved from a validated artifact view.
///
/// This is the infrastructure-boundary representation used by generic trace
/// rendering. Pack code normally uses [`TypedRelation`] instead.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PersistedRelation<'a> {
    table: &'a EncodedTable,
    row: &'a Value,
    metadata: &'a RelationIndexRow,
}

impl<'a> PersistedRelation<'a> {
    #[must_use]
    pub(crate) fn reference(&self) -> &'a RowRef {
        &self.metadata.relation
    }

    #[must_use]
    pub(crate) const fn version(&self) -> u32 {
        self.table.version
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &'a Value {
        self.row
    }

    #[must_use]
    pub(crate) const fn metadata(&self) -> &'a RelationIndexRow {
        self.metadata
    }
}

/// Read-only typed access to one finalized artifact fact database.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ArtifactDbView<'a> {
    artifact: &'a ArtifactFactIr,
    registry: &'a SchemaRegistry,
}

impl<'a> ArtifactDbView<'a> {
    /// Opens an artifact only after validating its generic and registered shape.
    ///
    /// This is the sole construction boundary. Once it succeeds, typed access,
    /// relation adjacency, and persisted rendering may rely on canonical table
    /// and index order, valid registered rows, stable entity identities, and
    /// schema-correct endpoints for every known relation.
    pub(crate) fn open(
        artifact: &'a ArtifactFactIr,
        registry: &'a SchemaRegistry,
    ) -> Result<Self, ViewError> {
        artifact
            .validate_shape()
            .map_err(|error| ViewError::InvalidArtifact {
                reason: error.to_string(),
            })?;
        let view = Self { artifact, registry };
        view.validate_registered_tables()?;
        Ok(view)
    }

    /// Returns the underlying open container, including opaque tables.
    #[must_use]
    pub(crate) const fn artifact(&self) -> &'a ArtifactFactIr {
        self.artifact
    }

    /// Returns the compile-time schema composition used to validate this view.
    #[must_use]
    pub(crate) const fn registry(&self) -> &'a SchemaRegistry {
        self.registry
    }

    /// Returns tables whose schemas are not installed in this composition.
    ///
    /// Registered tables with an incompatible version or kind are not opaque;
    /// typed access reports those as structured errors.
    pub(crate) fn opaque_tables(&self) -> impl Iterator<Item = &'a EncodedTable> + 'a {
        let registry = self.registry;
        self.artifact
            .tables
            .iter()
            .filter(move |table| registry.descriptor(&table.schema).is_none())
    }

    /// Decodes one registered table after checking schema version and kind.
    pub(crate) fn table<S>(&self) -> Result<TypedTable<S>, ViewError>
    where
        S: RowSchema,
    {
        let descriptor = self
            .registry
            .descriptor_for::<S>()
            .map_err(|error| ViewError::registry_static::<S>(error))?;
        let Some(table) = self.encoded_table(descriptor.id()) else {
            return Ok(TypedTable {
                schema: descriptor.id().clone(),
                rows: Vec::new(),
            });
        };

        let rows = table
            .rows
            .iter()
            .enumerate()
            .map(|(row, encoded)| {
                let row = row_index(row, &table.schema)?;
                serde_json::from_value(encoded.data.clone()).map_err(|error| {
                    ViewError::InvalidRow {
                        schema: table.schema.clone(),
                        row,
                        reason: error.to_string(),
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(TypedTable {
            schema: table.schema.clone(),
            rows,
        })
    }

    /// Decodes one row after checking that its erased reference names `S`.
    pub(crate) fn indexed_row<S>(&self, reference: &RowRef) -> Result<IndexedRow<S>, ViewError>
    where
        S: RowSchema,
    {
        let descriptor = self
            .registry
            .descriptor_for::<S>()
            .map_err(|error| ViewError::registry_static::<S>(error))?;
        if reference.schema != *descriptor.id() {
            return Err(ViewError::RowSchemaMismatch {
                reference: reference.clone(),
                expected: descriptor.id().clone(),
            });
        }
        let data = self.row::<S>(reference.row)?;
        Ok(IndexedRow {
            reference: reference.clone(),
            data,
        })
    }

    /// Decodes one registered row directly from its persisted slot.
    ///
    /// Unlike [`Self::table`], this does not allocate or deserialize unrelated
    /// rows. The authoritative [`Self::open`] boundary has already validated
    /// the complete registered table and its canonical encoding.
    fn row<S>(&self, row: u32) -> Result<S, ViewError>
    where
        S: RowSchema,
    {
        let descriptor = self
            .registry
            .descriptor_for::<S>()
            .map_err(|error| ViewError::registry_static::<S>(error))?;
        let table = self.encoded_table(descriptor.id());
        let row_count = table.map_or(0, |table| table.rows.len());
        let encoded = table
            .and_then(|table| {
                usize::try_from(row)
                    .ok()
                    .and_then(|row| table.rows.get(row))
            })
            .ok_or_else(|| ViewError::RowOutOfBounds {
                schema: descriptor.id().clone(),
                row,
                row_count,
            })?;
        serde_json::from_value(encoded.data.clone()).map_err(|error| ViewError::InvalidRow {
            schema: descriptor.id().clone(),
            row,
            reason: error.to_string(),
        })
    }

    /// Decodes all rows with their canonical finalized references.
    pub(crate) fn indexed_rows<S>(&self) -> Result<Vec<IndexedRow<S>>, ViewError>
    where
        S: RowSchema,
    {
        let table = self.table::<S>()?;
        let schema = table.schema.clone();
        table
            .rows
            .into_iter()
            .enumerate()
            .map(|(row, data)| {
                Ok(IndexedRow {
                    reference: RowRef {
                        schema: schema.clone(),
                        row: row_index(row, &schema)?,
                    },
                    data,
                })
            })
            .collect()
    }

    /// Decodes one fact and joins its generic metadata by canonical row ref.
    pub(crate) fn fact<F>(&self, row: u32) -> Result<TypedFact<F>, ViewError>
    where
        F: FactSchema,
    {
        let reference = RowRef {
            schema: self
                .registry
                .descriptor_for::<F>()
                .map_err(|error| ViewError::registry_static::<F>(error))?
                .id()
                .clone(),
            row,
        };
        self.fact_at::<F>(&reference)
    }

    /// Decodes one fact by erased reference and joins its generic metadata.
    pub(crate) fn fact_at<F>(&self, reference: &RowRef) -> Result<TypedFact<F>, ViewError>
    where
        F: FactSchema,
    {
        let fact = self.indexed_row::<F>(reference)?;
        let metadata = self.fact_index(reference)?.clone();
        Ok(TypedFact { fact, metadata })
    }

    /// Decodes every fact and joins each row with its generic metadata.
    pub(crate) fn facts<F>(&self) -> Result<Vec<TypedFact<F>>, ViewError>
    where
        F: FactSchema,
    {
        self.indexed_rows::<F>()?
            .into_iter()
            .map(|fact| {
                let metadata = self.fact_index(&fact.reference)?.clone();
                Ok(TypedFact { fact, metadata })
            })
            .collect()
    }

    /// Resolves and decodes an entity by its typed finalized ID.
    pub(crate) fn entity<E>(&self, id: EntityId<E>) -> Result<E, ViewError>
    where
        E: EntitySchema,
    {
        self.row::<E>(id.row())
    }

    /// Finds an entity's finalized ID by its stable typed key.
    pub(crate) fn entity_id_by_key<E>(&self, key: &E::Key) -> Result<Option<EntityId<E>>, ViewError>
    where
        E: EntitySchema,
    {
        let descriptor = self
            .registry
            .descriptor_for::<E>()
            .map_err(|error| ViewError::registry_static::<E>(error))?;
        let Some(table) = self.encoded_table(descriptor.id()) else {
            return Ok(None);
        };
        let encoded_key = encode_entity_key::<E>(key).map_err(|error| ViewError::InvalidKey {
            schema: descriptor.id().clone(),
            reason: error.to_string(),
        })?;
        let target =
            serde_json::to_vec(&encoded_key).expect("serializing a JSON value cannot fail");
        match table.rows.binary_search_by(|row| {
            let key = row
                .stable_key
                .as_ref()
                .expect("validated entity rows always carry stable keys");
            serde_json::to_vec(key)
                .expect("serializing a JSON value cannot fail")
                .cmp(&target)
        }) {
            Ok(row) => Ok(Some(EntityId::new(row_index(row, &table.schema)?))),
            Err(_) => Ok(None),
        }
    }

    /// Finds and decodes an entity by its stable typed key.
    pub(crate) fn entity_by_key<E>(
        &self,
        key: &E::Key,
    ) -> Result<Option<(EntityId<E>, E)>, ViewError>
    where
        E: EntitySchema,
    {
        let Some(id) = self.entity_id_by_key::<E>(key)? else {
            return Ok(None);
        };
        Ok(Some((id, self.entity(id)?)))
    }

    /// Decodes one registered relation row and checks its typed endpoints.
    pub(crate) fn relation<R>(&self, row: u32) -> Result<TypedRelation<R>, ViewError>
    where
        R: RelationSchema,
    {
        let table = self.table::<R>()?;
        let data = table
            .get(row)
            .cloned()
            .ok_or_else(|| ViewError::RowOutOfBounds {
                schema: table.schema().clone(),
                row,
                row_count: table.len(),
            })?;
        let relation = RowRef {
            schema: table.schema().clone(),
            row,
        };
        let from_entities = self.table::<R::From>()?;
        let to_entities = self.table::<R::To>()?;
        self.typed_relation(relation, data, &from_entities, &to_entities)
    }

    /// Decodes every row in one registered relation table.
    pub(crate) fn relations<R>(&self) -> Result<Vec<TypedRelation<R>>, ViewError>
    where
        R: RelationSchema,
    {
        let table = self.table::<R>()?;
        let from_entities = self.table::<R::From>()?;
        let to_entities = self.table::<R::To>()?;
        let schema = table.schema;
        table
            .rows
            .into_iter()
            .enumerate()
            .map(|(row, data)| {
                let row = row_index(row, &schema)?;
                self.typed_relation(
                    RowRef {
                        schema: schema.clone(),
                        row,
                    },
                    data,
                    &from_entities,
                    &to_entities,
                )
            })
            .collect()
    }

    fn typed_relation<R>(
        &self,
        relation: RowRef,
        data: R,
        from_entities: &TypedTable<R::From>,
        to_entities: &TypedTable<R::To>,
    ) -> Result<TypedRelation<R>, ViewError>
    where
        R: RelationSchema,
    {
        let index = self.relation_index(&relation)?;

        if index.from.schema != *from_entities.schema() {
            return Err(ViewError::EndpointSchemaMismatch {
                relation,
                endpoint: "from",
                expected: from_entities.schema().clone(),
                found: index.from.schema.clone(),
            });
        }
        if index.to.schema != *to_entities.schema() {
            return Err(ViewError::EndpointSchemaMismatch {
                relation,
                endpoint: "to",
                expected: to_entities.schema().clone(),
                found: index.to.schema.clone(),
            });
        }

        let from = EntityId::<R::From>::new(index.from.row);
        let to = EntityId::<R::To>::new(index.to.row);
        // Endpoint rows are decoded here so a typed relation can never expose a
        // dangling or version-incompatible typed entity reference.
        if from_entities.get(from.row()).is_none() {
            return Err(ViewError::RowOutOfBounds {
                schema: from_entities.schema().clone(),
                row: from.row(),
                row_count: from_entities.len(),
            });
        }
        if to_entities.get(to.row()).is_none() {
            return Err(ViewError::RowOutOfBounds {
                schema: to_entities.schema().clone(),
                row: to.row(),
                row_count: to_entities.len(),
            });
        }

        Ok(TypedRelation {
            relation: index.relation.clone(),
            from,
            to,
            source: index.source.clone(),
            data,
        })
    }

    /// Resolves one relation row without requiring its schema to be registered.
    ///
    /// Unknown relation schemas therefore remain renderable and traversable.
    pub(crate) fn persisted_relation(
        &self,
        relation: &RowRef,
    ) -> Result<PersistedRelation<'a>, ViewError> {
        let table =
            self.encoded_table(&relation.schema)
                .ok_or_else(|| ViewError::MissingTable {
                    schema: relation.schema.clone(),
                })?;
        if table.kind != TableKind::Relation {
            return Err(ViewError::TableKindMismatch {
                schema: table.schema.clone(),
                expected: TableKind::Relation,
                found: table.kind,
            });
        }
        let encoded = table
            .rows
            .get(usize::try_from(relation.row).unwrap_or(usize::MAX))
            .ok_or_else(|| ViewError::RowOutOfBounds {
                schema: relation.schema.clone(),
                row: relation.row,
                row_count: table.rows.len(),
            })?;
        Ok(PersistedRelation {
            table,
            row: &encoded.data,
            metadata: self.relation_index(relation)?,
        })
    }

    fn validate_registered_tables(&self) -> Result<(), ViewError> {
        for table in &self.artifact.tables {
            let Some(descriptor) = self
                .registry
                .validate_table(&table.schema, table.version, table.kind)
                .map_err(|error| ViewError::registry_id(&table.schema, error))?
            else {
                continue;
            };

            for (row, encoded) in table.rows.iter().enumerate() {
                let row = row_index(row, &table.schema)?;
                let canonical = descriptor
                    .canonicalize_row(&encoded.data)
                    .map_err(|error| match error {
                        SchemaCodecError::NonCanonicalRow { .. } => ViewError::NonCanonicalRow {
                            schema: table.schema.clone(),
                            row,
                        },
                        error @ SchemaCodecError::Serde { .. } => ViewError::InvalidRow {
                            schema: table.schema.clone(),
                            row,
                            reason: error.to_string(),
                        },
                    })?;
                if canonical != encoded.data {
                    return Err(ViewError::NonCanonicalRow {
                        schema: table.schema.clone(),
                        row,
                    });
                }

                if table.kind == TableKind::Entity {
                    let expected = descriptor
                        .entity_key(&encoded.data)
                        .map_err(|error| ViewError::InvalidRow {
                            schema: table.schema.clone(),
                            row,
                            reason: error.to_string(),
                        })?
                        .expect("registered entity descriptors expose stable keys");
                    if encoded.stable_key.as_ref() != Some(&expected) {
                        return Err(ViewError::EntityKeyMismatch {
                            schema: table.schema.clone(),
                            row,
                        });
                    }
                }

                if let Some(endpoints) = descriptor.relation_endpoints() {
                    let relation = RowRef {
                        schema: table.schema.clone(),
                        row,
                    };
                    let metadata = self.relation_index(&relation)?;
                    Self::validate_endpoint_schema(
                        &relation,
                        "from",
                        &endpoints.from,
                        &metadata.from.schema,
                    )?;
                    Self::validate_endpoint_schema(
                        &relation,
                        "to",
                        &endpoints.to,
                        &metadata.to.schema,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn validate_endpoint_schema(
        relation: &RowRef,
        endpoint: &'static str,
        expected: &SchemaId,
        found: &SchemaId,
    ) -> Result<(), ViewError> {
        if expected == found {
            Ok(())
        } else {
            Err(ViewError::EndpointSchemaMismatch {
                relation: relation.clone(),
                endpoint,
                expected: expected.clone(),
                found: found.clone(),
            })
        }
    }

    fn encoded_table(&self, schema: &SchemaId) -> Option<&'a EncodedTable> {
        self.artifact
            .tables
            .binary_search_by(|table| table.schema.cmp(schema))
            .ok()
            .map(|index| &self.artifact.tables[index])
    }

    fn relation_index(&self, relation: &RowRef) -> Result<&'a RelationIndexRow, ViewError> {
        self.artifact
            .relation_index
            .binary_search_by(|index| index.relation.cmp(relation))
            .ok()
            .map(|index| &self.artifact.relation_index[index])
            .ok_or_else(|| ViewError::MissingRelationIndex {
                relation: relation.clone(),
            })
    }

    fn fact_index(&self, fact: &RowRef) -> Result<&'a FactIndexRow, ViewError> {
        self.artifact
            .fact_index
            .binary_search_by(|index| index.fact.cmp(fact))
            .ok()
            .map(|index| &self.artifact.fact_index[index])
            .ok_or_else(|| ViewError::MissingFactIndex { fact: fact.clone() })
    }
}

fn row_index(row: usize, schema: &SchemaId) -> Result<u32, ViewError> {
    u32::try_from(row).map_err(|_| ViewError::TooManyRows {
        schema: schema.clone(),
        row_count: row.saturating_add(1),
    })
}

/// Structured failure while opening a typed view of erased rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ViewError {
    InvalidArtifact {
        reason: String,
    },
    Registry {
        schema: SchemaId,
        reason: String,
    },
    MissingTable {
        schema: SchemaId,
    },
    InvalidRow {
        schema: SchemaId,
        row: u32,
        reason: String,
    },
    InvalidKey {
        schema: SchemaId,
        reason: String,
    },
    NonCanonicalRow {
        schema: SchemaId,
        row: u32,
    },
    EntityKeyMismatch {
        schema: SchemaId,
        row: u32,
    },
    RowSchemaMismatch {
        reference: RowRef,
        expected: SchemaId,
    },
    TableKindMismatch {
        schema: SchemaId,
        expected: TableKind,
        found: TableKind,
    },
    RowOutOfBounds {
        schema: SchemaId,
        row: u32,
        row_count: usize,
    },
    TooManyRows {
        schema: SchemaId,
        row_count: usize,
    },
    MissingRelationIndex {
        relation: RowRef,
    },
    MissingFactIndex {
        fact: RowRef,
    },
    EndpointSchemaMismatch {
        relation: RowRef,
        endpoint: &'static str,
        expected: SchemaId,
        found: SchemaId,
    },
}

impl ViewError {
    fn registry_static<S: RowSchema>(error: impl Display) -> Self {
        let schema = SchemaId::new(S::ID)
            .unwrap_or_else(|_| SchemaId::new("invalid.schema").expect("valid fallback ID"));
        Self::registry_id(&schema, error)
    }

    fn registry_id(schema: &SchemaId, error: impl Display) -> Self {
        Self::Registry {
            schema: schema.clone(),
            reason: error.to_string(),
        }
    }
}

impl Display for ViewError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifact { reason } => {
                write!(formatter, "artifact fact database is invalid: {reason}")
            }
            Self::Registry { schema, reason } => {
                write!(
                    formatter,
                    "schema `{}` is not available to this typed view: {reason}",
                    schema.as_str()
                )
            }
            Self::MissingTable { schema } => {
                write!(formatter, "artifact has no table for schema `{schema}`")
            }
            Self::InvalidRow {
                schema,
                row,
                reason,
            } => write!(
                formatter,
                "row {row} in schema `{}` could not be decoded: {reason}",
                schema.as_str()
            ),
            Self::InvalidKey { schema, reason } => write!(
                formatter,
                "entity key for schema `{}` could not be encoded: {reason}",
                schema.as_str()
            ),
            Self::NonCanonicalRow { schema, row } => write!(
                formatter,
                "row {row} in schema `{}` is not in its registered canonical encoding",
                schema.as_str()
            ),
            Self::EntityKeyMismatch { schema, row } => write!(
                formatter,
                "entity row {row} in schema `{}` has a persisted stable key that does not match its registered semantic key",
                schema.as_str()
            ),
            Self::RowSchemaMismatch {
                reference,
                expected,
            } => write!(
                formatter,
                "row reference `{}`:{} names the wrong schema; expected `{}`",
                reference.schema.as_str(),
                reference.row,
                expected.as_str()
            ),
            Self::TableKindMismatch {
                schema,
                expected,
                found,
            } => write!(
                formatter,
                "table `{}` has infrastructure kind {found:?}, expected {expected:?}",
                schema.as_str()
            ),
            Self::RowOutOfBounds {
                schema,
                row,
                row_count,
            } => write!(
                formatter,
                "row {row} is outside schema `{}` with {row_count} rows",
                schema.as_str()
            ),
            Self::TooManyRows { schema, row_count } => write!(
                formatter,
                "schema `{}` has {row_count} rows, exceeding the u32 row-ID space",
                schema.as_str()
            ),
            Self::MissingRelationIndex { relation } => write!(
                formatter,
                "relation row `{}`:{} has no relation index entry",
                relation.schema.as_str(),
                relation.row
            ),
            Self::MissingFactIndex { fact } => write!(
                formatter,
                "fact row `{}`:{} has no fact index entry",
                fact.schema.as_str(),
                fact.row
            ),
            Self::EndpointSchemaMismatch {
                relation,
                endpoint,
                expected,
                found,
            } => write!(
                formatter,
                "relation row `{}`:{} has {endpoint} endpoint schema `{}`, expected `{}`",
                relation.schema.as_str(),
                relation.row,
                found.as_str(),
                expected.as_str()
            ),
        }
    }
}

impl std::error::Error for ViewError {}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use super::*;
    use crate::analysis::facts::encoded::{
        EncodedRow, FACT_IR_FORMAT_VERSION, FactIndexRow, TableKind,
    };
    use crate::analysis::facts::schema::PassId;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct LivesIn {
        since: u16,
    }

    impl RowSchema for LivesIn {
        const ID: &'static str = "sample.lives-in";
        const VERSION: u32 = 1;
    }

    impl RelationSchema for LivesIn {
        type From = Person;
        type To = Place;
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Observation {
        note: String,
    }

    impl RowSchema for Observation {
        const ID: &'static str = "sample.observation";
        const VERSION: u32 = 1;
    }

    impl FactSchema for Observation {}

    thread_local! {
        static DECODED_PROBE_ROWS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct DecodeProbe {
        note: String,
    }

    impl<'de> Deserialize<'de> for DecodeProbe {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            #[derive(Deserialize)]
            struct Fields {
                note: String,
            }

            let fields = Fields::deserialize(deserializer)?;
            DECODED_PROBE_ROWS.with(|rows| rows.borrow_mut().push(fields.note.clone()));
            Ok(Self { note: fields.note })
        }
    }

    impl RowSchema for DecodeProbe {
        const ID: &'static str = "sample.decode-probe";
        const VERSION: u32 = 1;
    }

    impl FactSchema for DecodeProbe {}

    fn schema(id: &str) -> SchemaId {
        SchemaId::new(id).expect("valid test schema ID")
    }

    fn encoded_table(schema_id: &str, kind: TableKind, rows: Vec<EncodedRow>) -> EncodedTable {
        EncodedTable {
            schema: schema(schema_id),
            version: 1,
            kind,
            rows,
        }
    }

    fn entity_row(key: &str, data: serde_json::Value) -> EncodedRow {
        EncodedRow {
            stable_key: Some(json!(key)),
            data,
        }
    }

    fn registry() -> SchemaRegistry {
        let mut registry = SchemaRegistry::new();
        registry.register_entity::<Person>().unwrap();
        registry.register_entity::<Place>().unwrap();
        registry.register_relation::<LivesIn>().unwrap();
        registry.register_fact::<Observation>().unwrap();
        registry
    }

    fn artifact_with_decode_probes() -> ArtifactFactIr {
        let mut artifact = artifact();
        let probe_schema = schema(DecodeProbe::ID);
        let table_position = artifact
            .tables
            .binary_search_by(|table| table.schema.cmp(&probe_schema))
            .unwrap_err();
        artifact.tables.insert(
            table_position,
            encoded_table(
                DecodeProbe::ID,
                TableKind::Fact,
                vec![
                    EncodedRow {
                        stable_key: None,
                        data: json!({ "note": "selected" }),
                    },
                    EncodedRow {
                        stable_key: None,
                        data: json!({ "note": "unrelated" }),
                    },
                ],
            ),
        );
        artifact.fact_index = ["selected", "unrelated"]
            .into_iter()
            .enumerate()
            .map(|(row, _)| FactIndexRow {
                fact: RowRef {
                    schema: probe_schema.clone(),
                    row: u32::try_from(row).unwrap(),
                },
                owner: None,
                anchor: None,
                provenance_root: None,
                requirements: Vec::new(),
                producer: PassId::new("sample.decode-probe").unwrap(),
            })
            .collect();
        artifact
    }

    fn artifact() -> ArtifactFactIr {
        ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables: vec![
                encoded_table("future.allocator-fact", TableKind::Fact, Vec::new()),
                encoded_table(
                    LivesIn::ID,
                    TableKind::Relation,
                    vec![EncodedRow {
                        stable_key: None,
                        data: json!({ "since": 1843 }),
                    }],
                ),
                encoded_table(
                    Person::ID,
                    TableKind::Entity,
                    vec![
                        entity_row("Ada", json!({ "name": "Ada" })),
                        entity_row("Grace", json!({ "name": "Grace" })),
                    ],
                ),
                encoded_table(
                    Place::ID,
                    TableKind::Entity,
                    vec![entity_row("London", json!({ "name": "London" }))],
                ),
            ],
            fact_index: Vec::new(),
            relation_index: vec![RelationIndexRow {
                relation: RowRef {
                    schema: schema(LivesIn::ID),
                    row: 0,
                },
                from: EntityRef {
                    schema: schema(Person::ID),
                    row: 0,
                },
                to: EntityRef {
                    schema: schema(Place::ID),
                    row: 0,
                },
                source: None,
            }],
        }
    }

    #[test]
    fn decodes_registered_tables_entities_and_relations() {
        let artifact = artifact();
        let registry = registry();
        let view = ArtifactDbView::open(&artifact, &registry).unwrap();

        let people = view.table::<Person>().unwrap();
        assert_eq!(people.len(), 2);
        assert_eq!(people.get(1).unwrap().name, "Grace");
        assert_eq!(view.entity(EntityId::<Person>::new(0)).unwrap().name, "Ada");

        let (ada_id, ada) = view
            .entity_by_key::<Person>(&"Ada".to_owned())
            .unwrap()
            .unwrap();
        assert_eq!(ada_id.row(), 0);
        assert_eq!(ada.name, "Ada");
        assert!(
            view.entity_id_by_key::<Person>(&"missing".to_owned())
                .unwrap()
                .is_none()
        );

        let relation = view.relation::<LivesIn>(0).unwrap();
        assert_eq!(relation.from.row(), 0);
        assert_eq!(relation.to.row(), 0);
        assert_eq!(relation.data, LivesIn { since: 1843 });
        assert_eq!(view.relations::<LivesIn>().unwrap().len(), 1);
    }

    #[test]
    fn leaves_unknown_tables_opaque() {
        let artifact = artifact();
        let registry = registry();
        let view = ArtifactDbView::open(&artifact, &registry).unwrap();

        let opaque = view.opaque_tables().collect::<Vec<_>>();
        assert_eq!(opaque.len(), 1);
        assert_eq!(opaque[0].schema.as_str(), "future.allocator-fact");
    }

    #[test]
    fn rejects_registered_table_version_mismatches() {
        let mut artifact = artifact();
        artifact
            .tables
            .iter_mut()
            .find(|table| table.schema.as_str() == Person::ID)
            .unwrap()
            .version = 2;
        assert!(matches!(
            ArtifactDbView::open(&artifact, &registry()),
            Err(ViewError::Registry { .. })
        ));
    }

    #[test]
    fn rejects_dangling_typed_relation_endpoints() {
        let mut artifact = artifact();
        artifact.relation_index[0].to.row = 1;
        assert!(matches!(
            ArtifactDbView::open(&artifact, &registry()),
            Err(ViewError::InvalidArtifact { .. })
        ));
    }

    #[test]
    fn missing_registered_tables_are_empty() {
        let artifact = artifact();
        let registry = registry();
        let view = ArtifactDbView::open(&artifact, &registry).unwrap();

        assert!(view.table::<Observation>().unwrap().is_empty());
        assert!(view.indexed_rows::<Observation>().unwrap().is_empty());
        assert!(view.facts::<Observation>().unwrap().is_empty());
    }

    #[test]
    fn open_rejects_malformed_and_noncanonical_registered_rows() {
        let mut malformed = artifact();
        malformed
            .tables
            .iter_mut()
            .find(|table| table.schema.as_str() == Person::ID)
            .unwrap()
            .rows[0]
            .data = json!({ "wrong": "Ada" });
        assert!(matches!(
            ArtifactDbView::open(&malformed, &registry()),
            Err(ViewError::InvalidRow { .. })
        ));

        let mut noncanonical = artifact();
        noncanonical
            .tables
            .iter_mut()
            .find(|table| table.schema.as_str() == Person::ID)
            .unwrap()
            .rows[0]
            .data = json!({ "name": "Ada", "ignored": true });
        assert!(matches!(
            ArtifactDbView::open(&noncanonical, &registry()),
            Err(ViewError::NonCanonicalRow { .. })
        ));
    }

    #[test]
    fn open_rejects_entity_keys_that_disagree_with_registered_semantics() {
        let mut artifact = artifact();
        artifact
            .tables
            .iter_mut()
            .find(|table| table.schema.as_str() == Person::ID)
            .unwrap()
            .rows[0]
            .stable_key = Some(json!("Babbage"));

        assert!(matches!(
            ArtifactDbView::open(&artifact, &registry()),
            Err(ViewError::EntityKeyMismatch { .. })
        ));
    }

    #[test]
    fn open_rejects_known_relation_endpoint_schema_mismatches() {
        let mut artifact = artifact();
        artifact.relation_index[0].to = EntityRef {
            schema: schema(Person::ID),
            row: 1,
        };

        assert!(matches!(
            ArtifactDbView::open(&artifact, &registry()),
            Err(ViewError::EndpointSchemaMismatch { endpoint: "to", .. })
        ));
    }

    #[test]
    fn typed_facts_join_persisted_metadata_by_row_reference() {
        let mut artifact = artifact();
        let table_position = artifact
            .tables
            .binary_search_by(|table| table.schema.as_str().cmp(Observation::ID))
            .unwrap_err();
        artifact.tables.insert(
            table_position,
            encoded_table(
                Observation::ID,
                TableKind::Fact,
                vec![EncodedRow {
                    stable_key: None,
                    data: json!({ "note": "compiler observation" }),
                }],
            ),
        );
        artifact.fact_index.push(FactIndexRow {
            fact: RowRef {
                schema: schema(Observation::ID),
                row: 0,
            },
            owner: Some(EntityRef {
                schema: schema(Person::ID),
                row: 0,
            }),
            anchor: None,
            provenance_root: None,
            requirements: Vec::new(),
            producer: PassId::new("sample.observe").unwrap(),
        });

        let registry = registry();
        let view = ArtifactDbView::open(&artifact, &registry).unwrap();
        let fact = view.fact::<Observation>(0).unwrap();

        assert_eq!(fact.fact.reference.row, 0);
        assert_eq!(fact.fact.data.note, "compiler observation");
        assert_eq!(fact.metadata.owner.unwrap().row, 0);
        assert_eq!(view.facts::<Observation>().unwrap().len(), 1);
    }

    #[test]
    fn exact_row_reads_do_not_decode_unrelated_rows() {
        let artifact = artifact_with_decode_probes();
        let mut registry = registry();
        registry.register_fact::<DecodeProbe>().unwrap();
        let view = ArtifactDbView::open(&artifact, &registry).unwrap();
        DECODED_PROBE_ROWS.with(|rows| rows.borrow_mut().clear());

        let selected = RowRef {
            schema: schema(DecodeProbe::ID),
            row: 0,
        };
        assert_eq!(
            view.indexed_row::<DecodeProbe>(&selected)
                .unwrap()
                .data
                .note,
            "selected"
        );
        DECODED_PROBE_ROWS.with(|rows| assert_eq!(&*rows.borrow(), &["selected"]));

        DECODED_PROBE_ROWS.with(|rows| rows.borrow_mut().clear());
        let unrelated = RowRef {
            schema: schema(DecodeProbe::ID),
            row: 1,
        };
        assert_eq!(
            view.fact_at::<DecodeProbe>(&unrelated)
                .unwrap()
                .fact
                .data
                .note,
            "unrelated"
        );
        DECODED_PROBE_ROWS.with(|rows| assert_eq!(&*rows.borrow(), &["unrelated"]));
    }
}
