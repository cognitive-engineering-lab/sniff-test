//! Symbolic collection and deterministic finalization of typed artifact rows.
//!
//! Collection never exposes numeric row IDs. Entity references carry stable
//! typed keys until every pass has committed, then finalization assigns IDs in
//! canonical order and resolves fact and relation metadata atomically.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

use serde_json::Value;

use super::encoded::{
    ArtifactFactIr, ArtifactFactIrError, EncodedRow, EncodedTable, EntityRef,
    FACT_IR_FORMAT_VERSION, FactIndexRow, RelationIndexRow, RowRef, TableKind,
};
use super::registry::{SchemaDescriptor, SchemaRegistry};
use super::schema::{
    EntityHandle, EntitySchema, FactSchema, PassId, RelationSchema, RequirementSchema, RowHandle,
    RowSchema, SchemaId, canonical_json_bytes, decode_row, encode_entity_key, encode_row,
};

/// Symbolic common metadata attached to one fact row.
#[derive(Debug, Clone)]
pub(crate) struct FactMeta {
    producer: PassId,
    owner: Option<SymbolicEntityRef>,
    anchor: Option<SymbolicEntityRef>,
    provenance_root: Option<SymbolicEntityRef>,
    requirements: BTreeSet<SymbolicRowRef>,
}

impl FactMeta {
    #[must_use]
    pub(super) const fn new(producer: PassId) -> Self {
        Self {
            producer,
            owner: None,
            anchor: None,
            provenance_root: None,
            requirements: BTreeSet::new(),
        }
    }

    #[must_use]
    pub(super) const fn producer(&self) -> &PassId {
        &self.producer
    }

    pub(crate) fn with_owner<E: EntitySchema>(
        mut self,
        owner: &EntityHandle<E>,
    ) -> Result<Self, BuildError> {
        self.owner = Some(SymbolicEntityRef::new(owner)?);
        Ok(self)
    }

    pub(crate) fn with_anchor<E: EntitySchema>(
        mut self,
        anchor: &EntityHandle<E>,
    ) -> Result<Self, BuildError> {
        self.anchor = Some(SymbolicEntityRef::new(anchor)?);
        Ok(self)
    }

    pub(crate) fn with_provenance_root<E: EntitySchema>(
        mut self,
        root: &EntityHandle<E>,
    ) -> Result<Self, BuildError> {
        self.provenance_root = Some(SymbolicEntityRef::new(root)?);
        Ok(self)
    }

    /// Associates one typed requirement row with this fact.
    pub(crate) fn with_requirement<R: RequirementSchema>(
        mut self,
        requirement: &RowHandle<R>,
    ) -> Result<Self, BuildError> {
        self.requirements.insert(SymbolicRowRef::new(requirement)?);
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SymbolicRowRef {
    schema: SchemaId,
    canonical: Vec<u8>,
}

impl SymbolicRowRef {
    fn new<S: RowSchema>(handle: &RowHandle<S>) -> Result<Self, BuildError> {
        Ok(Self {
            schema: typed_schema_id::<S>()?,
            canonical: handle.canonical_bytes().to_vec(),
        })
    }
}

/// Erased symbolic identity of a referenced non-entity row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SymbolicRowReference {
    schema: SchemaId,
    canonical: Vec<u8>,
}

impl SymbolicRowReference {
    #[must_use]
    pub(crate) const fn schema(&self) -> &SchemaId {
        &self.schema
    }

    #[must_use]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    #[must_use]
    pub(crate) fn matches<S: RowSchema>(&self, handle: &RowHandle<S>) -> bool {
        self.schema.as_str() == S::ID && self.canonical == handle.canonical_bytes()
    }
}

impl From<&SymbolicRowRef> for SymbolicRowReference {
    fn from(reference: &SymbolicRowRef) -> Self {
        Self {
            schema: reference.schema.clone(),
            canonical: reference.canonical.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SymbolicEntityRef {
    schema: SchemaId,
    key: Vec<u8>,
}

impl SymbolicEntityRef {
    fn new<E: EntitySchema>(handle: &EntityHandle<E>) -> Result<Self, BuildError> {
        let schema = typed_schema_id::<E>()?;
        let key = encode_entity_key::<E>(handle.key()).map_err(BuildError::codec)?;
        let key = canonical_json_bytes(E::ID, &key).map_err(BuildError::codec)?;
        Ok(Self { schema, key })
    }
}

/// Erased symbolic entity identity exposed to derived artifact passes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SymbolicEntityReference {
    schema: SchemaId,
    canonical_key: Vec<u8>,
}

impl SymbolicEntityReference {
    #[must_use]
    pub(crate) const fn schema(&self) -> &SchemaId {
        &self.schema
    }

    #[must_use]
    pub(crate) fn canonical_key(&self) -> &[u8] {
        &self.canonical_key
    }

    /// Recovers a typed handle only when this reference names `E`.
    pub(crate) fn typed<E: EntitySchema>(&self) -> Result<Option<EntityHandle<E>>, BuildError> {
        if self.schema.as_str() != E::ID {
            return Ok(None);
        }
        let key =
            serde_json::from_slice::<E::Key>(&self.canonical_key).map_err(BuildError::codec)?;
        Ok(Some(EntityHandle::new(key)))
    }
}

impl From<&SymbolicEntityRef> for SymbolicEntityReference {
    fn from(reference: &SymbolicEntityRef) -> Self {
        Self {
            schema: reference.schema.clone(),
            canonical_key: reference.key.clone(),
        }
    }
}

#[derive(Debug, Clone)]
enum PendingMeta {
    Entity {
        key: Value,
        key_bytes: Vec<u8>,
    },
    Fact(FactMeta),
    Relation {
        from: SymbolicEntityRef,
        to: SymbolicEntityRef,
        source: Option<SymbolicEntityRef>,
    },
    Plain,
}

#[derive(Debug, Clone)]
struct PendingRow {
    data: Value,
    data_bytes: Vec<u8>,
    meta: PendingMeta,
}

#[derive(Debug, Clone)]
struct PendingTable {
    version: u32,
    kind: TableKind,
    rows: Vec<PendingRow>,
}

/// Mutable symbolic database shared by artifact-pass deltas.
#[derive(Debug, Clone, Default)]
pub(crate) struct ArtifactDbBuilder {
    tables: BTreeMap<SchemaId, PendingTable>,
}

impl ArtifactDbBuilder {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            tables: BTreeMap::new(),
        }
    }

    /// Borrows all successfully committed symbolic rows for a later pass.
    #[must_use]
    pub(crate) const fn draft_view(&self) -> ArtifactDbDraftView<'_> {
        ArtifactDbDraftView { builder: self }
    }

    pub(crate) fn schema_ids(&self) -> impl Iterator<Item = &SchemaId> {
        self.tables.keys()
    }

    /// Materializes a declared output even when a pass emits no rows.
    ///
    /// Empty tables are part of the committed schema surface: a consumer can
    /// distinguish "this producer ran and found nothing" from a missing
    /// required producer without inventing sentinel rows.
    pub(crate) fn declare_table(
        &mut self,
        descriptor: &SchemaDescriptor,
    ) -> Result<(), BuildError> {
        let schema = descriptor.id().clone();
        let incoming = PendingTable {
            version: descriptor.version(),
            kind: descriptor.kind(),
            rows: Vec::new(),
        };
        if let Some(existing) = self.tables.get(&schema) {
            if existing.version != incoming.version || existing.kind != incoming.kind {
                return Err(BuildError::SchemaConflict {
                    schema,
                    first_version: existing.version,
                    second_version: incoming.version,
                    first_kind: existing.kind,
                    second_kind: incoming.kind,
                });
            }
            return Ok(());
        }
        self.tables.insert(schema, incoming);
        Ok(())
    }

    /// Adds one semantic entity and returns its stable symbolic handle.
    pub(crate) fn insert_entity<E: EntitySchema>(
        &mut self,
        entity: &E,
    ) -> Result<EntityHandle<E>, BuildError> {
        let handle = EntityHandle::from_entity(entity);
        let key = encode_entity_key::<E>(handle.key()).map_err(BuildError::codec)?;
        let key_bytes = canonical_json_bytes(E::ID, &key).map_err(BuildError::codec)?;
        self.insert_typed(
            TableKind::Entity,
            entity,
            PendingMeta::Entity { key, key_bytes },
        )?;
        Ok(handle)
    }

    /// Adds one compiler- or human-derived fact with common provenance.
    pub(crate) fn insert_fact<F: FactSchema>(
        &mut self,
        fact: &F,
        meta: FactMeta,
    ) -> Result<(), BuildError> {
        self.insert_typed(TableKind::Fact, fact, PendingMeta::Fact(meta))
    }

    /// Adds one open typed requirement row.
    pub(crate) fn insert_requirement<R: RequirementSchema>(
        &mut self,
        requirement: &R,
    ) -> Result<RowHandle<R>, BuildError> {
        let handle = RowHandle::from_row(requirement).map_err(BuildError::codec)?;
        self.insert_typed(TableKind::Requirement, requirement, PendingMeta::Plain)?;
        Ok(handle)
    }

    /// Adds one provenance relation without a source anchor.
    pub(crate) fn relate<R: RelationSchema>(
        &mut self,
        from: &EntityHandle<R::From>,
        to: &EntityHandle<R::To>,
        relation: &R,
    ) -> Result<(), BuildError> {
        self.insert_relation(from, to, None, relation)
    }

    /// Adds one provenance relation anchored to another semantic entity.
    pub(crate) fn relate_with_source<R, A>(
        &mut self,
        from: &EntityHandle<R::From>,
        to: &EntityHandle<R::To>,
        source: &EntityHandle<A>,
        relation: &R,
    ) -> Result<(), BuildError>
    where
        R: RelationSchema,
        A: EntitySchema,
    {
        self.insert_relation(from, to, Some(SymbolicEntityRef::new(source)?), relation)
    }

    fn insert_relation<R: RelationSchema>(
        &mut self,
        from: &EntityHandle<R::From>,
        to: &EntityHandle<R::To>,
        source: Option<SymbolicEntityRef>,
        relation: &R,
    ) -> Result<(), BuildError> {
        let meta = PendingMeta::Relation {
            from: SymbolicEntityRef::new(from)?,
            to: SymbolicEntityRef::new(to)?,
            source,
        };
        self.insert_typed(TableKind::Relation, relation, meta)
    }

    fn insert_typed<S: RowSchema>(
        &mut self,
        kind: TableKind,
        row: &S,
        meta: PendingMeta,
    ) -> Result<(), BuildError> {
        let schema = typed_schema_id::<S>()?;
        if S::VERSION == 0 {
            return Err(BuildError::InvalidSchema {
                schema: S::ID.to_owned(),
                reason: String::from("schema version must be nonzero"),
            });
        }
        let data = encode_row(row).map_err(BuildError::codec)?;
        let data_bytes = canonical_json_bytes(S::ID, &data).map_err(BuildError::codec)?;
        let table = self
            .tables
            .entry(schema.clone())
            .or_insert_with(|| PendingTable {
                version: S::VERSION,
                kind,
                rows: Vec::new(),
            });
        if table.version != S::VERSION || table.kind != kind {
            return Err(BuildError::SchemaConflict {
                schema,
                first_version: table.version,
                second_version: S::VERSION,
                first_kind: table.kind,
                second_kind: kind,
            });
        }
        table.rows.push(PendingRow {
            data,
            data_bytes,
            meta,
        });
        Ok(())
    }

    /// Atomically incorporates a successfully completed pass delta.
    pub(crate) fn merge(&mut self, delta: Self) -> Result<(), BuildError> {
        for (schema, incoming) in &delta.tables {
            let Some(existing) = self.tables.get(schema) else {
                continue;
            };
            if existing.version != incoming.version || existing.kind != incoming.kind {
                return Err(BuildError::SchemaConflict {
                    schema: schema.clone(),
                    first_version: existing.version,
                    second_version: incoming.version,
                    first_kind: existing.kind,
                    second_kind: incoming.kind,
                });
            }
        }
        for (schema, mut incoming) in delta.tables {
            let Some(existing) = self.tables.get_mut(&schema) else {
                self.tables.insert(schema, incoming);
                continue;
            };
            existing.rows.append(&mut incoming.rows);
        }
        Ok(())
    }

    /// Assigns final row IDs once, after all passes have committed.
    pub(crate) fn finalize(
        mut self,
        registry: &SchemaRegistry,
    ) -> Result<ArtifactFactIr, BuildError> {
        self.validate_registered_rows(registry)?;
        let entity_ids = self.assign_entity_ids()?;
        let requirement_ids = self.assign_requirement_ids()?;
        self.sort_resolved_rows(&entity_ids, &requirement_ids);
        let artifact = self.into_artifact(&entity_ids, &requirement_ids)?;
        artifact
            .validate_shape()
            .map_err(BuildError::InvalidArtifact)?;
        Ok(artifact)
    }

    /// Validates the complete symbolic database without consuming it.
    ///
    /// Pass scheduling uses this before committing a delta so dangling
    /// symbolic references retain the producing pass in their error context.
    pub(crate) fn validate_pending(&self, registry: &SchemaRegistry) -> Result<(), BuildError> {
        self.clone().finalize(registry).map(drop)
    }

    fn assign_entity_ids(&mut self) -> Result<BTreeMap<SymbolicEntityRef, EntityRef>, BuildError> {
        let mut entity_ids = BTreeMap::<SymbolicEntityRef, EntityRef>::new();
        for (schema, table) in &mut self.tables {
            if table.kind != TableKind::Entity {
                continue;
            }
            table.rows.sort_by(entity_order);
            let mut previous = None;
            for (row, pending) in table.rows.iter().enumerate() {
                let PendingMeta::Entity { key_bytes, .. } = &pending.meta else {
                    return Err(BuildError::InvalidPendingRow {
                        schema: schema.clone(),
                        reason: String::from("entity table contains non-entity metadata"),
                    });
                };
                if previous == Some(key_bytes) {
                    return Err(BuildError::DuplicateEntityKey {
                        schema: schema.clone(),
                        key: String::from_utf8_lossy(key_bytes).into_owned(),
                    });
                }
                previous = Some(key_bytes);
                let row = row_index(row, schema)?;
                entity_ids.insert(
                    SymbolicEntityRef {
                        schema: schema.clone(),
                        key: key_bytes.clone(),
                    },
                    EntityRef {
                        schema: schema.clone(),
                        row,
                    },
                );
            }
        }
        Ok(entity_ids)
    }

    fn assign_requirement_ids(&mut self) -> Result<BTreeMap<SymbolicRowRef, RowRef>, BuildError> {
        let mut requirement_ids = BTreeMap::new();
        for (schema, table) in &mut self.tables {
            if table.kind != TableKind::Requirement {
                continue;
            }
            table
                .rows
                .sort_by(|left, right| left.data_bytes.cmp(&right.data_bytes));
            table
                .rows
                .dedup_by(|left, right| left.data_bytes == right.data_bytes);
            for (row, pending) in table.rows.iter().enumerate() {
                let reference = RowRef {
                    schema: schema.clone(),
                    row: row_index(row, schema)?,
                };
                requirement_ids.insert(
                    SymbolicRowRef {
                        schema: schema.clone(),
                        canonical: pending.data_bytes.clone(),
                    },
                    reference,
                );
            }
        }
        Ok(requirement_ids)
    }

    fn sort_resolved_rows(
        &mut self,
        entity_ids: &BTreeMap<SymbolicEntityRef, EntityRef>,
        requirement_ids: &BTreeMap<SymbolicRowRef, RowRef>,
    ) {
        for table in self.tables.values_mut() {
            match table.kind {
                TableKind::Entity => {}
                TableKind::Fact => table.rows.sort_by(|left, right| {
                    resolved_fact_order(left, right, entity_ids, requirement_ids)
                }),
                TableKind::Relation => table
                    .rows
                    .sort_by(|left, right| resolved_relation_order(left, right, entity_ids)),
                TableKind::Requirement | TableKind::Derived | TableKind::Issue => {
                    table
                        .rows
                        .sort_by(|left, right| left.data_bytes.cmp(&right.data_bytes));
                }
            }
        }
    }

    fn into_artifact(
        self,
        entity_ids: &BTreeMap<SymbolicEntityRef, EntityRef>,
        requirement_ids: &BTreeMap<SymbolicRowRef, RowRef>,
    ) -> Result<ArtifactFactIr, BuildError> {
        let mut tables = Vec::with_capacity(self.tables.len());
        let mut fact_index = Vec::new();
        let mut relation_index = Vec::new();
        for (schema, table) in self.tables {
            let mut rows = Vec::with_capacity(table.rows.len());
            for (row, pending) in table.rows.into_iter().enumerate() {
                let row = row_index(row, &schema)?;
                let reference = RowRef {
                    schema: schema.clone(),
                    row,
                };
                let stable_key = match pending.meta {
                    PendingMeta::Entity { key, .. } => Some(key),
                    PendingMeta::Fact(meta) => {
                        fact_index.push(resolve_fact(
                            reference,
                            meta,
                            entity_ids,
                            requirement_ids,
                        )?);
                        None
                    }
                    PendingMeta::Relation { from, to, source } => {
                        relation_index.push(RelationIndexRow {
                            relation: reference,
                            from: resolve_entity(&from, entity_ids)?,
                            to: resolve_entity(&to, entity_ids)?,
                            source: source
                                .as_ref()
                                .map(|source| resolve_entity(source, entity_ids))
                                .transpose()?,
                        });
                        None
                    }
                    PendingMeta::Plain => None,
                };
                rows.push(EncodedRow {
                    stable_key,
                    data: pending.data,
                });
            }
            tables.push(EncodedTable {
                schema,
                version: table.version,
                kind: table.kind,
                rows,
            });
        }
        fact_index.sort();
        relation_index.sort();
        Ok(ArtifactFactIr {
            format_version: FACT_IR_FORMAT_VERSION,
            tables,
            fact_index,
            relation_index,
        })
    }

    fn validate_registered_rows(&mut self, registry: &SchemaRegistry) -> Result<(), BuildError> {
        for (schema, table) in &mut self.tables {
            let descriptor = registry
                .validate_table(schema, table.version, table.kind)
                .map_err(|error| BuildError::Registry {
                    schema: schema.clone(),
                    reason: error.to_string(),
                })?
                .ok_or_else(|| BuildError::UnregisteredSchema {
                    schema: schema.clone(),
                })?;
            for row in &mut table.rows {
                row.data = descriptor
                    .canonicalize_row(&row.data)
                    .map_err(BuildError::codec)?;
                row.data_bytes =
                    canonical_json_bytes(schema.as_str(), &row.data).map_err(BuildError::codec)?;
                if let PendingMeta::Entity { key, key_bytes } = &mut row.meta {
                    let extracted = descriptor
                        .entity_key(&row.data)
                        .map_err(BuildError::codec)?
                        .ok_or_else(|| BuildError::InvalidPendingRow {
                            schema: schema.clone(),
                            reason: String::from("entity descriptor did not produce a stable key"),
                        })?;
                    *key = extracted;
                    *key_bytes =
                        canonical_json_bytes(schema.as_str(), key).map_err(BuildError::codec)?;
                }
            }
        }
        Ok(())
    }
}

/// Immutable typed view of rows already committed between artifact passes.
#[derive(Clone, Copy)]
pub(crate) struct ArtifactDbDraftView<'a> {
    builder: &'a ArtifactDbBuilder,
}

/// One typed fact plus its still-symbolic provenance between artifact passes.
#[derive(Debug, Clone)]
pub(crate) struct DraftFact<F: FactSchema> {
    pub(crate) data: F,
    pub(crate) producer: PassId,
    pub(crate) owner: Option<SymbolicEntityReference>,
    pub(crate) anchor: Option<SymbolicEntityReference>,
    pub(crate) provenance_root: Option<SymbolicEntityReference>,
    pub(crate) requirements: Vec<SymbolicRowReference>,
}

/// One typed relation plus its symbolic endpoints between artifact passes.
#[derive(Clone)]
pub(crate) struct DraftRelation<R: RelationSchema> {
    pub(crate) data: R,
    pub(crate) from: EntityHandle<R::From>,
    pub(crate) to: EntityHandle<R::To>,
    pub(crate) source: Option<SymbolicEntityReference>,
}

impl ArtifactDbDraftView<'_> {
    #[must_use]
    pub(crate) fn contains_schema<S: RowSchema>(self) -> bool {
        SchemaId::new(S::ID)
            .ok()
            .is_some_and(|schema| self.builder.tables.contains_key(&schema))
    }

    pub(crate) fn table<S: RowSchema>(self) -> Result<Vec<S>, BuildError> {
        let schema = typed_schema_id::<S>()?;
        let Some(table) = self.builder.tables.get(&schema) else {
            return Ok(Vec::new());
        };
        table
            .rows
            .iter()
            .map(|row| decode_row::<S>(&row.data).map_err(BuildError::codec))
            .collect()
    }

    /// Returns typed facts together with all symbolic provenance available to
    /// a derived collection pass before final row assignment.
    pub(crate) fn facts<F: FactSchema>(self) -> Result<Vec<DraftFact<F>>, BuildError> {
        let schema = typed_schema_id::<F>()?;
        let Some(table) = self.builder.tables.get(&schema) else {
            return Ok(Vec::new());
        };
        if table.kind != TableKind::Fact || table.version != F::VERSION {
            return Err(BuildError::InvalidPendingRow {
                schema,
                reason: String::from("typed fact view found an incompatible table descriptor"),
            });
        }
        table
            .rows
            .iter()
            .map(|row| {
                let PendingMeta::Fact(meta) = &row.meta else {
                    return Err(BuildError::InvalidPendingRow {
                        schema: schema.clone(),
                        reason: String::from("fact table contains non-fact metadata"),
                    });
                };
                Ok(DraftFact {
                    data: decode_row::<F>(&row.data).map_err(BuildError::codec)?,
                    producer: meta.producer.clone(),
                    owner: meta.owner.as_ref().map(Into::into),
                    anchor: meta.anchor.as_ref().map(Into::into),
                    provenance_root: meta.provenance_root.as_ref().map(Into::into),
                    requirements: meta.requirements.iter().map(Into::into).collect(),
                })
            })
            .collect()
    }

    /// Returns typed relation payloads with typed symbolic endpoints.
    pub(crate) fn relations<R: RelationSchema>(self) -> Result<Vec<DraftRelation<R>>, BuildError> {
        let schema = typed_schema_id::<R>()?;
        let Some(table) = self.builder.tables.get(&schema) else {
            return Ok(Vec::new());
        };
        if table.kind != TableKind::Relation || table.version != R::VERSION {
            return Err(BuildError::InvalidPendingRow {
                schema,
                reason: String::from("typed relation view found an incompatible table descriptor"),
            });
        }
        table
            .rows
            .iter()
            .map(|row| {
                let PendingMeta::Relation { from, to, source } = &row.meta else {
                    return Err(BuildError::InvalidPendingRow {
                        schema: schema.clone(),
                        reason: String::from("relation table contains non-relation metadata"),
                    });
                };
                let from = SymbolicEntityReference::from(from)
                    .typed::<R::From>()?
                    .ok_or_else(|| BuildError::InvalidPendingRow {
                        schema: schema.clone(),
                        reason: String::from("relation has the wrong from-endpoint schema"),
                    })?;
                let to = SymbolicEntityReference::from(to)
                    .typed::<R::To>()?
                    .ok_or_else(|| BuildError::InvalidPendingRow {
                        schema: schema.clone(),
                        reason: String::from("relation has the wrong to-endpoint schema"),
                    })?;
                Ok(DraftRelation {
                    data: decode_row::<R>(&row.data).map_err(BuildError::codec)?,
                    from,
                    to,
                    source: source.as_ref().map(Into::into),
                })
            })
            .collect()
    }
}

fn resolve_fact(
    fact: RowRef,
    meta: FactMeta,
    entities: &BTreeMap<SymbolicEntityRef, EntityRef>,
    requirements: &BTreeMap<SymbolicRowRef, RowRef>,
) -> Result<FactIndexRow, BuildError> {
    Ok(FactIndexRow {
        fact,
        owner: meta
            .owner
            .as_ref()
            .map(|entity| resolve_entity(entity, entities))
            .transpose()?,
        anchor: meta
            .anchor
            .as_ref()
            .map(|entity| resolve_entity(entity, entities))
            .transpose()?,
        provenance_root: meta
            .provenance_root
            .as_ref()
            .map(|entity| resolve_entity(entity, entities))
            .transpose()?,
        requirements: meta
            .requirements
            .iter()
            .map(|requirement| resolve_requirement(requirement, requirements))
            .collect::<Result<Vec<_>, _>>()?,
        producer: meta.producer,
    })
}

fn resolve_requirement(
    reference: &SymbolicRowRef,
    requirements: &BTreeMap<SymbolicRowRef, RowRef>,
) -> Result<RowRef, BuildError> {
    requirements
        .get(reference)
        .cloned()
        .ok_or_else(|| BuildError::MissingRow {
            schema: reference.schema.clone(),
            canonical: String::from_utf8_lossy(&reference.canonical).into_owned(),
        })
}

fn resolve_entity(
    reference: &SymbolicEntityRef,
    entities: &BTreeMap<SymbolicEntityRef, EntityRef>,
) -> Result<EntityRef, BuildError> {
    entities
        .get(reference)
        .cloned()
        .ok_or_else(|| BuildError::MissingEntity {
            schema: reference.schema.clone(),
            key: String::from_utf8_lossy(&reference.key).into_owned(),
        })
}

fn entity_order(left: &PendingRow, right: &PendingRow) -> Ordering {
    match (&left.meta, &right.meta) {
        (
            PendingMeta::Entity {
                key_bytes: left, ..
            },
            PendingMeta::Entity {
                key_bytes: right, ..
            },
        ) => left.cmp(right),
        _ => Ordering::Equal,
    }
}

fn resolved_fact_order(
    left: &PendingRow,
    right: &PendingRow,
    entities: &BTreeMap<SymbolicEntityRef, EntityRef>,
    requirements: &BTreeMap<SymbolicRowRef, RowRef>,
) -> Ordering {
    match (&left.meta, &right.meta) {
        (PendingMeta::Fact(left_meta), PendingMeta::Fact(right_meta)) => {
            resolved_optional(left_meta.owner.as_ref(), entities)
                .cmp(&resolved_optional(right_meta.owner.as_ref(), entities))
                .then_with(|| {
                    resolved_optional(left_meta.anchor.as_ref(), entities)
                        .cmp(&resolved_optional(right_meta.anchor.as_ref(), entities))
                })
                .then_with(|| {
                    resolved_optional(left_meta.provenance_root.as_ref(), entities).cmp(
                        &resolved_optional(right_meta.provenance_root.as_ref(), entities),
                    )
                })
                .then_with(|| {
                    resolved_requirements(&left_meta.requirements, requirements).cmp(
                        &resolved_requirements(&right_meta.requirements, requirements),
                    )
                })
                .then_with(|| left_meta.producer.cmp(&right_meta.producer))
                .then_with(|| left.data_bytes.cmp(&right.data_bytes))
        }
        _ => Ordering::Equal,
    }
}

fn resolved_requirements(
    references: &BTreeSet<SymbolicRowRef>,
    requirements: &BTreeMap<SymbolicRowRef, RowRef>,
) -> Vec<RowRef> {
    references
        .iter()
        .filter_map(|reference| requirements.get(reference).cloned())
        .collect()
}

fn resolved_relation_order(
    left: &PendingRow,
    right: &PendingRow,
    entities: &BTreeMap<SymbolicEntityRef, EntityRef>,
) -> Ordering {
    match (&left.meta, &right.meta) {
        (
            PendingMeta::Relation {
                from: left_from,
                to: left_to,
                source: left_source,
            },
            PendingMeta::Relation {
                from: right_from,
                to: right_to,
                source: right_source,
            },
        ) => resolve_entity(left_from, entities)
            .ok()
            .cmp(&resolve_entity(right_from, entities).ok())
            .then_with(|| {
                resolve_entity(left_to, entities)
                    .ok()
                    .cmp(&resolve_entity(right_to, entities).ok())
            })
            .then_with(|| {
                resolved_optional(left_source.as_ref(), entities)
                    .cmp(&resolved_optional(right_source.as_ref(), entities))
            })
            .then_with(|| left.data_bytes.cmp(&right.data_bytes)),
        _ => Ordering::Equal,
    }
}

fn resolved_optional(
    reference: Option<&SymbolicEntityRef>,
    entities: &BTreeMap<SymbolicEntityRef, EntityRef>,
) -> Option<EntityRef> {
    reference.and_then(|reference| entities.get(reference).cloned())
}

fn row_index(row: usize, schema: &SchemaId) -> Result<u32, BuildError> {
    u32::try_from(row).map_err(|_| BuildError::TooManyRows {
        schema: schema.clone(),
    })
}

fn typed_schema_id<S: RowSchema>() -> Result<SchemaId, BuildError> {
    SchemaId::new(S::ID).map_err(|error| BuildError::InvalidSchema {
        schema: S::ID.to_owned(),
        reason: error.to_string(),
    })
}

/// Structured symbolic-collection or finalization failure.
#[derive(Debug)]
pub(crate) enum BuildError {
    InvalidSchema {
        schema: String,
        reason: String,
    },
    SchemaConflict {
        schema: SchemaId,
        first_version: u32,
        second_version: u32,
        first_kind: TableKind,
        second_kind: TableKind,
    },
    UnregisteredSchema {
        schema: SchemaId,
    },
    Registry {
        schema: SchemaId,
        reason: String,
    },
    Codec {
        schema: String,
        reason: String,
    },
    DuplicateEntityKey {
        schema: SchemaId,
        key: String,
    },
    MissingEntity {
        schema: SchemaId,
        key: String,
    },
    MissingRow {
        schema: SchemaId,
        canonical: String,
    },
    InvalidPendingRow {
        schema: SchemaId,
        reason: String,
    },
    TooManyRows {
        schema: SchemaId,
    },
    InvalidArtifact(ArtifactFactIrError),
}

impl BuildError {
    fn codec(error: impl Display) -> Self {
        Self::Codec {
            schema: String::from("typed row"),
            reason: error.to_string(),
        }
    }
}

impl Display for BuildError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSchema { schema, reason } => {
                write!(formatter, "invalid schema `{schema}`: {reason}")
            }
            Self::SchemaConflict {
                schema,
                first_version,
                second_version,
                first_kind,
                second_kind,
            } => write!(
                formatter,
                "schema `{schema}` was written with incompatible descriptors \
                 ({first_kind:?} v{first_version} and {second_kind:?} v{second_version})"
            ),
            Self::UnregisteredSchema { schema } => {
                write!(formatter, "producer wrote undeclared schema `{schema}`")
            }
            Self::Registry { schema, reason } => {
                write!(
                    formatter,
                    "schema `{schema}` is incompatible with the registry: {reason}"
                )
            }
            Self::Codec { schema, reason } => {
                write!(formatter, "could not encode or decode {schema}: {reason}")
            }
            Self::DuplicateEntityKey { schema, key } => {
                write!(
                    formatter,
                    "entity table `{schema}` contains duplicate stable key {key}"
                )
            }
            Self::MissingEntity { schema, key } => {
                write!(
                    formatter,
                    "reference to missing entity `{schema}` with stable key {key}"
                )
            }
            Self::MissingRow { schema, canonical } => write!(
                formatter,
                "reference to missing row `{schema}` with canonical identity {canonical}"
            ),
            Self::InvalidPendingRow { schema, reason } => {
                write!(formatter, "pending row for `{schema}` is invalid: {reason}")
            }
            Self::TooManyRows { schema } => {
                write!(formatter, "table `{schema}` has more than u32::MAX rows")
            }
            Self::InvalidArtifact(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for BuildError {}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::analysis::facts::registry::SchemaRegistry;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

    #[derive(Clone, Serialize, Deserialize)]
    struct Observed {
        detail: String,
    }

    impl RowSchema for Observed {
        const ID: &'static str = "sample.observed";
        const VERSION: u32 = 1;
    }

    impl FactSchema for Observed {}

    #[derive(Clone, Serialize, Deserialize)]
    struct Needed {
        condition: String,
    }

    impl RowSchema for Needed {
        const ID: &'static str = "sample.needed";
        const VERSION: u32 = 1;
    }

    impl RequirementSchema for Needed {}

    #[derive(Clone, Serialize, Deserialize)]
    struct Reaches;

    impl RowSchema for Reaches {
        const ID: &'static str = "sample.reaches";
        const VERSION: u32 = 1;
    }

    impl RelationSchema for Reaches {
        type From = Node;
        type To = Node;
    }

    fn registry() -> SchemaRegistry {
        let mut registry = SchemaRegistry::new();
        registry.register_entity::<Node>().unwrap();
        registry.register_fact::<Observed>().unwrap();
        registry.register_relation::<Reaches>().unwrap();
        registry.register_requirement::<Needed>().unwrap();
        registry
    }

    fn build(reverse: bool) -> ArtifactFactIr {
        let mut builder = ArtifactDbBuilder::new();
        let nodes = if reverse { ["z", "a"] } else { ["a", "z"] };
        for name in nodes {
            builder
                .insert_entity(&Node {
                    name: name.to_owned(),
                })
                .unwrap();
        }
        let requirements = if reverse { ["z", "a"] } else { ["a", "z"] };
        let mut handles = BTreeMap::new();
        for condition in requirements {
            let handle = builder
                .insert_requirement(&Needed {
                    condition: condition.to_owned(),
                })
                .unwrap();
            handles.insert(condition, handle);
        }
        let a = EntityHandle::<Node>::new(String::from("a"));
        let z = EntityHandle::<Node>::new(String::from("z"));
        let relations = if reverse {
            [(&z, &a), (&a, &z)]
        } else {
            [(&a, &z), (&z, &a)]
        };
        for (from, to) in relations {
            builder.relate(from, to, &Reaches).unwrap();
        }
        let facts = if reverse {
            [("z", &z), ("a", &a)]
        } else {
            [("a", &a), ("z", &z)]
        };
        for (detail, owner) in facts {
            builder
                .insert_fact(
                    &Observed {
                        detail: detail.to_owned(),
                    },
                    FactMeta::new(PassId::new("sample.collect").unwrap())
                        .with_owner(owner)
                        .unwrap()
                        .with_requirement(&handles[detail])
                        .unwrap(),
                )
                .unwrap();
        }
        builder.finalize(&registry()).unwrap()
    }

    #[test]
    fn final_bytes_do_not_depend_on_insertion_order() {
        let forward = serde_json::to_vec(&build(false)).unwrap();
        let reverse = serde_json::to_vec(&build(true)).unwrap();

        assert_eq!(forward, reverse);
    }

    #[test]
    fn finalization_rejects_duplicate_stable_entity_keys() {
        let mut builder = ArtifactDbBuilder::new();
        for _ in 0..2 {
            builder
                .insert_entity(&Node {
                    name: String::from("same"),
                })
                .unwrap();
        }

        let error = builder.finalize(&registry()).unwrap_err();

        assert!(matches!(error, BuildError::DuplicateEntityKey { .. }));
    }

    #[test]
    fn finalization_rejects_dangling_symbolic_relation_endpoints() {
        let mut builder = ArtifactDbBuilder::new();
        let present = builder
            .insert_entity(&Node {
                name: String::from("present"),
            })
            .unwrap();
        let absent = EntityHandle::<Node>::new(String::from("absent"));
        builder.relate(&present, &absent, &Reaches).unwrap();

        let error = builder.finalize(&registry()).unwrap_err();

        assert!(matches!(error, BuildError::MissingEntity { .. }));
    }

    #[test]
    fn fact_metadata_resolves_typed_requirement_handles() {
        let artifact = build(false);
        let requirement_schema = SchemaId::new(Needed::ID).unwrap();

        assert_eq!(artifact.fact_index.len(), 2);
        assert!(artifact.fact_index.iter().all(|fact| {
            fact.requirements.len() == 1 && fact.requirements[0].schema == requirement_schema
        }));
    }

    #[test]
    fn derived_pass_views_keep_symbolic_fact_and_relation_provenance() {
        let mut builder = ArtifactDbBuilder::new();
        let from = builder
            .insert_entity(&Node {
                name: String::from("from"),
            })
            .unwrap();
        let to = builder
            .insert_entity(&Node {
                name: String::from("to"),
            })
            .unwrap();
        let requirement = builder
            .insert_requirement(&Needed {
                condition: String::from("condition"),
            })
            .unwrap();
        builder
            .insert_fact(
                &Observed {
                    detail: String::from("observed"),
                },
                FactMeta::new(PassId::new("sample.collect").unwrap())
                    .with_owner(&to)
                    .unwrap()
                    .with_requirement(&requirement)
                    .unwrap(),
            )
            .unwrap();
        builder.relate(&from, &to, &Reaches).unwrap();

        let facts = builder.draft_view().facts::<Observed>().unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].data.detail, "observed");
        assert_eq!(facts[0].producer.as_str(), "sample.collect");
        assert_eq!(
            facts[0].owner.as_ref().unwrap().typed::<Node>().unwrap(),
            Some(to.clone())
        );
        assert!(facts[0].requirements[0].matches(&requirement));

        let relations = builder.draft_view().relations::<Reaches>().unwrap();
        assert_eq!(relations.len(), 1);
        assert_eq!(relations[0].from, from);
        assert_eq!(relations[0].to, to);
    }
}
