//! Artifact-scoped composition of validated fact database views.
//!
//! Workspace composition retains each artifact generation as an exact scope;
//! it never flattens artifact-local row IDs into one global table. Entity
//! equivalence is an explicit typed operation over registered semantic keys.
//!
//! This module deliberately creates no implicit cross-scope provenance edge.
//! [`super::composition`] adds explicit, typed, evaluation-root-bound edges for
//! instance selection, consumer overlays, and callable joins.
//!
//! [`ArtifactScopeId`] is an infrastructure brand, not proof of cache-envelope
//! identity. The production composition root must derive it from the verified
//! exact artifact identity; this domain-agnostic layer never guesses a scope
//! from fact contents or an arbitrary package label.

use std::any::type_name;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::encoded::{EntityRef, RowRef, TableKind};
use super::relations::RelationGraph;
use super::schema::{EntityId, EntitySchema, FactSchema, RowSchema, SchemaId};
use super::view::{ArtifactDbView, TypedFact, ViewError};

/// Stable exact identity of one artifact generation in a workspace analysis.
///
/// Two generations of the same package must receive different scope IDs. The
/// scope is part of every workspace reference and is never inferred from a row
/// schema or artifact contents.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct ArtifactScopeId(SchemaId);

impl ArtifactScopeId {
    /// Canonically identifies one verified persisted compiler artifact.
    ///
    /// The strict version hash must use rustc's 32-digit lowercase hexadecimal
    /// spelling. Verifying that the ID belongs to a particular cache envelope
    /// remains the composition root's responsibility.
    pub(crate) fn for_persisted(
        stable_crate_id: u64,
        strict_version_hash: impl Into<String>,
    ) -> Result<Self, ArtifactScopeIdError> {
        let strict_version_hash = strict_version_hash.into();
        if strict_version_hash.len() != 32
            || !strict_version_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ArtifactScopeIdError::InvalidStrictVersionHash {
                found: strict_version_hash,
            });
        }
        let encoded = format!("persisted.{stable_crate_id:016x}.{strict_version_hash}");
        Ok(Self(SchemaId::new(encoded).expect(
            "canonical persisted artifact scope components form a stable ID",
        )))
    }

    /// Canonically identifies one explicitly numbered in-memory generation.
    ///
    /// Callers assign ordinals from a stable semantic order. Pointer addresses
    /// and collection insertion order are not valid generation identities.
    #[must_use]
    pub(crate) fn for_in_memory(stable_crate_id: u64, ordinal: u32) -> Self {
        let encoded = format!("in-memory.{stable_crate_id:016x}.{ordinal:08x}");
        Self(
            SchemaId::new(encoded)
                .expect("canonical in-memory artifact scope components form a stable ID"),
        )
    }

    /// Test-only constructor for fixtures that predate canonical compiler IDs.
    #[cfg(test)]
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, super::schema::StableIdError> {
        SchemaId::new(value).map(Self)
    }

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Failure to construct an authoritative exact-generation scope identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArtifactScopeIdError {
    InvalidStrictVersionHash { found: String },
}

impl Display for ArtifactScopeIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStrictVersionHash { found } => write!(
                formatter,
                "strict version hash {found:?} is not 32-digit lowercase hexadecimal"
            ),
        }
    }
}

impl Error for ArtifactScopeIdError {}

impl AsRef<str> for ArtifactScopeId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Display for ArtifactScopeId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Artifact-scoped erased entity reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ScopedEntityRef {
    scope: ArtifactScopeId,
    entity: EntityRef,
}

impl ScopedEntityRef {
    /// Associates an artifact-local entity row with an exact generation.
    ///
    /// Construction does not prove membership; [`WorkspaceFactView::entity`]
    /// performs that check against the selected validated artifact view.
    #[must_use]
    pub(crate) const fn new(scope: ArtifactScopeId, entity: EntityRef) -> Self {
        Self { scope, entity }
    }

    #[must_use]
    pub(crate) const fn scope(&self) -> &ArtifactScopeId {
        &self.scope
    }

    #[must_use]
    pub(crate) const fn entity(&self) -> &EntityRef {
        &self.entity
    }

    #[must_use]
    pub(crate) fn as_row(&self) -> ScopedRowRef {
        ScopedRowRef::new(self.scope.clone(), self.entity.clone().into())
    }
}

/// Typed entity ID paired with its exact artifact generation.
pub(crate) struct ScopedEntityId<E: EntitySchema> {
    scope: ArtifactScopeId,
    entity: EntityId<E>,
}

impl<E: EntitySchema> Clone for ScopedEntityId<E> {
    fn clone(&self) -> Self {
        Self {
            scope: self.scope.clone(),
            entity: self.entity,
        }
    }
}

impl<E: EntitySchema> PartialEq for ScopedEntityId<E> {
    fn eq(&self, other: &Self) -> bool {
        self.scope == other.scope && self.entity == other.entity
    }
}

impl<E: EntitySchema> Eq for ScopedEntityId<E> {}

impl<E: EntitySchema> PartialOrd for ScopedEntityId<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<E: EntitySchema> Ord for ScopedEntityId<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.scope
            .cmp(&other.scope)
            .then_with(|| self.entity.cmp(&other.entity))
    }
}

impl<E: EntitySchema> Hash for ScopedEntityId<E> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.scope.hash(state);
        self.entity.hash(state);
    }
}

impl<E: EntitySchema> fmt::Debug for ScopedEntityId<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct(type_name::<Self>())
            .field("scope", &self.scope)
            .field("entity", &self.entity)
            .finish()
    }
}

impl<E: EntitySchema> ScopedEntityId<E> {
    pub(super) fn new(scope: ArtifactScopeId, entity: EntityId<E>) -> Self {
        Self { scope, entity }
    }

    #[must_use]
    pub(crate) const fn scope(&self) -> &ArtifactScopeId {
        &self.scope
    }

    #[must_use]
    pub(crate) const fn entity(&self) -> EntityId<E> {
        self.entity
    }

    #[must_use]
    pub(crate) fn erase(&self) -> ScopedEntityRef {
        ScopedEntityRef::new(self.scope.clone(), self.entity.erase())
    }
}

/// Artifact-scoped erased row reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ScopedRowRef {
    scope: ArtifactScopeId,
    row: RowRef,
}

impl ScopedRowRef {
    /// Associates an artifact-local row with an exact generation.
    ///
    /// Construction does not prove membership; typed workspace lookup does.
    #[must_use]
    pub(crate) const fn new(scope: ArtifactScopeId, row: RowRef) -> Self {
        Self { scope, row }
    }

    #[must_use]
    pub(crate) const fn scope(&self) -> &ArtifactScopeId {
        &self.scope
    }

    #[must_use]
    pub(crate) const fn row(&self) -> &RowRef {
        &self.row
    }
}

/// Artifact-scoped provenance-relation reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ScopedRelationRef {
    scope: ArtifactScopeId,
    relation: RowRef,
}

impl ScopedRelationRef {
    /// Associates an artifact-local relation row with an exact generation.
    ///
    /// Construction does not prove membership; [`WorkspaceFactView::relation`]
    /// performs that check against the selected validated artifact view.
    #[must_use]
    pub(crate) const fn new(scope: ArtifactScopeId, relation: RowRef) -> Self {
        Self { scope, relation }
    }

    #[must_use]
    pub(crate) const fn scope(&self) -> &ArtifactScopeId {
        &self.scope
    }

    #[must_use]
    pub(crate) const fn relation(&self) -> &RowRef {
        &self.relation
    }

    #[must_use]
    pub(crate) fn as_row(&self) -> ScopedRowRef {
        ScopedRowRef::new(self.scope.clone(), self.relation.clone())
    }
}

/// One typed row resolved without dropping its exact artifact scope.
#[derive(Debug, Clone)]
pub(crate) struct ScopedIndexedRow<S> {
    pub(crate) reference: ScopedRowRef,
    pub(crate) data: S,
}

/// Generic relation metadata with the artifact scope retained everywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopedRelationRecord {
    pub(crate) relation: ScopedRelationRef,
    pub(crate) from: ScopedEntityRef,
    pub(crate) to: ScopedEntityRef,
    pub(crate) source: Option<ScopedEntityRef>,
}

impl ScopedRelationRecord {
    #[must_use]
    pub(crate) const fn relation(&self) -> &ScopedRelationRef {
        &self.relation
    }

    #[must_use]
    pub(crate) const fn from(&self) -> &ScopedEntityRef {
        &self.from
    }

    #[must_use]
    pub(crate) const fn to(&self) -> &ScopedEntityRef {
        &self.to
    }

    #[must_use]
    pub(crate) const fn source(&self) -> Option<&ScopedEntityRef> {
        self.source.as_ref()
    }
}

/// Non-flattening collection of validated artifact-generation views.
#[derive(Debug)]
pub(crate) struct WorkspaceFactView<'a> {
    identity: Arc<WorkspaceIdentity>,
    artifacts: BTreeMap<ArtifactScopeId, ArtifactDbView<'a>>,
}

/// Process-local brand proving that prepared indexes came from one exact view.
///
/// The brand is never serialized or used for deterministic ordering. It only
/// prevents an index prepared from one collection of artifact generations
/// from being attached to another `WorkspaceFactView`, even when both views
/// happen to reuse the same scope strings.
#[derive(Debug)]
pub(super) struct WorkspaceIdentity;

impl<'a> WorkspaceFactView<'a> {
    /// Composes exact artifact scopes in canonical scope-ID order.
    pub(crate) fn compose(
        artifacts: impl IntoIterator<Item = (ArtifactScopeId, ArtifactDbView<'a>)>,
    ) -> Result<Self, WorkspaceViewError> {
        let mut composed = BTreeMap::new();
        for (scope, view) in artifacts {
            if composed.insert(scope.clone(), view).is_some() {
                return Err(WorkspaceViewError::DuplicateScope { scope });
            }
        }
        Ok(Self {
            identity: Arc::new(WorkspaceIdentity),
            artifacts: composed,
        })
    }

    /// Returns the opaque process-local identity shared by prepared indexes.
    #[must_use]
    pub(super) fn identity(&self) -> Arc<WorkspaceIdentity> {
        Arc::clone(&self.identity)
    }

    /// Checks whether an infrastructure index belongs to this exact view.
    #[must_use]
    pub(super) fn has_identity(&self, identity: &Arc<WorkspaceIdentity>) -> bool {
        Arc::ptr_eq(&self.identity, identity)
    }

    /// Exact artifact scopes in deterministic ID order.
    pub(crate) fn scopes(
        &self,
    ) -> impl ExactSizeIterator<Item = &ArtifactScopeId> + DoubleEndedIterator {
        self.artifacts.keys()
    }

    /// Resolves one typed row strictly inside the scope carried by its ref.
    pub(crate) fn row<S: RowSchema>(
        &self,
        reference: &ScopedRowRef,
    ) -> Result<ScopedIndexedRow<S>, WorkspaceViewError> {
        let view = self.artifact(reference.scope())?;
        let row =
            view.indexed_row::<S>(reference.row())
                .map_err(|source| WorkspaceViewError::View {
                    scope: reference.scope().clone(),
                    source,
                })?;
        Ok(ScopedIndexedRow {
            reference: reference.clone(),
            data: row.data,
        })
    }

    /// Resolves one typed fact and its persisted metadata in its exact scope.
    pub(crate) fn fact<F: FactSchema>(
        &self,
        reference: &ScopedRowRef,
    ) -> Result<TypedFact<F>, WorkspaceViewError> {
        let view = self.artifact(reference.scope())?;
        view.fact_at::<F>(reference.row())
            .map_err(|source| WorkspaceViewError::View {
                scope: reference.scope().clone(),
                source,
            })
    }

    /// Resolves one typed entity strictly inside its exact artifact scope.
    pub(crate) fn entity<E: EntitySchema>(
        &self,
        reference: &ScopedEntityRef,
    ) -> Result<E, WorkspaceViewError> {
        let view = self.artifact(reference.scope())?;
        let expected = Self::ensure_entity_schema::<E>(reference.scope(), view)?;
        if reference.entity().schema != expected {
            return Err(WorkspaceViewError::EntitySchemaMismatch {
                reference: reference.clone(),
                expected,
            });
        }
        self.row::<E>(&reference.as_row()).map(|row| row.data)
    }

    /// Looks up one semantic entity key in exactly one artifact scope.
    pub(crate) fn entity_by_key<E: EntitySchema>(
        &self,
        scope: &ArtifactScopeId,
        key: &E::Key,
    ) -> Result<Option<ScopedEntityRef>, WorkspaceViewError> {
        self.entity_id_by_key::<E>(scope, key)
            .map(|found| found.map(|entity| entity.erase()))
    }

    /// Looks up a typed entity ID in exactly one artifact scope.
    pub(crate) fn entity_id_by_key<E: EntitySchema>(
        &self,
        scope: &ArtifactScopeId,
        key: &E::Key,
    ) -> Result<Option<ScopedEntityId<E>>, WorkspaceViewError> {
        let view = self.artifact(scope)?;
        Self::ensure_entity_schema::<E>(scope, view)?;
        view.entity_id_by_key::<E>(key)
            .map(|found| found.map(|entity| ScopedEntityId::new(scope.clone(), entity)))
            .map_err(|source| WorkspaceViewError::View {
                scope: scope.clone(),
                source,
            })
    }

    /// Compares canonical typed entity keys while retaining exact references.
    ///
    /// This is the only cross-scope entity join in Phase 2. It refuses erased,
    /// unregistered, or non-entity schemas instead of guessing equivalence.
    pub(crate) fn entities_equivalent<E: EntitySchema>(
        &self,
        left: &ScopedEntityRef,
        right: &ScopedEntityRef,
    ) -> Result<bool, WorkspaceViewError> {
        let left = self.entity::<E>(left)?;
        let right = self.entity::<E>(right)?;
        Ok(left.key() == right.key())
    }

    /// Finds every exact scoped entity with the same canonical typed key.
    ///
    /// Results follow [`ArtifactScopeId`] order and therefore do not depend on
    /// artifact registration order.
    pub(crate) fn equivalent_entities<E: EntitySchema>(
        &self,
        reference: &ScopedEntityRef,
    ) -> Result<Vec<ScopedEntityRef>, WorkspaceViewError> {
        let key = self.entity::<E>(reference)?.key();
        let mut equivalent = Vec::new();
        for scope in self.scopes() {
            if let Some(entity) = self.entity_by_key::<E>(scope, &key)? {
                equivalent.push(entity);
            }
        }
        Ok(equivalent)
    }

    /// Resolves generic provenance metadata inside the relation's exact scope.
    pub(crate) fn relation(
        &self,
        reference: &ScopedRelationRef,
    ) -> Result<ScopedRelationRecord, WorkspaceViewError> {
        let view = self.artifact(reference.scope())?;
        let persisted = view
            .persisted_relation(reference.relation())
            .map_err(|source| WorkspaceViewError::View {
                scope: reference.scope().clone(),
                source,
            })?;
        let metadata = persisted.metadata();
        let scope = reference.scope().clone();
        Ok(ScopedRelationRecord {
            relation: reference.clone(),
            from: ScopedEntityRef::new(scope.clone(), metadata.from.clone()),
            to: ScopedEntityRef::new(scope.clone(), metadata.to.clone()),
            source: metadata
                .source
                .clone()
                .map(|source| ScopedEntityRef::new(scope, source)),
        })
    }

    /// Selects a deterministic shortest path inside one exact artifact scope.
    ///
    /// Equivalent entities in another scope are not implicit trace edges.
    pub(crate) fn shortest_path(
        &self,
        from: &ScopedEntityRef,
        to: &ScopedEntityRef,
    ) -> Result<Option<Vec<ScopedRelationRef>>, WorkspaceViewError> {
        Self::ensure_same_path_scope(from, to)?;
        let view = self.validate_erased_entity(from)?;
        self.validate_erased_entity(to)?;
        Ok(RelationGraph::new(view)
            .shortest_path(from.entity(), to.entity())
            .map(|path| {
                path.into_iter()
                    .map(|relation| ScopedRelationRef::new(from.scope().clone(), relation))
                    .collect()
            }))
    }

    /// Validates an explicitly selected same-scope provenance path.
    ///
    /// The returned metadata preserves scope on endpoints and source anchors,
    /// making it suitable for exact traversal witnesses without flattening
    /// artifact-local identities.
    pub(crate) fn validate_path(
        &self,
        from: &ScopedEntityRef,
        to: &ScopedEntityRef,
        path: &[ScopedRelationRef],
    ) -> Result<Vec<ScopedRelationRecord>, WorkspaceViewError> {
        Self::ensure_same_path_scope(from, to)?;
        self.validate_erased_entity(from)?;
        self.validate_erased_entity(to)?;

        let mut current = from.clone();
        let mut resolved = Vec::with_capacity(path.len());
        for (position, reference) in path.iter().enumerate() {
            if reference.scope() != from.scope() {
                return Err(WorkspaceViewError::RelationScopeMismatch {
                    position,
                    expected: from.scope().clone(),
                    found: reference.scope().clone(),
                });
            }
            let relation = self.relation(reference)?;
            if relation.from != current {
                return Err(WorkspaceViewError::PathDiscontinuity {
                    position,
                    expected: current,
                    found: relation.from,
                });
            }
            current = relation.to.clone();
            resolved.push(relation);
        }
        if &current != to {
            return Err(WorkspaceViewError::PathTargetMismatch {
                expected: to.clone(),
                found: current,
            });
        }
        Ok(resolved)
    }

    /// Returns one validated artifact view without erasing its exact scope.
    pub(crate) fn artifact(
        &self,
        scope: &ArtifactScopeId,
    ) -> Result<ArtifactDbView<'a>, WorkspaceViewError> {
        self.artifacts
            .get(scope)
            .copied()
            .ok_or_else(|| WorkspaceViewError::MissingScope {
                scope: scope.clone(),
            })
    }

    /// Whether every managed artifact contains this exact registered row type.
    ///
    /// Present-empty tables count as complete producer output. A missing table
    /// in even one scope is incomplete workspace input and must fail preflight.
    pub(crate) fn all_artifacts_contain_typed_table<S: RowSchema>(
        &self,
        expected: TableKind,
    ) -> bool {
        self.artifacts.values().all(|view| {
            let Ok(descriptor) = view.registry().descriptor_for::<S>() else {
                return false;
            };
            if descriptor.kind() != expected {
                return false;
            }
            let schema = descriptor.id();
            view.artifact()
                .tables
                .binary_search_by(|table| table.schema.cmp(schema))
                .is_ok()
        })
    }

    /// Validates an erased row against its exact scope and optional table kind.
    pub(crate) fn validate_erased_row(
        &self,
        reference: &ScopedRowRef,
        expected: Option<TableKind>,
    ) -> Result<(), WorkspaceViewError> {
        let view = self.artifact(reference.scope())?;
        let artifact = view.artifact();
        let table = artifact
            .tables
            .binary_search_by(|table| table.schema.cmp(&reference.row().schema))
            .ok()
            .map(|index| &artifact.tables[index])
            .ok_or_else(|| WorkspaceViewError::View {
                scope: reference.scope().clone(),
                source: ViewError::MissingTable {
                    schema: reference.row().schema.clone(),
                },
            })?;
        if let Some(expected) = expected
            && table.kind != expected
        {
            return Err(WorkspaceViewError::View {
                scope: reference.scope().clone(),
                source: ViewError::TableKindMismatch {
                    schema: table.schema.clone(),
                    expected,
                    found: table.kind,
                },
            });
        }
        if usize::try_from(reference.row().row)
            .ok()
            .is_none_or(|row| row >= table.rows.len())
        {
            return Err(WorkspaceViewError::View {
                scope: reference.scope().clone(),
                source: ViewError::RowOutOfBounds {
                    schema: table.schema.clone(),
                    row: reference.row().row,
                    row_count: table.rows.len(),
                },
            });
        }
        Ok(())
    }

    /// Validates an erased entity reference against its exact artifact scope.
    pub(crate) fn validate_entity(
        &self,
        reference: &ScopedEntityRef,
    ) -> Result<(), WorkspaceViewError> {
        self.validate_erased_row(&reference.as_row(), Some(TableKind::Entity))
    }

    fn ensure_entity_schema<E: EntitySchema>(
        scope: &ArtifactScopeId,
        view: ArtifactDbView<'_>,
    ) -> Result<SchemaId, WorkspaceViewError> {
        let schema = SchemaId::new(E::ID).map_err(|error| WorkspaceViewError::InvalidSchema {
            scope: scope.clone(),
            declared: E::ID.to_owned(),
            reason: error.to_string(),
        })?;
        let descriptor = view.registry().descriptor_for::<E>().map_err(|error| {
            WorkspaceViewError::SchemaUnavailable {
                scope: scope.clone(),
                schema: schema.clone(),
                reason: error.to_string(),
            }
        })?;
        if descriptor.kind() != TableKind::Entity {
            return Err(WorkspaceViewError::SchemaKindMismatch {
                scope: scope.clone(),
                schema,
                expected: TableKind::Entity,
                found: descriptor.kind(),
            });
        }
        Ok(schema)
    }

    fn ensure_same_path_scope(
        from: &ScopedEntityRef,
        to: &ScopedEntityRef,
    ) -> Result<(), WorkspaceViewError> {
        if from.scope() == to.scope() {
            Ok(())
        } else {
            Err(WorkspaceViewError::CrossScopePath {
                from: from.scope().clone(),
                to: to.scope().clone(),
            })
        }
    }

    fn validate_erased_entity(
        &self,
        reference: &ScopedEntityRef,
    ) -> Result<ArtifactDbView<'a>, WorkspaceViewError> {
        let view = self.artifact(reference.scope())?;
        self.validate_entity(reference)?;
        Ok(view)
    }
}

/// Structured artifact-composition or scoped-lookup failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WorkspaceViewError {
    DuplicateScope {
        scope: ArtifactScopeId,
    },
    MissingScope {
        scope: ArtifactScopeId,
    },
    InvalidSchema {
        scope: ArtifactScopeId,
        declared: String,
        reason: String,
    },
    SchemaUnavailable {
        scope: ArtifactScopeId,
        schema: SchemaId,
        reason: String,
    },
    SchemaKindMismatch {
        scope: ArtifactScopeId,
        schema: SchemaId,
        expected: TableKind,
        found: TableKind,
    },
    EntitySchemaMismatch {
        reference: ScopedEntityRef,
        expected: SchemaId,
    },
    View {
        scope: ArtifactScopeId,
        source: ViewError,
    },
    CrossScopePath {
        from: ArtifactScopeId,
        to: ArtifactScopeId,
    },
    RelationScopeMismatch {
        position: usize,
        expected: ArtifactScopeId,
        found: ArtifactScopeId,
    },
    PathDiscontinuity {
        position: usize,
        expected: ScopedEntityRef,
        found: ScopedEntityRef,
    },
    PathTargetMismatch {
        expected: ScopedEntityRef,
        found: ScopedEntityRef,
    },
}

impl Display for WorkspaceViewError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateScope { scope } => {
                write!(formatter, "duplicate exact artifact scope `{scope}`")
            }
            Self::MissingScope { scope } => {
                write!(formatter, "workspace has no artifact scope `{scope}`")
            }
            Self::InvalidSchema {
                scope,
                declared,
                reason,
            } => write!(
                formatter,
                "schema {declared:?} is invalid in artifact scope `{scope}`: {reason}"
            ),
            Self::SchemaUnavailable {
                scope,
                schema,
                reason,
            } => write!(
                formatter,
                "schema `{schema}` is unavailable in artifact scope `{scope}`: {reason}"
            ),
            Self::SchemaKindMismatch {
                scope,
                schema,
                expected,
                found,
            } => write!(
                formatter,
                "schema `{schema}` in artifact scope `{scope}` has kind {found:?}, expected {expected:?}"
            ),
            Self::EntitySchemaMismatch {
                reference,
                expected,
            } => write!(
                formatter,
                "entity reference `{}`:{} in artifact scope `{}` does not match expected schema `{expected}`",
                reference.entity.schema, reference.entity.row, reference.scope
            ),
            Self::View { scope, source } => {
                write!(
                    formatter,
                    "artifact scope `{scope}` lookup failed: {source}"
                )
            }
            Self::CrossScopePath { from, to } => write!(
                formatter,
                "no implicit provenance path crosses artifact scopes `{from}` and `{to}`"
            ),
            Self::RelationScopeMismatch {
                position,
                expected,
                found,
            } => write!(
                formatter,
                "path relation {position} belongs to artifact scope `{found}`, expected `{expected}`"
            ),
            Self::PathDiscontinuity {
                position,
                expected,
                found,
            } => write!(
                formatter,
                "path relation {position} starts at {found:?}, expected {expected:?}"
            ),
            Self::PathTargetMismatch { expected, found } => write!(
                formatter,
                "path ends at {found:?}, expected target {expected:?}"
            ),
        }
    }
}

impl Error for WorkspaceViewError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::View { source, .. } => Some(source),
            Self::DuplicateScope { .. }
            | Self::MissingScope { .. }
            | Self::InvalidSchema { .. }
            | Self::SchemaUnavailable { .. }
            | Self::SchemaKindMismatch { .. }
            | Self::EntitySchemaMismatch { .. }
            | Self::CrossScopePath { .. }
            | Self::RelationScopeMismatch { .. }
            | Self::PathDiscontinuity { .. }
            | Self::PathTargetMismatch { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
