//! One-time validation and indexing of exact-generation program facts.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use super::super::super::encoded::{EntityRef, TableKind};
use super::super::super::human::markers::{
    MarkerClaimEntity, MarkerClaimKey, MarkerOccurrenceEntity, MarkerOccurrenceKey,
};
use super::super::super::safety::operations::{
    UnsafeOperationEntity, UnsafeOperationKey, UnsafeOperationMacroExpansionEntity,
    UnsafeOperationMacroExpansionKey,
};
use super::super::super::schema::{EntityId, EntitySchema, RelationSchema, RowSchema};
use super::super::super::view::{ArtifactDbView, TypedRelation, ViewError};
use super::super::super::workspace::{
    ArtifactScopeId, ScopedEntityId, ScopedEntityRef, WorkspaceFactView, WorkspaceIdentity,
};
use super::super::topology::{
    CallKind, CallMacroExpansionEntity, CallMacroExpansionKey, CallOccurrenceEntity,
    CallOccurrenceKey, CallSiteEntity, CallSiteKey, CallableEntity, CallableKey, CallableKeyEntity,
    FunctionDefinesCallable, SafetyEffectGroupEntity, SafetyEffectGroupKey,
};
use super::super::{
    EffectSiteEntity, EffectSiteKey, FunctionBodyProvenance, FunctionEntity,
    FunctionHasSourceAnchor, FunctionKey, MacroExpansionEntity, MacroExpansionKey,
    SourceAnchorEntity, SourceAnchorInFile, SourceAnchorKey, SourceFileEntity,
};
use super::CallableBodySelectionKind;
use super::topology::ArtifactTopology;

/// One decoded entity that never drops its exact artifact generation.
#[derive(Clone, Debug)]
pub(crate) struct ScopedProgramEntity<E> {
    reference: ScopedEntityRef,
    data: E,
}

impl<E> ScopedProgramEntity<E> {
    #[must_use]
    pub(crate) const fn reference(&self) -> &ScopedEntityRef {
        &self.reference
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &E {
        &self.data
    }
}

impl<E: EntitySchema> ScopedProgramEntity<E> {
    /// Returns the typed identity validated for this exact artifact generation.
    #[must_use]
    pub(crate) fn id(&self) -> ScopedEntityId<E> {
        ScopedEntityId::new(
            self.reference.scope().clone(),
            EntityId::new(self.reference.entity().row),
        )
    }
}

/// One policy-neutral body candidate and the selection provenance it would emit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FunctionBodyCandidate<'a> {
    body: &'a ScopedProgramEntity<FunctionEntity>,
    selection_kind: CallableBodySelectionKind,
}

impl<'a> FunctionBodyCandidate<'a> {
    #[must_use]
    pub(crate) const fn body(&self) -> &'a ScopedProgramEntity<FunctionEntity> {
        self.body
    }

    #[must_use]
    pub(crate) const fn selection_kind(&self) -> CallableBodySelectionKind {
        self.selection_kind
    }
}

#[derive(Debug)]
pub(super) struct EntityTable<E: EntitySchema> {
    pub(super) by_key: BTreeMap<E::Key, ScopedProgramEntity<E>>,
    pub(super) by_row: BTreeMap<u32, E::Key>,
}

impl<E: EntitySchema> EntityTable<E> {
    fn load(
        scope: &ArtifactScopeId,
        view: ArtifactDbView<'_>,
    ) -> Result<Self, WorkspaceProgramIndexError> {
        require_table::<E>(scope, view, TableKind::Entity)?;
        let mut by_key = BTreeMap::new();
        let mut by_row = BTreeMap::new();
        for row in view
            .indexed_rows::<E>()
            .map_err(|source| view_error(scope, &source))?
        {
            let key = row.data.key();
            let reference = ScopedEntityRef::new(
                scope.clone(),
                EntityRef {
                    schema: row.reference.schema,
                    row: row.reference.row,
                },
            );
            if by_row.insert(reference.entity().row, key.clone()).is_some()
                || by_key
                    .insert(
                        key,
                        ScopedProgramEntity {
                            reference,
                            data: row.data,
                        },
                    )
                    .is_some()
            {
                return Err(malformed(scope, E::ID, "duplicate entity identity"));
            }
        }
        Ok(Self { by_key, by_row })
    }

    pub(super) fn get(&self, key: &E::Key) -> Option<&ScopedProgramEntity<E>> {
        self.by_key.get(key)
    }

    fn get_borrowed<Q>(&self, key: &Q) -> Option<&ScopedProgramEntity<E>>
    where
        E::Key: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.by_key.get(key)
    }

    pub(super) fn key_for_id(
        &self,
        scope: &ArtifactScopeId,
        id: EntityId<E>,
        relation: &'static str,
        endpoint: &'static str,
    ) -> Result<E::Key, WorkspaceProgramIndexError> {
        self.by_row.get(&id.row()).cloned().ok_or_else(|| {
            malformed(
                scope,
                relation,
                format!("{endpoint} entity row {} is unavailable", id.row()),
            )
        })
    }

    pub(super) fn entity_for_id(
        &self,
        scope: &ArtifactScopeId,
        id: EntityId<E>,
        relation: &'static str,
        endpoint: &'static str,
    ) -> Result<&ScopedProgramEntity<E>, WorkspaceProgramIndexError> {
        let key = self.key_for_id(scope, id, relation, endpoint)?;
        Ok(self
            .by_key
            .get(&key)
            .expect("row and key indexes are built atomically"))
    }
}

#[derive(Debug)]
pub(super) struct ArtifactProgramIndex {
    pub(super) source_files: EntityTable<SourceFileEntity>,
    pub(super) source_anchors: EntityTable<SourceAnchorEntity>,
    pub(super) functions: EntityTable<FunctionEntity>,
    pub(super) callables: EntityTable<CallableEntity>,
    pub(super) call_sites: EntityTable<CallSiteEntity>,
    pub(super) occurrences: EntityTable<CallOccurrenceEntity>,
    pub(super) callable_keys: EntityTable<CallableKeyEntity>,
    pub(super) safety_groups: EntityTable<SafetyEffectGroupEntity>,
    pub(super) effects: EntityTable<EffectSiteEntity>,
    pub(super) effect_macros: EntityTable<MacroExpansionEntity>,
    pub(super) call_macros: EntityTable<CallMacroExpansionEntity>,
    pub(super) unsafe_operations: EntityTable<UnsafeOperationEntity>,
    pub(super) unsafe_macros: EntityTable<UnsafeOperationMacroExpansionEntity>,
    pub(super) marker_occurrences: EntityTable<MarkerOccurrenceEntity>,
    pub(super) marker_claims: EntityTable<MarkerClaimEntity>,
    function_anchors: BTreeMap<FunctionKey, SourceAnchorKey>,
    pub(super) topology: ArtifactTopology,
}

impl ArtifactProgramIndex {
    fn open(
        scope: &ArtifactScopeId,
        view: ArtifactDbView<'_>,
        stable_crate_id: u64,
    ) -> Result<Self, WorkspaceProgramIndexError> {
        let mut index = Self {
            source_files: EntityTable::load(scope, view)?,
            source_anchors: EntityTable::load(scope, view)?,
            functions: EntityTable::load(scope, view)?,
            callables: EntityTable::load(scope, view)?,
            call_sites: EntityTable::load(scope, view)?,
            occurrences: EntityTable::load(scope, view)?,
            callable_keys: EntityTable::load(scope, view)?,
            safety_groups: EntityTable::load(scope, view)?,
            effects: EntityTable::load(scope, view)?,
            effect_macros: EntityTable::load(scope, view)?,
            call_macros: EntityTable::load(scope, view)?,
            unsafe_operations: EntityTable::load(scope, view)?,
            unsafe_macros: EntityTable::load(scope, view)?,
            marker_occurrences: EntityTable::load(scope, view)?,
            marker_claims: EntityTable::load(scope, view)?,
            function_anchors: BTreeMap::new(),
            topology: ArtifactTopology::default(),
        };
        index.validate_sources(scope, view)?;
        index.function_anchors = index.validate_function_source_anchors(scope, view)?;
        index.validate_functions(scope, view, stable_crate_id)?;
        let topology = ArtifactTopology::open(scope, view, &index)?;
        index.topology = topology;
        Ok(index)
    }

    fn validate_sources(
        &self,
        scope: &ArtifactScopeId,
        view: ArtifactDbView<'_>,
    ) -> Result<(), WorkspaceProgramIndexError> {
        for file in self.source_files.by_key.values() {
            for (field, value) in [
                ("id", file.data.id()),
                ("filename", file.data.filename()),
                ("content hash", file.data.content_hash()),
            ] {
                if value.is_empty() {
                    return Err(malformed(
                        scope,
                        SourceFileEntity::ID,
                        format!("source file {field} is empty"),
                    ));
                }
            }
        }

        let relations = load_relations::<SourceAnchorInFile>(scope, view)?;
        let mut files_by_anchor = BTreeMap::<SourceAnchorKey, String>::new();
        for relation in relations {
            let anchor = self.source_anchors.key_for_id(
                scope,
                relation.from,
                SourceAnchorInFile::ID,
                "from",
            )?;
            let file =
                self.source_files
                    .key_for_id(scope, relation.to, SourceAnchorInFile::ID, "to")?;
            if files_by_anchor
                .insert(anchor.clone(), file.clone())
                .is_some()
            {
                return Err(malformed(
                    scope,
                    SourceAnchorInFile::ID,
                    format!("source anchor {anchor:?} has multiple source files"),
                ));
            }
            if anchor.file() != file {
                return Err(malformed(
                    scope,
                    SourceAnchorInFile::ID,
                    format!("source anchor {anchor:?} points to mismatched file {file:?}"),
                ));
            }
        }
        for anchor in self.source_anchors.by_key.keys() {
            let Some(file_key) = files_by_anchor.get(anchor) else {
                return Err(malformed(
                    scope,
                    SourceAnchorInFile::ID,
                    format!("source anchor {anchor:?} has no source file"),
                ));
            };
            let file = self
                .source_files
                .get(file_key)
                .expect("validated source relation names an indexed file");
            if anchor.byte_start() > anchor.byte_end() || anchor.byte_end() > file.data.byte_len() {
                return Err(malformed(
                    scope,
                    SourceAnchorEntity::ID,
                    format!(
                        "source anchor {anchor:?} exceeds file length {}",
                        file.data.byte_len()
                    ),
                ));
            }
        }
        Ok(())
    }

    fn validate_functions(
        &self,
        scope: &ArtifactScopeId,
        view: ArtifactDbView<'_>,
        stable_crate_id: u64,
    ) -> Result<(), WorkspaceProgramIndexError> {
        for callable in self.callables.by_key.values() {
            if callable.data.display_path().is_empty()
                || callable.data.namespace_candidates().is_empty()
                || callable
                    .data
                    .namespace_candidates()
                    .iter()
                    .any(String::is_empty)
            {
                return Err(malformed(
                    scope,
                    CallableEntity::ID,
                    format!(
                        "callable {:?} has incomplete naming metadata",
                        callable.data.key()
                    ),
                ));
            }
        }

        let relations = load_relations::<FunctionDefinesCallable>(scope, view)?;
        let mut callable_by_function = BTreeMap::<FunctionKey, FunctionKey>::new();
        for relation in relations {
            let function = self.functions.key_for_id(
                scope,
                relation.from,
                FunctionDefinesCallable::ID,
                "from",
            )?;
            let callable =
                self.callables
                    .key_for_id(scope, relation.to, FunctionDefinesCallable::ID, "to")?;
            if function != callable {
                return Err(malformed(
                    scope,
                    FunctionDefinesCallable::ID,
                    format!("function {function:?} defines mismatched callable {callable:?}"),
                ));
            }
            if callable_by_function.insert(function, callable).is_some() {
                return Err(malformed(
                    scope,
                    FunctionDefinesCallable::ID,
                    format!("function {function:?} defines multiple callable rows"),
                ));
            }
        }

        for function in self.functions.by_key.values() {
            if function.data.display_path().is_empty() {
                return Err(malformed(
                    scope,
                    FunctionEntity::ID,
                    format!(
                        "function {:?} has an empty display path",
                        function.data.key()
                    ),
                ));
            }
            let definition_stable_crate_id = function.data.key().definition().stable_crate_id();
            let provenance_is_valid = match function.data.provenance() {
                FunctionBodyProvenance::DefiningArtifact => {
                    definition_stable_crate_id == stable_crate_id
                }
                FunctionBodyProvenance::ConsumerInstantiation {
                    consumer_stable_crate_id,
                } => {
                    consumer_stable_crate_id == stable_crate_id
                        && definition_stable_crate_id != stable_crate_id
                        && function.data.key().instance().is_some()
                }
            };
            if !provenance_is_valid {
                return Err(malformed(
                    scope,
                    FunctionEntity::ID,
                    format!(
                        "function {:?} has provenance {:?} incompatible with verified artifact owner {stable_crate_id:016x}",
                        function.data.key(),
                        function.data.provenance()
                    ),
                ));
            }
            if !callable_by_function.contains_key(function.data.key()) {
                return Err(malformed(
                    scope,
                    FunctionDefinesCallable::ID,
                    format!("function {:?} has no callable row", function.data.key()),
                ));
            }
        }
        Ok(())
    }

    fn validate_function_source_anchors(
        &self,
        scope: &ArtifactScopeId,
        view: ArtifactDbView<'_>,
    ) -> Result<BTreeMap<FunctionKey, SourceAnchorKey>, WorkspaceProgramIndexError> {
        let mut anchors = BTreeMap::new();
        for relation in load_relations::<FunctionHasSourceAnchor>(scope, view)? {
            let function = self.functions.key_for_id(
                scope,
                relation.from,
                FunctionHasSourceAnchor::ID,
                "from",
            )?;
            let anchor = self.source_anchors.key_for_id(
                scope,
                relation.to,
                FunctionHasSourceAnchor::ID,
                "to",
            )?;
            if anchors.insert(function, anchor).is_some() {
                return Err(malformed(
                    scope,
                    FunctionHasSourceAnchor::ID,
                    format!("function {function:?} has multiple declaration anchors"),
                ));
            }
        }
        Ok(anchors)
    }
}

#[derive(Debug)]
struct WorkspaceProgramIndexInner {
    workspace: Arc<WorkspaceIdentity>,
    stable_crate_ids: BTreeMap<ArtifactScopeId, u64>,
    artifacts: BTreeMap<ArtifactScopeId, ArtifactProgramIndex>,
    callable_evidence: BTreeMap<CallableKey, Vec<super::topology::IndexedCallableEvidence>>,
    callable_evidence_by_occurrence: BTreeMap<
        ScopedEntityId<CallOccurrenceEntity>,
        Vec<super::topology::IndexedCallableEvidence>,
    >,
}

/// Trusted cache-envelope ownership for one exact artifact generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedArtifactOwner {
    scope: ArtifactScopeId,
    stable_crate_id: u64,
}

impl VerifiedArtifactOwner {
    #[must_use]
    pub(crate) const fn new(scope: ArtifactScopeId, stable_crate_id: u64) -> Self {
        Self {
            scope,
            stable_crate_id,
        }
    }

    #[must_use]
    pub(crate) const fn scope(&self) -> &ArtifactScopeId {
        &self.scope
    }

    #[must_use]
    pub(crate) const fn stable_crate_id(&self) -> u64 {
        self.stable_crate_id
    }
}

/// Immutable, one-time program preparation for one exact workspace view.
#[derive(Clone, Debug)]
pub(crate) struct WorkspaceProgramIndex {
    inner: Arc<WorkspaceProgramIndexInner>,
}

impl WorkspaceProgramIndex {
    pub(crate) fn open(
        workspace: &WorkspaceFactView<'_>,
        owners: impl IntoIterator<Item = VerifiedArtifactOwner>,
    ) -> Result<Self, WorkspaceProgramIndexError> {
        let expected_scopes = workspace.scopes().cloned().collect::<BTreeSet<_>>();
        let mut stable_crate_ids = BTreeMap::new();
        for owner in owners {
            if stable_crate_ids
                .insert(owner.scope, owner.stable_crate_id)
                .is_some()
            {
                return Err(WorkspaceProgramIndexError::InvalidScopeOwners {
                    reason: String::from("one artifact scope has multiple verified owners"),
                });
            }
        }
        let owner_scopes = stable_crate_ids.keys().cloned().collect::<BTreeSet<_>>();
        if expected_scopes != owner_scopes {
            return Err(WorkspaceProgramIndexError::InvalidScopeOwners {
                reason: format!(
                    "verified owner scopes differ from workspace scopes: expected {expected_scopes:?}, found {owner_scopes:?}"
                ),
            });
        }

        let mut artifacts = BTreeMap::new();
        for scope in workspace.scopes() {
            let view = workspace.artifact(scope).map_err(|source| {
                WorkspaceProgramIndexError::InvalidWorkspace {
                    scope: scope.clone(),
                    reason: source.to_string(),
                }
            })?;
            let stable_crate_id = *stable_crate_ids
                .get(scope)
                .expect("exact owner coverage was validated");
            artifacts.insert(
                scope.clone(),
                ArtifactProgramIndex::open(scope, view, stable_crate_id)?,
            );
        }
        let mut callable_evidence =
            BTreeMap::<CallableKey, Vec<super::topology::IndexedCallableEvidence>>::new();
        let mut callable_evidence_by_occurrence = BTreeMap::<
            ScopedEntityId<CallOccurrenceEntity>,
            Vec<super::topology::IndexedCallableEvidence>,
        >::new();
        for artifact in artifacts.values() {
            for (key, records) in artifact.topology.callable_evidence_index() {
                callable_evidence
                    .entry(*key)
                    .or_default()
                    .extend(records.iter().cloned());
                for record in records {
                    callable_evidence_by_occurrence
                        .entry(record.occurrence().clone())
                        .or_default()
                        .push(record.clone());
                }
            }
        }
        for records in callable_evidence.values_mut() {
            records.sort_by(|left, right| {
                left.occurrence
                    .cmp(&right.occurrence)
                    .then_with(|| left.callable.cmp(&right.callable))
            });
        }
        for records in callable_evidence_by_occurrence.values_mut() {
            records.sort_unstable();
        }
        Ok(Self {
            inner: Arc::new(WorkspaceProgramIndexInner {
                workspace: workspace.identity(),
                stable_crate_ids,
                artifacts,
                callable_evidence,
                callable_evidence_by_occurrence,
            }),
        })
    }

    pub(crate) fn validate_workspace(
        &self,
        workspace: &WorkspaceFactView<'_>,
    ) -> Result<(), WorkspaceProgramIndexError> {
        if workspace.has_identity(&self.inner.workspace) {
            Ok(())
        } else {
            Err(WorkspaceProgramIndexError::WorkspaceMismatch)
        }
    }

    pub(crate) fn scopes(
        &self,
    ) -> impl ExactSizeIterator<Item = &ArtifactScopeId> + DoubleEndedIterator {
        self.inner.artifacts.keys()
    }

    pub(crate) fn stable_crate_id(
        &self,
        scope: &ArtifactScopeId,
    ) -> Result<u64, WorkspaceProgramIndexError> {
        self.inner
            .stable_crate_ids
            .get(scope)
            .copied()
            .ok_or_else(|| WorkspaceProgramIndexError::UnknownScope {
                scope: scope.clone(),
            })
    }

    /// Stable crate identities named by authority-relevant typed rows in one scope.
    ///
    /// The result is canonical and includes the artifact's own stable crate
    /// identity when it owns a callable. Dynamic-dispatch definitions and macro
    /// definitions participate; function-pointer type hashes do not name a
    /// definition owner. Callers use this set to require an explicit contextual
    /// authority decision without parsing display paths or consulting legacy IR.
    pub(crate) fn referenced_definition_stable_crate_ids(
        &self,
        scope: &ArtifactScopeId,
    ) -> Result<BTreeSet<u64>, WorkspaceProgramIndexError> {
        let artifact = self.artifact(scope)?;
        let mut stable_crate_ids = artifact
            .callables
            .by_key
            .keys()
            .map(|key| key.definition().stable_crate_id())
            .collect::<BTreeSet<_>>();
        stable_crate_ids.extend(
            artifact
                .callable_keys
                .by_key
                .keys()
                .filter_map(|key| match key {
                    CallableKey::DynDispatch(definition) => Some(definition.stable_crate_id()),
                    CallableKey::FnPointer(_) => None,
                }),
        );
        stable_crate_ids.extend(
            artifact
                .effect_macros
                .by_key
                .values()
                .map(|entity| entity.data().macro_definition().stable_crate_id()),
        );
        stable_crate_ids.extend(
            artifact
                .call_macros
                .by_key
                .values()
                .map(|entity| entity.data().macro_definition().stable_crate_id()),
        );
        stable_crate_ids.extend(
            artifact
                .unsafe_macros
                .by_key
                .values()
                .map(|entity| entity.data().macro_definition().stable_crate_id()),
        );
        Ok(stable_crate_ids)
    }

    #[must_use]
    pub(crate) fn exact_function(
        &self,
        scope: &ArtifactScopeId,
        key: &FunctionKey,
    ) -> Option<&ScopedProgramEntity<FunctionEntity>> {
        self.inner.artifacts.get(scope)?.functions.get(key)
    }

    pub(crate) fn function_declaration_anchor(
        &self,
        scope: &ArtifactScopeId,
        function: &FunctionKey,
    ) -> Result<Option<&ScopedProgramEntity<SourceAnchorEntity>>, WorkspaceProgramIndexError> {
        let artifact = self.artifact(scope)?;
        if artifact.functions.get(function).is_none() {
            return Err(WorkspaceProgramIndexError::InvalidQuery {
                reason: format!("function {function:?} is unavailable"),
            });
        }
        Ok(artifact
            .function_anchors
            .get(function)
            .and_then(|anchor| artifact.source_anchors.get(anchor)))
    }

    #[must_use]
    pub(crate) fn exact_source_file(
        &self,
        scope: &ArtifactScopeId,
        key: &str,
    ) -> Option<&ScopedProgramEntity<SourceFileEntity>> {
        self.inner
            .artifacts
            .get(scope)?
            .source_files
            .get_borrowed(key)
    }

    #[must_use]
    pub(crate) fn exact_source_anchor(
        &self,
        scope: &ArtifactScopeId,
        key: &SourceAnchorKey,
    ) -> Option<&ScopedProgramEntity<SourceAnchorEntity>> {
        self.inner.artifacts.get(scope)?.source_anchors.get(key)
    }

    #[must_use]
    pub(crate) fn exact_callable(
        &self,
        scope: &ArtifactScopeId,
        key: &FunctionKey,
    ) -> Option<&ScopedProgramEntity<CallableEntity>> {
        self.inner.artifacts.get(scope)?.callables.get(key)
    }

    #[must_use]
    pub(crate) fn exact_call_site(
        &self,
        scope: &ArtifactScopeId,
        key: &CallSiteKey,
    ) -> Option<&ScopedProgramEntity<CallSiteEntity>> {
        self.inner.artifacts.get(scope)?.call_sites.get(key)
    }

    #[must_use]
    pub(crate) fn exact_call_occurrence(
        &self,
        scope: &ArtifactScopeId,
        key: &CallOccurrenceKey,
    ) -> Option<&ScopedProgramEntity<CallOccurrenceEntity>> {
        self.inner.artifacts.get(scope)?.occurrences.get(key)
    }

    #[must_use]
    pub(crate) fn exact_callable_key(
        &self,
        scope: &ArtifactScopeId,
        key: &CallableKey,
    ) -> Option<&ScopedProgramEntity<CallableKeyEntity>> {
        self.inner.artifacts.get(scope)?.callable_keys.get(key)
    }

    #[must_use]
    pub(crate) fn exact_safety_group(
        &self,
        scope: &ArtifactScopeId,
        key: &SafetyEffectGroupKey,
    ) -> Option<&ScopedProgramEntity<SafetyEffectGroupEntity>> {
        self.inner.artifacts.get(scope)?.safety_groups.get(key)
    }

    #[must_use]
    pub(crate) fn exact_effect_site(
        &self,
        scope: &ArtifactScopeId,
        key: &EffectSiteKey,
    ) -> Option<&ScopedProgramEntity<EffectSiteEntity>> {
        self.inner.artifacts.get(scope)?.effects.get(key)
    }

    #[must_use]
    pub(crate) fn exact_effect_macro(
        &self,
        scope: &ArtifactScopeId,
        key: &MacroExpansionKey,
    ) -> Option<&ScopedProgramEntity<MacroExpansionEntity>> {
        self.inner.artifacts.get(scope)?.effect_macros.get(key)
    }

    #[must_use]
    pub(crate) fn exact_call_macro(
        &self,
        scope: &ArtifactScopeId,
        key: &CallMacroExpansionKey,
    ) -> Option<&ScopedProgramEntity<CallMacroExpansionEntity>> {
        self.inner.artifacts.get(scope)?.call_macros.get(key)
    }

    #[must_use]
    pub(crate) fn exact_unsafe_operation(
        &self,
        scope: &ArtifactScopeId,
        key: &UnsafeOperationKey,
    ) -> Option<&ScopedProgramEntity<UnsafeOperationEntity>> {
        self.inner.artifacts.get(scope)?.unsafe_operations.get(key)
    }

    #[must_use]
    pub(crate) fn exact_unsafe_macro(
        &self,
        scope: &ArtifactScopeId,
        key: &UnsafeOperationMacroExpansionKey,
    ) -> Option<&ScopedProgramEntity<UnsafeOperationMacroExpansionEntity>> {
        self.inner.artifacts.get(scope)?.unsafe_macros.get(key)
    }

    #[must_use]
    pub(crate) fn exact_marker_occurrence(
        &self,
        scope: &ArtifactScopeId,
        key: &MarkerOccurrenceKey,
    ) -> Option<&ScopedProgramEntity<MarkerOccurrenceEntity>> {
        self.inner.artifacts.get(scope)?.marker_occurrences.get(key)
    }

    #[must_use]
    pub(crate) fn exact_marker_claim(
        &self,
        scope: &ArtifactScopeId,
        key: &MarkerClaimKey,
    ) -> Option<&ScopedProgramEntity<MarkerClaimEntity>> {
        self.inner.artifacts.get(scope)?.marker_claims.get(key)
    }

    pub(crate) fn body_candidates(
        &self,
        scope: &ArtifactScopeId,
        requested: &FunctionKey,
    ) -> Result<Vec<FunctionBodyCandidate<'_>>, WorkspaceProgramIndexError> {
        let artifact = self.artifact(scope)?;
        let mut candidates = Vec::with_capacity(2);
        if let Some(body) = artifact.functions.get(requested) {
            candidates.push(FunctionBodyCandidate {
                body,
                selection_kind: if requested.instance().is_some() {
                    CallableBodySelectionKind::ExactPreferred
                } else {
                    CallableBodySelectionKind::GenericPreferred
                },
            });
        }
        if requested.instance().is_some() {
            let generic = FunctionKey::new(requested.definition(), None);
            if let Some(body) = artifact.functions.get(&generic) {
                candidates.push(FunctionBodyCandidate {
                    body,
                    selection_kind: CallableBodySelectionKind::GenericPreferred,
                });
            }
        }
        Ok(candidates)
    }

    pub(crate) fn defining_body_candidates(
        &self,
        consumer_scope: &ArtifactScopeId,
        consumer_key: &FunctionKey,
        defining_scope: &ArtifactScopeId,
    ) -> Result<Vec<FunctionBodyCandidate<'_>>, WorkspaceProgramIndexError> {
        let consumer_artifact = self.artifact(consumer_scope)?;
        let consumer = consumer_artifact
            .functions
            .get(consumer_key)
            .ok_or_else(|| WorkspaceProgramIndexError::InvalidQuery {
                reason: format!(
                    "consumer function {consumer_key:?} is unavailable in `{consumer_scope}`"
                ),
            })?;
        if consumer.data.key().instance().is_none()
            || !matches!(
                consumer.data.provenance(),
                FunctionBodyProvenance::ConsumerInstantiation { .. }
            )
        {
            return Err(WorkspaceProgramIndexError::InvalidQuery {
                reason: format!(
                    "defining-source lookup requires an exact consumer overlay, found {:?}",
                    consumer.data.key()
                ),
            });
        }

        self.managed_body_candidates(defining_scope, consumer.data.key())
    }

    /// Finds defining-artifact bodies only inside an explicitly selected managed scope.
    pub(crate) fn managed_body_candidates(
        &self,
        defining_scope: &ArtifactScopeId,
        requested: &FunctionKey,
    ) -> Result<Vec<FunctionBodyCandidate<'_>>, WorkspaceProgramIndexError> {
        let defining = self.artifact(defining_scope)?;
        let mut candidates = Vec::with_capacity(2);
        if let Some(body) = defining.functions.get(requested)
            && body.data.provenance() == FunctionBodyProvenance::DefiningArtifact
        {
            candidates.push(FunctionBodyCandidate {
                body,
                selection_kind: if requested.instance().is_some() {
                    CallableBodySelectionKind::ExactDefining
                } else {
                    CallableBodySelectionKind::GenericDefining
                },
            });
        }
        if requested.instance().is_some() {
            let generic = FunctionKey::new(requested.definition(), None);
            if let Some(body) = defining.functions.get(&generic)
                && body.data.provenance() == FunctionBodyProvenance::DefiningArtifact
            {
                candidates.push(FunctionBodyCandidate {
                    body,
                    selection_kind: CallableBodySelectionKind::GenericDefining,
                });
            }
        }
        Ok(candidates)
    }

    pub(crate) fn call_sites_owned_by(
        &self,
        scope: &ArtifactScopeId,
        function: &FunctionKey,
    ) -> Result<&[CallSiteKey], WorkspaceProgramIndexError> {
        Ok(self
            .artifact(scope)?
            .topology
            .call_sites_by_function(function))
    }

    pub(crate) fn call_site_edges_owned_by(
        &self,
        scope: &ArtifactScopeId,
        function: &FunctionKey,
    ) -> Result<&[super::topology::IndexedCallSite], WorkspaceProgramIndexError> {
        Ok(self
            .artifact(scope)?
            .topology
            .call_site_edges_by_function(function))
    }

    pub(crate) fn call_occurrences_at(
        &self,
        scope: &ArtifactScopeId,
        site: &CallSiteKey,
    ) -> Result<&[CallOccurrenceKey], WorkspaceProgramIndexError> {
        Ok(self.artifact(scope)?.topology.call_occurrences_at(site))
    }

    pub(crate) fn call_occurrence_edges_at(
        &self,
        scope: &ArtifactScopeId,
        site: &CallSiteKey,
    ) -> Result<&[super::topology::IndexedCallOccurrence], WorkspaceProgramIndexError> {
        Ok(self
            .artifact(scope)?
            .topology
            .call_occurrence_edges_at(site))
    }

    pub(crate) fn call_targets(
        &self,
        scope: &ArtifactScopeId,
        occurrence: &CallOccurrenceKey,
    ) -> Result<&[super::topology::IndexedCallTarget], WorkspaceProgramIndexError> {
        Ok(self.artifact(scope)?.topology.call_targets(occurrence))
    }

    pub(crate) fn callable_keys(
        &self,
        scope: &ArtifactScopeId,
        occurrence: &CallOccurrenceKey,
    ) -> Result<&[CallableKey], WorkspaceProgramIndexError> {
        Ok(self.artifact(scope)?.topology.callable_keys(occurrence))
    }

    /// Returns records owned by this exact reached evidence occurrence only.
    pub(crate) fn callable_evidence_at(
        &self,
        scope: &ArtifactScopeId,
        evidence: &CallOccurrenceKey,
    ) -> Result<&[super::topology::IndexedCallableEvidence], WorkspaceProgramIndexError> {
        let artifact = self.artifact(scope)?;
        let occurrence = artifact.occurrences.get(evidence).ok_or_else(|| {
            WorkspaceProgramIndexError::InvalidQuery {
                reason: format!("callable evidence {evidence:?} is unavailable in `{scope}`"),
            }
        })?;
        if !matches!(
            occurrence.data().kind(),
            CallKind::FnPointerReify | CallKind::ClosureFnPointerReify | CallKind::VTableEntry
        ) {
            return Err(WorkspaceProgramIndexError::InvalidQuery {
                reason: format!(
                    "call occurrence {:?} is an invocation, not callable evidence",
                    occurrence.data().key()
                ),
            });
        }
        Ok(self
            .inner
            .callable_evidence_by_occurrence
            .get(&occurrence.id())
            .map_or(&[], Vec::as_slice))
    }

    pub(crate) fn call_source_anchors(
        &self,
        scope: &ArtifactScopeId,
        occurrence: &CallOccurrenceKey,
    ) -> Result<&[super::topology::IndexedCallSourceAnchor], WorkspaceProgramIndexError> {
        Ok(self
            .artifact(scope)?
            .topology
            .call_source_anchors(occurrence))
    }

    pub(crate) fn call_macro_path(
        &self,
        scope: &ArtifactScopeId,
        occurrence: &CallOccurrenceKey,
    ) -> Result<Option<&super::topology::IndexedCallMacroPath>, WorkspaceProgramIndexError> {
        Ok(self.artifact(scope)?.topology.call_macro_path(occurrence))
    }

    pub(crate) fn occurrence_safety_group(
        &self,
        scope: &ArtifactScopeId,
        occurrence: &CallOccurrenceKey,
    ) -> Result<&SafetyEffectGroupKey, WorkspaceProgramIndexError> {
        self.artifact(scope)?
            .topology
            .occurrence_safety_group(occurrence)
            .ok_or_else(|| WorkspaceProgramIndexError::InvalidQuery {
                reason: format!("call occurrence {occurrence:?} is unavailable"),
            })
    }

    pub(crate) fn effect_sites_owned_by(
        &self,
        scope: &ArtifactScopeId,
        function: &FunctionKey,
    ) -> Result<&[EffectSiteKey], WorkspaceProgramIndexError> {
        Ok(self
            .artifact(scope)?
            .topology
            .effect_sites_by_function(function))
    }

    pub(crate) fn effect_site_edges_owned_by(
        &self,
        scope: &ArtifactScopeId,
        function: &FunctionKey,
    ) -> Result<&[super::topology::IndexedEffectSite], WorkspaceProgramIndexError> {
        Ok(self
            .artifact(scope)?
            .topology
            .effect_site_edges_by_function(function))
    }

    pub(crate) fn effect_source_anchors(
        &self,
        scope: &ArtifactScopeId,
        effect: &EffectSiteKey,
    ) -> Result<&[super::topology::IndexedEffectSourceAnchor], WorkspaceProgramIndexError> {
        Ok(self.artifact(scope)?.topology.effect_source_anchors(effect))
    }

    pub(crate) fn effect_macro_path(
        &self,
        scope: &ArtifactScopeId,
        effect: &EffectSiteKey,
    ) -> Result<Option<&super::topology::IndexedEffectMacroPath>, WorkspaceProgramIndexError> {
        Ok(self.artifact(scope)?.topology.effect_macro_path(effect))
    }

    pub(crate) fn unsafe_operations_owned_by(
        &self,
        scope: &ArtifactScopeId,
        function: &FunctionKey,
    ) -> Result<&[UnsafeOperationKey], WorkspaceProgramIndexError> {
        Ok(self
            .artifact(scope)?
            .topology
            .unsafe_operations_by_function(function))
    }

    pub(crate) fn unsafe_operation_edges_owned_by(
        &self,
        scope: &ArtifactScopeId,
        function: &FunctionKey,
    ) -> Result<&[super::topology::IndexedUnsafeOperation], WorkspaceProgramIndexError> {
        let artifact = self.artifact(scope)?;
        if artifact.functions.get(function).is_none() {
            return Err(WorkspaceProgramIndexError::InvalidQuery {
                reason: format!("function {function:?} is unavailable in `{scope}`"),
            });
        }
        Ok(artifact
            .topology
            .unsafe_operation_edges_by_function(function))
    }

    pub(crate) fn unsafe_operation_safety_group(
        &self,
        scope: &ArtifactScopeId,
        operation: &UnsafeOperationKey,
    ) -> Result<&SafetyEffectGroupKey, WorkspaceProgramIndexError> {
        self.artifact(scope)?
            .topology
            .unsafe_operation_group(operation)
            .ok_or_else(|| WorkspaceProgramIndexError::InvalidQuery {
                reason: format!("unsafe operation {operation:?} is unavailable"),
            })
    }

    pub(crate) fn unsafe_operation_group_edge(
        &self,
        scope: &ArtifactScopeId,
        operation: &UnsafeOperationKey,
    ) -> Result<&super::topology::IndexedUnsafeOperationSafetyGroup, WorkspaceProgramIndexError>
    {
        self.artifact(scope)?
            .topology
            .unsafe_operation_group_edge(operation)
            .ok_or_else(|| WorkspaceProgramIndexError::InvalidQuery {
                reason: format!("unsafe operation {operation:?} is unavailable"),
            })
    }

    pub(crate) fn unsafe_operation_source_anchors(
        &self,
        scope: &ArtifactScopeId,
        operation: &UnsafeOperationKey,
    ) -> Result<&[super::topology::IndexedUnsafeOperationSourceAnchor], WorkspaceProgramIndexError>
    {
        let artifact = self.artifact(scope)?;
        if artifact.unsafe_operations.get(operation).is_none() {
            return Err(WorkspaceProgramIndexError::InvalidQuery {
                reason: format!("unsafe operation {operation:?} is unavailable in `{scope}`"),
            });
        }
        Ok(artifact.topology.unsafe_operation_source_anchors(operation))
    }

    pub(crate) fn unsafe_operation_macro_path(
        &self,
        scope: &ArtifactScopeId,
        operation: &UnsafeOperationKey,
    ) -> Result<Option<&super::topology::IndexedUnsafeOperationMacroPath>, WorkspaceProgramIndexError>
    {
        let artifact = self.artifact(scope)?;
        if artifact.unsafe_operations.get(operation).is_none() {
            return Err(WorkspaceProgramIndexError::InvalidQuery {
                reason: format!("unsafe operation {operation:?} is unavailable in `{scope}`"),
            });
        }
        Ok(artifact.topology.unsafe_operation_macro_path(operation))
    }

    pub(crate) fn function_marker_candidates(
        &self,
        scope: &ArtifactScopeId,
        function: &FunctionKey,
    ) -> Result<&[super::topology::IndexedMarkerCandidate], WorkspaceProgramIndexError> {
        Ok(self
            .artifact(scope)?
            .topology
            .function_marker_candidates(function))
    }

    pub(crate) fn call_marker_candidates(
        &self,
        scope: &ArtifactScopeId,
        occurrence: &CallOccurrenceKey,
    ) -> Result<&[super::topology::IndexedMarkerCandidate], WorkspaceProgramIndexError> {
        Ok(self
            .artifact(scope)?
            .topology
            .call_marker_candidates(occurrence))
    }

    pub(crate) fn effect_marker_candidates(
        &self,
        scope: &ArtifactScopeId,
        effect: &EffectSiteKey,
    ) -> Result<&[super::topology::IndexedMarkerCandidate], WorkspaceProgramIndexError> {
        Ok(self
            .artifact(scope)?
            .topology
            .effect_marker_candidates(effect))
    }

    pub(crate) fn unsafe_marker_candidates(
        &self,
        scope: &ArtifactScopeId,
        operation: &UnsafeOperationKey,
    ) -> Result<&[super::topology::IndexedMarkerCandidate], WorkspaceProgramIndexError> {
        Ok(self
            .artifact(scope)?
            .topology
            .unsafe_marker_candidates(operation))
    }

    pub(crate) fn query(
        &self,
        workspace: &WorkspaceFactView<'_>,
        reachable_scopes: impl IntoIterator<Item = ArtifactScopeId>,
    ) -> Result<WorkspaceProgramQuery<'_>, WorkspaceProgramIndexError> {
        self.validate_workspace(workspace)?;
        let reachable_scopes = reachable_scopes.into_iter().collect::<BTreeSet<_>>();
        for scope in &reachable_scopes {
            self.artifact(scope)?;
        }
        Ok(WorkspaceProgramQuery {
            index: self,
            reachable_scopes,
        })
    }

    fn artifact(
        &self,
        scope: &ArtifactScopeId,
    ) -> Result<&ArtifactProgramIndex, WorkspaceProgramIndexError> {
        self.inner
            .artifacts
            .get(scope)
            .ok_or_else(|| WorkspaceProgramIndexError::UnknownScope {
                scope: scope.clone(),
            })
    }
}

/// A policy-neutral query restricted to caller-supplied reachable generations.
#[derive(Debug)]
pub(crate) struct WorkspaceProgramQuery<'a> {
    index: &'a WorkspaceProgramIndex,
    reachable_scopes: BTreeSet<ArtifactScopeId>,
}

impl WorkspaceProgramQuery<'_> {
    #[must_use]
    pub(crate) const fn index(&self) -> &WorkspaceProgramIndex {
        self.index
    }

    #[must_use]
    pub(crate) fn contains_scope(&self, scope: &ArtifactScopeId) -> bool {
        self.reachable_scopes.contains(scope)
    }

    /// Finds callable evidence only in the caller-supplied reachable scopes.
    pub(crate) fn callable_evidence_candidates(
        &self,
        invocation_scope: &ArtifactScopeId,
        invocation_key: &CallOccurrenceKey,
    ) -> Result<Vec<super::topology::CallableEvidenceCandidate>, WorkspaceProgramIndexError> {
        if !self.reachable_scopes.contains(invocation_scope) {
            return Err(WorkspaceProgramIndexError::InvalidQuery {
                reason: format!(
                    "callable invocation belongs to unreachable scope `{invocation_scope}`"
                ),
            });
        }
        let invocation_artifact = self.index.artifact(invocation_scope)?;
        let invocation_entity = invocation_artifact
            .occurrences
            .get(invocation_key)
            .ok_or_else(|| WorkspaceProgramIndexError::InvalidQuery {
                reason: format!(
                    "callable invocation {invocation_key:?} is unavailable in `{invocation_scope}`"
                ),
            })?;
        if !matches!(
            invocation_entity.data().kind(),
            CallKind::DirectCall | CallKind::TailCall | CallKind::IndirectCall
        ) {
            return Err(WorkspaceProgramIndexError::InvalidQuery {
                reason: format!(
                    "call occurrence {:?} is evidence, not a callable invocation",
                    invocation_entity.data().key()
                ),
            });
        }

        let mut candidates = BTreeSet::new();
        for key in invocation_artifact
            .topology
            .callable_keys(invocation_entity.data().key())
        {
            if let Some(records) = self.index.inner.callable_evidence.get(key) {
                for evidence in records {
                    if !self.reachable_scopes.contains(evidence.occurrence.scope()) {
                        continue;
                    }
                    candidates.insert(super::topology::CallableEvidenceCandidate::new(
                        invocation_entity.id(),
                        evidence,
                    ));
                }
            }
        }
        Ok(candidates.into_iter().collect())
    }
}

/// Structured failure to prepare or query typed workspace topology.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkspaceProgramIndexError {
    WorkspaceMismatch,
    InvalidScopeOwners {
        reason: String,
    },
    UnknownScope {
        scope: ArtifactScopeId,
    },
    InvalidWorkspace {
        scope: ArtifactScopeId,
        reason: String,
    },
    MalformedTopology {
        scope: ArtifactScopeId,
        schema: &'static str,
        reason: String,
    },
    InvalidQuery {
        reason: String,
    },
}

impl Display for WorkspaceProgramIndexError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceMismatch => {
                formatter.write_str("program index belongs to a replacement workspace view")
            }
            Self::InvalidScopeOwners { reason } => {
                write!(formatter, "invalid verified artifact owners: {reason}")
            }
            Self::UnknownScope { scope } => {
                write!(formatter, "program index has no artifact scope `{scope}`")
            }
            Self::InvalidWorkspace { scope, reason } => {
                write!(
                    formatter,
                    "artifact scope `{scope}` cannot be indexed: {reason}"
                )
            }
            Self::MalformedTopology {
                scope,
                schema,
                reason,
            } => write!(
                formatter,
                "artifact scope `{scope}` has malformed `{schema}` topology: {reason}"
            ),
            Self::InvalidQuery { reason } => write!(formatter, "invalid program query: {reason}"),
        }
    }
}

impl Error for WorkspaceProgramIndexError {}

fn require_table<S: RowSchema>(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
    expected: TableKind,
) -> Result<(), WorkspaceProgramIndexError> {
    let descriptor = view.registry().descriptor_for::<S>().map_err(|source| {
        WorkspaceProgramIndexError::InvalidWorkspace {
            scope: scope.clone(),
            reason: source.to_string(),
        }
    })?;
    if descriptor.kind() != expected {
        return Err(WorkspaceProgramIndexError::InvalidWorkspace {
            scope: scope.clone(),
            reason: format!(
                "schema `{}` is {:?}, expected {expected:?}",
                descriptor.id(),
                descriptor.kind()
            ),
        });
    }
    if view
        .artifact()
        .tables
        .binary_search_by(|table| table.schema.cmp(descriptor.id()))
        .is_err()
    {
        return Err(WorkspaceProgramIndexError::InvalidWorkspace {
            scope: scope.clone(),
            reason: format!("required table `{}` is absent", descriptor.id()),
        });
    }
    Ok(())
}

pub(super) fn load_relations<R: RelationSchema>(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
) -> Result<Vec<TypedRelation<R>>, WorkspaceProgramIndexError> {
    require_table::<R>(scope, view, TableKind::Relation)?;
    view.relations::<R>()
        .map_err(|source| view_error(scope, &source))
}

fn view_error(scope: &ArtifactScopeId, source: &ViewError) -> WorkspaceProgramIndexError {
    WorkspaceProgramIndexError::InvalidWorkspace {
        scope: scope.clone(),
        reason: source.to_string(),
    }
}

pub(super) fn malformed(
    scope: &ArtifactScopeId,
    schema: &'static str,
    reason: impl Into<String>,
) -> WorkspaceProgramIndexError {
    WorkspaceProgramIndexError::MalformedTopology {
        scope: scope.clone(),
        schema,
        reason: reason.into(),
    }
}
