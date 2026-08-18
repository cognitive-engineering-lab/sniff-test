//! Exact-generation lookup of permanent typed MIR assertions by effect site.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use super::super::encoded::TableKind;
use super::super::program::workspace_index::{WorkspaceProgramIndex, WorkspaceProgramIndexError};
use super::super::program::{EffectSiteEntity, FunctionEntity, FunctionKey};
use super::super::schema::{RowSchema, SchemaId};
use super::super::view::{ArtifactDbView, ViewError};
use super::super::workspace::{
    ArtifactScopeId, ScopedEntityId, ScopedEntityRef, ScopedRowRef, WorkspaceFactView,
    WorkspaceIdentity, WorkspaceViewError,
};
use super::model::MirAssertFact;

/// One permanent compiler assertion with exact artifact-scoped provenance.
#[derive(Clone, Debug)]
pub(crate) struct IndexedMirAssert {
    source: ScopedRowRef,
    data: MirAssertFact,
    owner: ScopedEntityId<EffectSiteEntity>,
    provenance: ScopedEntityId<FunctionEntity>,
    requirements: Vec<ScopedRowRef>,
}

impl IndexedMirAssert {
    #[must_use]
    pub(crate) const fn source(&self) -> &ScopedRowRef {
        &self.source
    }

    #[must_use]
    pub(crate) const fn data(&self) -> &MirAssertFact {
        &self.data
    }

    #[must_use]
    pub(crate) const fn owner(&self) -> &ScopedEntityId<EffectSiteEntity> {
        &self.owner
    }

    #[must_use]
    pub(crate) const fn provenance(&self) -> &ScopedEntityId<FunctionEntity> {
        &self.provenance
    }

    #[must_use]
    pub(crate) fn requirements(&self) -> &[ScopedRowRef] {
        &self.requirements
    }
}

/// Immutable exact-generation lookup prepared once for one workspace view.
#[derive(Clone, Debug)]
pub(crate) struct WorkspaceMirAssertIndex {
    workspace: Arc<WorkspaceIdentity>,
    by_effect: BTreeMap<ScopedEntityId<EffectSiteEntity>, IndexedMirAssert>,
}

impl WorkspaceMirAssertIndex {
    pub(crate) fn open(
        workspace: &WorkspaceFactView<'_>,
        program: &WorkspaceProgramIndex,
    ) -> Result<Self, WorkspaceMirAssertIndexError> {
        program
            .validate_workspace(workspace)
            .map_err(WorkspaceMirAssertIndexError::program)?;
        let mut by_effect = BTreeMap::new();
        for scope in workspace.scopes() {
            let view = workspace
                .artifact(scope)
                .map_err(WorkspaceMirAssertIndexError::workspace)?;
            require_assertion_table(scope, view)?;
            let assertions = view.facts::<MirAssertFact>().map_err(|source| {
                WorkspaceMirAssertIndexError::ReadAssertions {
                    scope: scope.clone(),
                    source: Box::new(source),
                }
            })?;
            for assertion in assertions {
                index_assertion(workspace, program, scope, assertion, &mut by_effect)?;
            }
        }
        Ok(Self {
            workspace: workspace.identity(),
            by_effect,
        })
    }

    pub(crate) fn validate_workspace(
        &self,
        workspace: &WorkspaceFactView<'_>,
    ) -> Result<(), WorkspaceMirAssertIndexError> {
        if workspace.has_identity(&self.workspace) {
            Ok(())
        } else {
            Err(WorkspaceMirAssertIndexError::WorkspaceMismatch)
        }
    }

    pub(crate) fn assertion_for_effect(
        &self,
        workspace: &WorkspaceFactView<'_>,
        effect: &ScopedEntityId<EffectSiteEntity>,
    ) -> Result<Option<&IndexedMirAssert>, WorkspaceMirAssertIndexError> {
        self.validate_workspace(workspace)?;
        workspace
            .entity::<EffectSiteEntity>(&effect.erase())
            .map_err(WorkspaceMirAssertIndexError::workspace)?;
        Ok(self.by_effect.get(effect))
    }
}

fn require_assertion_table(
    scope: &ArtifactScopeId,
    view: ArtifactDbView<'_>,
) -> Result<(), WorkspaceMirAssertIndexError> {
    let schema =
        SchemaId::new(MirAssertFact::ID).expect("the built-in MIR assertion schema ID is valid");
    let descriptor = view.registry().descriptor(&schema).ok_or_else(|| {
        WorkspaceMirAssertIndexError::AssertionSchemaUnavailable {
            scope: scope.clone(),
        }
    })?;
    if descriptor.kind() != TableKind::Fact {
        return Err(WorkspaceMirAssertIndexError::InvalidAssertionTableKind {
            scope: scope.clone(),
            found: descriptor.kind(),
        });
    }
    if view
        .artifact()
        .tables
        .binary_search_by(|table| table.schema.cmp(&schema))
        .is_err()
    {
        return Err(WorkspaceMirAssertIndexError::MissingAssertionTable {
            scope: scope.clone(),
        });
    }
    Ok(())
}

fn index_assertion(
    workspace: &WorkspaceFactView<'_>,
    program: &WorkspaceProgramIndex,
    scope: &ArtifactScopeId,
    assertion: super::super::view::TypedFact<MirAssertFact>,
    by_effect: &mut BTreeMap<ScopedEntityId<EffectSiteEntity>, IndexedMirAssert>,
) -> Result<(), WorkspaceMirAssertIndexError> {
    let source = ScopedRowRef::new(scope.clone(), assertion.fact.reference);
    let owner = assertion
        .metadata
        .owner
        .map(|owner| ScopedEntityRef::new(scope.clone(), owner))
        .ok_or_else(|| WorkspaceMirAssertIndexError::MissingOwner {
            assertion: source.clone(),
        })?;
    let effect = workspace
        .entity::<EffectSiteEntity>(&owner)
        .map_err(|error| WorkspaceMirAssertIndexError::InvalidOwner {
            assertion: source.clone(),
            owner: Box::new(owner.clone()),
            source: Box::new(error),
        })?;
    let indexed_effect = program
        .exact_effect_site(scope, effect.site())
        .filter(|indexed| indexed.reference() == &owner)
        .ok_or_else(|| WorkspaceMirAssertIndexError::OwnerNotIndexed {
            assertion: source.clone(),
            owner: Box::new(owner.clone()),
        })?;
    let owner = indexed_effect.id();

    let provenance = assertion
        .metadata
        .provenance_root
        .map(|root| ScopedEntityRef::new(scope.clone(), root))
        .ok_or_else(|| WorkspaceMirAssertIndexError::MissingProvenance {
            assertion: source.clone(),
        })?;
    let function = workspace
        .entity::<FunctionEntity>(&provenance)
        .map_err(|error| WorkspaceMirAssertIndexError::InvalidProvenance {
            assertion: source.clone(),
            provenance: Box::new(provenance.clone()),
            source: Box::new(error),
        })?;
    let indexed_function = program
        .exact_function(scope, function.key())
        .filter(|indexed| indexed.reference() == &provenance)
        .ok_or_else(|| WorkspaceMirAssertIndexError::ProvenanceNotIndexed {
            assertion: source.clone(),
            provenance: Box::new(provenance.clone()),
        })?;
    if effect.site().function() != function.key() {
        return Err(WorkspaceMirAssertIndexError::FunctionMismatch {
            assertion: source,
            effect_function: Box::new(*effect.site().function()),
            provenance_function: Box::new(*function.key()),
        });
    }
    let provenance = indexed_function.id();
    let ownership_edges = program
        .effect_site_edges_owned_by(scope, function.key())
        .map_err(WorkspaceMirAssertIndexError::program)?;
    let ownership_exists = ownership_edges
        .binary_search_by_key(
            effect.site(),
            super::super::program::workspace_index::IndexedEffectSite::site,
        )
        .is_ok_and(|position| ownership_edges[position].effect() == &owner);
    if !ownership_exists {
        return Err(WorkspaceMirAssertIndexError::OwnershipMismatch {
            assertion: source,
            owner: Box::new(owner),
            provenance: Box::new(provenance),
        });
    }
    let requirements =
        validate_requirements(workspace, &source, scope, assertion.metadata.requirements)?;
    if let Some(first) = by_effect.get(&owner) {
        return Err(WorkspaceMirAssertIndexError::DuplicateOwner {
            owner: Box::new(owner),
            first: first.source.clone(),
            duplicate: source,
        });
    }
    by_effect.insert(
        owner.clone(),
        IndexedMirAssert {
            source,
            data: assertion.fact.data,
            owner,
            provenance,
            requirements,
        },
    );
    Ok(())
}

fn validate_requirements(
    workspace: &WorkspaceFactView<'_>,
    assertion: &ScopedRowRef,
    scope: &ArtifactScopeId,
    requirements: Vec<super::super::encoded::RowRef>,
) -> Result<Vec<ScopedRowRef>, WorkspaceMirAssertIndexError> {
    if requirements.is_empty() {
        return Err(WorkspaceMirAssertIndexError::MissingRequirements {
            assertion: assertion.clone(),
        });
    }
    let mut unique = BTreeSet::new();
    let mut scoped = Vec::with_capacity(requirements.len());
    for requirement in requirements {
        let requirement = ScopedRowRef::new(scope.clone(), requirement);
        if !unique.insert(requirement.clone()) {
            return Err(WorkspaceMirAssertIndexError::DuplicateRequirement {
                assertion: assertion.clone(),
                requirement,
            });
        }
        workspace
            .validate_erased_row(&requirement, Some(TableKind::Requirement))
            .map_err(|error| WorkspaceMirAssertIndexError::InvalidRequirement {
                assertion: assertion.clone(),
                requirement: requirement.clone(),
                source: Box::new(error),
            })?;
        scoped.push(requirement);
    }
    Ok(scoped)
}

/// Structured failure while preparing permanent compiler-assert lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkspaceMirAssertIndexError {
    WorkspaceMismatch,
    AssertionSchemaUnavailable {
        scope: ArtifactScopeId,
    },
    InvalidAssertionTableKind {
        scope: ArtifactScopeId,
        found: TableKind,
    },
    MissingAssertionTable {
        scope: ArtifactScopeId,
    },
    Program {
        source: Box<WorkspaceProgramIndexError>,
    },
    Workspace {
        source: Box<WorkspaceViewError>,
    },
    ReadAssertions {
        scope: ArtifactScopeId,
        source: Box<ViewError>,
    },
    MissingOwner {
        assertion: ScopedRowRef,
    },
    InvalidOwner {
        assertion: ScopedRowRef,
        owner: Box<ScopedEntityRef>,
        source: Box<WorkspaceViewError>,
    },
    OwnerNotIndexed {
        assertion: ScopedRowRef,
        owner: Box<ScopedEntityRef>,
    },
    MissingProvenance {
        assertion: ScopedRowRef,
    },
    InvalidProvenance {
        assertion: ScopedRowRef,
        provenance: Box<ScopedEntityRef>,
        source: Box<WorkspaceViewError>,
    },
    ProvenanceNotIndexed {
        assertion: ScopedRowRef,
        provenance: Box<ScopedEntityRef>,
    },
    FunctionMismatch {
        assertion: ScopedRowRef,
        effect_function: Box<FunctionKey>,
        provenance_function: Box<FunctionKey>,
    },
    OwnershipMismatch {
        assertion: ScopedRowRef,
        owner: Box<ScopedEntityId<EffectSiteEntity>>,
        provenance: Box<ScopedEntityId<FunctionEntity>>,
    },
    MissingRequirements {
        assertion: ScopedRowRef,
    },
    DuplicateRequirement {
        assertion: ScopedRowRef,
        requirement: ScopedRowRef,
    },
    InvalidRequirement {
        assertion: ScopedRowRef,
        requirement: ScopedRowRef,
        source: Box<WorkspaceViewError>,
    },
    DuplicateOwner {
        owner: Box<ScopedEntityId<EffectSiteEntity>>,
        first: ScopedRowRef,
        duplicate: ScopedRowRef,
    },
}

impl WorkspaceMirAssertIndexError {
    fn program(source: WorkspaceProgramIndexError) -> Self {
        Self::Program {
            source: Box::new(source),
        }
    }

    fn workspace(source: WorkspaceViewError) -> Self {
        Self::Workspace {
            source: Box::new(source),
        }
    }
}

impl Display for WorkspaceMirAssertIndexError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceMismatch => {
                formatter.write_str("MIR assertion index belongs to a replacement workspace view")
            }
            Self::AssertionSchemaUnavailable { scope } => write!(
                formatter,
                "artifact scope `{scope}` has no registered MIR assertion schema"
            ),
            Self::InvalidAssertionTableKind { scope, found } => write!(
                formatter,
                "artifact scope `{scope}` registers MIR assertions as {found:?}, expected Fact"
            ),
            Self::MissingAssertionTable { scope } => write!(
                formatter,
                "artifact scope `{scope}` is missing its MIR assertion producer table"
            ),
            Self::Program { .. } => formatter.write_str("permanent program index is invalid"),
            Self::Workspace { .. } => formatter.write_str("workspace artifact lookup failed"),
            Self::ReadAssertions { scope, .. } => {
                write!(
                    formatter,
                    "cannot read MIR assertions in artifact scope `{scope}`"
                )
            }
            Self::MissingOwner { assertion } => {
                write!(
                    formatter,
                    "MIR assertion {assertion:?} has no effect-site owner"
                )
            }
            Self::InvalidOwner { assertion, .. } => {
                write!(
                    formatter,
                    "MIR assertion {assertion:?} has an invalid effect-site owner"
                )
            }
            Self::OwnerNotIndexed { assertion, .. } => write!(
                formatter,
                "MIR assertion {assertion:?} owner is absent from the permanent program index"
            ),
            Self::MissingProvenance { assertion } => write!(
                formatter,
                "MIR assertion {assertion:?} has no function provenance root"
            ),
            Self::InvalidProvenance { assertion, .. } => write!(
                formatter,
                "MIR assertion {assertion:?} has an invalid function provenance root"
            ),
            Self::ProvenanceNotIndexed { assertion, .. } => write!(
                formatter,
                "MIR assertion {assertion:?} provenance is absent from the permanent program index"
            ),
            Self::FunctionMismatch { assertion, .. } => write!(
                formatter,
                "MIR assertion {assertion:?} owner and provenance identify different functions"
            ),
            Self::OwnershipMismatch { assertion, .. } => write!(
                formatter,
                "MIR assertion {assertion:?} owner is not owned by its provenance function"
            ),
            Self::MissingRequirements { assertion } => write!(
                formatter,
                "MIR assertion {assertion:?} has no attached requirement"
            ),
            Self::DuplicateRequirement { assertion, .. } => write!(
                formatter,
                "MIR assertion {assertion:?} repeats one attached requirement"
            ),
            Self::InvalidRequirement { assertion, .. } => write!(
                formatter,
                "MIR assertion {assertion:?} has an invalid attached requirement"
            ),
            Self::DuplicateOwner { owner, .. } => {
                write!(
                    formatter,
                    "effect site {owner:?} owns multiple MIR assertions"
                )
            }
        }
    }
}

impl Error for WorkspaceMirAssertIndexError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Program { source } => Some(source.as_ref()),
            Self::Workspace { source }
            | Self::InvalidOwner { source, .. }
            | Self::InvalidProvenance { source, .. }
            | Self::InvalidRequirement { source, .. } => Some(source.as_ref()),
            Self::ReadAssertions { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use reachability::MirBodyLocation;

    use super::{WorkspaceMirAssertIndex, WorkspaceMirAssertIndexError};
    use crate::analysis::facts::builder::{ArtifactDbBuilder, FactMeta};
    use crate::analysis::facts::collection::CollectedArtifactSchemaPack;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::panic::model::{MirAssertFact, MirAssertKind, NonZeroRequirement};
    use crate::analysis::facts::program::topology::{CallableEntity, FunctionDefinesCallable};
    use crate::analysis::facts::program::workspace_index::{
        VerifiedArtifactOwner, WorkspaceProgramIndex,
    };
    use crate::analysis::facts::program::{
        EffectSiteEntity, EffectSiteKey, FunctionBodyProvenance, FunctionEntity, FunctionKey,
        FunctionOwnsEffectSite,
    };
    use crate::analysis::facts::schema::{PassId, RowSchema, SchemaId};
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::analysis::facts::workspace::{ArtifactScopeId, WorkspaceFactView};
    use crate::namespace::StableDefPathHash;

    fn function(stable_crate_id: u64, local: u64) -> FunctionKey {
        let definition = serde_json::from_str::<StableDefPathHash>(&format!(
            "\"{stable_crate_id:016x}{local:016x}\""
        ))
        .unwrap();
        FunctionKey::new(definition, None)
    }

    fn artifact(
        registry: &AnalysisRegistry<()>,
        stable_crate_id: u64,
        assertions: &[MirAssertKind],
    ) -> (
        crate::analysis::facts::encoded::ArtifactFactIr,
        EffectSiteKey,
    ) {
        let function_key = function(stable_crate_id, 1);
        let effect_key = EffectSiteKey::from_mir(
            function_key,
            MirBodyLocation {
                basic_block: 2,
                statement_index: 3,
            },
        )
        .unwrap();
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        let body = builder
            .insert_entity(&FunctionEntity::new(
                function_key,
                "crate::assertion_owner",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let callable = builder
            .insert_entity(&CallableEntity::new(
                function_key,
                "crate::assertion_owner",
                false,
                false,
                true,
                false,
                vec![String::from("crate::assertion_owner")],
            ))
            .unwrap();
        builder
            .relate(&body, &callable, &FunctionDefinesCallable::new())
            .unwrap();
        let effect = builder
            .insert_entity(&EffectSiteEntity::new(effect_key))
            .unwrap();
        builder
            .relate(&body, &effect, &FunctionOwnsEffectSite::new())
            .unwrap();
        let other_key = function(stable_crate_id, 2);
        let other_function = builder
            .insert_entity(&FunctionEntity::new(
                other_key,
                "crate::other",
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let other_callable = builder
            .insert_entity(&CallableEntity::new(
                other_key,
                "crate::other",
                false,
                false,
                true,
                false,
                vec![String::from("crate::other")],
            ))
            .unwrap();
        builder
            .relate(
                &other_function,
                &other_callable,
                &FunctionDefinesCallable::new(),
            )
            .unwrap();
        if !assertions.is_empty() {
            let requirement = builder
                .insert_requirement(&NonZeroRequirement::new())
                .unwrap();
            for kind in assertions {
                let metadata = FactMeta::new(PassId::new("test.panic.assertion-index").unwrap())
                    .with_owner(&effect)
                    .unwrap()
                    .with_provenance_root(&body)
                    .unwrap()
                    .with_requirement(&requirement)
                    .unwrap();
                builder
                    .insert_fact(&MirAssertFact::new(*kind), metadata)
                    .unwrap();
            }
        }
        (builder.finalize(registry.schemas()).unwrap(), effect_key)
    }

    fn assertion_metadata_mut(
        artifact: &mut crate::analysis::facts::encoded::ArtifactFactIr,
    ) -> &mut crate::analysis::facts::encoded::FactIndexRow {
        artifact
            .fact_index
            .iter_mut()
            .find(|metadata| metadata.fact.schema.as_str() == MirAssertFact::ID)
            .expect("fixture contains one MIR assertion")
    }

    fn index_artifact(
        artifact: &crate::analysis::facts::encoded::ArtifactFactIr,
        registry: &AnalysisRegistry<()>,
        stable_crate_id: u64,
    ) -> Result<WorkspaceMirAssertIndex, WorkspaceMirAssertIndexError> {
        let scope = ArtifactScopeId::for_in_memory(stable_crate_id, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program = WorkspaceProgramIndex::open(
            &workspace,
            [VerifiedArtifactOwner::new(scope, stable_crate_id)],
        )
        .unwrap();
        WorkspaceMirAssertIndex::open(&workspace, &program)
    }

    #[test]
    fn indexes_local_and_dependency_assertions_with_exact_metadata() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let (local_artifact, local_effect) =
            artifact(&registry, 1, &[MirAssertKind::DivisionByZero]);
        let (dependency_artifact, dependency_effect) =
            artifact(&registry, 2, &[MirAssertKind::RemainderByZero]);
        let local = ArtifactScopeId::for_in_memory(1, 0);
        let dependency = ArtifactScopeId::for_in_memory(2, 0);
        let workspace = WorkspaceFactView::compose([
            (
                local.clone(),
                ArtifactDbView::open(&local_artifact, registry.schemas()).unwrap(),
            ),
            (
                dependency.clone(),
                ArtifactDbView::open(&dependency_artifact, registry.schemas()).unwrap(),
            ),
        ])
        .unwrap();
        let program = WorkspaceProgramIndex::open(
            &workspace,
            [
                VerifiedArtifactOwner::new(local.clone(), 1),
                VerifiedArtifactOwner::new(dependency.clone(), 2),
            ],
        )
        .unwrap();

        let assertions = WorkspaceMirAssertIndex::open(&workspace, &program).unwrap();
        let local_effect = program
            .exact_effect_site(&local, &local_effect)
            .unwrap()
            .id();
        let dependency_effect = program
            .exact_effect_site(&dependency, &dependency_effect)
            .unwrap()
            .id();
        let local_assertion = assertions
            .assertion_for_effect(&workspace, &local_effect)
            .unwrap()
            .unwrap();
        assert_eq!(local_assertion.data().kind(), MirAssertKind::DivisionByZero);
        assert_eq!(local_assertion.source().scope(), &local);
        assert_eq!(
            local_assertion.source().row().schema.as_str(),
            MirAssertFact::ID
        );
        assert_eq!(local_assertion.owner(), &local_effect);
        assert_eq!(
            local_assertion.provenance(),
            &program
                .exact_function(&local, &function(1, 1))
                .unwrap()
                .id()
        );
        assert_eq!(local_assertion.requirements().len(), 1);
        assert_eq!(
            local_assertion.requirements()[0].row().schema.as_str(),
            NonZeroRequirement::ID
        );
        assert_eq!(
            assertions
                .assertion_for_effect(&workspace, &dependency_effect)
                .unwrap()
                .unwrap()
                .data()
                .kind(),
            MirAssertKind::RemainderByZero
        );
    }

    #[test]
    fn effect_without_assertion_returns_none() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let (artifact, effect) = artifact(&registry, 3, &[]);
        let scope = ArtifactScopeId::for_in_memory(3, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 3)])
                .unwrap();
        let assertions = WorkspaceMirAssertIndex::open(&workspace, &program).unwrap();
        let effect = program.exact_effect_site(&scope, &effect).unwrap().id();

        assert!(
            assertions
                .assertion_for_effect(&workspace, &effect)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn duplicate_assertions_for_one_effect_are_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let (artifact, _) = artifact(
            &registry,
            4,
            &[
                MirAssertKind::DivisionByZero,
                MirAssertKind::RemainderByZero,
            ],
        );
        let scope = ArtifactScopeId::for_in_memory(4, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope, 4)])
                .unwrap();

        assert!(matches!(
            WorkspaceMirAssertIndex::open(&workspace, &program),
            Err(WorkspaceMirAssertIndexError::DuplicateOwner { .. })
        ));
    }

    #[test]
    fn replacement_workspace_is_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let (artifact, effect) = artifact(&registry, 5, &[MirAssertKind::DivisionByZero]);
        let scope = ArtifactScopeId::for_in_memory(5, 0);
        let view = ArtifactDbView::open(&artifact, registry.schemas()).unwrap();
        let workspace = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
        let replacement = WorkspaceFactView::compose([(scope.clone(), view)]).unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 5)])
                .unwrap();
        let assertions = WorkspaceMirAssertIndex::open(&workspace, &program).unwrap();

        assert!(matches!(
            assertions.validate_workspace(&replacement),
            Err(WorkspaceMirAssertIndexError::WorkspaceMismatch)
        ));
        assert!(matches!(
            WorkspaceMirAssertIndex::open(&replacement, &program),
            Err(WorkspaceMirAssertIndexError::Program { .. })
        ));
        let replacement_effect = replacement
            .entity_id_by_key::<EffectSiteEntity>(&scope, &effect)
            .unwrap()
            .unwrap();
        assert!(matches!(
            assertions.assertion_for_effect(&replacement, &replacement_effect),
            Err(WorkspaceMirAssertIndexError::WorkspaceMismatch)
        ));
    }

    #[test]
    fn missing_dangling_and_non_effect_owners_are_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();

        let (mut missing, _) = artifact(&registry, 6, &[MirAssertKind::DivisionByZero]);
        assertion_metadata_mut(&mut missing).owner = None;
        assert!(matches!(
            index_artifact(&missing, &registry, 6),
            Err(WorkspaceMirAssertIndexError::MissingOwner { .. })
        ));

        let (dangling, _) = artifact(&registry, 7, &[MirAssertKind::DivisionByZero]);
        let scope = ArtifactScopeId::for_in_memory(7, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&dangling, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program =
            WorkspaceProgramIndex::open(&workspace, [VerifiedArtifactOwner::new(scope.clone(), 7)])
                .unwrap();
        let mut assertion = workspace
            .artifact(&scope)
            .unwrap()
            .facts::<MirAssertFact>()
            .unwrap()
            .pop()
            .unwrap();
        let owner = assertion.metadata.owner.as_mut().unwrap();
        owner.row = u32::MAX;
        assert!(matches!(
            super::index_assertion(
                &workspace,
                &program,
                &scope,
                assertion,
                &mut std::collections::BTreeMap::new(),
            ),
            Err(WorkspaceMirAssertIndexError::InvalidOwner { .. })
        ));

        let (mut non_effect, _) = artifact(&registry, 8, &[MirAssertKind::DivisionByZero]);
        let view = ArtifactDbView::open(&non_effect, registry.schemas()).unwrap();
        let function = view
            .entity_id_by_key::<FunctionEntity>(&function(8, 1))
            .unwrap()
            .unwrap()
            .erase();
        assertion_metadata_mut(&mut non_effect).owner = Some(function);
        assert!(matches!(
            index_artifact(&non_effect, &registry, 8),
            Err(WorkspaceMirAssertIndexError::InvalidOwner { .. })
        ));
    }

    #[test]
    fn missing_dangling_non_function_and_mismatched_provenance_are_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();

        let (mut missing, _) = artifact(&registry, 9, &[MirAssertKind::DivisionByZero]);
        assertion_metadata_mut(&mut missing).provenance_root = None;
        assert!(matches!(
            index_artifact(&missing, &registry, 9),
            Err(WorkspaceMirAssertIndexError::MissingProvenance { .. })
        ));

        let (wrong, _) = artifact(&registry, 10, &[MirAssertKind::DivisionByZero]);
        let scope = ArtifactScopeId::for_in_memory(10, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&wrong, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let program = WorkspaceProgramIndex::open(
            &workspace,
            [VerifiedArtifactOwner::new(scope.clone(), 10)],
        )
        .unwrap();
        let mut assertion = workspace
            .artifact(&scope)
            .unwrap()
            .facts::<MirAssertFact>()
            .unwrap()
            .pop()
            .unwrap();
        let provenance = assertion.metadata.provenance_root.as_mut().unwrap();
        provenance.row = u32::MAX;
        assert!(matches!(
            super::index_assertion(
                &workspace,
                &program,
                &scope,
                assertion,
                &mut std::collections::BTreeMap::new(),
            ),
            Err(WorkspaceMirAssertIndexError::InvalidProvenance { .. })
        ));

        let (mut non_function, _) = artifact(&registry, 14, &[MirAssertKind::DivisionByZero]);
        let effect = assertion_metadata_mut(&mut non_function)
            .owner
            .clone()
            .unwrap();
        assertion_metadata_mut(&mut non_function).provenance_root = Some(effect);
        assert!(matches!(
            index_artifact(&non_function, &registry, 14),
            Err(WorkspaceMirAssertIndexError::InvalidProvenance { .. })
        ));

        let (mut mismatched, _) = artifact(&registry, 11, &[MirAssertKind::DivisionByZero]);
        let view = ArtifactDbView::open(&mismatched, registry.schemas()).unwrap();
        let other_function = view
            .entity_id_by_key::<FunctionEntity>(&function(11, 2))
            .unwrap()
            .unwrap()
            .erase();
        assertion_metadata_mut(&mut mismatched).provenance_root = Some(other_function);
        assert!(matches!(
            index_artifact(&mismatched, &registry, 11),
            Err(WorkspaceMirAssertIndexError::FunctionMismatch { .. })
        ));
    }

    #[test]
    fn empty_requirement_metadata_is_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let (mut artifact, _) = artifact(&registry, 12, &[MirAssertKind::DivisionByZero]);
        assertion_metadata_mut(&mut artifact).requirements.clear();

        assert!(matches!(
            index_artifact(&artifact, &registry, 12),
            Err(WorkspaceMirAssertIndexError::MissingRequirements { .. })
        ));
    }

    #[test]
    fn missing_assertion_table_is_not_treated_as_present_empty() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let (mut artifact, _) = artifact(&registry, 15, &[MirAssertKind::DivisionByZero]);
        artifact
            .tables
            .retain(|table| table.schema.as_str() != MirAssertFact::ID);
        artifact
            .fact_index
            .retain(|metadata| metadata.fact.schema.as_str() != MirAssertFact::ID);

        assert!(matches!(
            index_artifact(&artifact, &registry, 15),
            Err(WorkspaceMirAssertIndexError::MissingAssertionTable { .. })
        ));
    }

    #[test]
    fn duplicate_dangling_and_wrong_kind_requirements_are_rejected() {
        let mut registry = AnalysisRegistry::<()>::new();
        registry.install(&CollectedArtifactSchemaPack).unwrap();
        let (artifact, _) = artifact(&registry, 13, &[MirAssertKind::DivisionByZero]);
        let scope = ArtifactScopeId::for_in_memory(13, 0);
        let workspace = WorkspaceFactView::compose([(
            scope.clone(),
            ArtifactDbView::open(&artifact, registry.schemas()).unwrap(),
        )])
        .unwrap();
        let metadata = artifact
            .fact_index
            .iter()
            .find(|metadata| metadata.fact.schema.as_str() == MirAssertFact::ID)
            .unwrap();
        let assertion = crate::analysis::facts::workspace::ScopedRowRef::new(
            scope.clone(),
            metadata.fact.clone(),
        );
        let requirement = metadata.requirements[0].clone();

        assert!(matches!(
            super::validate_requirements(
                &workspace,
                &assertion,
                &scope,
                vec![requirement.clone(), requirement.clone()],
            ),
            Err(WorkspaceMirAssertIndexError::DuplicateRequirement { .. })
        ));
        let mut dangling = requirement;
        dangling.row = u32::MAX;
        assert!(matches!(
            super::validate_requirements(&workspace, &assertion, &scope, vec![dangling]),
            Err(WorkspaceMirAssertIndexError::InvalidRequirement { .. })
        ));
        let wrong_kind = crate::analysis::facts::encoded::RowRef {
            schema: SchemaId::new(MirAssertFact::ID).unwrap(),
            row: 0,
        };
        assert!(matches!(
            super::validate_requirements(&workspace, &assertion, &scope, vec![wrong_kind]),
            Err(WorkspaceMirAssertIndexError::InvalidRequirement { .. })
        ));
    }
}
