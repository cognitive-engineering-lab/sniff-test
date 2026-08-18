//! Exact-generation authority for a complete managed typed workspace.
//!
//! The compiler-assert driver uses this boundary to bind cache-envelope
//! identities to typed fact views. It never accepts legacy IR or parsed scope
//! strings as authority.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

#[cfg(test)]
use std::cell::Cell;

use super::cache::RustcArtifactId;
use super::facts::program::root_traversal::{
    DefiningScopeAuthority, DefiningScopeMapError, StableCrateResolution, VerifiedDefiningScopeMap,
};
use super::facts::program::workspace_index::{
    VerifiedArtifactOwner, WorkspaceProgramIndex, WorkspaceProgramIndexError,
};
use super::facts::workspace::{ArtifactScopeId, ArtifactScopeIdError, WorkspaceFactView};

/// Exact generation of one managed artifact in the typed closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ManagedArtifactGeneration {
    Persisted(RustcArtifactId),
    InMemory { stable_crate_id: u64, ordinal: u32 },
}

impl ManagedArtifactGeneration {
    #[must_use]
    pub(crate) fn persisted(artifact: RustcArtifactId) -> Self {
        Self::Persisted(artifact)
    }

    #[must_use]
    pub(crate) const fn in_memory(stable_crate_id: u64, ordinal: u32) -> Self {
        Self::InMemory {
            stable_crate_id,
            ordinal,
        }
    }

    #[must_use]
    pub(crate) const fn stable_crate_id(&self) -> u64 {
        match self {
            Self::Persisted(artifact) => artifact.stable_crate_id,
            Self::InMemory {
                stable_crate_id, ..
            } => *stable_crate_id,
        }
    }

    pub(crate) fn scope(&self) -> Result<ArtifactScopeId, ArtifactScopeIdError> {
        match self {
            Self::Persisted(artifact) => {
                ArtifactScopeId::for_persisted(artifact.stable_crate_id, artifact.svh.clone())
            }
            Self::InMemory {
                stable_crate_id,
                ordinal,
            } => Ok(ArtifactScopeId::for_in_memory(*stable_crate_id, *ordinal)),
        }
    }
}

/// One managed generation and its direct exact persisted dependency identities.
///
/// Dependency edges are deliberately persisted rustc identities even when the
/// owning generation is in-memory. The current compiler/cache boundary does
/// not support one in-memory generation depending on another in-memory one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManagedArtifactManifest {
    generation: ManagedArtifactGeneration,
    dependencies: Vec<RustcArtifactId>,
}

/// Exact contextual classification retained beside the traversal authority map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum VerifiedDefinitionResolution {
    Managed(ArtifactScopeId),
    Unmanaged(RustcArtifactId),
}

type ContextualDefinitionMap = BTreeMap<(ArtifactScopeId, u64), VerifiedDefinitionResolution>;

#[derive(Default)]
struct ContextualAuthorityInventory {
    managed_scopes: BTreeMap<u64, Vec<ArtifactScopeId>>,
    unmanaged_generations: BTreeMap<u64, Vec<RustcArtifactId>>,
}

struct AuthorityInventories {
    by_preferred_scope: BTreeMap<ArtifactScopeId, ContextualAuthorityInventory>,
    all_managed_scopes: BTreeMap<u64, Vec<ArtifactScopeId>>,
}

/// Canonical exact-generation dependency graph shared by reachability and
/// contextual authority preparation.
///
/// Construction is `O((V + E) log V)`. Authority preparation later adds
/// `O((R + P) log V)`, where `R` is the typed request count and `P` is the
/// materialized candidate-to-context propagation output. No preferred scope
/// launches its own graph traversal.
struct ManagedDependencyGraph {
    forward: BTreeMap<ArtifactScopeId, Vec<ArtifactScopeId>>,
    reverse: BTreeMap<ArtifactScopeId, Vec<ArtifactScopeId>>,
    unmanaged_by_owner: BTreeMap<ArtifactScopeId, Vec<RustcArtifactId>>,
}

struct PreparedClosureInput {
    root_scope: ArtifactScopeId,
    managed: BTreeMap<ArtifactScopeId, ManagedArtifactManifest>,
    #[cfg(test)]
    owners: Vec<VerifiedArtifactOwner>,
    reachable: BTreeSet<ArtifactScopeId>,
    graph: ManagedDependencyGraph,
}

struct PreparedManagedInput {
    root_scope: ArtifactScopeId,
    managed: BTreeMap<ArtifactScopeId, ManagedArtifactManifest>,
    owners: Vec<VerifiedArtifactOwner>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ReachabilityMetrics {
    traversals: usize,
    dependency_edges_examined: usize,
    authority_candidates_propagated: usize,
    authority_edges_examined: usize,
}

#[cfg(test)]
thread_local! {
    static REACHABILITY_METRICS: Cell<ReachabilityMetrics> = const {
        Cell::new(ReachabilityMetrics {
            traversals: 0,
            dependency_edges_examined: 0,
            authority_candidates_propagated: 0,
            authority_edges_examined: 0,
        })
    };
}

#[cfg(test)]
fn reset_reachability_metrics() {
    REACHABILITY_METRICS.set(ReachabilityMetrics::default());
}

#[cfg(test)]
fn reachability_metrics() -> ReachabilityMetrics {
    REACHABILITY_METRICS.get()
}

#[cfg(test)]
fn record_reachability_traversal() {
    REACHABILITY_METRICS.with(|cell| {
        let mut metrics = cell.get();
        metrics.traversals += 1;
        cell.set(metrics);
    });
}

#[cfg(test)]
fn record_dependency_edge_examined() {
    REACHABILITY_METRICS.with(|cell| {
        let mut metrics = cell.get();
        metrics.dependency_edges_examined += 1;
        cell.set(metrics);
    });
}

#[cfg(test)]
fn record_authority_candidate_propagated() {
    REACHABILITY_METRICS.with(|cell| {
        let mut metrics = cell.get();
        metrics.authority_candidates_propagated += 1;
        cell.set(metrics);
    });
}

#[cfg(test)]
fn record_authority_edge_examined() {
    REACHABILITY_METRICS.with(|cell| {
        let mut metrics = cell.get();
        metrics.authority_edges_examined += 1;
        cell.set(metrics);
    });
}

impl ManagedArtifactManifest {
    #[must_use]
    pub(crate) fn new(
        generation: ManagedArtifactGeneration,
        dependencies: Vec<RustcArtifactId>,
    ) -> Self {
        Self {
            generation,
            dependencies,
        }
    }
}

/// Workspace-branded ownership and defining-scope authority prepared together.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedWorkspaceClosure {
    root_scope: ArtifactScopeId,
    #[cfg(test)]
    owners: Vec<VerifiedArtifactOwner>,
    program: WorkspaceProgramIndex,
    defining_scopes: Arc<VerifiedDefiningScopeMap>,
    #[cfg(test)]
    definition_resolutions: ContextualDefinitionMap,
}

impl VerifiedWorkspaceClosure {
    #[cfg(test)]
    pub(crate) fn open(
        workspace: &WorkspaceFactView<'_>,
        root: ManagedArtifactManifest,
        managed_dependencies: impl IntoIterator<Item = ManagedArtifactManifest>,
        unmanaged: impl IntoIterator<Item = RustcArtifactId>,
    ) -> Result<Self, VerifiedWorkspaceClosureError> {
        let prepared = prepare_closure_input(workspace, root, managed_dependencies, unmanaged)?;
        let program = WorkspaceProgramIndex::open(workspace, prepared.owners.clone())
            .map_err(VerifiedWorkspaceClosureError::ProgramIndex)?;
        Self::from_prepared(workspace, prepared, program)
    }

    /// Opens an exact managed workspace and derives only the unmanaged runtime
    /// edges required by authority-relevant typed rows.
    ///
    /// Managed cache manifests remain authoritative for managed reachability.
    /// The active runtime inventory is consulted only for stable crate IDs
    /// referenced by typed facts and absent from every managed generation.
    pub(crate) fn open_with_runtime_inventory(
        workspace: &WorkspaceFactView<'_>,
        root: ManagedArtifactManifest,
        managed_dependencies: impl IntoIterator<Item = ManagedArtifactManifest>,
        active_runtime_artifacts: impl IntoIterator<Item = RustcArtifactId>,
    ) -> Result<Self, VerifiedWorkspaceClosureError> {
        let prepared = prepare_managed_input(root, managed_dependencies)?;
        validate_workspace_scope_set(workspace, &prepared.managed)?;
        let program = WorkspaceProgramIndex::open(workspace, prepared.owners.clone())
            .map_err(VerifiedWorkspaceClosureError::ProgramIndex)?;
        let prepared =
            complete_from_runtime_inventory(prepared, &program, active_runtime_artifacts)?;
        Self::from_prepared(workspace, prepared, program)
    }

    fn from_prepared(
        workspace: &WorkspaceFactView<'_>,
        prepared: PreparedClosureInput,
        program: WorkspaceProgramIndex,
    ) -> Result<Self, VerifiedWorkspaceClosureError> {
        let (authorities, definition_resolutions) =
            prepare_definition_authorities(&prepared, &program)?;
        #[cfg(not(test))]
        let _ = definition_resolutions;
        let defining_scopes = Arc::new(
            VerifiedDefiningScopeMap::new(workspace, &program, authorities)
                .map_err(VerifiedWorkspaceClosureError::DefiningScopes)?,
        );

        Ok(Self {
            root_scope: prepared.root_scope,
            #[cfg(test)]
            owners: prepared.owners,
            program,
            defining_scopes,
            #[cfg(test)]
            definition_resolutions,
        })
    }

    #[must_use]
    pub(crate) const fn root_scope(&self) -> &ArtifactScopeId {
        &self.root_scope
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn owners(&self) -> &[VerifiedArtifactOwner] {
        &self.owners
    }

    #[must_use]
    pub(crate) const fn program(&self) -> &WorkspaceProgramIndex {
        &self.program
    }

    /// Shares the verified authority with root lifecycles without cloning its
    /// contextual decision map.
    #[must_use]
    pub(crate) fn defining_scopes_handle(&self) -> Arc<VerifiedDefiningScopeMap> {
        Arc::clone(&self.defining_scopes)
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn definition_resolution(
        &self,
        preferred_scope: &ArtifactScopeId,
        stable_crate_id: u64,
    ) -> Option<&VerifiedDefinitionResolution> {
        self.definition_resolutions
            .get(&(preferred_scope.clone(), stable_crate_id))
    }
}

/// Exact closure construction failed before traversal policy could run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum VerifiedWorkspaceClosureError {
    ArtifactScope {
        generation: ManagedArtifactGeneration,
        source: ArtifactScopeIdError,
    },
    RuntimeArtifactScope {
        artifact: RustcArtifactId,
        referring_scopes: BTreeSet<ArtifactScopeId>,
        source: ArtifactScopeIdError,
    },
    DependencyArtifactScope {
        owner_scope: ArtifactScopeId,
        dependency: RustcArtifactId,
        source: ArtifactScopeIdError,
    },
    RuntimeArtifactUnavailable {
        stable_crate_id: u64,
        referring_scopes: BTreeSet<ArtifactScopeId>,
    },
    ConflictingRuntimeArtifactGenerations {
        stable_crate_id: u64,
        referring_scopes: BTreeSet<ArtifactScopeId>,
        artifacts: Vec<RustcArtifactId>,
    },
    WorkspaceScopeMismatch {
        expected: BTreeSet<ArtifactScopeId>,
        found: BTreeSet<ArtifactScopeId>,
    },
    DuplicateManagedScope {
        scope: ArtifactScopeId,
    },
    DuplicateUnmanagedGeneration {
        scope: ArtifactScopeId,
    },
    ManagedUnmanagedConflict {
        stable_crate_id: u64,
        scope: ArtifactScopeId,
    },
    DependencyUsesOwnerStableCrate {
        owner: ManagedArtifactGeneration,
        dependency: RustcArtifactId,
    },
    ConflictingDirectDependencyGenerations {
        owner: ManagedArtifactGeneration,
        first: RustcArtifactId,
        second: RustcArtifactId,
    },
    DependencyUnclassified {
        owner_scope: ArtifactScopeId,
        dependency: RustcArtifactId,
    },
    DependencyGenerationUnavailable {
        owner_scope: ArtifactScopeId,
        declared: RustcArtifactId,
        available_scopes: Vec<ArtifactScopeId>,
    },
    ManagedGraphScopeUnavailable {
        scope: ArtifactScopeId,
    },
    RuntimeReferringScopeUnavailable {
        stable_crate_id: u64,
        scope: ArtifactScopeId,
    },
    AuthorityInventoryUnavailable {
        preferred_scope: ArtifactScopeId,
        stable_crate_id: u64,
    },
    UnreachableManagedGenerations {
        root_scope: ArtifactScopeId,
        unreachable: BTreeSet<ArtifactScopeId>,
    },
    AmbiguousDefinition {
        preferred_scope: ArtifactScopeId,
        stable_crate_id: u64,
        managed_scopes: Vec<ArtifactScopeId>,
        unmanaged_generations: Vec<RustcArtifactId>,
    },
    ReferencedManagedDefinitionUnreachable {
        preferred_scope: ArtifactScopeId,
        stable_crate_id: u64,
        candidate_scopes: Vec<ArtifactScopeId>,
    },
    ReferencedDefinitionUnclassified {
        preferred_scope: ArtifactScopeId,
        stable_crate_id: u64,
    },
    ProgramIndex(WorkspaceProgramIndexError),
    DefiningScopes(DefiningScopeMapError),
}

impl Display for VerifiedWorkspaceClosureError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactScope { .. }
            | Self::RuntimeArtifactScope { .. }
            | Self::DependencyArtifactScope { .. }
            | Self::RuntimeArtifactUnavailable { .. }
            | Self::ConflictingRuntimeArtifactGenerations { .. } => {
                fmt_artifact_identity_error(formatter, self)
            }
            Self::WorkspaceScopeMismatch { .. }
            | Self::DuplicateManagedScope { .. }
            | Self::DuplicateUnmanagedGeneration { .. }
            | Self::ManagedUnmanagedConflict { .. }
            | Self::DependencyUsesOwnerStableCrate { .. }
            | Self::ConflictingDirectDependencyGenerations { .. }
            | Self::DependencyUnclassified { .. }
            | Self::DependencyGenerationUnavailable { .. }
            | Self::ManagedGraphScopeUnavailable { .. }
            | Self::RuntimeReferringScopeUnavailable { .. }
            | Self::UnreachableManagedGenerations { .. } => fmt_manifest_error(formatter, self),
            Self::AuthorityInventoryUnavailable { .. }
            | Self::AmbiguousDefinition { .. }
            | Self::ReferencedManagedDefinitionUnreachable { .. }
            | Self::ReferencedDefinitionUnclassified { .. }
            | Self::ProgramIndex(_)
            | Self::DefiningScopes(_) => fmt_authority_error(formatter, self),
        }
    }
}

fn fmt_artifact_identity_error(
    formatter: &mut Formatter<'_>,
    error: &VerifiedWorkspaceClosureError,
) -> fmt::Result {
    match error {
        VerifiedWorkspaceClosureError::ArtifactScope { generation, source } => write!(
            formatter,
            "managed generation {generation:?} has invalid identity: {source}"
        ),
        VerifiedWorkspaceClosureError::RuntimeArtifactScope {
            artifact,
            referring_scopes,
            source,
        } => fmt_invalid_runtime_artifact(formatter, artifact, referring_scopes, source),
        VerifiedWorkspaceClosureError::DependencyArtifactScope {
            owner_scope,
            dependency,
            source,
        } => write!(
            formatter,
            "managed artifact `{owner_scope}` declares dependency {dependency} with an invalid identity: {source}"
        ),
        VerifiedWorkspaceClosureError::RuntimeArtifactUnavailable {
            stable_crate_id,
            referring_scopes,
        } => fmt_unavailable_runtime_artifact(formatter, *stable_crate_id, referring_scopes),
        VerifiedWorkspaceClosureError::ConflictingRuntimeArtifactGenerations {
            stable_crate_id,
            referring_scopes,
            artifacts,
        } => fmt_conflicting_runtime_artifacts(
            formatter,
            *stable_crate_id,
            referring_scopes,
            artifacts,
        ),
        _ => formatter.write_str("artifact identity validation failed"),
    }
}

fn fmt_manifest_error(
    formatter: &mut Formatter<'_>,
    error: &VerifiedWorkspaceClosureError,
) -> fmt::Result {
    match error {
        VerifiedWorkspaceClosureError::WorkspaceScopeMismatch { expected, found } => write!(
            formatter,
            "workspace scopes differ from the managed closure: expected {expected:?}, found {found:?}"
        ),
        VerifiedWorkspaceClosureError::DuplicateManagedScope { scope } => write!(
            formatter,
            "managed artifact scope `{scope}` is declared more than once"
        ),
        VerifiedWorkspaceClosureError::DuplicateUnmanagedGeneration { scope } => write!(
            formatter,
            "unmanaged artifact generation `{scope}` is declared more than once"
        ),
        VerifiedWorkspaceClosureError::ManagedUnmanagedConflict {
            stable_crate_id,
            scope,
        } => write!(
            formatter,
            "exact generation `{scope}` of stable crate {stable_crate_id:016x} is both managed and unmanaged"
        ),
        VerifiedWorkspaceClosureError::DependencyUsesOwnerStableCrate { owner, dependency } => {
            write!(
                formatter,
                "managed generation {owner:?} cannot depend on another generation of its own stable crate identity: {dependency}"
            )
        }
        VerifiedWorkspaceClosureError::ConflictingDirectDependencyGenerations {
            owner,
            first,
            second,
        } => write!(
            formatter,
            "managed generation {owner:?} declares two exact generations for one direct stable crate identity: {first} and {second}"
        ),
        VerifiedWorkspaceClosureError::DependencyUnclassified {
            owner_scope,
            dependency,
        } => write!(
            formatter,
            "managed artifact `{owner_scope}` depends on unclassified generation {dependency}"
        ),
        VerifiedWorkspaceClosureError::DependencyGenerationUnavailable {
            owner_scope,
            declared,
            available_scopes,
        } => write!(
            formatter,
            "managed artifact `{owner_scope}` declares unavailable dependency {declared}; generations with that stable crate identity are {available_scopes:?}"
        ),
        VerifiedWorkspaceClosureError::ManagedGraphScopeUnavailable { scope } => write!(
            formatter,
            "managed dependency graph has no canonical node for `{scope}`"
        ),
        VerifiedWorkspaceClosureError::RuntimeReferringScopeUnavailable {
            stable_crate_id,
            scope,
        } => write!(
            formatter,
            "typed runtime reference to stable crate {stable_crate_id:016x} names unavailable managed scope `{scope}`"
        ),
        VerifiedWorkspaceClosureError::UnreachableManagedGenerations {
            root_scope,
            unreachable,
        } => write!(
            formatter,
            "managed generations {unreachable:?} are unreachable from root `{root_scope}`"
        ),
        _ => formatter.write_str("managed manifest validation failed"),
    }
}

fn fmt_authority_error(
    formatter: &mut Formatter<'_>,
    error: &VerifiedWorkspaceClosureError,
) -> fmt::Result {
    match error {
        VerifiedWorkspaceClosureError::AuthorityInventoryUnavailable {
            preferred_scope,
            stable_crate_id,
        } => write!(
            formatter,
            "typed definitions in `{preferred_scope}` reference stable crate {stable_crate_id:016x} without a prepared contextual authority inventory"
        ),
        VerifiedWorkspaceClosureError::AmbiguousDefinition {
            preferred_scope,
            stable_crate_id,
            managed_scopes,
            unmanaged_generations,
        } => fmt_ambiguous_definition(
            formatter,
            preferred_scope,
            *stable_crate_id,
            managed_scopes,
            unmanaged_generations,
        ),
        VerifiedWorkspaceClosureError::ReferencedManagedDefinitionUnreachable {
            preferred_scope,
            stable_crate_id,
            candidate_scopes,
        } => fmt_unreachable_managed_definition(
            formatter,
            preferred_scope,
            *stable_crate_id,
            candidate_scopes,
        ),
        VerifiedWorkspaceClosureError::ReferencedDefinitionUnclassified {
            preferred_scope,
            stable_crate_id,
        } => write!(
            formatter,
            "typed definitions in `{preferred_scope}` reference stable crate {stable_crate_id:016x} without a managed or explicit unmanaged identity"
        ),
        VerifiedWorkspaceClosureError::ProgramIndex(source) => Display::fmt(source, formatter),
        VerifiedWorkspaceClosureError::DefiningScopes(source) => Display::fmt(source, formatter),
        _ => formatter.write_str("definition authority validation failed"),
    }
}

impl Error for VerifiedWorkspaceClosureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ArtifactScope { source, .. }
            | Self::RuntimeArtifactScope { source, .. }
            | Self::DependencyArtifactScope { source, .. } => Some(source),
            Self::ProgramIndex(source) => Some(source),
            Self::DefiningScopes(source) => Some(source),
            Self::RuntimeArtifactUnavailable { .. }
            | Self::ConflictingRuntimeArtifactGenerations { .. }
            | Self::WorkspaceScopeMismatch { .. }
            | Self::DuplicateManagedScope { .. }
            | Self::DuplicateUnmanagedGeneration { .. }
            | Self::ManagedUnmanagedConflict { .. }
            | Self::DependencyUsesOwnerStableCrate { .. }
            | Self::ConflictingDirectDependencyGenerations { .. }
            | Self::DependencyUnclassified { .. }
            | Self::DependencyGenerationUnavailable { .. }
            | Self::ManagedGraphScopeUnavailable { .. }
            | Self::RuntimeReferringScopeUnavailable { .. }
            | Self::AuthorityInventoryUnavailable { .. }
            | Self::UnreachableManagedGenerations { .. }
            | Self::AmbiguousDefinition { .. }
            | Self::ReferencedManagedDefinitionUnreachable { .. }
            | Self::ReferencedDefinitionUnclassified { .. } => None,
        }
    }
}

fn fmt_invalid_runtime_artifact(
    formatter: &mut Formatter<'_>,
    artifact: &RustcArtifactId,
    referring_scopes: &BTreeSet<ArtifactScopeId>,
    source: &ArtifactScopeIdError,
) -> fmt::Result {
    write!(
        formatter,
        "typed definitions in {referring_scopes:?} select runtime artifact {artifact} with an invalid identity: {source}"
    )
}

fn fmt_unavailable_runtime_artifact(
    formatter: &mut Formatter<'_>,
    stable_crate_id: u64,
    referring_scopes: &BTreeSet<ArtifactScopeId>,
) -> fmt::Result {
    write!(
        formatter,
        "typed definitions in {referring_scopes:?} reference unmanaged stable crate {stable_crate_id:016x}, which is absent from the active rustc artifact inventory"
    )
}

fn fmt_conflicting_runtime_artifacts(
    formatter: &mut Formatter<'_>,
    stable_crate_id: u64,
    referring_scopes: &BTreeSet<ArtifactScopeId>,
    artifacts: &[RustcArtifactId],
) -> fmt::Result {
    write!(
        formatter,
        "typed definitions in {referring_scopes:?} reference unmanaged stable crate {stable_crate_id:016x}, which has conflicting active rustc artifact identities {artifacts:?}"
    )
}

fn fmt_ambiguous_definition(
    formatter: &mut Formatter<'_>,
    preferred_scope: &ArtifactScopeId,
    stable_crate_id: u64,
    managed_scopes: &[ArtifactScopeId],
    unmanaged_generations: &[RustcArtifactId],
) -> fmt::Result {
    write!(
        formatter,
        "typed definitions in `{preferred_scope}` reference stable crate {stable_crate_id:016x} ambiguously: managed {managed_scopes:?}, unmanaged {unmanaged_generations:?}"
    )
}

fn fmt_unreachable_managed_definition(
    formatter: &mut Formatter<'_>,
    preferred_scope: &ArtifactScopeId,
    stable_crate_id: u64,
    candidate_scopes: &[ArtifactScopeId],
) -> fmt::Result {
    write!(
        formatter,
        "typed definitions in `{preferred_scope}` reference stable crate {stable_crate_id:016x}, whose managed generations {candidate_scopes:?} are not reachable from that scope"
    )
}

#[cfg(test)]
fn prepare_closure_input(
    workspace: &WorkspaceFactView<'_>,
    root: ManagedArtifactManifest,
    managed_dependencies: impl IntoIterator<Item = ManagedArtifactManifest>,
    unmanaged: impl IntoIterator<Item = RustcArtifactId>,
) -> Result<PreparedClosureInput, VerifiedWorkspaceClosureError> {
    let prepared = prepare_managed_input(root, managed_dependencies)?;
    let unmanaged = prepare_unmanaged_inventory(&prepared.managed, unmanaged)?;
    validate_workspace_scope_set(workspace, &prepared.managed)?;
    finish_closure_input(prepared, &unmanaged)
}

fn prepare_managed_input(
    root: ManagedArtifactManifest,
    managed_dependencies: impl IntoIterator<Item = ManagedArtifactManifest>,
) -> Result<PreparedManagedInput, VerifiedWorkspaceClosureError> {
    let root_scope = canonical_scope(&root.generation)?;
    let mut managed = BTreeMap::new();
    insert_managed_manifest(&mut managed, root)?;
    for manifest in managed_dependencies {
        insert_managed_manifest(&mut managed, manifest)?;
    }
    let owners = managed
        .iter()
        .map(|(scope, manifest)| {
            VerifiedArtifactOwner::new(scope.clone(), manifest.generation.stable_crate_id())
        })
        .collect();
    Ok(PreparedManagedInput {
        root_scope,
        managed,
        owners,
    })
}

fn finish_closure_input(
    prepared: PreparedManagedInput,
    unmanaged: &BTreeMap<ArtifactScopeId, RustcArtifactId>,
) -> Result<PreparedClosureInput, VerifiedWorkspaceClosureError> {
    let graph = ManagedDependencyGraph::open(&prepared.managed, unmanaged)?;
    let reachable = graph.reachable_from(&prepared.root_scope)?;
    validate_root_reachability(&prepared.managed, &prepared.root_scope, &reachable)?;
    Ok(PreparedClosureInput {
        root_scope: prepared.root_scope,
        managed: prepared.managed,
        #[cfg(test)]
        owners: prepared.owners,
        reachable,
        graph,
    })
}

fn complete_from_runtime_inventory(
    mut prepared: PreparedManagedInput,
    program: &WorkspaceProgramIndex,
    active_runtime_artifacts: impl IntoIterator<Item = RustcArtifactId>,
) -> Result<PreparedClosureInput, VerifiedWorkspaceClosureError> {
    let managed_stable_crate_ids = prepared
        .managed
        .values()
        .map(|manifest| manifest.generation.stable_crate_id())
        .collect::<BTreeSet<_>>();
    let mut referring_scopes = BTreeMap::<u64, BTreeSet<ArtifactScopeId>>::new();
    for scope in program.scopes() {
        let owner = program
            .stable_crate_id(scope)
            .map_err(VerifiedWorkspaceClosureError::ProgramIndex)?;
        for stable_crate_id in program
            .referenced_definition_stable_crate_ids(scope)
            .map_err(VerifiedWorkspaceClosureError::ProgramIndex)?
        {
            if stable_crate_id != owner && !managed_stable_crate_ids.contains(&stable_crate_id) {
                referring_scopes
                    .entry(stable_crate_id)
                    .or_default()
                    .insert(scope.clone());
            }
        }
    }

    let mut runtime_by_stable_crate = BTreeMap::<u64, BTreeSet<RustcArtifactId>>::new();
    for artifact in active_runtime_artifacts {
        runtime_by_stable_crate
            .entry(artifact.stable_crate_id)
            .or_default()
            .insert(artifact);
    }

    let mut unmanaged = Vec::with_capacity(referring_scopes.len());
    for (stable_crate_id, scopes) in referring_scopes {
        let artifact = match runtime_by_stable_crate.get(&stable_crate_id) {
            None => {
                return Err(VerifiedWorkspaceClosureError::RuntimeArtifactUnavailable {
                    stable_crate_id,
                    referring_scopes: scopes,
                });
            }
            Some(artifacts) => {
                let mut candidates = artifacts.iter();
                match (candidates.next(), candidates.next()) {
                    (Some(artifact), None) => artifact.clone(),
                    (None, _) => {
                        return Err(VerifiedWorkspaceClosureError::RuntimeArtifactUnavailable {
                            stable_crate_id,
                            referring_scopes: scopes,
                        });
                    }
                    (Some(_), Some(_)) => {
                        return Err(
                            VerifiedWorkspaceClosureError::ConflictingRuntimeArtifactGenerations {
                                stable_crate_id,
                                referring_scopes: scopes,
                                artifacts: artifacts.iter().cloned().collect(),
                            },
                        );
                    }
                }
            }
        };
        ArtifactScopeId::for_persisted(artifact.stable_crate_id, artifact.svh.clone()).map_err(
            |source| VerifiedWorkspaceClosureError::RuntimeArtifactScope {
                artifact: artifact.clone(),
                referring_scopes: scopes.clone(),
                source,
            },
        )?;
        for scope in &scopes {
            let manifest = prepared.managed.get_mut(scope).ok_or_else(|| {
                VerifiedWorkspaceClosureError::RuntimeReferringScopeUnavailable {
                    stable_crate_id,
                    scope: scope.clone(),
                }
            })?;
            manifest.dependencies.push(artifact.clone());
        }
        unmanaged.push(artifact);
    }
    for manifest in prepared.managed.values_mut() {
        manifest.dependencies.sort_unstable();
        manifest.dependencies.dedup();
        validate_direct_dependencies(manifest)?;
    }
    let unmanaged = prepare_unmanaged_inventory(&prepared.managed, unmanaged)?;
    finish_closure_input(prepared, &unmanaged)
}

fn prepare_unmanaged_inventory(
    managed: &BTreeMap<ArtifactScopeId, ManagedArtifactManifest>,
    unmanaged: impl IntoIterator<Item = RustcArtifactId>,
) -> Result<BTreeMap<ArtifactScopeId, RustcArtifactId>, VerifiedWorkspaceClosureError> {
    let mut by_scope = BTreeMap::new();
    for artifact in unmanaged {
        let scope = canonical_persisted_scope(&artifact)?;
        if managed.contains_key(&scope) {
            return Err(VerifiedWorkspaceClosureError::ManagedUnmanagedConflict {
                stable_crate_id: artifact.stable_crate_id,
                scope,
            });
        }
        if by_scope.insert(scope.clone(), artifact).is_some() {
            return Err(VerifiedWorkspaceClosureError::DuplicateUnmanagedGeneration { scope });
        }
    }
    Ok(by_scope)
}

fn validate_workspace_scope_set(
    workspace: &WorkspaceFactView<'_>,
    managed: &BTreeMap<ArtifactScopeId, ManagedArtifactManifest>,
) -> Result<(), VerifiedWorkspaceClosureError> {
    let expected = managed.keys().cloned().collect::<BTreeSet<_>>();
    let found = workspace.scopes().cloned().collect::<BTreeSet<_>>();
    if expected == found {
        Ok(())
    } else {
        Err(VerifiedWorkspaceClosureError::WorkspaceScopeMismatch { expected, found })
    }
}

fn validate_root_reachability(
    managed: &BTreeMap<ArtifactScopeId, ManagedArtifactManifest>,
    root_scope: &ArtifactScopeId,
    reachable: &BTreeSet<ArtifactScopeId>,
) -> Result<(), VerifiedWorkspaceClosureError> {
    if reachable.len() == managed.len() {
        return Ok(());
    }
    let unreachable = managed
        .keys()
        .filter(|scope| !reachable.contains(*scope))
        .cloned()
        .collect();
    Err(
        VerifiedWorkspaceClosureError::UnreachableManagedGenerations {
            root_scope: root_scope.clone(),
            unreachable,
        },
    )
}

fn prepare_definition_authorities(
    prepared: &PreparedClosureInput,
    program: &WorkspaceProgramIndex,
) -> Result<(Vec<DefiningScopeAuthority>, ContextualDefinitionMap), VerifiedWorkspaceClosureError> {
    let mut requests = Vec::new();
    let mut foreign_requests = BTreeMap::<u64, BTreeSet<ArtifactScopeId>>::new();
    for preferred_scope in &prepared.reachable {
        let owner = program
            .stable_crate_id(preferred_scope)
            .map_err(VerifiedWorkspaceClosureError::ProgramIndex)?;
        for stable_crate_id in program
            .referenced_definition_stable_crate_ids(preferred_scope)
            .map_err(VerifiedWorkspaceClosureError::ProgramIndex)?
        {
            let is_owner = stable_crate_id == owner;
            if !is_owner {
                foreign_requests
                    .entry(stable_crate_id)
                    .or_default()
                    .insert(preferred_scope.clone());
            }
            requests.push((preferred_scope.clone(), stable_crate_id, is_owner));
        }
    }
    let inventories = prepare_authority_inventories(prepared, &foreign_requests)?;
    let mut authorities = Vec::new();
    let mut resolutions = BTreeMap::new();
    for (preferred_scope, stable_crate_id, is_owner) in requests {
        let exact = if is_owner {
            VerifiedDefinitionResolution::Managed(preferred_scope.clone())
        } else {
            resolve_contextual_definition(&inventories, &preferred_scope, stable_crate_id)?
        };
        let resolution = match &exact {
            VerifiedDefinitionResolution::Managed(scope) => {
                StableCrateResolution::Managed(scope.clone())
            }
            VerifiedDefinitionResolution::Unmanaged(_) => StableCrateResolution::Unmanaged,
        };
        resolutions.insert((preferred_scope.clone(), stable_crate_id), exact);
        authorities.push(DefiningScopeAuthority::new(
            preferred_scope,
            stable_crate_id,
            resolution,
        ));
    }
    Ok((authorities, resolutions))
}

fn prepare_authority_inventories(
    prepared: &PreparedClosureInput,
    requests: &BTreeMap<u64, BTreeSet<ArtifactScopeId>>,
) -> Result<AuthorityInventories, VerifiedWorkspaceClosureError> {
    let mut all_managed_scopes = BTreeMap::<u64, Vec<ArtifactScopeId>>::new();
    for (scope, manifest) in &prepared.managed {
        all_managed_scopes
            .entry(manifest.generation.stable_crate_id())
            .or_default()
            .push(scope.clone());
    }

    let mut by_preferred_scope = BTreeMap::new();
    for preferred_scopes in requests.values() {
        for preferred_scope in preferred_scopes {
            by_preferred_scope
                .entry(preferred_scope.clone())
                .or_insert_with(ContextualAuthorityInventory::default);
        }
    }

    for (stable_crate_id, candidate_scopes) in &all_managed_scopes {
        let Some(requested_scopes) = requests.get(stable_crate_id) else {
            continue;
        };
        for candidate_scope in candidate_scopes {
            #[cfg(test)]
            record_authority_candidate_propagated();
            let contexts = requested_contexts_reaching(
                &prepared.graph,
                std::slice::from_ref(candidate_scope),
                requested_scopes,
            )?;
            for context in contexts {
                by_preferred_scope
                    .entry(context)
                    .or_default()
                    .managed_scopes
                    .entry(*stable_crate_id)
                    .or_default()
                    .push(candidate_scope.clone());
            }
        }
    }

    let mut unmanaged_owners = BTreeMap::<RustcArtifactId, Vec<ArtifactScopeId>>::new();
    for (owner, artifacts) in &prepared.graph.unmanaged_by_owner {
        for artifact in artifacts {
            unmanaged_owners
                .entry(artifact.clone())
                .or_default()
                .push(owner.clone());
        }
    }
    for (artifact, owners) in unmanaged_owners {
        let Some(requested_scopes) = requests.get(&artifact.stable_crate_id) else {
            continue;
        };
        #[cfg(test)]
        record_authority_candidate_propagated();
        let contexts = requested_contexts_reaching(&prepared.graph, &owners, requested_scopes)?;
        for context in contexts {
            by_preferred_scope
                .entry(context)
                .or_default()
                .unmanaged_generations
                .entry(artifact.stable_crate_id)
                .or_default()
                .push(artifact.clone());
        }
    }

    for inventory in by_preferred_scope.values_mut() {
        for scopes in inventory.managed_scopes.values_mut() {
            scopes.sort_unstable();
            scopes.dedup();
        }
        for artifacts in inventory.unmanaged_generations.values_mut() {
            artifacts.sort_unstable();
            artifacts.dedup();
        }
    }
    Ok(AuthorityInventories {
        by_preferred_scope,
        all_managed_scopes,
    })
}

fn requested_contexts_reaching(
    graph: &ManagedDependencyGraph,
    candidate_owners: &[ArtifactScopeId],
    requested_scopes: &BTreeSet<ArtifactScopeId>,
) -> Result<BTreeSet<ArtifactScopeId>, VerifiedWorkspaceClosureError> {
    let mut contexts = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut pending = candidate_owners.iter().cloned().collect::<VecDeque<_>>();
    while let Some(scope) = pending.pop_front() {
        if !visited.insert(scope.clone()) {
            continue;
        }
        if requested_scopes.contains(&scope) {
            contexts.insert(scope.clone());
        }
        let predecessors = graph.reverse.get(&scope).ok_or_else(|| {
            VerifiedWorkspaceClosureError::ManagedGraphScopeUnavailable {
                scope: scope.clone(),
            }
        })?;
        for predecessor in predecessors {
            #[cfg(test)]
            record_authority_edge_examined();
            pending.push_back(predecessor.clone());
        }
    }
    Ok(contexts)
}

fn resolve_contextual_definition(
    inventories: &AuthorityInventories,
    preferred_scope: &ArtifactScopeId,
    stable_crate_id: u64,
) -> Result<VerifiedDefinitionResolution, VerifiedWorkspaceClosureError> {
    let inventory = inventories
        .by_preferred_scope
        .get(preferred_scope)
        .ok_or_else(
            || VerifiedWorkspaceClosureError::AuthorityInventoryUnavailable {
                preferred_scope: preferred_scope.clone(),
                stable_crate_id,
            },
        )?;
    let managed_scopes = inventory
        .managed_scopes
        .get(&stable_crate_id)
        .map_or(&[][..], Vec::as_slice);
    let unmanaged_generations = inventory
        .unmanaged_generations
        .get(&stable_crate_id)
        .map_or(&[][..], Vec::as_slice);
    match (managed_scopes, unmanaged_generations) {
        ([scope], []) => Ok(VerifiedDefinitionResolution::Managed(scope.clone())),
        ([], [artifact]) => Ok(VerifiedDefinitionResolution::Unmanaged(artifact.clone())),
        ([], []) => unresolved_contextual_definition(inventories, preferred_scope, stable_crate_id),
        _ => Err(VerifiedWorkspaceClosureError::AmbiguousDefinition {
            preferred_scope: preferred_scope.clone(),
            stable_crate_id,
            managed_scopes: managed_scopes.to_vec(),
            unmanaged_generations: unmanaged_generations.to_vec(),
        }),
    }
}

fn unresolved_contextual_definition(
    inventories: &AuthorityInventories,
    preferred_scope: &ArtifactScopeId,
    stable_crate_id: u64,
) -> Result<VerifiedDefinitionResolution, VerifiedWorkspaceClosureError> {
    let candidate_scopes = inventories
        .all_managed_scopes
        .get(&stable_crate_id)
        .cloned()
        .unwrap_or_default();
    if candidate_scopes.is_empty() {
        Err(
            VerifiedWorkspaceClosureError::ReferencedDefinitionUnclassified {
                preferred_scope: preferred_scope.clone(),
                stable_crate_id,
            },
        )
    } else {
        Err(
            VerifiedWorkspaceClosureError::ReferencedManagedDefinitionUnreachable {
                preferred_scope: preferred_scope.clone(),
                stable_crate_id,
                candidate_scopes,
            },
        )
    }
}

fn canonical_scope(
    generation: &ManagedArtifactGeneration,
) -> Result<ArtifactScopeId, VerifiedWorkspaceClosureError> {
    generation
        .scope()
        .map_err(|source| VerifiedWorkspaceClosureError::ArtifactScope {
            generation: generation.clone(),
            source,
        })
}

fn canonical_persisted_scope(
    artifact: &RustcArtifactId,
) -> Result<ArtifactScopeId, VerifiedWorkspaceClosureError> {
    canonical_scope(&ManagedArtifactGeneration::persisted(artifact.clone()))
}

fn insert_managed_manifest(
    managed: &mut BTreeMap<ArtifactScopeId, ManagedArtifactManifest>,
    mut manifest: ManagedArtifactManifest,
) -> Result<(), VerifiedWorkspaceClosureError> {
    let scope = canonical_scope(&manifest.generation)?;
    manifest.dependencies.sort_unstable();
    manifest.dependencies.dedup();
    validate_direct_dependencies(&manifest)?;
    if managed.insert(scope.clone(), manifest).is_some() {
        return Err(VerifiedWorkspaceClosureError::DuplicateManagedScope { scope });
    }
    Ok(())
}

fn validate_direct_dependencies(
    manifest: &ManagedArtifactManifest,
) -> Result<(), VerifiedWorkspaceClosureError> {
    for pair in manifest.dependencies.windows(2) {
        if pair[0].stable_crate_id == pair[1].stable_crate_id {
            return Err(
                VerifiedWorkspaceClosureError::ConflictingDirectDependencyGenerations {
                    owner: manifest.generation.clone(),
                    first: pair[0].clone(),
                    second: pair[1].clone(),
                },
            );
        }
    }
    if let Some(dependency) = manifest
        .dependencies
        .iter()
        .find(|dependency| dependency.stable_crate_id == manifest.generation.stable_crate_id())
    {
        return Err(
            VerifiedWorkspaceClosureError::DependencyUsesOwnerStableCrate {
                owner: manifest.generation.clone(),
                dependency: dependency.clone(),
            },
        );
    }
    Ok(())
}

impl ManagedDependencyGraph {
    fn open(
        managed: &BTreeMap<ArtifactScopeId, ManagedArtifactManifest>,
        unmanaged: &BTreeMap<ArtifactScopeId, RustcArtifactId>,
    ) -> Result<Self, VerifiedWorkspaceClosureError> {
        let mut graph = Self {
            forward: managed
                .keys()
                .cloned()
                .map(|scope| (scope, Vec::new()))
                .collect(),
            reverse: managed
                .keys()
                .cloned()
                .map(|scope| (scope, Vec::new()))
                .collect(),
            unmanaged_by_owner: managed
                .keys()
                .cloned()
                .map(|scope| (scope, Vec::new()))
                .collect(),
        };
        for (owner_scope, manifest) in managed {
            for dependency in &manifest.dependencies {
                #[cfg(test)]
                record_dependency_edge_examined();
                let dependency_scope = ArtifactScopeId::for_persisted(
                    dependency.stable_crate_id,
                    dependency.svh.clone(),
                )
                .map_err(|source| {
                    VerifiedWorkspaceClosureError::DependencyArtifactScope {
                        owner_scope: owner_scope.clone(),
                        dependency: dependency.clone(),
                        source,
                    }
                })?;
                if managed.contains_key(&dependency_scope) {
                    graph.managed_edge(owner_scope, &dependency_scope)?;
                } else if unmanaged.get(&dependency_scope) == Some(dependency) {
                    graph.unmanaged_edge(owner_scope, dependency)?;
                } else {
                    return Err(unavailable_dependency_error(
                        managed,
                        unmanaged,
                        owner_scope,
                        dependency,
                    ));
                }
            }
        }
        Ok(graph)
    }

    fn managed_edge(
        &mut self,
        owner_scope: &ArtifactScopeId,
        dependency_scope: &ArtifactScopeId,
    ) -> Result<(), VerifiedWorkspaceClosureError> {
        self.forward
            .get_mut(owner_scope)
            .ok_or_else(
                || VerifiedWorkspaceClosureError::ManagedGraphScopeUnavailable {
                    scope: owner_scope.clone(),
                },
            )?
            .push(dependency_scope.clone());
        self.reverse
            .get_mut(dependency_scope)
            .ok_or_else(
                || VerifiedWorkspaceClosureError::ManagedGraphScopeUnavailable {
                    scope: dependency_scope.clone(),
                },
            )?
            .push(owner_scope.clone());
        Ok(())
    }

    fn unmanaged_edge(
        &mut self,
        owner_scope: &ArtifactScopeId,
        dependency: &RustcArtifactId,
    ) -> Result<(), VerifiedWorkspaceClosureError> {
        self.unmanaged_by_owner
            .get_mut(owner_scope)
            .ok_or_else(
                || VerifiedWorkspaceClosureError::ManagedGraphScopeUnavailable {
                    scope: owner_scope.clone(),
                },
            )?
            .push(dependency.clone());
        Ok(())
    }

    fn reachable_from(
        &self,
        root_scope: &ArtifactScopeId,
    ) -> Result<BTreeSet<ArtifactScopeId>, VerifiedWorkspaceClosureError> {
        #[cfg(test)]
        record_reachability_traversal();
        let mut reachable = BTreeSet::new();
        let mut pending = VecDeque::from([root_scope.clone()]);
        while let Some(scope) = pending.pop_front() {
            if !reachable.insert(scope.clone()) {
                continue;
            }
            let dependencies = self.forward.get(&scope).ok_or_else(|| {
                VerifiedWorkspaceClosureError::ManagedGraphScopeUnavailable {
                    scope: scope.clone(),
                }
            })?;
            pending.extend(dependencies.iter().cloned());
        }
        Ok(reachable)
    }
}

fn unavailable_dependency_error(
    managed: &BTreeMap<ArtifactScopeId, ManagedArtifactManifest>,
    unmanaged: &BTreeMap<ArtifactScopeId, RustcArtifactId>,
    owner_scope: &ArtifactScopeId,
    dependency: &RustcArtifactId,
) -> VerifiedWorkspaceClosureError {
    let available_scopes = managed
        .iter()
        .filter(|(_, manifest)| manifest.generation.stable_crate_id() == dependency.stable_crate_id)
        .map(|(scope, _)| scope.clone())
        .chain(
            unmanaged
                .iter()
                .filter(|(_, artifact)| artifact.stable_crate_id == dependency.stable_crate_id)
                .map(|(scope, _)| scope.clone()),
        )
        .collect::<Vec<_>>();
    if available_scopes.is_empty() {
        VerifiedWorkspaceClosureError::DependencyUnclassified {
            owner_scope: owner_scope.clone(),
            dependency: dependency.clone(),
        }
    } else {
        VerifiedWorkspaceClosureError::DependencyGenerationUnavailable {
            owner_scope: owner_scope.clone(),
            declared: dependency.clone(),
            available_scopes,
        }
    }
}

#[cfg(test)]
mod tests {
    use reachability::MirBodyLocation;

    use super::*;
    use crate::analysis::collected::CollectedArtifact;
    use crate::analysis::facts::builder::ArtifactDbBuilder;
    use crate::analysis::facts::encoded::ArtifactFactIr;
    use crate::analysis::facts::human::markers::HumanMarkerCollectionPack;
    use crate::analysis::facts::pack::AnalysisRegistry;
    use crate::analysis::facts::panic::contract_collector::PanicContractCollectionPack;
    use crate::analysis::facts::program::collector::CoreProgramCollectionPack;
    use crate::analysis::facts::program::topology::{
        CallAttributionRole, CallKind, CallMacroExpansionEntity, CallMacroExpansionKey,
        CallMacroExpansionProducesCallOccurrence, CallOccurrenceEntity,
        CallOccurrenceHasCallableKey, CallOccurrenceInSafetyEffectGroup, CallOccurrenceKey,
        CallSiteEntity, CallSiteHasOccurrence, CallSiteKey, CallableEntity, CallableKey,
        CallableKeyEntity, FunctionDefinesCallable, FunctionEntersCallMacroExpansion,
        FunctionOwnsCallSite, FunctionOwnsSafetyEffectGroup, SafetyEffectGroupEntity,
        SafetyEffectGroupKey,
    };
    use crate::analysis::facts::program::{
        EffectSiteEntity, EffectSiteKey, FunctionBodyProvenance, FunctionEntersMacroExpansion,
        FunctionEntity, FunctionKey, FunctionOwnsEffectSite, MacroExpansionEntity,
        MacroExpansionKey, MacroExpansionProducesEffectSite,
    };
    use crate::analysis::facts::safety::collector::SafetyCollectionPack;
    use crate::analysis::facts::safety::operations::{
        FunctionEntersUnsafeOperationMacroExpansion, FunctionOwnsUnsafeOperation,
        SafetyOperationKind, UnsafeOperationEntity, UnsafeOperationInSafetyEffectGroup,
        UnsafeOperationKey, UnsafeOperationMacroExpansionEntity, UnsafeOperationMacroExpansionKey,
        UnsafeOperationMacroExpansionProducesUnsafeOperation,
    };
    use crate::analysis::facts::schema::EntityHandle;
    use crate::analysis::facts::view::ArtifactDbView;
    use crate::namespace::{StableDefPathHash, StableExpansionHash, StableTypeHash};

    fn definition(stable_crate_id: u64, local: u64) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{stable_crate_id:016x}{local:016x}\""))
            .expect("valid definition hash")
    }

    fn expansion(value: u128) -> StableExpansionHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid expansion hash")
    }

    fn type_hash(first: u64, second: u64) -> StableTypeHash {
        serde_json::from_str(&format!("\"{first:016x}{second:016x}\"")).expect("valid type hash")
    }

    fn artifact_id(stable_crate_id: u64, digit: char) -> RustcArtifactId {
        RustcArtifactId::new(stable_crate_id, digit.to_string().repeat(32))
    }

    fn registry() -> AnalysisRegistry<CollectedArtifact> {
        let mut registry = AnalysisRegistry::<CollectedArtifact>::new();
        registry.install(&CoreProgramCollectionPack).unwrap();
        registry.install(&PanicContractCollectionPack).unwrap();
        registry.install(&SafetyCollectionPack).unwrap();
        registry.install(&HumanMarkerCollectionPack).unwrap();
        registry
    }

    fn declared_builder(registry: &AnalysisRegistry<CollectedArtifact>) -> ArtifactDbBuilder {
        let mut builder = ArtifactDbBuilder::new();
        for descriptor in registry.schemas().descriptors() {
            builder.declare_table(descriptor).unwrap();
        }
        builder
    }

    fn insert_local_function(
        builder: &mut ArtifactDbBuilder,
        owner: u64,
    ) -> (EntityHandle<FunctionEntity>, FunctionKey) {
        let local_key = FunctionKey::new(definition(owner, 1), None);
        let function = builder
            .insert_entity(&FunctionEntity::new(
                local_key,
                format!("crate_{owner}::root"),
                FunctionBodyProvenance::DefiningArtifact,
            ))
            .unwrap();
        let local_callable = builder
            .insert_entity(&CallableEntity::new(
                local_key,
                format!("crate_{owner}::root"),
                false,
                false,
                true,
                false,
                vec![format!("crate_{owner}")],
            ))
            .unwrap();
        builder
            .relate(&function, &local_callable, &FunctionDefinesCallable::new())
            .unwrap();
        (function, local_key)
    }

    fn artifact(
        registry: &AnalysisRegistry<CollectedArtifact>,
        owner: u64,
        referenced_stable_crates: &[u64],
    ) -> ArtifactFactIr {
        let mut builder = declared_builder(registry);
        let _ = insert_local_function(&mut builder, owner);

        for (offset, stable_crate_id) in referenced_stable_crates.iter().copied().enumerate() {
            if stable_crate_id == owner {
                continue;
            }
            let key = FunctionKey::new(definition(stable_crate_id, offset as u64 + 2), None);
            builder
                .insert_entity(&CallableEntity::new(
                    key,
                    format!("crate_{stable_crate_id}::target_{offset}"),
                    false,
                    false,
                    true,
                    false,
                    vec![format!("crate_{stable_crate_id}")],
                ))
                .unwrap();
        }
        builder.finalize(registry.schemas()).unwrap()
    }

    #[derive(Clone, Copy, Debug)]
    enum TypedDefinitionReferenceKind {
        CallableDefinition,
        DynamicDispatchKey,
        EffectMacro,
        CallMacro,
        UnsafeOperationMacro,
    }

    impl TypedDefinitionReferenceKind {
        const ALL: [Self; 5] = [
            Self::CallableDefinition,
            Self::DynamicDispatchKey,
            Self::EffectMacro,
            Self::CallMacro,
            Self::UnsafeOperationMacro,
        ];
    }

    fn insert_safety_group(
        builder: &mut ArtifactDbBuilder,
        function: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
    ) -> EntityHandle<SafetyEffectGroupEntity> {
        let group = builder
            .insert_entity(&SafetyEffectGroupEntity::new(SafetyEffectGroupKey::new(
                owner, 0,
            )))
            .unwrap();
        builder
            .relate(function, &group, &FunctionOwnsSafetyEffectGroup::new())
            .unwrap();
        group
    }

    fn insert_call_occurrence(
        builder: &mut ArtifactDbBuilder,
        function: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        group: &EntityHandle<SafetyEffectGroupEntity>,
        kind: CallKind,
    ) -> EntityHandle<CallOccurrenceEntity> {
        let site = builder
            .insert_entity(&CallSiteEntity::new(CallSiteKey::new(owner, 0)))
            .unwrap();
        builder
            .relate(function, &site, &FunctionOwnsCallSite::new())
            .unwrap();
        let occurrence = builder
            .insert_entity(&CallOccurrenceEntity::new(
                CallOccurrenceKey::new(owner, 0),
                kind,
                vec![CallAttributionRole::CallSite],
                false,
                false,
                Some(String::from("typed reference fixture")),
            ))
            .unwrap();
        builder
            .relate(&site, &occurrence, &CallSiteHasOccurrence::new())
            .unwrap();
        builder
            .relate(
                &occurrence,
                group,
                &CallOccurrenceInSafetyEffectGroup::new(),
            )
            .unwrap();
        occurrence
    }

    fn insert_callable_definition_reference(
        builder: &mut ArtifactDbBuilder,
        foreign_definition: StableDefPathHash,
    ) {
        builder
            .insert_entity(&CallableEntity::new(
                FunctionKey::new(foreign_definition, None),
                "foreign::callable",
                false,
                false,
                true,
                false,
                vec![String::from("foreign")],
            ))
            .unwrap();
    }

    fn insert_dynamic_dispatch_reference(
        builder: &mut ArtifactDbBuilder,
        function: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        foreign_definition: StableDefPathHash,
    ) {
        let group = insert_safety_group(builder, function, owner);
        let occurrence =
            insert_call_occurrence(builder, function, owner, &group, CallKind::IndirectCall);
        let key = builder
            .insert_entity(&CallableKeyEntity::new(CallableKey::DynDispatch(
                foreign_definition,
            )))
            .unwrap();
        builder
            .relate(&occurrence, &key, &CallOccurrenceHasCallableKey::new())
            .unwrap();
    }

    fn insert_effect_macro_reference(
        builder: &mut ArtifactDbBuilder,
        function: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        foreign_definition: StableDefPathHash,
    ) {
        let effect_key = EffectSiteKey::from_mir(
            owner,
            MirBodyLocation {
                basic_block: 0,
                statement_index: 0,
            },
        )
        .unwrap();
        let effect = builder
            .insert_entity(&EffectSiteEntity::new(effect_key))
            .unwrap();
        builder
            .relate(function, &effect, &FunctionOwnsEffectSite::new())
            .unwrap();
        let frame = builder
            .insert_entity(&MacroExpansionEntity::new(
                MacroExpansionKey::new(effect_key, 0),
                expansion(1),
                foreign_definition,
                "foreign::effect_macro",
            ))
            .unwrap();
        builder
            .relate(function, &frame, &FunctionEntersMacroExpansion::new())
            .unwrap();
        builder
            .relate(&frame, &effect, &MacroExpansionProducesEffectSite::new())
            .unwrap();
    }

    fn insert_call_macro_reference(
        builder: &mut ArtifactDbBuilder,
        function: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        foreign_definition: StableDefPathHash,
    ) {
        let group = insert_safety_group(builder, function, owner);
        let occurrence =
            insert_call_occurrence(builder, function, owner, &group, CallKind::DirectCall);
        let frame = builder
            .insert_entity(&CallMacroExpansionEntity::new(
                CallMacroExpansionKey::new(*occurrence.key(), 0),
                expansion(2),
                foreign_definition,
                "foreign::call_macro",
            ))
            .unwrap();
        builder
            .relate(function, &frame, &FunctionEntersCallMacroExpansion::new())
            .unwrap();
        builder
            .relate(
                &frame,
                &occurrence,
                &CallMacroExpansionProducesCallOccurrence::new(),
            )
            .unwrap();
    }

    fn insert_unsafe_macro_reference(
        builder: &mut ArtifactDbBuilder,
        function: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        foreign_definition: StableDefPathHash,
    ) {
        let group = insert_safety_group(builder, function, owner);
        let operation_key = UnsafeOperationKey::new(owner, 0);
        let operation = builder
            .insert_entity(&UnsafeOperationEntity::new(
                operation_key,
                SafetyOperationKind::DerefRawPointer,
            ))
            .unwrap();
        builder
            .relate(function, &operation, &FunctionOwnsUnsafeOperation::new())
            .unwrap();
        builder
            .relate(
                &operation,
                &group,
                &UnsafeOperationInSafetyEffectGroup::new(),
            )
            .unwrap();
        let frame = builder
            .insert_entity(&UnsafeOperationMacroExpansionEntity::new(
                UnsafeOperationMacroExpansionKey::new(operation_key, 0),
                expansion(3),
                foreign_definition,
                "foreign::unsafe_macro",
            ))
            .unwrap();
        builder
            .relate(
                function,
                &frame,
                &FunctionEntersUnsafeOperationMacroExpansion::new(),
            )
            .unwrap();
        builder
            .relate(
                &frame,
                &operation,
                &UnsafeOperationMacroExpansionProducesUnsafeOperation::new(),
            )
            .unwrap();
    }

    fn insert_typed_definition_reference(
        builder: &mut ArtifactDbBuilder,
        function: &EntityHandle<FunctionEntity>,
        owner: FunctionKey,
        referenced_stable_crate_id: u64,
        kind: TypedDefinitionReferenceKind,
    ) {
        let foreign_definition = definition(referenced_stable_crate_id, 9);
        match kind {
            TypedDefinitionReferenceKind::CallableDefinition => {
                insert_callable_definition_reference(builder, foreign_definition);
            }
            TypedDefinitionReferenceKind::DynamicDispatchKey => {
                insert_dynamic_dispatch_reference(builder, function, owner, foreign_definition);
            }
            TypedDefinitionReferenceKind::EffectMacro => {
                insert_effect_macro_reference(builder, function, owner, foreign_definition);
            }
            TypedDefinitionReferenceKind::CallMacro => {
                insert_call_macro_reference(builder, function, owner, foreign_definition);
            }
            TypedDefinitionReferenceKind::UnsafeOperationMacro => {
                insert_unsafe_macro_reference(builder, function, owner, foreign_definition);
            }
        }
    }

    fn artifact_with_typed_definition_reference(
        registry: &AnalysisRegistry<CollectedArtifact>,
        owner: u64,
        referenced_stable_crate_id: u64,
        kind: TypedDefinitionReferenceKind,
    ) -> ArtifactFactIr {
        let mut builder = declared_builder(registry);
        let (function, local_key) = insert_local_function(&mut builder, owner);
        insert_typed_definition_reference(
            &mut builder,
            &function,
            local_key,
            referenced_stable_crate_id,
            kind,
        );
        builder.finalize(registry.schemas()).unwrap()
    }

    fn artifact_with_function_pointer_type_hash(
        registry: &AnalysisRegistry<CollectedArtifact>,
        owner: u64,
    ) -> ArtifactFactIr {
        let mut builder = declared_builder(registry);
        let (function, local_key) = insert_local_function(&mut builder, owner);
        let group = insert_safety_group(&mut builder, &function, local_key);
        let occurrence = insert_call_occurrence(
            &mut builder,
            &function,
            local_key,
            &group,
            CallKind::IndirectCall,
        );
        let key = builder
            .insert_entity(&CallableKeyEntity::new(CallableKey::FnPointer(type_hash(
                2, 9,
            ))))
            .unwrap();
        builder
            .relate(&occurrence, &key, &CallOccurrenceHasCallableKey::new())
            .unwrap();
        builder.finalize(registry.schemas()).unwrap()
    }

    fn workspace<'a>(
        registry: &'a AnalysisRegistry<CollectedArtifact>,
        artifacts: &'a [(ManagedArtifactGeneration, ArtifactFactIr)],
    ) -> WorkspaceFactView<'a> {
        WorkspaceFactView::compose(artifacts.iter().map(|(generation, artifact)| {
            (
                generation.scope().unwrap(),
                ArtifactDbView::open(artifact, registry.schemas()).unwrap(),
            )
        }))
        .unwrap()
    }

    fn authority_inventory_metrics(
        registry: &AnalysisRegistry<CollectedArtifact>,
        root_references: &[u64],
    ) -> ReachabilityMetrics {
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let dependencies = [
            ManagedArtifactGeneration::persisted(artifact_id(2, '2')),
            ManagedArtifactGeneration::persisted(artifact_id(3, '3')),
            ManagedArtifactGeneration::persisted(artifact_id(4, '4')),
            ManagedArtifactGeneration::persisted(artifact_id(5, '5')),
        ];
        let mut artifacts = vec![(root.clone(), artifact(registry, 1, root_references))];
        artifacts.extend(dependencies.iter().cloned().map(|generation| {
            let owner = generation.stable_crate_id();
            (generation, artifact(registry, owner, &[]))
        }));
        let workspace = workspace(registry, &artifacts);
        let root_dependencies = dependencies
            .iter()
            .map(|generation| match generation {
                ManagedArtifactGeneration::Persisted(artifact) => artifact.clone(),
                ManagedArtifactGeneration::InMemory { .. } => unreachable!(),
            })
            .collect();
        let managed_dependencies = dependencies
            .iter()
            .cloned()
            .map(|generation| ManagedArtifactManifest::new(generation, Vec::new()));

        reset_reachability_metrics();
        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root, root_dependencies),
            managed_dependencies,
            [],
        )
        .unwrap();
        drop(closure);
        reachability_metrics()
    }

    fn large_chain_and_fanout_metrics(
        registry: &AnalysisRegistry<CollectedArtifact>,
        node_count: u64,
    ) -> ReachabilityMetrics {
        assert!(node_count >= 2);
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let persisted_id = |stable_crate_id| {
            RustcArtifactId::new(stable_crate_id, format!("{stable_crate_id:032x}"))
        };
        let mut artifacts = vec![(
            root.clone(),
            artifact(registry, 1, &(2..=node_count).collect::<Vec<_>>()),
        )];
        let mut manifests = Vec::new();
        for stable_crate_id in 2..=node_count {
            let generation = ManagedArtifactGeneration::persisted(persisted_id(stable_crate_id));
            let references = (stable_crate_id < node_count)
                .then_some(stable_crate_id + 1)
                .into_iter()
                .collect::<Vec<_>>();
            artifacts.push((
                generation.clone(),
                artifact(registry, stable_crate_id, &references),
            ));
            let dependencies = references.into_iter().map(persisted_id).collect();
            manifests.push(ManagedArtifactManifest::new(generation, dependencies));
        }
        let workspace = workspace(registry, &artifacts);
        let root_dependencies = (2..=node_count).map(persisted_id).collect();

        reset_reachability_metrics();
        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root, root_dependencies),
            manifests,
            [],
        )
        .unwrap();
        drop(closure);
        reachability_metrics()
    }

    #[test]
    fn every_typed_definition_reference_requires_contextual_classification() {
        let registry = registry();
        for kind in TypedDefinitionReferenceKind::ALL {
            let root = ManagedArtifactGeneration::in_memory(1, 0);
            let artifacts = vec![(
                root.clone(),
                artifact_with_typed_definition_reference(&registry, 1, 2, kind),
            )];
            let workspace = workspace(&registry, &artifacts);

            let error = VerifiedWorkspaceClosure::open(
                &workspace,
                ManagedArtifactManifest::new(root.clone(), Vec::new()),
                [],
                [],
            )
            .unwrap_err();

            assert_eq!(
                error,
                VerifiedWorkspaceClosureError::ReferencedDefinitionUnclassified {
                    preferred_scope: root.scope().unwrap(),
                    stable_crate_id: 2,
                },
                "typed reference kind {kind:?} escaped classification"
            );
        }
    }

    #[test]
    fn every_typed_definition_reference_accepts_an_exact_unmanaged_generation() {
        let registry = registry();
        for kind in TypedDefinitionReferenceKind::ALL {
            let root = ManagedArtifactGeneration::in_memory(1, 0);
            let artifacts = vec![(
                root.clone(),
                artifact_with_typed_definition_reference(&registry, 1, 2, kind),
            )];
            let workspace = workspace(&registry, &artifacts);
            let unmanaged = artifact_id(2, '2');

            let closure = VerifiedWorkspaceClosure::open(
                &workspace,
                ManagedArtifactManifest::new(root.clone(), vec![unmanaged.clone()]),
                [],
                [unmanaged.clone()],
            )
            .unwrap_or_else(|error| {
                panic!("typed reference kind {kind:?} rejected unmanaged authority: {error}")
            });

            assert_eq!(
                closure.definition_resolution(closure.root_scope(), 2),
                Some(&VerifiedDefinitionResolution::Unmanaged(unmanaged)),
                "typed reference kind {kind:?} lost unmanaged authority"
            );
        }
    }

    #[test]
    fn every_typed_definition_reference_accepts_a_reachable_managed_generation() {
        let registry = registry();
        for kind in TypedDefinitionReferenceKind::ALL {
            let root = ManagedArtifactGeneration::in_memory(1, 0);
            let defining = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
            let artifacts = vec![
                (
                    root.clone(),
                    artifact_with_typed_definition_reference(&registry, 1, 2, kind),
                ),
                (defining.clone(), artifact(&registry, 2, &[])),
            ];
            let workspace = workspace(&registry, &artifacts);

            let closure = VerifiedWorkspaceClosure::open(
                &workspace,
                ManagedArtifactManifest::new(root, vec![artifact_id(2, '2')]),
                [ManagedArtifactManifest::new(defining.clone(), Vec::new())],
                [],
            )
            .unwrap_or_else(|error| {
                panic!("typed reference kind {kind:?} rejected managed authority: {error}")
            });

            assert_eq!(
                closure.definition_resolution(closure.root_scope(), 2),
                Some(&VerifiedDefinitionResolution::Managed(
                    defining.scope().unwrap()
                )),
                "typed reference kind {kind:?} lost managed authority"
            );
        }
    }

    #[test]
    fn function_pointer_type_hashes_do_not_claim_definition_authority() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(
            root.clone(),
            artifact_with_function_pointer_type_hash(&registry, 1),
        )];
        let workspace = workspace(&registry, &artifacts);

        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), Vec::new()),
            [],
            [],
        )
        .unwrap();
        let root_scope = root.scope().unwrap();

        assert_eq!(
            closure.definition_resolution(&root_scope, 1),
            Some(&VerifiedDefinitionResolution::Managed(root_scope))
        );
        assert_eq!(closure.definition_resolution(closure.root_scope(), 2), None);
    }

    #[test]
    fn explicit_unmanaged_identity_satisfies_a_typed_definition_reference() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[2]))];
        let workspace = workspace(&registry, &artifacts);

        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), vec![artifact_id(2, '2')]),
            [],
            [artifact_id(2, '2')],
        )
        .unwrap();

        assert_eq!(closure.root_scope(), &root.scope().unwrap());
        assert_eq!(closure.owners().len(), 1);
        assert_eq!(closure.owners()[0].stable_crate_id(), 1);
        assert_eq!(
            closure.definition_resolution(closure.root_scope(), 2),
            Some(&VerifiedDefinitionResolution::Unmanaged(artifact_id(
                2, '2'
            )))
        );
    }

    #[test]
    fn authority_inventory_uses_one_root_traversal_independent_of_reference_count() {
        let registry = registry();

        let one_reference = authority_inventory_metrics(&registry, &[2]);
        let four_references = authority_inventory_metrics(&registry, &[2, 3, 4, 5]);

        assert_eq!(one_reference.traversals, four_references.traversals);
        assert_eq!(one_reference.dependency_edges_examined, 4);
        assert_eq!(four_references.dependency_edges_examined, 4);
        assert_eq!(one_reference.authority_candidates_propagated, 1);
        assert_eq!(one_reference.authority_edges_examined, 1);
        assert_eq!(
            four_references,
            ReachabilityMetrics {
                traversals: 1,
                dependency_edges_examined: 4,
                authority_candidates_propagated: 4,
                authority_edges_examined: 4,
            }
        );
    }

    #[test]
    fn large_chain_and_fanout_does_not_start_one_traversal_per_preferred_scope() {
        let registry = registry();
        let small = large_chain_and_fanout_metrics(&registry, 8);
        let large = large_chain_and_fanout_metrics(&registry, 64);

        assert_eq!(small.traversals, 1);
        assert_eq!(large.traversals, 1);
        assert_eq!(small.authority_candidates_propagated, 7);
        assert_eq!(large.authority_candidates_propagated, 63);
        assert_eq!(small.dependency_edges_examined, 13);
        assert_eq!(large.dependency_edges_examined, 125);
    }

    #[test]
    fn self_owned_typed_definition_has_explicit_managed_authority() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[]))];
        let workspace = workspace(&registry, &artifacts);

        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), Vec::new()),
            [],
            [],
        )
        .unwrap();
        let root_scope = root.scope().unwrap();

        assert_eq!(
            closure.definition_resolution(&root_scope, 1),
            Some(&VerifiedDefinitionResolution::Managed(root_scope))
        );
    }

    #[test]
    fn workspace_scope_set_must_equal_the_declared_managed_closure() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let omitted = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (omitted.clone(), artifact(&registry, 2, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let error = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root, Vec::new()),
            [],
            [],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            VerifiedWorkspaceClosureError::WorkspaceScopeMismatch { .. }
        ));
    }

    #[test]
    fn absent_typed_definition_classification_is_an_error() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[2]))];
        let workspace = workspace(&registry, &artifacts);

        let error = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), Vec::new()),
            [],
            [],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::ReferencedDefinitionUnclassified {
                preferred_scope: root.scope().unwrap(),
                stable_crate_id: 2,
            }
        );
    }

    #[test]
    fn unrelated_unmanaged_inventory_does_not_authorize_an_omitted_context_edge() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[2]))];
        let workspace = workspace(&registry, &artifacts);

        let error = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), Vec::new()),
            [],
            [artifact_id(2, '2')],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::ReferencedDefinitionUnclassified {
                preferred_scope: root.scope().unwrap(),
                stable_crate_id: 2,
            }
        );
    }

    #[test]
    fn managed_definition_must_be_reachable_from_its_referring_generation() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let sibling = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let defining = ManagedArtifactGeneration::persisted(artifact_id(3, '3'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (sibling.clone(), artifact(&registry, 2, &[3])),
            (defining.clone(), artifact(&registry, 3, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let error = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root, vec![artifact_id(2, '2'), artifact_id(3, '3')]),
            [
                ManagedArtifactManifest::new(sibling.clone(), Vec::new()),
                ManagedArtifactManifest::new(defining.clone(), Vec::new()),
            ],
            [],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::ReferencedManagedDefinitionUnreachable {
                preferred_scope: sibling.scope().unwrap(),
                stable_crate_id: 3,
                candidate_scopes: vec![defining.scope().unwrap()],
            }
        );
    }

    #[test]
    fn managed_dependency_generation_must_match_its_exact_declared_identity() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let managed = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (managed.clone(), artifact(&registry, 2, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let error = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), vec![artifact_id(2, '3')]),
            [ManagedArtifactManifest::new(managed.clone(), Vec::new())],
            [],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::DependencyGenerationUnavailable {
                owner_scope: root.scope().unwrap(),
                declared: artifact_id(2, '3'),
                available_scopes: vec![managed.scope().unwrap()],
            }
        );
    }

    #[test]
    fn dependency_edges_require_managed_or_exact_unmanaged_classification() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[]))];
        let workspace = workspace(&registry, &artifacts);

        let error = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), vec![artifact_id(2, '2')]),
            [],
            [],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::DependencyUnclassified {
                owner_scope: root.scope().unwrap(),
                dependency: artifact_id(2, '2'),
            }
        );
    }

    #[test]
    fn direct_dependencies_cannot_reuse_the_owner_stable_crate_identity() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[]))];
        let workspace = workspace(&registry, &artifacts);
        let dependency = artifact_id(1, '1');

        let error = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), vec![dependency.clone()]),
            [],
            [dependency.clone()],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::DependencyUsesOwnerStableCrate {
                owner: root,
                dependency,
            }
        );
    }

    #[test]
    fn one_manifest_cannot_name_two_direct_generations_of_one_dependency() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let owner = ManagedArtifactGeneration::persisted(artifact_id(3, '3'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (owner.clone(), artifact(&registry, 3, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);
        let first = artifact_id(2, '2');
        let second = artifact_id(2, '3');

        let error = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root, vec![artifact_id(3, '3')]),
            [ManagedArtifactManifest::new(
                owner.clone(),
                vec![second.clone(), first.clone()],
            )],
            [first.clone(), second.clone()],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::ConflictingDirectDependencyGenerations {
                owner,
                first,
                second,
            }
        );
    }

    #[test]
    fn repeated_exact_direct_dependency_identity_is_normalized() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[]))];
        let workspace = workspace(&registry, &artifacts);
        let dependency = artifact_id(2, '2');

        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root, vec![dependency.clone(), dependency.clone()]),
            [],
            [dependency],
        )
        .unwrap();

        assert_eq!(closure.owners().len(), 1);
    }

    #[test]
    fn every_declared_managed_generation_must_be_root_reachable() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let unreachable = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (unreachable.clone(), artifact(&registry, 2, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let error = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), Vec::new()),
            [ManagedArtifactManifest::new(
                unreachable.clone(),
                Vec::new(),
            )],
            [],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::UnreachableManagedGenerations {
                root_scope: root.scope().unwrap(),
                unreachable: BTreeSet::from([unreachable.scope().unwrap()]),
            }
        );
    }

    #[test]
    fn one_exact_generation_cannot_be_both_managed_and_unmanaged() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let managed = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (managed.clone(), artifact(&registry, 2, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let error = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root, vec![artifact_id(2, '2')]),
            [ManagedArtifactManifest::new(managed.clone(), Vec::new())],
            [artifact_id(2, '2')],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::ManagedUnmanagedConflict {
                stable_crate_id: 2,
                scope: managed.scope().unwrap(),
            }
        );
    }

    #[test]
    fn one_context_rejects_two_reachable_generations_for_the_same_definition_owner() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let first_context = ManagedArtifactGeneration::persisted(artifact_id(3, '3'));
        let second_context = ManagedArtifactGeneration::persisted(artifact_id(4, '4'));
        let first = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let second = ManagedArtifactGeneration::persisted(artifact_id(2, '3'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[2])),
            (first_context.clone(), artifact(&registry, 3, &[])),
            (second_context.clone(), artifact(&registry, 4, &[])),
            (first.clone(), artifact(&registry, 2, &[])),
            (second.clone(), artifact(&registry, 2, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let error = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(
                root.clone(),
                vec![artifact_id(3, '3'), artifact_id(4, '4')],
            ),
            [
                ManagedArtifactManifest::new(first_context, vec![artifact_id(2, '2')]),
                ManagedArtifactManifest::new(second_context, vec![artifact_id(2, '3')]),
                ManagedArtifactManifest::new(first.clone(), Vec::new()),
                ManagedArtifactManifest::new(second.clone(), Vec::new()),
            ],
            [],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::AmbiguousDefinition {
                preferred_scope: root.scope().unwrap(),
                stable_crate_id: 2,
                managed_scopes: vec![first.scope().unwrap(), second.scope().unwrap()],
                unmanaged_generations: Vec::new(),
            }
        );
    }

    #[test]
    fn distinct_contexts_may_select_different_generations_of_one_definition_owner() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let first_context = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let second_context = ManagedArtifactGeneration::persisted(artifact_id(3, '3'));
        let first_defining = ManagedArtifactGeneration::persisted(artifact_id(4, '4'));
        let second_defining = ManagedArtifactGeneration::persisted(artifact_id(4, '5'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (first_context.clone(), artifact(&registry, 2, &[4])),
            (second_context.clone(), artifact(&registry, 3, &[4])),
            (first_defining.clone(), artifact(&registry, 4, &[])),
            (second_defining.clone(), artifact(&registry, 4, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root, vec![artifact_id(2, '2'), artifact_id(3, '3')]),
            [
                ManagedArtifactManifest::new(first_context.clone(), vec![artifact_id(4, '4')]),
                ManagedArtifactManifest::new(second_context.clone(), vec![artifact_id(4, '5')]),
                ManagedArtifactManifest::new(first_defining.clone(), Vec::new()),
                ManagedArtifactManifest::new(second_defining.clone(), Vec::new()),
            ],
            [],
        )
        .unwrap();

        assert_eq!(
            closure.definition_resolution(&first_context.scope().unwrap(), 4),
            Some(&VerifiedDefinitionResolution::Managed(
                first_defining.scope().unwrap()
            ))
        );
        assert_eq!(
            closure.definition_resolution(&second_context.scope().unwrap(), 4),
            Some(&VerifiedDefinitionResolution::Managed(
                second_defining.scope().unwrap()
            ))
        );
    }

    #[test]
    fn invalid_persisted_identity_is_rejected_before_workspace_matching() {
        let registry = registry();
        let workspace =
            WorkspaceFactView::compose(std::iter::empty::<(ArtifactScopeId, ArtifactDbView<'_>)>())
                .unwrap();
        let invalid = ManagedArtifactGeneration::persisted(RustcArtifactId::new(1, "INVALID"));

        let error = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(invalid.clone(), Vec::new()),
            [],
            [],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            VerifiedWorkspaceClosureError::ArtifactScope {
                generation,
                source: ArtifactScopeIdError::InvalidStrictVersionHash { .. },
            } if generation == invalid
        ));
        drop(registry);
    }

    #[test]
    fn multiple_contexts_may_share_one_reachable_managed_generation() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let first = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let second = ManagedArtifactGeneration::persisted(artifact_id(3, '3'));
        let defining = ManagedArtifactGeneration::persisted(artifact_id(4, '4'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (first.clone(), artifact(&registry, 2, &[4])),
            (second.clone(), artifact(&registry, 3, &[4])),
            (defining.clone(), artifact(&registry, 4, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let closure = VerifiedWorkspaceClosure::open(
            &workspace,
            ManagedArtifactManifest::new(root, vec![artifact_id(2, '2'), artifact_id(3, '3')]),
            [
                ManagedArtifactManifest::new(first, vec![artifact_id(4, '4')]),
                ManagedArtifactManifest::new(second, vec![artifact_id(4, '4')]),
                ManagedArtifactManifest::new(defining, Vec::new()),
            ],
            [],
        )
        .unwrap();

        assert_eq!(closure.owners().len(), 4);
        let _ = closure.program();
        let _ = closure.defining_scopes_handle();
    }

    #[test]
    fn runtime_inventory_completes_typed_unmanaged_references_for_in_memory_and_persisted_roots() {
        let registry = registry();
        for root in [
            ManagedArtifactGeneration::in_memory(1, 0),
            ManagedArtifactGeneration::persisted(artifact_id(1, '1')),
        ] {
            let artifacts = vec![(root.clone(), artifact(&registry, 1, &[2]))];
            let workspace = workspace(&registry, &artifacts);

            let closure = VerifiedWorkspaceClosure::open_with_runtime_inventory(
                &workspace,
                ManagedArtifactManifest::new(root, Vec::new()),
                [],
                [artifact_id(2, '2')],
            )
            .unwrap();

            assert_eq!(
                closure.definition_resolution(closure.root_scope(), 2),
                Some(&VerifiedDefinitionResolution::Unmanaged(artifact_id(
                    2, '2'
                )))
            );
        }
    }

    #[test]
    fn runtime_inventory_requires_every_typed_unmanaged_identity() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[2]))];
        let workspace = workspace(&registry, &artifacts);

        let error = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), Vec::new()),
            [],
            [],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::RuntimeArtifactUnavailable {
                stable_crate_id: 2,
                referring_scopes: BTreeSet::from([root.scope().unwrap()]),
            }
        );
    }

    #[test]
    fn repeated_exact_runtime_identity_is_normalized() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[2]))];
        let workspace = workspace(&registry, &artifacts);
        let runtime = artifact_id(2, '2');

        let closure = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root, Vec::new()),
            [],
            [runtime.clone(), runtime.clone()],
        )
        .unwrap();

        assert_eq!(
            closure.definition_resolution(closure.root_scope(), 2),
            Some(&VerifiedDefinitionResolution::Unmanaged(runtime))
        );
    }

    #[test]
    fn conflicting_runtime_generations_are_rejected_with_all_referring_contexts() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[2]))];
        let workspace = workspace(&registry, &artifacts);
        let first = artifact_id(2, '2');
        let second = artifact_id(2, '3');

        let error = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), Vec::new()),
            [],
            [second.clone(), first.clone()],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::ConflictingRuntimeArtifactGenerations {
                stable_crate_id: 2,
                referring_scopes: BTreeSet::from([root.scope().unwrap()]),
                artifacts: vec![first, second],
            }
        );
    }

    #[test]
    fn runtime_edges_are_added_only_to_their_typed_referring_contexts() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let referring = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let other = ManagedArtifactGeneration::persisted(artifact_id(3, '3'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (referring.clone(), artifact(&registry, 2, &[4])),
            (other.clone(), artifact(&registry, 3, &[5])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let closure = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root, vec![artifact_id(2, '2'), artifact_id(3, '3')]),
            [
                ManagedArtifactManifest::new(referring.clone(), Vec::new()),
                ManagedArtifactManifest::new(other.clone(), Vec::new()),
            ],
            [artifact_id(4, '4'), artifact_id(5, '5')],
        )
        .unwrap();

        assert_eq!(
            closure.definition_resolution(&referring.scope().unwrap(), 4),
            Some(&VerifiedDefinitionResolution::Unmanaged(artifact_id(
                4, '4'
            )))
        );
        assert_eq!(
            closure.definition_resolution(&other.scope().unwrap(), 5),
            Some(&VerifiedDefinitionResolution::Unmanaged(artifact_id(
                5, '5'
            )))
        );
        assert_eq!(
            closure.definition_resolution(&referring.scope().unwrap(), 5),
            None
        );
        assert_eq!(
            closure.definition_resolution(&other.scope().unwrap(), 4),
            None
        );
    }

    #[test]
    fn unrelated_runtime_inventory_is_not_added_to_the_closure() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[2]))];
        let workspace = workspace(&registry, &artifacts);

        let closure = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root, Vec::new()),
            [],
            [artifact_id(9, '9'), artifact_id(2, '2')],
        )
        .unwrap();

        assert_eq!(
            closure.definition_resolution(closure.root_scope(), 2),
            Some(&VerifiedDefinitionResolution::Unmanaged(artifact_id(
                2, '2'
            )))
        );
        assert_eq!(closure.definition_resolution(closure.root_scope(), 9), None);
    }

    #[test]
    fn typed_managed_reference_uses_a_transitively_reachable_exact_generation() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let intermediate = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let defining = ManagedArtifactGeneration::persisted(artifact_id(3, '3'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[3])),
            (intermediate.clone(), artifact(&registry, 2, &[])),
            (defining.clone(), artifact(&registry, 3, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let closure = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root, vec![artifact_id(2, '2')]),
            [
                ManagedArtifactManifest::new(intermediate, vec![artifact_id(3, '3')]),
                ManagedArtifactManifest::new(defining.clone(), Vec::new()),
            ],
            [artifact_id(3, '4')],
        )
        .unwrap();

        assert_eq!(
            closure.definition_resolution(closure.root_scope(), 3),
            Some(&VerifiedDefinitionResolution::Managed(
                defining.scope().unwrap()
            ))
        );
    }

    #[test]
    fn wrong_managed_generation_is_not_reclassified_from_runtime_inventory() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let managed = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[2])),
            (managed.clone(), artifact(&registry, 2, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let error = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), vec![artifact_id(2, '3')]),
            [ManagedArtifactManifest::new(managed.clone(), Vec::new())],
            [artifact_id(2, '3')],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::DependencyGenerationUnavailable {
                owner_scope: root.scope().unwrap(),
                declared: artifact_id(2, '3'),
                available_scopes: vec![managed.scope().unwrap()],
            }
        );
    }

    #[test]
    fn unreachable_managed_definition_is_not_reclassified_from_runtime_inventory() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let referring = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let defining = ManagedArtifactGeneration::persisted(artifact_id(3, '3'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (referring.clone(), artifact(&registry, 2, &[3])),
            (defining.clone(), artifact(&registry, 3, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let error = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root, vec![artifact_id(2, '2'), artifact_id(3, '3')]),
            [
                ManagedArtifactManifest::new(referring.clone(), Vec::new()),
                ManagedArtifactManifest::new(defining.clone(), Vec::new()),
            ],
            [artifact_id(3, '4')],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::ReferencedManagedDefinitionUnreachable {
                preferred_scope: referring.scope().unwrap(),
                stable_crate_id: 3,
                candidate_scopes: vec![defining.scope().unwrap()],
            }
        );
    }

    #[test]
    fn self_owned_typed_references_never_create_runtime_dependencies() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[]))];
        let workspace = workspace(&registry, &artifacts);

        let closure = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), Vec::new()),
            [],
            [artifact_id(1, '9')],
        )
        .unwrap();

        assert_eq!(
            closure.definition_resolution(closure.root_scope(), 1),
            Some(&VerifiedDefinitionResolution::Managed(
                root.scope().unwrap()
            ))
        );
    }

    #[test]
    fn runtime_inventory_does_not_classify_unreferenced_manifest_edges() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[]))];
        let workspace = workspace(&registry, &artifacts);
        let dependency = artifact_id(2, '2');

        let error = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), vec![dependency.clone()]),
            [],
            [dependency.clone()],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::DependencyUnclassified {
                owner_scope: root.scope().unwrap(),
                dependency,
            }
        );
    }

    #[test]
    fn malformed_selected_runtime_identity_retains_artifact_and_referrer_context() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[2]))];
        let workspace = workspace(&registry, &artifacts);
        let invalid = RustcArtifactId::new(2, "INVALID");

        let error = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), Vec::new()),
            [],
            [invalid.clone()],
        )
        .unwrap_err();

        assert!(matches!(
            &error,
            VerifiedWorkspaceClosureError::RuntimeArtifactScope {
                artifact,
                referring_scopes,
                source: ArtifactScopeIdError::InvalidStrictVersionHash { .. },
            } if artifact == &invalid
                && referring_scopes == &BTreeSet::from([root.scope().unwrap()])
        ));
        assert!(error.source().is_some());
    }

    #[test]
    fn malformed_manifest_dependency_retains_owner_and_artifact_context() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let artifacts = vec![(root.clone(), artifact(&registry, 1, &[]))];
        let workspace = workspace(&registry, &artifacts);
        let invalid = RustcArtifactId::new(2, "INVALID");

        let error = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root.clone(), vec![invalid.clone()]),
            [],
            [],
        )
        .unwrap_err();

        assert!(matches!(
            &error,
            VerifiedWorkspaceClosureError::DependencyArtifactScope {
                owner_scope,
                dependency,
                source: ArtifactScopeIdError::InvalidStrictVersionHash { .. },
            } if owner_scope == &root.scope().unwrap() && dependency == &invalid
        ));
        assert!(error.source().is_some());
    }

    #[test]
    fn runtime_conflict_reports_every_typed_referring_scope() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let first_context = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let second_context = ManagedArtifactGeneration::persisted(artifact_id(3, '3'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (first_context.clone(), artifact(&registry, 2, &[4])),
            (second_context.clone(), artifact(&registry, 3, &[4])),
        ];
        let workspace = workspace(&registry, &artifacts);
        let first = artifact_id(4, '4');
        let second = artifact_id(4, '5');

        let error = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root, vec![artifact_id(2, '2'), artifact_id(3, '3')]),
            [
                ManagedArtifactManifest::new(first_context.clone(), Vec::new()),
                ManagedArtifactManifest::new(second_context.clone(), Vec::new()),
            ],
            [second.clone(), first.clone()],
        )
        .unwrap_err();

        assert_eq!(
            error,
            VerifiedWorkspaceClosureError::ConflictingRuntimeArtifactGenerations {
                stable_crate_id: 4,
                referring_scopes: BTreeSet::from([
                    first_context.scope().unwrap(),
                    second_context.scope().unwrap(),
                ]),
                artifacts: vec![first, second],
            }
        );
    }

    #[test]
    fn runtime_constructor_preserves_distinct_managed_generation_contexts() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let first_context = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let second_context = ManagedArtifactGeneration::persisted(artifact_id(3, '3'));
        let first_defining = ManagedArtifactGeneration::persisted(artifact_id(4, '4'));
        let second_defining = ManagedArtifactGeneration::persisted(artifact_id(4, '5'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (first_context.clone(), artifact(&registry, 2, &[4])),
            (second_context.clone(), artifact(&registry, 3, &[4])),
            (first_defining.clone(), artifact(&registry, 4, &[])),
            (second_defining.clone(), artifact(&registry, 4, &[])),
        ];
        let workspace = workspace(&registry, &artifacts);

        let closure = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            ManagedArtifactManifest::new(root, vec![artifact_id(2, '2'), artifact_id(3, '3')]),
            [
                ManagedArtifactManifest::new(first_context.clone(), vec![artifact_id(4, '4')]),
                ManagedArtifactManifest::new(second_context.clone(), vec![artifact_id(4, '5')]),
                ManagedArtifactManifest::new(first_defining.clone(), Vec::new()),
                ManagedArtifactManifest::new(second_defining.clone(), Vec::new()),
            ],
            [artifact_id(4, '9')],
        )
        .unwrap();

        assert_eq!(
            closure.definition_resolution(&first_context.scope().unwrap(), 4),
            Some(&VerifiedDefinitionResolution::Managed(
                first_defining.scope().unwrap()
            ))
        );
        assert_eq!(
            closure.definition_resolution(&second_context.scope().unwrap(), 4),
            Some(&VerifiedDefinitionResolution::Managed(
                second_defining.scope().unwrap()
            ))
        );
    }

    #[test]
    fn runtime_constructor_is_deterministic_under_reversed_inputs() {
        let registry = registry();
        let root = ManagedArtifactGeneration::in_memory(1, 0);
        let first_context = ManagedArtifactGeneration::persisted(artifact_id(2, '2'));
        let second_context = ManagedArtifactGeneration::persisted(artifact_id(3, '3'));
        let artifacts = vec![
            (root.clone(), artifact(&registry, 1, &[])),
            (first_context.clone(), artifact(&registry, 2, &[4])),
            (second_context.clone(), artifact(&registry, 3, &[5])),
        ];
        let workspace = workspace(&registry, &artifacts);
        let root_manifest =
            ManagedArtifactManifest::new(root, vec![artifact_id(3, '3'), artifact_id(2, '2')]);
        let first_manifest = ManagedArtifactManifest::new(first_context.clone(), Vec::new());
        let second_manifest = ManagedArtifactManifest::new(second_context.clone(), Vec::new());

        let forward = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            root_manifest.clone(),
            [first_manifest.clone(), second_manifest.clone()],
            [artifact_id(4, '4'), artifact_id(5, '5')],
        )
        .unwrap();
        let reversed = VerifiedWorkspaceClosure::open_with_runtime_inventory(
            &workspace,
            root_manifest,
            [second_manifest, first_manifest],
            [artifact_id(5, '5'), artifact_id(4, '4')],
        )
        .unwrap();

        assert_eq!(forward.root_scope(), reversed.root_scope());
        assert_eq!(forward.owners(), reversed.owners());
        for (scope, stable_crate_id) in [
            (first_context.scope().unwrap(), 4),
            (second_context.scope().unwrap(), 5),
        ] {
            assert_eq!(
                forward.definition_resolution(&scope, stable_crate_id),
                reversed.definition_resolution(&scope, stable_crate_id)
            );
        }
    }
}
