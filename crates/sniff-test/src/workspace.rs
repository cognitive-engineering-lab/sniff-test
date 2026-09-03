//! Loading and validation of direct, versioned artifact-fact caches.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};

use crate::artifact::{FunctionFactProvenance, SourceFileFact, SourceFileId};
use crate::artifact_cache::{
    ArtifactAnalysisCache, ArtifactInfo, CacheError, CacheExpectations, RustcArtifactId,
    artifact_cache_path,
};

/// One path-bearing rustc `--extern` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternArtifactInput {
    pub(crate) name: String,
    pub(crate) artifact_id: RustcArtifactId,
}

/// A structured reason why an artifact could not join the composed graph.
#[derive(Debug)]
pub(crate) enum GraphLoadFailure {
    Missing {
        artifact_id: RustcArtifactId,
        path: PathBuf,
    },
    Invalid {
        artifact_id: RustcArtifactId,
        error: CacheError,
    },
    ArtifactIdentityMismatch {
        expected: RustcArtifactId,
        found: RustcArtifactId,
    },
    StableCrateIdConflict {
        stable_crate_id: u64,
        artifacts: Vec<RustcArtifactId>,
    },
    ConflictingFunctionDefinition {
        display_path: String,
        first_artifact: RustcArtifactId,
        second_artifact: RustcArtifactId,
    },
    Cycle {
        artifacts: Vec<RustcArtifactId>,
        direct_aliases: Vec<String>,
    },
}

impl Display for GraphLoadFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { artifact_id, path } => write!(
                formatter,
                "missing artifact facts for {} at {}",
                artifact_id,
                path.display()
            ),
            Self::Invalid { artifact_id, error } => {
                write!(
                    formatter,
                    "invalid artifact facts for {artifact_id}: {error}"
                )
            }
            Self::ArtifactIdentityMismatch { expected, found } => {
                write!(
                    formatter,
                    "artifact facts for {expected} identifies itself as {found}"
                )
            }
            Self::StableCrateIdConflict {
                stable_crate_id,
                artifacts,
            } => write!(
                formatter,
                "rustc crate graph contains multiple SVHs for stable crate id \
                 {stable_crate_id:016x}: {}",
                artifacts
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::ConflictingFunctionDefinition {
                display_path,
                first_artifact,
                second_artifact,
            } => write!(
                formatter,
                "function `{display_path}` is defined by both artifact {first_artifact} and artifact {second_artifact}",
            ),
            Self::Cycle {
                artifacts,
                direct_aliases,
            } => {
                write!(
                    formatter,
                    "artifact analysis dependency cycle: {}",
                    artifacts
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" -> ")
                )?;
                if !direct_aliases.is_empty() {
                    write!(
                        formatter,
                        " (reachable from direct extern aliases {})",
                        direct_aliases.join(", ")
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for GraphLoadFailure {}

#[derive(Debug, Clone, Copy)]
struct FunctionLocation {
    artifact: usize,
}

#[derive(Debug, Clone, Copy)]
struct SourceLocation {
    artifact: usize,
    source: usize,
}

/// All verified artifacts reachable from the active rustc externs.
#[derive(Debug, Default)]
pub(crate) struct ArtifactAnalysisGraph {
    artifacts: Vec<ArtifactAnalysisCache>,
    artifact_indices: BTreeMap<RustcArtifactId, usize>,
    stable_crate_indices: HashMap<u64, usize>,
    direct_aliases: BTreeMap<RustcArtifactId, BTreeSet<String>>,
    sources: HashMap<SourceFileId, SourceLocation>,
    failures: Vec<GraphLoadFailure>,
}

impl ArtifactAnalysisGraph {
    #[must_use]
    pub(crate) fn load(
        cache_dir: &Path,
        externs: &[ExternArtifactInput],
        expected: &CacheExpectations<'_>,
    ) -> Self {
        Self::load_with(cache_dir, externs, |_, path| {
            ArtifactAnalysisCache::read(path, expected)
        })
    }

    fn load_with(
        cache_dir: &Path,
        externs: &[ExternArtifactInput],
        read: impl FnMut(&RustcArtifactId, &Path) -> Result<ArtifactAnalysisCache, CacheError>,
    ) -> Self {
        GraphLoader::new(cache_dir, externs, read).load()
    }

    fn from_loaded(
        loaded: BTreeMap<RustcArtifactId, ArtifactAnalysisCache>,
        direct_aliases: BTreeMap<RustcArtifactId, BTreeSet<String>>,
        mut failures: Vec<GraphLoadFailure>,
    ) -> Self {
        let artifacts = loaded.into_values().collect::<Vec<_>>();
        let mut artifact_indices = BTreeMap::new();
        let mut stable_crate_indices = HashMap::new();
        let mut defining_functions = HashMap::new();
        let mut sources = HashMap::new();
        for (artifact, analysis) in artifacts.iter().enumerate() {
            artifact_indices.insert(analysis.artifact.id.clone(), artifact);
            stable_crate_indices.insert(analysis.artifact.id.stable_crate_id, artifact);
            for body in &analysis.facts.functions {
                if matches!(body.provenance, FunctionFactProvenance::DefiningArtifact) {
                    match defining_functions.entry(body.function) {
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert(FunctionLocation { artifact });
                        }
                        std::collections::hash_map::Entry::Occupied(entry) => {
                            let first = &artifacts[entry.get().artifact];
                            failures.push(GraphLoadFailure::ConflictingFunctionDefinition {
                                display_path: body.display_path.clone(),
                                first_artifact: first.artifact.id.clone(),
                                second_artifact: analysis.artifact.id.clone(),
                            });
                        }
                    }
                }
            }
            for (source, file) in analysis.facts.source_files.iter().enumerate() {
                sources
                    .entry(file.id.clone())
                    .or_insert(SourceLocation { artifact, source });
            }
        }
        Self {
            artifacts,
            artifact_indices,
            stable_crate_indices,
            direct_aliases,
            sources,
            failures,
        }
    }

    pub(crate) fn artifacts(&self) -> impl Iterator<Item = &ArtifactAnalysisCache> {
        self.artifacts.iter()
    }

    #[must_use]
    pub(crate) fn artifact(&self, artifact_id: &RustcArtifactId) -> Option<&ArtifactAnalysisCache> {
        self.artifact_indices
            .get(artifact_id)
            .map(|index| &self.artifacts[*index])
    }

    /// Returns the persisted ownership metadata for the one exact artifact
    /// loaded under this stable crate identity.
    #[must_use]
    pub(crate) fn artifact_info_by_stable_crate_id(
        &self,
        stable_crate_id: u64,
    ) -> Option<&ArtifactInfo> {
        self.stable_crate_indices
            .get(&stable_crate_id)
            .map(|index| &self.artifacts[*index].artifact)
    }

    #[must_use]
    pub(crate) fn source_file(
        &self,
        source_file: &SourceFileId,
    ) -> Option<(&ArtifactInfo, &SourceFileFact)> {
        let location = self.sources.get(source_file)?;
        let artifact = &self.artifacts[location.artifact];
        Some((
            &artifact.artifact,
            &artifact.facts.source_files[location.source],
        ))
    }

    /// Direct rustc artifact identities that were read and verified.
    pub(crate) fn direct_dependency_ids(&self) -> impl Iterator<Item = RustcArtifactId> + '_ {
        self.direct_aliases.keys().filter_map(|artifact_id| {
            self.artifact(artifact_id)
                .map(|analysis| analysis.artifact.id.clone())
        })
    }

    pub(crate) fn failures(&self) -> impl Iterator<Item = &GraphLoadFailure> {
        self.failures.iter()
    }

    #[must_use]
    pub(crate) fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }
}

struct GraphLoader<'a, R> {
    cache_dir: &'a Path,
    read: R,
    direct_aliases: BTreeMap<RustcArtifactId, BTreeSet<String>>,
    pending: VecDeque<RustcArtifactId>,
    attempted: BTreeSet<RustcArtifactId>,
    rejected: BTreeSet<RustcArtifactId>,
    loaded: BTreeMap<RustcArtifactId, ArtifactAnalysisCache>,
    failures: Vec<GraphLoadFailure>,
}

impl<'a, R> GraphLoader<'a, R>
where
    R: FnMut(&RustcArtifactId, &Path) -> Result<ArtifactAnalysisCache, CacheError>,
{
    fn new(cache_dir: &'a Path, externs: &[ExternArtifactInput], read: R) -> Self {
        let mut direct_aliases = BTreeMap::<RustcArtifactId, BTreeSet<String>>::new();
        for dependency in externs {
            direct_aliases
                .entry(dependency.artifact_id.clone())
                .or_default()
                .insert(dependency.name.clone());
        }
        let pending = direct_aliases.keys().cloned().collect();
        Self {
            cache_dir,
            read,
            direct_aliases,
            pending,
            attempted: BTreeSet::new(),
            rejected: BTreeSet::new(),
            loaded: BTreeMap::new(),
            failures: Vec::new(),
        }
    }

    fn load(mut self) -> ArtifactAnalysisGraph {
        while let Some(artifact_id) = self.pending.pop_front() {
            self.load_artifact(&artifact_id);
        }
        self.reject_stable_crate_id_conflicts();
        self.reject_cycle();
        ArtifactAnalysisGraph::from_loaded(self.loaded, self.direct_aliases, self.failures)
    }

    fn load_artifact(&mut self, artifact_id: &RustcArtifactId) {
        if self.rejected.contains(artifact_id)
            || self.loaded.contains_key(artifact_id)
            || !self.attempted.insert(artifact_id.clone())
        {
            return;
        }

        let Some(analysis) = self.read_artifact(artifact_id) else {
            return;
        };
        if analysis.artifact.id != *artifact_id {
            let found = analysis.artifact.id;
            self.failures
                .push(GraphLoadFailure::ArtifactIdentityMismatch {
                    expected: artifact_id.clone(),
                    found,
                });
            self.rejected.insert(artifact_id.clone());
            return;
        }

        for dependency in &analysis.dependencies {
            self.pending.push_back(dependency.clone());
        }
        self.loaded.insert(artifact_id.clone(), analysis);
    }

    fn read_artifact(&mut self, artifact_id: &RustcArtifactId) -> Option<ArtifactAnalysisCache> {
        let path = artifact_cache_path(self.cache_dir, artifact_id);
        match (self.read)(artifact_id, &path) {
            Ok(analysis) => Some(analysis),
            Err(error) if error.is_missing_file() => {
                self.failures.push(GraphLoadFailure::Missing {
                    artifact_id: artifact_id.clone(),
                    path,
                });
                self.rejected.insert(artifact_id.clone());
                None
            }
            Err(error) => {
                self.failures.push(GraphLoadFailure::Invalid {
                    artifact_id: artifact_id.clone(),
                    error,
                });
                self.rejected.insert(artifact_id.clone());
                None
            }
        }
    }

    fn reject_stable_crate_id_conflicts(&mut self) {
        let mut artifacts_by_stable_id = BTreeMap::<u64, Vec<RustcArtifactId>>::new();
        for artifact_id in self.loaded.keys() {
            artifacts_by_stable_id
                .entry(artifact_id.stable_crate_id)
                .or_default()
                .push(artifact_id.clone());
        }
        for (stable_crate_id, artifacts) in artifacts_by_stable_id {
            if artifacts.len() < 2 {
                continue;
            }
            self.failures.push(GraphLoadFailure::StableCrateIdConflict {
                stable_crate_id,
                artifacts: artifacts.clone(),
            });
            for artifact in artifacts {
                self.loaded.remove(&artifact);
            }
        }
    }

    fn reject_cycle(&mut self) {
        let Some(artifacts) = find_dependency_cycle(&self.loaded) else {
            return;
        };
        let direct_aliases = artifacts
            .iter()
            .filter_map(|artifact_id| self.direct_aliases.get(artifact_id))
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        self.failures.push(GraphLoadFailure::Cycle {
            artifacts: artifacts.clone(),
            direct_aliases,
        });
        for artifact_id in artifacts {
            self.loaded.remove(&artifact_id);
        }
    }
}

fn find_dependency_cycle(
    artifacts: &BTreeMap<RustcArtifactId, ArtifactAnalysisCache>,
) -> Option<Vec<RustcArtifactId>> {
    let mut finished = BTreeSet::new();
    let mut active = BTreeMap::<RustcArtifactId, usize>::new();
    let mut stack = Vec::new();
    for artifact_id in artifacts.keys() {
        if let Some(cycle) = visit_artifact(
            artifact_id,
            artifacts,
            &mut finished,
            &mut active,
            &mut stack,
        ) {
            return Some(cycle);
        }
    }
    None
}

fn visit_artifact(
    artifact_id: &RustcArtifactId,
    artifacts: &BTreeMap<RustcArtifactId, ArtifactAnalysisCache>,
    finished: &mut BTreeSet<RustcArtifactId>,
    active: &mut BTreeMap<RustcArtifactId, usize>,
    stack: &mut Vec<RustcArtifactId>,
) -> Option<Vec<RustcArtifactId>> {
    if finished.contains(artifact_id) {
        return None;
    }
    if let Some(start) = active.get(artifact_id).copied() {
        let mut cycle = stack[start..].to_vec();
        cycle.push(artifact_id.clone());
        return Some(cycle);
    }

    active.insert(artifact_id.clone(), stack.len());
    stack.push(artifact_id.clone());
    let artifact = artifacts
        .get(artifact_id)
        .expect("cycle traversal starts from a loaded artifact");
    for dependency in &artifact.dependencies {
        if !artifacts.contains_key(dependency) {
            continue;
        }
        if let Some(cycle) = visit_artifact(dependency, artifacts, finished, active, stack) {
            return Some(cycle);
        }
    }
    stack.pop();
    active.remove(artifact_id);
    finished.insert(artifact_id.clone());
    None
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;

    use super::{
        ArtifactAnalysisGraph, ExternArtifactInput, GraphLoadFailure, artifact_cache_path,
    };
    use crate::artifact::{
        ArtifactFacts, FunctionAttributesFact, FunctionFact, FunctionFactProvenance, FunctionId,
        SourceFileFact, SourceFileId,
    };
    use crate::artifact_cache::{
        ArtifactAnalysisCache, ArtifactInfo, ArtifactScope, CacheError, CacheExpectations,
        RustcArtifactId,
    };
    use crate::namespace::StableDefPathHash;

    const EXPECTED: CacheExpectations<'static> = CacheExpectations {
        tool_version: "test-tool",
        rustc_version: "test-rustc",
    };

    #[test]
    fn conflicting_function_errors_render_the_human_function_path() {
        let first_artifact = rustc_id(1, &crate_hash(1));
        let second_artifact = rustc_id(2, &crate_hash(2));
        let failure = GraphLoadFailure::ConflictingFunctionDefinition {
            display_path: String::from("crate1::generic_20"),
            first_artifact: first_artifact.clone(),
            second_artifact: second_artifact.clone(),
        };

        assert_eq!(
            failure.to_string(),
            format!(
                "function `crate1::generic_20` is defined by both artifact {first_artifact} and artifact {second_artifact}"
            )
        );
    }

    #[test]
    fn recursively_loads_exact_rustc_artifacts_and_exposes_sources() {
        let directory = tempdir().expect("cache directory");
        let old_child_id = rustc_id(2, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let old_child = analysis_with_id("child-old", old_child_id.clone(), Vec::new(), Vec::new());
        let child = analysis("child-a", 2, Vec::new(), vec![generic_function(2, 20)]);
        let root = analysis(
            "root-a",
            1,
            vec![child.artifact.id.clone()],
            vec![generic_function(1, 10)],
        );
        let root_id = root.artifact.id.clone();
        let child_id = child.artifact.id.clone();
        write(directory.path(), &old_child);
        write(directory.path(), &child);
        write(directory.path(), &root);

        let graph =
            ArtifactAnalysisGraph::load(directory.path(), &[external("root_alias", 1)], &EXPECTED);

        assert!(graph.is_complete());
        assert_eq!(
            graph
                .artifacts()
                .map(|artifact| artifact.artifact.id.clone())
                .collect::<Vec<_>>(),
            [root_id.clone(), child_id]
        );
        assert_eq!(
            graph
                .artifacts()
                .flat_map(|analysis| {
                    analysis.facts.source_files.iter().map(move |source| {
                        (
                            analysis.artifact.crate_name.as_str(),
                            source.filename.as_str(),
                        )
                    })
                })
                .collect::<Vec<_>>(),
            [("root-a", "src/root-a.rs"), ("child-a", "src/child-a.rs")]
        );
        assert_eq!(graph.direct_dependency_ids().collect::<Vec<_>>(), [root_id]);
        assert!(graph.artifact(&old_child_id).is_none());
    }

    #[test]
    fn stable_crate_lookup_preserves_workspace_and_dependency_scope() {
        let directory = tempdir().expect("cache directory");
        let dependency = analysis("third-party", 3, Vec::new(), vec![generic_function(3, 30)]);
        let workspace = analysis_with_scope(
            "workspace-sibling",
            2,
            ArtifactScope::Workspace,
            vec![dependency.artifact.id.clone()],
            vec![generic_function(2, 20)],
        );
        let root = analysis(
            "root",
            1,
            vec![workspace.artifact.id.clone()],
            vec![generic_function(1, 10)],
        );
        write(directory.path(), &dependency);
        write(directory.path(), &workspace);
        write(directory.path(), &root);

        let graph =
            ArtifactAnalysisGraph::load(directory.path(), &[external("root", 1)], &EXPECTED);

        let workspace_owner = graph
            .artifact_info_by_stable_crate_id(2)
            .expect("workspace sibling artifact info");
        assert_eq!(workspace_owner.crate_name, "workspace-sibling");
        assert_eq!(workspace_owner.scope, ArtifactScope::Workspace);
        let dependency_owner = graph
            .artifact_info_by_stable_crate_id(3)
            .expect("dependency artifact info");
        assert_eq!(dependency_owner.crate_name, "third-party");
        assert_eq!(dependency_owner.scope, ArtifactScope::Dependency);
        assert!(graph.artifact_info_by_stable_crate_id(99).is_none());
    }

    #[test]
    fn repeated_aliases_share_one_rustc_artifact_identity() {
        let directory = tempdir().expect("cache directory");
        let artifact = analysis("shared-a", 1, Vec::new(), Vec::new());
        let artifact_id = artifact.artifact.id.clone();
        write(directory.path(), &artifact);

        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[external("first_alias", 1), external("second_alias", 1)],
            &EXPECTED,
        );

        assert_eq!(
            graph
                .direct_aliases
                .get(&artifact_id)
                .expect("aliases for shared artifact")
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["first_alias", "second_alias"]
        );
        assert_eq!(graph.direct_dependency_ids().count(), 1);
    }

    #[test]
    fn artifact_identity_mismatches_are_reported_and_excluded() {
        let directory = tempdir().expect("cache directory");
        let artifact = analysis("root-a", 1, Vec::new(), Vec::new());
        let found = artifact.artifact.id.clone();
        let expected = rustc_id(1, "ffffffffffffffffffffffffffffffff");
        let extern_input = external_with_id("root", expected.clone());

        let graph = ArtifactAnalysisGraph::load_with(directory.path(), &[extern_input], |_, _| {
            Ok(artifact.clone())
        });

        assert!(matches!(
            graph.failures().next(),
            Some(GraphLoadFailure::ArtifactIdentityMismatch {
                expected: actual_expected,
                found: actual,
            }) if actual_expected == &expected && actual == &found
        ));
        assert!(graph.artifact(&expected).is_none());
    }

    #[test]
    fn distinguishes_missing_and_invalid_direct_inputs() {
        let directory = tempdir().expect("cache directory");
        let corrupt_id = rustc_id(1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let missing_id = rustc_id(2, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let corrupt = artifact_cache_path(directory.path(), &corrupt_id);
        fs::create_dir_all(corrupt.parent().expect("cache parent")).expect("create cache parent");
        fs::write(&corrupt, "{not json").expect("write corrupt cache");

        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[
                external_with_id("corrupt_alias", corrupt_id.clone()),
                external_with_id("missing_alias", missing_id.clone()),
            ],
            &EXPECTED,
        );

        assert!(graph.failures().any(|failure| matches!(
            failure,
            GraphLoadFailure::Missing { artifact_id, .. } if artifact_id == &missing_id
        )));
        assert!(graph.failures().any(|failure| matches!(
            failure,
            GraphLoadFailure::Invalid { artifact_id, .. } if artifact_id == &corrupt_id
        )));
        assert_eq!(graph.direct_dependency_ids().count(), 0);
    }

    #[test]
    fn extraction_environment_mismatches_are_reported_as_invalid() {
        let directory = tempdir().expect("cache directory");
        let artifact = analysis("root-a", 1, Vec::new(), Vec::new());
        let artifact_id = artifact.artifact.id.clone();
        write(directory.path(), &artifact);
        let stale_environment = CacheExpectations {
            rustc_version: "different-rustc",
            ..EXPECTED
        };

        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[external("root", 1)],
            &stale_environment,
        );

        assert!(matches!(
            graph.failures().next(),
            Some(GraphLoadFailure::Invalid {
                error: CacheError::Version { field: "rustc", .. },
                ..
            })
        ));
        assert!(graph.artifact(&artifact_id).is_none());
        assert_eq!(graph.direct_dependency_ids().count(), 0);
    }

    #[test]
    fn stable_crate_identity_conflicts_are_reported_and_excluded() {
        let directory = tempdir().expect("cache directory");
        let first_child_id = rustc_id(3, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let second_child_id = rustc_id(3, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let first_child = analysis_with_id(
            "child-first",
            first_child_id.clone(),
            Vec::new(),
            vec![generic_function(3, 30)],
        );
        let second_child = analysis_with_id(
            "child-second",
            second_child_id.clone(),
            Vec::new(),
            vec![generic_function(3, 30)],
        );
        let first = analysis("first-a", 1, vec![first_child_id.clone()], Vec::new());
        let second = analysis("second-a", 2, vec![second_child_id.clone()], Vec::new());
        write(directory.path(), &first_child);
        write(directory.path(), &second_child);
        write(directory.path(), &first);
        write(directory.path(), &second);

        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[external("first", 1), external("second", 2)],
            &EXPECTED,
        );

        assert!(matches!(
            graph.failures().next(),
            Some(GraphLoadFailure::StableCrateIdConflict {
                stable_crate_id: 3,
                artifacts,
            }) if artifacts == &[first_child_id.clone(), second_child_id.clone()]
        ));
        assert!(graph.artifact(&first_child_id).is_none());
        assert!(graph.artifact(&second_child_id).is_none());
        assert!(graph.artifact_info_by_stable_crate_id(3).is_none());
    }

    #[test]
    fn detects_cycles_in_declared_rustc_artifact_edges() {
        let directory = tempdir().expect("cache directory");
        let mut first = analysis("first-a", 1, Vec::new(), Vec::new());
        let mut second = analysis("second-a", 2, Vec::new(), Vec::new());
        let first_id = first.artifact.id.clone();
        let second_id = second.artifact.id.clone();
        first.dependencies = vec![second_id.clone()];
        second.dependencies = vec![first_id.clone()];
        write(directory.path(), &first);
        write(directory.path(), &second);

        let graph =
            ArtifactAnalysisGraph::load(directory.path(), &[external("first", 1)], &EXPECTED);

        assert!(graph.failures().any(|failure| matches!(
            failure,
            GraphLoadFailure::Cycle {
                artifacts,
                direct_aliases,
            } if artifacts == &[first_id.clone(), second_id.clone(), first_id.clone()]
                && direct_aliases == &["first"]
        )));
    }

    fn analysis(
        crate_name: &str,
        stable_crate_id: u64,
        dependencies: Vec<RustcArtifactId>,
        functions: Vec<FunctionFact>,
    ) -> ArtifactAnalysisCache {
        analysis_with_scope(
            crate_name,
            stable_crate_id,
            ArtifactScope::Dependency,
            dependencies,
            functions,
        )
    }

    fn analysis_with_scope(
        crate_name: &str,
        stable_crate_id: u64,
        scope: ArtifactScope,
        dependencies: Vec<RustcArtifactId>,
        functions: Vec<FunctionFact>,
    ) -> ArtifactAnalysisCache {
        analysis_with_id_and_scope(
            crate_name,
            rustc_id(stable_crate_id, &crate_hash(stable_crate_id)),
            scope,
            dependencies,
            functions,
        )
    }

    fn analysis_with_id(
        crate_name: &str,
        artifact_id: RustcArtifactId,
        dependencies: Vec<RustcArtifactId>,
        functions: Vec<FunctionFact>,
    ) -> ArtifactAnalysisCache {
        analysis_with_id_and_scope(
            crate_name,
            artifact_id,
            ArtifactScope::Dependency,
            dependencies,
            functions,
        )
    }

    fn analysis_with_id_and_scope(
        crate_name: &str,
        artifact_id: RustcArtifactId,
        scope: ArtifactScope,
        dependencies: Vec<RustcArtifactId>,
        functions: Vec<FunctionFact>,
    ) -> ArtifactAnalysisCache {
        let source_files = vec![SourceFileFact {
            id: SourceFileId::new(format!("source-{crate_name}")),
            filename: format!("src/{crate_name}.rs"),
            content_hash: String::from("hash"),
            byte_len: 1,
        }];
        ArtifactAnalysisCache::new(
            EXPECTED.tool_version,
            EXPECTED.rustc_version,
            ArtifactInfo {
                id: artifact_id,
                crate_name: crate_name.to_owned(),
                scope,
            },
            dependencies,
            ArtifactFacts::new(functions, source_files).expect("valid artifact facts"),
        )
        .expect("valid cache")
    }

    fn generic_function(stable_crate_id: u64, local_id: u64) -> FunctionFact {
        function(
            FunctionId::generic(definition_hash(stable_crate_id, local_id)),
            format!("crate{stable_crate_id}::generic_{local_id}"),
        )
    }

    fn function(function: FunctionId, display_path: String) -> FunctionFact {
        FunctionFact {
            function,
            provenance: FunctionFactProvenance::DefiningArtifact,
            display_path: display_path.clone(),
            attributes: FunctionAttributesFact {
                is_unsafe: false,
                is_exported: false,
                has_rust_body: true,
                is_foreign: false,
                namespace_candidates: vec![display_path],
            },
            contract_declaration: None,
            source_range: None,
            calls: Vec::new(),
            effects: Vec::new(),
            markers: Vec::new(),
            unverified_marker_probes: Vec::new(),
        }
    }

    fn definition_hash(stable_crate_id: u64, local_id: u64) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{stable_crate_id:016x}{local_id:016x}\""))
            .expect("valid definition hash")
    }

    fn external(name: &str, stable_crate_id: u64) -> ExternArtifactInput {
        external_with_id(
            name,
            rustc_id(stable_crate_id, &crate_hash(stable_crate_id)),
        )
    }

    fn external_with_id(name: &str, artifact_id: RustcArtifactId) -> ExternArtifactInput {
        ExternArtifactInput {
            name: name.to_owned(),
            artifact_id,
        }
    }

    fn rustc_id(stable_crate_id: u64, svh: &str) -> RustcArtifactId {
        RustcArtifactId::new(stable_crate_id, svh)
    }

    fn crate_hash(stable_crate_id: u64) -> String {
        format!("{stable_crate_id:032x}")
    }

    fn write(directory: &Path, analysis: &ArtifactAnalysisCache) {
        analysis.write(directory).expect("write cache");
    }
}
