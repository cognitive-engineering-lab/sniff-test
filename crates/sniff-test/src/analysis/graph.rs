//! Policy-neutral composition of exact artifact-IR cache generations.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};

use super::cache::{
    AnalysisId, ArtifactAnalysisCache, ArtifactInfo, CacheError, CacheExpectations,
    DependencyAnalysisRef, artifact_cache_path,
};
use super::ir::{
    FunctionBodyIr, FunctionBodyProvenanceIr, FunctionId, SourceFileId, SourceFileIr,
    StableDefPathHash,
};

/// One path-bearing rustc `--extern` input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternArtifactInput {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) artifact_id: String,
    pub(crate) crate_name: String,
    pub(crate) stable_crate_id: u64,
    pub(crate) crate_hash: String,
}

/// The artifact and direct-rustc-alias context for a load failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArtifactLoadContext {
    pub(crate) artifact_id: String,
    pub(crate) direct_aliases: Vec<String>,
    pub(crate) requested_by: Option<String>,
}

/// A structured reason why an artifact could not join the composed graph.
#[derive(Debug)]
pub(crate) enum GraphLoadFailure {
    UnresolvableExtern {
        alias: String,
        path: PathBuf,
    },
    Missing {
        context: ArtifactLoadContext,
        path: PathBuf,
    },
    Invalid {
        context: ArtifactLoadContext,
        error: CacheError,
    },
    ArtifactIdentityMismatch {
        context: ArtifactLoadContext,
        found: String,
    },
    LoadedCrateIdentityMismatch {
        context: ArtifactLoadContext,
        expected_stable_crate_id: u64,
        found_stable_crate_id: u64,
        expected_crate_name: String,
        found_crate_name: String,
        expected_crate_hash: String,
        found_crate_hash: String,
    },
    ConflictingExternIdentity {
        context: ArtifactLoadContext,
    },
    ConflictingFunctionDefinition {
        function: FunctionId,
        first_artifact: String,
        second_artifact: String,
    },
    GenerationMismatch {
        context: ArtifactLoadContext,
        expected: AnalysisId,
        found: AnalysisId,
    },
    GenerationConflict {
        context: ArtifactLoadContext,
        first: AnalysisId,
        first_requested_by: Option<String>,
        second: AnalysisId,
    },
    Cycle {
        artifacts: Vec<String>,
        direct_aliases: Vec<String>,
    },
}

impl Display for GraphLoadFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnresolvableExtern { alias, path } => write!(
                formatter,
                "cannot resolve artifact identity for rustc extern {alias} at {}",
                path.display()
            ),
            Self::Missing { context, path } => write!(
                formatter,
                "missing artifact IR for {} at {}",
                context.artifact_id,
                path.display()
            ),
            Self::Invalid { context, error } => {
                write!(
                    formatter,
                    "invalid artifact IR for {}: {error}",
                    context.artifact_id
                )
            }
            Self::ArtifactIdentityMismatch { context, found } => write!(
                formatter,
                "artifact IR for {} identifies itself as {found}",
                context.artifact_id
            ),
            Self::LoadedCrateIdentityMismatch {
                context,
                expected_stable_crate_id,
                found_stable_crate_id,
                expected_crate_name,
                found_crate_name,
                expected_crate_hash,
                found_crate_hash,
            } => write!(
                formatter,
                "artifact IR for {} does not match rustc's loaded crate identity (crate {found_crate_name}, stable crate id {found_stable_crate_id:016x}, hash {found_crate_hash}; expected crate {expected_crate_name}, stable crate id {expected_stable_crate_id:016x}, hash {expected_crate_hash})",
                context.artifact_id
            ),
            Self::ConflictingExternIdentity { context } => write!(
                formatter,
                "rustc extern aliases for {} resolve to conflicting crate identities",
                context.artifact_id
            ),
            Self::ConflictingFunctionDefinition {
                function,
                first_artifact,
                second_artifact,
            } => write!(
                formatter,
                "function {function:?} is defined by both artifact {first_artifact} and artifact {second_artifact}",
            ),
            Self::GenerationMismatch {
                context,
                expected,
                found,
            } => write!(
                formatter,
                "artifact {} requires analysis generation {expected}, found {found}",
                context.artifact_id
            ),
            Self::GenerationConflict {
                context,
                first,
                first_requested_by,
                second,
            } => {
                let first_requester = first_requested_by.as_deref().unwrap_or("a direct extern");
                let second_requester = context.requested_by.as_deref().unwrap_or("a direct extern");
                write!(
                    formatter,
                    "artifact {} is required at conflicting analysis generations {first} by {first_requester} and {second} by {second_requester}",
                    context.artifact_id
                )
            }
            Self::Cycle {
                artifacts,
                direct_aliases,
            } => {
                write!(
                    formatter,
                    "artifact analysis dependency cycle: {}",
                    artifacts.join(" -> ")
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

/// Runtime identity of the exact artifact generation that owns body facts.
///
/// Exact consumer instantiations are meaningful only in the rustc artifact
/// that materialized them. Keeping this owner beside the body prevents two
/// consumers of the same upstream instance from sharing dispatch facts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum BodyScope {
    Artifact {
        artifact_id: String,
        analysis_id: AnalysisId,
    },
    /// Test-only/in-memory IR has no cache envelope. Its address is stable for
    /// the duration of one interpretation and still keeps distinct IR layers
    /// isolated.
    InMemory(usize),
}

impl BodyScope {
    #[must_use]
    pub(crate) fn artifact(analysis: &ArtifactAnalysisCache) -> Self {
        Self::Artifact {
            artifact_id: analysis.artifact.artifact_id.clone(),
            analysis_id: analysis.analysis_id.clone(),
        }
    }

    #[must_use]
    pub(crate) fn in_memory(analysis: &super::ir::ArtifactAnalysisIr) -> Self {
        Self::InMemory(std::ptr::from_ref(analysis).addr())
    }
}

/// One function body together with its owning artifact generation.
#[derive(Debug, Clone)]
pub(crate) struct LoadedFunction<'a> {
    body: &'a FunctionBodyIr,
    scope: BodyScope,
}

impl<'a> LoadedFunction<'a> {
    #[must_use]
    pub(crate) fn new(body: &'a FunctionBodyIr, scope: BodyScope) -> Self {
        Self { body, scope }
    }

    #[must_use]
    pub(crate) const fn body(&self) -> &'a FunctionBodyIr {
        self.body
    }

    #[must_use]
    pub(crate) fn scope(&self) -> &BodyScope {
        &self.scope
    }
}

#[derive(Debug, Clone, Copy)]
struct FunctionLocation {
    artifact: usize,
    function: usize,
}

#[derive(Debug, Clone, Copy)]
struct SourceLocation {
    artifact: usize,
    source: usize,
}

/// All verified artifact generations reachable from the active rustc externs.
#[derive(Debug, Default)]
pub(crate) struct ArtifactAnalysisGraph {
    artifacts: Vec<ArtifactAnalysisCache>,
    artifact_indices: BTreeMap<String, usize>,
    direct_aliases: BTreeMap<String, BTreeSet<String>>,
    defining_functions: HashMap<FunctionId, FunctionLocation>,
    defining_source_functions: HashMap<StableDefPathHash, FunctionLocation>,
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
        read: impl FnMut(&str, &Path) -> Result<ArtifactAnalysisCache, CacheError>,
    ) -> Self {
        GraphLoader::new(cache_dir, externs, read).load()
    }

    fn from_loaded(
        loaded: BTreeMap<String, ArtifactAnalysisCache>,
        direct_aliases: BTreeMap<String, BTreeSet<String>>,
        mut failures: Vec<GraphLoadFailure>,
    ) -> Self {
        let artifacts = loaded.into_values().collect::<Vec<_>>();
        let mut artifact_indices = BTreeMap::new();
        let mut defining_functions = HashMap::new();
        let mut defining_source_functions = HashMap::new();
        let mut sources = HashMap::new();
        for (artifact, analysis) in artifacts.iter().enumerate() {
            artifact_indices.insert(analysis.artifact.artifact_id.clone(), artifact);
            for (function, body) in analysis.ir.functions.iter().enumerate() {
                if matches!(body.provenance, FunctionBodyProvenanceIr::DefiningArtifact) {
                    defining_source_functions
                        .entry(body.function.def_path_hash)
                        .or_insert(FunctionLocation { artifact, function });
                    match defining_functions.entry(body.function) {
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert(FunctionLocation { artifact, function });
                        }
                        std::collections::hash_map::Entry::Occupied(entry) => {
                            let first = &artifacts[entry.get().artifact];
                            failures.push(GraphLoadFailure::ConflictingFunctionDefinition {
                                function: body.function,
                                first_artifact: first.artifact.artifact_id.clone(),
                                second_artifact: analysis.artifact.artifact_id.clone(),
                            });
                        }
                    }
                }
            }
            for (source, file) in analysis.ir.source_files.iter().enumerate() {
                sources
                    .entry(file.id.clone())
                    .or_insert(SourceLocation { artifact, source });
            }
        }
        Self {
            artifacts,
            artifact_indices,
            direct_aliases,
            defining_functions,
            defining_source_functions,
            sources,
            failures,
        }
    }

    pub(crate) fn artifacts(&self) -> impl Iterator<Item = &ArtifactAnalysisCache> {
        self.artifacts.iter()
    }

    #[must_use]
    pub(crate) fn artifact(&self, artifact_id: &str) -> Option<&ArtifactAnalysisCache> {
        self.artifact_indices
            .get(artifact_id)
            .map(|index| &self.artifacts[*index])
    }

    #[must_use]
    pub(crate) fn source_file(
        &self,
        source_file: &SourceFileId,
    ) -> Option<(&ArtifactInfo, &SourceFileIr)> {
        let location = self.sources.get(source_file)?;
        let artifact = &self.artifacts[location.artifact];
        Some((
            &artifact.artifact,
            &artifact.ir.source_files[location.source],
        ))
    }

    #[must_use]
    pub(crate) fn function(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        let location = function
            .resolution_candidates()
            .find_map(|candidate| self.defining_functions.get(&candidate).copied())?;
        let artifact = &self.artifacts[location.artifact];
        Some(LoadedFunction::new(
            &artifact.ir.functions[location.function],
            BodyScope::artifact(artifact),
        ))
    }

    /// Resolves a body only inside one exact artifact generation.
    #[must_use]
    pub(crate) fn function_in_scope(
        &self,
        scope: &BodyScope,
        function: FunctionId,
    ) -> Option<LoadedFunction<'_>> {
        let BodyScope::Artifact {
            artifact_id,
            analysis_id,
        } = scope
        else {
            return None;
        };
        let artifact = self.artifact(artifact_id)?;
        if &artifact.analysis_id != analysis_id {
            return None;
        }
        let body = artifact.ir.function_body(function)?;
        Some(LoadedFunction::new(body, scope.clone()))
    }

    /// Resolves only facts extracted by the function's defining artifact.
    ///
    /// Exact defining bodies are tried before the generic definition because
    /// closures, coroutines, nested constants, and similar compiler-generated
    /// bodies can have exact identities without a generic counterpart.
    #[must_use]
    pub(crate) fn defining_function(&self, function: FunctionId) -> Option<LoadedFunction<'_>> {
        self.function(function)
    }

    /// Resolves source facts for a definition even when nested-body instance
    /// hashes differ between the defining artifact and a consumer overlay.
    #[must_use]
    pub(crate) fn defining_source_function(
        &self,
        function: FunctionId,
    ) -> Option<LoadedFunction<'_>> {
        if let Some(body) = self.defining_function(function) {
            return Some(body);
        }
        let location = self
            .defining_source_functions
            .get(&function.def_path_hash)?;
        let artifact = &self.artifacts[location.artifact];
        Some(LoadedFunction::new(
            &artifact.ir.functions[location.function],
            BodyScope::artifact(artifact),
        ))
    }

    pub(crate) fn direct_dependency_aliases(&self) -> impl Iterator<Item = (&str, &str)> {
        self.direct_aliases
            .iter()
            .flat_map(|(artifact_id, aliases)| {
                aliases
                    .iter()
                    .map(move |alias| (alias.as_str(), artifact_id.as_str()))
            })
    }

    /// Direct dependency generations that were read and verified successfully.
    pub(crate) fn direct_dependency_refs(
        &self,
    ) -> impl Iterator<Item = DependencyAnalysisRef> + '_ {
        self.direct_aliases.keys().filter_map(|artifact_id| {
            self.artifact(artifact_id)
                .map(|analysis| DependencyAnalysisRef {
                    artifact_id: artifact_id.clone(),
                    analysis_id: analysis.analysis_id.clone(),
                })
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

#[derive(Debug)]
struct LoadRequest {
    artifact_id: String,
    expected_generation: Option<AnalysisId>,
    expected_identity: Option<LoadedCrateIdentity>,
    requested_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoadedCrateIdentity {
    crate_name: String,
    stable_crate_id: u64,
    crate_hash: String,
}

struct GraphLoader<'a, R> {
    cache_dir: &'a Path,
    read: R,
    direct_aliases: BTreeMap<String, BTreeSet<String>>,
    pending: VecDeque<LoadRequest>,
    expected_generations: BTreeMap<String, (AnalysisId, Option<String>)>,
    attempted: BTreeSet<String>,
    rejected: BTreeSet<String>,
    loaded: BTreeMap<String, ArtifactAnalysisCache>,
    failures: Vec<GraphLoadFailure>,
}

impl<'a, R> GraphLoader<'a, R>
where
    R: FnMut(&str, &Path) -> Result<ArtifactAnalysisCache, CacheError>,
{
    fn new(cache_dir: &'a Path, externs: &[ExternArtifactInput], read: R) -> Self {
        let mut direct_aliases = BTreeMap::<String, BTreeSet<String>>::new();
        let mut direct_identities = BTreeMap::<String, LoadedCrateIdentity>::new();
        let mut failures = Vec::new();
        for dependency in externs {
            if dependency.artifact_id.trim().is_empty() {
                failures.push(GraphLoadFailure::UnresolvableExtern {
                    alias: dependency.name.clone(),
                    path: dependency.path.clone(),
                });
                continue;
            }
            let artifact_id = dependency.artifact_id.clone();
            direct_aliases
                .entry(artifact_id.clone())
                .or_default()
                .insert(dependency.name.clone());
            let identity = LoadedCrateIdentity {
                crate_name: dependency.crate_name.clone(),
                stable_crate_id: dependency.stable_crate_id,
                crate_hash: dependency.crate_hash.clone(),
            };
            if let Some(first) = direct_identities.get(&artifact_id) {
                if first != &identity {
                    failures.push(GraphLoadFailure::ConflictingExternIdentity {
                        context: load_context(&direct_aliases, &artifact_id, None),
                    });
                }
            } else {
                direct_identities.insert(artifact_id, identity);
            }
        }
        let pending = direct_identities
            .into_iter()
            .map(|(artifact_id, expected_identity)| LoadRequest {
                artifact_id: artifact_id.clone(),
                expected_generation: None,
                expected_identity: Some(expected_identity),
                requested_by: None,
            })
            .collect();
        Self {
            cache_dir,
            read,
            direct_aliases,
            pending,
            expected_generations: BTreeMap::new(),
            attempted: BTreeSet::new(),
            rejected: BTreeSet::new(),
            loaded: BTreeMap::new(),
            failures,
        }
    }

    fn load(mut self) -> ArtifactAnalysisGraph {
        while let Some(request) = self.pending.pop_front() {
            self.load_request(&request);
        }
        self.reject_cycle();
        ArtifactAnalysisGraph::from_loaded(self.loaded, self.direct_aliases, self.failures)
    }

    fn load_request(&mut self, request: &LoadRequest) {
        if !self.register_generation(request) || self.rejected.contains(&request.artifact_id) {
            return;
        }
        if let Some(found) = self
            .loaded
            .get(&request.artifact_id)
            .map(|analysis| analysis.analysis_id.clone())
        {
            if let Some(expected) = request.expected_generation.as_ref()
                && &found != expected
            {
                self.reject_generation(request, expected.clone(), found);
            }
            return;
        }
        if !self.attempted.insert(request.artifact_id.clone()) {
            return;
        }

        let Some(analysis) = self.read_artifact(request) else {
            return;
        };
        if analysis.artifact.artifact_id != request.artifact_id {
            self.failures
                .push(GraphLoadFailure::ArtifactIdentityMismatch {
                    context: self.context(request),
                    found: analysis.artifact.artifact_id,
                });
            self.rejected.insert(request.artifact_id.clone());
            return;
        }
        if let Some(expected) = request.expected_identity.as_ref()
            && (analysis.artifact.crate_name != expected.crate_name
                || analysis.artifact.stable_crate_id != expected.stable_crate_id
                || analysis.artifact.crate_hash.as_deref() != Some(expected.crate_hash.as_str()))
        {
            self.failures
                .push(GraphLoadFailure::LoadedCrateIdentityMismatch {
                    context: self.context(request),
                    expected_stable_crate_id: expected.stable_crate_id,
                    found_stable_crate_id: analysis.artifact.stable_crate_id,
                    expected_crate_name: expected.crate_name.clone(),
                    found_crate_name: analysis.artifact.crate_name,
                    expected_crate_hash: expected.crate_hash.clone(),
                    found_crate_hash: analysis
                        .artifact
                        .crate_hash
                        .unwrap_or_else(|| String::from("<unavailable>")),
                });
            self.rejected.insert(request.artifact_id.clone());
            return;
        }
        if let Some(expected) = request.expected_generation.as_ref()
            && &analysis.analysis_id != expected
        {
            self.reject_generation(request, expected.clone(), analysis.analysis_id);
            return;
        }

        for dependency in &analysis.dependencies {
            self.pending.push_back(LoadRequest {
                artifact_id: dependency.artifact_id.clone(),
                expected_generation: Some(dependency.analysis_id.clone()),
                expected_identity: None,
                requested_by: Some(request.artifact_id.clone()),
            });
        }
        self.loaded.insert(request.artifact_id.clone(), analysis);
    }

    fn register_generation(&mut self, request: &LoadRequest) -> bool {
        let Some(expected) = request.expected_generation.as_ref() else {
            return true;
        };
        let Some((first, first_requested_by)) = self.expected_generations.get(&request.artifact_id)
        else {
            self.expected_generations.insert(
                request.artifact_id.clone(),
                (expected.clone(), request.requested_by.clone()),
            );
            return true;
        };
        if first == expected {
            return true;
        }

        self.failures.push(GraphLoadFailure::GenerationConflict {
            context: self.context(request),
            first: first.clone(),
            first_requested_by: first_requested_by.clone(),
            second: expected.clone(),
        });
        self.rejected.insert(request.artifact_id.clone());
        self.loaded.remove(&request.artifact_id);
        false
    }

    fn read_artifact(&mut self, request: &LoadRequest) -> Option<ArtifactAnalysisCache> {
        let path = artifact_cache_path(self.cache_dir, &request.artifact_id);
        match (self.read)(&request.artifact_id, &path) {
            Ok(analysis) => Some(analysis),
            Err(error) if error.is_missing_file() => {
                self.failures.push(GraphLoadFailure::Missing {
                    context: self.context(request),
                    path,
                });
                self.rejected.insert(request.artifact_id.clone());
                None
            }
            Err(error) => {
                self.failures.push(GraphLoadFailure::Invalid {
                    context: self.context(request),
                    error,
                });
                self.rejected.insert(request.artifact_id.clone());
                None
            }
        }
    }

    fn reject_generation(
        &mut self,
        request: &LoadRequest,
        expected: AnalysisId,
        found: AnalysisId,
    ) {
        self.failures.push(GraphLoadFailure::GenerationMismatch {
            context: self.context(request),
            expected,
            found,
        });
        self.rejected.insert(request.artifact_id.clone());
        self.loaded.remove(&request.artifact_id);
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

    fn context(&self, request: &LoadRequest) -> ArtifactLoadContext {
        load_context(
            &self.direct_aliases,
            &request.artifact_id,
            request.requested_by.as_deref(),
        )
    }
}

fn load_context(
    direct_aliases: &BTreeMap<String, BTreeSet<String>>,
    artifact_id: &str,
    requested_by: Option<&str>,
) -> ArtifactLoadContext {
    ArtifactLoadContext {
        artifact_id: artifact_id.to_owned(),
        direct_aliases: direct_aliases
            .get(artifact_id)
            .into_iter()
            .flatten()
            .cloned()
            .collect(),
        requested_by: requested_by.map(str::to_owned),
    }
}

fn find_dependency_cycle(
    artifacts: &BTreeMap<String, ArtifactAnalysisCache>,
) -> Option<Vec<String>> {
    let mut finished = BTreeSet::new();
    let mut active = BTreeMap::<String, usize>::new();
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
    artifact_id: &str,
    artifacts: &BTreeMap<String, ArtifactAnalysisCache>,
    finished: &mut BTreeSet<String>,
    active: &mut BTreeMap<String, usize>,
    stack: &mut Vec<String>,
) -> Option<Vec<String>> {
    if finished.contains(artifact_id) {
        return None;
    }
    if let Some(start) = active.get(artifact_id).copied() {
        let mut cycle = stack[start..].to_vec();
        cycle.push(artifact_id.to_owned());
        return Some(cycle);
    }

    active.insert(artifact_id.to_owned(), stack.len());
    stack.push(artifact_id.to_owned());
    let artifact = artifacts
        .get(artifact_id)
        .expect("cycle traversal starts from a loaded artifact");
    for dependency in &artifact.dependencies {
        let Some(target) = artifacts.get(&dependency.artifact_id) else {
            continue;
        };
        if target.analysis_id != dependency.analysis_id {
            continue;
        }
        if let Some(cycle) =
            visit_artifact(&dependency.artifact_id, artifacts, finished, active, stack)
        {
            return Some(cycle);
        }
    }
    stack.pop();
    active.remove(artifact_id);
    finished.insert(artifact_id.to_owned());
    None
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    use tempfile::tempdir;

    use super::{
        ArtifactAnalysisGraph, BodyScope, ExternArtifactInput, GraphLoadFailure,
        artifact_cache_path,
    };
    use crate::analysis::cache::{
        AnalysisId, ArtifactAnalysisCache, ArtifactInfo, CacheError, CacheExpectations,
        DependencyAnalysisRef,
    };
    use crate::analysis::ir::{
        ArtifactAnalysisIr, FunctionAttributesIr, FunctionBodyIr, FunctionBodyProvenanceIr,
        FunctionId, SourceFileId, SourceFileIr,
    };
    use crate::namespace::{StableDefPathHash, StableInstanceHash};

    const EXPECTED: CacheExpectations<'static> = CacheExpectations {
        tool_version: "test-tool",
        rustc_version: "test-rustc",
    };

    #[test]
    fn recursively_loads_exact_generations_and_exposes_artifacts_and_sources() {
        let directory = tempdir().expect("cache directory");
        let child = analysis("child-a", 2, Vec::new(), vec![generic_function(2, 20)]);
        let root = analysis(
            "root-a",
            1,
            vec![dependency("child-a", child.analysis_id.clone())],
            vec![generic_function(1, 10)],
        );
        write(directory.path(), &child);
        write(directory.path(), &root);

        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[external("root_alias", "libroot-a.rlib", 1)],
            &EXPECTED,
        );

        assert!(graph.is_complete());
        assert_eq!(
            graph
                .artifacts()
                .map(|artifact| artifact.artifact.artifact_id.as_str())
                .collect::<Vec<_>>(),
            ["child-a", "root-a"]
        );
        assert_eq!(
            graph
                .artifacts()
                .flat_map(|analysis| {
                    analysis.ir.source_files.iter().map(move |source| {
                        (
                            analysis.artifact.artifact_id.as_str(),
                            source.filename.as_str(),
                        )
                    })
                })
                .collect::<Vec<_>>(),
            [("child-a", "src/child-a.rs"), ("root-a", "src/root-a.rs")]
        );
        assert_eq!(
            graph
                .direct_dependency_refs()
                .map(|dependency| dependency.artifact_id)
                .collect::<Vec<_>>(),
            ["root-a"]
        );
    }

    #[test]
    fn exact_function_lookup_falls_back_only_to_its_generic_definition() {
        let directory = tempdir().expect("cache directory");
        let exact = exact_function(1, 10, 100);
        let generic = generic_function(1, 10);
        let artifact = analysis("root-a", 1, Vec::new(), vec![generic, exact]);
        write(directory.path(), &artifact);
        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[external("root", "libroot-a.rmeta", 1)],
            &EXPECTED,
        );

        let exact = graph
            .function(FunctionId::exact(
                definition_hash(1, 10),
                instance_hash(100),
            ))
            .expect("exact function");
        let generic = graph
            .function(FunctionId::exact(
                definition_hash(1, 10),
                instance_hash(101),
            ))
            .expect("generic fallback");

        assert_eq!(exact.body().display_path, "crate1::exact_100");
        assert!(exact.body().function.instance_hash.is_some());
        assert_eq!(generic.body().display_path, "crate1::generic_10");
        assert!(generic.body().function.instance_hash.is_none());
        assert!(
            graph
                .function(FunctionId::generic(definition_hash(9, 10)))
                .is_none()
        );
    }

    #[test]
    fn retains_same_instance_overlays_in_each_consumer_artifact() {
        let directory = tempdir().expect("cache directory");
        let shared = FunctionId::exact(definition_hash(3, 10), instance_hash(100));
        let mut first_overlay = function(shared, String::from("shared::<first::Callback>"));
        first_overlay.provenance = FunctionBodyProvenanceIr::ConsumerInstantiation {
            consumer_stable_crate_id: 1,
        };
        let mut second_overlay = function(shared, String::from("shared::<second::Callback>"));
        second_overlay.provenance = FunctionBodyProvenanceIr::ConsumerInstantiation {
            consumer_stable_crate_id: 2,
        };
        let first = analysis("first-a", 1, Vec::new(), vec![first_overlay]);
        let second = analysis("second-a", 2, Vec::new(), vec![second_overlay]);
        write(directory.path(), &first);
        write(directory.path(), &second);

        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[
                external("first", "libfirst-a.rlib", 1),
                external("second", "libsecond-a.rlib", 2),
            ],
            &EXPECTED,
        );
        let first_scope = BodyScope::artifact(graph.artifact("first-a").expect("first artifact"));
        let second_scope =
            BodyScope::artifact(graph.artifact("second-a").expect("second artifact"));

        assert!(graph.is_complete());
        assert_eq!(
            graph
                .function_in_scope(&first_scope, shared)
                .expect("first overlay")
                .body()
                .display_path,
            "shared::<first::Callback>"
        );
        assert_eq!(
            graph
                .function_in_scope(&second_scope, shared)
                .expect("second overlay")
                .body()
                .display_path,
            "shared::<second::Callback>"
        );
        assert!(
            graph.function(shared).is_none(),
            "unscoped lookup must not silently select either consumer overlay"
        );
    }

    #[test]
    fn repeated_direct_aliases_are_preserved_for_one_verified_generation() {
        let directory = tempdir().expect("cache directory");
        let artifact = analysis("shared-a", 1, Vec::new(), Vec::new());
        write(directory.path(), &artifact);

        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[
                external("first_alias", "libshared-a.rlib", 1),
                external("second_alias", "libshared-a.rmeta", 1),
            ],
            &EXPECTED,
        );

        assert_eq!(
            graph.direct_dependency_aliases().collect::<Vec<_>>(),
            [("first_alias", "shared-a"), ("second_alias", "shared-a")]
        );
        assert_eq!(graph.direct_dependency_refs().count(), 1);
    }

    #[test]
    fn rejects_a_direct_cache_that_does_not_match_rustcs_loaded_crate() {
        let directory = tempdir().expect("cache directory");
        let artifact = analysis("root-a", 1, Vec::new(), Vec::new());
        write(directory.path(), &artifact);
        let extern_input = ExternArtifactInput {
            name: String::from("root"),
            path: PathBuf::from("/deps/libroot-a.rlib"),
            artifact_id: String::from("root-a"),
            crate_name: String::from("root"),
            stable_crate_id: 1,
            crate_hash: String::from("different-rustc-svh"),
        };

        let graph = ArtifactAnalysisGraph::load(directory.path(), &[extern_input], &EXPECTED);

        assert!(matches!(
            graph.failures().next(),
            Some(GraphLoadFailure::LoadedCrateIdentityMismatch {
                expected_stable_crate_id: 1,
                found_stable_crate_id: 1,
                expected_crate_hash,
                found_crate_hash,
                ..
            }) if expected_crate_hash == "different-rustc-svh"
                && found_crate_hash == &crate_hash(1)
        ));
        assert!(graph.artifact("root-a").is_none());
    }

    #[test]
    fn distinguishes_missing_invalid_and_unresolvable_direct_inputs() {
        let directory = tempdir().expect("cache directory");
        let corrupt = artifact_cache_path(directory.path(), "corrupt-a");
        fs::create_dir_all(corrupt.parent().expect("cache parent")).expect("create cache parent");
        fs::write(&corrupt, "{not json").expect("write corrupt cache");

        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[
                external("corrupt_alias", "libcorrupt-a.rlib", 0),
                external("missing_alias", "libmissing-a.rlib", 0),
                ExternArtifactInput {
                    name: String::from("bad_alias"),
                    path: PathBuf::from("/"),
                    artifact_id: String::new(),
                    crate_name: String::new(),
                    stable_crate_id: 0,
                    crate_hash: crate_hash(0),
                },
            ],
            &EXPECTED,
        );

        assert!(graph.failures().any(|failure| matches!(
            failure,
            GraphLoadFailure::Missing { context, .. }
                if context.artifact_id == "missing-a"
                    && context.direct_aliases == ["missing_alias"]
        )));
        assert!(graph.failures().any(|failure| matches!(
            failure,
            GraphLoadFailure::Invalid { context, .. }
                if context.artifact_id == "corrupt-a"
                    && context.direct_aliases == ["corrupt_alias"]
        )));
        assert!(graph.failures().any(|failure| matches!(
            failure,
            GraphLoadFailure::UnresolvableExtern { alias, .. } if alias == "bad_alias"
        )));
        assert_eq!(graph.direct_dependency_refs().count(), 0);
    }

    #[test]
    fn rejects_caches_from_a_different_extraction_environment() {
        let directory = tempdir().expect("cache directory");
        let artifact = analysis("root-a", 1, Vec::new(), Vec::new());
        write(directory.path(), &artifact);
        let stale_environment = CacheExpectations {
            rustc_version: "different-rustc",
            ..EXPECTED
        };

        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[external("root", "libroot-a.rlib", 1)],
            &stale_environment,
        );

        assert!(matches!(
            graph.failures().next(),
            Some(GraphLoadFailure::Invalid {
                error: CacheError::Version { field: "rustc", .. },
                ..
            })
        ));
        assert!(graph.artifact("root-a").is_none());
        assert_eq!(graph.direct_dependency_refs().count(), 0);
    }

    #[test]
    fn rejects_a_transitive_cache_with_the_wrong_generation() {
        let directory = tempdir().expect("cache directory");
        let child = analysis("child-a", 2, Vec::new(), Vec::new());
        let root = analysis(
            "root-a",
            1,
            vec![dependency(
                "child-a",
                AnalysisId::from("expected-generation"),
            )],
            Vec::new(),
        );
        write(directory.path(), &child);
        write(directory.path(), &root);

        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[external("root", "libroot-a.rlib", 1)],
            &EXPECTED,
        );

        assert!(graph.failures().any(|failure| matches!(
            failure,
            GraphLoadFailure::GenerationMismatch {
                context,
                expected,
                found,
            } if context.artifact_id == "child-a"
                && context.requested_by.as_deref() == Some("root-a")
                && expected.to_string() == "expected-generation"
                && found == &child.analysis_id
        )));
        assert!(graph.artifact("child-a").is_none());
    }

    #[test]
    fn rejects_conflicting_generation_requirements_from_two_parents() {
        let directory = tempdir().expect("cache directory");
        let child = analysis("child-a", 3, Vec::new(), Vec::new());
        let first = analysis(
            "first-a",
            1,
            vec![dependency("child-a", child.analysis_id.clone())],
            Vec::new(),
        );
        let second = analysis(
            "second-a",
            2,
            vec![dependency("child-a", AnalysisId::from("other-generation"))],
            Vec::new(),
        );
        write(directory.path(), &child);
        write(directory.path(), &first);
        write(directory.path(), &second);

        let graph = ArtifactAnalysisGraph::load(
            directory.path(),
            &[
                external("first", "libfirst-a.rlib", 1),
                external("second", "libsecond-a.rlib", 2),
            ],
            &EXPECTED,
        );

        assert!(graph.failures().any(|failure| matches!(
            failure,
            GraphLoadFailure::GenerationConflict {
                context,
                first,
                second,
                ..
            }
                if context.artifact_id == "child-a"
                    && first != second
        )));
        assert!(graph.artifact("child-a").is_none());
    }

    #[test]
    fn detects_cycles_in_declared_exact_generation_edges() {
        let directory = tempdir().expect("cache directory");
        let mut first = analysis("first-a", 1, Vec::new(), Vec::new());
        let mut second = analysis("second-a", 2, Vec::new(), Vec::new());
        first.dependencies = vec![dependency("second-a", second.analysis_id.clone())];
        second.dependencies = vec![dependency("first-a", first.analysis_id.clone())];
        let mut artifacts = BTreeMap::from([
            (String::from("first-a"), first),
            (String::from("second-a"), second),
        ]);

        // Production reads always validate the cache envelope first. This
        // injected reader isolates the defensive graph-cycle check, since a
        // content-addressed cycle cannot be serialized with self-consistent
        // analysis IDs.
        let graph = ArtifactAnalysisGraph::load_with(
            directory.path(),
            &[external("first", "libfirst-a.rlib", 1)],
            |artifact_id, path| {
                artifacts
                    .remove(artifact_id)
                    .ok_or_else(|| missing_error(path))
            },
        );

        assert!(graph.failures().any(|failure| matches!(
            failure,
            GraphLoadFailure::Cycle {
                artifacts,
                direct_aliases,
            } if artifacts == &["first-a", "second-a", "first-a"]
                && direct_aliases == &["first"]
        )));
    }

    fn analysis(
        artifact_id: &str,
        stable_crate_id: u64,
        dependencies: Vec<DependencyAnalysisRef>,
        functions: Vec<FunctionBodyIr>,
    ) -> ArtifactAnalysisCache {
        let source_files = vec![SourceFileIr {
            id: SourceFileId::new(format!("source-{artifact_id}")),
            filename: format!("src/{artifact_id}.rs"),
            content_hash: String::from("hash"),
            byte_len: 1,
        }];
        ArtifactAnalysisCache::new(
            EXPECTED.tool_version,
            EXPECTED.rustc_version,
            "test-compiler",
            ArtifactInfo {
                artifact_id: artifact_id.to_owned(),
                crate_name: artifact_id
                    .split_once('-')
                    .map_or(artifact_id, |(name, _)| name)
                    .to_owned(),
                stable_crate_id,
                crate_hash: Some(crate_hash(stable_crate_id)),
            },
            dependencies,
            ArtifactAnalysisIr::new(functions, source_files).expect("valid IR"),
        )
        .expect("valid cache")
    }

    fn generic_function(stable_crate_id: u64, local_id: u64) -> FunctionBodyIr {
        function(
            FunctionId::generic(definition_hash(stable_crate_id, local_id)),
            format!("crate{stable_crate_id}::generic_{local_id}"),
        )
    }

    fn exact_function(stable_crate_id: u64, local_id: u64, instance: u64) -> FunctionBodyIr {
        function(
            FunctionId::exact(
                definition_hash(stable_crate_id, local_id),
                instance_hash(instance),
            ),
            format!("crate{stable_crate_id}::exact_{instance}"),
        )
    }

    fn function(function: FunctionId, display_path: String) -> FunctionBodyIr {
        FunctionBodyIr {
            function,
            provenance: FunctionBodyProvenanceIr::DefiningArtifact,
            display_path: display_path.clone(),
            attributes: FunctionAttributesIr {
                is_unsafe: false,
                is_exported: false,
                has_rust_body: true,
                is_foreign: false,
                namespace_candidates: vec![display_path],
            },
            source_range: None,
            calls: Vec::new(),
            effects: Vec::new(),
            markers: Vec::new(),
        }
    }

    fn definition_hash(stable_crate_id: u64, local_id: u64) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{stable_crate_id:016x}{local_id:016x}\""))
            .expect("valid definition hash")
    }

    fn instance_hash(value: u64) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{value:032x}\"")).expect("valid instance hash")
    }

    fn dependency(artifact_id: &str, analysis_id: AnalysisId) -> DependencyAnalysisRef {
        DependencyAnalysisRef {
            artifact_id: artifact_id.to_owned(),
            analysis_id,
        }
    }

    fn external(name: &str, filename: &str, stable_crate_id: u64) -> ExternArtifactInput {
        let artifact_id = Path::new(filename)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.strip_prefix("lib").or(Some(stem)))
            .expect("test extern filename has a UTF-8 stem")
            .to_owned();
        let crate_name = artifact_id
            .split_once('-')
            .map_or(artifact_id.as_str(), |(name, _)| name)
            .to_owned();
        ExternArtifactInput {
            name: name.to_owned(),
            path: Path::new("/deps").join(filename),
            artifact_id,
            crate_name,
            stable_crate_id,
            crate_hash: crate_hash(stable_crate_id),
        }
    }

    fn crate_hash(stable_crate_id: u64) -> String {
        format!("{stable_crate_id:032x}")
    }

    fn write(directory: &Path, analysis: &ArtifactAnalysisCache) {
        analysis.write(directory).expect("write cache");
    }

    fn missing_error(path: &Path) -> CacheError {
        CacheError::Io {
            path: path.to_owned(),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        }
    }
}
