//! Runtime view of cached dependency analyses.
//!
//! This module loads cache files for the `--extern` artifacts rustc passed to
//! the current compilation. Full stable item keys identify cached functions
//! across all loaded artifacts; rendered crate names are policy labels, not
//! cache identity.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::cache::{
    AnalysisId, CacheError, CacheExpectations, CachedArtifactAnalysis, CachedFinding,
    CachedFindingId, CachedFunctionSummary, CachedItemKey, CachedTraceId, artifact_cache_path,
    artifact_id_from_extern_path,
};
use crate::config::SniffTestConfig;
use crate::namespace::{StableDefPathHash, StableInstanceHash};

/// A rustc `--extern` dependency relevant to cache lookup.
#[derive(Debug, Clone)]
pub struct DependencyInput {
    pub name: String,
    pub path: PathBuf,
}

/// Loaded dependency cache for one rustc invocation.
#[derive(Debug, Default)]
pub struct DependencyAnalysisCache {
    store: Rc<LoadedArtifacts>,
    dependencies: BTreeMap<String, DependencyState>,
}

impl DependencyAnalysisCache {
    #[must_use]
    pub fn load(
        cache_dir: &Path,
        externs: &[DependencyInput],
        config: &SniffTestConfig,
        expected: &CacheExpectations<'_>,
    ) -> Self {
        let mut dependencies = BTreeMap::<String, DependencyState>::new();
        for dependency in externs {
            // Cargo dependencies can be renamed independently of their
            // canonical crate names, so apply alias policy before loading.
            if config.all_effects_ignore_namespace(&dependency.name) {
                continue;
            }
            let Some(artifact_id) = artifact_id_from_extern_path(&dependency.path) else {
                continue;
            };
            dependencies
                .entry(artifact_id)
                .or_default()
                .extern_names
                .insert(dependency.name.clone());
        }

        let mut pending = dependencies.keys().cloned().collect::<VecDeque<_>>();
        let mut store = LoadedArtifacts::default();

        while let Some(artifact_id) = pending.pop_front() {
            let dependency = dependencies
                .get_mut(&artifact_id)
                .expect("pending dependency must have loader state");
            if matches!(dependency.cache, DependencyCacheState::Unread) {
                dependency.cache = match read_cached_analysis(cache_dir, &artifact_id, expected) {
                    Ok(Some(analysis))
                        if config.all_effects_ignore_namespace(&analysis.artifact.crate_name) =>
                    {
                        DependencyCacheState::Ignored
                    }
                    Ok(Some(analysis)) => DependencyCacheState::Available {
                        analysis: Box::new(analysis),
                        generation_error: None,
                    },
                    Ok(None) => DependencyCacheState::Missing,
                    Err(error) => DependencyCacheState::Invalid(error.to_string()),
                };
            }

            let Some(analysis) = dependency.take_accepted_analysis(&artifact_id) else {
                continue;
            };
            for transitive in &analysis.dependencies {
                let transitive_id = transitive.artifact_id.clone();
                if dependencies
                    .entry(transitive_id.clone())
                    .or_default()
                    .expected_analysis_ids
                    .insert(transitive.analysis_id.clone())
                {
                    pending.push_back(transitive_id);
                }
            }
            store.insert(analysis, config);
        }

        Self {
            store: Rc::new(store),
            dependencies,
        }
    }

    #[must_use]
    pub fn function(
        &self,
        def_path_hash: StableDefPathHash,
        instance_hash: Option<StableInstanceHash>,
    ) -> Option<CachedFunction> {
        let location = instance_hash
            .and_then(|instance_hash| {
                self.store
                    .functions
                    .get(&CachedItemKey::exact_item(def_path_hash, instance_hash))
                    .copied()
            })
            .or_else(|| {
                self.store
                    .functions
                    .get(&CachedItemKey::generic_template(def_path_hash))
                    .copied()
            })?;
        Some(CachedFunction {
            store: Rc::clone(&self.store),
            location,
        })
    }

    #[must_use]
    pub fn has_analysis_for_crate(&self, stable_crate_id: u64) -> bool {
        self.store
            .artifacts
            .iter()
            .any(|analysis| analysis.artifact.stable_crate_id == stable_crate_id)
    }

    /// Whether rustc's path for an external crate names an artifact that this
    /// invocation was asked to analyze.
    ///
    /// This remains true when that artifact's cache is missing or invalid,
    /// which lets callers distinguish an expected Cargo dependency from a
    /// routine sysroot cache miss.
    #[must_use]
    pub fn tracks_artifact_path(&self, path: &Path) -> bool {
        let Some(artifact_id) = artifact_id_from_extern_path(path) else {
            return false;
        };
        self.dependencies
            .get(&artifact_id)
            .is_some_and(|dependency| !dependency.is_ignored())
    }

    /// Dependencies whose cache files exist but could not be used, with the
    /// reason. Missing files are not failures.
    pub fn load_failures(&self) -> impl Iterator<Item = (&str, &str)> {
        self.dependencies
            .iter()
            .filter_map(|(artifact_id, dependency)| {
                let error = match &dependency.cache {
                    DependencyCacheState::Available {
                        generation_error, ..
                    } => generation_error.as_deref(),
                    DependencyCacheState::Invalid(error) => Some(error.as_str()),
                    _ => None,
                }?;
                Some((
                    dependency
                        .extern_names
                        .first()
                        .map_or(artifact_id.as_str(), String::as_str),
                    error,
                ))
            })
    }

    pub fn direct_dependency_aliases(&self) -> impl Iterator<Item = (&str, &str)> {
        self.dependencies
            .iter()
            .filter(|(_, dependency)| !dependency.is_ignored())
            .flat_map(|(artifact_id, dependency)| {
                dependency
                    .extern_names
                    .iter()
                    .map(|name| (name.as_str(), artifact_id.as_str()))
            })
    }
}

#[derive(Debug, Clone)]
pub struct CachedFunction {
    store: Rc<LoadedArtifacts>,
    location: FunctionLocation,
}

impl CachedFunction {
    #[must_use]
    pub fn analysis(&self) -> &CachedArtifactAnalysis {
        &self.store.artifacts[self.location.artifact]
    }

    #[must_use]
    pub fn summary(&self) -> &CachedFunctionSummary {
        &self.analysis().functions[self.location.function]
    }

    #[must_use]
    pub fn is_generic_template(&self) -> bool {
        matches!(self.summary().key, CachedItemKey::GenericTemplate { .. })
    }

    #[must_use]
    pub fn finding(&self, id: CachedFindingId) -> Option<&CachedFinding> {
        self.analysis().finding(id)
    }

    /// Resolves a trace across exact dependency generations.
    ///
    /// Missing, stale, malformed, or cyclic dependency tails leave the
    /// semantic finding intact and return the verified local prefix with
    /// `complete` set to false.
    #[must_use]
    pub fn resolve_trace(&self, trace: CachedTraceId) -> CachedTraceResolution {
        let mut steps = Vec::new();
        let mut artifact = self.location.artifact;
        let mut trace = trace;
        let mut visited = HashSet::new();

        loop {
            let Some(analysis) = self.store.artifacts.get(artifact) else {
                return CachedTraceResolution::incomplete(steps);
            };
            if !visited.insert((artifact, trace)) {
                return CachedTraceResolution::incomplete(steps);
            }
            let Some(cached_trace) = analysis.trace(trace) else {
                return CachedTraceResolution::incomplete(steps);
            };
            for step in &cached_trace.steps {
                let Some(step) = analysis.trace_step(*step) else {
                    return CachedTraceResolution::incomplete(steps);
                };
                steps.push(step.to_owned());
            }

            let Some(tail) = &cached_trace.dependency_tail else {
                return CachedTraceResolution {
                    steps,
                    complete: true,
                };
            };
            let Some(dependency) = analysis.dependency(tail.dependency) else {
                return CachedTraceResolution::incomplete(steps);
            };
            let Some(next_artifact) = self
                .store
                .artifact_indices
                .get(&dependency.artifact_id)
                .copied()
            else {
                return CachedTraceResolution::incomplete(steps);
            };
            let Some(next_analysis) = self.store.artifacts.get(next_artifact) else {
                return CachedTraceResolution::incomplete(steps);
            };
            if next_analysis.analysis_id != dependency.analysis_id {
                return CachedTraceResolution::incomplete(steps);
            }
            artifact = next_artifact;
            trace = tail.trace;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedTraceResolution {
    pub steps: Vec<String>,
    pub complete: bool,
}

impl CachedTraceResolution {
    fn incomplete(steps: Vec<String>) -> Self {
        Self {
            steps,
            complete: false,
        }
    }
}

#[derive(Debug, Default)]
struct LoadedArtifacts {
    artifacts: Vec<CachedArtifactAnalysis>,
    artifact_indices: HashMap<String, usize>,
    functions: HashMap<CachedItemKey, FunctionLocation>,
}

impl LoadedArtifacts {
    fn insert(&mut self, analysis: CachedArtifactAnalysis, config: &SniffTestConfig) {
        let artifact = self.artifacts.len();
        for (function, summary) in analysis.functions.iter().enumerate() {
            if !config.all_effects_ignore_namespace(&summary.path) {
                self.functions
                    .entry(summary.key)
                    .or_insert(FunctionLocation { artifact, function });
            }
        }
        self.artifact_indices
            .insert(analysis.artifact.artifact_id.clone(), artifact);
        self.artifacts.push(analysis);
    }
}

#[derive(Debug, Clone, Copy)]
struct FunctionLocation {
    artifact: usize,
    function: usize,
}

#[derive(Debug, Default)]
struct DependencyState {
    extern_names: BTreeSet<String>,
    expected_analysis_ids: BTreeSet<AnalysisId>,
    cache: DependencyCacheState,
}

impl DependencyState {
    fn take_accepted_analysis(&mut self, artifact_id: &str) -> Option<CachedArtifactAnalysis> {
        let analysis = match std::mem::take(&mut self.cache) {
            DependencyCacheState::Available { analysis, .. } => analysis,
            cache => {
                self.cache = cache;
                return None;
            }
        };
        if !self.extern_names.is_empty()
            || self.expected_analysis_ids.is_empty()
            || self.expected_analysis_ids.contains(&analysis.analysis_id)
        {
            self.cache = DependencyCacheState::Loaded;
            return Some(*analysis);
        }

        let error = format!(
            "expected analysis generation {} for artifact {}, found {}",
            self.expected_analysis_ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" or "),
            artifact_id,
            analysis.analysis_id
        );
        self.cache = DependencyCacheState::Available {
            analysis,
            generation_error: Some(error),
        };
        None
    }

    fn is_ignored(&self) -> bool {
        matches!(self.cache, DependencyCacheState::Ignored)
    }
}

#[derive(Debug, Default)]
enum DependencyCacheState {
    #[default]
    Unread,
    Missing,
    Available {
        analysis: Box<CachedArtifactAnalysis>,
        generation_error: Option<String>,
    },
    Loaded,
    Ignored,
    Invalid(String),
}

fn read_cached_analysis(
    cache_dir: &Path,
    artifact_id: &str,
    expected: &CacheExpectations<'_>,
) -> Result<Option<CachedArtifactAnalysis>, CacheError> {
    let path = artifact_cache_path(cache_dir, artifact_id);
    match CachedArtifactAnalysis::read(&path, expected) {
        Ok(analysis) if analysis.artifact.artifact_id == artifact_id => Ok(Some(analysis)),
        Ok(analysis) => Err(CacheError::Invalid {
            path,
            reason: format!(
                "cache for artifact {artifact_id} contains artifact {}",
                analysis.artifact.artifact_id
            ),
        }),
        Err(error) if error.is_missing_file() => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use crate::cache::{
        AnalysisId, CacheExpectations, CachedArtifactAnalysis, CachedArtifactInfo,
        CachedDependencyRef, CachedDependencyTraceInput, CachedEffectInput, CachedFindingInput,
        CachedFindingKind, CachedFunctionInput, CachedItemKey, CachedTraceInput,
        artifact_cache_path,
    };
    use crate::config::SniffTestConfig;
    use crate::namespace::{StableDefPathHash, StableInstanceHash};

    use super::{DependencyAnalysisCache, DependencyInput};

    const EXPECTED: CacheExpectations<'static> = CacheExpectations {
        tool_version: "test-tool",
        rustc_version: "test-rustc",
    };

    #[test]
    fn same_named_artifacts_resolve_by_full_stable_identity() {
        let cache_dir = tempfile::tempdir().expect("cache dir");
        let first_definition = definition_hash_text("00000000000000010000000000000002");
        let second_definition = definition_hash_text("00000000000000030000000000000004");
        let first_instance = instance_hash_text("00000000000000100000000000000020");
        let second_instance = instance_hash_text("00000000000000300000000000000040");
        write_analysis(
            cache_dir.path(),
            &analysis(
                "serde-a",
                "serde",
                "0000000000000001",
                vec![(
                    CachedItemKey::exact_item(first_definition, first_instance),
                    "serde::v1",
                )],
            ),
        );
        write_analysis(
            cache_dir.path(),
            &analysis(
                "serde-b",
                "serde",
                "0000000000000003",
                vec![(
                    CachedItemKey::exact_item(second_definition, second_instance),
                    "serde::v2",
                )],
            ),
        );

        let cache = DependencyAnalysisCache::load(
            cache_dir.path(),
            &[
                dependency("serde_v1", "libserde-a.rlib"),
                dependency("serde_v2", "libserde-b.rlib"),
            ],
            &SniffTestConfig::default(),
            &EXPECTED,
        );

        let first = cache
            .function(first_definition, Some(first_instance))
            .expect("first artifact function");
        let second = cache
            .function(second_definition, Some(second_instance))
            .expect("second artifact function");
        assert_eq!(first.summary().path, "serde::v1");
        assert_eq!(second.summary().path, "serde::v2");
        assert!(!first.is_generic_template());
        assert!(!second.is_generic_template());
    }

    #[test]
    fn exact_lookup_falls_back_to_the_generic_template() {
        let cache_dir = tempfile::tempdir().expect("cache dir");
        let definition = definition_hash_text("00000000000000010000000000000002");
        let exact_instance = instance_hash_text("00000000000000100000000000000020");
        write_analysis(
            cache_dir.path(),
            &analysis(
                "generic-a",
                "generic",
                "0000000000000001",
                vec![
                    (
                        CachedItemKey::generic_template(definition),
                        "generic::template",
                    ),
                    (
                        CachedItemKey::exact_item(definition, exact_instance),
                        "generic::exact",
                    ),
                ],
            ),
        );
        let cache = DependencyAnalysisCache::load(
            cache_dir.path(),
            &[dependency("generic", "libgeneric-a.rlib")],
            &SniffTestConfig::default(),
            &EXPECTED,
        );

        let exact = cache
            .function(definition, Some(exact_instance))
            .expect("exact instance");
        let template = cache
            .function(
                definition,
                Some(instance_hash_text("00000000000000100000000000000021")),
            )
            .expect("generic template");

        assert_eq!(exact.summary().path, "generic::exact");
        assert!(!exact.is_generic_template());
        assert_eq!(template.summary().path, "generic::template");
        assert!(template.is_generic_template());
    }

    #[test]
    fn repeated_extern_aliases_load_one_artifact_generation() {
        let cache_dir = tempfile::tempdir().expect("cache dir");
        write_analysis(
            cache_dir.path(),
            &analysis("shared-a", "shared", "0000000000000001", Vec::new()),
        );

        let cache = DependencyAnalysisCache::load(
            cache_dir.path(),
            &[
                dependency("first_alias", "libshared-a.rlib"),
                dependency("second_alias", "libshared-a.rlib"),
            ],
            &SniffTestConfig::default(),
            &EXPECTED,
        );
        let dependencies = cache.direct_dependency_aliases().collect::<Vec<_>>();
        assert_eq!(
            dependencies,
            [("first_alias", "shared-a"), ("second_alias", "shared-a")]
        );
    }

    #[test]
    fn transitive_dependency_is_loaded_recursively() {
        let cache_dir = tempfile::tempdir().expect("cache dir");
        let transitive = analysis("transitive-a", "transitive", "0000000000000002", Vec::new());
        let transitive_analysis_id = transitive.analysis_id.clone();
        let root = analysis_with_dependencies(
            "root-a",
            "root",
            "0000000000000001",
            vec![CachedDependencyRef {
                artifact_id: String::from("transitive-a"),
                analysis_id: transitive_analysis_id.clone(),
            }],
        );
        write_analysis(cache_dir.path(), &transitive);
        write_analysis(cache_dir.path(), &root);

        let cache = DependencyAnalysisCache::load(
            cache_dir.path(),
            &[dependency("root", "libroot-a.rlib")],
            &SniffTestConfig::default(),
            &EXPECTED,
        );
        let transitive = cache
            .store
            .artifacts
            .iter()
            .find(|analysis| analysis.artifact.artifact_id == "transitive-a")
            .expect("transitive dependency");

        assert_eq!(transitive.analysis_id, transitive_analysis_id);
    }

    #[test]
    fn a_later_matching_parent_can_activate_a_deferred_generation() {
        let cache_dir = tempfile::tempdir().expect("cache dir");
        let child_key = exact_key(3, 30);
        let stale_child = analysis(
            "child-a",
            "child",
            "0000000000000003",
            vec![(child_key, "child::stale")],
        );
        let current_child = analysis(
            "child-a",
            "child",
            "0000000000000003",
            vec![(child_key, "child::current")],
        );
        assert_ne!(stale_child.analysis_id, current_child.analysis_id);
        let first_parent = analysis_with_dependencies(
            "root-a",
            "root_a",
            "0000000000000001",
            vec![CachedDependencyRef {
                artifact_id: String::from("child-a"),
                analysis_id: stale_child.analysis_id,
            }],
        );
        let second_parent = analysis_with_dependencies(
            "root-b",
            "root_b",
            "0000000000000002",
            vec![CachedDependencyRef {
                artifact_id: String::from("child-a"),
                analysis_id: current_child.analysis_id.clone(),
            }],
        );
        write_analysis(cache_dir.path(), &current_child);
        write_analysis(cache_dir.path(), &first_parent);
        write_analysis(cache_dir.path(), &second_parent);

        let cache = DependencyAnalysisCache::load(
            cache_dir.path(),
            &[
                dependency("root_a", "libroot-a.rlib"),
                dependency("root_b", "libroot-b.rlib"),
            ],
            &SniffTestConfig::default(),
            &EXPECTED,
        );
        let child = cache
            .function(definition_hash(3), Some(instance_hash_value(30)))
            .expect("current child generation");

        assert_eq!(child.summary().path, "child::current");
        assert!(cache.load_failures().next().is_none());
    }

    #[test]
    fn missing_cache_file_is_a_normal_miss() {
        let cache_dir = tempfile::tempdir().expect("cache dir");

        let cache = DependencyAnalysisCache::load(
            cache_dir.path(),
            &[dependency("missing", "libmissing-a.rlib")],
            &SniffTestConfig::default(),
            &EXPECTED,
        );

        assert_eq!(cache.load_failures().count(), 0);
        assert!(cache.store.artifacts.is_empty());
        assert!(cache.tracks_artifact_path(Path::new("/deps/libmissing-a.rmeta")));
        assert!(!cache.tracks_artifact_path(Path::new("/sysroot/libcore-a.rmeta")));
    }

    #[test]
    fn corrupt_cache_file_is_a_load_failure() {
        let cache_dir = tempfile::tempdir().expect("cache dir");
        let path = artifact_cache_path(cache_dir.path(), "corrupt-a");
        fs::create_dir_all(path.parent().expect("artifact cache parent"))
            .expect("create artifact cache");
        fs::write(&path, "{not-json").expect("write corrupt cache");

        let cache = DependencyAnalysisCache::load(
            cache_dir.path(),
            &[dependency("corrupt", "libcorrupt-a.rlib")],
            &SniffTestConfig::default(),
            &EXPECTED,
        );
        let failures = cache.load_failures().collect::<Vec<_>>();

        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, "corrupt");
        assert!(failures[0].1.contains("failed to parse"));
    }

    #[test]
    fn resolves_a_trace_through_the_declared_dependency_generation() {
        let cache_dir = tempfile::tempdir().expect("cache dir");
        let dependency_analysis = analysis_with_finding(
            "dependency-a",
            "dependency",
            "0000000000000002",
            exact_key(2, 20),
            "dependency::hidden",
            "dependency step",
            None,
        );
        let dependency_trace = dependency_trace(&dependency_analysis);
        let root = analysis_with_finding(
            "root-a",
            "root",
            "0000000000000001",
            exact_key(1, 10),
            "root::entry",
            "root step",
            Some(CachedDependencyTraceInput {
                artifact_id: String::from("dependency-a"),
                analysis_id: dependency_analysis.analysis_id.clone(),
                trace: dependency_trace,
            }),
        );
        write_analysis(cache_dir.path(), &dependency_analysis);
        write_analysis(cache_dir.path(), &root);

        let cache = DependencyAnalysisCache::load(
            cache_dir.path(),
            &[dependency("root", "libroot-a.rlib")],
            &SniffTestConfig::default(),
            &EXPECTED,
        );
        let function = cache
            .function(definition_hash(1), Some(instance_hash_value(10)))
            .expect("root function");
        let finding = function
            .finding(function.summary().panic.findings[0])
            .expect("root finding");
        let trace = function.resolve_trace(finding.trace);

        assert!(trace.complete);
        assert_eq!(trace.steps, ["root step", "dependency step"]);
    }

    #[test]
    fn missing_dependency_generation_keeps_the_verified_trace_prefix() {
        let cache_dir = tempfile::tempdir().expect("cache dir");
        let missing_generation = AnalysisId::from("missing-generation");
        let root = analysis_with_finding(
            "root-a",
            "root",
            "0000000000000001",
            exact_key(1, 10),
            "root::entry",
            "root step",
            Some(CachedDependencyTraceInput {
                artifact_id: String::from("dependency-a"),
                analysis_id: missing_generation.clone(),
                trace: crate::cache::CachedTraceId::new(0),
            }),
        );
        write_analysis(cache_dir.path(), &root);

        let cache = DependencyAnalysisCache::load(
            cache_dir.path(),
            &[dependency("root", "libroot-a.rlib")],
            &SniffTestConfig::default(),
            &EXPECTED,
        );
        let function = cache
            .function(definition_hash(1), Some(instance_hash_value(10)))
            .expect("root function");
        let finding = function
            .finding(function.summary().panic.findings[0])
            .expect("root finding");
        let trace = function.resolve_trace(finding.trace);

        assert!(!trace.complete);
        assert_eq!(trace.steps.len(), 1);
        assert_eq!(trace.steps[0], "root step");
    }

    #[test]
    fn mismatched_dependency_generation_is_not_loaded_as_the_declared_tail() {
        let cache_dir = tempfile::tempdir().expect("cache dir");
        let stale = analysis_with_finding(
            "dependency-a",
            "dependency",
            "0000000000000002",
            exact_key(2, 20),
            "dependency::hidden",
            "stale step",
            None,
        );
        let stale_trace = dependency_trace(&stale);
        let current = analysis_with_finding(
            "dependency-a",
            "dependency",
            "0000000000000002",
            exact_key(2, 20),
            "dependency::hidden",
            "current step",
            None,
        );
        assert_ne!(stale.analysis_id, current.analysis_id);
        let root = analysis_with_finding(
            "root-a",
            "root",
            "0000000000000001",
            exact_key(1, 10),
            "root::entry",
            "root step",
            Some(CachedDependencyTraceInput {
                artifact_id: String::from("dependency-a"),
                analysis_id: stale.analysis_id.clone(),
                trace: stale_trace,
            }),
        );
        write_analysis(cache_dir.path(), &current);
        write_analysis(cache_dir.path(), &root);

        let cache = DependencyAnalysisCache::load(
            cache_dir.path(),
            &[dependency("root", "libroot-a.rlib")],
            &SniffTestConfig::default(),
            &EXPECTED,
        );
        let function = cache
            .function(definition_hash(1), Some(instance_hash_value(10)))
            .expect("root function");
        let finding = function
            .finding(function.summary().panic.findings[0])
            .expect("root finding");
        let trace = function.resolve_trace(finding.trace);
        let failures = cache.load_failures().collect::<Vec<_>>();

        assert!(!trace.complete);
        assert_eq!(trace.steps.len(), 1);
        assert_eq!(trace.steps[0], "root step");
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, "dependency-a");
        assert!(failures[0].1.contains("expected analysis generation"));
    }

    fn analysis(
        artifact_id: &str,
        crate_name: &str,
        stable_crate_id: &str,
        functions: Vec<(CachedItemKey, &str)>,
    ) -> CachedArtifactAnalysis {
        CachedArtifactAnalysis::new(
            EXPECTED.tool_version,
            EXPECTED.rustc_version,
            CachedArtifactInfo {
                artifact_id: artifact_id.to_owned(),
                crate_name: crate_name.to_owned(),
                stable_crate_id: u64::from_str_radix(stable_crate_id, 16).expect("stable crate id"),
            },
            functions
                .into_iter()
                .map(|(key, path)| CachedFunctionInput {
                    key,
                    path: path.to_owned(),
                    panic: clean_effect(),
                    safety: clean_effect(),
                })
                .collect(),
        )
        .expect("valid analysis")
    }

    fn clean_effect() -> CachedEffectInput {
        CachedEffectInput {
            analysis_complete: true,
            has_contract: false,
            findings: Vec::new(),
        }
    }

    fn analysis_with_dependencies(
        artifact_id: &str,
        crate_name: &str,
        stable_crate_id: &str,
        dependencies: Vec<CachedDependencyRef>,
    ) -> CachedArtifactAnalysis {
        let stable_crate_id = u64::from_str_radix(stable_crate_id, 16).expect("stable crate id");
        let findings = dependencies
            .into_iter()
            .enumerate()
            .map(|(index, dependency)| CachedFindingInput {
                kind: CachedFindingKind::PanicInvocation,
                compiler_assert_kind: None,
                safety_op_kind: None,
                span: format!("dependency {index}"),
                source_span: None,
                trace: CachedTraceInput {
                    steps: Vec::new(),
                    dependency_tail: Some(CachedDependencyTraceInput {
                        artifact_id: dependency.artifact_id,
                        analysis_id: dependency.analysis_id,
                        trace: crate::cache::CachedTraceId::new(0),
                    }),
                },
                reason: String::from("dependency edge"),
                missing_requirements: Vec::new(),
            })
            .collect::<Vec<_>>();
        CachedArtifactAnalysis::new(
            EXPECTED.tool_version,
            EXPECTED.rustc_version,
            CachedArtifactInfo {
                artifact_id: artifact_id.to_owned(),
                crate_name: crate_name.to_owned(),
                stable_crate_id,
            },
            (!findings.is_empty())
                .then(|| CachedFunctionInput {
                    key: exact_key(stable_crate_id, 0),
                    path: format!("{crate_name}::__dependency_edges"),
                    panic: CachedEffectInput {
                        analysis_complete: true,
                        has_contract: false,
                        findings,
                    },
                    safety: clean_effect(),
                })
                .into_iter()
                .collect(),
        )
        .expect("valid analysis")
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test factory exposes each independently varied cache field"
    )]
    fn analysis_with_finding(
        artifact_id: &str,
        crate_name: &str,
        stable_crate_id: &str,
        key: CachedItemKey,
        path: &str,
        step_span: &str,
        dependency_tail: Option<CachedDependencyTraceInput>,
    ) -> CachedArtifactAnalysis {
        CachedArtifactAnalysis::new(
            EXPECTED.tool_version,
            EXPECTED.rustc_version,
            CachedArtifactInfo {
                artifact_id: artifact_id.to_owned(),
                crate_name: crate_name.to_owned(),
                stable_crate_id: u64::from_str_radix(stable_crate_id, 16).expect("stable crate id"),
            },
            vec![CachedFunctionInput {
                key,
                path: path.to_owned(),
                panic: CachedEffectInput {
                    analysis_complete: true,
                    has_contract: false,
                    findings: vec![CachedFindingInput {
                        kind: CachedFindingKind::PanicInvocation,
                        compiler_assert_kind: None,
                        safety_op_kind: None,
                        span: step_span.to_owned(),
                        source_span: None,
                        trace: CachedTraceInput {
                            steps: vec![trace_step(step_span)],
                            dependency_tail,
                        },
                        reason: String::from("panic"),
                        missing_requirements: Vec::new(),
                    }],
                },
                safety: clean_effect(),
            }],
        )
        .expect("valid analysis")
    }

    fn dependency_trace(analysis: &CachedArtifactAnalysis) -> crate::cache::CachedTraceId {
        let finding_id = analysis.functions[0].panic.findings[0];
        analysis.finding(finding_id).expect("finding").trace
    }

    fn trace_step(span: &str) -> String {
        span.to_owned()
    }

    fn exact_key(definition: u64, instance: u64) -> CachedItemKey {
        CachedItemKey::exact_item(definition_hash(definition), instance_hash_value(instance))
    }

    fn write_analysis(cache_dir: &Path, analysis: &CachedArtifactAnalysis) {
        analysis.write(cache_dir).expect("write analysis");
    }

    fn dependency(name: &str, filename: &str) -> DependencyInput {
        DependencyInput {
            name: name.to_owned(),
            path: Path::new("/deps").join(filename),
        }
    }

    fn definition_hash_text(value: &str) -> StableDefPathHash {
        serde_json::from_value(serde_json::Value::String(value.to_owned()))
            .expect("definition hash")
    }

    fn instance_hash_text(value: &str) -> StableInstanceHash {
        serde_json::from_value(serde_json::Value::String(value.to_owned())).expect("instance hash")
    }

    fn definition_hash(value: u64) -> StableDefPathHash {
        definition_hash_text(&format!("{value:016x}{value:016x}"))
    }

    fn instance_hash_value(value: u64) -> StableInstanceHash {
        instance_hash_text(&format!("{value:032x}"))
    }
}
