//! Runtime view of cached dependency analyses.
//!
//! This module loads cache files for the `--extern` artifacts rustc passed to
//! the current compilation. It indexes panic-reachable functions by artifact id
//! and def path hash, then only permits crate-name lookup when that crate name
//! resolves to exactly one artifact.

use std::collections::{HashMap, hash_map::Entry};
use std::path::{Path, PathBuf};

use crate::cache::{
    CacheExpectations, CachedDependencyRef, CachedFunctionSummary, artifact_cache_path,
    artifact_id_from_extern_path, read_artifact_analysis,
};
use crate::config::PanicConfig;

/// A rustc `--extern` dependency relevant to cache lookup.
#[derive(Debug, Clone)]
pub struct DependencyInput {
    pub name: String,
    pub path: Option<PathBuf>,
}

/// Loaded dependency cache for one rustc invocation.
///
/// The cache deliberately fails closed for ambiguous crate names. If two loaded
/// artifacts both report the same crate name, callers cannot accidentally reuse
/// a summary from the wrong artifact.
#[derive(Debug, Default)]
pub struct DependencyAnalysisCache {
    dependencies: Vec<ResolvedDependency>,
    crate_artifacts: HashMap<String, CrateArtifactIndex>,
    functions: HashMap<FunctionCacheKey, CachedFunctionSummary>,
}

impl DependencyAnalysisCache {
    #[must_use]
    pub fn load(
        cache_dir: &Path,
        externs: impl IntoIterator<Item = DependencyInput>,
        config: &PanicConfig,
        expected: &CacheExpectations<'_>,
    ) -> Self {
        let mut dependencies = Vec::new();
        let mut crate_artifacts = HashMap::new();
        let mut functions = HashMap::new();

        for extern_arg in externs {
            if config.ignores_namespace(&extern_arg.name) {
                continue;
            }

            let artifact_id = extern_arg
                .path
                .as_deref()
                .and_then(artifact_id_from_extern_path);
            let exact_cache_path = artifact_id
                .as_deref()
                .map(|id| artifact_cache_path(cache_dir, id));
            let mut load_error = None;
            let analysis = exact_cache_path.as_deref().and_then(|path| {
                match read_artifact_analysis(path, expected) {
                    Ok(analysis) => Some(analysis),
                    Err(error) => {
                        // A missing file is the routine miss for crates that
                        // were never analyzed, such as sysroot crates.
                        if !error.is_missing_file() {
                            load_error = Some(error.to_string());
                        }
                        None
                    }
                }
            });

            if let Some(analysis) = &analysis {
                if config.ignores_namespace(&analysis.artifact.crate_name) {
                    continue;
                }

                let analysis_artifact_id = analysis.artifact.artifact_id.clone();
                match crate_artifacts.entry(analysis.artifact.crate_name.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(CrateArtifactIndex::Unique(analysis_artifact_id.clone()));
                    }
                    Entry::Occupied(mut entry) => match entry.get() {
                        CrateArtifactIndex::Unique(existing)
                            if existing == &analysis_artifact_id => {}
                        CrateArtifactIndex::Unique(_) => {
                            entry.insert(CrateArtifactIndex::Ambiguous);
                        }
                        CrateArtifactIndex::Ambiguous => {}
                    },
                }

                for function in analysis.functions.values() {
                    // Incomplete summaries stay loaded even with clean counts:
                    // their evidence under-approximates.
                    if (function.is_panic_reachable() || !function.analysis_complete)
                        && !config.ignores_namespace(&function.path)
                    {
                        functions.insert(
                            FunctionCacheKey {
                                artifact_id: analysis_artifact_id.clone(),
                                def_path_hash: function.def_path_hash.clone(),
                            },
                            function.clone(),
                        );
                    }
                }
            }

            dependencies.push(ResolvedDependency {
                extern_name: extern_arg.name,
                artifact_id,
                load_error,
            });
        }

        Self {
            dependencies,
            crate_artifacts,
            functions,
        }
    }

    #[must_use]
    pub fn function(
        &self,
        crate_name: &str,
        def_path_hash: &str,
    ) -> Option<&CachedFunctionSummary> {
        let artifact_id = self.unique_artifact_id(crate_name)?;
        self.functions.get(&FunctionCacheKey {
            artifact_id: artifact_id.to_owned(),
            def_path_hash: def_path_hash.to_owned(),
        })
    }

    /// Extern names whose cache files exist but could not be used, with the
    /// reason. Missing files are not failures.
    pub fn load_failures(&self) -> impl Iterator<Item = (&str, &str)> {
        self.dependencies.iter().filter_map(|dependency| {
            let error = dependency.load_error.as_deref()?;
            Some((dependency.extern_name.as_str(), error))
        })
    }

    /// Crate names that resolved to more than one cached artifact; their
    /// evidence is disabled because lookups cannot pick a version.
    #[must_use]
    pub fn ambiguous_crate_names(&self) -> Vec<&str> {
        let mut names = self
            .crate_artifacts
            .iter()
            .filter(|(_, index)| matches!(index, CrateArtifactIndex::Ambiguous))
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        names.sort_unstable();
        names
    }

    #[must_use]
    pub fn resolved_dependencies(&self) -> Vec<CachedDependencyRef> {
        self.dependencies
            .iter()
            .filter_map(|dependency| {
                Some(CachedDependencyRef {
                    extern_name: dependency.extern_name.clone(),
                    artifact_id: dependency.artifact_id.clone()?,
                })
            })
            .collect()
    }

    fn unique_artifact_id(&self, crate_name: &str) -> Option<&str> {
        match self.crate_artifacts.get(crate_name)? {
            CrateArtifactIndex::Unique(artifact_id) => Some(artifact_id),
            CrateArtifactIndex::Ambiguous => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FunctionCacheKey {
    artifact_id: String,
    def_path_hash: String,
}

#[derive(Debug)]
enum CrateArtifactIndex {
    Unique(String),
    Ambiguous,
}

#[derive(Debug)]
struct ResolvedDependency {
    extern_name: String,
    artifact_id: Option<String>,
    load_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::cache::CachedFunctionSummary;

    use super::{CrateArtifactIndex, DependencyAnalysisCache, FunctionCacheKey};

    #[test]
    fn duplicate_crate_names_do_not_reuse_an_arbitrary_cached_function() {
        let mut cache = DependencyAnalysisCache::default();
        cache
            .crate_artifacts
            .insert(String::from("serde"), CrateArtifactIndex::Ambiguous);
        cache.functions.insert(
            FunctionCacheKey {
                artifact_id: String::from("serde-a"),
                def_path_hash: String::from("00000000000000010000000000000002"),
            },
            function_summary("serde::from_str"),
        );

        assert!(
            cache
                .function("serde", "00000000000000010000000000000002")
                .is_none()
        );
        assert_eq!(cache.ambiguous_crate_names(), ["serde"]);
    }

    fn function_summary(path: &str) -> CachedFunctionSummary {
        CachedFunctionSummary {
            def_path_hash: String::from("00000000000000010000000000000002"),
            path: path.to_owned(),
            is_generic: false,
            analysis_complete: true,
            has_panic_docs: false,
            root_span: None,
            raw_panic_paths: 1,
            panic_obligations: 0,
            trusted_panic_obligations: 0,
            graph: None,
            findings: Vec::new(),
        }
    }
}
