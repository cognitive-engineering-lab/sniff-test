//! Runtime view of cached dependency analyses.
//!
//! This module loads cache files for the `--extern` artifacts rustc passed to
//! the current compilation. It indexes panic-reachable functions by artifact id
//! and function path, then only permits crate-name lookup when that crate name
//! resolves to exactly one artifact.

use std::collections::{HashMap, hash_map::Entry};
use std::path::{Path, PathBuf};

use crate::cache::{
    CachedArtifactAnalysis, CachedDependencyRef, CachedFunctionSummary, artifact_cache_path,
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
            let analysis = exact_cache_path
                .as_deref()
                .and_then(|path| read_artifact_analysis(path).ok());

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
                    if function.is_panic_reachable() && !config.ignores_namespace(&function.path) {
                        functions.insert(
                            FunctionCacheKey {
                                artifact_id: analysis_artifact_id.clone(),
                                path: function.path.clone(),
                            },
                            function.clone(),
                        );
                    }
                }
            }

            dependencies.push(ResolvedDependency {
                extern_name: extern_arg.name,
                artifact_path: extern_arg.path,
                artifact_id,
                exact_cache_path,
                analysis,
            });
        }

        Self {
            dependencies,
            crate_artifacts,
            functions,
        }
    }

    #[must_use]
    pub fn function(&self, crate_name: &str, path: &str) -> Option<&CachedFunctionSummary> {
        let artifact_id = self.unique_artifact_id(crate_name)?;
        self.functions.get(&FunctionCacheKey {
            artifact_id: artifact_id.to_owned(),
            path: path.to_owned(),
        })
    }

    #[must_use]
    pub fn dependency_count(&self) -> usize {
        self.dependencies.len()
    }

    #[must_use]
    pub fn hit_count(&self) -> usize {
        self.dependencies
            .iter()
            .filter(|dependency| dependency.analysis.is_some())
            .count()
    }

    #[must_use]
    pub fn resolved_dependencies(&self) -> Vec<CachedDependencyRef> {
        self.dependencies
            .iter()
            .map(|dependency| CachedDependencyRef {
                extern_name: dependency.extern_name.clone(),
                artifact_path: dependency
                    .artifact_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
                artifact_id: dependency.artifact_id.clone(),
                exact_cache_path: dependency
                    .exact_cache_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
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
    path: String,
}

#[derive(Debug)]
enum CrateArtifactIndex {
    Unique(String),
    Ambiguous,
}

#[derive(Debug)]
struct ResolvedDependency {
    extern_name: String,
    artifact_path: Option<PathBuf>,
    artifact_id: Option<String>,
    exact_cache_path: Option<PathBuf>,
    analysis: Option<CachedArtifactAnalysis>,
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
                path: String::from("serde::from_str"),
            },
            function_summary("serde::from_str"),
        );

        assert!(cache.function("serde", "serde::from_str").is_none());
    }

    fn function_summary(path: &str) -> CachedFunctionSummary {
        CachedFunctionSummary {
            path: path.to_owned(),
            is_generic: false,
            has_panic_docs: false,
            raw_panic_paths: 1,
            panic_obligations: 0,
            trusted_panic_obligations: 0,
            graph: None,
            findings: Vec::new(),
        }
    }
}
