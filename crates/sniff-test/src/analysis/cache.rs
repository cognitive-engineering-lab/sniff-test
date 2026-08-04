//! Versioned on-disk envelope for policy-neutral artifact analysis IR.
//!
//! The cache contains extraction facts only. Lint levels, selected report
//! roots, interpreted findings, and rendered traces deliberately live outside
//! this schema so a workspace can reinterpret one dependency artifact under a
//! different policy without recompiling it.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::hash::Hasher as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use rustc_data_structures::{fingerprint::Fingerprint, stable_hasher::StableHasher};
use serde::{Deserialize, Serialize};

use super::ir::{ArtifactAnalysisIr, FunctionBodyProvenanceIr};

pub(crate) const CACHE_FORMAT_VERSION: u32 = 13;
pub(crate) const CACHE_DIR_NAME: &str = "sniff-test-cache";
pub(crate) const CACHE_VERSION_DIR: &str = "v13";

/// Cached policy-neutral analysis for one exact rustc output artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ArtifactAnalysisCache {
    pub(crate) format_version: u32,
    pub(crate) tool_version: String,
    pub(crate) rustc_version: String,
    pub(crate) compiler_fingerprint: String,
    pub(crate) analysis_id: AnalysisId,
    pub(crate) artifact: ArtifactInfo,
    pub(crate) dependencies: Vec<DependencyAnalysisRef>,
    pub(crate) ir: ArtifactAnalysisIr,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct CacheFormatHeader {
    format_version: u32,
}

impl ArtifactAnalysisCache {
    /// Builds a validated cache value in deterministic serialized order.
    pub(crate) fn new(
        tool_version: impl Into<String>,
        rustc_version: impl Into<String>,
        compiler_fingerprint: impl Into<String>,
        artifact: ArtifactInfo,
        dependencies: Vec<DependencyAnalysisRef>,
        mut ir: ArtifactAnalysisIr,
    ) -> Result<Self, CacheValidationError> {
        let dependencies = canonical_dependencies(dependencies)?;
        ir.canonicalize();
        let mut analysis = Self {
            format_version: CACHE_FORMAT_VERSION,
            tool_version: tool_version.into(),
            rustc_version: rustc_version.into(),
            compiler_fingerprint: compiler_fingerprint.into(),
            analysis_id: AnalysisId::default(),
            artifact,
            dependencies,
            ir,
        };
        analysis.validate()?;
        analysis.analysis_id = analysis.compute_analysis_id()?;
        Ok(analysis)
    }

    /// Writes this analysis to the path derived from its artifact identity.
    pub(crate) fn write(&self, cache_dir: &Path) -> Result<(), CacheError> {
        let path = artifact_cache_path(cache_dir, &self.artifact.artifact_id);
        self.validate()
            .map_err(|error| CacheError::invalid(&path, error))?;
        let expected_id = self
            .compute_analysis_id()
            .map_err(|error| CacheError::invalid(&path, error))?;
        if self.analysis_id != expected_id {
            return Err(CacheError::Invalid {
                path,
                reason: format!(
                    "analysis id {} does not match canonical content {expected_id}",
                    self.analysis_id
                ),
            });
        }
        let source = serde_json::to_string_pretty(self).map_err(|source| CacheError::Json {
            path: path.clone(),
            source,
        })?;
        write_atomic(&path, &source)
    }

    /// Reads and validates one v13 cache file against the active extraction
    /// environment.
    pub(crate) fn read(path: &Path, expected: &CacheExpectations<'_>) -> Result<Self, CacheError> {
        let source = std::fs::read_to_string(path).map_err(|source| CacheError::Io {
            path: path.to_owned(),
            source,
        })?;
        let header = serde_json::from_str::<CacheFormatHeader>(&source).map_err(|source| {
            CacheError::Json {
                path: path.to_owned(),
                source,
            }
        })?;
        if header.format_version != CACHE_FORMAT_VERSION {
            return Err(CacheError::Format {
                path: path.to_owned(),
                version: header.format_version,
            });
        }

        let analysis =
            serde_json::from_str::<Self>(&source).map_err(|source| CacheError::Json {
                path: path.to_owned(),
                source,
            })?;
        for (field, found, expected) in [
            (
                "sniff-test",
                analysis.tool_version.as_str(),
                expected.tool_version,
            ),
            (
                "rustc",
                analysis.rustc_version.as_str(),
                expected.rustc_version,
            ),
        ] {
            if found != expected {
                return Err(CacheError::Version {
                    path: path.to_owned(),
                    field,
                    found: found.to_owned(),
                    expected: expected.to_owned(),
                });
            }
        }
        analysis
            .validate()
            .map_err(|error| CacheError::invalid(path, error))?;
        let expected_id = analysis
            .compute_analysis_id()
            .map_err(|error| CacheError::invalid(path, error))?;
        if analysis.analysis_id != expected_id {
            return Err(CacheError::Invalid {
                path: path.to_owned(),
                reason: format!(
                    "analysis id {} does not match canonical content {expected_id}",
                    analysis.analysis_id
                ),
            });
        }
        Ok(analysis)
    }

    fn validate(&self) -> Result<(), CacheValidationError> {
        if self.format_version != CACHE_FORMAT_VERSION {
            return Err(CacheValidationError::new(format!(
                "analysis declares cache format {}, expected {}",
                self.format_version, CACHE_FORMAT_VERSION
            )));
        }
        for (value, label) in [
            (self.tool_version.as_str(), "sniff-test version"),
            (self.rustc_version.as_str(), "rustc version"),
            (
                self.compiler_fingerprint.as_str(),
                "compiler configuration fingerprint",
            ),
            (self.artifact.artifact_id.as_str(), "artifact ID"),
            (self.artifact.crate_name.as_str(), "artifact crate name"),
        ] {
            if value.trim().is_empty() {
                return Err(CacheValidationError::new(format!(
                    "{label} must not be empty"
                )));
            }
        }
        if self
            .artifact
            .crate_hash
            .as_deref()
            .is_some_and(|hash| hash.trim().is_empty())
        {
            return Err(CacheValidationError::new(
                "rustc crate hash must not be empty when present",
            ));
        }
        validate_dependencies(&self.artifact, &self.dependencies)?;
        self.ir
            .validate()
            .map_err(|error| CacheValidationError::new(error.to_string()))?;
        for (index, body) in self.ir.functions.iter().enumerate() {
            let definition_stable_crate_id = body.function.def_path_hash.stable_crate_id();
            match body.provenance {
                FunctionBodyProvenanceIr::DefiningArtifact
                    if definition_stable_crate_id != self.artifact.stable_crate_id =>
                {
                    return Err(CacheValidationError::new(format!(
                        "defining function {index} does not belong to artifact stable crate id \
                         {:016x}",
                        self.artifact.stable_crate_id
                    )));
                }
                FunctionBodyProvenanceIr::ConsumerInstantiation {
                    consumer_stable_crate_id,
                } if consumer_stable_crate_id != self.artifact.stable_crate_id => {
                    return Err(CacheValidationError::new(format!(
                        "consumer function {index} names stable crate id \
                         {consumer_stable_crate_id:016x}, expected {:016x}",
                        self.artifact.stable_crate_id
                    )));
                }
                FunctionBodyProvenanceIr::ConsumerInstantiation { .. }
                    if definition_stable_crate_id == self.artifact.stable_crate_id =>
                {
                    return Err(CacheValidationError::new(format!(
                        "consumer function {index} must be defined by another artifact"
                    )));
                }
                FunctionBodyProvenanceIr::DefiningArtifact
                | FunctionBodyProvenanceIr::ConsumerInstantiation { .. } => {}
            }
        }
        Ok(())
    }

    fn compute_analysis_id(&self) -> Result<AnalysisId, CacheValidationError> {
        let mut canonical = self.clone();
        canonical.analysis_id = AnalysisId::default();
        let source = serde_json::to_vec(&canonical).map_err(|error| {
            CacheValidationError::new(format!("cannot fingerprint cache data: {error}"))
        })?;
        let mut hasher = StableHasher::new();
        hasher.write(&source);
        let mut id = String::with_capacity(32);
        for byte in hasher.finish::<Fingerprint>().to_le_bytes() {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            id.push(char::from(HEX[usize::from(byte >> 4)]));
            id.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(AnalysisId(id))
    }
}

/// Deterministic generation identity for one sealed artifact IR.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct AnalysisId(String);

impl From<&str> for AnalysisId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for AnalysisId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl Display for AnalysisId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Identity and provenance for the exact compiled artifact represented here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ArtifactInfo {
    pub(crate) artifact_id: String,
    pub(crate) crate_name: String,
    pub(crate) stable_crate_id: u64,
    /// rustc's strict version hash (SVH), when this compilation configuration
    /// produces one. Artifacts that cannot be loaded as dependencies, such as
    /// ordinary executables, may not need a crate hash.
    pub(crate) crate_hash: Option<String>,
}

/// Exact dependency generation needed to compose this artifact's graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct DependencyAnalysisRef {
    pub(crate) artifact_id: String,
    pub(crate) analysis_id: AnalysisId,
}

fn canonical_dependencies(
    dependencies: Vec<DependencyAnalysisRef>,
) -> Result<Vec<DependencyAnalysisRef>, CacheValidationError> {
    let mut by_artifact = BTreeMap::<String, AnalysisId>::new();
    for dependency in dependencies {
        match by_artifact.entry(dependency.artifact_id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(dependency.analysis_id);
            }
            std::collections::btree_map::Entry::Occupied(entry)
                if entry.get() == &dependency.analysis_id => {}
            std::collections::btree_map::Entry::Occupied(entry) => {
                return Err(CacheValidationError::new(format!(
                    "dependency {} has conflicting analysis generations {} and {}",
                    entry.key(),
                    entry.get(),
                    dependency.analysis_id
                )));
            }
        }
    }
    Ok(by_artifact
        .into_iter()
        .map(|(artifact_id, analysis_id)| DependencyAnalysisRef {
            artifact_id,
            analysis_id,
        })
        .collect())
}

fn validate_dependencies(
    artifact: &ArtifactInfo,
    dependencies: &[DependencyAnalysisRef],
) -> Result<(), CacheValidationError> {
    for pair in dependencies.windows(2) {
        if pair[0].artifact_id >= pair[1].artifact_id {
            return Err(CacheValidationError::new(
                "dependencies must be uniquely sorted by artifact id",
            ));
        }
    }
    for dependency in dependencies {
        if dependency.artifact_id.trim().is_empty() {
            return Err(CacheValidationError::new(
                "dependency artifact ID must not be empty",
            ));
        }
        if dependency.artifact_id == artifact.artifact_id {
            return Err(CacheValidationError::new(format!(
                "artifact {} cannot depend on its own analysis",
                artifact.artifact_id
            )));
        }
        if dependency.analysis_id.0.trim().is_empty() {
            return Err(CacheValidationError::new(format!(
                "dependency {} has an empty analysis generation",
                dependency.artifact_id
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CacheValidationError {
    reason: String,
}

impl CacheValidationError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl Display for CacheValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.reason.fmt(formatter)
    }
}

impl std::error::Error for CacheValidationError {}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CacheExpectations<'a> {
    pub(crate) tool_version: &'a str,
    pub(crate) rustc_version: &'a str,
}

#[derive(Debug)]
pub(crate) enum CacheError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    Format {
        path: PathBuf,
        version: u32,
    },
    Version {
        path: PathBuf,
        field: &'static str,
        found: String,
        expected: String,
    },
    Invalid {
        path: PathBuf,
        reason: String,
    },
}

impl CacheError {
    fn invalid(path: &Path, error: CacheValidationError) -> Self {
        Self::Invalid {
            path: path.to_owned(),
            reason: error.reason,
        }
    }

    #[must_use]
    pub(crate) fn is_missing_file(&self) -> bool {
        matches!(
            self,
            Self::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound
        )
    }
}

impl Display for CacheError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "failed to access {}: {source}", path.display())
            }
            Self::Json { path, source } => {
                write!(formatter, "failed to parse {}: {source}", path.display())
            }
            Self::Format { path, version } => write!(
                formatter,
                "unsupported cache format {version} in {}",
                path.display()
            ),
            Self::Version {
                path,
                field,
                found,
                expected,
            } => write!(
                formatter,
                "stale cache {}: written by {field} {found}, current is {expected}",
                path.display()
            ),
            Self::Invalid { path, reason } => {
                write!(formatter, "invalid cache {}: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Format { .. } | Self::Version { .. } | Self::Invalid { .. } => None,
        }
    }
}

#[must_use]
pub(crate) fn artifact_cache_path(cache_dir: &Path, artifact_id: &str) -> PathBuf {
    cache_dir
        .join("artifacts")
        .join(format!("{}.json", sanitize_path_component(artifact_id)))
}

#[must_use]
pub(crate) fn artifact_id(crate_name: &str, extra_filename: Option<&str>) -> String {
    format!("{}{}", crate_name, extra_filename.unwrap_or_default())
}

#[must_use]
pub(crate) fn default_cache_dir(target_dir: impl AsRef<Path>) -> PathBuf {
    target_dir
        .as_ref()
        .join(CACHE_DIR_NAME)
        .join(CACHE_VERSION_DIR)
}

fn write_atomic(path: &Path, source: &str) -> Result<(), CacheError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|source| CacheError::Io {
        path: parent.to_owned(),
        source,
    })?;
    let mut temporary_file =
        tempfile::NamedTempFile::new_in(parent).map_err(|source| CacheError::Io {
            path: parent.to_owned(),
            source,
        })?;
    temporary_file
        .write_all(source.as_bytes())
        .map_err(|source| CacheError::Io {
            path: temporary_file.path().to_owned(),
            source,
        })?;
    temporary_file
        .persist(path)
        .map(|_| ())
        .map_err(|error| CacheError::Io {
            path: path.to_owned(),
            source: error.error,
        })
}

fn sanitize_path_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        String::from("_")
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{
        AnalysisId, ArtifactAnalysisCache, ArtifactInfo, CACHE_FORMAT_VERSION, CacheError,
        CacheExpectations, DependencyAnalysisRef, artifact_cache_path, default_cache_dir,
    };
    use crate::analysis::ir::{
        ArtifactAnalysisIr, FunctionAttributesIr, FunctionBodyIr, FunctionBodyProvenanceIr,
        FunctionId,
    };
    use crate::namespace::{StableDefPathHash, StableInstanceHash};

    const LOCAL_STABLE_CRATE_ID: u64 = 1;

    fn def_hash(value: &str) -> StableDefPathHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid definition hash")
    }

    fn instance_hash(value: &str) -> StableInstanceHash {
        serde_json::from_str(&format!("\"{value}\"")).expect("valid instance hash")
    }

    fn ir() -> ArtifactAnalysisIr {
        ArtifactAnalysisIr::new(
            vec![FunctionBodyIr {
                function: FunctionId::generic(def_hash("00000000000000010000000000000002")),
                provenance: FunctionBodyProvenanceIr::DefiningArtifact,
                display_path: String::from("sample::root"),
                attributes: FunctionAttributesIr {
                    is_unsafe: false,
                    is_exported: true,
                    has_rust_body: true,
                    is_foreign: false,
                    namespace_candidates: vec![String::from("sample::root")],
                },
                source_range: None,
                calls: Vec::new(),
                effects: Vec::new(),
                markers: Vec::new(),
            }],
            Vec::new(),
        )
        .expect("valid IR")
    }

    fn artifact() -> ArtifactInfo {
        ArtifactInfo {
            artifact_id: String::from("sample-a1b2"),
            crate_name: String::from("sample"),
            stable_crate_id: LOCAL_STABLE_CRATE_ID,
            crate_hash: Some(String::from("0123456789abcdef0123456789abcdef")),
        }
    }

    fn analysis(compiler_fingerprint: &str) -> ArtifactAnalysisCache {
        ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc 1.90.0-nightly",
            compiler_fingerprint,
            artifact(),
            vec![DependencyAnalysisRef {
                artifact_id: String::from("dependency-c3d4"),
                analysis_id: AnalysisId::from("dependency-generation"),
            }],
            ir(),
        )
        .expect("valid artifact analysis")
    }

    fn expectations() -> CacheExpectations<'static> {
        CacheExpectations {
            tool_version: "0.1.0",
            rustc_version: "rustc 1.90.0-nightly",
        }
    }

    #[test]
    fn v13_round_trip_preserves_only_artifact_ir_and_dependencies() {
        let directory = tempdir().expect("temporary cache root");
        let expected = analysis("compiler-profile");
        expected.write(directory.path()).expect("write cache");

        let path = artifact_cache_path(directory.path(), "sample-a1b2");
        let source = fs::read_to_string(&path).expect("read serialized cache");
        let json: serde_json::Value = serde_json::from_str(&source).expect("valid JSON");
        let object = json.as_object().expect("cache object");

        assert_eq!(json["format-version"], CACHE_FORMAT_VERSION);
        assert!(object.contains_key("ir"));
        assert!(!object.contains_key("finding-arena"));
        assert!(!object.contains_key("trace-arena"));
        assert!(!object.contains_key("functions"));
        assert!(!object.contains_key("scope"));

        let decoded = ArtifactAnalysisCache::read(&path, &expectations()).expect("read cache");
        assert_eq!(decoded, expected);
        assert_eq!(decoded.ir, ir());
        assert_eq!(decoded.dependencies.len(), 1);
    }

    #[test]
    fn writing_same_artifact_twice_replaces_the_previous_generation() {
        let directory = tempdir().expect("temporary cache root");
        let first = analysis("compiler-profile");
        let second = analysis("compiler-overflow-on");

        first
            .write(directory.path())
            .expect("write first generation");
        second
            .write(directory.path())
            .expect("replace first generation");

        let path = artifact_cache_path(directory.path(), "sample-a1b2");
        let decoded =
            ArtifactAnalysisCache::read(&path, &expectations()).expect("read second generation");

        assert_eq!(decoded, second);
    }

    #[test]
    fn compiler_fingerprint_is_artifact_local_and_part_of_generation_identity() {
        let profile = analysis("compiler-profile");
        let overflow_on = analysis("compiler-overflow-on");

        assert_ne!(profile.analysis_id, overflow_on.analysis_id);

        let directory = tempdir().expect("temporary cache root");
        profile.write(directory.path()).expect("write cache");
        let path = artifact_cache_path(directory.path(), "sample-a1b2");
        let decoded = ArtifactAnalysisCache::read(&path, &expectations())
            .expect("a consumer must not impose its compiler profile on a dependency");

        assert_eq!(decoded.compiler_fingerprint, "compiler-profile");
    }

    #[test]
    fn canonicalization_makes_dependency_order_irrelevant() {
        let dependencies = vec![
            DependencyAnalysisRef {
                artifact_id: String::from("z-dependency"),
                analysis_id: AnalysisId::from("z-generation"),
            },
            DependencyAnalysisRef {
                artifact_id: String::from("a-dependency"),
                analysis_id: AnalysisId::from("a-generation"),
            },
        ];
        let forward = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            "compiler",
            artifact(),
            dependencies.clone(),
            ir(),
        )
        .expect("valid analysis");
        let reverse = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            "compiler",
            artifact(),
            dependencies.into_iter().rev().collect(),
            ir(),
        )
        .expect("valid analysis");

        assert_eq!(forward, reverse);
        assert_eq!(forward.dependencies[0].artifact_id, "a-dependency");
    }

    #[test]
    fn rejects_conflicting_dependency_generations() {
        let error = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            "compiler",
            artifact(),
            vec![
                DependencyAnalysisRef {
                    artifact_id: String::from("dependency"),
                    analysis_id: AnalysisId::from("first"),
                },
                DependencyAnalysisRef {
                    artifact_id: String::from("dependency"),
                    analysis_id: AnalysisId::from("second"),
                },
            ],
            ir(),
        )
        .expect_err("one artifact cannot name two dependency generations");

        assert!(
            error
                .to_string()
                .contains("conflicting analysis generations")
        );
    }

    #[test]
    fn rejects_ir_owned_by_another_artifact() {
        let foreign_ir = ArtifactAnalysisIr::new(
            vec![FunctionBodyIr {
                function: FunctionId::generic(def_hash("00000000000000090000000000000002")),
                provenance: FunctionBodyProvenanceIr::DefiningArtifact,
                display_path: String::from("foreign::root"),
                attributes: FunctionAttributesIr {
                    is_unsafe: false,
                    is_exported: false,
                    has_rust_body: true,
                    is_foreign: false,
                    namespace_candidates: vec![String::from("foreign::root")],
                },
                source_range: None,
                calls: Vec::new(),
                effects: Vec::new(),
                markers: Vec::new(),
            }],
            Vec::new(),
        )
        .expect("structurally valid IR");

        let error = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            "compiler",
            artifact(),
            Vec::new(),
            foreign_ir,
        )
        .expect_err("function identities must belong to the artifact");

        assert!(error.to_string().contains("does not belong to artifact"));
    }

    #[test]
    fn accepts_exact_foreign_body_owned_as_a_consumer_instantiation() {
        let mut overlay = ir().functions.remove(0);
        overlay.function = FunctionId::exact(
            def_hash("00000000000000090000000000000002"),
            instance_hash("000000000000000a000000000000000b"),
        );
        overlay.provenance = FunctionBodyProvenanceIr::ConsumerInstantiation {
            consumer_stable_crate_id: LOCAL_STABLE_CRATE_ID,
        };
        overlay.display_path = String::from("foreign::generic::<sample::Local>");
        overlay.attributes.namespace_candidates =
            vec![String::from("foreign::generic"), String::from("foreign")];
        let overlay_ir =
            ArtifactAnalysisIr::new(vec![overlay], Vec::new()).expect("structurally valid overlay");

        ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            "compiler",
            artifact(),
            Vec::new(),
            overlay_ir,
        )
        .expect("the consumer artifact should own the exact foreign overlay");
    }

    #[test]
    fn rejects_consumer_instantiation_claimed_by_another_artifact() {
        let mut overlay = ir().functions.remove(0);
        overlay.function = FunctionId::exact(
            def_hash("00000000000000090000000000000002"),
            instance_hash("000000000000000a000000000000000b"),
        );
        overlay.provenance = FunctionBodyProvenanceIr::ConsumerInstantiation {
            consumer_stable_crate_id: 99,
        };
        let overlay_ir =
            ArtifactAnalysisIr::new(vec![overlay], Vec::new()).expect("structurally valid overlay");

        let error = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            "compiler",
            artifact(),
            Vec::new(),
            overlay_ir,
        )
        .expect_err("consumer provenance must match the artifact owner");

        assert!(
            error
                .to_string()
                .contains("consumer function 0 names stable crate id")
        );
    }

    #[test]
    fn rejects_v12_before_deserializing_the_old_schema() {
        let directory = tempdir().expect("temporary cache root");
        let path = directory.path().join("legacy.json");
        fs::write(&path, r#"{"format-version":12,"functions":[]}"#).expect("write legacy header");

        let error = ArtifactAnalysisCache::read(&path, &expectations())
            .expect_err("v12 is deliberately incompatible");

        assert!(matches!(error, CacheError::Format { version: 12, .. }));
    }

    #[test]
    fn cache_paths_use_the_v13_directory() {
        let root = default_cache_dir("/target/plugin-nightly");

        assert_eq!(
            root.to_string_lossy(),
            "/target/plugin-nightly/sniff-test-cache/v13"
        );
        assert_eq!(
            artifact_cache_path(&root, "sample-a1b2").to_string_lossy(),
            "/target/plugin-nightly/sniff-test-cache/v13/artifacts/sample-a1b2.json"
        );
    }
}
