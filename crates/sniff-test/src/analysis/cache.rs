//! Versioned on-disk envelope for policy-neutral artifact analysis IR.
//!
//! The cache contains extraction facts only. Lint levels, selected report
//! roots, interpreted findings, and rendered traces deliberately live outside
//! this schema so a workspace can reinterpret one dependency artifact under a
//! different policy without recompiling it.

use std::fmt::{self, Display, Formatter};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::ir::{ArtifactAnalysisIr, FunctionBodyProvenanceIr};

pub(crate) const CACHE_FORMAT_VERSION: u32 = 15;
pub(crate) const CACHE_DIR_NAME: &str = "sniff-test-cache";
pub(crate) const CACHE_VERSION_DIR: &str = "v15";

/// Cached policy-neutral analysis for one exact rustc output artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ArtifactAnalysisCache {
    pub(crate) format_version: u32,
    pub(crate) tool_version: String,
    pub(crate) rustc_version: String,
    pub(crate) artifact: ArtifactInfo,
    pub(crate) dependencies: Vec<RustcArtifactId>,
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
        artifact: ArtifactInfo,
        mut dependencies: Vec<RustcArtifactId>,
        mut ir: ArtifactAnalysisIr,
    ) -> Result<Self, CacheValidationError> {
        dependencies.sort_unstable();
        dependencies.dedup();
        ir.canonicalize();
        let analysis = Self {
            format_version: CACHE_FORMAT_VERSION,
            tool_version: tool_version.into(),
            rustc_version: rustc_version.into(),
            artifact,
            dependencies,
            ir,
        };
        analysis.validate()?;
        Ok(analysis)
    }

    /// Writes this analysis to the path derived from its artifact identity.
    pub(crate) fn write(&self, cache_dir: &Path) -> Result<(), CacheError> {
        let path = artifact_cache_path(cache_dir, &self.artifact.id);
        self.validate()
            .map_err(|error| CacheError::invalid(&path, error))?;
        let source = serde_json::to_string_pretty(self).map_err(|source| CacheError::Json {
            path: path.clone(),
            source,
        })?;
        write_atomic(&path, &source)
    }

    /// Reads and validates one v15 cache file against the active extraction
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
            (self.artifact.crate_name.as_str(), "artifact crate name"),
        ] {
            if value.trim().is_empty() {
                return Err(CacheValidationError::new(format!(
                    "{label} must not be empty"
                )));
            }
        }
        self.artifact.id.validate()?;
        validate_dependencies(&self.artifact, &self.dependencies)?;
        self.ir
            .validate()
            .map_err(|error| CacheValidationError::new(error.to_string()))?;
        for (index, body) in self.ir.functions.iter().enumerate() {
            let definition_stable_crate_id = body.function.def_path_hash.stable_crate_id();
            match body.provenance {
                FunctionBodyProvenanceIr::DefiningArtifact
                    if definition_stable_crate_id != self.artifact.id.stable_crate_id =>
                {
                    return Err(CacheValidationError::new(format!(
                        "defining function {index} does not belong to artifact stable crate id \
                         {:016x}",
                        self.artifact.id.stable_crate_id
                    )));
                }
                FunctionBodyProvenanceIr::ConsumerInstantiation {
                    consumer_stable_crate_id,
                } if consumer_stable_crate_id != self.artifact.id.stable_crate_id => {
                    return Err(CacheValidationError::new(format!(
                        "consumer function {index} names stable crate id \
                         {consumer_stable_crate_id:016x}, expected {:016x}",
                        self.artifact.id.stable_crate_id
                    )));
                }
                FunctionBodyProvenanceIr::ConsumerInstantiation { .. }
                    if definition_stable_crate_id == self.artifact.id.stable_crate_id =>
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
}

/// rustc's identity for one loadable crate artifact.
///
/// The stable crate ID identifies the crate, while the strict version hash
/// (SVH) selects the exact artifact rustc loaded. Cargo output filenames are
/// deliberately not part of this identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct RustcArtifactId {
    pub(crate) stable_crate_id: u64,
    pub(crate) svh: String,
}

impl RustcArtifactId {
    #[must_use]
    pub(crate) fn new(stable_crate_id: u64, svh: impl Into<String>) -> Self {
        Self {
            stable_crate_id,
            svh: svh.into(),
        }
    }

    fn validate(&self) -> Result<(), CacheValidationError> {
        if self.svh.len() != 32
            || !self
                .svh
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CacheValidationError::new(
                "rustc artifact SVH must be a 32-digit lowercase hexadecimal value",
            ));
        }
        Ok(())
    }
}

impl Display for RustcArtifactId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:016x}-{}", self.stable_crate_id, self.svh)
    }
}

/// Identity and provenance for the exact compiled artifact represented here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct ArtifactInfo {
    pub(crate) id: RustcArtifactId,
    pub(crate) crate_name: String,
}

fn validate_dependencies(
    artifact: &ArtifactInfo,
    dependencies: &[RustcArtifactId],
) -> Result<(), CacheValidationError> {
    for pair in dependencies.windows(2) {
        if pair[0] >= pair[1] {
            return Err(CacheValidationError::new(
                "dependencies must be uniquely sorted by rustc artifact identity",
            ));
        }
        if pair[0].stable_crate_id == pair[1].stable_crate_id {
            return Err(CacheValidationError::new(format!(
                "dependencies contain two SVHs for stable crate id {:016x}",
                pair[0].stable_crate_id
            )));
        }
    }
    for dependency in dependencies {
        dependency.validate()?;
        if dependency.stable_crate_id == artifact.id.stable_crate_id {
            return Err(CacheValidationError::new(format!(
                "artifact {} cannot depend on another SVH of its own stable crate id",
                artifact.id,
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
pub(crate) fn artifact_cache_path(cache_dir: &Path, artifact_id: &RustcArtifactId) -> PathBuf {
    cache_dir
        .join("artifacts")
        .join(format!("{artifact_id}.json"))
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;

    use super::{
        ArtifactAnalysisCache, ArtifactInfo, CACHE_FORMAT_VERSION, CacheError, CacheExpectations,
        RustcArtifactId, artifact_cache_path, default_cache_dir,
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
            id: rustc_id(LOCAL_STABLE_CRATE_ID, "0123456789abcdef0123456789abcdef"),
            crate_name: String::from("sample"),
        }
    }

    fn analysis() -> ArtifactAnalysisCache {
        ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc 1.90.0-nightly",
            artifact(),
            vec![rustc_id(2, "22222222222222222222222222222222")],
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

    fn rustc_id(stable_crate_id: u64, svh: &str) -> RustcArtifactId {
        RustcArtifactId::new(stable_crate_id, svh)
    }

    #[test]
    fn rustc_identity_alone_determines_the_cache_path() {
        let identity =
            RustcArtifactId::new(0x0123_4567_89ab_cdef, "fedcba98765432100123456789abcdef");

        assert_eq!(
            identity.to_string(),
            "0123456789abcdef-fedcba98765432100123456789abcdef"
        );
        assert_eq!(
            artifact_cache_path(Path::new("/cache"), &identity).to_string_lossy(),
            "/cache/artifacts/0123456789abcdef-fedcba98765432100123456789abcdef.json"
        );
    }

    #[test]
    fn v15_round_trip_preserves_artifact_identity_dependencies_and_ir() {
        let directory = tempdir().expect("temporary cache root");
        let expected = analysis();
        expected.write(directory.path()).expect("write cache");

        let path = artifact_cache_path(directory.path(), &expected.artifact.id);
        let source = fs::read_to_string(&path).expect("read serialized cache");
        let json: serde_json::Value = serde_json::from_str(&source).expect("valid JSON");
        let object = json.as_object().expect("cache object");

        assert_eq!(json["format-version"], CACHE_FORMAT_VERSION);
        let mut fields = object.keys().map(String::as_str).collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "artifact",
                "dependencies",
                "format-version",
                "ir",
                "rustc-version",
                "tool-version",
            ]
        );
        assert_eq!(
            json["artifact"]["id"]["stable-crate-id"],
            LOCAL_STABLE_CRATE_ID
        );
        assert_eq!(
            json["artifact"]["id"]["svh"],
            "0123456789abcdef0123456789abcdef"
        );
        let artifact = json["artifact"].as_object().expect("artifact object");
        let mut artifact_fields = artifact.keys().map(String::as_str).collect::<Vec<_>>();
        artifact_fields.sort_unstable();
        assert_eq!(artifact_fields, ["crate-name", "id"]);

        let decoded = ArtifactAnalysisCache::read(&path, &expectations()).expect("read cache");
        assert_eq!(decoded, expected);
        assert_eq!(decoded.ir, ir());
        assert_eq!(
            decoded.dependencies,
            [rustc_id(2, "22222222222222222222222222222222")]
        );
    }

    #[test]
    fn writing_same_rustc_artifact_identity_refreshes_cached_ir() {
        let directory = tempdir().expect("temporary cache root");
        let first = analysis();
        let second = analysis();

        first.write(directory.path()).expect("write first cache");
        second.write(directory.path()).expect("refresh first cache");

        let path = artifact_cache_path(directory.path(), &second.artifact.id);
        let decoded =
            ArtifactAnalysisCache::read(&path, &expectations()).expect("read refreshed cache");

        assert_eq!(decoded, second);
    }

    #[test]
    fn canonicalization_makes_dependency_order_irrelevant() {
        let dependencies = vec![
            rustc_id(3, "33333333333333333333333333333333"),
            rustc_id(2, "22222222222222222222222222222222"),
        ];
        let forward =
            ArtifactAnalysisCache::new("0.1.0", "rustc", artifact(), dependencies.clone(), ir())
                .expect("valid analysis");
        let reverse = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            artifact(),
            dependencies.into_iter().rev().collect(),
            ir(),
        )
        .expect("valid analysis");

        assert_eq!(forward, reverse);
        assert_eq!(forward.dependencies[0].stable_crate_id, 2);
    }

    #[test]
    fn exact_duplicate_dependencies_are_deduplicated() {
        let dependency = rustc_id(2, "22222222222222222222222222222222");
        let analysis = ArtifactAnalysisCache::new(
            "0.1.0",
            "rustc",
            artifact(),
            vec![dependency.clone(), dependency.clone()],
            ir(),
        )
        .expect("duplicate graph edges are harmless");

        assert_eq!(analysis.dependencies, [dependency]);
    }

    #[test]
    fn new_rejects_invalid_cache_data() {
        let mut invalid_artifact = artifact();
        invalid_artifact.id.svh = String::from("not-a-valid-svh");

        let error =
            ArtifactAnalysisCache::new("0.1.0", "rustc", invalid_artifact, Vec::new(), ir())
                .expect_err("malformed cache data must be rejected");

        assert!(error.to_string().contains("lowercase hexadecimal"));
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

        ArtifactAnalysisCache::new("0.1.0", "rustc", artifact(), Vec::new(), overlay_ir)
            .expect("the consumer artifact should own the exact foreign overlay");
    }

    #[test]
    fn read_reports_v14_as_incompatible_before_deserializing() {
        let directory = tempdir().expect("temporary cache root");
        let path = directory.path().join("legacy.json");
        fs::write(&path, r#"{"format-version":14,"functions":[]}"#).expect("write legacy header");

        let error = ArtifactAnalysisCache::read(&path, &expectations())
            .expect_err("v14 is deliberately incompatible");

        assert!(matches!(error, CacheError::Format { version: 14, .. }));
    }

    #[test]
    fn cache_paths_use_the_v15_directory() {
        let root = default_cache_dir("/target/plugin-nightly");
        let identity = rustc_id(1, "0123456789abcdef0123456789abcdef");

        assert_eq!(
            root.to_string_lossy(),
            "/target/plugin-nightly/sniff-test-cache/v15"
        );
        assert_eq!(
            artifact_cache_path(&root, &identity).to_string_lossy(),
            "/target/plugin-nightly/sniff-test-cache/v15/artifacts/0000000000000001-0123456789abcdef0123456789abcdef.json"
        );
    }
}
